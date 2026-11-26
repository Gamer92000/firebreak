from __future__ import annotations

import struct
import sys
import time
from typing import TYPE_CHECKING

import serial
import serial.tools.list_ports

from firebreak.ui import FatalError

if TYPE_CHECKING:
    import threading
    from collections.abc import Callable

    Trace = Callable[[str], None]

MAX_IMAGE = 2 * 1024 * 1024
START_ATTEMPTS = 6
USB_ID = (0x0E8D, 0x2000)
WINDOW_ACK = 1.0
WINDOW_CHECKSUM = 3.0
WINDOW_ECHO = 0.5


def checksum(data: bytes) -> bytes:
    padded = data + b"\0" * (len(data) % 2)
    value = 0
    for (word,) in struct.iter_unpack("<H", padded):
        value ^= word
    return value.to_bytes(2, "big")


def expect(
    port: serial.Serial,
    wanted: bytes,
    *,
    seconds: float = 10,
    trace: Trace = None,
    until: bool = False,
) -> None:
    got = (
        until_read(port, wanted, seconds=seconds)
        if until
        else read(port, len(wanted), seconds=seconds)
    )
    traced(trace, "rx", got)
    if not got.endswith(wanted):
        raise FatalError(message="BL2 response mismatch; no further command sent")


def listen(
    seconds: float = 45, *, ready: threading.Event | None = None
) -> serial.Serial:
    deadline = time.monotonic() + seconds
    if ready is not None:
        ready.set()
    while time.monotonic() < deadline:
        ports = [
            p for p in serial.tools.list_ports.comports() if (p.vid, p.pid) == USB_ID
        ]
        if sys.platform == "darwin":
            ports = [p for p in ports if p.device.startswith("/dev/cu.")]
        if len(ports) > 1:
            raise FatalError(
                message="Multiple preloader ports; connect only the target Echo"
            )
        if ports:
            try:
                return serial.Serial(
                    ports[0].device,
                    baudrate=921600,
                    dsrdtr=False,
                    rtscts=False,
                    timeout=0.1,
                    write_timeout=30,
                    xonxoff=False,
                )
            except (serial.SerialException, OSError):
                pass
        time.sleep(0.01)
    raise FatalError(
        message="No preloader appeared; power on after the listener starts"
    )


def read(port: serial.Serial, count: int, *, seconds: float = 10) -> bytes:
    deadline = time.monotonic() + seconds
    data = bytearray()
    while len(data) < count:
        if time.monotonic() >= deadline:
            raise FatalError(message="BL2 response timed out; no further command sent")
        data.extend(port.read(count - len(data)))
    return bytes(data)


def started(port: serial.Serial, *, trace: Trace, window: bool) -> bool:
    for attempt in range(START_ATTEMPTS if window else 1):
        if attempt:
            port.reset_input_buffer()
            time.sleep(0.05)
        if port.write(b"\xa0") != 1:
            raise FatalError(message="Short BL2 handshake write")
        traced(trace, "tx", b"\xa0")
        try:
            expect(
                port,
                b"\x5f",
                seconds=WINDOW_ECHO if window else 10,
                trace=trace,
                until=window,
            )
        except FatalError:
            if not window:
                raise
        else:
            return True
    return False


def traced(trace: Trace, direction: str, data: bytes) -> None:
    if trace is not None and data:
        trace(f"{direction} {data.hex(' ')}")


def until_read(port: serial.Serial, wanted: bytes, *, seconds: float) -> bytes:
    got = bytearray()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not got.endswith(wanted):
        got.extend(port.read(1))
    return bytes(got)


def upload(  # ruff: ignore[complex-structure]
    port: serial.Serial, image: bytes, *, trace: Trace = None, window: bool = False
) -> None:
    if not image.startswith(b"\xd0\x0d\xfe\xed") or not 0 < len(image) <= MAX_IMAGE:
        raise FatalError(message="Invalid BL2 FIT upload")
    echo_wait, ack_wait = (WINDOW_ECHO, WINDOW_ACK) if window else (10, 10)
    image_wait = WINDOW_CHECKSUM if window else 10

    def reply(wanted: bytes, seconds: float) -> None:
        expect(port, wanted, seconds=seconds, trace=trace, until=window)

    def sent(value: bytes) -> None:
        if port.write(value) != len(value):
            raise FatalError(message="Short BL2 write; no further command sent")
        traced(trace, "tx", value)

    port.dtr = False
    port.rts = True
    if not started(port, trace=trace, window=window):
        raise FatalError(message="BL2 response mismatch; no further command sent")
    for value in (0x0A, 0x50, 0x05):
        if port.write(bytes([value])) != 1:
            raise FatalError(message="Short BL2 handshake write")
        traced(trace, "tx", bytes([value]))
        reply(bytes([value ^ 0xFF]), echo_wait)
    for value in (b"\xd7", *(struct.pack(">I", n) for n in (0x200000, len(image), 0))):
        sent(value)
        reply(value, echo_wait)
    reply(b"\0\0", ack_wait)
    for offset in range(0, len(image), 8192):
        block = image[offset : offset + 8192]
        if port.write(block) != len(block):
            raise FatalError(message="Short BL2 image write; execution refused")
    port.flush()
    reply(checksum(image), image_wait)
    reply(b"\0\0", ack_wait)
    for value in (b"\xd5", b"\xff\xff\xff\xff"):
        sent(value)
        reply(value, echo_wait)
    reply(b"\0\0", ack_wait)
