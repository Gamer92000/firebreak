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

MAX_IMAGE = 2 * 1024 * 1024
USB_ID = (0x0E8D, 0x2000)


def checksum(data: bytes) -> bytes:
    padded = data + b"\0" * (len(data) % 2)
    value = 0
    for (word,) in struct.iter_unpack("<H", padded):
        value ^= word
    return value.to_bytes(2, "big")


def echo(port: serial.Serial, value: bytes) -> None:
    if port.write(value) != len(value):
        raise FatalError(message="Short BL2 write; no further command sent")
    expect(port, value)


def expect(port: serial.Serial, wanted: bytes) -> None:
    if read(port, len(wanted)) != wanted:
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
                message="Multiple Cannoli preloader ports; connect only the target Echo"
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
        message="No Cannoli preloader appeared; power on after the listener starts"
    )


def read(port: serial.Serial, count: int) -> bytes:
    deadline = time.monotonic() + 10
    data = bytearray()
    while len(data) < count:
        if time.monotonic() >= deadline:
            raise FatalError(message="BL2 response timed out; no further command sent")
        data.extend(port.read(count - len(data)))
    return bytes(data)


def upload(port: serial.Serial, image: bytes) -> None:
    if not image.startswith(b"\xd0\x0d\xfe\xed") or not 0 < len(image) <= MAX_IMAGE:
        raise FatalError(message="Invalid BL2 FIT upload")
    port.dtr = False
    port.rts = True
    for value in (0xA0, 0x0A, 0x50, 0x05):
        if port.write(bytes([value])) != 1:
            raise FatalError(message="Short BL2 handshake write")
        expect(port, bytes([value ^ 0xFF]))
    echo(port, b"\xd7")
    for value in (0x200000, len(image), 0):
        echo(port, struct.pack(">I", value))
    expect(port, b"\0\0")
    for offset in range(0, len(image), 8192):
        block = image[offset : offset + 8192]
        if port.write(block) != len(block):
            raise FatalError(message="Short BL2 image write; execution refused")
    port.flush()
    expect(port, checksum(image))
    expect(port, b"\0\0")
    echo(port, b"\xd5")
    echo(port, b"\xff\xff\xff\xff")
    expect(port, b"\0\0")
