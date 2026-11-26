from __future__ import annotations

import struct
import types

import pytest

from firebreak.mediatek import bl2
from firebreak.ui import FatalError

IMAGE = b"\xd0\x0d\xfe\xed" + b"a" * 8201


class Port:
    def __init__(
        self,
        image: bytes,
        *,
        bad_checksum: bool = False,
        prefix: bytes = b"",
        short_at: int | None = None,
        silent: int = 0,
    ) -> None:
        self.image = image
        self.sent = []
        self.short_at = short_at
        self.silent = silent
        self.flushes = 0
        self.reply = bytearray(
            prefix
            + bytes(v ^ 255 for v in (0xA0, 0x0A, 0x50, 0x05))
            + b"\xd7"
            + struct.pack(">III", 0x200000, len(image), 0)
            + b"\0\0"
            + (b"xx" if bad_checksum else bl2.checksum(image))
            + b"\0\0\xd5\xff\xff\xff\xff\0\0"
        )

    def flush(self) -> None:
        pass

    def read(self, _count: int) -> bytes:
        if self.silent > 0:
            self.silent -= 1
            return b""
        taken = bytes(self.reply[:1])
        del self.reply[:1]
        return taken

    def reset_input_buffer(self) -> None:
        self.flushes += 1

    def write(self, data: bytes) -> int:
        self.sent.append(data)
        return 0 if len(self.sent) == self.short_at else len(data)


@pytest.fixture(autouse=True)
def ticking_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [0.0]

    def monotonic() -> float:
        now[0] += 0.1
        return now[0]

    monkeypatch.setattr(bl2.time, "monotonic", monotonic)
    monkeypatch.setattr(bl2.time, "sleep", lambda _: None)
    return now


def test_invalid_image_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    port = Port(b"bad")
    with pytest.raises(FatalError, match="Invalid"):
        bl2.upload(port, b"bad")
    clock = iter([0, 11])
    monkeypatch.setattr(bl2.time, "monotonic", lambda: next(clock))
    with pytest.raises(FatalError, match="timed out"):
        bl2.read(port, 1)


def test_listener_filters_ports_and_recovers_from_open_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ports = [
        types.SimpleNamespace(device="/dev/cu.test", pid=0x2000, vid=0x0E8D),
        types.SimpleNamespace(device="/dev/tty.test", pid=0x2000, vid=0x0E8D),
    ]
    monkeypatch.setattr(bl2.sys, "platform", "darwin")
    monkeypatch.setattr(bl2.serial.tools.list_ports, "comports", lambda: ports)
    calls = []

    def opened(*args: object, **_kwargs: object) -> str:
        calls.append(args)
        if len(calls) == 1:
            raise OSError
        return "port"

    monkeypatch.setattr(bl2.serial, "Serial", opened)
    assert bl2.listen() == "port"
    assert calls == [("/dev/cu.test",)] * 2
    monkeypatch.setattr(bl2.sys, "platform", "linux")
    with pytest.raises(FatalError, match="Multiple preloader"):
        bl2.listen()
    monkeypatch.setattr(bl2.serial.tools.list_ports, "comports", list)
    clock = iter([0, 1, 46])
    monkeypatch.setattr(bl2.time, "monotonic", lambda: next(clock))
    with pytest.raises(FatalError, match="No preloader"):
        bl2.listen()


@pytest.mark.parametrize("short_at", [1, 5, 9])
def test_short_writes_abort(short_at: int | None) -> None:
    image = b"\xd0\x0d\xfe\xedabc"
    for window in (False, True):
        port = Port(image, short_at=short_at)
        with pytest.raises(FatalError, match="Short"):
            bl2.upload(port, image, window=window)
        assert b"\xd5" not in port.sent


def test_upload_checks_checksum_before_execution() -> None:
    port = Port(IMAGE)
    bl2.upload(port, IMAGE)
    assert port.sent[-2:] == [b"\xd5", b"\xff" * 4]
    assert b"".join(port.sent[8:-2]) == IMAGE
    assert not port.dtr
    assert port.rts
    port = Port(IMAGE, bad_checksum=True)
    with pytest.raises(FatalError, match="mismatch"):
        bl2.upload(port, IMAGE)
    assert b"\xd5" not in port.sent


def test_window_mode_gives_up_after_its_start_attempts() -> None:
    port = Port(IMAGE, silent=10**6)
    with pytest.raises(FatalError, match="mismatch"):
        bl2.upload(port, IMAGE, window=True)
    assert port.sent == [b"\xa0"] * bl2.START_ATTEMPTS
    assert port.flushes == bl2.START_ATTEMPTS - 1


def test_window_mode_reads_past_stray_bytes_and_traces_each_exchange() -> None:
    port = Port(IMAGE, prefix=b"\x01\x02")
    with pytest.raises(FatalError, match="mismatch"):
        bl2.upload(port, IMAGE)
    port = Port(IMAGE, prefix=b"\x01\x02")
    lines = []
    bl2.upload(port, IMAGE, trace=lines.append, window=True)
    assert port.sent[-2:] == [b"\xd5", b"\xff" * 4]
    assert lines[:6] == ["tx a0", "rx 01 02 5f", "tx 0a", "rx f5", "tx 50", "rx af"]
    assert lines[-5:] == [
        "tx d5",
        "rx d5",
        "tx ff ff ff ff",
        "rx ff ff ff ff",
        "rx 00 00",
    ]


def test_window_mode_retries_a_start_byte_that_was_not_echoed() -> None:
    port = Port(IMAGE, silent=4)
    bl2.upload(port, IMAGE, window=True)
    assert port.sent[:3] == [b"\xa0", b"\xa0", b"\x0a"]
    assert port.flushes == 1
    assert b"".join(port.sent[9:-2]) == IMAGE


def test_window_mode_waits_only_moments_for_a_silent_device(
    ticking_clock: list[float],
) -> None:
    port = Port(IMAGE)
    port.reply.clear()
    with pytest.raises(FatalError, match="mismatch"):
        bl2.upload(port, IMAGE, window=True)
    assert port.sent == [b"\xa0"] * bl2.START_ATTEMPTS
    assert ticking_clock[0] < 10
