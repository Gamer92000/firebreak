from __future__ import annotations

import struct
import types

import pytest

from firebreak.mediatek import bl2
from firebreak.ui import FatalError


class Port:
    def __init__(
        self, image: bytes, *, bad_checksum: bool = False, short_at: int | None = None
    ) -> None:
        self.image = image
        self.sent = []
        self.short_at = short_at
        self.reply = bytearray(
            bytes(v ^ 255 for v in (0xA0, 0x0A, 0x50, 0x05))
            + b"\xd7"
            + struct.pack(">III", 0x200000, len(image), 0)
            + b"\0\0"
            + (b"xx" if bad_checksum else bl2.checksum(image))
            + b"\0\0\xd5\xff\xff\xff\xff\0\0"
        )

    def flush(self) -> None:
        pass

    def read(self, _count: int) -> bytes:
        taken = bytes(self.reply[:1])
        del self.reply[:1]
        return taken

    def write(self, data: bytes) -> int:
        self.sent.append(data)
        return 0 if len(self.sent) == self.short_at else len(data)


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
    monkeypatch.setattr(bl2.time, "sleep", lambda _: None)
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
    with pytest.raises(FatalError, match="Multiple"):
        bl2.listen()
    monkeypatch.setattr(bl2.serial.tools.list_ports, "comports", list)
    clock = iter([0, 1, 46])
    monkeypatch.setattr(bl2.time, "monotonic", lambda: next(clock))
    with pytest.raises(FatalError, match="No Cannoli"):
        bl2.listen()


@pytest.mark.parametrize("short_at", [1, 5, 9])
def test_short_writes_abort(short_at: int | None) -> None:
    image = b"\xd0\x0d\xfe\xedabc"
    port = Port(image, short_at=short_at)
    with pytest.raises(FatalError, match="Short"):
        bl2.upload(port, image)
    assert b"\xd5" not in port.sent


def test_upload_checks_checksum_before_execution() -> None:
    image = b"\xd0\x0d\xfe\xed" + b"a" * 8201
    port = Port(image)
    bl2.upload(port, image)
    assert port.sent[-2:] == [b"\xd5", b"\xff" * 4]
    assert b"".join(port.sent[8:-2]) == image
    assert not port.dtr
    assert port.rts
    port = Port(image, bad_checksum=True)
    with pytest.raises(FatalError, match="mismatch"):
        bl2.upload(port, image)
    assert b"\xd5" not in port.sent
