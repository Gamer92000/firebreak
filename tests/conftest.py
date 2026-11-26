from __future__ import annotations

import hashlib
import struct
import subprocess
import sys
import time
import types
from typing import TYPE_CHECKING

import pytest

from firebreak import cache, fireos, host, identify, ui
from firebreak.devices import BISCUIT, DEFAULTS, TARGETS
from firebreak.mediatek import fit, gcpu, usbdl

if TYPE_CHECKING:
    import pathlib
    from collections.abc import Callable, Iterator

ADB_KEY = b"QAAAAtest firebreak@host\n"
DEFINED = {(usbdl, "mediatek_ports")}
FIT_D = int(
    "83770612396893488838889438817013918313809550743219158826828690993812"
    "92350090659397015507055124710652947017246673198294047459090107605226"
    "45013116269689105172073868639193040718301235241974921220674450526607"
    "84654835792058370002761561948787205916821083585250472839084646250945"
    "0862060457665285241872163733877313"
)
FIT_HEADER = 56
FIT_KEY = (
    int(
        "16738032392241489567177735218751954769915050387373030524493511956"
        "2851145349966934421404050570642732336033130882689450182008636094018"
        "94016032385549075187467729241533652745816241945448785212619022105898"
        "47207055260467266709451174045640168822362757377415942381331013848133"
        "46422592828787885490362930001966009687239"
    ),
    65537,
)
FIT_SALT = b"firebreak's test salt" + bytes(11)
REAL_USB_DEVICES = identify.usb_devices


class FakeAdb:
    def __init__(self) -> None:
        self.answers: dict[
            str, list[str | tuple[int, str] | Exception | Callable[[], str]]
        ] = {}
        self.asked: list[list[str]] = []
        self.raw = b""
        self.raws: list[bytes] = []
        self.sent: list[bytes] = []

    def answer(self, *, words: list[str]) -> tuple[int, str]:
        answer = next(
            (
                said.pop(0) if len(said) > 1 else said[0]
                for key, said in self.answers.items()
                if key in words[-1]
            ),
            "",
        )
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):
            answer = answer()
        return answer if isinstance(answer, tuple) else (0, answer)

    def command(
        self, *, arguments: list[object], standard_input: object = None, **_: object
    ) -> subprocess.CompletedProcess[bytes]:
        words = [str(word) for word in arguments]
        self.asked.append(words)
        if words[1] == "exec-out":
            return subprocess.CompletedProcess(
                args=words,
                returncode=0,
                stdout=self.raws.pop(0) if self.raws else self.raw,
            )
        if hasattr(standard_input, "read"):
            self.sent.append(standard_input.read())
        returncode, text = self.answer(words=words)
        return subprocess.CompletedProcess(
            args=words, returncode=returncode, stdout=text.encode()
        )

    def commands(self, *, holding: str) -> list[str]:
        return [words[-1] for words in self.asked if holding in words[-1]]

    def stream(
        self, *, arguments: list[str], pieces: list[pathlib.Path], **_: object
    ) -> subprocess.CompletedProcess[str]:
        self.asked.append(arguments)
        self.sent.append(b"".join(piece.read_bytes() for piece in pieces))
        returncode, text = self.answer(words=arguments)
        return subprocess.CompletedProcess(
            args=arguments, returncode=returncode, stdout=text
        )


class FakePort:
    def __init__(self, *, replies: bytes = b"", short: bool = False) -> None:
        self.flushes = 0
        self.replies = bytearray(replies)
        self.short = short
        self.timeout: float | None = None
        self.written = bytearray()

    def read(self, *, size: int) -> bytes:
        count = 1 if self.short else size
        taken = bytes(self.replies[:count])
        del self.replies[: len(taken)]
        return taken

    def reset_input_buffer(self) -> None:
        self.flushes += 1

    def write(self, *, data: bytes) -> int:
        self.written += data
        return len(data)


class FitTree:
    def __init__(self) -> None:
        self.body = bytearray()
        self.strings = bytearray(b"\0")

    def begin(self, name: str) -> None:
        self.body += struct.pack(">I", fit.BEGIN_NODE) + name.encode() + b"\0"
        self.pad()

    def end(self) -> None:
        self.body += struct.pack(">I", fit.END_NODE)

    def image(self) -> bytes:
        strings_at = FIT_HEADER + len(self.body) + 4
        return (
            struct.pack(
                ">10I",
                fit.FIT_MAGIC,
                strings_at + len(self.strings),
                FIT_HEADER,
                strings_at,
                40,
                17,
                16,
                0,
                len(self.strings),
                len(self.body) + 4,
            )
            + bytes(16)
            + self.body
            + struct.pack(">I", fit.END)
            + self.strings
        )

    def nop(self) -> None:
        self.body += struct.pack(">I", fit.NOP)

    def pad(self) -> None:
        self.body += b"\0" * (-len(self.body) % 4)

    def prop(self, name: str, value: bytes) -> int:
        at = FIT_HEADER + len(self.body) + 12
        self.body += struct.pack(">III", fit.PROP, len(value), self.text(name)) + value
        self.pad()
        return at

    def text(self, name: str) -> int:
        data = name.encode() + b"\0"
        at = self.strings.find(data)
        if at < 0:
            at = len(self.strings)
            self.strings += data
        return at


@pytest.fixture(autouse=True)
def adb_home(*, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    key = tmp_path / "adbkey.pub"
    key.write_bytes(data=ADB_KEY)
    monkeypatch.setattr(name="HOST_KEY", target=fireos, value=key)


@pytest.fixture(autouse=True)
def fresh_session() -> Iterator[None]:
    ui.ARGUMENTS.target = TARGETS[BISCUIT][DEFAULTS[BISCUIT]]
    ui.ARGUMENTS.verbose = False
    vars(ui.SESSION).update(vars(ui.Session()))
    vars(ui.PROGRESS).update(vars(ui.Progress()))
    yield
    ui.PROGRESS.halt()


@pytest.fixture(autouse=True)
def no_real_cache(*, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    directory = tmp_path / "real-cache"
    directory.mkdir()
    for name, module in tuple(sys.modules.items()):
        if name != "firebreak" and not name.startswith((
            "firebreak.",
            "test_",
            "tests.",
        )):
            continue
        for attribute, value in (
            ("CACHE", directory),
            ("mediatek_ports", no_real_ports),
            ("usb_devices", no_real_usb),
        ):
            if hasattr(module, attribute) and (module, attribute) not in DEFINED:
                monkeypatch.setattr(name=attribute, target=module, value=value)
    monkeypatch.setenv(name="HOME", value=str(tmp_path / "real-home"))
    monkeypatch.setenv(name="USERPROFILE", value=str(tmp_path / "real-home"))
    monkeypatch.setattr(name="get", target=cache.webbrowser, value=real_browser)


@pytest.fixture
def adb(*, monkeypatch: pytest.MonkeyPatch) -> FakeAdb:
    fake = FakeAdb()
    real = {"command": host.command, "stream": host.stream}
    for name, module in tuple(sys.modules.items()):
        if name != "firebreak" and not name.startswith("firebreak."):
            continue
        for attribute, value in real.items():
            if getattr(module, attribute, None) is value:
                monkeypatch.setattr(
                    name=attribute, target=module, value=getattr(fake, attribute)
                )
    monkeypatch.setattr(name="sleep", target=time, value=lambda _: None)
    return fake


@pytest.fixture
def real_usb_devices(*, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(name="usb_devices", target=identify, value=REAL_USB_DEVICES)


def acquire_replies() -> bytes:
    return reply_write(
        address=gcpu.BASE + gcpu.Register.CONTROL, words=gcpu.ACQUIRE_VALUES
    )


def aes_replies(*, address: int, data: bytes, status: int = 1) -> bytes:
    return (
        clear_input_replies()
        + reply_write(
            address=gcpu.BASE + gcpu.Register.INPUT,
            words=gcpu.vector_words(data=data, decryption=gcpu.ZERO_DECRYPTION),
        )
        + reply_write(address=gcpu.BASE + gcpu.Register.SOURCE, words=(0, address, 1))
        + reply_write(
            address=gcpu.BASE + gcpu.Register.SLOT_POINTERS,
            words=gcpu.SLOT_POINTER_VALUES,
        )
        + function_replies(status=status)
    )


def clear_input_replies() -> bytes:
    return reply_write(
        address=gcpu.BASE + gcpu.Register.SLOTS, words=(0,) * gcpu.SLOT_WORDS
    )


def clear_replies() -> bytes:
    return (
        reply_write(
            address=gcpu.BASE + gcpu.Register.LENGTH, words=(0,) * gcpu.CLEAR_WORDS
        )
        + clear_input_replies()
    )


def fit_image(payload: bytes, *, private: int = FIT_D, stock: bytes) -> bytes:
    tree = FitTree()
    tree.begin("")
    tree.begin("images")
    for node, data in (("kernel-1", payload), ("archive/kernel-1", stock)):
        if node == "archive/kernel-1":
            tree.begin("archive")
        tree.begin("kernel-1")
        tree.prop("description", b"u-boot\0")
        tree.prop("data", data)
        tree.begin("hash-1")
        tree.prop("algo", b"sha256\0")
        tree.prop("value", hashlib.sha256(data).digest())
        tree.end()
        tree.end()
    tree.end()
    tree.end()
    tree.begin("configurations")
    tree.begin("conf-1")
    tree.prop("kernel-1", b"kernel-1\0")
    tree.begin("signature-1")
    tree.prop("algo", b"sha256,rsa2048\0")
    tree.prop("key-name-hint", b"dev\0")
    tree.prop("hashed-nodes", b"/images/archive/kernel-1\0")
    tree.prop("hashed-strings", struct.pack(">II", 0, len(tree.strings)))
    length = FIT_KEY[0].bit_length() // 8
    at = tree.prop("value", bytes(length))
    tree.end()
    tree.end()
    tree.end()
    tree.end()
    image = bytearray(tree.image())
    stream = fit.Fit(image).signed_stream(fit.SIGNATURE)
    digest = hashlib.sha256(b"\0" * 8 + hashlib.sha256(stream).digest() + FIT_SALT)
    room = length - 34 - len(FIT_SALT)
    data = bytes(room) + b"\x01" + FIT_SALT
    mask = bytearray()
    while len(mask) < len(data):
        mask += hashlib.sha256(
            digest.digest() + (len(mask) // 32).to_bytes(4, "big")
        ).digest()
    masked = bytearray(a ^ b for a, b in zip(data, mask))
    masked[0] &= 0x7F
    encoded = bytes(masked) + digest.digest() + b"\xbc"
    signature = pow(int.from_bytes(encoded, "big"), private, FIT_KEY[0]).to_bytes(
        length, "big"
    )
    image[at : at + length] = signature
    return bytes(image)


def fit_stream(image: bytes) -> str:
    return hashlib.sha256(fit.Fit(image).signed_stream(fit.SIGNATURE)).hexdigest()


def function_replies(*, status: int) -> bytes:
    polls = reply_read(
        address=gcpu.BASE + gcpu.Register.INTERRUPT_STATUS, values=(0,)
    ) + reply_read(address=gcpu.BASE + gcpu.Register.INTERRUPT_STATUS, values=(status,))
    read_again = reply_read(
        address=gcpu.BASE + gcpu.Register.INTERRUPT_STATUS, values=(status,)
    )
    if status & gcpu.Interrupt.ERROR:
        tail = (
            b""
            if status & gcpu.Interrupt.FINISHED
            else reply_read(
                address=gcpu.BASE + gcpu.Register.INTERRUPT_STATUS, values=(status,)
            )
        )
    else:
        tail = reply_read(address=gcpu.BASE + gcpu.Register.MONITOR, values=(1,))
    return (
        reply_write(
            address=gcpu.BASE + gcpu.Register.INTERRUPT_CLEAR,
            words=(gcpu.Interrupt.BOTH,),
        )
        + reply_write(
            address=gcpu.BASE + gcpu.Register.INTERRUPT_ENABLE,
            words=(gcpu.Interrupt.BOTH,),
        )
        + reply_write(
            address=gcpu.BASE + gcpu.Register.COMMAND,
            words=(gcpu.DECRYPT_FUNCTION,),
        )
        + reply_write(address=gcpu.BASE + gcpu.Register.PROGRAM_CONTROL, words=(0,))
        + polls
        + read_again
        + tail
        + reply_write(
            address=gcpu.BASE + gcpu.Register.INTERRUPT_CLEAR,
            words=(gcpu.Interrupt.BOTH,),
        )
    )


def no_real_ports() -> dict[str, int | None]:
    return {}


def no_real_usb() -> list[object]:
    return []


def opened_a_browser(**options: str) -> None:
    message = f"a test opened the real browser at {options}"
    raise AssertionError(message)


def real_browser() -> types.SimpleNamespace:
    return types.SimpleNamespace(name="real-browser", open=opened_a_browser)


def reply_payload(*, length: int, room: bytes = usbdl.PAYLOAD_STATUS) -> bytes:
    return (
        bytes([usbdl.BootromCommand.SEND_PAYLOAD])
        + struct.pack(">I", length)
        + room
        + (usbdl.PAYLOAD_STATUS * 2 if room == usbdl.PAYLOAD_STATUS else b"")
    )


def reply_read(*, address: int, values: tuple[int, ...]) -> bytes:
    return (
        bytes([usbdl.BootromCommand.READ_WORDS])
        + struct.pack(">II", address, len(values))
        + usbdl.READ_STATUS
        + struct.pack(f">{len(values)}I", *values)
        + usbdl.READ_STATUS
    )


def reply_write(*, address: int, end: bool = True, words: tuple[int, ...]) -> bytes:
    return (
        bytes([usbdl.BootromCommand.WRITE_WORDS])
        + struct.pack(">II", address, len(words))
        + usbdl.WRITE_STATUS
        + b"".join(struct.pack(">I", word) for word in words)
        + (usbdl.WRITE_STATUS if end else b"")
    )


def sent_payload(*, payload: bytes) -> bytes:
    return (
        bytes([usbdl.BootromCommand.SEND_PAYLOAD])
        + struct.pack(">I", len(payload))
        + payload
    )


def sent_read(*, address: int, count: int) -> bytes:
    return bytes([usbdl.BootromCommand.READ_WORDS]) + struct.pack(">II", address, count)


def sent_write(*, address: int, words: tuple[int, ...]) -> bytes:
    return (
        bytes([usbdl.BootromCommand.WRITE_WORDS])
        + struct.pack(">II", address, len(words))
        + b"".join(struct.pack(">I", word) for word in words)
    )


def shook(*, replies: bytes) -> tuple[usbdl.Bootrom, FakePort]:
    port = FakePort(replies=replies)
    return usbdl.Bootrom(port=port, timeout=0), port
