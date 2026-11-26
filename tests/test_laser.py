from __future__ import annotations

import functools
import hashlib
import itertools
import json
import pathlib
import struct
import subprocess
import threading
import types
from typing import TYPE_CHECKING

import pytest
from conftest import FIT_KEY, fit_image, fit_stream

from firebreak import __main__, laser, sparse
from firebreak.mediatek import bl2
from firebreak.ui import FatalError

if TYPE_CHECKING:
    from collections.abc import Callable

    from typing_extensions import Self

PORT = "/dev/ttyACM0"
SERIAL = "TEST1234"
STOCK = b"the stock loader" * 40
SYSTEM = bytearray(1024 * 1024)
SYSTEM[0x438:0x43A] = b"\x53\xef"


class Port:
    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exception: object) -> None:
        return None

    def __init__(self, device: str) -> None:
        self.device = device


class StubTransport:
    failing: tuple[str, int] | None = None

    def __init__(self, serial: str) -> None:
        assert serial == SERIAL
        self.calls: list[tuple] = []
        self.counts: dict[str, int] = {}

    def flash(self, partition: str, image: bytes) -> None:
        self.calls.append(("flash", partition, image))
        self.counts[partition] = self.counts.get(partition, 0) + 1
        if self.failing == (partition, self.counts[partition]):
            said = "Laser fastboot failed; no further writes attempted"
            raise FatalError(message=said)

    def load(self, data: bytes) -> None:
        self.calls.append(("load", data))

    def rehearse(self, data: bytes) -> None:
        self.calls.append(("rehearse", data))


class Windows:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, clock: list[float]) -> None:
        self.always: list[str] = []
        self.attempts = 0
        self.clock = clock
        self.failing = 0
        self.uploads: list[tuple[str, bytes]] = []
        self.unopenable_until = -1.0
        self.warnings: list[str] = []
        self.when: Callable[[float], bool] | None = None
        monkeypatch.setattr(laser, "preloader", self.ports)
        monkeypatch.setattr(laser.serial, "Serial", self.open)
        monkeypatch.setattr(bl2, "upload", self.upload)
        monkeypatch.setattr(
            laser, "warn", lambda **said: self.warnings.append(said["text"])
        )

    def open(self, device: str, **_options: object) -> Port:
        self.attempts += 1
        if self.clock[0] < self.unopenable_until:
            said = "busy"
            raise OSError(said)
        return Port(device)

    def ports(self) -> list[str]:
        if self.when is not None:
            return [PORT] if self.when(self.clock[0]) else []
        return list(self.always)

    def upload(self, port: Port, data: bytes, **_options: object) -> None:
        if self.failing:
            self.failing -= 1
            said = "BL2 response mismatch; no further command sent"
            raise FatalError(message=said)
        self.uploads.append((port.device, data))


@pytest.fixture(autouse=True)
def validated(monkeypatch: pytest.MonkeyPatch) -> dict[str, bytes]:
    images = {
        "access": fit_image(b"access payload" * 30, stock=STOCK),
        "boot_b": b"\xd0\x0d\xfe\xed" + b"stock boot" + bytes(20),
        "verity": fit_image(b"verity payload" * 30, stock=STOCK),
    }
    monkeypatch.setattr(laser, "KEY", FIT_KEY)
    monkeypatch.setattr(laser, "STOCK_STREAM", fit_stream(images["access"]))
    monkeypatch.setattr(
        laser,
        "LOADERS",
        {"access": sha(images["access"]), "verity": sha(images["verity"])},
    )
    monkeypatch.setattr(laser, "STOCK_BOOT", sha(images["boot_b"]))
    return images


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [0.0]

    def monotonic() -> float:
        now[0] += 0.02
        return now[0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    monkeypatch.setattr(laser.time, "monotonic", monotonic)
    monkeypatch.setattr(laser.time, "sleep", sleep)
    return now


@pytest.fixture
def windows(monkeypatch: pytest.MonkeyPatch, clock: list[float]) -> Windows:
    return Windows(monkeypatch, clock)


def argv(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> list[dict[str, object]]:
    monkeypatch.setattr(
        __main__.sys, "argv", ["firebreak", *arguments, "--no-update-check"]
    )
    for name in ("check_python", "check_user", "check_adb", "make_cache"):
        monkeypatch.setattr(__main__, name, lambda: None)
    monkeypatch.setattr(__main__.shutil, "which", lambda **_: "tool")
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(laser, "run", lambda **kwargs: calls.append(kwargs))
    return calls


def make_bundle(
    tmp_path: pathlib.Path,
    images: dict[str, bytes],
    replace: dict[str, bytes] | None = None,
) -> pathlib.Path:
    directory = tmp_path / "bundle"
    directory.mkdir(parents=True)
    content = {
        "access": images["access"],
        "boot_b": images["boot_b"],
        "system_a": bytes(SYSTEM),
        "verity": images["verity"],
        **(replace or {}),
    }
    manifest: dict[str, object] = {
        "adb": "keyless",
        "build": "NS6575/8349",
        "format": 1,
        "images": {},
        "product": "laser",
        "serial": SERIAL,
    }
    saved: dict[str, object] = manifest["images"]  # type: ignore[assignment]
    for name, data in content.items():
        (directory / (name + ".img")).write_bytes(data)
        saved[name] = {"sha256": sha(data), "size": len(data)}
    (directory / "bundle.json").write_text(json.dumps(manifest))
    return directory


def rewrite(directory: pathlib.Path, name: str, data: bytes) -> None:
    path = directory / "bundle.json"
    manifest = json.loads(path.read_text())
    (directory / (name + ".img")).write_bytes(data)
    manifest["images"][name] = {"sha256": sha(data), "size": len(data)}
    path.write_text(json.dumps(manifest))


def rig(
    monkeypatch: pytest.MonkeyPatch, failing: tuple[str, int] | None = None
) -> list[list[tuple]]:
    made: list[list[tuple]] = []

    class Transport(StubTransport):
        def __init__(self, serial: str) -> None:
            super().__init__(serial)
            made.append(self.calls)

    Transport.failing = failing
    monkeypatch.setattr(laser, "Transport", Transport)
    monkeypatch.setattr(laser, "wait_adb", lambda *_args, **_kwargs: None)
    answers = {
        "getenforce": "Enforcing",
        "getprop ro.adb.secure": "0",
        "getprop ro.boot.slot_suffix": "_b",
        "getprop ro.product.device": "laser",
        "getprop service.adb.tcp.port": "-1",
        "id -u": "0",
    }
    monkeypatch.setattr(
        laser, "shell", lambda _serial, command, **_unused: answers[command]
    )
    monkeypatch.setattr(laser, "confirm", lambda **_kwargs: None)
    return made


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize(
    ("answers", "said"),
    [
        ({"getprop ro.boot.slot_suffix": "_a"}, "Slot B did not boot"),
        ({"getprop ro.adb.secure": "1"}, "authentication is still enabled"),
        ({"id -u": "2000"}, "did not provide root"),
        ({"getenforce": "Permissive"}, "SELinux enforcing"),
        ({"getprop service.adb.tcp.port": "5555"}, "USB-only"),
    ],
)
def test_a_boot_that_is_not_the_rooted_image_is_reported(
    tmp_path: pathlib.Path,
    validated: dict[str, bytes],
    monkeypatch: pytest.MonkeyPatch,
    answers: dict[str, str],
    said: str,
) -> None:
    made = rig(monkeypatch)
    rooted = {
        "getenforce": "Enforcing",
        "getprop ro.adb.secure": "0",
        "getprop ro.boot.slot_suffix": "_b",
        "getprop ro.product.device": "laser",
        "getprop service.adb.tcp.port": "-1",
        "id -u": "0",
        **answers,
    }
    monkeypatch.setattr(
        laser, "shell", lambda _serial, command, **_unused: rooted[command]
    )
    with pytest.raises(FatalError, match=said):
        laser.run(
            bundle_dir=make_bundle(tmp_path, validated),
            check=False,
            force=True,
            select_a=False,
            serial=SERIAL,
        )
    assert [call[1] for call in made[-1][2:]] == [
        "boot_b",
        "uboot_b",
        "system_b",
        "misc",
    ]


def test_a_failed_upload_waits_for_the_next_window(windows: Windows) -> None:
    windows.failing = 1
    windows.when = lambda now: 0.4 < now < 1.0 or now > 1.5
    laser.through_window(b"loader", fresh=True, seconds=120)
    assert windows.uploads == [(PORT, b"loader")]
    assert windows.warnings == [
        (
            "That window did not take the loader (BL2 response mismatch; no further"
            " command sent). Power-cycle the Echo to offer another"
        )
    ]


def test_a_failed_write_stops_before_misc(
    tmp_path: pathlib.Path,
    validated: dict[str, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = make_bundle(tmp_path, validated)
    rewrite(directory, "system_a", bytes(SYSTEM) + b"x" * (30 * 4096))
    monkeypatch.setattr(laser, "DOWNLOAD_LIMIT", 0x8000)
    made = rig(monkeypatch, failing=("system_b", 2))
    with pytest.raises(
        FatalError, match="Writing system_b failed; nothing after it was written"
    ):
        laser.run(
            bundle_dir=directory,
            check=False,
            force=True,
            select_a=False,
            serial=SERIAL,
        )
    assert [call[:2] for call in made[-1][2:]] == [
        ("flash", "boot_b"),
        ("flash", "uboot_b"),
        ("flash", "system_b"),
        ("flash", "system_b"),
    ]


def test_a_fresh_window_is_caught_and_given_one_attempt(windows: Windows) -> None:
    windows.when = lambda now: now > 0.5
    laser.through_window(b"loader", fresh=True, seconds=120)
    assert windows.uploads == [(PORT, b"loader")]
    assert windows.warnings == []
    assert windows.attempts == 1


def test_a_port_that_is_not_openable_yet_is_retried(windows: Windows) -> None:
    windows.unopenable_until = 0.9
    windows.when = lambda now: now > 0.5
    laser.through_window(b"loader", fresh=True, seconds=120)
    assert windows.uploads == [(PORT, b"loader")]
    assert windows.warnings == []
    assert windows.attempts > 1


def test_a_port_unopenable_beyond_its_grace_is_left_until_it_comes_back(
    windows: Windows,
) -> None:
    windows.unopenable_until = 3.2
    windows.when = lambda now: 0.5 < now < 3.0 or now > 3.5
    laser.through_window(b"loader", fresh=True, seconds=120)
    assert windows.uploads == [(PORT, b"loader")]
    assert windows.warnings == [f"{PORT} stayed unopenable for 0.9 s: busy"]


def test_after_a_reset_a_dead_port_is_left_until_it_comes_back(
    windows: Windows,
) -> None:
    windows.when = lambda now: now < 1.0 or now > 1.5
    laser.through_window(b"loader", fresh=False, seconds=120)
    assert windows.uploads == [(PORT, b"loader")]
    assert windows.warnings == []


def test_an_echo_already_on_is_refused_for_a_fresh_window(windows: Windows) -> None:
    windows.always = [PORT]
    with pytest.raises(FatalError, match="already on"):
        laser.through_window(b"loader", fresh=True, seconds=120)
    assert windows.uploads == []


def test_an_echo_powered_on_too_early_is_refused(
    windows: Windows, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(laser, "POWER_ON", 10.0)
    windows.when = lambda now: now > 0.5
    with pytest.raises(FatalError, match="powered on before"):
        laser.through_window(b"loader", fresh=True, seconds=120)
    assert windows.uploads == []


def test_an_install_waits_for_the_echo_and_checks_it(
    tmp_path: pathlib.Path, validated: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    waiting = laser.wait_adb
    made = rig(monkeypatch)
    monkeypatch.setattr(laser, "wait_adb", waiting)
    asked: list[list[str]] = []

    def done(arguments: list[str], **_options: object) -> subprocess.CompletedProcess:
        asked.append(arguments)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(laser.subprocess, "run", done)
    monkeypatch.setattr(laser.time, "monotonic", iter([0, 1]).__next__)
    laser.run(
        bundle_dir=make_bundle(tmp_path, validated),
        check=False,
        force=True,
        select_a=False,
        serial=SERIAL,
    )
    assert asked == [["adb", "-s", SERIAL, "get-state"]]
    assert [call[1] for call in made[-1][2:]] == [
        "boot_b",
        "uboot_b",
        "system_b",
        "misc",
    ]


def test_await_loader_polls_fastboot_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = laser.Transport(SERIAL)
    answers = iter([
        "",
        f"{SERIAL}X\tAndroid Fastboot\n",
        ("no permissions (missing udev rules? user is in the plugdev group?)\n"),
        f"other\tdevice\n{SERIAL}\tfastboot\n",
    ])
    monkeypatch.setattr(laser, "fastboot_devices", lambda: next(answers, ""))
    monkeypatch.setattr(laser.time, "monotonic", itertools.count(0, 3).__next__)
    monkeypatch.setattr(laser.time, "sleep", lambda _seconds: None)
    transport.await_loader()
    with pytest.raises(FatalError, match="did not appear"):
        transport.await_loader()


@pytest.mark.parametrize(
    "problem",
    [
        "wrong-device",
        "other-build",
        "old-bundle",
        "unknown-image",
        "missing",
        "symlink",
        "oversize",
        "checksum",
        "magic",
        "malformed",
        "manifest-link",
        "boot-not-stock",
        "loader-not-pinned",
        "loader-edited",
        "loader-environment",
        "loader-signature",
        "loader-not-fit",
        "system-not-ext4",
        "system-not-blocks",
    ],
)
def test_bundle_rejected_before_usb(  # ruff: ignore[complex-structure, too-many-branches, too-many-statements]
    tmp_path: pathlib.Path, problem: str, validated: dict[str, bytes]
) -> None:
    directory = make_bundle(tmp_path, validated)
    path = directory / "bundle.json"
    manifest = json.loads(path.read_text())
    access = validated["access"]
    said: str | None = None
    if problem == "wrong-device":
        manifest["serial"] = "WRONG"
    elif problem == "other-build":
        manifest["build"] = "NS6575/8348"
    elif problem == "old-bundle":
        manifest.pop("adb")
    elif problem == "unknown-image":
        manifest["images"]["tee1"] = {}
    elif problem == "missing":
        (directory / "access.img").unlink()
    elif problem == "symlink":
        (directory / "access.img").unlink()
        (directory / "access.img").symlink_to(directory / "system_a.img")
    elif problem == "oversize":
        manifest["images"]["access"]["size"] = 9999999
    elif problem == "checksum":
        manifest["images"]["access"]["sha256"] = "0" * 64
    elif problem == "malformed":
        path.write_text("{")
    elif problem == "manifest-link":
        path.rename(path.with_suffix(".saved"))
        path.symlink_to(path.with_suffix(".saved"))
    elif problem == "boot-not-stock":
        rewrite(directory, "boot_b", b"\xd0\x0d\xfe\xed" + b"another boot" + bytes(20))
        said = "stock 8349 boot image"
    elif problem == "loader-not-pinned":
        rewrite(directory, "access", fit_image(b"another payload" * 25, stock=STOCK))
        said = "not the one validated"
    elif problem == "loader-edited":
        at = access.index(b"access payload")
        rewrite(
            directory, "access", access[:at] + b"ACCESS PAYLOAD" + access[at + 14 :]
        )
        said = "edited after sealing"
    elif problem == "loader-environment":
        at = access.index(b"u-boot\0", access.index(b"u-boot\0") + 1)
        rewrite(directory, "access", access[:at] + b"U-Boot\0" + access[at + 7 :])
        said = "differs from the stock loader"
    elif problem == "loader-signature":
        at = access.rindex(b"\xbc") - 20
        rewrite(
            directory,
            "access",
            access[:at] + bytes([access[at] ^ 0xFF]) + access[at + 1 :],
        )
        said = "does not verify"
    elif problem == "loader-not-fit":
        rewrite(directory, "access", b"\xd0\x0d\xfe\xed" + bytes(900))
        said = "not a loader FIT"
    elif problem == "system-not-ext4":
        rewrite(directory, "system_a", bytes(len(SYSTEM)))
        said = "Unexpected bundle image format"
    elif problem == "system-not-blocks":
        odd = bytearray(4097)
        odd[0x438:0x43A] = b"\x53\xef"
        rewrite(directory, "system_a", bytes(odd))
        said = "multiple of the block size"
    elif problem == "magic":
        rewrite(directory, "access", b"garbage")
        said = "Unexpected bundle image format"
    if problem in {
        "wrong-device",
        "other-build",
        "old-bundle",
        "unknown-image",
        "oversize",
        "checksum",
    }:
        path.write_text(json.dumps(manifest))
    with pytest.raises(FatalError) as stopped:
        laser.load_bundle(directory, SERIAL)
    assert said is None or said in stopped.value.message


def test_check_mode_makes_no_writes(
    tmp_path: pathlib.Path, validated: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    made = rig(monkeypatch)
    laser.run(
        bundle_dir=make_bundle(tmp_path, validated),
        check=True,
        force=True,
        select_a=False,
        serial=SERIAL,
    )
    assert [call[0] for call in made[-1]] == ["load", "rehearse"]


def test_fastboot_devices_failure_is_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_arguments: object, **_options: object) -> subprocess.CompletedProcess:
        said = "no fastboot"
        raise OSError(said)

    monkeypatch.setattr(laser.subprocess, "run", boom)
    with pytest.raises(FatalError, match="did not answer"):
        laser.fastboot_devices()


def test_fastboot_reports_what_went_wrong(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = laser.Transport(SERIAL)
    asked: list[tuple[list[str], dict[str, object]]] = []

    def done(arguments: list[str], **options: object) -> subprocess.CompletedProcess:
        asked.append((arguments, options))
        return subprocess.CompletedProcess(
            arguments, 0, stdout=b"(bootloader) product: laser \nOKAY\n"
        )

    monkeypatch.setattr(laser.subprocess, "run", done)
    said = transport.fastboot("getvar", "product", timeout=20)
    assert said == "(bootloader) product: laser \nOKAY\n"
    assert asked == [
        (
            ["fastboot", "-s", SERIAL, "getvar", "product"],
            {
                "check": True,
                "stderr": subprocess.STDOUT,
                "stdout": subprocess.PIPE,
                "timeout": 20,
            },
        )
    ]
    assert transport.variable("product") == "laser"

    def refused(
        arguments: list[str], **_options: object
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            arguments, 0, stdout=b"FAILED (remote: not allowed)"
        )

    monkeypatch.setattr(laser.subprocess, "run", refused)
    with pytest.raises(FatalError, match="reported failure"):
        transport.fastboot("getvar", "product")

    def quiet(arguments: list[str], **_options: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(arguments, 0, stdout=b"OKAY\n")

    monkeypatch.setattr(laser.subprocess, "run", quiet)
    with pytest.raises(FatalError, match="incomplete"):
        transport.variable("product")

    def failed(arguments: list[str], **_options: object) -> subprocess.CompletedProcess:
        output = b"fastboot: error: " + b"y" * 600
        raise subprocess.CalledProcessError(1, arguments, output=output)

    monkeypatch.setattr(laser.subprocess, "run", failed)
    with pytest.raises(FatalError, match="no further writes attempted") as stopped:
        transport.fastboot("flash", "misc", "x")
    assert "fastboot: error" not in stopped.value.message
    assert len(stopped.value.message) < 600

    for error in (subprocess.TimeoutExpired("fastboot", 60), OSError("gone")):

        def died(
            _arguments: list[str], _error: Exception = error, **_options: object
        ) -> subprocess.CompletedProcess:
            raise _error

        monkeypatch.setattr(laser.subprocess, "run", died)
        with pytest.raises(FatalError, match=r"no further writes attempted$"):
            transport.fastboot("reboot")


def test_flash_order_and_boot_checks(
    tmp_path: pathlib.Path,
    validated: dict[str, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    made = rig(monkeypatch)
    laser.run(
        bundle_dir=make_bundle(tmp_path, validated),
        check=False,
        force=True,
        select_a=False,
        serial=SERIAL,
    )
    calls = made[-1]
    assert calls[:2] == [
        ("load", validated["access"]),
        ("rehearse", validated["access"]),
    ]
    flashes = calls[2:]
    assert [call[1] for call in flashes] == ["boot_b", "uboot_b", "system_b", "misc"]
    assert flashes[0][2] == validated["boot_b"]
    assert flashes[1][2] == validated["verity"]
    assert sparse.replay([flashes[2][2]], len(SYSTEM)) == bytes(SYSTEM)
    assert flashes[3][2] == laser.misc_image("b")
    assert all(call[0] == "flash" for call in flashes)


@pytest.mark.parametrize(
    "partition", ["uboot_a", "boot_a", "system_a", "recovery", "lk", "tee1", "miscx"]
)
def test_flash_refuses_partitions_outside_slot_b(
    monkeypatch: pytest.MonkeyPatch, partition: str
) -> None:
    transport = laser.Transport(SERIAL)
    asked: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        transport, "fastboot", lambda *arguments, **_options: asked.append(arguments)
    )
    with pytest.raises(FatalError, match="never writes"):
        transport.flash(partition, b"x")
    assert asked == []


def test_flash_without_an_okay_is_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = laser.Transport(SERIAL)
    monkeypatch.setattr(transport, "fastboot", lambda *_a, **_k: "")
    with pytest.raises(FatalError, match="did not confirm"):
        transport.flash("misc", b"x")


def test_flash_writes_through_a_file_that_is_gone_afterwards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = laser.Transport(SERIAL)
    asked: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def fastboot(*arguments: str, **options: object) -> str:
        asked.append((arguments, options))
        return "Sending... OKAY"

    monkeypatch.setattr(transport, "fastboot", fastboot)
    transport.flash("misc", laser.misc_image("b"))
    [(arguments, options)] = asked
    assert arguments[:2] == ("flash", "misc")
    assert options == {"timeout": 1800}
    assert not pathlib.Path(arguments[2]).exists()


@pytest.mark.parametrize(
    ("answers", "said"),
    [
        ({}, None),
        ({"product": "cannoli"}, "Unexpected RAM loader"),
        ({"serialno": "OTHER"}, "serial differs"),
        ({"partition-size:uboot_b": "0x1000"}, "partition size"),
        ({"max-download-size": "0x8000000"}, "max-download-size"),
        ({"max-download-size": "lots"}, "max-download-size"),
    ],
)
def test_identify_checks_identity_and_geometry(
    monkeypatch: pytest.MonkeyPatch, answers: dict[str, str], said: str | None
) -> None:
    transport = laser.Transport(SERIAL)
    geometry = {
        "max-download-size": "0x01e00000",
        "product": "laser",
        "serialno": SERIAL,
        **{
            "partition-size:" + name: hex(size)
            for name, size in laser.PARTITIONS.items()
        },
        **answers,
    }
    monkeypatch.setattr(transport, "variable", geometry.__getitem__, raising=False)
    if said is None:
        transport.identify()
    else:
        with pytest.raises(FatalError, match=said):
            transport.identify()


def test_in_fastboot_recognises_the_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    # what `fastboot devices` printed on 2026-11-26, the access loader in RAM: the
    # serial, a tab, a space and the USB interface's name; a stock fastboot is listed
    # as "fastboot".  The serial is what the route looks for
    loader = SERIAL + "\t Android Fastboot\n"
    stock = SERIAL + "\tfastboot\n"
    not_listed = [
        "",
        ("no permissions (missing udev rules? user is in the plugdev group?)\n"),
        "other\tAndroid Fastboot\n",
        SERIAL + "X\tAndroid Fastboot\n",
        "other fastboot\n",
    ]
    answers = iter([*not_listed, loader, "", stock])
    monkeypatch.setattr(laser, "fastboot_devices", lambda: next(answers, ""))
    transport = laser.Transport(SERIAL)
    for _ in not_listed:
        assert transport.in_fastboot() is False
    assert transport.in_fastboot() is True
    assert transport.in_fastboot() is False
    assert transport.in_fastboot() is True


def test_laser_cli_dispatches_without_emmc(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_emmc(**_kwargs: object) -> None:
        pytest.fail("Laser entered an eMMC route")

    monkeypatch.setattr(__main__, "choose_target", no_emmc)
    calls = argv(
        monkeypatch,
        "unlock",
        "--device",
        "laser",
        "--bundle",
        "bundle",
        "--serial",
        SERIAL,
        "--check",
    )
    __main__.cli()
    assert calls == [
        {
            "bundle_dir": pathlib.Path("bundle"),
            "check": True,
            "force": False,
            "select_a": False,
            "serial": SERIAL,
        }
    ]


def test_laser_cli_passes_select_a_through(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = argv(
        monkeypatch,
        "unlock",
        "--device",
        "laser",
        "--bundle",
        "bundle",
        "--serial",
        SERIAL,
        "--select-a",
    )
    __main__.cli()
    assert calls[0]["select_a"] is True
    assert calls[0]["check"] is False


@pytest.mark.parametrize(
    "arguments",
    [
        ["unlock", "--device", "laser"],
        ["unlock", "--bundle", "bundle", "--serial", SERIAL],
        ["restore", "--device", "laser", "--bundle", "bundle", "--serial", SERIAL],
        [
            "unlock",
            "--device",
            "laser",
            "--bundle",
            "bundle",
            "--serial",
            SERIAL,
            "--backup",
            "backup",
        ],
        [
            "unlock",
            "--device",
            "cannoli",
            "--bundle",
            "bundle",
            "--serial",
            SERIAL,
            "--backup",
            "backup",
            "--select-a",
        ],
        ["unlock", "--bundle", "bundle", "--serial", SERIAL, "--select-a"],
    ],
)
def test_laser_cli_refuses_incomplete_or_unrelated_options(
    monkeypatch: pytest.MonkeyPatch, arguments: list[str]
) -> None:
    argv(monkeypatch, *arguments)
    with pytest.raises(SystemExit):
        __main__.cli()


def test_load_bundle_verifies_and_cuts_the_system_image(
    tmp_path: pathlib.Path, validated: dict[str, bytes]
) -> None:
    bundle = laser.load_bundle(make_bundle(tmp_path, validated), SERIAL)
    assert bundle.serial == SERIAL
    assert bundle.image("verity").name == "verity.img"
    assert len(bundle.system) == 1
    assert sparse.replay(bundle.system, len(SYSTEM)) == bytes(SYSTEM)
    with pytest.raises(FatalError, match="Unknown Laser image"):
        bundle.image("../../secret")


def test_load_prompts_then_catches_a_fresh_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = laser.Transport(SERIAL)
    order: list[object] = []
    monkeypatch.setattr(
        laser, "power_prompt", functools.partial(order.append, "prompt")
    )
    monkeypatch.setattr(
        transport, "await_loader", functools.partial(order.append, "loader")
    )
    monkeypatch.setattr(
        transport, "identify", functools.partial(order.append, "identify")
    )

    def catch(data: bytes, **options: object) -> None:
        order.append(("catch", data, options))

    monkeypatch.setattr(laser, "through_window", catch)
    transport.load(b"loader")
    assert order == [
        "prompt",
        ("catch", b"loader", {"fresh": True, "seconds": 120, "trace": None}),
        "loader",
        "identify",
    ]


def test_misc_image_selects_a_slot_with_both_successful() -> None:
    image = laser.misc_image("b")
    assert len(image) == 0x80000
    assert image[:0x360] == bytes(0x360)
    assert struct.unpack_from("<I", image, 0x360) == (0x42424100,)
    assert image[0x364:0x367] == b"\x01\xbe\xbf"
    assert laser.misc_image("a")[0x364:0x367] == b"\x01\xbf\xbe"


@pytest.mark.usefixtures("windows")
def test_no_window_at_all_is_fatal() -> None:
    with pytest.raises(FatalError, match="No preloader window was caught in 2 s"):
        laser.through_window(b"loader", fresh=False, seconds=2)


def test_power_prompt_needs_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(laser.sys.stdin, "isatty", lambda: False)
    with pytest.raises(FatalError, match="terminal"):
        laser.power_prompt()
    asked: list[str] = []
    monkeypatch.setattr(laser.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", asked.append)
    laser.power_prompt()
    assert asked == ["Disconnect the Echo's power, wait 5 s, then press Enter: "]


def test_preloader_lists_only_the_download_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ports = [
        types.SimpleNamespace(device="/dev/ttyACM1", pid=0x02C0, vid=0x1949),
        types.SimpleNamespace(device="/dev/ttyACM0", pid=0x2000, vid=0x0E8D),
        types.SimpleNamespace(device="/dev/cu.mi0", pid=0x2000, vid=0x0E8D),
    ]
    monkeypatch.setattr(laser.serial.tools.list_ports, "comports", lambda: ports)
    monkeypatch.setattr(laser.sys, "platform", "linux")
    assert laser.preloader() == ["/dev/cu.mi0", "/dev/ttyACM0"]
    monkeypatch.setattr(laser.sys, "platform", "darwin")
    assert laser.preloader() == ["/dev/cu.mi0"]


@pytest.mark.parametrize(
    "error", [subprocess.TimeoutExpired("fastboot", 60), OSError()]
)
def test_reboot_ignores_a_hanging_fastboot(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    transport = laser.Transport(SERIAL)
    asked: list[list[str]] = []

    def run(arguments: list[str], **_options: object) -> subprocess.CompletedProcess:
        asked.append(arguments)
        raise error

    monkeypatch.setattr(laser.subprocess, "run", run)
    transport.reboot()
    assert asked == [["fastboot", "-s", SERIAL, "reboot"]]


def test_rehearse_catches_before_it_reboots(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = laser.Transport(SERIAL)
    order: list[object] = []
    monkeypatch.setattr(
        transport, "await_loader", functools.partial(order.append, "loader")
    )
    monkeypatch.setattr(
        transport, "identify", functools.partial(order.append, "identify")
    )

    def catch(data: bytes, **options: object) -> None:
        options["ready"].set()
        order.append(("catch", data, sorted(options)))

    monkeypatch.setattr(laser, "through_window", catch)
    monkeypatch.setattr(laser.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(transport, "reboot", functools.partial(order.append, "reboot"))
    monkeypatch.setattr(transport, "in_fastboot", lambda: pytest.fail("asked late"))
    transport.rehearse(b"loader")
    assert order == [
        ("catch", b"loader", ["fresh", "ready", "seconds", "stop", "trace"]),
        "reboot",
        "loader",
        "identify",
    ]


def test_rehearse_stops_early_when_the_echo_stays_in_fastboot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = laser.Transport(SERIAL)
    stopped = threading.Event()

    def catch(
        _data: bytes,
        *,
        ready: threading.Event,
        stop: threading.Event,
        **_options: object,
    ) -> None:
        ready.set()
        assert stop.wait(5)
        stopped.set()
        said = "No preloader window was caught in 600 s"
        raise FatalError(message=said)

    monkeypatch.setattr(laser, "through_window", catch)
    monkeypatch.setattr(laser.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(transport, "reboot", lambda: None)
    monkeypatch.setattr(transport, "in_fastboot", lambda: True)
    with pytest.raises(FatalError, match="in fastboot again") as raised:
        transport.rehearse(b"loader")
    assert "nothing was written" in raised.value.message
    assert stopped.is_set()


def test_rehearse_stops_when_no_window_is_caught(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = laser.Transport(SERIAL)
    reboots: list[object] = []

    def catch(_data: bytes, *, ready: threading.Event, **_options: object) -> None:
        ready.set()
        said = "none came"
        raise FatalError(message=said)

    monkeypatch.setattr(laser, "through_window", catch)
    monkeypatch.setattr(laser.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(transport, "reboot", lambda: reboots.append(None))
    with pytest.raises(
        FatalError, match=r"rescue move is not shown.*none came"
    ) as stopped:
        transport.rehearse(b"loader")
    assert "nothing was written" in stopped.value.message
    assert reboots == [None]


def test_select_a_in_check_mode_writes_nothing(
    tmp_path: pathlib.Path, validated: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    made = rig(monkeypatch)
    laser.run(
        bundle_dir=make_bundle(tmp_path, validated),
        check=True,
        force=True,
        select_a=True,
        serial=SERIAL,
    )
    assert [call[0] for call in made[-1]] == ["load"]


def test_select_a_writes_only_the_slot_block(
    tmp_path: pathlib.Path, validated: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    made = rig(monkeypatch)
    laser.run(
        bundle_dir=make_bundle(tmp_path, validated),
        check=False,
        force=True,
        select_a=True,
        serial=SERIAL,
    )
    assert made[-1] == [
        ("load", validated["access"]),
        ("flash", "misc", laser.misc_image("a")),
    ]


def test_shell_failure_is_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: str, **_kwargs: object) -> subprocess.CompletedProcess:
        raise subprocess.CalledProcessError(1, "adb")

    monkeypatch.setattr(laser.subprocess, "run", boom)
    with pytest.raises(FatalError):
        laser.shell(SERIAL, "id -u")


def test_shell_returns_what_the_echo_said(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[list[str]] = []

    def done(arguments: list[str], **_options: object) -> subprocess.CompletedProcess:
        asked.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, stdout=b"0\n")

    monkeypatch.setattr(laser.subprocess, "run", done)
    assert laser.shell(SERIAL, "id -u") == "0"
    assert asked == [["adb", "-s", SERIAL, "shell", "id -u"]]


@pytest.mark.usefixtures("windows")
def test_through_window_signals_when_it_is_listening() -> None:
    ready = threading.Event()
    with pytest.raises(FatalError):
        laser.through_window(b"loader", fresh=False, ready=ready, seconds=1)
    assert ready.is_set()


def test_traced_prints_the_time_and_the_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    laser.traced("tx a0")
    assert capsys.readouterr().out.strip().endswith("tx a0")


def test_transport_refuses_an_odd_serial() -> None:
    for serial in ("has space", "x" * 65, "", "sl/sh", "new\nline"):
        with pytest.raises(FatalError, match="USB serial"):
            laser.Transport(serial)
    assert laser.Transport("dash-ok_under").serial == "dash-ok_under"


def test_two_preloader_ports_are_refused(windows: Windows) -> None:
    windows.always = [PORT, "/dev/ttyACM9"]
    with pytest.raises(FatalError, match="Multiple preloader ports"):
        laser.through_window(b"loader", fresh=False, seconds=2)


def test_wait_adb_waits_for_the_echo_and_names_the_way_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked: list[list[str]] = []

    def run(arguments: list[str], **_options: object) -> subprocess.CompletedProcess:
        asked.append(arguments)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(laser.subprocess, "run", run)
    monkeypatch.setattr(laser.time, "monotonic", iter([0, 1]).__next__)
    monkeypatch.setattr(laser, "shell", lambda *_a, **_k: "cannoli")
    with pytest.raises(FatalError, match="not Laser"):
        laser.wait_adb(SERIAL, seconds=240)
    assert asked == [["adb", "-s", SERIAL, "get-state"]]

    def none(*_arguments: object, **_options: object) -> subprocess.CompletedProcess:
        said = "no adb"
        raise OSError(said)

    monkeypatch.setattr(laser.subprocess, "run", none)
    monkeypatch.setattr(laser.time, "monotonic", iter([0, 301]).__next__)
    monkeypatch.setattr(laser.time, "sleep", lambda _seconds: None)
    with pytest.raises(FatalError, match="--select-a"):
        laser.wait_adb(SERIAL, seconds=300)
