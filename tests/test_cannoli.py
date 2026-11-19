from __future__ import annotations

import hashlib
import json
import subprocess
import types
from typing import TYPE_CHECKING

import pytest

from firebreak import __main__, cannoli, ubi
from firebreak.ui import FatalError

if TYPE_CHECKING:
    import pathlib
    import threading

SERIAL = "TEST1234"


class Device:
    @staticmethod
    def shell(command: str) -> str:
        return {
            "getenforce": "Enforcing",
            "getprop ro.adb.secure": "0",
            "getprop ro.boot.slot_suffix": "_a",
            "getprop ro.product.device": "cannoli",
            "getprop service.adb.tcp.port": "-1",
            "id -u": "0",
        }[command]

    @staticmethod
    def volumes() -> dict[str, ubi.Volume]:
        return {
            name: ubi.Volume(name, f"/dev/ubi0_{index}", 2000000, 2000000, 0)
            for index, name in enumerate((
                *ubi.BACKUP_VOLUMES,
                *cannoli.PREREQUISITES,
                "mcupm_b",
                "scp_b",
            ))
        }

    def __init__(self, bundle: cannoli.Bundle) -> None:
        self.bundle = bundle
        self.serial = SERIAL
        self.actions = []
        self.saved = {}
        self.failed = None

    def backup(self, *_args: object) -> None:
        self.actions.append("backup")

    def check(self) -> None:
        self.actions.append("check")

    def command(self, *args: object, **_kwargs: object) -> None:
        self.actions.append(args)

    def remote_digest(self, volume: ubi.Volume, _size: int | None = None) -> str:
        if volume.name in cannoli.PREREQUISITES:
            return cannoli.PREREQUISITES[volume.name][1]
        return ubi.digest(self.bundle.image(volume.name))

    def stage_helper(self, _helper: pathlib.Path) -> None:
        self.actions.append("stage_helper")

    def unmounted(self, volumes: dict[str, ubi.Volume]) -> None:
        self.actions.append(("unmounted", set(volumes)))

    def write(self, volume: ubi.Volume, image: pathlib.Path) -> None:
        self.actions.append(("write", volume.name))
        if self.failed == volume.name:
            raise FatalError(message="interrupted write")
        self.saved[volume.name] = image


class Link:
    @staticmethod
    def variable(name: str) -> str:
        return hex(cannoli.LIMITS[name.split(":")[1]])

    def __init__(self) -> None:
        self.actions = []

    def fastboot(self, *args: object) -> None:
        self.actions.append(args)

    def ram(self, image: pathlib.Path, product: object) -> None:
        self.actions.append(("ram", image.stem, product))


@pytest.fixture
def bundle(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> cannoli.Bundle:
    directory = tmp_path / "bundle"
    directory.mkdir()
    manifest = {
        "adb": "keyless",
        "build": "NS6575/8349",
        "format": 1,
        "images": {},
        "product": "cannoli",
        "serial": SERIAL,
    }
    for name in cannoli.LIMITS:
        data = (
            b"\x7fELF"
            if name == "ubivol"
            else b"hsqs"
            if name == "system_a"
            else b"\xd0\x0d\xfe\xed"
        ) + name.encode()
        path = directory / (name + ".img")
        path.write_bytes(data)
        manifest["images"][name] = {"sha256": ubi.digest(path), "size": len(data)}
    monkeypatch.setattr(cannoli, "STOCK_BOOT", manifest["images"]["boot_a"]["sha256"])
    (directory / "bundle.json").write_text(json.dumps(manifest))
    return cannoli.load_bundle(directory, SERIAL)


@pytest.fixture
def rig(bundle: cannoli.Bundle, monkeypatch: pytest.MonkeyPatch) -> tuple[Device, Link]:
    device, link = Device(bundle), Link()
    monkeypatch.setattr(cannoli, "Recovery", lambda _: device)
    monkeypatch.setattr(cannoli, "Transport", lambda *_: link)
    monkeypatch.setattr(cannoli, "confirm", lambda **_: None)
    return device, link


def invoke(bundle: cannoli.Bundle, tmp_path: pathlib.Path, **kwargs: object) -> None:
    cannoli.run(
        backup=tmp_path / "backup",
        check=False,
        directory=bundle.directory,
        force=True,
        serial=SERIAL,
        **kwargs,
    )


def invoke_upgrade(
    bundle: cannoli.Bundle,
    ota: pathlib.Path,
    *,
    check: bool = False,
    force: bool = True,
    serial: str = SERIAL,
) -> None:
    cannoli.upgrade_prerequisites(
        check=check,
        directory=bundle.directory,
        force=force,
        ota=ota,
        serial=serial,
    )


def on_2022_firmware(device: Device, monkeypatch: pytest.MonkeyPatch) -> None:
    def after_write(volume: ubi.Volume, size: int | None = None) -> str:
        path = device.saved.get(volume.name)
        if path is None:
            return "0" * 64
        data = path.read_bytes()
        if size is not None:
            data = data[:size]
        return hashlib.sha256(data).hexdigest()

    monkeypatch.setattr(device, "remote_digest", after_write)


@pytest.mark.parametrize(
    "problem",
    [
        "wrong-device",
        "old-bundle",
        "unknown-image",
        "missing",
        "symlink",
        "oversize",
        "checksum",
        "magic",
        "stock-boot",
        "malformed",
        "manifest-link",
    ],
)
def test_bundle_rejected_before_usb(  # ruff: ignore[complex-structure]
    bundle: cannoli.Bundle, monkeypatch: pytest.MonkeyPatch, problem: str
) -> None:
    path = bundle.directory / "bundle.json"
    report = json.loads(path.read_text())
    image = bundle.image("access")
    if problem == "wrong-device":
        report["serial"] = "WRONG"
    elif problem == "old-bundle":
        report.pop("adb")
    elif problem == "unknown-image":
        report["images"]["tee1"] = {}
    elif problem == "missing":
        image.unlink()
    elif problem == "symlink":
        image.unlink()
        image.symlink_to(bundle.image("select-a"))
    elif problem == "oversize":
        report["images"]["access"]["size"] = 9999999
    elif problem == "checksum":
        report["images"]["access"]["sha256"] = "0" * 64
    elif problem == "magic":
        image.write_bytes(b"garbage")
        report["images"]["access"] = {"sha256": ubi.digest(image), "size": 7}
    elif problem == "stock-boot":
        monkeypatch.setattr(cannoli, "STOCK_BOOT", "0" * 64)
    if problem == "malformed":
        path.write_text("{")
    elif problem == "manifest-link":
        path.rename(path.with_suffix(".saved"))
        path.symlink_to(path.with_suffix(".saved"))
    else:
        path.write_text(json.dumps(report))
    with pytest.raises(FatalError):
        cannoli.load_bundle(bundle.directory, SERIAL)
    with pytest.raises(FatalError):
        bundle.image("../../secret")


def test_cannoli_cli_dispatches_without_emmc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        __main__.sys,
        "argv",
        [
            "firebreak",
            "unlock",
            "--device",
            "cannoli",
            "--bundle",
            "bundle",
            "--serial",
            SERIAL,
            "--check",
            "--no-update-check",
        ],
    )
    for name in ("check_python", "check_user", "check_adb", "make_cache"):
        monkeypatch.setattr(__main__, name, lambda: None)
    monkeypatch.setattr(__main__.shutil, "which", lambda **_: "tool")
    calls = []
    monkeypatch.setattr(cannoli, "run", lambda **kwargs: calls.append(kwargs))

    def no_emmc(**_kwargs: object) -> None:
        pytest.fail("Cannoli entered an eMMC route")

    monkeypatch.setattr(__main__, "choose_target", no_emmc)
    __main__.cli()
    assert calls[0]["check"]
    assert calls[0]["serial"] == SERIAL


@pytest.mark.parametrize(
    "arguments",
    [
        ["unlock", "--device", "cannoli"],
        ["unlock", "--bundle", "bundle", "--serial", SERIAL],
        ["unlock", "--device", "cannoli", "--bundle", "bundle", "--serial", SERIAL],
        [
            "unlock",
            "--device",
            "cannoli",
            "--bundle",
            "bundle",
            "--serial",
            SERIAL,
            "--factory-reset",
            "--backup",
            "backup",
        ],
        ["stock", "--device", "cannoli"],
    ],
)
def test_cannoli_cli_refuses_incomplete_or_unrelated_options(
    arguments: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(__main__.sys, "argv", ["firebreak", *arguments])
    with pytest.raises(SystemExit) as caught:
        __main__.parsed()
    assert caught.value.code == 2


def test_changed_b_stops_before_selecting_a(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, link = rig
    original = device.remote_digest
    monkeypatch.setattr(
        device,
        "remote_digest",
        lambda volume, size=None: (
            "changed"
            if volume.name == "boot_b" and device.saved
            else original(volume, size)
        ),
    )
    with pytest.raises(FatalError, match="slot B changed"):
        invoke(bundle, tmp_path)
    assert not any(action[:2] == ("ram", "select-a") for action in link.actions)


def test_fastboot_and_variable_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    link = cannoli.Transport(SERIAL)

    def result(*_args: object, **_kwargs: object) -> types.SimpleNamespace:
        return types.SimpleNamespace(stdout=b"(bootloader) product: cannoli\nFinished")

    monkeypatch.setattr(subprocess, "run", result)
    assert link.variable("product") == "cannoli"
    with pytest.raises(FatalError, match="incomplete"):
        link.variable("serialno")
    monkeypatch.setattr(
        subprocess, "run", lambda *_a, **_k: types.SimpleNamespace(stdout=b"FAILED")
    )
    with pytest.raises(FatalError):
        link.fastboot("reboot")

    def fails(*_args: object, **_kwargs: object) -> None:
        msg = "USB"
        raise OSError(msg)

    monkeypatch.setattr(subprocess, "run", fails)
    with pytest.raises(FatalError):
        link.fastboot("reboot")
    with pytest.raises(FatalError):
        cannoli.Transport("../bad")


def test_initial_staging_checks_all_capacities_before_writing(
    bundle: cannoli.Bundle,
) -> None:
    device, link = Device(bundle), Link()
    count = [0]

    def check() -> None:
        count[0] += 1
        if count[0] == 1:
            raise FatalError(message="Boot Cannoli slot B TWRP first")

    device.check = check
    cannoli.start_recovery(bundle, link, device)
    assert link.actions[:4] == [
        ("ram", "access", "cannoli"),
        ("ram", "select-a", "cannoli-bcb-1"),
        ("flash", "boot_b", str(bundle.image("boot_b"))),
        ("flash", "uboot_b", str(bundle.image("uboot_b"))),
    ]
    count[0] = 0
    link.actions.clear()
    link.variable = lambda _: "1"
    with pytest.raises(FatalError, match="size"):
        cannoli.start_recovery(bundle, link, device)
    assert len(link.actions) == 1


def test_partial_b_flash_keeps_bcb_on_a(bundle: cannoli.Bundle) -> None:
    device, link = Device(bundle), Link()
    count = [0]

    def check() -> None:
        count[0] += 1
        if count[0] == 1:
            raise FatalError(message="Boot Cannoli slot B TWRP first")

    device.check = check

    original_fastboot = link.fastboot

    def failing_fastboot(*args: object) -> None:
        original_fastboot(*args)
        if args[:2] == ("flash", "uboot_b"):
            raise FatalError(message="fastboot flash failed")

    link.fastboot = failing_fastboot

    with pytest.raises(FatalError, match="fastboot flash failed"):
        cannoli.start_recovery(bundle, link, device)

    assert ("flash", "boot_b", str(bundle.image("boot_b"))) in link.actions
    assert ("ram", "select-a", "cannoli-bcb-1") in link.actions
    bcb_index = link.actions.index(("ram", "select-a", "cannoli-bcb-1"))
    flash_boot_index = next(
        i for i, a in enumerate(link.actions) if a[:2] == ("flash", "boot_b")
    )
    assert bcb_index < flash_boot_index
    assert not any(action[:2] == ("ram", "select-b") for action in link.actions)
    assert ("reboot",) not in link.actions


def test_partial_backup_refused_before_writes(
    bundle: cannoli.Bundle, rig: tuple[Device, Link], tmp_path: pathlib.Path
) -> None:
    directory = tmp_path / "backup"
    directory.mkdir()
    (directory / "system_a.bin").write_bytes(b"partial")
    with pytest.raises(FatalError, match="incomplete backup"):
        invoke(bundle, tmp_path)
    assert not rig[1].actions


@pytest.mark.parametrize(
    "problem", ["prerequisite", "recovery", "capacity", "missing-prerequisite"]
)
def test_preflight_failure_prevents_a_writes(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    problem: str,
) -> None:
    device, link = rig
    if problem in {"prerequisite", "recovery"}:
        old = device.remote_digest
        monkeypatch.setattr(
            device,
            "remote_digest",
            lambda volume, size=None: (
                "0" * 64
                if volume.name == ("tee1" if problem == "prerequisite" else "boot_b")
                else old(volume, size)
            ),
        )
    else:
        volumes = device.volumes()
        if problem == "capacity":
            volumes["system_a"] = ubi.Volume("system_a", "/dev/ubi0_1", 1, 1, 0)
        else:
            del volumes["tee1"]
        monkeypatch.setattr(device, "volumes", lambda: volumes)
    with pytest.raises(FatalError):
        invoke(bundle, tmp_path)
    assert "backup" not in device.actions
    assert device.saved == {}
    assert not any(action[:2] == ("ram", "select-a") for action in link.actions)


def test_ram_listener_starts_before_power_prompt(
    bundle: cannoli.Bundle, monkeypatch: pytest.MonkeyPatch
) -> None:
    actions = []
    link = cannoli.Transport(SERIAL)

    class Port:
        def __enter__(self) -> object:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

    def listen(*, ready: threading.Event) -> Port:
        actions.append("listen")
        ready.set()
        return Port()

    monkeypatch.setattr(cannoli.bl2, "listen", listen)
    monkeypatch.setattr(cannoli.bl2, "upload", lambda *_: actions.append("upload"))
    monkeypatch.setattr(
        link, "variable", lambda name: "cannoli" if name == "product" else SERIAL
    )
    monkeypatch.setattr("builtins.input", lambda _: "")
    link.ram(bundle.image("access"), "cannoli")
    assert actions == ["listen", "upload"]
    monkeypatch.setattr(link, "variable", lambda _: "WRONG")
    with pytest.raises(FatalError, match="Unexpected RAM"):
        link.ram(bundle.image("access"), "cannoli")


def test_read_only_check_has_no_backup_or_writes(
    bundle: cannoli.Bundle, rig: tuple[Device, Link]
) -> None:
    device, link = rig
    cannoli.run(
        backup=None,
        check=True,
        directory=bundle.directory,
        force=False,
        serial=SERIAL,
    )
    assert link.actions == []
    assert device.saved == {}
    assert "backup" not in device.actions


def test_restore_can_boot_a(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cannoli,
        "load_backup",
        lambda *_: {"volumes": {name: {"size": 5} for name in ubi.A_VOLUMES}},
    )
    invoke(bundle, tmp_path, end_in_fireos=True, restore=True)
    assert rig[1].actions[-2:] == [("ram", "select-a", "cannoli-bcb-1"), ("reboot",)]


def test_restore_validates_first_and_preserves_b(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, link = rig
    calls = []

    def load(*_args: object) -> dict:
        calls.append(tuple(link.actions))
        return {"volumes": {name: {"size": 5} for name in ubi.A_VOLUMES}}

    monkeypatch.setattr(cannoli, "load_backup", load)
    invoke(bundle, tmp_path, restore=True)
    assert calls[0] == ()
    assert list(device.saved) == list(ubi.A_VOLUMES)
    assert all(path.suffix == ".bin" for path in device.saved.values())
    assert "backup" not in device.actions
    assert not any(action[:2] == ("ram", "select-a") for action in link.actions)


def test_unlock_orders_backup_writes_and_slot_selection(
    bundle: cannoli.Bundle, rig: tuple[Device, Link], tmp_path: pathlib.Path
) -> None:
    device, link = rig
    invoke(bundle, tmp_path)
    assert device.actions.index("backup") < device.actions.index(("write", "system_a"))
    assert list(device.saved) == list(ubi.A_VOLUMES)
    assert link.actions == [
        ("ram", "select-b", "cannoli-bcb-1"),
        ("reboot",),
        ("ram", "select-a", "cannoli-bcb-1"),
        ("reboot",),
    ]


@pytest.mark.parametrize(
    "case",
    [
        ("ro.adb.secure", "1", "authentication"),
        ("ro.boot.slot_suffix", "_b", "Slot A did not boot"),
    ],
)
def test_unlock_rejects_authenticated_or_wrong_slot_boot(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[str, str, str],
) -> None:
    property_name, value, message = case
    device, _link = rig
    original = device.shell
    monkeypatch.setattr(
        device,
        "shell",
        lambda command: (
            value if command == "getprop " + property_name else original(command)
        ),
    )
    with pytest.raises(FatalError, match=message):
        invoke(bundle, tmp_path)


def test_upgrade_asks_before_writing(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prereqs, parts = upgrade_parts(bundle, tmp_path)
    monkeypatch.setattr(cannoli, "PREREQUISITES", prereqs)
    device, _link = rig
    on_2022_firmware(device, monkeypatch)
    asked = []

    def record(**what: object) -> None:
        asked.append(what)
        asked.append(list(device.actions))

    monkeypatch.setattr(cannoli, "confirm", record)
    invoke_upgrade(bundle, parts, force=False)
    assert asked
    assert "eFuse" in asked[0]["what"]
    assert "stage_helper" not in asked[1]
    assert not [action for action in asked[1] if action[:1] == ("write",)]


def test_upgrade_check_reports_without_writing(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prereqs, parts = upgrade_parts(bundle, tmp_path)
    monkeypatch.setattr(cannoli, "PREREQUISITES", prereqs)
    device, _link = rig
    on_2022_firmware(device, monkeypatch)
    invoke_upgrade(bundle, parts, check=True)
    assert "check" in device.actions
    assert not [action for action in device.actions if action[:1] == ("write",)]


def test_upgrade_counts_an_interrupted_volume_as_stale(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prereqs, parts = upgrade_parts(bundle, tmp_path)
    monkeypatch.setattr(cannoli, "PREREQUISITES", prereqs)
    device, _link = rig
    on_2022_firmware(device, monkeypatch)
    original = device.volumes

    def with_updating_tee1() -> dict[str, ubi.Volume]:
        volumes = original()
        if "tee1" not in device.saved:
            volumes["tee1"] = ubi.Volume("tee1", "/dev/ubi0_x", 2000000, 2000000, 1)
        return volumes

    device.volumes = with_updating_tee1
    invoke_upgrade(bundle, parts)
    assert "tee1" in device.saved


def test_upgrade_refuses_a_unit_with_missing_volumes(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prereqs, parts = upgrade_parts(bundle, tmp_path)
    monkeypatch.setattr(cannoli, "PREREQUISITES", prereqs)
    device, _link = rig
    original = device.volumes

    def without_scp_b() -> dict[str, ubi.Volume]:
        volumes = original()
        volumes.pop("scp_b")
        return volumes

    device.volumes = without_scp_b
    with pytest.raises(FatalError, match="missing on this unit"):
        invoke_upgrade(bundle, parts)
    assert device.actions == ["check"]


@pytest.mark.parametrize(
    "problem",
    ["hash", "boot", "empty-system", "oversize-system", "missing"],
)
def test_upgrade_rejects_wrong_or_missing_parts(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    problem: str,
) -> None:
    prereqs, parts = upgrade_parts(bundle, tmp_path)
    if problem == "hash":
        (parts / "scp.img").write_bytes(b"2022-launch-scp")
    elif problem == "boot":
        (parts / "boot.img").write_bytes(b"2022-launch-boot")
    elif problem == "empty-system":
        (parts / "system.img").write_bytes(b"")
    elif problem == "oversize-system":
        (parts / "system.img").write_bytes(b"hsqs" + b"0" * 2000000)
    else:
        (parts / "tee2.img").unlink()
    monkeypatch.setattr(cannoli, "PREREQUISITES", prereqs)
    device, _link = rig
    with pytest.raises(FatalError, match=r"differs|missing|not a stock|exceeds"):
        invoke_upgrade(bundle, parts)
    if problem == "oversize-system":
        assert device.actions == ["check"]
    else:
        assert device.actions == []


def test_upgrade_sees_a_padded_volume_as_8349(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prereqs, parts = upgrade_parts(bundle, tmp_path)
    monkeypatch.setattr(cannoli, "PREREQUISITES", prereqs)
    device, _link = rig
    on_2022_firmware(device, monkeypatch)
    for name in cannoli.PREREQUISITES:
        device.saved[name] = parts / cannoli.UPGRADE_PARTS[name]
    with pytest.raises(FatalError, match="already"):
        invoke_upgrade(bundle, parts)
    assert not [action for action in device.actions if action[:1] == ("write",)]


def test_upgrade_writes_nine_volumes_in_order_and_rechecks(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prereqs, parts = upgrade_parts(bundle, tmp_path)
    monkeypatch.setattr(cannoli, "PREREQUISITES", prereqs)
    device, _link = rig
    on_2022_firmware(device, monkeypatch)
    invoke_upgrade(bundle, parts)
    writes = [action for action in device.actions if action[:1] == ("write",)]
    assert [name for _, name in writes] == [
        "system_a",
        "boot_a",
        "uboot_a",
        "mcupm_a",
        "mcupm_b",
        "scp_a",
        "scp_b",
        "tee1",
        "tee2",
    ]
    assert "stage_helper" in device.actions
    assert device.saved["mcupm_b"].name == "mcupm.img"
    assert device.saved["scp_b"].name == "scp.img"


def test_upgrade_writes_nothing_when_declined(
    bundle: cannoli.Bundle,
    rig: tuple[Device, Link],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prereqs, parts = upgrade_parts(bundle, tmp_path)
    monkeypatch.setattr(cannoli, "PREREQUISITES", prereqs)
    device, _link = rig
    on_2022_firmware(device, monkeypatch)

    def declined(**_what: object) -> None:
        raise FatalError(message="declined")

    monkeypatch.setattr(cannoli, "confirm", declined)
    with pytest.raises(FatalError, match="declined"):
        invoke_upgrade(bundle, parts, force=False)
    assert "stage_helper" not in device.actions
    assert not [action for action in device.actions if action[:1] == ("write",)]


def test_wait_recovery_has_deadline(
    monkeypatch: pytest.MonkeyPatch, bundle: cannoli.Bundle
) -> None:
    device = Device(bundle)

    def fails() -> None:
        raise FatalError(message="not ready")

    device.check = fails
    clock = iter([0, 1, 121])
    monkeypatch.setattr(cannoli.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(cannoli.time, "sleep", lambda _: None)
    with pytest.raises(FatalError, match="did not answer"):
        cannoli.wait_recovery(device)


def test_write_failure_never_selects_a(
    bundle: cannoli.Bundle, rig: tuple[Device, Link], tmp_path: pathlib.Path
) -> None:
    device, link = rig
    device.failed = "boot_a"
    with pytest.raises(FatalError, match="interrupted"):
        invoke(bundle, tmp_path)
    assert "uboot_a" not in device.saved
    assert not any(action[:2] == ("ram", "select-a") for action in link.actions)


def upgrade_parts(
    bundle: cannoli.Bundle, tmp_path: pathlib.Path
) -> tuple[dict[str, tuple[int, str]], pathlib.Path]:
    prereqs = {}
    directory = tmp_path / "parts"
    directory.mkdir()
    for name, file in (
        ("mcupm_a", "mcupm.img"),
        ("scp_a", "scp.img"),
        ("tee1", "tee1.img"),
        ("tee2", "tee2.img"),
    ):
        path = directory / file
        path.write_bytes(b"8349-" + file.encode())
        prereqs[name] = (path.stat().st_size, ubi.digest(path))
    (directory / "boot.img").write_bytes(bundle.image("boot_a").read_bytes())
    (directory / "system.img").write_bytes(b"hsqs-system")
    (directory / "uboot.img").write_bytes(b"\xd0\x0d\xfe\xed-uboot")
    return prereqs, directory
