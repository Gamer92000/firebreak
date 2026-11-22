from __future__ import annotations

import concurrent.futures
import dataclasses
import json
import re
import subprocess
import threading
import time
from typing import TYPE_CHECKING

from firebreak.mediatek import bl2
from firebreak.ubi import (
    A_VOLUMES,
    B_VOLUMES,
    Recovery,
    Volume,
    digest,
    load_backup,
    require,
)
from firebreak.ui import FatalError, confirm, passed, say

if TYPE_CHECKING:
    import pathlib

LIMITS = {
    "access": 0x200000,
    "boot_a": 0xD0B000,
    "boot_b": 0xD0B000,
    "select-a": 0x200000,
    "select-b": 0x200000,
    "system_a": 131088384,
    "ubivol": 1024 * 1024,
    "uboot_a": 0xFC000,
    "uboot_b": 0xFC000,
}
PREREQUISITES = {
    "mcupm_a": (
        122880,
        (
            "37857df6481383e0a2a69d1e4e27935cb64f5b1df17fa5f74b77ab647c8dcaed",
            "34a6616b9c8c80ec8351d64214b9910dae78865c39cd379515a415ea9ae3ee60",
        ),
    ),
    "scp_a": (
        1028096,
        (
            "e241c5c3faa563efd48dd6a2361d4a1b04ecf9faecf4fc73d6ba5d0f505d20ba",
            "79332b506f031418d0db06f31ad809be21a022d97833047ca2a05f4c588b5fa5",
        ),
    ),
    "tee1": (
        647168,
        (
            "b3be918bb0e3dd74e5e7b436809bfd83b9667e9ce58c0081e29aa8d78e7199d6",
            "05d4f64defb7bc528bc69945acab41f4974ee0fb6d4fc8e54b8e561584ce2296",
        ),
    ),
    "tee2": (
        647168,
        (
            "b3be918bb0e3dd74e5e7b436809bfd83b9667e9ce58c0081e29aa8d78e7199d6",
            "05d4f64defb7bc528bc69945acab41f4974ee0fb6d4fc8e54b8e561584ce2296",
        ),
    ),
}
STOCK_BOOT = "548dd73848cfcc76cb921ec5d8c68438c95886f4fc7187da9fa5f4b7efb8b201"
UPGRADE_ORDER = (
    "system_a",
    "boot_a",
    "uboot_a",
    "mcupm_a",
    "mcupm_b",
    "scp_a",
    "scp_b",
    "tee1",
    "tee2",
)
UPGRADE_PARTS = {
    "boot_a": "boot.img",
    "mcupm_a": "mcupm.img",
    "mcupm_b": "mcupm.img",
    "scp_a": "scp.img",
    "scp_b": "scp.img",
    "system_a": "system.img",
    "tee1": "tee1.img",
    "tee2": "tee2.img",
    "uboot_a": "uboot.img",
}


@dataclasses.dataclass(frozen=True)
class Bundle:
    directory: pathlib.Path
    serial: str
    checksum: str

    def image(self, name: str) -> pathlib.Path:
        require(name in LIMITS, "Unknown Cannoli image")
        return self.directory / (name + ".img")


class Transport:
    def __init__(self, serial: str) -> None:
        self.serial = Recovery(serial).serial

    def fastboot(self, *arguments: str, timeout: int = 180) -> str:
        try:
            result = subprocess.run(
                ["fastboot", "-s", self.serial, *arguments],
                check=True,
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                timeout=timeout,
            )
        except (subprocess.SubprocessError, OSError) as error:
            raise FatalError(
                message="Cannoli fastboot failed; no further writes attempted"
            ) from error
        text = result.stdout.decode()
        require("FAILED" not in text, "Fastboot reported failure")
        return text

    def ram(self, image: pathlib.Path, product: str) -> None:
        data = image.read_bytes()
        say(text=f"Loading {image.stem} into RAM")
        input("Disconnect Echo power, then press Enter: ")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            ready = threading.Event()
            future = pool.submit(bl2.listen, ready=ready)
            require(ready.wait(5), "BL2 listener did not start")
            print("Listener ready. Connect Echo power now.", flush=True)
            with future.result(timeout=50) as port:
                bl2.upload(port, data)
        require(
            self.variable("product") == product,
            "Unexpected RAM loader; stop before writing flash",
        )
        require(self.variable("serialno") == self.serial, "Fastboot serial differs")
        passed(message="RAM fastboot identity verified")

    def variable(self, name: str) -> str:
        text = self.fastboot("getvar", name, timeout=20)
        found = re.search(
            r"(?:^|\n)(?:\(bootloader\) )?" + re.escape(name) + r":\s*(\S+)", text
        )
        require(found is not None, "Fastboot variable response was incomplete")
        return found[1]


def carries_8349(recovery: Recovery, volume: Volume) -> bool:
    size, checksums = PREREQUISITES[volume.name]
    return (
        not volume.updating
        and volume.used >= size
        and recovery.remote_digest(volume, size) in checksums
    )


def load_bundle(directory: pathlib.Path, serial: str) -> Bundle:
    try:  # ruff: ignore[too-many-statements-in-try-clause]
        path = directory / "bundle.json"
        require(not path.is_symlink(), "Bundle manifest must not be a symlink")
        manifest = json.loads(path.read_text())
        require(
            manifest["format"] == 1
            and manifest["product"] == "cannoli"
            and manifest["build"] == "NS6575/8349"
            and manifest["serial"] == serial,
            "Bundle is not for this Cannoli serial and build",
        )
        require(
            manifest.get("adb") == "keyless",
            "Bundle predates keyless ADB; rebuild it with a current OS builder",
        )
        require(set(manifest["images"]) == set(LIMITS), "Bundle image set differs")
        bundle = Bundle(directory, serial, digest(path))
        for name, maximum in LIMITS.items():
            image = bundle.image(name)
            saved = manifest["images"][name]
            require(
                not image.is_symlink() and image.is_file(),
                "Bundle image is missing or a symlink",
            )
            size = image.stat().st_size
            require(
                0 < size <= maximum and size == saved["size"],
                "Bundle image size differs or exceeds its limit",
            )
            require(digest(image) == saved["sha256"], "Bundle checksum mismatch")
            with image.open("rb") as source:
                magic = source.read(4)
            require(
                magic
                == (
                    b"\x7fELF"
                    if name == "ubivol"
                    else b"hsqs"
                    if name == "system_a"
                    else b"\xd0\x0d\xfe\xed"
                ),
                "Unexpected bundle image format",
            )
        require(
            digest(bundle.image("boot_a")) == STOCK_BOOT,
            "Slot A requires the stock 8349 boot image",
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise FatalError(
            message=(
                "Invalid Cannoli bundle; rebuild it with cannoli-os-builder "
                "(see docs/cannoli.md)"
            )
        ) from error

    return bundle


def preflight(bundle: Bundle, recovery: Recovery) -> dict[str, Volume]:
    recovery.check()
    volumes = recovery.volumes()
    require(
        set(PREREQUISITES).issubset(volumes), "8349 prerequisite volumes are missing"
    )
    for name, (size, checksums) in PREREQUISITES.items():
        require(
            recovery.remote_digest(volumes[name], size) in checksums,
            "Unsupported firmware prerequisite: "
            + name
            + "; cannoli-upgrade brings an older unit up to 8349",
        )
    for name in B_VOLUMES:
        image = bundle.image(name)
        require(
            recovery.remote_digest(volumes[name], image.stat().st_size)
            == digest(image),
            "Recovery slot B differs from the bundle",
        )
    for name in A_VOLUMES:
        require(
            bundle.image(name).stat().st_size <= volumes[name].capacity,
            "Slot A image exceeds device capacity",
        )
    recovery.unmounted({name: volumes[name] for name in A_VOLUMES})
    return volumes


def resolve_upgrade_parts(ota: pathlib.Path) -> dict[str, pathlib.Path]:
    require(
        bool(ota.is_dir() and not ota.is_symlink()),
        "Use the unpacked 8349 OTA parts directory",
    )
    parts = {}
    for name, file in UPGRADE_PARTS.items():
        image = ota / file
        require(
            bool(image.is_file() and not image.is_symlink()),
            "OTA part missing or not a regular file: " + file,
        )
        parts[name] = image
    return parts


def run(  # ruff: ignore[too-many-arguments]
    *,
    backup: pathlib.Path,
    check: bool,
    directory: pathlib.Path,
    end_in_fireos: bool = False,
    force: bool,
    restore: bool = False,
    serial: str,
) -> None:
    bundle = load_bundle(directory, serial)
    recovery = Recovery(serial)
    transport = Transport(serial)
    if check:
        preflight(bundle, recovery)
        passed(message="Cannoli bundle and recovery checks passed; no writes performed")
        return
    require(
        backup is not None and not backup.is_symlink(), "Use a host backup directory"
    )
    if restore:
        load_backup(backup, serial)
    elif (backup / "backup.json").exists():
        load_backup(backup, serial, bundle.checksum)
    else:
        require(
            not backup.exists() or not any(backup.iterdir()),
            "Use a new backup directory; incomplete backup exists",
        )
    confirm(
        force=force,
        what="restore Cannoli slot A from backup and change boot selection"
        if restore
        else "replace Cannoli slot A, install TWRP in slot B, "
        "and change boot selection",
    )
    start_recovery(bundle, transport, recovery)
    say(text="Checking firmware prerequisites and recovery slot B")
    volumes = preflight(bundle, recovery)
    protected = {name: recovery.remote_digest(volumes[name]) for name in B_VOLUMES}
    if restore:
        report = load_backup(backup, serial)
        for name in A_VOLUMES:
            require(
                report["volumes"][name]["size"] <= volumes[name].capacity,
                "Backup exceeds target capacity",
            )
    else:
        recovery.backup(backup, volumes, bundle.checksum)
    recovery.stage_helper(bundle.image("ubivol"))
    for name in A_VOLUMES:
        image = backup / (name + ".bin") if restore else bundle.image(name)
        passed(message="Writing and verifying " + name)
        recovery.write(volumes[name], image)
    current = recovery.volumes()
    for name, checksum in protected.items():
        require(
            recovery.remote_digest(current[name]) == checksum,
            "Recovery slot B changed; leave the device in recovery",
        )
    if restore and not end_in_fireos:
        passed(message="Slot A restored. Slot B remains selected in TWRP")
        return
    transport.ram(bundle.image("select-a"), "cannoli-bcb-1")
    transport.fastboot("reboot")
    if restore:
        passed(message="Slot A restored and selected; normal boot requested")
        return
    recovery.command("wait-for-device", timeout=120)
    require(
        recovery.shell("getprop ro.product.device") == "cannoli",
        "Booted device is not Cannoli",
    )
    require(
        recovery.shell("getprop ro.boot.slot_suffix") == "_a", "Slot A did not boot"
    )
    require(
        recovery.shell("getprop ro.adb.secure") == "0",
        "ADB authentication is still enabled; rebuild the bundle with a "
        "current OS builder",
    )
    require(recovery.shell("id -u") == "0", "Slot A did not provide root ADB")
    require(recovery.shell("getenforce") == "Enforcing", "Expected SELinux enforcing")
    require(
        recovery.shell("getprop service.adb.tcp.port") == "-1", "Expected USB-only ADB"
    )
    passed(message="Cannoli rooted on slot A; hold Volume Up at power-on for TWRP")


def start_recovery(bundle: Bundle, transport: Transport, recovery: Recovery) -> None:
    try:
        recovery.check()
    except FatalError as error:
        if error.message not in {
            "Boot Cannoli slot B TWRP first",
            "Cannoli ADB operation failed; inspect the device before retrying",
        }:
            raise
        transport.ram(bundle.image("access"), "cannoli")
        for name in B_VOLUMES:
            value = transport.variable("partition-size:" + name)
            require(
                bool(re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", value)),
                "Invalid fastboot partition size",
            )
            require(
                int(value, 16) == LIMITS[name], "Unexpected Cannoli B partition size"
            )
        transport.ram(bundle.image("select-a"), "cannoli-bcb-1")
        for name in B_VOLUMES:
            transport.fastboot("flash", name, str(bundle.image(name)))
            passed(message=f"Recovery {name} installed")
        # No host-side readback: fastboot has no read-partition command,
        # so B is verified after reboot via remote_digest in preflight.
    else:
        preflight(bundle, recovery)
    transport.ram(bundle.image("select-b"), "cannoli-bcb-1")
    transport.fastboot("reboot")
    say(text="Waiting for slot B TWRP")
    wait_recovery(recovery)


def upgrade_prerequisites(
    *,
    check: bool,
    directory: pathlib.Path,
    force: bool,
    ota: pathlib.Path,
    serial: str,
) -> None:
    bundle = load_bundle(directory, serial)
    parts = resolve_upgrade_parts(ota)
    verify_upgrade_parts(parts)
    recovery = Recovery(serial)
    recovery.check()
    volumes = recovery.volumes()
    require(
        set(UPGRADE_PARTS) <= set(volumes),
        "8349 upgrade volumes are missing on this unit",
    )
    for name, image in parts.items():
        require(
            image.stat().st_size <= volumes[name].capacity,
            "OTA part exceeds its volume: " + name,
        )
    recovery.unmounted({name: volumes[name] for name in UPGRADE_PARTS})
    say(text="Reading the device's protected volumes")
    stale = [
        name for name in PREREQUISITES if not carries_8349(recovery, volumes[name])
    ]
    if check:
        for name in sorted(PREREQUISITES):
            say(
                text=name + ": " + ("older firmware" if name in stale else "8349")
            )
        passed(
            message=str(len(stale))
            + " of "
            + str(len(PREREQUISITES))
            + " volumes need cannoli-upgrade; no writes performed"
        )
        return
    require(
        bool(stale),
        "Device already carries the 8349 prerequisite volumes; rerun the"
        " Cannoli install, which rewrites slot A",
    )
    confirm(
        force=force,
        what="upgrade nine Cannoli volumes to stock 8349 — one-way: the "
        "first 8349 TEE boot burns the anti-rollback eFuse",
    )
    recovery.stage_helper(bundle.image("ubivol"))
    for name in UPGRADE_ORDER:
        passed(message="Writing and verifying " + name)
        recovery.write(volumes[name], parts[name])
    say(text="Re-reading the protected volumes")
    current = recovery.volumes()
    for name in PREREQUISITES:
        require(
            carries_8349(recovery, current[name]),
            "Prerequisite volume still differs: " + name,
        )
    passed(
        message="Prerequisites upgraded; see the guide's factory-unit section"
        " for the brhgptlk step, then rerun the Cannoli install"
    )


def verify_upgrade_parts(parts: dict[str, pathlib.Path]) -> None:
    pins = {
        **PREREQUISITES,
        "mcupm_b": PREREQUISITES["mcupm_a"],
        "scp_b": PREREQUISITES["scp_a"],
    }
    for name, image in parts.items():
        if name in pins:
            size, checksums = pins[name]
            require(
                image.stat().st_size == size and digest(image) in checksums,
                "OTA part differs from the pinned 8349 image: " + image.name,
            )
        elif name == "boot_a":
            require(
                digest(image) == STOCK_BOOT,
                "OTA boot.img differs from the pinned 8349 boot image",
            )
        else:
            with image.open("rb") as source:
                magic = source.read(4)
            require(
                0 < image.stat().st_size <= LIMITS[name]
                and magic == (b"hsqs" if name == "system_a" else b"\xd0\x0d\xfe\xed"),
                "OTA part is not a stock 8349 image: " + image.name,
            )
            say(text=image.name + " is not pinned; size and format checked only")


def wait_recovery(recovery: Recovery) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            recovery.check()
        except FatalError:  # ruff: ignore[try-except-in-loop]
            time.sleep(1)
        else:
            return
    raise FatalError(
        message="TWRP did not answer; keep slot B selected and retry the recovery boot"
    )
