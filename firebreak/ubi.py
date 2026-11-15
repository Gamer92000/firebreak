from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
from typing import TYPE_CHECKING

from firebreak.ui import FatalError, passed, say

if TYPE_CHECKING:
    import pathlib

A_VOLUMES = ("system_a", "boot_a", "uboot_a")
B_VOLUMES = ("boot_b", "uboot_b")
BACKUP_VOLUMES = (*A_VOLUMES, *B_VOLUMES, "misc")
MAX_VOLUME = 512 * 1024 * 1024
REMOTE_HELPER = "/tmp/firebreak-ubivol"  # ruff: ignore[hardcoded-temp-file]
REMOTE_IMAGE = "/tmp/firebreak-image"  # ruff: ignore[hardcoded-temp-file]


class Recovery:
    def __init__(self, serial: str) -> None:
        require(
            bool(re.fullmatch(r"[A-Za-z0-9_-]{4,64}", serial)),
            "Use the Echo's USB serial",
        )
        self.serial = serial
        self.adb = ["adb", "-s", serial]

    def backup(
        self, directory: pathlib.Path, volumes: dict[str, Volume], bundle: str
    ) -> dict:
        manifest_path = directory / "backup.json"
        if manifest_path.exists():
            say(text="Validating the existing backup before resuming")
            return load_backup(directory, self.serial, bundle)
        require(
            not directory.exists() or not any(directory.iterdir()),
            "Use a new backup directory; incomplete backup exists",
        )
        directory.mkdir(exist_ok=True, mode=0o700, parents=True)
        directory.chmod(0o700)
        report = {
            "bundle": bundle,
            "format": 1,
            "product": "cannoli",
            "serial": self.serial,
            "volumes": {},
        }
        for name in BACKUP_VOLUMES:
            volume = volumes[name]
            require(
                volume.used > 0 and not volume.updating,
                "Cannot back up an interrupted UBI update",
            )
            say(text=f"Backing up {name} to the host")
            path = directory / (name + ".bin")
            with path.open("xb") as target:
                path.chmod(0o600)
                result = subprocess.run(
                    [*self.adb, "exec-out", "cat " + volume.node],
                    check=False,
                    stderr=subprocess.PIPE,
                    stdout=target,
                    timeout=300,
                )
                target.flush()
                os.fsync(target.fileno())
            require(
                result.returncode == 0 and path.stat().st_size == volume.used,
                "Backup read failed or was truncated",
            )
            checksum = digest(path)
            require(checksum == self.remote_digest(volume), "Backup readback mismatch")
            report["volumes"][name] = {"sha256": checksum, "size": volume.used}
            passed(message=f"{name} backup verified")
        temporary = directory / "backup.partial"
        with temporary.open("x") as target:
            temporary.chmod(0o600)
            json.dump(report, target, indent=2)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        temporary.replace(manifest_path)
        return report

    def check(self) -> None:
        require(
            self.command("get-state").strip() == b"recovery",
            "Boot Cannoli slot B TWRP first",
        )
        require(
            self.shell("getprop ro.product.device") == "cannoli",
            "Recovery is not Cannoli",
        )
        require(self.shell("id -u") == "0", "Recovery ADB is not root")
        require(
            "root=/dev/ram0" in self.shell("cat /proc/cmdline"),
            "Expected a recovery ramdisk",
        )
        require(
            self.shell("getprop ro.twrp.version") == "3.7.0_9-0",
            "Unexpected Cannoli TWRP version",
        )

    def command(self, *arguments: str, timeout: int = 180) -> bytes:
        try:
            result = subprocess.run(
                [*self.adb, *arguments],
                capture_output=True,
                check=True,
                timeout=timeout,
            )
        except (subprocess.SubprocessError, OSError) as error:
            raise FatalError(
                message="Cannoli ADB operation failed; "
                "inspect the device before retrying"
            ) from error
        return result.stdout

    def push(self, path: pathlib.Path, remote: str) -> None:
        self.command("push", str(path), remote)
        words = self.shell("sha256sum " + shlex.quote(remote)).split()
        actual = words[0] if words else ""
        require(actual == digest(path), "ADB staging checksum mismatch")

    def remote_digest(self, volume: Volume, size: int | None = None) -> str:
        count = volume.used if size is None else size
        require(
            0 < count <= volume.used and not volume.updating,
            "Volume has no complete data to verify",
        )
        prefix = f"head -c {count} {volume.node}"
        require(self.shell(prefix + " | wc -c") == str(count), "Truncated UBI read")
        words = self.shell(prefix + " | sha256sum").split()
        value = words[0] if words else ""
        require(bool(re.fullmatch(r"[a-f0-9]{64}", value)), "Invalid recovery checksum")
        return value

    def shell(self, command: str) -> str:
        marker = "FIREBREAK_" + secrets.token_hex(16)
        wrapped = (
            "(set -e; "
            + command
            + "); result=$?; printf '\\n"
            + marker
            + ':%s\\n\' "$result"'
        )
        result = self.command("shell", wrapped).decode().replace("\r\n", "\n")
        body, found, status = result.rpartition("\n" + marker + ":")
        require(
            bool(found) and status.strip() == "0",
            "Recovery command failed or its response was truncated",
        )
        return body.strip()

    def unmounted(self, volumes: dict[str, Volume]) -> None:
        mounts = self.shell("cat /proc/mounts").splitlines()
        nodes = {v.node for v in volumes.values()}
        blocks = {n.replace("/dev/ubi", "/dev/ubiblock") for n in nodes}
        blocks |= {n.replace("/dev/ubi", "/dev/block/ubiblock") for n in nodes}
        names = {v.name for v in volumes.values()}
        for line in mounts:
            source = line.split()[0]
            require(
                source not in nodes | blocks and source.partition(":")[2] not in names,
                "A target UBI volume is mounted",
            )

    def volumes(self) -> dict[str, Volume]:
        raw = self.shell(
            "for p in /sys/class/ubi/ubi0_*; do [ -f $p/name ] || continue; "
            "echo ${p##*/}; "
            "for key in name data_bytes reserved_ebs usable_eb_size upd_marker; "
            "do cat $p/$key || exit 1; done; done"
        ).splitlines()
        require(len(raw) % 6 == 0 and bool(raw), "Incomplete UBI inventory")
        volumes = {}
        for index in range(0, len(raw), 6):
            node, name, used, blocks, leb, updating = raw[index : index + 6]
            require(bool(re.fullmatch(r"ubi0_\d+", node)), "Invalid UBI node")
            require(
                bool(re.fullmatch(r"[a-z0-9_]+", name)) and name not in volumes,
                "Ambiguous UBI volume",
            )
            require(
                all(v.isdecimal() for v in (used, blocks, leb, updating)),
                "Invalid UBI geometry",
            )
            capacity = int(blocks) * int(leb)
            require(
                0 < capacity <= MAX_VOLUME
                and 0 <= int(used) <= capacity
                and updating in {"0", "1"},
                "Invalid UBI size or update marker",
            )
            volumes[name] = Volume(
                name, "/dev/" + node, int(used), capacity, int(updating)
            )
        require(
            set(BACKUP_VOLUMES).issubset(volumes),
            "Required Cannoli volumes are missing",
        )
        return volumes

    def write(self, volume: Volume, image: pathlib.Path, helper: pathlib.Path) -> None:
        require(
            0 < image.stat().st_size <= volume.capacity, "Image exceeds UBI capacity"
        )
        self.unmounted({volume.name: volume})
        self.push(helper, REMOTE_HELPER)
        self.shell("chmod 700 /tmp/firebreak-ubivol")
        self.push(image, REMOTE_IMAGE)
        args = f"{volume.node} {volume.name} /tmp/firebreak-image"
        self.shell(REMOTE_HELPER + " check " + args)
        self.shell(REMOTE_HELPER + " write " + args)
        current = self.volumes()[volume.name]
        require(
            self.remote_digest(current, image.stat().st_size) == digest(image),
            "UBI readback mismatch",
        )
        self.shell("rm /tmp/firebreak-image; sync")


@dataclasses.dataclass(frozen=True)
class Volume:
    name: str
    node: str
    used: int
    capacity: int
    updating: int


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def load_backup(
    directory: pathlib.Path, serial: str, bundle: str | None = None
) -> dict:
    try:  # ruff: ignore[too-many-statements-in-try-clause]
        require(
            not directory.is_symlink() and not (directory / "backup.json").is_symlink(),
            "Backup paths must not be symlinks",
        )
        report = json.loads((directory / "backup.json").read_text())
        require(
            report["format"] == 1
            and report["product"] == "cannoli"
            and report["serial"] == serial,
            "Backup belongs to a different device",
        )
        require(
            bundle is None or report["bundle"] == bundle,
            "Resume requires the same image bundle",
        )
        require(
            set(report["volumes"]) == set(BACKUP_VOLUMES), "Backup volume set differs"
        )
        for name, saved in report["volumes"].items():
            path = directory / (name + ".bin")
            require(
                not path.is_symlink() and 0 < saved["size"] <= MAX_VOLUME,
                "Invalid backup file",
            )
            require(
                path.stat().st_size == saved["size"]
                and digest(path) == saved["sha256"],
                "Backup checksum or size mismatch",
            )
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise FatalError(message="Invalid or incomplete Cannoli backup") from error
    return report


def require(condition: bool, message: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]
    if not condition:
        raise FatalError(message=message)
