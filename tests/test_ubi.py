from __future__ import annotations

import hashlib
import json
import subprocess
import types
from typing import TYPE_CHECKING

import pytest

from firebreak import ubi
from firebreak.ui import FatalError

if TYPE_CHECKING:
    import pathlib

SERIAL = "TEST1234"


@pytest.fixture
def recovery() -> ubi.Recovery:
    return ubi.Recovery(SERIAL)


@pytest.fixture
def saved(
    recovery: ubi.Recovery, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> pathlib.Path:
    def read(*_args: object, **kwargs: object) -> types.SimpleNamespace:
        kwargs["stdout"].write(b"data")
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", read)
    monkeypatch.setattr(
        recovery, "remote_digest", lambda _: hashlib.sha256(b"data").hexdigest()
    )
    directory = tmp_path / "backup"
    recovery.backup(directory, inventory(), "bundle-hash")
    return directory


def inventory() -> dict[str, ubi.Volume]:
    return {
        name: ubi.Volume(name, f"/dev/ubi0_{i}", 4, 100, 0)
        for i, name in enumerate(ubi.BACKUP_VOLUMES)
    }


def test_adb_serial_and_command_failure(
    recovery: ubi.Recovery, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def command(args: object, **_kwargs: object) -> types.SimpleNamespace:
        calls.append(args)
        return types.SimpleNamespace(stdout=b"recovery")

    monkeypatch.setattr(subprocess, "run", command)
    assert recovery.command("get-state") == b"recovery"
    assert calls == [["adb", "-s", SERIAL, "get-state"]]

    def fails(*_args: object, **_kwargs: object) -> None:
        raise OSError

    monkeypatch.setattr(subprocess, "run", fails)
    with pytest.raises(FatalError, match="ADB operation failed"):
        recovery.command("get-state")


def test_backup_is_verified_private_and_resumable(
    recovery: ubi.Recovery, saved: pathlib.Path
) -> None:
    report = recovery.backup(saved, inventory(), "bundle-hash")
    assert set(report["volumes"]) == set(ubi.BACKUP_VOLUMES)
    assert saved.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in saved.iterdir())
    assert not (saved / "backup.partial").exists()


@pytest.mark.parametrize(
    "problem",
    ["serial", "bundle", "volume-set", "size", "hash", "symlink", "incomplete"],
)
def test_invalid_backup_cannot_resume(saved: pathlib.Path, problem: str) -> None:
    path = saved / "backup.json"
    report = json.loads(path.read_text())
    if problem == "serial":
        report["serial"] = "OTHER"
    elif problem == "bundle":
        report["bundle"] = "OTHER"
    elif problem == "volume-set":
        report["volumes"].pop("misc")
    elif problem == "size":
        report["volumes"]["system_a"]["size"] = 5
    elif problem == "hash":
        (saved / "system_a.bin").write_bytes(b"evil")
    elif problem == "symlink":
        (saved / "system_a.bin").unlink()
        (saved / "system_a.bin").symlink_to(saved / "boot_a.bin")
    path.write_text("{" if problem == "incomplete" else json.dumps(report))
    with pytest.raises(FatalError):
        ubi.load_backup(saved, SERIAL, "bundle-hash")


@pytest.mark.parametrize(
    "source",
    ["/dev/ubi0_0", "/dev/ubiblock0_0", "/dev/block/ubiblock0_0", "ubi0:system_a"],
)
def test_mounted_targets_refused(
    recovery: ubi.Recovery, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    monkeypatch.setattr(
        recovery, "shell", lambda _: source + " /system squashfs ro 0 0"
    )
    with pytest.raises(FatalError, match="mounted"):
        recovery.unmounted(inventory())
    monkeypatch.setattr(recovery, "shell", lambda _: "tmpfs /tmp tmpfs rw 0 0")
    recovery.unmounted(inventory())


def test_partial_backup_is_never_overwritten(
    recovery: ubi.Recovery, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "backup"
    directory.mkdir()
    (directory / "system_a.bin").write_bytes(b"partial")
    with pytest.raises(FatalError, match="incomplete"):
        recovery.backup(directory, inventory(), "bundle")
    (directory / "system_a.bin").unlink()
    volumes = inventory()
    volumes["boot_a"] = ubi.Volume("boot_a", "/dev/ubi0_1", 0, 100, 1)

    def read(*_args: object, **kwargs: object) -> types.SimpleNamespace:
        kwargs["stdout"].write(b"data")
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", read)
    monkeypatch.setattr(
        recovery, "remote_digest", lambda _: hashlib.sha256(b"data").hexdigest()
    )
    with pytest.raises(FatalError, match="interrupted"):
        recovery.backup(directory, volumes, "bundle")
    assert not (directory / "backup.json").exists()


@pytest.mark.parametrize(
    "wrong", [None, "state", "product", "uid", "cmdline", "version"]
)
def test_recovery_identity(
    recovery: ubi.Recovery, monkeypatch: pytest.MonkeyPatch, wrong: str | None
) -> None:
    monkeypatch.setattr(
        recovery, "command", lambda *_a: b"device" if wrong == "state" else b"recovery"
    )
    responses = {
        "cat /proc/cmdline": ("cmdline", "root=/dev/ram0"),
        "getprop ro.product.device": ("product", "cannoli"),
        "getprop ro.twrp.version": ("version", "3.7.0_9-0"),
        "id -u": ("uid", "0"),
    }
    monkeypatch.setattr(
        recovery,
        "shell",
        lambda command: (
            "wrong" if wrong == responses[command][0] else responses[command][1]
        ),
    )
    if wrong:
        with pytest.raises(FatalError):
            recovery.check()
    else:
        recovery.check()


def test_remote_hash_checks_count_and_update_marker(
    recovery: ubi.Recovery, monkeypatch: pytest.MonkeyPatch
) -> None:
    volume = inventory()["system_a"]
    monkeypatch.setattr(
        recovery,
        "shell",
        lambda command: "4" if "wc -c" in command else "a" * 64 + "  -",
    )
    assert recovery.remote_digest(volume) == "a" * 64
    with pytest.raises(FatalError):
        recovery.remote_digest(volume, 101)
    monkeypatch.setattr(recovery, "shell", lambda _: "3")
    with pytest.raises(FatalError, match="Truncated"):
        recovery.remote_digest(volume)
    monkeypatch.setattr(
        recovery, "shell", lambda command: "4" if "wc -c" in command else "not-a-hash"
    )
    with pytest.raises(FatalError, match="checksum"):
        recovery.remote_digest(volume)


def test_shell_requires_final_success_marker(
    recovery: ubi.Recovery, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ubi.secrets, "token_hex", lambda _: "marker")
    for output in [b"ok\nFIREBREAK_marker:0\n", b"ok\r\nFIREBREAK_marker:0\r\n"]:
        monkeypatch.setattr(recovery, "command", lambda *_a, output=output: output)
        assert recovery.shell("id") == "ok"
    for output in [
        b"ok",
        b"ok\nFIREBREAK_marker:1\n",
        b"ok\nFIREBREAK_marker:0\ntrailing",
        b"ok\nFIREBREAK_marker:",
    ]:
        monkeypatch.setattr(recovery, "command", lambda *_a, output=output: output)
        with pytest.raises(FatalError, match="truncated"):
            recovery.shell("id")


def test_ubi_inventory_rejects_ambiguous_and_incomplete_tables(
    recovery: ubi.Recovery, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = "\n".join(
        f"ubi0_{i}\n{name}\n4\n1\n100\n0" for i, name in enumerate(ubi.BACKUP_VOLUMES)
    )
    monkeypatch.setattr(recovery, "shell", lambda _: raw)
    assert recovery.volumes() == inventory()
    bads = [
        "",
        raw + "\nextra",
        raw.replace("ubi0_0", "ubi0_../../etc"),
        raw.replace("system_a", "boot_a"),
        raw.replace("\n4\n", "\nno\n"),
        raw.replace("\n100\n", "\n1\n"),
        raw.replace("system_a", "something_else"),
    ]
    for bad in bads:
        monkeypatch.setattr(recovery, "shell", lambda _, bad=bad: bad)
        with pytest.raises(FatalError):
            recovery.volumes()


def test_write_stages_and_verifies_image(
    recovery: ubi.Recovery, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "image"
    image.write_bytes(b"data")
    calls = []
    monkeypatch.setattr(recovery, "command", lambda *args: calls.append(args))
    monkeypatch.setattr(
        recovery,
        "shell",
        lambda command: (
            calls.append(command)
            or (ubi.digest(image) if "sha256sum" in command else "")
        ),
    )
    monkeypatch.setattr(recovery, "volumes", inventory)
    monkeypatch.setattr(recovery, "remote_digest", lambda *_args: ubi.digest(image))
    recovery.write(inventory()["system_a"], image, image)
    assert any(
        isinstance(command, str) and " write /dev/ubi0_0 system_a " in command
        for command in calls
    )
    monkeypatch.setattr(recovery, "remote_digest", lambda *_args: "bad")
    with pytest.raises(FatalError, match="readback"):
        recovery.write(inventory()["system_a"], image, image)
    monkeypatch.setattr(recovery, "shell", lambda _: "wrong")
    with pytest.raises(FatalError, match="staging"):
        recovery.push(image, "/tmp/image")
