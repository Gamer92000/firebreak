from __future__ import annotations

import concurrent.futures
import contextlib
import dataclasses
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import TYPE_CHECKING

import serial
import serial.tools.list_ports

from firebreak import sparse
from firebreak.mediatek import bl2, fit
from firebreak.ubi import digest, require
from firebreak.ui import (
    ARGUMENTS,
    FatalError,
    clock,
    confirm,
    passed,
    say,
    show,
    warn,
)

if TYPE_CHECKING:
    import pathlib
    from collections.abc import Callable

    Trace = Callable[[str], None]

BUILD = "NS6575/8349"
DOWNLOAD_LIMIT = 0x1E00000
KEY = (
    int(
        (
            "cca0f6154d4432f7f05ff8accaf88b00d58f7fa71bb32128ae56d841042f035a"
            "c5697aa31387f111882f84f88174c4d50f541607b48027c33425931e2174df51"
            "262b17708800ad8855cabf3967cdc13e1b59056ffe0d9c7596a3ee8ade95cc56"
            "d981dc8d340d286424388ef99dc1dc1fef8324eac2bdb07c2fc4e3cd81ac307e"
            "18e9f602742f9d68a604eecab71f12f3f1ba314297d90464841e9b12f37611d7"
            "e38b024af49af979f442279f223afdccbc488b6f8b7d0f96e6f1e41316b2e053"
            "db7e27ea72d0abbcd1168ff0cfb44cc0d2f45e145efbaecb50e85e2e70bf2931"
            "0405e19c9c2cb2a3b6c38ce699b73dbcdafcbcf1637a13845fc13614501a65d7"
        ),
        16,
    ),
    65537,
)
LATER, MISSED, UPLOADED = "later", "missed", "uploaded"
LIMITS = {
    "access": bl2.MAX_IMAGE,
    "boot_b": 0x1000000,
    "system_a": 0x3E800000,
    "verity": bl2.MAX_IMAGE,
}
LOADERS = {
    "access": "d7fe66dcc2718488a7adb8bb9b3b0bc6ed765bd7f90cdee3e55ac4964eb77646",
    "verity": "48222d2cb19baafd613d1f632acdd8e3a72f070f6eb10ab58b5ca323f031acaa",
}
MISC_SIZE = 0x80000
OPEN_GRACE = 0.9
PARTITIONS = {
    "boot_a": 0x1000000,
    "boot_b": 0x1000000,
    "recovery": 0x1000000,
    "system_a": 0x3E800000,
    "system_b": 0x3E800000,
    "uboot_a": 0x100000,
    "uboot_b": 0x100000,
}
POWER_ON = 0.25
REBOOT_SECONDS = 60
RESCUE_SECONDS = 600
SLOT_MAGIC = 0x42424100
STOCK_BOOT = "771c93d070a19f33928842779f2dabcc42fa50159f5d0dd7fab7ba17b1a32830"
STOCK_STREAM = "6bd574cae11bf258f12cd2bf2f463fd55732077daf2e45fae1fcc7a9a3e7f55c"
WINDOW_SECONDS = 120
WRITABLE = frozenset({"boot_b", "misc", "system_b", "uboot_b"})


@dataclasses.dataclass(frozen=True)
class Bundle:
    directory: pathlib.Path
    serial: str
    checksum: str
    system: list[bytes]

    def image(self, name: str) -> pathlib.Path:
        require(name in LIMITS, "Unknown Laser image")
        return self.directory / (name + ".img")


class Transport:
    def __init__(self, serial: str) -> None:
        require(
            bool(re.fullmatch(r"[A-Za-z0-9_-]{4,64}", serial)),
            "Use the Echo's USB serial",
        )
        self.serial = serial
        self.trace = traced if ARGUMENTS.verbose else None

    def await_loader(self) -> None:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.in_fastboot():
                return
            time.sleep(0.2)
        raise FatalError(
            message="The RAM loader's fastboot did not appear; nothing was written."
            " Power-cycle the Echo and run again"
        )

    def fastboot(self, *arguments: str, timeout: int = 900) -> str:
        try:
            result = subprocess.run(
                ["fastboot", "-s", self.serial, *arguments],
                check=True,
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                timeout=timeout,
            )
        except subprocess.CalledProcessError as error:
            output = error.stdout or b""
            raise FatalError(
                message="Laser fastboot failed; no further writes attempted:"
                " " + output.decode(errors="replace").strip()[-500:]
            ) from error
        except (subprocess.SubprocessError, OSError) as error:
            raise FatalError(
                message="Laser fastboot failed; no further writes attempted"
            ) from error
        text = result.stdout.decode()
        require("FAILED" not in text, "Fastboot reported failure")
        return text

    def flash(self, partition: str, image: bytes) -> None:
        require(partition in WRITABLE, "The Laser route never writes " + partition)
        with tempfile.NamedTemporaryFile(
            prefix="firebreak-laser-", suffix=".img"
        ) as handle:
            handle.write(image)
            handle.flush()
            text = self.fastboot("flash", partition, handle.name, timeout=1800)
        require("OKAY" in text, f"Fastboot did not confirm the write to {partition}")

    def identify(self) -> None:
        require(
            self.variable("product") == "laser",
            "Unexpected RAM loader; stop before writing flash",
        )
        require(self.variable("serialno") == self.serial, "Fastboot serial differs")
        for name, size in PARTITIONS.items():
            require(
                self.partition(name) == size, "Unexpected Laser partition size: " + name
            )
        limit = self.variable("max-download-size")
        require(
            bool(re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", limit))
            and int(limit, 16) == DOWNLOAD_LIMIT,
            "The loader's max-download-size differs from the surveyed one",
        )
        passed(
            message="RAM loader verified; serial, product and partition geometry"
            " match the survey"
        )

    def in_fastboot(self) -> bool:
        return any(
            line.split()[:1] == [self.serial]
            for line in fastboot_devices().splitlines()
        )

    def load(self, data: bytes) -> None:
        say(
            text="Loading the access loader into RAM through the preloader's USB window"
        )
        power_prompt()
        through_window(data, fresh=True, seconds=WINDOW_SECONDS, trace=self.trace)
        self.await_loader()
        self.identify()

    def partition(self, name: str) -> int:
        value = self.variable("partition-size:" + name)
        require(
            bool(re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", value)),
            "Invalid fastboot partition size",
        )
        return int(value, 16)

    def reboot(self) -> None:
        with contextlib.suppress(subprocess.SubprocessError, OSError):
            subprocess.run(
                ["fastboot", "-s", self.serial, "reboot"],
                check=False,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                timeout=REBOOT_SECONDS,
            )

    def rehearse(self, data: bytes) -> None:
        say(
            text="Practising the rescue move with nothing written: the loader's"
            " `reboot` hangs until the watchdog resets the Echo, about 30 s on,"
            " and the preloader window after that reset is caught"
        )
        stop = threading.Event()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            ready = threading.Event()
            waiting = pool.submit(
                through_window,
                data,
                fresh=False,
                ready=ready,
                seconds=RESCUE_SECONDS,
                stop=stop,
                trace=self.trace,
            )
            require(ready.wait(5), "The window catcher did not start")
            self.reboot()
            time.sleep(2)
            if not waiting.done() and self.in_fastboot():
                stop.set()
                raise FatalError(
                    message="After the loader's `reboot` the Echo is in fastboot"
                    " again and no preloader window was caught, so the rescue"
                    " move is not shown on this Echo; nothing was written."
                    " Power-cycle the Echo, which boots as before"
                )
            try:
                waiting.result(timeout=RESCUE_SECONDS + REBOOT_SECONDS)
            except FatalError as error:
                raise FatalError(
                    message="The preloader window after a reset was not caught, so"
                    " the rescue move is not shown on this Echo; nothing was"
                    " written. Power-cycle the Echo, which boots as before. "
                    + error.message
                ) from error
        self.await_loader()
        self.identify()
        passed(message="Rescue move shown: a window after a reset was caught")

    def variable(self, name: str) -> str:
        text = self.fastboot("getvar", name, timeout=20)
        found = re.search(
            r"(?:^|\n)(?:\(bootloader\) )?" + re.escape(name) + r":\s*(\S+)", text
        )
        require(found is not None, "Fastboot variable response was incomplete")
        return found[1]


def fastboot_devices() -> str:
    try:
        return subprocess.run(
            ["fastboot", "devices"],
            check=True,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            timeout=30,
        ).stdout
    except (subprocess.SubprocessError, OSError) as error:
        raise FatalError(
            message="fastboot did not answer; nothing was written"
        ) from error


def load_bundle(directory: pathlib.Path, serial: str) -> Bundle:
    try:  # ruff: ignore[too-many-statements-in-try-clause]
        path = directory / "bundle.json"
        require(not path.is_symlink(), "Bundle manifest must not be a symlink")
        manifest = json.loads(path.read_text())
        require(
            manifest["format"] == 1
            and manifest["product"] == "laser"
            and manifest["build"] == BUILD
            and manifest["serial"] == serial,
            "Bundle is not for this Laser serial and build",
        )
        require(
            manifest.get("adb") == "keyless",
            "Bundle predates keyless ADB; rebuild it with a current OS builder",
        )
        require(set(manifest["images"]) == set(LIMITS), "Bundle image set differs")
        checksum = digest(path)
        for name, maximum in LIMITS.items():
            image = directory / (name + ".img")
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
                head = source.read(0x440)
            magic = (
                head[0x438:0x43A] == b"\x53\xef"
                if name == "system_a"
                else head[:4] == b"\xd0\x0d\xfe\xed"
            )
            require(magic, "Unexpected bundle image format: " + name)
            if name == "boot_b":
                require(
                    saved["sha256"] == STOCK_BOOT,
                    "boot_b must be the stock 8349 boot image",
                )
            elif name in LOADERS:
                sealed(image.read_bytes(), name)
        image = directory.joinpath("system_a.img").read_bytes()
        parts = sparse.pieces(image, DOWNLOAD_LIMIT)
        sparse.check(image, parts, DOWNLOAD_LIMIT)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise FatalError(
            message="Invalid Laser bundle; rebuild it with laser-os-builder"
            f" (see docs/laser.md): {error}"
        ) from error
    return Bundle(directory, serial, checksum, parts)


def misc_image(active: str) -> bytes:
    require(active in {"a", "b"}, "Unknown slot")
    block = bytearray(MISC_SIZE)
    struct.pack_into("<I", block, 0x360, SLOT_MAGIC)
    block[0x364] = 1
    chosen, other = 0xBE, 0xBF
    block[0x365] = chosen if active == "b" else other
    block[0x366] = chosen if active == "a" else other
    return bytes(block)


def offer(data: bytes, device: str, *, first: float, fresh: bool, trace: Trace) -> str:
    try:
        port = serial.Serial(
            device,
            baudrate=921600,
            dsrdtr=False,
            rtscts=False,
            timeout=0.05,
            write_timeout=5,
            xonxoff=False,
        )
    except (serial.SerialException, OSError) as error:
        if time.monotonic() - first > OPEN_GRACE:
            warn(text=f"{device} stayed unopenable for {OPEN_GRACE} s: {error}")
            return MISSED
        return LATER
    with port:
        try:
            bl2.upload(port, data, trace=trace, window=True)
        except (FatalError, serial.SerialException, OSError) as error:
            said = getattr(error, "message", str(error))
            warn(
                text="That window did not take the loader ("
                + said
                + ("). Power-cycle the Echo to offer another" if fresh else ")")
            )
            return MISSED
    return UPLOADED


def power_prompt() -> None:
    require(
        sys.stdin.isatty(),
        "The power prompts need a terminal; run firebreak from an interactive shell",
    )
    input("Disconnect the Echo's power, wait 5 s, then press Enter: ")
    print("Listening now. Power the Echo on.", flush=True)


def preloader() -> list[str]:
    found = [
        each.device
        for each in serial.tools.list_ports.comports()
        if (each.vid, each.pid) == bl2.USB_ID
    ]
    if sys.platform == "darwin":
        found = [each for each in found if each.startswith("/dev/cu.")]
    return sorted(found)


def run(
    *,
    bundle_dir: pathlib.Path,
    check: bool,
    force: bool,
    select_a: bool,
    serial: str,
) -> None:
    bundle = load_bundle(bundle_dir, serial)
    transport = Transport(serial)
    loader = bundle.image("access").read_bytes()
    transport.load(loader)
    if select_a:
        if not check:
            confirm(
                force=force,
                what="write the boot-control block that selects stock slot A again",
            )
            write(transport, "misc", misc_image("a"))
            passed(
                message="Slot A is selected again. Power-cycle the Echo: it boots"
                " the stock system"
            )
        else:
            passed(message="Laser bundle and RAM loader checked; nothing was written")
        return
    transport.rehearse(loader)
    if check:
        passed(
            message="Laser bundle, RAM loader and rescue move checked; nothing was"
            " written"
        )
        say(text="The loader stays in fastboot until the Echo is power-cycled.")
        return
    confirm(
        force=force,
        what="write the rooted system to Laser's slot B and select it (slot A"
        " stays stock)",
    )
    passed(message="Writing boot_b")
    write(transport, "boot_b", bundle.image("boot_b").read_bytes())
    passed(message="Writing uboot_b")
    write(transport, "uboot_b", bundle.image("verity").read_bytes())
    passed(
        message=f"Writing system_b as {len(bundle.system)} pieces, one download each"
    )
    for number, part in enumerate(bundle.system, 1):
        write(transport, "system_b", part)
        show(text=f"  piece {number} of {len(bundle.system)} written")
    passed(message="Selecting slot B")
    write(transport, "misc", misc_image("b"))
    passed(message="Slot B is written and selected. Power-cycle the Echo now")
    say(
        text="It boots the rooted system on slot B; stock slot A stays as it was."
        " If slot B does not come up, `firebreak unlock --device laser"
        " --select-a` with this bundle and serial selects slot A again."
    )
    wait_adb(serial, seconds=240)
    require(shell(serial, "getprop ro.boot.slot_suffix") == "_b", "Slot B did not boot")
    require(
        shell(serial, "getprop ro.adb.secure") == "0",
        "ADB authentication is still enabled; rebuild the bundle with a "
        "current OS builder",
    )
    require(shell(serial, "id -u") == "0", "Slot B did not provide root ADB")
    require(shell(serial, "getenforce") == "Enforcing", "Expected SELinux enforcing")
    require(
        shell(serial, "getprop service.adb.tcp.port") == "-1", "Expected USB-only ADB"
    )
    passed(message="Laser rooted on slot B; slot A stays stock")


def sealed(data: bytes, name: str) -> None:
    try:
        image = fit.Fit(data)
        payload = image.prop(fit.IMAGE, "data")
        fresh = hashlib.sha256(payload).digest() == image.prop(
            fit.IMAGE + "/hash-1", "value"
        )
        stock = (
            hashlib.sha256(image.signed_stream(fit.SIGNATURE)).hexdigest()
            == STOCK_STREAM
        )
    except (ValueError, KeyError) as error:
        raise FatalError(
            message=f"Laser {name} image is not a loader FIT the preloader takes;"
            " rebuild it with laser-os-builder"
        ) from error
    require(
        fresh,
        f"Laser {name} image was edited after sealing: its data hash is stale."
        " The preloader refuses such an image; rebuild it through the seal",
    )
    require(
        stock,
        f"Laser {name} image differs from the stock loader outside its payload;"
        " rebuild it with laser-os-builder",
    )
    require(
        fit.verifies(image, KEY),
        f"Laser {name} image's signature does not verify under Amazon's key;"
        " rebuild it with laser-os-builder",
    )
    require(
        hashlib.sha256(data).hexdigest() == LOADERS[name],
        f"Laser {name} image is not the one validated on hardware; rebuild it"
        " with laser-os-builder, or validate the new image first",
    )


def shell(serial: str, command: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "shell", command],
            check=True,
            stdout=subprocess.PIPE,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError) as error:
        raise FatalError(message="Laser ADB failed; inspect the device") from error
    return result.stdout.decode().strip()


def through_window(  # ruff: ignore[too-many-arguments]
    data: bytes,
    *,
    fresh: bool,
    ready: threading.Event | None = None,
    seconds: float,
    stop: threading.Event | None = None,
    trace: Trace = None,
) -> None:
    if ready is not None:
        ready.set()
    began = time.monotonic()
    deadline = began + seconds
    present = bool(preloader())
    if fresh:
        require(
            not present,
            "The Echo was already on when the listener started, so its window is"
            " nearly over; power-cycle it and run again",
        )
    live = not present
    tried: set[str] = set()
    appeared: dict[str, float] = {}
    while time.monotonic() < deadline and not (stop is not None and stop.is_set()):
        found = preloader()
        require(
            len(found) <= 1, "Multiple preloader ports; connect only the target Echo"
        )
        if not found:
            tried.clear()
            appeared.clear()
            live = True
        elif live:
            device = found[0]
            first = appeared.setdefault(device, time.monotonic())
            if fresh and first - began < POWER_ON:
                raise FatalError(
                    message="The Echo was powered on before the listener started, so"
                    " its window is nearly over; power-cycle it and run again"
                )
            if device not in tried:
                outcome = offer(data, device, first=first, fresh=fresh, trace=trace)
                if outcome == UPLOADED:
                    return
                if outcome == MISSED:
                    tried.add(device)
        time.sleep(0.02)
    raise FatalError(
        message=f"No preloader window was caught in {int(seconds)} s; nothing was"
        " written. Power-cycle the Echo and run again"
    )


def traced(line: str) -> None:
    print(f"  {clock()} {line}", flush=True)


def wait_adb(serial: str, seconds: int = 240) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            subprocess.run(
                ["adb", "-s", serial, "get-state"],
                check=True,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                timeout=10,
            )
        except (subprocess.SubprocessError, OSError):  # ruff: ignore[try-except-in-loop]
            time.sleep(1)
        else:
            require(
                shell(serial, "getprop ro.product.device") == "laser",
                "Boot device is not Laser",
            )
            return
    raise FatalError(
        message="Laser did not answer over ADB after the power-cycle; if slot B"
        " does not boot, `firebreak unlock --device laser --select-a` selects"
        " slot A again"
    )


def write(transport: Transport, partition: str, image: bytes) -> None:
    try:
        transport.flash(partition, image)
    except FatalError as error:
        raise FatalError(
            message=f"Writing {partition} failed; nothing after it was written. "
            + error.message
        ) from error
