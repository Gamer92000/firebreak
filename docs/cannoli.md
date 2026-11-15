# Root an Echo Dot (5th Generation)

Use this guide for **Cannoli, NS6575/build 8349**, on an x86-64 Linux host.
The installer puts rooted stock Fire OS in slot A and headless TWRP in
slot B. Hold Volume Up during power-on to enter recovery after installation.
It preserves userdata.

Cannoli stores firmware in NAND UBI volumes and has no published XDA unlock,
so this route builds its own recovery and image bundle locally and writes
through an explicit `--device cannoli` path.
[The implementation notes](unlocking.md#cannoli) explain the boot chain and
credit the research and software used.

## Connect USB

USB is exposed on the 3×3 matrix of gold test pads in a recess behind the
base's rubber foot — the matrix sits in a white silkscreen box between the
two large gold screw holes. GND is the centre pad of the nine, D− the pad
straight below GND, and D+ the corner pad to the left of D−.
[This teardown][teardown] shows the pads.

1. Disconnect power and USB.
2. Solder D+, D−, and ground to a USB cable or breakout. Leave the cable's
   5 V wire disconnected from these pads.
3. Insulate the connections and connect USB to the host. Power the Echo from
   its normal adapter when the installer prompts you.

Holding the action button while powering on enters fastboot, which the
installer uses and `fastboot devices` reads the USB serial from.

[teardown]: https://www.briandorey.com/post/echo-dot-5th-gen-smart-speaker-teardown#gallery-7

## Prepare the host

Start from a checkout containing this change. Run these commands from the
repository root:

```sh
sudo apt install adb fastboot
uv sync
sudo groupadd -f plugdev
sudo install -m 644 contrib/73-cannoli.rules \
  /etc/udev/rules.d/73-cannoli.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo usermod -aG plugdev,dialout "$USER"
```

Log out and back in if your account was added to either group. Keep the Echo
off Wi-Fi until rooting completes so an update cannot replace the supported
firmware.

## Build the image bundle

The builders live in two separate repositories:

1. [Cannoli TWRP builder][twrp-builder] compiles headless recovery from a
   pinned source manifest and packages `boot_b.img` with `recovery.json`.
2. [Cannoli OS builder][os-builder] validates that recovery, builds rooted
   stock Fire OS and the loaders, and produces the complete `bundle.json`
   image directory consumed by Firebreak.

Follow their READMEs on an x86-64 Linux host. They resolve the stock firmware
through [FTVDB's Cannoli NS6575/8349 record][firmware] and verify pinned
SHA-256 hashes. No firmware binaries are included in these repositories.

Use the same USB serial for recovery packaging, OS building and installation.
The OS builder embeds this host's public ADB key; keep the private key on the
host. Once the bundle is built, set these variables in the Firebreak shell:

```sh
CANNOLI_SERIAL=REPLACE_WITH_USB_SERIAL
CANNOLI_BUNDLE=/absolute/path/to/cannoli-os-builder/work/bundle
```

[twrp-builder]: https://github.com/Gamer92000/twrp_device_amazon_cannoli
[os-builder]: https://github.com/Gamer92000/cannoli-os-builder
[firmware]: https://ftvdb.com/echo/firmware/com.amazon.cannoli.android.os/0bf96b3cd8fca30fdd12f61208e44d76-13323246980-fire-os-6-5-7-5-ns6575-8349-2026-10-27/

## Install recovery and root

```sh
uv run firebreak unlock --device cannoli \
  --bundle "$CANNOLI_BUNDLE" \
  --serial "$CANNOLI_SERIAL" \
  --backup "$PWD/backups/cannoli-original"
```

Follow the power prompts. The listener starts before each power-on so it can
catch the brief BL2 USB window. Add `--force` to skip the initial write
confirmation.

The installer replaces `boot_b` and `uboot_b` before it can take a host
backup. **The backup does not contain the original slot B images or the
original boot selection.** It contains slot A before its first write,
the installed recovery in B, and the boot metadata read from recovery.

Before writing A, Firebreak checks the recovery, the B images, and the
host backup, and readback-verifies every write; the full check list is in
[the implementation notes](unlocking.md#cannoli).

On slot A, ADB listens on USB only and requires a key already authorized on
the device or the bundle's embedded public key. SELinux stays enforcing,
with only the root `su` domain permissive; the system disables OTA
autostart and blocks the upstream Firebreak OTA host list.

Slot B provides TWRP's root USB recovery shell without host-key authentication.

## Check or resume an installation

To check an existing slot B recovery without writing to the device, run:

```sh
uv run firebreak unlock --device cannoli \
  --bundle "$CANNOLI_BUNDLE" \
  --serial "$CANNOLI_SERIAL" --check
```

The recovery images must match this bundle. A recovery built with a
different serial or source tree can fail this check.

If a slot A write fails, keep B selected and rerun the install command with
the **same bundle and backup directory**. Firebreak validates the completed
backup and retains it. An incomplete backup is refused; inspect it and use
a new empty directory to retry a backup. Never delete the only completed
backup to work around an error.

Do not use TWRP's generic wipe, format, or ZIP installation interface for
this route. Those operations have not been validated for Cannoli NAND.

## Restore slot A

Restore the saved A volumes from a verified backup:

```sh
uv run firebreak restore "$PWD/backups/cannoli-original" \
  --device cannoli --bundle "$CANNOLI_BUNDLE" \
  --serial "$CANNOLI_SERIAL"
```

The default leaves B selected in TWRP; add `--end-in-fireos` to select A and
boot normally once every readback passes. This restores A only: not the
original B images, boot metadata, userdata, preloader, or factory lock
behavior. A stock A bootloader also lacks the Volume Up recovery hook;
retain the bundle and USB connection for the BL2 recovery route.
