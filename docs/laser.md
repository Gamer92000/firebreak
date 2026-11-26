# Root an Amazon Echo (4th Generation)

Use this guide for **Laser, NS6575/build 8349**, on an x86-64 Linux host.
The installer writes the rooted system to **slot B** and selects it. Slot A
stays stock and is never written, so it is the fallback. Userdata is kept.
Read the next section first: the wrong loader image can brick the Echo, and
the rules there are what this route is built on.

## Read first: how a laser gets bricked

Never edit a sealed loader in place. The FIT signature does not cover an
image's `data`, so a loader patched after sealing still verifies under the
preloader's key while its `hash-1` value no longer matches the payload.
The preloader checks exactly that and refuses the image. Flashed to **both**
`uboot` partitions, it leaves no loader that ever runs: black LEDs, a loop
before the kernel, and no console to show why. A loader that verifies is
not thereby a loader that boots.

Established on hardware (2026-11-26): every image with a stale data hash
completes the preloader transfer with a correct checksum and is then
refused (3 of 3: no `00 00`, or a non-zero reply); every image sealed
through the builder went through (8 of 8); the stale hash was the only
difference. The refusal reads as "BL2 response mismatch" right after the
checksum, which looks like a handshake problem and is not one. Fastboot
would write the same image without a word, because it verifies nothing it
writes.

Hard rules, non-negotiable, for any work here:

1. Only sealed images, ever: built through the builder's seal
   (`images.shadow`), never by editing a sealed file. Before any upload or
   flash, check `sha256(payload) == hash-1`. The preloader's verdict over
   its download port is a real one: an image it refuses there must never
   be written through fastboot.
2. Never flash both slots of a boot-critical partition in one step. Flash
   one slot, verify a full boot end to end, then mirror.
3. No image can be boot-tested before it is flashed, so never pretend one
   was. A RAM-loaded loader only ever sits in fastboot and cannot boot the
   device: it resets about 30 s after an attempt (seen 2026-11-26: three
   different RAM images, reset at 31.7, 31.8 and 31.8 s). The download
   path most likely leaves the secure monitor out, so the normal boot
   path's first call into it (`do_reset` is a PSCI `SMC`) hangs until the
   watchdog. That mechanism is inferred from the timing, not read out of
   the box. A `reboot` sent to a RAM loader hangs the same way, and the
   reset comes from the watchdog. What stands in for a test: sealed and
   hash-checked, the smallest possible diff from stock, the patched
   function's callers traced in the disassembly, and prior on-flash
   evidence for that exact patch.
4. Keep the loader's environment byte-identical to stock. Nothing good
   comes from editing it.
5. `bootcmd` ends with `;reset`, so a `bootm` failure is an unrecoverable
   loop. No prompt, no second chance, no console. There is **no UART on
   the laser board** (TM10 and TM11 are LED I2C).
6. A listed `0e8d:2000` port is not necessarily a listening preloader.
   After a refused image the preloader hangs until the watchdog resets the
   Echo about 30 s later, and the port stays enumerated and answers
   nothing until then. Only a power cycle or a reset gives a live one. A
   live download window lasts about 1.3 s after the port appears, and its
   tty node cannot be opened for its first ~100 ms.

An Echo whose loaders were both refused is not necessarily lost: its
preloader window still takes a sealed `access.img`, and that loader's
fastboot can write sealed stock loaders back. That way back is untried.

## What the route does

Laser's stock fastboot refuses every flash command, so the route rides the
preloader. At power-on the preloader briefly exposes MediaTek's legacy USB
download, `0e8d:2000`. Through it the installer uploads `access.img`: the
stock U-Boot FIT with its fastboot restriction check patched out and
re-sealed under the preloader's own key. The loader in RAM then writes
slot B through its unrestricted fastboot.

1. The bundle is verified before USB is touched: serial, product, build
   and the checksum of every image; each loader's seal (data hash fresh,
   signed stream equal to stock, signature under Amazon's key) and its
   identity as the image that ran on hardware; and that the system image
   is cut into pieces which put it back byte for byte.
2. You disconnect the power, press Enter and power the Echo on. The
   listener is already running and uploads the access loader in the
   preloader window. The loader's fastboot is then asked for its serial,
   its product, the size of every partition and its `max-download-size`.
3. The rescue move is practised with nothing written: the loader is sent
   `reboot`, which hangs until the watchdog resets the Echo about 30 s on,
   and the preloader window after that reset is caught and given the
   loader again. If it is not caught, the run stops here.
4. After a confirmation, the route writes, in this order: `boot_b` (the
   stock boot image), `uboot_b` (the builder's `verity.img`, the stock
   loader with its verity gate off), `system_b` (the rooted system, as ten
   sparse pieces of one download each) and last `misc`, the block that
   selects slot B.
5. You power-cycle the Echo. It boots the rooted system on slot B, and the
   route waits for it over USB adb, then checks the slot, root, SELinux and
   that the adb network listener is off.

Nothing is written to slot A, the preloader, `lk`, `tee1`, `tee2`,
`recovery`, `persist` or `idme`. The LK that burns anti-rollback eFuses on
loader updates is never touched, because `verity.img` goes into a `uboot`
partition and is not a loader update. `reboot` is never sent after a
write: from a RAM loader it hangs, and the watchdog reset that follows is
no way to start a first boot.

Every run writes all ten pieces. A reflash therefore takes a few minutes
longer than it might, but no run can ever skip a piece on the assumption
that it is already on the Echo.

Units on another build: the route was shown on a unit on 8349 only. It
writes the 8349 system, boot image and loader into slot B and leaves the
shared `tee1`, `tee2` and `lk` partitions as they are. Whether an older
TEE runs the 8349 system is not analysed.

## Prepare the host

Start from a checkout containing this change. Run these commands from the
repository root:

```sh
sudo apt install adb fastboot
uv sync
sudo groupadd -f plugdev
sudo install -m 644 contrib/73-laser.rules \
  /etc/udev/rules.d/73-laser.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo usermod -aG plugdev "$USER"
```

Log out and back in if your account was added. Keep the Echo off Wi-Fi
until rooting completes, so an update cannot replace the supported
firmware.

## Connect USB

Bring out USB the way you already did for fastboot, and keep the Echo's
power within reach. The route asks you to disconnect the power, starts its
listener, and asks you to connect power so that it catches the brief
`0e8d:2000` window. Holding the action button while powering on enters the
stock fastboot, which the route never writes through. The wires stay
useful afterwards: a rescue needs them too.

## Build the bundle

[laser-os-builder][os-builder] builds everything the route consumes:
`access.img`, `verity.img`, `boot_b.img` (the pinned stock boot image) and
the rooted `system_a.img`, with the `bundle.json` manifest this installer
verifies. Follow its README; the build's system step needs sudo. Use the
same USB serial for building and installation:

```sh
LASER_SERIAL=REPLACE_WITH_USB_SERIAL
LASER_BUNDLE=/absolute/path/to/laser-os-builder/work/bundle
```

[os-builder]: https://github.com/Gamer92000/laser-os-builder

## Check first, with nothing written

This runs everything up to the writes: the bundle checks, the upload, the
loader's identity and partition sizes, and the rescue rehearsal. It leaves
the loader in fastboot, which a power-cycle ends.

```sh
uv run firebreak unlock --device laser \
  --bundle "$LASER_BUNDLE" \
  --serial "$LASER_SERIAL" \
  --check
```

## Install

Then the install itself. It repeats the checks, asks before the first
write, and ends by waiting for the rooted Echo:

```sh
uv run firebreak unlock --device laser \
  --bundle "$LASER_BUNDLE" \
  --serial "$LASER_SERIAL"
```

It asks you to power-cycle the Echo once the slot is written, then checks
what booted: slot B, keyless root USB adb, SELinux enforcing, and the adb
network listener off.

If a write fails, the run stops there and writes nothing after it. Slot A
is untouched throughout, so the Echo still boots as long as `misc` was not
reached; rerun the command to repeat every write.

## Going back, and the way back

`--select-a` writes only the `misc` block that selects slot A again. It is
the undo of an install, and it is the rescue for an Echo that does not
boot: it needs no working system, only a preloader window, and it catches
the next one, for up to ten minutes.

```sh
uv run firebreak unlock --device laser \
  --bundle "$LASER_BUNDLE" \
  --serial "$LASER_SERIAL" \
  --select-a
```

Disconnect the power, press Enter, power the Echo on, and power-cycle it
again when the block is written: it boots stock slot A. With `--check`
added, the command loads the loader and stops, to show that a window can
be caught, with nothing written.

## The boot-control block

The LK reads its slot decision from the end of `misc`'s first 0x368 bytes:
a magic `0x42424100`, an init byte, and one flags byte per slot. The
priority is the **inverted** low nibble (0xE is selected, 0xF is not), the
tries are bits 4 to 6, and bit 7 marks a slot successful. The route writes
the block with slot B selected, three tries, and both slots marked
successful. That is the block the first rooted laser booted from, on a
cold start and again after a reboot (2026-11-26). `--select-a` writes the
same block with the other nibble selected.

Fastboot reports `misc` as 0x80000 bytes, while the kernel's partition
table gives `mmcblk0p8` 1024 bytes. The route writes 0x80000, as fastboot
expects; the block sits in the first 0x368 bytes either way.

## What was shown on hardware

All of it on one unit on build 8349, 2026-11-26:

- A sealed loader goes through the preloader window: 8 uploads of 8. One
  edited after sealing is refused after a correct checksum: 3 of 3.
- A RAM-loaded loader only sits in fastboot. Three images reset at 31.7,
  31.8 and 31.8 s after an attempt to boot.
- The system went in as ten sparse pieces, about 308 MB of downloads for
  the 1 GB image.
- Slot B booted from a cold start and again after `adb reboot`, with the
  stock `boot_b`, `verity.img` in `uboot_b` and the rooted `system_b`.
  Root USB adb came up by itself, about 29 s after the reboot.
- The stock unit's `recovery` partition is 16 MiB of zeros. Stock never
  uses it, and neither does this route.
- The route's own `--check` (a second run the same day): the listener caught
  the window and the access loader went through it. The loader answered
  fastboot with the serial, `product laser`, the surveyed partition sizes and
  `max-download-size`. `fastboot devices` lists it as `Android Fastboot`, not
  `fastboot`; the route's first run stopped on that difference.

Those writes were first made by the day's separate stage tools, kept in
the OS builder's `work/tools/2026-11-26/`. This route makes the same
writes, in the same order, with the same loader and the same `misc`
block, and ran end to end on the same unit later that day: its `--check`
(the window, the loader's identity, the rescue rehearsal) and then its
thirteen writes, with the Echo Dot Assist port baked into the system, and
its checks of the booted Echo. Its first run that day stopped after the
upload, on the loader's `Android Fastboot`; the fix was checked against
the loader before the install ran.
