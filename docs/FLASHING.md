# Flashing Bruce onto a board

The one page for getting a built image onto real hardware, for every
supported board: the five development boards, which have a BOOT
button, and the sealed Feitian RP2350 USB-C token, which has none. Per
board it covers the buttons and connectors, getting into boot mode
(BOOTSEL), what the board shows after a flash, and the wipe and
recovery procedures; then the flashing troubleshooting list; and, in
its own section at the end, the complete procedure for the USB-C
token. [GETTING-STARTED.md](GETTING-STARTED.md) is the linear path
(tools, build, flash, verify) and covers the common case in a few
commands; this page is where to look when your board's buttons,
connector, flash size or post-flash behaviour differ from the generic
recipe. It assumes a built UF2 -- the build options are in
[BUILD.md](BUILD.md) -- and hands over to [USAGE.md](USAGE.md) once
the token is running.

> WARNING: **Holding a Feitian RP2350 USB-C token? Go straight to
> [The Feitian RP2350 USB-C token](#the-feitian-usb-c-token) at the end of this
> page, and do nothing else first.**
>
> That token has no BOOT button and no working power-on boot mode.
> Nothing between here and its section applies to it: not the boot-mode
> recipes, not `./flash.sh`, not `picotool load`, not the wipe recipe.
> The wrong image, or the right image written the wrong way, can leave
> it running firmware it can never be reflashed out of. Its section says
> how to make that impossible, and `tools/flash-usbc.sh` enforces it.

Both firmwares flash the same way: the C port's UF2 (`bruce-c.uf2`
from `./build-c.sh`, or `c/firmware/build*/bruce_c.uf2`) goes
wherever the Rust `bruce.uf2` goes in the recipes below.
`./flash.sh [file]` is `picotool load -x` with a check that the file
exists; it also reads the image's `pqf-*` markers
([Checking an image before you flash it](#checking-an-image-before-you-flash-it)),
says which board the image was built for and whether its host reboot
waits for a touch, asks for confirmation, and refuses an image built
for the USB-C token. A board that carries no readable marker -- a
blank one, or one with an image not from this tree -- could be a blank
USB-C token, so `flash.sh` refuses it until you say which board it is:
`./flash.sh --board feitian_rp2350` (any `build.sh` board id but the
USB-C token's; the image must have been built for that board). And on
a board that carries a USB-C image it takes only an image whose
markers say `pqf-reboot=no-touch`. After flashing, the
[Verification](#verification) section lists what a correctly enumerated
device reports.

## Which board do you have?

Find your board, then follow its row. Every board except the last one
is flashed with `./flash.sh` once it is in boot mode.

| Board | Buttons | Into boot mode | Flash with | Read |
| --- | --- | --- | --- | --- |
| Pimoroni Tiny 2350 (default) | B (BOOT), R (RESET) | hold B, tap R -- or replug holding B | `./flash.sh` | [Tiny 2350](#board-pimoroni-tiny-2350) |
| Seeed Studio XIAO RP2350 | B, R | hold B, tap R -- or replug holding B | `./flash.sh` | [XIAO RP2350](#board-seeed-studio-xiao-rp2350) |
| Waveshare RP2350-LCD-1.47 | B, RST | hold B, tap RST -- or replug holding B | `./flash.sh` | [Waveshare](#board-waveshare-rp2350-lcd-147) |
| Spotpear RP2350-LCD-1.28 | BOOT, RST | hold BOOT, tap RST -- or replug holding BOOT | `./flash.sh` | [Spotpear](#board-spotpear-rp2350-lcd-128) |
| Feitian RP2350 | one button, no RESET | replug holding the button | `./flash.sh` | [Feitian RP2350](#board-feitian-rp2350) |
| **Feitian RP2350 USB-C token** | **none** (a touch pad) | **only through the firmware on it**; a new token arrives in boot mode | **`tools/flash-usbc.sh`, nothing else** | [**The Feitian RP2350 USB-C token**](#the-feitian-usb-c-token) |

Any board already running `bruce` can also be put into boot mode
from the host, without a button: see
[Software BOOTSEL entry](#software-bootsel-entry-no-button).

Contents:

- [Which board do you have?](#which-board-do-you-have)
- [Prerequisites](#prerequisites)
- [Software BOOTSEL entry (no button)](#software-bootsel-entry-no-button) -- including [what each board does by default](#what-each-board-does-by-default) and [checking an image before you flash it](#checking-an-image-before-you-flash-it)
- The development boards:
  - [Pimoroni Tiny 2350](#board-pimoroni-tiny-2350) (default board)
  - [Seeed Studio XIAO RP2350](#board-seeed-studio-xiao-rp2350)
  - [Waveshare RP2350-LCD-1.47 (-A / -B / -B-M)](#board-waveshare-rp2350-lcd-147)
  - [Spotpear RP2350-LCD-1.28](#board-spotpear-rp2350-lcd-128)
  - [Feitian RP2350](#board-feitian-rp2350)
- [Flashing the C port](#flashing-the-c-port)
- [Verification](#verification)
- [Updating firmware (no wipe)](#updating-firmware-no-wipe)
- [Wiping the device](#wiping-the-device)
- [Troubleshooting](#troubleshooting)
- [**The Feitian RP2350 USB-C token**](#the-feitian-usb-c-token) -- the complete procedure; nothing else on this page applies to it:
  - [What this token is](#what-this-token-is)
  - [The three ways to lose it](#the-three-ways-to-lose-it)
  - [The rules](#the-rules)
  - [Before you start](#before-you-start)
  - [Step 1: build the image and check it](#step-1-build-the-image-and-check-it)
  - [Step 2: rehearse on a USB-A board](#step-2-rehearse-on-a-usb-a-board)
  - [Step 3: flash the token](#step-3-flash-the-token)
  - [Step 4: check that it works](#step-4-check-that-it-works)
  - [Updating the firmware later](#updating-the-firmware-later)
  - [The LED](#the-led)
  - [When something goes wrong](#when-something-goes-wrong)
  - [What is not yet known about this token](#what-is-not-yet-known-about-this-token)
  - [Why the defaults are what they are](#why-the-defaults-are-what-they-are)
- [Going further](#going-further)

> WARNING: **Flashing is non-destructive to credentials in normal use.**
> A `picotool load -x` overwrites the firmware area only; the
> credential store (last 4 KiB sector) and any persisted PIN / config
> survive. Use the [Wiping the device](#wiping-the-device) recipe
> when you actually want a clean slate. **Switching between the Rust
> and C firmware is the exception: erase first** (see
> [Intermittent dark device](#intermittent-dark-device-after-flashing-erase-first)).
> The Feitian RP2350 USB-C token is the other exception: its flashing
> tool erases the first 2 MiB before every write, so expect every
> update of a USB-C token to wipe its credentials and PIN.

---

## Prerequisites

`picotool` >= 2.0 on the host, installed as described in
[GETTING-STARTED.md](GETTING-STARTED.md#2-install-the-tools), and a
built UF2 (`./build.sh` or `./build-c.sh`). A data-capable USB cable
and a direct port on the host: skip hubs for the first bring-up so
picotool can talk to the boot ROM without an extra hop. On Linux,
the udev rules from `tools/udev/` so the board and the token are
reachable without root.

---

## Software BOOTSEL entry (no button)

If the firmware already on the token implements `CTAPHID_CMD_REBOOT`
(both current ports do, on every board; only images from before the
command was added lack it), you can drop it into BOOTSEL **from the
host, no button dance**, with the in-tree reboot CLI:

```bash
make -C c/hid reboot                       # one-time build
c/hid/reboot --list                        # which Bruce tokens are attached; sends nothing
c/hid/reboot bootsel                       # -> BOOTSEL
# (Rust equivalent: cargo run -p pqf-ctaphid --example reboot -- bootsel)
```

Whether that reboot waits for a press depends on the board the image
was built for ([What each board does by default](#what-each-board-does-by-default),
below). Once the board is in boot mode, flash as usual (on a USB-C
token, `tools/flash-usbc.sh` does all of this itself -- see
[The Feitian RP2350 USB-C token](#the-feitian-usb-c-token)):

```bash
until picotool info -a 2>/dev/null | grep -qi 'boot type:.*bootsel'; do sleep 0.5; done
picotool load -x bruce.uf2
```

Full details, the `reboot_no_up` build option, and the host API are in
[`docs/REBOOT.md`](REBOOT.md).

### What each board does by default

Both firmwares always contain the host-driven reboot into boot mode
("software BOOTSEL"): it is not optional and needs no build flag on any
board. What differs per board is only **whether that reboot waits for
a press**, and that is decided by the board profile you build for:

```
reboot waits for a press  =  the board has a readable button
                             AND the board has a power-on boot mode (a button you can hold while plugging in)
                             AND the build does not say reboot_no_up / PQF_REBOOT_NO_UP
                             AND the build is not a test_no_user_button / PQF_TEST_NO_USER_BUTTON build
```

Which gives, for a default build of either firmware:

| Board | FIDO presence (register / log in) | Software boot mode (`c/hid/reboot bootsel`) | Physical fallback |
| --- | --- | --- | --- |
| Pimoroni Tiny 2350 | **Real**: BOOT button (or the GP0 pad, Rust) | **Press the button** within 10 s | Hold BOOT, tap RESET |
| Feitian RP2350 | **Real**: the BOOTSEL button | **Press the button** within 10 s | Hold the button, replug |
| **Feitian RP2350 USB-C token** | **Real**: the touch pad (confirmed on one production token) | **No touch, by design** | **None** |
| Seeed XIAO RP2350 | Auto-confirms (no readable button) | No touch (nothing to press) | Hold B, tap R |
| Waveshare RP2350-LCD-1.47 | Auto-confirms | No touch | Hold BOOT, tap RST |
| Spotpear RP2350-LCD-1.28 | Auto-confirms | No touch | Hold BOOT, tap RST |
| Any board, built `reboot_no_up` / `-DPQF_REBOOT_NO_UP=ON` | unchanged | No touch (flash-station builds) | as above |

In words: a board with a button gets **button boot mode**; a board
without one gets **buttonless boot mode**; and the USB-C token, which
has a pad for logins but no way to hold anything at power-on, gets
buttonless boot mode **so that getting back in never depends on the
pad**. FIDO presence -- the touch that a website asks for -- is not
changed by any of this on any board. The build option `reboot_no_up`
still exists, but it now only changes anything on the two button
boards; you do not need it for the USB-C token, and must not need it.
Why the USB-C token is the exception is in
[Why the defaults are what they are](#why-the-defaults-are-what-they-are).

### Checking an image before you flash it

Every image records the outcome in its picotool metadata, so it can be
checked before it is flashed. `picotool info -a <file.uf2>` lists these
markers under `features:`, one per line, in no fixed order:

| Marker | Values | Meaning |
| --- | --- | --- |
| `pqf-board=` | `tiny2350`, `xiao_rp2350`, `feitian_rp2350`, `feitian_rp2350_usbc`, `waveshare_rp2350_lcd_1_47`, `spotpear_rp2350_lcd_1_28` | The board profile the image was built for |
| `pqf-reboot=` | `no-touch` / `touch` | Whether the software reboot into boot mode waits for a press |
| `pqf-fido-up=` | `touch` / `auto` | Whether FIDO presence is a real touch or auto-confirms (buttonless board, or a test build) |

For a script, the markers alone:

```bash
picotool info -a bruce.uf2 | grep -o 'pqf-[a-z-]*=[a-z0-9_-]*'
```

An image with none of them predates this scheme and must not go on a
USB-C token. `tools/flash-usbc.sh` reads these and refuses anything but
`pqf-board=feitian_rp2350_usbc` with `pqf-reboot=no-touch`; `./flash.sh`
(for the development boards) names the image's board and refuses a
USB-C token image, because the two tools must never be crossed. The full
reference is [BUILD.md](BUILD.md#identifying-an-image-before-flashing-it).

> WARNING: **A token with no power-on BOOTSEL depends entirely on the
> image it runs.**
>
> The physical recipes below need a **BOOT / BOOTSEL button** held at
> power-on. The Feitian RP2350 USB-C token has none that works: it is
> sealed, and holding its capacitive pad while plugging in does not
> trigger the boot ROM's power-on sensing. Software `CMD_REBOOT` is its
> **only** way into BOOTSEL, so a token running firmware without
> `CMD_REBOOT`, firmware built for another board (whose reboot waits
> for a press the pad might never give), or firmware that hangs before
> USB **cannot be reflashed at all**.
>
> The board profile takes care of the reboot: an image built for
> `feitian_rp2350_usbc` never gates `CMD_REBOOT`, with no build option
> needed (`reboot_no_up` changes nothing on it). What remains is which
> image goes on the token: rehearse the exact UF2 on a USB-A board,
> then flash the token only with `tools/flash-usbc.sh`, which refuses
> any UF2 not marked for that board with a touch-free reboot, erases
> first, and proves the way back after every flash. See
> [The rules](#the-rules) and
> [`docs/REBOOT.md`](REBOOT.md#warning-buttonless-tokens-can-be-locked-out-of-bootsel).

---

## Board: Pimoroni Tiny 2350

[Product page](https://shop.pimoroni.com/products/tiny-2350) /
22.9 x 18.2 mm / USB-C / on-board RGB LED + BOOT + RESET buttons.

### Entering BOOTSEL mode

The Tiny 2350 has **B** (BOOT) and **R** (RESET) buttons on the same
short edge as the USB-C port.

The reliable sequence:

1. **Unplug** the board from USB.
2. **Hold the B button**.
3. While still holding B, **plug the USB-C cable back in**.
4. **Release B** after 1-2 seconds.

The board mounts as a USB mass-storage volume named `RP2350` and
`picotool info` should now report no program info (or `program: Bruce`
if you'd already flashed it before):

```bash
$ picotool info
Program Information
 name:          Bruce
 version:       0.1.0
 description:   Hybrid PQC FIDO2 authenticator on RP2350 (Pimoroni Tiny 2350)
 features:      pqf-board=tiny2350
                pqf-reboot=touch
                pqf-fido-up=touch
 binary start:  0x10000000
 target chip:   RP2350
 image type:    ARM Secure
```

(or `Program Information none` on a fresh / wiped device). The
description names the board the image was built for, and the three
`pqf-*` features say the same in a form scripts can check
([Checking an image before you flash it](#checking-an-image-before-you-flash-it)).

### Flashing

```bash
$ picotool load -x bruce.uf2
Family ID 'rp2350-arm-s' can be downloaded in absolute space:
  00000000->02000000
Loading into Flash:   [==============================]  100%

The device was rebooted to start the application.
```

The `-x` switch executes the new firmware after writing. Within
~1 second the board re-enumerates as a USB HID device (`Bruce
Tiny 2350 PQC`).

### Expected visual indicators

- **Idle**: slow blue blink (heartbeat), about once a second.
- **CTAP2 command in flight** (registering, signing, etc.): red on. The heartbeat pauses while a command runs, so blue holds whatever state it was in: purple if it was on.
- **`KEEPALIVE-UPNEEDED` / Chrome's "Touch your key" window**: fast green flicker, red and blue off.
- **`CMD_WINK`** (host asking the device to identify itself): solid green for ~1 second.

If the LED is **completely dark and not blinking**, the firmware
hasn't started or has panicked. Power-cycle and reflash.

---

## Board: Seeed Studio XIAO RP2350

[Product page](https://www.seeedstudio.com/Seeed-XIAO-RP2350-p-5944.html) /
21 x 17.5 mm / USB-C / single dual-colour user LED on GP25.

### Entering BOOTSEL mode

The XIAO has **B** (BOOT) and **R** (RESET) buttons on the same side
as the USB-C port. The reliable sequence is the same as the Tiny 2350:

1. **Unplug** the board from USB.
2. **Hold the B button**.
3. While still holding B, **plug the USB-C cable back in**.
4. **Release B** after 1-2 seconds.

Or, while plugged in: **hold B, tap R, release B**.

`picotool info` should report the device.

### Flashing

```bash
picotool load -x bruce.uf2
```

### Expected visual indicators

The XIAO has **only one physical LED** (dual red/yellow, on GP25,
active-low). The firmware's three logical channels (R = busy, G = UP-
wait, B = idle) OR-merge onto it, so the colour cue is lost but the
"device is doing something" signal isn't:

- **Idle**: slow orange blink, about once a second.
- **CTAP2 command in flight**: solid orange.
- **UP-wait window**: faster orange flicker.

The on-board NeoPixel chain stays dark -- the firmware drives GP23
(NeoPixel power-enable) LOW to keep VBUS clean during USB
enumeration. See [docs/HARDWARE.md](HARDWARE.md#the-gp23-quirk) for
why this matters.

---

## Board: Waveshare RP2350-LCD-1.47

[Product page](https://www.waveshare.com/rp2350-lcd-1.47.htm) /
RP2350A / USB-C (B / B-M variants) or micro-USB (A variant) /
**16 MB** flash / 1.47" 172x320 ST7789 LCD / WS2812 RGB chain /
micro-SD slot. All three variants share the same GPIO map; only
the USB connector and pin headers differ.

### Entering BOOTSEL mode

The board has **B** (BOOT) and **RST** (RESET) buttons on the side
opposite the USB connector. The reliable sequence:

1. **Unplug** the board.
2. **Hold the B button**.
3. While still holding B, **plug the USB cable back in**.
4. **Release B** after 1-2 seconds.

Or while plugged in: **hold B, tap RST, release B**.

`picotool info` should now report the device.

### Flashing

```bash
picotool load -x bruce.uf2
```

Build the right feature combo first -- this board needs the LCD-
specific feature:

```bash
./build.sh waveshare_rp2350_lcd_1_47          # ML-DSA-65 + LCD stats -> bruce.uf2
MLDSA=87 ED25519=1 ./build.sh waveshare_rp2350_lcd_1_47   # ML-DSA-87 + Ed25519 + LCD stats
```

or, as raw `cargo` commands (then convert with `picotool uf2 convert`
as in [BUILD.md](BUILD.md#uf2-conversion)):

```bash
# Minimal: ML-DSA-65 + LCD stats
cargo build --release --no-default-features -F mldsa65,board_waveshare_rp2350_lcd_1_47
# Full: ML-DSA-87 + Ed25519 + LCD stats
cargo build --release --no-default-features -F mldsa87,board_waveshare_rp2350_lcd_1_47,ed25519
```

### Expected visual indicators

The Waveshare board's **primary status indicator is the LCD**. The
WS2812 RGB chain is held in reset (LEDs dark -- driving it as actual
RGB needs a PIO program with 800 kHz timing, which is future work).

Within ~1 second of flash the LCD lights up and shows:

```
Bruce v0.1.0
Waveshare RP2350-LCD-1.47

Algorithm
ML-DSA-87 + ES256 + Ed25519

USB serial
9798D20A

PIN: not set
Creds: 0
Uptime: 0:00:42

Last op
(none yet)
Op count: 0

Bruce alive
```

The values update live (~5 Hz max for the changeable fields):

- **Uptime** ticks every second.
- **Last op** + **Op count** + **Creds** + **PIN:** update as you
  exercise the device through Chrome / the `probe` example.

If the LCD is **completely dark** after a flash, see
[Troubleshooting -> LCD blank](#troubleshooting) below.

> Tip: **The 16 MB flash quirk.** On this board picotool can't
> autodetect the flash size and `picotool erase -a` fails with
> *"Cannot determine the flash size, so cannot erase the entirety
> of flash, try --range"*. For the full-wipe recipe see
> [Wiping the device](#wiping-the-device) -- TL;DR is
> `picotool erase --range 0x10000000 0x11000000`.

---

## Board: Spotpear RP2350-LCD-1.28

RP2350A / USB-C / 4 MB flash / round 1.28" 240x240 GC9A01 IPS LCD /
QMI8658 IMU (unused) / battery connector. Sometimes badged
`RP2350-LCD-1.28-B` with a metal case option -- bare PCB and cased
versions share the pinout.

### Entering BOOTSEL mode

Same dance as the other boards -- **BOOT** and **RST** buttons:

1. **Unplug** the board (or use RST if it stays plugged).
2. **Hold BOOT**.
3. **Plug in** (or tap **RST**) while BOOT is held.
4. **Release BOOT** after 1-2 seconds; `picotool info` should see it.

### Flashing

```bash
./build.sh spotpear_rp2350_lcd_1_28
./flash.sh
```

which is:

```bash
cargo build --release --no-default-features -F mldsa65,board_spotpear_rp2350_lcd_1_28
picotool uf2 convert -t elf \
    target/thumbv8m.main-none-eabihf/release/bruce \
    bruce.uf2 --family rp2350-arm-s
picotool load -x bruce.uf2
```

### Expected visual indicators

The round LCD lights up with the same stats panel as the Waveshare
board, laid out inside the inscribed square of the circular panel so
nothing clips at the edges. No discrete status LED on this board.

---

## Board: Feitian RP2350

RP2350A / USB-A / Pi Pico 2 reference design (4 MiB flash assumed) /
single green LED on GP25 (active-high) / **one button only** (BOOTSEL,
which doubles as the CTAP user-presence button at runtime).

> WARNING: **This is the USB-A board.** The sealed **RP2350
> USB-C token** is not flashed like this: it has no button, and nothing
> in this section applies to it. Its procedure is
> [The Feitian RP2350 USB-C token](#the-feitian-usb-c-token). This USB-A board
> is where that procedure is rehearsed.

### Entering BOOTSEL mode

There is no separate RESET button on this board, so the recipe is
always a full replug:

1. **Unplug** the board.
2. **Hold the button**.
3. **Plug in** while the button is held.
4. **Release** after 1-2 seconds; `picotool info` should see it.

A factory-fresh unit (blank flash) drops into BOOTSEL by itself -- just
plug it in and the mass-storage volume appears.

### Flashing

```bash
./build.sh feitian_rp2350
./flash.sh
```

which is:

```bash
cargo build --release --no-default-features -F mldsa65,board_feitian_rp2350
picotool uf2 convert -t elf \
    target/thumbv8m.main-none-eabihf/release/bruce \
    bruce.uf2 --family rp2350-arm-s
picotool load -x bruce.uf2
```

### Expected visual indicators

Green LED heartbeat blink once the firmware is up. During a WebAuthn
register/login the LED flickers fast while the device waits for you to
**tap the button** -- the same physical button used for BOOTSEL; a
runtime tap has no reset side effects. Timing out (no tap within 10 s)
fails the operation with `CTAP2_ERR_OPERATION_DENIED` (0x27).

> Tip: **Flash-size quirk (same symptom as the Waveshare).** The sample
> units ship with the `FLASH_DEVINFO` OTP row unprogrammed, so
> `picotool erase -a` may fail with *"Cannot determine the flash size"*.
> Use a bounded range erase instead:
> `picotool erase -r 0x10000000 0x10400000`.
>
> That range is 4 MiB because it is the address window the firmware's
> constants use -- **not** because the die is 4 MiB. The Pico 2 part is
> **2 MiB** (measured; see docs/DFU.md), so the top half of that range
> aliases onto the bottom half and gets erased twice. Harmless, and the
> command is right, but do not read the 4 MiB as a statement about the
> hardware. Do not "fix" the mismatch by programming `FLASH_DEVINFO` --
> that is a one-way fuse and 4 MiB would be a lie. Measure first: write
> a pattern high, read it back low.

---

## Flashing the C port

The C firmware produces a UF2 the same boot ROM accepts -- the BOOTSEL
recipes above apply unchanged (the USB-C token excepted, which uses
`tools/flash-usbc.sh` for either port), only the build step differs:

```bash
./build-c.sh tiny2350          # or any board name; needs PICO_SDK_PATH -- see GETTING-STARTED.md
./flash.sh bruce-c.uf2
```

The C port enumerates as a composite CDC + FIDO HID device -- the CDC
interface prints a liveness banner (`screen /dev/cu.usbmodem*`), and
the FIDO interface answers the `probe` example exactly like the Rust
build. Status surface is the board LED (Tiny 2350 green leg / XIAO
GP25); the C port does not drive the LCD panels. Note the C port has
its **own AAGUID and its own master keys** -- credentials registered
under one firmware do not survive flashing the other (this is by
design; an `authenticatorReset` + re-register is the expected flow
when switching implementations).

---

## Verification

The commands are in
[GETTING-STARTED.md, section 8](GETTING-STARTED.md#8-check-that-it-works):
the in-tree client's `probe` example enumerates the token and prints
the whole `getInfo` map, `register` and `pqc_roundtrip` run a real
MakeCredential / GetAssertion against the device's own keys, and
`alg_roundtrip -- -55` (or `-54` / `-56`) does the same for one named
composite algorithm. The examples read the PIN, if one is set, from
`BRUCE_PIN`.

What to look for in the `probe` output, after flashing **any** board:

- **The product string.** A Rust image names its board (`Tiny 2350
  PQC`, `XIAO RP2350 PQC`, `Feitian RP2350 PQC`, `Feitian USB-C PQC`,
  `RP2350-LCD-1.47 PQC`, `RP2350-LCD-1.28 PQC`; VID:PID `cafe:f1d0`).
  The C image is `Bruce (C port)` (the same `cafe:f1d0`) on every board: it
  names the firmware, not the board, so seeing it on a XIAO or a
  Waveshare is correct.
- **INIT capability flags** should read `WINK`, `CBOR`, `NMSG` (`0x0d`). `NMSG`
  is set on purpose: CTAP1/U2F is off at the transport in a default build, so
  browsers go straight to CTAP2 and attestation stays `fmt="packed"`.
- **`0x01 versions`** should list both `FIDO_2_0` and `FIDO_2_1`.
- **`0x0a algorithms`** count matches your build:
  - **4** entries (`-56/-55/-54/-7`) without the `ed25519` feature.
  - **5** entries (`-56/-55/-54/-8/-7`) with it.

  `-56/-55/-54` are the composite PQ/T identifiers the firmware mints (the
  draft-ietf-jose-pq-composite-sigs-04 requests, still provisional) -- all
  three are advertised whichever ML-DSA variant you built, so this list does
  **not** tell you which variant is compiled in. A device advertising
  `-53/-52/-51` is running firmware from before the 2026-09-30 relabel, and
  one advertising `-50/-49/-48` (the RFC 9964 *pure* ML-DSA ids) is older
  still; see [PROTOCOL.md](PROTOCOL.md#cose-algorithm-identifiers).
- **`0x02 extensions`** include `credBlob`, `credProtect`, `hmac-secret`,
  `largeBlobKey`, `minPinLength`.
- **`0x04 options`** include `rk`, `credMgmt`, `authnrCfg`, `largeBlobs`,
  `pinUvAuthToken` and `setMinPINLength`. `ep` is deliberately absent.
- **`0x05 maxMsgSize` = 7609** -- the CTAP HID hard cap, needed for ML-DSA-87
  hybrid responses.
- **`0x08 maxCredentialIdLength` = 161** -- the compact stateless credentialID.

If `probe` reports all of that and a register / assert round trip
verifies, the device is ready for Chrome / Firefox. See
[USAGE.md](USAGE.md) for the user-facing flow and
[USAGE.md, Inspecting the device](USAGE.md#inspecting-the-device) for
every `getInfo` field.

---

## Updating firmware (no wipe)

After a code change, the typical re-flash cycle is:

```bash
# 1. Rebuild (and convert to UF2): the wrapper does both.
./build.sh                    # or ./build.sh <board>, MLDSA=87 ./build.sh, ...
./build-c.sh                  # the C port

# 2. Put the device back into BOOTSEL (B + RST, as per board section above,
#    or `c/hid/reboot bootsel` from the host).

# 3. Re-flash.
./flash.sh                    # bruce.uf2
./flash.sh bruce-c.uf2     # the C image
```

The raw form (`cargo build --release` with your feature combo, then
`picotool uf2 convert -t elf ... --family rp2350-arm-s`, then
`picotool load -x bruce.uf2`) is in [BUILD.md](BUILD.md).

**Credentials, PIN, large-blob array, and authenticator-config
state persist across firmware updates** -- on every board except the
Feitian RP2350 USB-C token, whose flashing tool erases before every
write ([Updating the firmware later](#updating-the-firmware-later)).
This is by design -- you shouldn't have to re-register at every RP
every time you rebuild the firmware. The credential store sector at `0x103FF000` and the
LargeBlobs sector at `0x103FE000` are NOT touched by
`picotool load -x`, and neither are the overflow credential sectors
below the key sector that a build with extra discoverable-credential
capacity uses. Flashing a build with more of those sectors
(`RK_SECTORS=N`) over a token keeps its PIN and every passkey; flashing
one with fewer (a default build included) corrupts nothing, but the
passkeys in the dropped sectors stop being discoverable until a larger
build is flashed again -- see
[BUILD.md](BUILD.md#axis-7-optional-discoverable-credential-capacity).

If a code change ever bumps the credential-store schema version
(`flash_store::SECTOR_VERSION`), the first boot after the flash
detects the version mismatch and wipes the credential sector
automatically -- you'll see `clientPin: false` and `Creds: 0` on
the LCD / the `probe` example even though you didn't ask for a wipe.
That's a one-shot effect of the schema bump.

### Intermittent dark device after flashing (erase first)

**Erase before flashing, especially when switching ports:**

```bash
picotool erase -a
picotool load -x <the-other-port>.uf2
```

Skipping this hangs the incoming firmware at boot. Observed 2026-08-17
on a Feitian RP2350: a token running the C port was flashed with the
Rust port; it never enumerated and vanished from the USB bus entirely --
no CTAPHID, no CDC, and not in BOOTSEL, so neither `picotool` nor
`CTAPHID_CMD_REBOOT` could reach it. Recovery took a physical BOOT +
RESET. After `picotool erase -a` the **identical** UF2 booted and
enumerated normally, and nine consecutive port-switching flashes with an
erase in front of each one had no failures at all.

**The cause is not identified.** An earlier revision of this note blamed
the credential store; that was wrong, and the reasoning is worth keeping
so nobody re-derives it:

- Both ports put the store at the same place -- `STORE_OFFSET =
  4 MiB - 4096` -> `0x103FF000`, with the keys / large-blob / resident
  sectors just below (and, in a build with extra discoverable-credential
  capacity, its overflow sectors below those). On a board whose `FLASH_DEVINFO` OTP is
  unprogrammed (these USB-A samples), picotool assumes a 2 MiB part:
  the `erase -a` that fixed the device reported *"Erased 2097152
  bytes"*, i.e. `0x10000000`-`0x10200000` only. **The store sits 2,044
  KiB above that and was never erased** -- so it cannot be what the
  erase fixed.
- The ports' sector magics already differ (`"PQCF"` / `"PQKY"` in C,
  `"FIDO"` / `"KEYS"` in Rust), so a foreign store is rejected on the
  magic check and treated as cold regardless.

What the erase *did* clear is the low 2 MiB -- the image region. The
incoming image was smaller than the one it overwrote (333 KB of Rust
over 411 KB of C), leaving ~78 KB of stale image behind it, so a
leftover RP2350 boot block or second `IMAGE_DEF` past the new image is
the current suspect. That is a guess, not a finding: it has not been
tested. The cheap experiment on a spare is to erase only the new image's
extent versus the full 2 MiB and see which one recovers the device.

**It is intermittent, not tied to any one configuration.** Measured over
~28 flashes on 2026-08-17: three went dark, roughly one in nine. The
decisive observation is that the *same* build configuration (no test
flags at all) went dark on one flash and booted normally on another, so
it is not the user-presence gate, not the GDB stub, and not any
particular feature combination -- all three of those were suspected in
turn and each was cleared by a later successful flash of the same
config.

Erasing first has not been shown to prevent it either; it is simply what
recovered the device each time, and no dark event has followed an
erase-then-load on a device that was already erased. Treat a dark device
after flashing as this, not as a bug in whatever you just built: recover
with BOOT + RESET, erase, reflash, and it will almost certainly come up.
A USB-C token has no BOOT + RESET to recover with, which is why its
flashing tool erases before every write
([A firmware that never brings up USB](#a-firmware-that-never-brings-up-usb)).

This also applies to the TrustZone-M split images
([TRUSTZONE.md](TRUSTZONE.md), built with `./build-tz.sh`) -- they
overwrite the FIDO firmware outright, so erase before going back to a
normal build.

---

## Wiping the device

Three reasons to wipe:

1. **Forgot the PIN.** After 8 wrong PIN attempts the device locks
   itself and there's no recovery short of wipe -- the PIN hash
   isn't recoverable from the device, by design.
2. **Returning the device** or handing it to someone else. Wipe
   removes credentials, PIN, large-blob payloads, and rotates the
   master keys so previously-issued credentialIDs become
   permanently undecryptable.
3. **Debugging after a schema bump that didn't auto-wipe.** Rare
   but happens during firmware development.

### Wipe procedure

```bash
# 1. Put device into BOOTSEL (B + RST recipe per board section).

# 2. Erase flash. Picks below by board:

# Tiny 2350 / XIAO RP2350 / Spotpear RP2350-LCD-1.28 (4 MB flash, picotool autodetects):
picotool erase -a                              # what ./wipe.sh tiny2350 runs

# Waveshare RP2350-LCD-1.47 (16 MB flash, autodetect fails):
picotool erase --range 0x10000000 0x11000000

# Feitian RP2350 (flash size not programmed in OTP, autodetect may fail):
picotool erase -r 0x10000000 0x10400000

# Feitian RP2350 USB-C token: none of these -- tools/flash-usbc.sh
# erases as part of every flash (The Feitian RP2350 USB-C token, below).

# 3. Reflash:
./flash.sh                                     # picotool load -x bruce.uf2
```

`./wipe.sh <board>` runs the recipe for the board you name, after
showing the device picotool sees and asking for confirmation (it erases
whatever is in BOOTSEL, so the question is the point); it refuses the
USB-C token. It never tries to reboot the device into BOOTSEL itself
(the `picotool reboot -u -f` path has hung a device before), so enter
BOOTSEL by hand first.

After the wipe + flash cycle:

- `clientPin: false` (PIN destroyed).
- No resident credentials.
- New random master keys derived from the TRNG on first boot --
  any credential the RP has on file for this device is now
  undecryptable. You'll need to register again.
- AAGUID unchanged (it's hardcoded in firmware, not in flash).
- USB serial regenerates random per boot regardless (since
  commit `e718a05`).

> WARNING: **The 4 MB-flash baseline.** Both `STORE_OFFSET`
> (0x103FF000, the credential sector) and `LARGE_BLOB_OFFSET`
> (0x103FE000, the large-blob array sector) are hardcoded
> assuming a 4 MB flash. On the Waveshare's 16 MB flash this
> works -- they're just at the 4 MB mark instead of the actual
> end of flash -- but the wipe range `0x10000000 .. 0x11000000`
> only covers the first 16 MB which is everything on this board.
> Bigger flashes would need wider ranges.

---

## Troubleshooting

### `picotool load` says "No accessible RP-series devices in BOOTSEL mode were found"

The device isn't in BOOTSEL.

1. Check that the USB cable is **data-capable**, not charge-only. Some USB-C cables only carry power.
2. Verify the BOOTSEL procedure for your specific board (above). Try unplug -> hold B -> plug in (full power cycle), don't just tap RST.
3. `ls /Volumes/RP2350` (macOS) or `lsblk | grep RP2350` (Linux) -- if the mass-storage drive appears, BOOTSEL worked and `picotool` should see it too. If neither shows up, swap cables / try a different USB port (avoid hubs).
4. **macOS-specific**: sometimes after a USB-stack hiccup macOS caches the device's previous state. Unplug, wait 5 seconds, replug.

### `picotool load` reports success but the `probe` example shows nothing

Wait 1-2 seconds -- RP2350's USB enumeration sometimes takes a beat after `picotool load -x`'s `-x` (execute) reboot. If after 5 seconds the device still doesn't appear:

- On the Waveshare board, watch the LCD -- if it lights up, the firmware is running and USB is the only thing failing.
- On the Tiny 2350, watch the blue LED for the heartbeat blink -- if it's blinking, firmware is fine.
- If neither indicator works, the firmware probably panicked at boot. Cycle power and reflash with `--features mldsa44` (the smallest variant) to rule out an OOM or PAC peripheral conflict.
- **A dark device after flashing is most often the intermittent failure described in [Intermittent dark device after flashing](#intermittent-dark-device-after-flashing-erase-first)** -- about one flash in nine, independent of what you built. Recover with BOOT + RESET, then `picotool erase -a` and reflash. Do not go hunting in the code you just changed until a second flash of the same image also fails. (A USB-C token has no BOOT to recover with; see [When something goes wrong](#when-something-goes-wrong) in its section.)

### `picotool reboot -u -f` reports "No accessible RP-series devices in BOOTSEL mode were found"

Neither firmware implements the picotool reboot-via-USB (picoboot) vendor interface; the token exposes FIDO HID + CTAP HID only (plus the C port's CDC serial). So `picotool reboot -u -f` works **once per power cycle** -- right after manual BOOTSEL the bootrom's picoboot interface is still detectable; once the firmware has been running for any meaningful time it's gone.

To re-enter BOOTSEL: the manual B + RST recipe per board section, or the firmware's own `CTAPHID_CMD_REBOOT` via `c/hid/reboot bootsel` (see [Software BOOTSEL entry](#software-bootsel-entry-no-button)).

### Chrome doesn't show the device in the WebAuthn picker

This is its own debugging path -- see commits `a1c7b71` (`0x33` vs `0x36` discipline) and `829b172` (algorithm intersection, keepalive starvation, maxMsgSize); `git show <sha>` for the details. The current source has all the Chrome-interop fixes; if you're running an older build, a reflash is the first thing to try.

The most useful diagnostic when this happens: open `chrome://device-log/?refresh=5&types=fido` in a tab BEFORE attempting the WebAuthn op. Watch the log fill with `FIDODebug` / `FIDOError` lines.

### LCD blank (Waveshare only)

If the panel stays completely dark after a flash:

1. Confirm the LCD-stats firmware actually loaded. `picotool info -a` should report `description: Hybrid PQC FIDO2 authenticator on RP2350 (Waveshare RP2350-LCD-1.47)` and list `pqf-board=waveshare_rp2350_lcd_1_47` among its features.
2. Verify USB still works (the `probe` example). If USB is fine but the LCD is dark, the issue is panel-side, not firmware-side.
3. Look for any glow at all from the LCD area -- if there's faint light, the backlight is on but the panel hasn't been initialised (the SPI / pin map may be wrong for an unusual board variant).
4. Check that you used `-F board_waveshare_rp2350_lcd_1_47` (or `./build.sh waveshare_rp2350_lcd_1_47`) when building. A `board_tiny2350` build flashed to the Waveshare won't drive the LCD at all.
5. If the panel was visibly lit before and went dark after a flash, the firmware probably panicked during LCD init. Cycle power; if still dark, drop SPI clock from 32 MHz to 16 MHz in `crates/firmware/src/board/waveshare_rp2350_lcd_1_47/lcd.rs::build()`.

### Compile error: `compile_error!: Bruce: pick exactly ONE of...`

You passed two ML-DSA features (e.g. `--features mldsa44,mldsa65`) or two board features. They're mutually exclusive. Use `--no-default-features` then pick exactly one of each axis.

### Build succeeds but UF2 conversion fails

`picotool uf2 convert` needs the input file's `-t elf` flag, and the `--family rp2350-arm-s` for the firmware's `ImageDef::secure_exe()` configuration (`rp2350-riscv` for a RISC-V image). Skipping either may produce a UF2 the bootrom rejects. `./build.sh` passes both.

---

## The Feitian USB-C token

This section is the procedure for putting `bruce` onto the sealed
**Feitian RP2350 USB-C token** and for updating it afterwards, written
so that following it cannot leave the token unflashable. It is for
anyone who will hold one of these tokens and a cable, and assumes the
tools and a build from [GETTING-STARTED.md](GETTING-STARTED.md).
Everything about this token that differs from the five development
boards is here. Nothing earlier on this page applies to it, except the
per-board defaults and the image markers in
[Software BOOTSEL entry](#software-bootsel-entry-no-button), which this
section refers back to.

> WARNING: **This token has no way into boot mode except the firmware
> that is already on it.**
>
> Every other board in this project has a BOOT button: hold it while
> plugging in and the chip enters its USB bootloader, whatever is in
> flash. The USB-C token has a capacitive touch pad instead of a button,
> and the RP2350's power-on boot-mode sensing does not work through it.
> So the **only** way to reflash this token is to ask the firmware that
> is running on it to reboot into boot mode. If that firmware cannot do
> so -- because it wants a touch that never comes, because it was built
> for a different board, or because it never started at all -- the
> token stays exactly as it is, **for ever**. Nothing in this section
> can fix that afterwards. The whole point of the section is that it
> never happens.

If you only read one part of this section, read [The rules](#the-rules).

In this section:
[What this token is](#what-this-token-is) --
[The three ways to lose it](#the-three-ways-to-lose-it) --
[The rules](#the-rules) --
[Before you start](#before-you-start) --
[Step 1](#step-1-build-the-image-and-check-it),
[Step 2](#step-2-rehearse-on-a-usb-a-board),
[Step 3](#step-3-flash-the-token),
[Step 4](#step-4-check-that-it-works) --
[Updating the firmware later](#updating-the-firmware-later) --
[The LED](#the-led) --
[When something goes wrong](#when-something-goes-wrong) --
[What is not yet known about this token](#what-is-not-yet-known-about-this-token) --
[Why the defaults are what they are](#why-the-defaults-are-what-they-are).

### What this token is

A sealed USB security key: an RP2350A and its flash on the
Raspberry Pi Pico 2 reference design, in a case with a USB-C plug, one
LED and a **capacitive touch pad**. Electrically it is the Pico 2
USB-A development board with the button replaced by the pad.

What it does not have:

- **No BOOT button and no RESET button.** The pad is the only input.
- **No working power-on boot mode.** On every other board, holding BOOT
  while plugging in enters the RP2350 boot ROM's USB bootloader ("boot
  mode", also called BOOTSEL; the `RP2350` drive appears and `picotool`
  can flash). Touching the pad while plugging in does not do that on
  this token -- the pad's controller is not asserting anything at the
  instant the ROM looks.
- **No known debug connector.** Whether the SWD pads are reachable
  without opening the case is not known (see
  [What is not yet known](#what-is-not-yet-known-about-this-token)).
  Assume they are not.

What arrives: a token with **blank flash** (confirmed on the first
production token, 2026-10-02). A blank RP2350 has nothing to run, so
its boot ROM presents the `RP2350` drive by itself. Plug it in and it
is in boot mode. That is the one and only time this token
enters boot mode without being asked by firmware; from the first flash
on, the firmware has to do it.

What runs on it: either firmware, built for the board profile
`feitian_rp2350_usbc`. The Rust image shows up as the USB product
`Feitian USB-C PQC`; the C image, like on every board, as
`Bruce (C port)`. Built for that profile, the reboot into boot mode
never waits for a touch, while FIDO logins still need the pad (the
table in [What each board does by default](#what-each-board-does-by-default)).

Where it stands: **one production USB-C token has run this firmware.**
The board profile was derived from the USB-A board plus one USB-C
sample, on which the runtime touch worked and the power-on boot mode
did not. The procedure in this section was rehearsed on a Pico 2
USB-A board first: on 2026-09-23 both USB-C images, Rust and C, went
through `tools/flash-usbc.sh` four times with `PASS` each time,
including switching between the two ports, and the reboot into boot
mode took about a second with no touch
([TESTING.md](TESTING.md#the-usb-c-token-procedure-rehearsed-on-the-usb-a-feitian-2026-09-23)).
On 2026-10-02 the first production token, blank on arrival, took the
Rust image the same way (`PASS`, boot mode with no touch in 2 s) and
then registered and logged in through its pad at the first attempt
([TESTING.md](TESTING.md#the-first-production-usb-c-token-2026-10-02)).
That is one token and one port, so the board profile stays
**experimental** until more have been through this procedure. What is
measured and what is still assumed is listed in
[What is not yet known about this token](#what-is-not-yet-known-about-this-token).

For comparison, Token2's RP2350 keys keep a BOOT button that doubles as
the touch button, and their documentation warns that disabling
bootloader access makes a key non-upgradable without "specialized
hardware or factory intervention". This token is in that state
permanently, by construction. What they get from a button, we have to
get from the firmware -- which is why the rules below are strict about
which firmware goes on.

### The three ways to lose it

"Lose" means: the token can never be reflashed again. It may still work
as a security key, or it may be dark. Either way, the firmware it has
is the firmware it keeps.

#### A firmware that wants a touch before it reboots

Both firmwares can reboot into boot mode on request from the host: the
vendor command `CTAPHID_CMD_REBOOT`, sent by `c/hid/reboot bootsel`
([REBOOT.md](REBOOT.md)). On a board with a button, that command is
**gated on a button press**, like a WebAuthn touch: a host cannot knock
your key offline into boot mode without you confirming it. That is the
right default for a board with a button, because if the press never
comes you can still hold BOOT and replug.

On this token there is no such fallback. If the running firmware gates
the reboot on a touch, and the pad does not register (unproven
hardware, a case that shifted, a controller that needs recalibrating,
nobody at the desk), the reboot times out, the token stays a security
key, and there is no second way in. **Every image built for any other
board is exactly such an image.** The USB-A board build, the Tiny
2350 build, and any build from before the USB-C profile existed all
gate the reboot on a press.

The USB-C board profile removes that gate for the reboot, and only for
the reboot; FIDO logins still require the touch. Whether an image is
safe in this respect is written into the image itself and can be read
before flashing
([Checking an image before you flash it](#checking-an-image-before-you-flash-it)):

```bash
picotool info -a bruce.uf2 | grep -o 'pqf-[a-z-]*=[a-z0-9_-]*'
```

must print `pqf-board=feitian_rp2350_usbc` and `pqf-reboot=no-touch`.
Anything else, or nothing, is not for this token.

#### A firmware that never brings up USB

The reboot command travels over USB. A firmware that hangs before it
enumerates cannot receive it, so a token that comes up dark is a token
that stays dark. Four things do that:

- **The intermittent dark device after flashing.** On the Feitian RP2350
  board, roughly **one flash in nine** came up dark -- no FIDO device,
  no serial port, not in boot mode -- when the new image was loaded
  over the old one without erasing first (28 flashes, 3 dark, measured
  2026-08-17; [Intermittent dark device](#intermittent-dark-device-after-flashing-erase-first)).
  On the USB-A board that costs a BOOT-and-replug. On this token it
  costs the token. No dark event has followed an erase-then-load, so
  **the flash is always erased before it is written** here, and the
  tool in this procedure does it for you every time. The price is that
  a reflash also erases the credential store and the PIN (see
  [Updating the firmware later](#updating-the-firmware-later)).
- **A RISC-V or mixed-architecture image.** Running one leaves core 1
  switched to RISC-V, and the next plain Arm image then hangs before
  USB ([RISCV.md](RISCV.md), [BUILD.md](BUILD.md)). On a dev board the
  cure is `picotool reboot -a -c arm` from boot mode, which this token
  cannot reach. So: no `RISCV=1`, no `core1_riscv`, no
  `--target riscv32imac-unknown-none-elf` builds, ever, on this token.
- **Images that are not a plain, whole firmware.** The TrustZone-M pair
  (`build-tz.sh`), the DFU bootloader and its app-slot images
  (`c/bootloader/`, `PQF_APP_OFFSET`, [DFU.md](DFU.md)), the GDB-stub
  build, the network-gadget bring-up firmware, the `button_scan` tool,
  and anything experimental. Each has its own way of not coming up as a
  FIDO device. None of them belong on a token that cannot be recovered.
- **An interrupted write.** A blank flash is safe (the ROM falls back
  to boot mode). A half-written image is not: a complete header with
  truncated code behind it boots into nothing and hangs. The write
  takes a few seconds; the token must stay plugged in for all of them,
  and the tool verifies every byte before it reboots the token.

#### A one-way change to the chip

The RP2350 has one-time-programmable fuses. Some of them switch off the
USB bootloader interfaces, some enable secure boot so only signed
images run, one records the flash size. Every one of them is permanent,
and this project has tooling that writes them
(`tools/secureboot-provision.sh`, `build-secureboot`, `picotool otp`;
[SECUREBOOT.md](SECUREBOOT.md)). On a board with a button you can at
least get into boot mode after a mistake and see what you did. On this
token a wrong fuse is final. Do not run any of it against a USB-C
token.

### The rules

Print this section and put it next to the tokens.

**Always**

1. **Build for the right board:** `./build.sh feitian_rp2350_usbc` or
   `./build-c.sh feitian_rp2350_usbc`. No other board name. No extra
   knobs unless [BUILD.md](BUILD.md) says they are safe for this board.
2. **Flash with `tools/flash-usbc.sh` and nothing else.** It refuses
   any image that is not for this token, erases before it writes,
   verifies what it wrote, and then **proves the way back** by rebooting
   the token into boot mode and out again without a touch. If it does
   not end with `PASS`, stop and read
   [When something goes wrong](#when-something-goes-wrong).
3. **Rehearse first.** Run the identical UF2 through the identical
   command on a Feitian RP2350 before it goes near a USB-C token.
   The USB-A board is the same chip on the same reference design: a
   file that fails there would fail on the token, and there you have
   lost nothing. A file that passes there leaves only the differences
   listed in [What is not yet known](#what-is-not-yet-known-about-this-token).
4. **Keep the token plugged in** from the moment the tool starts
   writing until it prints `PASS`. Direct port, not a hub. A laptop on
   mains, not on a dying battery.
5. **Keep a USB-A board.** It is the rehearsal board, and it is the only
   place a new build can be tried without risk.

**Never**

1. Never flash a USB-C token with `./flash.sh`, `picotool load` by hand,
   or by dragging a file onto the `RP2350` drive. They do none of the
   checks.
2. Never flash an image built for another board, or an image from
   before the USB-C profile existed. If `picotool info -a <file>` does
   not print `pqf-board=feitian_rp2350_usbc` and `pqf-reboot=no-touch`,
   it is the wrong file.
3. Never flash a RISC-V, mixed-architecture, TrustZone, DFU, bootloader,
   GDB-stub, gadget or experimental image. Plain Arm builds of the two
   firmwares only.
4. Never unplug a token that the tool is writing.
5. Never write OTP, enable secure boot, disable the bootloader
   interfaces or "fix" the flash-size row on this token.
6. Never hand a token to a user with a test build on it. A test build
   (`test_no_user_button` / `PQF_TEST_NO_USER_BUTTON`) is marked
   `pqf-fido-up=auto` and logs anyone in without a touch. The tool
   warns about it; it does not refuse, because you may want one on the
   bench.
7. Never assume a token that was fine yesterday is fine today. Check
   what is on it with `c/hid/reboot --list` before you plan an update.

### Before you start

You need:

- The tools from [GETTING-STARTED.md, section 2](GETTING-STARTED.md#2-install-the-tools):
  the Rust toolchain and/or the C toolchain, and `picotool` 2.x.
- The reboot CLI built: `make -C c/hid reboot`. (`tools/flash-usbc.sh`
  builds it if it is missing.)
- **A Feitian RP2350**, for the rehearsal.
- The USB-C token, and a data-capable USB-C cable into a **direct port**
  on the host. No hub for this.
- On Linux, the udev rules from `tools/udev/` so the token and the
  `RP2350` boot device are reachable without root.

Check that nothing else is attached that could be mistaken for the
token:

```bash
c/hid/reboot --list      # Bruce tokens in application mode
picotool info -a         # RP2350 devices in boot mode
```

The tool refuses to run with more than one candidate of either kind
attached, so a flash station can never write the wrong device.

### Step 1: build the image and check it

Build for the USB-C board -- that one word is the whole safety
difference:

```bash
./build.sh feitian_rp2350_usbc          # Rust  -> bruce.uf2
./build-c.sh feitian_rp2350_usbc        # C     -> bruce-c.uf2
```

No `REBOOT_NO_UP=1` is needed: the board profile already makes the
reboot touch-free. `MLDSA=44|65|87` is fine. `SINGLE_CORE=1` is fine.
`RISCV=1` is **not** (see
[A firmware that never brings up USB](#a-firmware-that-never-brings-up-usb)).

Then check the file without touching any hardware:

```bash
tools/flash-usbc.sh --check bruce.uf2
```

It prints the three markers it found and exits 0 for a file that may
go on a USB-C token. It **refuses** (exit 2) a file built for another
board, a file whose reboot wants a touch, a RISC-V file, a file linked
for the DFU app slot, or a file too old to carry markers -- and says
which. There is no override flag, on purpose. If it refuses, rebuild;
do not look for another way to flash.

### Step 2: rehearse on a USB-A board

Plug in the Feitian RP2350 (and nothing else), and run the real
command on the file you just checked:

```bash
tools/flash-usbc.sh bruce.uf2
```

It walks through numbered steps: it inspects the file again; finds the
board (if the board is running a firmware already, it asks that
firmware to reboot into boot mode -- the USB-A board's older images
want a press for that, so **press its button when the LED blinks
fast**); erases the flash; writes and verifies the image; reboots the
board and waits for it to come up as a FIDO device; and then **reboots
it into boot mode again and back, with no touch**, which is the proof
that this exact file can always be reflashed. The last line is

```
PASS: the token went back into boot mode with no touch and is running again.
```

The USB-A board is now running the USB-C image. That is fine and
expected: same chip, same pins, and its button is what the image reads
as the pad. Register and log in once
([GETTING-STARTED.md, section 8](GETTING-STARTED.md#8-check-that-it-works))
so you have seen the FIDO side work as well.

If anything other than `PASS` comes out, the USB-C token does not get
this file. Fix the build, rehearse again. Nothing about the USB-A board
is at risk in this step -- it has a button.

### Step 3: flash the token

Unplug the USB-A board. Plug in the USB-C token, alone, into a direct
port.

- A **new** token is blank and appears in boot mode by itself.
  `picotool info -a` shows a `Device Information` block and the
  `RP2350` drive mounts. Nothing to press, nothing to hold.
- A token **already running `bruce`** appears as a FIDO device
  (`c/hid/reboot --list` shows it). The tool will ask it to reboot into
  boot mode; because it is running a USB-C image, that needs no touch.

Run the identical command on the identical file:

```bash
tools/flash-usbc.sh bruce.uf2
```

and do not touch the cable until it prints `PASS`. Read the steps as
they go by; each one says what it is doing and what it saw. The erase
and the write take a few seconds each; the two round trips at the end
take a few seconds more.

`PASS` means: the file was the right one, it was written and verified,
it came up as a FIDO device, and it went back into boot mode on request
with no touch and came back again. That is everything this section
exists to guarantee.

### Step 4: check that it works

The same checks as for any board,
[GETTING-STARTED.md, section 8](GETTING-STARTED.md#8-check-that-it-works)
and [Verification](#verification): the `probe` example lists the token
(`Feitian USB-C PQC` for the Rust image, `Bruce (C port)` for C),
`register` and `pqc_roundtrip` make and use a hybrid credential, and a
browser registration at a WebAuthn test site shows the "touch your
security key" prompt.

When the prompt appears, the LED blinks fast: **touch the pad**. This
is the first time the pad matters -- the flashing procedure never
depended on it. If the touch is not registered and the operation times
out after 10 s with `CTAP2_ERR_OPERATION_DENIED`, the token is still
completely recoverable (its reboot does not need the pad), and what you
have learned is that the pad is not where the profile assumes it is.
Note it, and see
[What is not yet known](#what-is-not-yet-known-about-this-token).

### Updating the firmware later

Same three steps: build for `feitian_rp2350_usbc`, rehearse the new
file on the USB-A board, run `tools/flash-usbc.sh <file>` with the
token plugged in. The token is running a USB-C image, so the tool's
request to reboot into boot mode needs no touch, and everything after
that is the same as the first flash.

Two things to know:

- **An update erases the credential store and the PIN.** The tool
  erases the first 2 MiB of flash before every write, because writing
  over an old image without erasing is what preceded every dark device
  ([A firmware that never brings up USB](#a-firmware-that-never-brings-up-usb)).
  On a 2 MiB part -- which the USB-A samples are -- that is the whole
  flash, credentials included. Every relying party has to be
  re-registered afterwards. This is the deliberate trade until the
  cause of the dark device is found; on a token that cannot be
  recovered, a fresh start beats a one-in-nine chance of a dead token.
- **Check what is on the token before you plan.** `c/hid/reboot --list`
  shows the product string. If a token ever ended up with an image that
  gates the reboot (someone bypassed the tool), the update will need a
  touch on the pad within 10 s of the tool's request, and if the pad
  does not work that token is frozen: it keeps working as a key, and it
  will not be updated again.

### The LED

One LED, so the three status channels the firmware has are merged onto
it (the same as on the Feitian RP2350;
[USAGE.md](USAGE.md#led-state-reference) has the three-colour version
for the Tiny 2350):

| LED | Meaning | What to do |
| --- | --- | --- |
| Slow blink, about once a second | Idle, enumerated, ready | Nothing |
| Steady on | A command is being processed (a hybrid signature takes about a second) | Wait |
| **Fast blink** | **Waiting for your touch** -- a website asked for presence, or `authenticatorReset` was requested | **Touch the pad** within 10 s |
| On for one second, then back to blinking | Wink: a host asked this token to identify itself | Nothing |
| Completely dark, token not in `c/hid/reboot --list` and not in `picotool info -a` | Firmware hung or never started | See [When something goes wrong](#when-something-goes-wrong) |

The tool's request to reboot into boot mode does **not** blink the LED
on a USB-C image; the token simply disappears and comes back as the
`RP2350` drive. If you see the fast blink right after
`c/hid/reboot bootsel`, the token is running an image that gates the
reboot -- which it should not be.

### When something goes wrong

| What you see | What it means | What to do |
| --- | --- | --- |
| `tools/flash-usbc.sh --check` refuses the file | The file is not for this token | Rebuild with `./build.sh feitian_rp2350_usbc` or `./build-c.sh feitian_rp2350_usbc`. Do not flash it any other way. |
| The tool says no token was found | Cable, port, or the token is neither in boot mode nor running our firmware | Data-capable cable, direct port, Linux udev rules. A new token should show in `picotool info -a` by itself. |
| The tool says more than one device | Another board or token is attached | Unplug everything but the one you mean. |
| The erase or the write fails | picotool could not talk to the token, or lost it | The token is still in boot mode and its flash is now blank, which is the safe state. Fix the cable or port and run the tool again. |
| Verify fails | The bytes in flash do not match the file | The tool did not reboot the token. It is still in boot mode. Run the tool again; if it repeats, try another port and another cable. |
| After the write, no FIDO device appears within 20 s | The image did not enumerate | Unplug and replug **once**. If it still shows in neither `c/hid/reboot --list` nor `picotool info -a`, this is the dark device. **There is no software recovery on this token.** See below. |
| The proof step fails: the token did not go into boot mode on request | Should not happen with a file the tool accepted | Try `c/hid/reboot bootsel` by hand and watch `picotool info -a`. If the LED blinks fast, the image gates the reboot: touch the pad within 10 s. Do not flash anything else until this works. |
| The proof step fails: the token did not come back after `picotool reboot` | The image hung on its second boot | As for "no FIDO device appears". |
| The token works but `c/hid/reboot bootsel` does nothing | The token is running an image that gates the reboot, or an old image | Touch the pad within 10 s of the command. If that never works, the token is frozen: it keeps working as a key and cannot be updated. |
| Register / log in times out, LED was blinking fast | The pad is not registering | The token is fine and reflashable. The presence input assumption is wrong for this hardware -- record it and see [What is not yet known](#what-is-not-yet-known-about-this-token). |

**A dark token.** If the token draws power, shows no LED, and appears
neither as a FIDO device nor in boot mode after a replug, the firmware
on it is hanging before USB. With no BOOT button and no power-on boot
mode there is no way to send it anything. The only remaining path is
the RP2350's SWD debug port, which means opening the case, finding the
pads (if they exist), and driving them with a debug probe -- and even
then only if the debug port has not been disabled. Treat a dark USB-C
token as lost. Everything above this line exists so that you never
read this paragraph about a token in your hand.

**Belt and braces, later.** The signed-image DFU bootloader
([DFU.md](DFU.md)) can catch an application that fails to boot and fall
back to DFU on its own, which would close the "dark after flashing" gap
that boot mode cannot. It is a different flow with its own layout and
its own risks, it has not been exercised on this token, and this
section does not use it. Do not improvise it on a USB-C token.

### What is not yet known about this token

Until 2026-10-02 everything in this section about the token's hardware
was inherited from the USB-A board and one USB-C sample. The first
production token settled some of it
([TESTING.md](TESTING.md#the-first-production-usb-c-token-2026-10-02));
the rest stays an assumption until it is measured:

| Item | Status | Basis | If wrong |
| --- | --- | --- | --- |
| Touch pad wired to the flash chip-select line (QSPI_SS), read by the same sampler as the USB-A button | **Measured**: register and login through the pad on the first production token | One token, the Rust image. On the earlier sample, runtime touch worked and power-on boot mode did not, which is what a touch controller that is not asserting during the ROM's early sample looks like | A token from another batch wired differently: FIDO presence never confirms (`OperationDenied` after 10 s). The token stays reflashable. A profile change follows. |
| LED on GP25, active-high | Assumed | Pico 2 reference design, as the USB-A board; not confirmed on the production token yet | LED dark or inverted. Cosmetic; token stays reflashable. |
| Flash die size | **Measured**: 2 MiB on the first production token (`picotool` reports 2048 KiB once flash has content) | Matches what the C port declares; the Rust port's 4 MiB address window is harmless on the smaller die (the store sits inside the first 2 MiB on this profile) | Do not program the `FLASH_DEVINFO` row to "fix" anything. |
| Arrives blank | **Confirmed** on the first production token: in boot mode by itself, the first 4 KiB `0xFF`, no OTP boot-flag row set | the vendor's description; the USB-A samples did | If a token arrives with Feitian RP2350's own firmware, that firmware decides how to enter boot mode. **Ask before plugging one in**; do not guess. |
| SWD pads reachable | Unknown | -- | Decides whether a dark token is recoverable at all. |
| Power-on boot mode really unavailable | Assumed | Observed on the one sample; not retried on the production token | If some gesture does enter it, the token is safer than this section assumes. Nice, but do not rely on it. |

Questions worth putting to the vendor before the tokens are opened: the
schematic or at least the pad's pin; whether the SWD pads are
reachable; what is in flash on arrival.

### Why the defaults are what they are

The reboot into boot mode is a vendor extension of the FIDO transport
(`CTAPHID_CMD_REBOOT`, `0x51`), and by default it is gated on the same
touch as a login, so that malware on a host cannot silently drop your
authenticator into a mode where it can be reflashed with anything
(these tokens do not use secure boot: in boot mode the flash is open).
That is the right default for a board that has a button, because the
gate can always be satisfied, and if it cannot, the button gets you
into boot mode anyway.

The USB-C token breaks the second half of that argument. A gate that
might never be satisfied, on a token with no other way in, converts a
failed touch into a dead token. So on this board the reboot is not
gated, and the touch is kept for what it protects best: the FIDO
operations themselves. The trade is explicit -- any software on a host
this token is plugged into can put it into boot mode -- and it is the
same trade every flash station build (`reboot_no_up`) already makes.
Writing it into the board profile, rather than leaving it to a build
flag someone might forget, is what makes the safe build the default
build.

The picotool markers exist for the same reason. A UF2 is a bag of bytes
with a chip family in it; nothing in it used to say which board it was
for or how it would behave. Now every image says both, and the flashing
tool reads them, so the decision "is this file safe for this token" is
made by the file, not by whoever is holding it.

See also: [REBOOT.md](REBOOT.md) for the command and the CLIs,
[BUILD.md](BUILD.md) for the board and the build options, and
[HARDWARE.md](HARDWARE.md) for the board profile itself.

---

## Going further

- [GETTING-STARTED.md](GETTING-STARTED.md) -- the linear path: tools, build, BOOTSEL, flash, verify.
- [docs/USAGE.md](USAGE.md) -- driving the device from the in-tree client examples and from a browser.
- [docs/REBOOT.md](REBOOT.md) -- the host-driven reboot into BOOTSEL, its per-board policy, and the reboot CLIs.
- [docs/HARDWARE.md](HARDWARE.md) -- board pinouts + GPIO maps + the USB descriptor.
- [docs/PROTOCOL.md](PROTOCOL.md) -- the CTAP2 + CTAP1 surface this firmware implements.
- [docs/TESTING.md](TESTING.md) -- verifying the hybrid signature programmatically, and the dated silicon record.
- [docs/BUILD.md](BUILD.md) -- toolchain pin, the full cargo feature matrix, the AAGUID override flag, release-profile rationale.
