# Getting started: from nothing to a working token

This is the one page to follow if you have never built `bruce`
before. It takes you from an empty machine to an RP2350 board that
enumerates as a FIDO2 authenticator, registers a hybrid post-quantum
credential, and logs you in to a website -- with the **Rust** firmware,
the **C** firmware, or both. Every command below was run, in this
order, on a clean checkout while writing this page (see
[Tested with](#tested-with) for the exact versions).

The two firmwares are wire-compatible and flash the same way; only the
build step differs. If you have no preference, build the Rust one
first: it needs fewer tools.

Budget about 20 minutes of your time plus the downloads (the Rust
toolchain is ~1 GiB, the Arm toolchain for the C port ~200 MiB).

Contents:

1. [Pick a board](#1-pick-a-board)
2. [Install the tools](#2-install-the-tools)
3. [Get the source](#3-get-the-source)
4. [Build the Rust firmware](#4-build-the-rust-firmware)
5. [Build the C firmware](#5-build-the-c-firmware)
6. [Put the board into BOOTSEL](#6-put-the-board-into-bootsel)
7. [Flash](#7-flash)
8. [Check that it works](#8-check-that-it-works)
9. [Day to day](#9-day-to-day)
10. [When something goes wrong](#10-when-something-goes-wrong)
11. [Where to go next](#11-where-to-go-next)

---

## 1. Pick a board

Any of the six supported boards works with both firmwares. Nothing
needs soldering; the only wiring is optional. Five of the six are
flashed from this page; the sixth, the Feitian RP2350 USB-C token, is
not -- see its row.

| Board | Presence gesture | Status surface | Notes |
| --- | --- | --- | --- |
| **Pimoroni Tiny 2350** (default) | **Real**: the BOOT button, or an optional touch pad on GP0 | RGB LED | The reference board. USB-C. |
| **Feitian RP2350** | **Real**: its one button (BOOTSEL doubles as the touch button) | Green LED | Pi Pico 2 reference design. USB-A. No RESET button. |
| **Feitian RP2350 USB-C token** | **Real**: a capacitive touch pad (validated on one production token) | Green LED | **Experimental.** Sealed: no button, no display, **no power-on BOOTSEL**. **Do not flash it from this guide; read [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token).** |
| Seeed Studio XIAO RP2350 | Auto-confirmed after a blink window | One two-colour LED | USB-C. |
| Waveshare RP2350-LCD-1.47 (-A / -B / -B-M) | Auto-confirmed | 1.47" LCD stats panel (Rust only) | 16 MiB flash: note the wipe recipe. |
| Spotpear RP2350-LCD-1.28 | Auto-confirmed | Round LCD stats panel (Rust only) | GP12 is the LCD reset, so no QRNG. |

A board with a real presence gesture behaves like a commercial key:
the browser says "touch your security key" and waits for you. The
others confirm presence on their own after the LED blink window; they
are fine for protocol work but are not security keys in the strict
sense.

You also need a data-capable USB cable to the host (USB-C for most
boards, USB-A for the Feitian RP2350). Charge-only cables are the
single most common reason a board "does not appear".

Optional: a momentary switch or a capacitive touch module between GP0
and ground on the Tiny 2350 gives a friendlier presence button than
BOOT. Any polarity works; the firmware learns the idle level during
the first second after power-up, so keep your finger off it while
plugging in. Details in [HARDWARE.md](HARDWARE.md#user-presence-buttons).

---

## 2. Install the tools

Everything is a public, standard tool. The version rules that matter
are called out in bold; they are the ones that cost people an
afternoon.

### 2.1 For both firmwares: git, Rust, picotool

| Tool | Why | Version rule |
| --- | --- | --- |
| `git` | cloning | any |
| `rustup` | installs the pinned Rust nightly on first build | any; the nightly itself is pinned by the tree |
| `picotool` | converts ELF to UF2 and flashes the board | **>= 2.0** for RP2350. **If you also build the C firmware, its major.minor must match your pico-sdk** (2.3.x for SDK 2.3.1). |

The Rust toolchain is pinned by `rust-toolchain.toml` to
`nightly-2025-06-23` with the `thumbv8m.main-none-eabihf` and
`riscv32imac-unknown-none-elf` targets. You install `rustup` once; the
first `cargo build` inside the checkout downloads exactly that toolchain
and those targets by itself. Do not install a nightly by hand.

**macOS** (Homebrew):

```bash
brew install git picotool
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Linux** (Debian / Ubuntu; other distributions have the same
packages under similar names):

```bash
sudo apt install git build-essential pkg-config libudev-dev libusb-1.0-0-dev cmake
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

`picotool` is not in most distributions at a new enough version. Build
it from source, which needs the pico-sdk from
[section 2.2](#22-for-the-c-firmware-cmake-the-arm-gnu-toolchain-pico-sdk)
even if you never build the C firmware:

```bash
git clone -b 2.3.1 https://github.com/raspberrypi/picotool.git ~/picotool
cmake -S ~/picotool -B ~/picotool/build -DPICO_SDK_PATH=~/pico-sdk
cmake --build ~/picotool/build -j
sudo cmake --install ~/picotool/build          # /usr/local/bin/picotool; on Linux also its udev rule
```

`libudev-dev` and `pkg-config` are for the in-tree client examples
(they wrap `hidapi`); `libusb-1.0-0-dev` is for picotool.

**Windows**: install Git for Windows, Rust from <https://rustup.rs>,
and picotool through the [Raspberry Pi Pico Windows
installer](https://github.com/raspberrypi/pico-setup-windows) or the
Pico VS Code extension, both of which also bring the tools in
section 2.2. Run the commands in this guide from the "Pico" developer
shell those installers create, or from Git Bash with the tools on
`PATH`. Raw HID access to a FIDO device on Windows 10 1903 and later
needs an **elevated (Administrator)** prompt; that is Windows policy,
not a limitation of this project. Enumeration works unelevated.

### 2.2 For the C firmware: CMake, the Arm GNU Toolchain, pico-sdk

Skip this section if you only want the Rust firmware.

| Tool | Version rule |
| --- | --- |
| `cmake` | >= 3.13 (pico-sdk's floor) |
| `arm-none-eabi-gcc` | **must come with newlib** (see below) |
| pico-sdk | **2.3.1**, **with the `lib/tinyusb` submodule initialised** |
| `picotool` | **same major.minor as the SDK** (2.3.x), or let the SDK build its own |

**The toolchain must include newlib.** pico-sdk links against libc.
The Arm GNU Toolchain from Arm does; some distribution packages do not.
The symptom of the wrong one is a link failure inside the SDK before
any of this project's code is reached:

```
arm-none-eabi-ld: cannot find -lg
arm-none-eabi-ld: cannot find -lc
```

**macOS**: use Arm's toolchain, not the bare Homebrew formula.

```bash
brew install cmake
brew install --cask gcc-arm-embedded        # Arm GNU Toolchain, includes newlib
```

The Homebrew *formula* `arm-none-eabi-gcc` is a compiler with no C
library and produces exactly the `cannot find -lc` failure above. If it
is already installed and first on your `PATH`, either uninstall it or
put the cask's `bin` directory in front. The cask installs under
`/Applications/ArmGNUToolchain/<version>/arm-none-eabi/bin`; the
tarball from
[Arm's download page](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)
works the same way (extract anywhere, prepend its `bin` to `PATH`).

**Linux**:

```bash
sudo apt install cmake gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib
```

**Windows**: the Pico installer or VS Code extension from section 2.1
provides CMake, Ninja, the Arm GNU Toolchain and the SDK.

**pico-sdk**, any platform:

```bash
git clone -b 2.3.1 https://github.com/raspberrypi/pico-sdk.git ~/pico-sdk
git -C ~/pico-sdk submodule update --init lib/tinyusb
export PICO_SDK_PATH=~/pico-sdk              # put this in your shell profile
```

TinyUSB is a submodule and is not fetched by a plain clone; without it
the firmware fails with `tusb.h: No such file or directory`. The
build scripts default `PICO_SDK_PATH` to `~/pico-sdk` if it is unset.

**picotool and the SDK must agree.** pico-sdk 2.3.x refuses a picotool
older than 2.3.0 at configure time:

```
Incompatible picotool installation found: Requires version 2.3.0, you have version 2.2.0
```

Fix it either way: upgrade picotool (`brew upgrade picotool`, or rebuild
it from the matching tag), or set `PICOTOOL_FORCE_FETCH_FROM_GIT=1`
in the environment and the SDK downloads and builds a private copy
inside the build directory (needs `libusb` on Linux). `build-c.sh`
checks this before CMake does and tells you which.

### 2.3 Linux only: let ordinary users open the token

The token's HID interface and the RP2350 bootloader are root-only on
Linux until udev is told otherwise. The tree ships the rules:

```bash
sudo cp tools/udev/99-bruce.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Then unplug and replug the board. Browsers use the same rule.

### 2.4 Optional tools

- `python3` with the `cryptography` package (`pip install cryptography`)
  -- only for `tools/pqf_sign.py`, which signs DFU images and provisions
  secure boot. Not needed to build or flash.
- A bare-metal RISC-V GCC (`riscv32-unknown-elf-gcc`) -- only for the
  RISC-V and mixed-ISA builds of the **C** firmware
  ([RISCV.md](RISCV.md)). The Rust RISC-V build needs nothing extra;
  rustup fetches the target.
- `screen` or another serial terminal -- the C firmware prints a
  liveness banner on a USB serial port, which is a handy second signal
  that it is running.

---

## 3. Get the source

```bash
git clone https://github.com/cryptsoft/Bruce
cd Bruce
```

That is the whole checkout. Every crate and every vendored library is in
the tree: the Bouncy Castle Rust crates under `crates/bc-rust-mini/`,
the OpenSSL primitives the C port uses under `c/firmware/openssl-mini/`.
No submodules, no sibling checkouts, no private registries.

Orientation, for the parts this guide touches:

```
build.sh         build the Rust firmware  -> bruce.uf2
build-c.sh       build the C firmware     -> bruce-c.uf2
flash.sh         flash a UF2 (board in BOOTSEL)
wipe.sh          erase the whole flash (board in BOOTSEL)
crates/firmware  the Rust firmware
c/firmware       the C firmware (CMake + pico-sdk)
crates/ctaphid-client   the host-side client and its examples (probe, register, ...)
tools/           test drivers, signing, udev rules, vendoring
docs/            everything else, listed at the end of this page
```

---

## 4. Build the Rust firmware

```bash
./build.sh                    # Tiny 2350, ML-DSA-65 (the defaults)
./build.sh feitian_rp2350     # or: xiao_rp2350, waveshare_rp2350_lcd_1_47, spotpear_rp2350_lcd_1_28,
                              #     feitian_rp2350_usbc (build here; flash only per FLASHING.md, USB-C token)
```

The first run downloads the pinned nightly and both targets (a few
minutes, once), then compiles. A cold release build takes a few
minutes; rebuilds are seconds. The result is `bruce.uf2` in the
repository root, about 340 KiB:

```
>> cargo build --release -p bruce --no-default-features --features mldsa65,board_tiny2350
    Finished `release` profile [optimized + debuginfo] target(s)
>> picotool uf2 convert target/thumbv8m.main-none-eabihf/release/bruce bruce.uf2 --family rp2350-arm-s
-rw-r--r--  1 you  staff  345088 bruce.uf2
done. board=tiny2350 mldsa=65 ed25519=0 single_core=0
```

Variants are environment variables on the same script:

| Setting | Effect |
| --- | --- |
| `MLDSA=44` / `MLDSA=87` | ML-DSA security level 2 or 5 instead of 3 (COSE `-54` / `-56` instead of `-55`) |
| `ED25519=1` | also offer EdDSA (COSE `-8`) |
| `SINGLE_CORE=1` | sign on core 0 with a timer-driven keepalive; core 1 stays asleep |
| `REBOOT_NO_UP=1` | the host reboot command needs no touch on the two button boards (Tiny 2350, Feitian RP2350; flash stations). The other boards never ask for one, so it changes nothing there. FIDO presence unchanged |

`./build.sh --help` prints the same list. The script is a thin wrapper;
the underlying commands, for when you want a feature it does not expose
(`core1_riscv`, `dfu_runtime`, a RISC-V target, the AAGUID override), are:

```bash
cargo build --release --no-default-features --features mldsa65,board_tiny2350
picotool uf2 convert -t elf target/thumbv8m.main-none-eabihf/release/bruce \
    bruce.uf2 --family rp2350-arm-s
```

The feature axes are mutually exclusive within an axis (exactly one
`mldsa*`, exactly one `board_*`); getting that wrong is a
`compile_error!` with the list of valid choices. The full matrix, the
RISC-V target and the `BRUCE_AAGUID` override are in
[BUILD.md](BUILD.md).

---

## 5. Build the C firmware

Needs section 2.2 done and `PICO_SDK_PATH` set (or the SDK at
`~/pico-sdk`).

```bash
./build-c.sh                  # Tiny 2350, ML-DSA-65
./build-c.sh feitian_rp2350   # same board names as build.sh, feitian_rp2350_usbc included
```

The script checks the SDK, the TinyUSB submodule, the compiler and the
picotool version before it calls CMake, so a missing prerequisite is
named rather than buried in CMake output. It configures into
`c/firmware/build-<board>/`, builds, and copies the image to
`bruce-c.uf2` in the repository root, about 420 KiB. A cold build
compiles the vendored OpenSSL primitives and takes well under a minute
on a recent machine (add a few minutes the very first time if the SDK
has to fetch and build its own picotool); a second board or a rebuild
takes seconds.

The same knobs as the Rust wrapper apply (`MLDSA=`, `SINGLE_CORE=1`,
`REBOOT_NO_UP=1`), plus `RISCV=1` for a Hazard3 build if you have a
riscv32 GCC, and `CMAKE_EXTRA="-D..."` for anything else, passed to
CMake verbatim.

The raw commands, for reference:

```bash
export PICO_SDK_PATH=~/pico-sdk
cmake -S c/firmware -B c/firmware/build -DPQF_BOARD=tiny2350 -DPQF_HYBRID_VARIANT=65
cmake --build c/firmware/build -j
# -> c/firmware/build/bruce_c.uf2
```

Two things to know about the raw form: CMake's default `PQF_BOARD` is
`waveshare_rp2350_lcd_1_47`, not the Tiny 2350 (the wrapper defaults to
the Tiny so both scripts agree), and the ML-DSA level is
`-DPQF_HYBRID_VARIANT=44|65|87`. Every CMake option is listed in
[BUILD.md](BUILD.md#cmake-options).

What differs from the Rust image once flashed: the C firmware
enumerates as `Bruce (C port)` (USB `cafe:f1d0`) with an extra USB
serial port carrying a liveness banner, it does not drive the LCD
panels (LED or nothing), and it has its own AAGUID and its own master
keys, so credentials registered under one firmware do not carry over
to the other. Both are complete CTAP 2.1 authenticators.

---

## 6. Put the board into BOOTSEL

> WARNING: **Every recipe in this section needs a BOOT button.** The
> Feitian RP2350 USB-C token has no button and no working power-on
> BOOTSEL (holding its touch pad while plugging in does nothing), so
> nothing in sections 6 and 7 applies to it, and flashing it the way
> the other boards are flashed can leave it running an image it can
> never be reflashed out of. If your board is the USB-C token, stop
> here and follow [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token) instead; it uses
> `tools/flash-usbc.sh`, never `flash.sh`.

The RP2350 boot ROM presents a USB mass-storage drive named `RP2350`
when the **BOOT** button is held as the chip comes out of reset. That
is the state `picotool` flashes in. A factory-fresh board with blank
flash drops into it by itself; just plug it in.

The universal recipe, works on every board:

1. Unplug the board.
2. Hold BOOT.
3. Plug the cable back in.
4. Release BOOT after a second.

On boards with a RESET button you can skip the replug: hold BOOT, tap
RESET, release BOOT.

| Board | Buttons | Recipe |
| --- | --- | --- |
| Tiny 2350 | B (BOOT), R (RESET), same edge as USB-C | hold B, tap R, release B -- or the replug recipe |
| XIAO RP2350 | B, R next to USB-C | same |
| Waveshare LCD-1.47 | B, RST opposite the USB connector | same |
| Spotpear LCD-1.28 | BOOT, RST | same |
| Feitian RP2350 | one button, no RESET | replug recipe only |
| Feitian RP2350 USB-C token | none | **no physical recipe** -- [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token) only |

Confirm before flashing:

```bash
picotool info
```

prints `Program Information` for the firmware currently in flash (or
`none` on a blank board). "No accessible RP-series devices in BOOTSEL
mode were found" means the board is not in BOOTSEL: try the full replug
recipe, a different cable, and a direct port rather than a hub. On
Linux, make sure the udev rules from section 2.3 are installed.

If the board is already running `bruce`, it can be rebooted into
BOOTSEL from the host without touching a button:

```bash
make -C c/hid reboot && c/hid/reboot bootsel   # button boards: press within 10 s
```

Whether a press is needed is a per-board policy. The Tiny 2350 and the
Feitian RP2350 -- the two boards with both a button and a power-on
BOOTSEL -- ask for a press within 10 s, unless the image was built
`REBOOT_NO_UP=1`. Every other board, the USB-C token included, reboots
at once. [REBOOT.md](REBOOT.md) has the details and an important
warning about tokens that can be locked out of BOOTSEL.

---

## 7. Flash

With the board in BOOTSEL:

```bash
./flash.sh                    # flashes bruce.uf2 (the Rust image)
./flash.sh bruce-c.uf2     # the C image
./flash.sh --board tiny2350   # the first flash of a blank board: say which it is
```

That is `picotool load -x <file>`: write the image and reboot into it.
Within a second or two the board re-enumerates as a USB HID device.
Before it writes, `flash.sh` reads the image's picotool markers
([BUILD.md](BUILD.md#identifying-an-image-before-flashing-it)) and says
in plain words which board the file was built for, whether its host
reboot into boot mode needs a button press, and how many passkey slots
it has; then it asks you to confirm. Every board's build lands in the
same `bruce.uf2`, so that board line is the check that the file is
the one you meant. An image built for the USB-C token is refused
outright: that token is flashed only with `tools/flash-usbc.sh`. A
blank board carries no marker to read, and a blank USB-C token looks
the same, so the first flash of a blank board needs `--board` with the
board's `build.sh` id (`./flash.sh --board feitian_rp2350`); the image
must have been built for that board.

**Switching between the two firmwares, or coming from an unrelated
image: erase first.**

```bash
picotool erase -a             # Tiny 2350, XIAO, Spotpear (4 MiB, autodetected)
picotool erase -r 0x10000000 0x11000000   # Waveshare (16 MiB; autodetect fails)
picotool erase -r 0x10000000 0x10400000   # Feitian RP2350 (flash size not programmed in OTP)
./flash.sh bruce-c.uf2
```

A plain reflash of the same firmware keeps credentials, the PIN and
the large-blob store (they live in the last flash sectors, which
`picotool load` does not touch). An erase wipes all of that; it is the
factory reset.

What you should see:

| Board | Rust image | C image |
| --- | --- | --- |
| Tiny 2350 | blue LED blinking about once a second; USB name `Tiny 2350 PQC` | green LED on, steady; USB name `Bruce (C port)` plus a serial port |
| Feitian RP2350 | green LED heartbeat; `Feitian RP2350 PQC` | green LED on, steady; `Bruce (C port)` |
| Feitian RP2350 USB-C token | `Feitian USB-C PQC`, same LED profile as the Feitian RP2350 (flashed only with `tools/flash-usbc.sh`) | `Bruce (C port)` |
| XIAO | orange LED blink; `XIAO RP2350 PQC` | LED on, steady; `Bruce (C port)` |
| Waveshare / Spotpear | LCD panel lights up with the stats page; `RP2350-LCD-1.47 PQC` / `RP2350-LCD-1.28 PQC` | no LCD; `Bruce (C port)` |

The USB manufacturer string is `bruce` on every image, so the
device shows up as `Bruce Tiny 2350 PQC` and so on in system tools.
The C image's serial port (`/dev/cu.usbmodem*` on macOS,
`/dev/ttyACM*` on Linux) prints a banner and a heartbeat line; `screen
/dev/cu.usbmodem<n> 115200` shows it.

**A dark board after flashing** (no LED, no USB, not in BOOTSEL) is
almost always the intermittent failure described in
[FLASHING.md](FLASHING.md#intermittent-dark-device-after-flashing-erase-first):
about one flash in nine, independent of what you built. Recover with
the BOOTSEL recipe, erase, flash again. Do not go looking for a bug in
your build until a second flash of the same image also fails.

---

## 8. Check that it works

The host-side client lives in the tree (`crates/ctaphid-client`, crate
`pqf-ctaphid`) and its examples are the test tools. They are built for
the host, not for the firmware target the workspace defaults to, so
every invocation needs the host triple; `./client.sh <example>` supplies
it, and `./client.sh list` names the examples. The long form, should
you want it:

```bash
export HOST_TARGET="$(rustc -vV | awk '/host/{print $2}')"
cargo run -p pqf-ctaphid --example probe --target "$HOST_TARGET"
```

### 8.1 Enumerate and read `getInfo`

```bash
./client.sh probe
```

```
Found 1 FIDO HID device(s):
  <path> cafe:f1d0 Some("Tiny 2350 PQC")
INIT ok: cid=0x00000001 caps=0x0d ver=0.1.0
  caps:  cbor=true wink=true nmsg=true
PING echo verified (27 bytes)
authenticatorGetInfo:
  versions:                  ["FIDO_2_0", "FIDO_2_1"]
  extensions:                ["credBlob", "credProtect", "hmac-secret", "largeBlobKey", "minPinLength"]
  ...
  algorithms:
    alg= -56  type=public-key
    alg= -55  type=public-key
    alg= -54  type=public-key
    alg=  -7  type=public-key
```

The C image shows `cafe:f1d0 Some("Bruce (C port)")`. All three
composite algorithm ids are advertised whichever ML-DSA level you
built; the list does not tell you which one is compiled in (that is
deliberate, see [PROTOCOL.md](PROTOCOL.md#knocommonalgorithms-defence)).
[USAGE.md](USAGE.md#inspecting-the-device) explains every field.

### 8.2 Register and sign

```bash
./client.sh register         # one registration with the token's preferred algorithm (the hybrid)
./client.sh pqc_roundtrip    # register, sign, check the signature, report the level
```

Both print `touch the button now` and then wait: on the Tiny 2350 and
both Feitians the LED flickers until you **press the button** (BOOT
on the Tiny, the one button on the Feitian RP2350, the touch pad on
the USB-C token; a fresh press, not a hold). The other boards confirm on
their own. Ten seconds without a press ends in `OperationDenied`; run it
again. Both send the client's default algorithm list, so the token
picks the strongest it implements, the hybrid; `alg_roundtrip -7` asks
for plain ES256 instead. `pqc_roundtrip` then verifies the ECDSA-P256
half of the assertion signature on the host and checks the ML-DSA half
for the size and shape FIPS 204 fixes. It does not verify the ML-DSA
half: the client crate carries no ML-DSA verifier, and in a deployment
that check is the relying party's; the firmware's own host suites cover
the signer.

### 8.3 Set a PIN

```bash
./client.sh pin_set          # sets 1234 on a PIN-less token
```

After this the examples need the PIN; give it to them in the
environment: `BRUCE_PIN=1234 cargo run ...`. Browsers set and ask for
the PIN in their own dialogs.

### 8.4 A real website

Register a passkey at <https://webauthn.io> in Chrome or Firefox. That
site only understands ES256, so it exercises the classical path;
the hybrid path is what `pqc_roundtrip` covers, and any relying party
that accepts the composite COSE algorithms `-54 / -55 / -56` can use it
directly. Chrome asks for the PIN if one is set, then for a touch on
the boards with a presence input. If the key never appears in the browser's picker,
`chrome://device-log/?refresh=5&types=fido` shows what Chrome saw.

---

## 9. Day to day

- **Rebuild and reflash** after a code change: `./build.sh` (or
  `./build-c.sh`), BOOTSEL, `./flash.sh`. Credentials survive. (The
  USB-C token is updated only with `tools/flash-usbc.sh`, which erases
  first: [FLASHING.md](FLASHING.md#updating-the-firmware-later).)
- **Factory reset** from the host, no BOOTSEL needed: `./client.sh reset`
  (needs a touch on the boards with a presence input). Or erase the
  flash from BOOTSEL with `./wipe.sh <board>` (it names the device it
  sees and asks first) and flash again.
- **Forgot the PIN**: eight wrong guesses lock the token; the way out is
  the reset above.
- **Run the host test suites** (no board needed):
  `tools/host-tests.sh` runs every Rust and C suite; `tools/host-tests.sh rust`
  or `c` for one side. The C descriptor tests need `PICO_SDK_PATH`.
- **Other configurations**: RISC-V and mixed-ISA images
  ([RISCV.md](RISCV.md)), the single-core signer, the DFU bootloader and
  signed updates ([DFU.md](DFU.md)), secure boot ([SECUREBOOT.md](SECUREBOOT.md)),
  the TrustZone-M split ([TRUSTZONE.md](TRUSTZONE.md)). Each is built
  on top of what this page set up.

---

## 10. When something goes wrong

Symptoms, in the order people hit them.

**`picotool` says no device in BOOTSEL.** The board is not in BOOTSEL,
the cable is charge-only, or (Linux) udev is not set up. Use the full
unplug / hold BOOT / replug recipe, a known-good cable, a direct port.
`ls /Volumes/RP2350` (macOS) or `lsblk` (Linux) shows the drive when
BOOTSEL worked.

**`Incompatible picotool installation found: Requires version 2.3.0`**
(C build). picotool and pico-sdk disagree on major.minor. Upgrade
picotool or run with `PICOTOOL_FORCE_FETCH_FROM_GIT=1` (section 2.2).

**`arm-none-eabi-ld: cannot find -lc`** (C build). Your Arm compiler has
no newlib. Install the Arm GNU Toolchain (macOS: the `gcc-arm-embedded`
cask, not the `arm-none-eabi-gcc` formula; Linux: the
`libnewlib-arm-none-eabi` package) and put it first on `PATH`.

**`tusb.h: No such file or directory`** (C build, or the C host tests).
The pico-sdk's TinyUSB submodule is missing:
`git -C $PICO_SDK_PATH submodule update --init lib/tinyusb`.

**`error: ...feature 'inherent_associated_types'`** or a nightly
complaint (Rust build). You are not on the pinned toolchain. Run
`rustup show` inside the checkout; it must report `nightly-2025-06-23`.
`rustup toolchain install nightly-2025-06-23` if rustup did not fetch
it, then build again from inside the checkout.

**`could not compile getrandom for thumbv8m...`** (Rust build). A
`bouncycastle-*` dependency was added without `default-features = false`;
see [BUILD.md](BUILD.md#common-build-problems).

**`compile_error!: Bruce: pick exactly ONE of...`** You asked for two
ML-DSA levels or two boards, or none (`--no-default-features` without
replacements). One of each.

**The board flashed but is dark and gone from USB.** The intermittent
post-flash failure (section 7): BOOTSEL, erase, flash again. If it is
the *same* image failing twice in a row, then look at the build.

**`probe` finds no device** but the LED blinks. Give it two seconds
after the reboot. On Linux, udev (section 2.3). On Windows, an
elevated prompt. If the board is a Waveshare or Spotpear, a
`board_tiny2350` image flashed by mistake still enumerates but drives
no LCD, so check the USB product string.

**The browser never shows the key.** Chrome logs at
`chrome://device-log/?refresh=5&types=fido`; open it before the
WebAuthn attempt and watch it fill. A key with a PIN set refuses
registration without the PIN, which browsers handle in their own
dialogs but the raw examples need in `BRUCE_PIN`.

**An Arm image after a mixed-ISA one hangs before USB.** A `core1_riscv`
/ `PQF_CORE1_RISCV` image leaves core 1's ARCHSEL bit set and nothing
clears it, not even an erase. Run `picotool reboot -a -c arm` once
before loading an Arm image. See [RISCV.md](RISCV.md).

**`picotool erase -a` says it cannot determine the flash size.** The
board's flash-size OTP row is unprogrammed (USB-A samples) or the
part is 16 MiB (Waveshare). Use the ranged erase from section 7.

**The board is the Feitian RP2350 USB-C token.** Nothing in this section
applies; [its section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token)
does.

---

## 11. Where to go next

- [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token) -- the Feitian RP2350 USB-C token:
  the only procedure for flashing it, and why no other flashing
  recipe -- in this guide or elsewhere in FLASHING.md -- may be used on it.
- [BUILD.md](BUILD.md) -- the build reference: every feature and CMake
  option of both ports, side by side; the toolchain pin; the vendored
  crates; the AAGUID override; the release profile.
- [FLASHING.md](FLASHING.md) -- per-board detail: buttons, connectors,
  what each board shows after a flash, wipe recipes, the dark-device
  note in full.
- [USAGE.md](USAGE.md) -- the user's view: every LED state, every
  `getInfo` field, PIN rules, browser flows.
- [HARDWARE.md](HARDWARE.md) -- pinouts, the presence buttons, the USB
  descriptor, memory map, adding a board.
- [TESTING.md](TESTING.md) -- what has been verified on silicon and how
  to repeat it.
- [ARCHITECTURE.md](ARCHITECTURE.md) and [PROTOCOL.md](PROTOCOL.md) --
  how it works inside and what it speaks on the wire.
- [c/firmware/README.md](../c/firmware/README.md) -- the C port's own
  map.

---

## Tested with

This page was run through, in order, on 2026-09-22:

| | |
| --- | --- |
| Host | macOS 26.5 on Apple silicon |
| Rust | `nightly-2025-06-23` (rustc 1.89.0-nightly), installed by rustup from `rust-toolchain.toml` |
| CMake | 4.3.2 |
| Arm GNU Toolchain | 14.2.Rel1 (`arm-none-eabi-gcc` 14.2.1 with newlib) |
| pico-sdk | 2.3.1 with `lib/tinyusb` |
| picotool | 2.3.1 (the SDK-built copy; the Homebrew 2.2.0 on the same machine was refused, as described) |
| Python | 3.14 (only for the signing tool) |

The Linux and Windows commands are the standard ones from Raspberry
Pi's own getting-started material and the tools' project pages; they
were not exercised in this pass. If one of them is wrong for your
distribution, the tool's project page is the authority.
