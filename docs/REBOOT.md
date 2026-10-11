# Rebooting the token from the host (`CTAPHID_CMD_REBOOT`)

`bruce` can reboot a running token **from the host, over USB** -- either
into the RP2350 USB bootloader (BOOTSEL / mass-storage, for reflashing)
or warm back into the firmware -- without touching a physical BOOTSEL
button on the board. This is the vendor command `CTAPHID_CMD_REBOOT` and
the two host CLIs that drive it.

It exists because one of the boards this firmware targets has **no
usable power-on BOOTSEL path**: the sealed Feitian RP2350 USB-C token
has no button, and the bootrom's power-on BOOTSEL sensing does not
react to its capacitive touch pad (on the one sample seen, only
*runtime* touch worked). For that token a host-issued reboot is the
only way back into the bootloader; on every other board it saves a
button dance.

This page is the reference for that command: its wire shape, the
per-board policy that decides whether it waits for a touch, the build
option that removes the touch on the two button boards, the image
markers that say which policy an image carries, the two host CLIs, and
the unattended reflash loop. It is for anyone reflashing tokens, and
assumes a token running either firmware and the in-tree client tools
built ([GETTING-STARTED.md](GETTING-STARTED.md)). The build options are
in [BUILD.md](BUILD.md), the physical BOOTSEL recipes in
[FLASHING.md](FLASHING.md), day-to-day use in [USAGE.md](USAGE.md), and
the only procedure for flashing a USB-C token in
[the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token).

## Warning: buttonless tokens can be locked out of BOOTSEL

> WARNING: **To put a board into BOOTSEL you need one of:**
>
> 1. a **physical BOOTSEL button** you can hold at power-on (the Tiny
>    2350, the XIAO, the Waveshare, the Spotpear and the Feitian RP2350
>    USB-A all have one), **or**
> 2. firmware that implements **`CTAPHID_CMD_REBOOT`** *and* whose
>    reboot you can satisfy -- a press you can give, or a reboot that
>    needs none.
>
> The **Feitian RP2350 USB-C token has only the second.** A USB-C token
> running firmware **without `CMD_REBOOT`**, firmware **built for
> another board** (whose reboot waits for a press the pad may never
> deliver), or firmware that **hangs before USB** has **no way back into
> BOOTSEL**. It keeps whatever firmware is on it and **cannot be
> reflashed** (short of opening the case and reaching the SWD pads, if
> they are reachable at all).
>
> The board profile takes care of the reboot: an image built for
> `feitian_rp2350_usbc` never gates `CMD_REBOOT` on a touch, and needs
> no build option for that (see [User presence](#user-presence) below).
> What the profile cannot take care of is which image goes on the
> token. **Flash a USB-C token only with `tools/flash-usbc.sh`**, which
> refuses any UF2 not marked `pqf-board=feitian_rp2350_usbc` and
> `pqf-reboot=no-touch`, erases first, and proves the way back after
> every flash; and rehearse the exact UF2 on a USB-A board first. The
> whole procedure is [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token); when in doubt,
> do the development on a board with a real BOOTSEL button.

---

## The command

`CTAPHID_CMD_REBOOT`, command number `0x51` (`0xD1` on the wire with the
init bit) -- inside the `0x40..0x7F` vendor range CTAP reserves. Both the
Rust and C firmware ports implement it, wire-compatible. Full wire spec:
[`docs/PROTOCOL.md`](PROTOCOL.md#vendor-reboot-command).

```
request payload:  1 byte  mode
                    0x00  warm reboot back into the firmware
                    0x01  reboot into BOOTSEL (USB mass storage / DFU)
response:         none -- the device re-enumerates away on success
                  (a declined / timed-out user-presence gate -> ERR_OTHER)
errors:           ERR_INVALID_LEN  (payload not exactly 1 byte)
                  ERR_INVALID_PAR  (mode not 0x00 / 0x01)
```

It is **fire-and-forget**: the token disappears from the bus when it
reboots, so the host sends the one-byte request and does not wait for a
reply. Confirm the result by polling for the device to re-appear -- as an
RP-series BOOTSEL device (`picotool info`) after mode `0x01`, or as the
FIDO device again after a warm reboot.

## User presence

Whether `CMD_REBOOT` waits for a touch is a **per-board policy**, the
same in both ports and for both modes (warm and BOOTSEL), fixed when the
image is built:

```
reboot needs a touch  =  HAS_USER_BUTTON && HAS_POWER_ON_BOOTSEL && !reboot_no_up && !test_no_user_button
```

Where it applies, the gate is the **same test of user presence as
`MakeCredential`** -- so a host (or malware on it) cannot knock your
authenticator offline into mass-storage mode without your physical
confirmation. That gate is only safe on a board with a second way in
should the press never register: a button you can hold at power-on. So
it applies only where the board has both a readable button
(`HAS_USER_BUTTON` / `PQF_BOARD_HAS_USER_BUTTON`) and a power-on BOOTSEL
(`HAS_POWER_ON_BOOTSEL` / `PQF_BOARD_HAS_POWER_ON_BOOTSEL`). Everywhere
else the reboot acts at once:

| Board / build | FIDO presence (register / log in) | Software BOOTSEL (`CMD_REBOOT`) |
| --- | --- | --- |
| Tiny 2350 (C or Rust) | real: the **BOOT button** (QSPI_SS); the GP0 pad too (Rust) | **press** the BOOT button within ~10 s (the GP0 pad also counts, Rust) |
| Feitian RP2350 (C or Rust) | real: the **BOOTSEL button** (QSPI_SS) | **press** the BOOTSEL button within ~10 s |
| Feitian RP2350 USB-C token (C or Rust) | real: the **touch pad** (on QSPI_SS; validated on one production token, 2026-10-02) | **no touch, by design**: the token has no power-on BOOTSEL, so its only way back into the bootloader must never depend on a gesture |
| XIAO RP2350, Waveshare LCD 1.47, Spotpear LCD 1.28 | auto-confirms (no readable button) | no touch (nothing to press) |
| Any board built `PQF_REBOOT_NO_UP` / `reboot_no_up` | unchanged | no touch |
| Any board built `PQF_TEST_NO_USER_BUTTON` / `test_no_user_button` (test only, never ship) | auto-confirms | no touch |

FIDO presence is not changed by any of this: the USB-C token still
wants a touch on its pad to register or log in. The trade on that token
is explicit -- any software on a host it is plugged into can put it into
BOOTSEL -- and it is the same trade a `reboot_no_up` flash-station build
makes on a button board.

Where the gate applies, the status LED blinks fast while it waits (up
to ~10 s) and the device ships `KEEPALIVE`-`UPNEEDED`, exactly like a
WebAuthn touch prompt. No press in time -> `ERR_OTHER`, and the token
stays running. Where it does not, the token leaves the bus at once,
with no blink.

> **Note:** both firmwares read the BOOT button on the Feitian RP2350
> and the Tiny 2350, and the touch pad on the USB-C token, through the
> same QSPI chip-select sampler. The Tiny 2350's GP0 capacitive touch
> is an additional **Rust-port** input; the C port gates on the BOOT
> button alone.

### Which policy an image carries

Every image records the outcome as picotool binary-info features, so it
can be checked **before** it is flashed. For a USB-C image:

```bash
picotool info -a bruce.uf2 | grep -o 'pqf-[a-z-]*=[a-z0-9_-]*'
# pqf-board=feitian_rp2350_usbc
# pqf-reboot=no-touch
# pqf-fido-up=touch
```

`pqf-board=` is the board profile, `pqf-reboot=` is `touch` or
`no-touch` per the table above, and `pqf-fido-up=` is `touch` or `auto`
for FIDO presence. [BUILD.md](BUILD.md#identifying-an-image-before-flashing-it)
has the full list of values. `tools/flash-usbc.sh` refuses anything but
`pqf-board=feitian_rp2350_usbc` with `pqf-reboot=no-touch`, and
`./flash.sh` refuses, on a board that carries a USB-C image, any
image not marked `pqf-reboot=no-touch` (a `touch` image, or one with
no or an unknown reboot marker), because such an image must never go
onto a USB-C token; and it refuses a blank board, which could be a
blank USB-C token, until `--board` says which board it is.

## Build option: skip the press on the button boards

For a **flash station** -- reflashing many Tiny 2350 or Feitian RP2350
boards unattended -- the press per reboot is friction. The
`PQF_REBOOT_NO_UP` (C) / `reboot_no_up` (Rust) build option removes the
user-presence gate **for `CMD_REBOOT` alone**. It is only meaningful on
those two button boards: every other board, the USB-C token included,
never asks for a touch, so there it changes nothing (the image's
`pqf-reboot` marker reads `no-touch` either way):

```bash
# C firmware (CMake)
cmake -S c/firmware -B <build-dir> -DPQF_BOARD=feitian_rp2350 -DPQF_REBOOT_NO_UP=ON
cmake --build <build-dir> -j

# Rust firmware
cargo build --release -p bruce --no-default-features --features mldsa65,board_tiny2350,reboot_no_up
REBOOT_NO_UP=1 ./build.sh tiny2350          # ...or via the wrapper
```

This is **not** the same as `PQF_TEST_NO_USER_BUTTON` (a never-ship,
blanket "auto-confirm all user presence" test gate). `reboot_no_up`
leaves FIDO user presence for `MakeCredential` / `GetAssertion` **fully
enforced** -- the token stays a real authenticator; it only trusts a host
that can already talk to it to reboot it. Nor is it what makes a sealed
token reflashable: the board profile does that by itself, and what a
USB-C token needs is an image built for `feitian_rp2350_usbc`, flashed
with `tools/flash-usbc.sh` (see the warning above).

See [`docs/BUILD.md`](BUILD.md) for where this sits in the feature
matrix.

## Host CLIs

Two interchangeable clients ship in-tree -- same behaviour, same
device-matching, pick whichever toolchain you have:

**C** ([`c/hid/reboot.c`](../c/hid/reboot.c), built on `libpqhid`):

```bash
make -C c/hid reboot
c/hid/reboot --list          # list the attached Bruce tokens; sends nothing
c/hid/reboot                 # BOOTSEL (default), the only token attached
c/hid/reboot bootsel
c/hid/reboot warm
c/hid/reboot bootsel Bruce # pick by product substring when several attached
```

`--list` (or `-l`; C CLI only) prints one `found: <product> (vid=... pid=...)
path=...` line per Bruce token and exits 0, or prints `no Bruce
token found` and exits 1. It never opens a device, so it is the safe
way to see what is attached -- and, from the product string, which
board's Rust image a token runs -- before sending anything.
`tools/flash-usbc.sh` uses it before and after every reboot it asks
for.

**Rust** ([`crates/ctaphid-client/examples/reboot.rs`](../crates/ctaphid-client/examples/reboot.rs),
built on `pqf-ctaphid`):

```bash
cargo run -p pqf-ctaphid --example reboot \
    --target "$(rustc -vV | awk '/host/{print $2}')" -- bootsel Bruce
```

Both select the token by FIDO product id `0xF1D0` plus manufacturer
`bruce` (or the placeholder vendor id `0xcafe` both ports use), so
one binary drives both ports. With more than one Bruce
token attached they **refuse to act unless you pass a product-substring**
(`bruce` for the C port, `Tiny` for the Rust tiny, `USB-C` for the
Rust USB-C token), so a flash station never reboots the wrong device.

Underlying API, if you're scripting instead of shelling out:
`pqhid_reboot(dev, mode)` in [`c/hid/pqhid.h`](../c/hid/pqhid.h), and
`hid::Device::reboot(RebootMode)` in
[`crates/ctaphid-client`](../crates/ctaphid-client/src/hid/mod.rs).

## Unattended reflash workflow

On a token whose image does not gate the reboot (`pqf-reboot=no-touch`:
a buttonless board, or a `reboot_no_up` build of a button board), the
whole reflash loop is software -- no button, no replug:

```bash
c/hid/reboot bootsel Bruce          # -> BOOTSEL, no touch
until picotool info -a 2>/dev/null | grep -qi 'boot type:.*bootsel'; do sleep 0.5; done
picotool load -v bruce.uf2          # flash the new image
picotool reboot                        # back into the firmware
until cargo run -q -p pqf-ctaphid --example probe \
        --target "$(rustc -vV | awk '/host/{print $2}')" 2>/dev/null \
      | grep -qi Bruce; do sleep 0.5; done
```

On a `pqf-reboot=touch` image (the default on the Tiny 2350 and the
Feitian RP2350), insert the gesture: after `c/hid/reboot bootsel` you
have ~10 s to press the button / tap the pad before it times out.

**Not on a USB-C token.** The loop above neither checks the image nor
erases first. On the Feitian RP2350 USB-C token use
`tools/flash-usbc.sh <file.uf2>`: the same loop, plus the refusal of
any UF2 not built for that token, an erase of the first 2 MiB before
`picotool load -v` (the
[intermittent dark device](FLASHING.md#intermittent-dark-device-after-flashing-erase-first)
would cost a token that cannot be recovered), and a final reboot into
BOOTSEL and back with no touch that proves the way back, ending in
`PASS` or `FAIL` ([FLASHING.md, step 3: flash the token](FLASHING.md#step-3-flash-the-token)).

> **Tip:** the USB serial randomises on every boot (a macOS HID-cache
> workaround -- see [`docs/HARDWARE.md`](HARDWARE.md)), so the
> `/dev/...usbmodem...` path changes each cycle. Don't hard-code it; let the
> CLI find the token by manufacturer / product id as above.

## See also

- [the USB-C token section of `docs/FLASHING.md`](FLASHING.md#the-feitian-usb-c-token) -- flashing the RP2350
  USB-C token, whose only way into BOOTSEL is this command
- [`docs/PROTOCOL.md`](PROTOCOL.md#vendor-reboot-command) -- the wire spec
- [`docs/FLASHING.md`](FLASHING.md) -- per-board BOOTSEL recipes + the
  physical fallback
- [`docs/BUILD.md`](BUILD.md#axis-5-optional-the-reboot-touch-policy-and-reboot_no_up)
  -- the reboot touch policy and the `reboot_no_up` build option in context
- [`docs/USAGE.md`](USAGE.md) -- day-to-day host commands
