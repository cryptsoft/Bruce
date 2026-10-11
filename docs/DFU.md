# DFU firmware update

Field-updatable firmware over standard **USB DFU 1.1**: the on-flash
DFU bootloader (`c/bootloader/`), the signed image format it verifies,
how to build, sign and provision, how RISC-V apps are launched through
it, and what has been validated on silicon. It is for someone deploying
or updating tokens without the BOOTSEL button, and assumes a working
build from [GETTING-STARTED.md](GETTING-STARTED.md) and
[BUILD.md](BUILD.md). The layer underneath -- the ROM verifying the
bootloader -- is [SECUREBOOT.md](SECUREBOOT.md); the boot-ROM analysis
behind the RISC-V launch path is
[RISCV-DFU-BOOTROM-ANALYSIS.md](RISCV-DFU-BOOTROM-ANALYSIS.md); plain
BOOTSEL flashing is [FLASHING.md](FLASHING.md).

Contents:

- [Components](#components)
- [Flash map](#flash-map-2-mib-defined-in-ccommonpqf_imageh)
- [Signed image format](#signed-image-format)
- [Building it all](#building-it-all)
- [First-time provisioning](#first-time-provisioning-factory--dev-bench)
- [What `dfu-util -D` actually does](#what-dfu-util--d-actually-does)
- [The Rust port](#the-rust-port)
- [Anti-rollback](#anti-rollback)
- [How this composes with secure boot](#how-this-composes-with-secure-boot-otp)
- [RISC-V apps over DFU: the block-loop annex](#risc-v-apps-over-dfu-the-block-loop-annex)
- [Silicon status](#silicon-status)
- [Limitations](#limitations)

A token running the DFU-enabled firmware is updated with stock
[`dfu-util`](https://dfu-util.sourceforge.net/) -- no BOOTSEL button
dance, no picotool, no custom flasher:

```bash
$ dfu-util -D bruce_c.dfu
```

That one command detaches the running token into the on-flash DFU
bootloader, streams the image, verifies its **ECDSA-P256 signature**,
installs it, and reboots into the new firmware. A bad or unsigned
image is rejected (`status(7) = errVERIFY`, non-zero exit) and the
old firmware keeps running. Credentials, PIN, and config survive
updates -- the persisted sectors are outside both firmware slots.

This is the update path for production tokens: once the OTP fuses are
blown per [SECUREBOOT.md](SECUREBOOT.md) (secure boot on, bootrom
BOOTSEL disabled), the stock UF2-drag-and-drop path is gone and this
bootloader is the only way firmware gets onto the device.

> WARNING: **Not for the Feitian RP2350 USB-C token.** That token has no
> power-on BOOTSEL to recover with, and neither the DFU bootloader nor
> its app-slot images have been run on it. It is flashed only with
> `tools/flash-usbc.sh`, and bootloader, DFU and OTP work are on the
> list of things that must never be done to it
> ([FLASHING.md, the rules for the USB-C token](FLASHING.md#the-rules)).

---

## Components

| Piece | Where | What it does |
|---|---|---|
| DFU bootloader | `c/bootloader/` -> `pqf_bootloader.uf2` | Owns flash `0x000000..0x020000`. Verifies + boots the app; exposes the DFU-mode USB device. |
| DFU-enabled app | `c/firmware/` with `-DPQF_BOOTLOADER=ON`, or `crates/firmware` with `PQF_APP_OFFSET=1` + `-F dfu_runtime` | Linked at `0x10021000`; adds a DFU *runtime* interface (detach-only) to the composite USB device. |
| Signing tool | `tools/pqf_sign.py` | Wraps an app `.bin` in the signed image header -> `.dfu` file. |
| Dev signing key | `keys/pqf-dev-fw.pem` | **Development only** -- checked in so dev builds are reproducible, which means its private half is public and a bootloader carrying it installs anyone's firmware. `sign --production` refuses it and the bootloader will not build with `-DPQF_PRODUCTION=1` against it. See *Production key ceremony* in [SECUREBOOT.md](SECUREBOOT.md). |
| Verifier tests | `c/bootloader/test/` | Host-side unit + python<->C interop tests of the exact verify TU the bootloader links. |

## Flash map (2 MiB, defined in `c/common/pqf_image.h`)

```
0x000000  128 KiB   pqf_bootloader        (what the bootrom boots)
0x020000    4 KiB   app slot: signed-image header
0x021000  944 KiB   app slot: application image  (XIP at 0x10021000)
0x10D000    4 KiB   staging slot: header          (DFU downloads land here)
0x10E000  944 KiB   staging slot: image
0x1FA000    4 KiB   boot-state sector (install journal)
0x1FB000    4 KiB   spare
0x1FC000   16 KiB   persisted sectors (keys/blobs/resident/store) -- unchanged
```

> **The die is 2 MiB, not 4.** This map used to be laid out for 4 MiB
> because the board header declares `PICO_FLASH_SIZE_BYTES = 4 MiB`.
> The part fitted to the Feitian RP2350 is 2 MiB, and addresses past
> the end **do not fault -- they alias**. Staging at `0x200000` was
> therefore `0x000000`, so the first sector of every download erased
> the bootloader's own vector table underneath itself; the transfer
> died at block 0 with the token unable to answer EP0, and no watchdog
> could help because the code doing the recovering was the code being
> erased.
>
> It survived several rounds of debugging because a wrap is
> self-consistent. The firmware's credential store at `0x3FC000` wraps
> to `0x1FC000` and reads wrap with it, so credentials persist and read
> back correctly while living 2 MiB from where the constants say they
> are. That apparent success was repeatedly taken as proof the die was
> 4 MiB. Settle this class of question by measurement, not inference --
> write a pattern high and read it back low:
>
> ```bash
> picotool load -o 0x10200000 pattern.bin -t bin && picotool save -r 0x10000000 0x10001000 low.bin -t bin
> ```
>
> The map is now computed from `PQF_FLASH_SIZE` and a `_Static_assert`
> rejects any layout that runs past the device.

A DFU download streams into **staging**, never over the live app.
Only after the full image verifies (SHA-256 of the image pinned in
the header; ECDSA-P256 over the header) does the bootloader copy
staging -> app slot, journalling the install in the boot-state sector
so a power cut mid-copy is redone on the next boot.

## Signed image format

`tools/pqf_sign.py sign` prepends one 4 KiB header sector to the app
`.bin` (layout in `c/common/pqf_image.h`): magic `PQFW`, image
length, monotonic `fw_version`, `board_id`, `alg_mask`, SHA-256 of
the image, and a DER ECDSA-P256 signature over the header's first 64
bytes. `alg_mask` + `header_version` leave room to add a post-quantum
signature section later without breaking fielded verifiers.

The bootloader enforces the signature **both** at DFU install time
(reporting `errVERIFY`/`errTARGET`/`errFILE` to dfu-util) and at
every boot -- an app slot that doesn't verify drops the token into
DFU mode instead of running it.

## Building it all

```bash
export PICO_SDK_PATH=/path/to/pico-sdk

# 1. Bootloader (per board):
cmake -S c/bootloader -B c/bootloader/build -DPQF_BOARD=feitian_rp2350
cmake --build c/bootloader/build -j
# -> c/bootloader/build/pqf_bootloader.uf2

# 2. App, DFU layout:
cmake -S c/firmware -B c/firmware/build-dfu \
      -DPQF_BOARD=feitian_rp2350 -DPQF_BOOTLOADER=ON
cmake --build c/firmware/build-dfu -j

# 3. Sign:
python3 tools/pqf_sign.py sign --key keys/pqf-dev-fw.pem \
    --in c/firmware/build-dfu/bruce_c.bin \
    --out bruce_c.dfu --fw-version 1 --board feitian_rp2350
```

`--board` pins the image to one board profile (the bootloader knows
its own `board_id` and refuses foreign images with `errTARGET`);
`--board any` builds a wildcard image.

## First-time provisioning (factory / dev bench)

Once per device, via the classic BOOTSEL path:

```bash
# BOOTSEL-mode device attached:
picotool load c/bootloader/build/pqf_bootloader.uf2
picotool load -t bin bruce_c.dfu -o 0x10020000   # header+app into the app slot
picotool reboot
```

After that the token never needs BOOTSEL again:

```bash
dfu-util -l            # shows the runtime interface on the running token
dfu-util -D bruce_c.dfu
```

## What `dfu-util -D` actually does

1. Finds the running token's DFU **runtime** interface (composite
   device, itf 3) and sends `DFU_DETACH`.
2. The firmware ACKs, writes a magic into watchdog scratch 2/3, and
   watchdog-reboots. The bootloader sees the magic and enumerates as
   the DFU-mode device (same VID:PID `cafe:f1d0`, product string
   "Bruce DFU bootloader").
3. dfu-util re-scans, downloads in 4 KiB blocks (= one flash sector
   per block, streamed into staging), then sends the zero-length
   manifest.
4. The bootloader verifies staging (format -> board -> SHA-256 ->
   ECDSA). On success: journal, copy into the app slot (read-back
   verified), clear journal, report OK -- dfu-util prints `Done!` --
   and self-reboot into the new firmware ~1.5 s later.
   On failure: DFU error status, staging discarded, old app
   untouched and still bootable.

Other ways into DFU mode:
- **Bad/missing app**: the bootloader falls into DFU mode whenever
  the app slot fails verification, so a botched update is always
  recoverable over USB.
- **BOOTSEL button held at power-on** -- relevant once the BOOTSEL
  fuses disable the bootrom's own BOOTSEL handling
  ([SECUREBOOT.md](SECUREBOOT.md#the-bootsel-fuses-and-the-trap-in-testing-them));
  until then the bootrom grabs the button first.
- Leaving DFU mode without updating: `dfu-util -e` (detach) or
  power-cycle -- the bootloader reboots into the app.

Notes:
- dfu-util prints a harmless `File has no DFU suffix` warning on raw
  files; silence it with `dfu-suffix -v cafe -p f1d0 -a <file>` if
  it bothers you.
- macOS: `brew install dfu-util`; no drivers needed. If the
  re-scan after detach misses the re-enumeration, add `-E 10`.

## The Rust port

Both halves exist as of 2026-09-01, but they are separate switches:

```bash
PQF_APP_OFFSET=1 cargo build --release -p bruce \
    --target thumbv8m.main-none-eabihf --no-default-features \
    --features mldsa65,board_tiny2350,dfu_runtime
```

`PQF_APP_OFFSET=1` (an env var read by `build.rs`, not a cargo feature)
relocates the image into the app slot; `-F dfu_runtime` adds the DFU
runtime interface. Either alone is legal and neither is much use without
the other -- a relocated image with no runtime interface boots under the
bootloader but cannot be detached, and a runtime interface on an image
linked at `0x10000000` is an interface on something the bootloader will
never launch.

Two differences from the C port, neither a defect:

- **The interface number is not 3.** `usb-device` allocates sequentially,
  so the class lands on interface 1, or 3 with `gdb_stub`. The C port
  pins it to 3 and 5. Nothing should depend on the number; `dfu-util`
  finds the interface by class.
- **The VID:PID is `cafe:f1d0`**, the same as the C port and the
  bootloader, so a `dfu-util -d` filter or a `dfu-suffix` stamped for it
  matches either port's image. (Until the public release the Rust port
  carried a different vendor id, which is what the older records below
  show.)

Validated on silicon under the sealed anti-rollback bootloader: linked at
`0x10021000`, installed over DFU, enumerated as
`Found Runtime: [1209:f1d0] ... intf=1 name="Bruce DFU runtime"` (the
Rust port's vendor id at the time; it is `cafe` now), then
detached itself and installed the next image through the interface it had
just gained. The conformance suite (an external CTAP 2.1 conformance
suite, not part of this repository) run for `-52` afterwards: 77 passed,
0 failed.

## Anti-rollback

The header carries a monotonic `fw_version`. By default the
bootloader does **not** reject downgrades -- in production BOOTSEL is
gone (the fuses in [SECUREBOOT.md](SECUREBOOT.md)) and DFU is the
only path, so rollback blocking would also block intentional
downgrades. Build the bootloader with
`-DPQF_BOOT_ANTI_ROLLBACK=ON` to refuse images with a lower
`fw_version` than the installed app (`errFILE`).

## How this composes with secure boot (OTP)

> Provisioning is written up separately in
> [SECUREBOOT.md](SECUREBOOT.md), with a staged script
> (`tools/secureboot-provision.sh`). Read its ordering section before
> blowing anything: DFU survives the BOOTSEL fuses only *while the
> bootloader boots*, and secure boot is exactly what can stop it
> booting -- so secure boot must be proven working first, while BOOTSEL
> is still there to recover with.

The RP2350's own secure boot (OTP `CRIT1.SECURE_BOOT_ENABLE`) is a
separate, complementary layer -- the bootrom verifies **secp256k1**
signatures on picobin `IMAGE_DEF`s against key fingerprints in OTP:

- The bootrom verifies the **bootloader** image at every boot.
- **The bootloader does NOT launch the app via `rom_chain_image()`, so
  the bootrom does NOT verify the app.** This bullet used to claim the
  opposite; it was wrong, and it was claiming a security property that
  is not in effect. Arm apps are started by an in-place vector-table
  jump and RISC-V apps by the annex + `rom_reboot(NORMAL | TO_RISCV)`;
  neither goes through `chain_image`. Under secure boot the chain of
  trust is therefore: the ROM verifies the **bootloader** against OTP,
  and the bootloader ECDSA-P256-verifies the **app** against
  `pqf_boot_pubkey.h`. That chain is unbroken -- the key lives in an
  image the ROM has already authenticated -- but the app's root of trust
  is that embedded key, not an OTP fingerprint.
- What a working `rom_chain_image()` would add is an OTP-anchored root
  key for the app and ROM-enforced rollback. That is hardening, not a
  precondition for secure boot, and it is currently blocked (see
  [TESTING.md](TESTING.md) and
  [RISCV-DFU-BOOTROM-ANALYSIS.md](RISCV-DFU-BOOTROM-ANALYSIS.md)). Note
  also that since secure boot disables the
  RISC-V cores, the RISC-V launch path and secure boot can never be
  active on the same token.
- The signing flow per image under secure boot, then: `picotool seal
  --sign` (secp256k1, OTP chain) **then** `tools/pqf_sign.py sign`
  (P-256, DFU envelope).
- OTP flags to blow alongside secure boot:
  `BOOT_FLAGS0.DISABLE_BOOTSEL_USB_MSD_IFC`,
  `DISABLE_BOOTSEL_USB_PICOBOOT_IFC` (and `DISABLE_BOOTSEL_UART_BOOT`)
  -- after which this bootloader's DFU is the only update path.
- WARNING: **Secure boot permanently disables the RISC-V cores** (OTP
  `CRIT1` bit doc). Secured production tokens are Arm-only: the
  RISC-V and mixed-ISA builds remain dev-bench configurations.
- Hardening follow-ups for secure boot: package the bootloader as an
  SRAM-resident signed image (kills the flash-swap TOCTOU per RP2350
  datasheet sec. 5.10.2), embed a partition table so BOOTSEL (if left
  enabled) can't scribble over the persisted sectors, and consider
  OTP-page-locking the boot keys.

## RISC-V apps over DFU: the block-loop annex

Implemented **and silicon-validated** 2026-08-21 on the Feitian RP2350.
A RISC-V C-port app installed over DFU launches through the annex,
enumerates as a FIDO HID device, and completes a full hybrid
ML-DSA-65-ES256 register + sign over the wire; the launch survived
five consecutive reboots and the Arm-app-then-RISC-V-app upgrade
transition with no dark fallback. (One earlier attempt the same day
went dark once and did not recur -- consistent with the known
intermittent dark-after-flash, not the annex path.)

Arm apps launch as before (in-place jump). A RISC-V app is launched
*by the ROM*: at boot, after ECDSA verification, the bootloader copies the
app's picobin IMAGE_DEF block into the **annex** -- the bootloader's
last flash sector (`PQF_ANNEX_OFF`, 0x1F000), which `pqf_annex.ld`
stitches into the slot-0 block loop -- and issues
`rom_reboot(NORMAL | TO_RISCV)`. The RISC-V-side boot scan then finds
a right-CPU IMAGE_DEF in slot 0 and launches the app identity-mapped
at its linked 0x10021000 (`entry` comes from the block; roll is 0, so
no ATRANS and the absolute credential-store reads stay valid). Why
every ROM-mediated alternative fails is derived in
[RISCV-DFU-BOOTROM-ANALYSIS.md](RISCV-DFU-BOOTROM-ANALYSIS.md).

Failure containment: a bad/stale annex makes the RISC-V scan fall
back to the Arm bootloader and the ROM auto-switches straight back;
the bounce sentinel (watchdog scratch 7, cleared by the firmware's
check-in) turns that into DFU mode instead of a reboot loop. The
annex re-syncs on every boot, so reflashing the bootloader (which
resets the annex to its IGNORED placeholder) self-heals in one extra
bounce. DFU re-entry from a running RISC-V app rides
`rom_reboot(NORMAL | TO_ARM)` with the DFU magic as the ROM's own
p0/p1 (they land in watchdog scratch 2/3 -- writing scratch by hand
does not survive `rom_reboot()`).

Validate any bootloader+app pair before flashing:

```bash
tools/annex_check.py --bootloader build-bl/pqf_bootloader.bin \
    --app build-fw/bruce_c.bin
```

It replays the ROM's block scan and CPU-preference selection for both
architectures (mirroring `pico-bootrom-rp2350`), including the annex
rewrite. `picotool info -a -t bin` on its `--compose` output
cross-checks with an independent parser.

Residual exposures, deliberate:

- An app that verifies, launches and crashes **before check-in**
  needs the button -- `rom_reboot()` owns the watchdog, so the launch
  guard cannot cover an arch-switch launch.
- Installing an **Arm app via picotool directly into the app slot**
  (bypassing DFU) while the token last ran RISC-V leaves a stale
  RISC-V annex pointing into Arm bytes; the next boot executes them
  as Hazard3 code and goes dark. DFU installs are immune (they enter
  through the Arm bootloader, which re-syncs the annex), as are
  whole-image and bootloader reflashes (they reset the annex).
  Recovery: BOOTSEL, flash the matching ISA.

## Silicon status

**Working end to end.** Validated 2026-09-01 on a Pimoroni Tiny 2350
(chipid `0x764d62245aa0b134`, 4 MiB die) with the C port at ML-DSA-65.

> The section that used to sit here was headed "DOES NOT WORK on
> FLASH_DEVINFO-unprogrammed boards" and it is disproven: the board
> above has entirely blank OTP -- `FLASH_DEVINFO` reads `0x000000` --
> and every DFU operation below succeeded on it. The real fault was
> never `FLASH_DEVINFO`; it was the 2 MiB die addressed as 4 MiB,
> written up at the top of this file, and the flash map has been laid
> out for 2 MiB since.
>
> **That old section also recommended irreversibly programming
> `FLASH_DEVINFO` to declare 4 MiB.** Do not do that. It contradicts
> this document's own measurement, and burning a false size into a
> one-way fuse recreates the exact aliasing that caused the original
> bug -- permanently. If you ever do want to program it, measure the
> die first (write a pattern high, read it back low) and encode the
> measured value: `CS0_SIZE = 0xA` is 4 MiB, `0x9` is 2 MiB.
>
> For the record, the bootrom's default when
> `BOOT_FLAGS0.FLASH_DEVINFO_ENABLE` is unset is `CS0_SIZE = 12`,
> i.e. **16 MiB** -- not the 2 MiB `picotool` assumes when it cannot
> size a chip. Two different defaults, and neither is the die.

| exercised | result |
|---|---|
| Provision bootloader + signed app over BOOTSEL | works |
| DFU runtime interface present on the running app (`intf=3`) | works |
| `dfu-util -D` update, verified by reading the slot header back | installs |
| Anti-rollback (`-DPQF_BOOT_ANTI_ROLLBACK=ON`), downgrade | refused |
| App signed with the wrong P-256 key | refused |
| App pinned to another board | refused |
| Corrupt image (byte flipped in the body, signature untouched) | refused |
| Recovery from `dfuERROR` by pushing a valid higher version | works |
| Recovery from `dfuERROR` by `dfu-util -e` | works |
| conformance suite, `-52`, on the DFU-installed app | 76 passed, 0 failed |

After all five refusal scenarios the app slot was unchanged --
`fw_version 5`, original sha -- so a rejected update never touches the
running image.

### Rejection statuses, and what each one means

The bootloader distinguishes its failure modes, which makes a failed
update diagnosable instead of a shrug:

| `dfu-util` reports | DFU status | cause |
|---|---|---|
| *File is not targeted for use by this device* | `errTARGET` (1) | image signed for another board (`--board`) |
| *File is for this device but fails some vendor-specific test* | `errFILE` (2) | `fw_version` lower than installed, anti-rollback build |
| *Programmed memory failed verification* | `errVERIFY` (7) | bad signature, wrong signing key, or corrupt image |

Note the download itself always completes -- the staging write succeeds
and the refusal happens at **manifest** time. "Download done." is not
success; read the state that follows it.

### A refusal leaves the token in DFU mode

After any of the three refusals the bootloader stays in DFU mode rather
than launching the app, so the token stops being a FIDO device. That is
fail-closed and correct, but worth knowing before it looks like a
brick. **`dfu-util -e` brings it straight back** -- no power cycle, no
BOOTSEL, no valid image required. Pushing a good image works too.

### Power loss mid-update, and why it did not need a cable pull

The install journal exists so that losing power during the staging->app
copy cannot leave a half-written application. It went untested for a
while because the obvious experiment -- pull USB during the manifest --
needs a hand on the board and a window measured in milliseconds.

It does not need that. What a power loss actually *produces* is a state
in flash: a staged image plus a pending journal at
`PQF_BOOT_STATE_OFF`. The interesting code is what the **next boot**
does with it, and that state can be written directly over BOOTSEL. The
replay path then runs for real; only the interruption is synthesised.
`tools/dfu-powerloss-test.sh` does this, four cases, 2026-09-01:

| case | expected | result |
|---|---|---|
| corrupt journal (bad check word) | no install | installed nothing |
| valid journal + good staging | **replay installs** | C image -> Rust image (`cafe:f1d0` -> `1209:f1d0`, the Rust vendor id at the time), slot at fw_version 9 |
| valid journal + corrupt staging | refuse | refused, app untouched |
| journal and staging disagree on `total_len` | refuse | refused |

The journal was cleared in every case that reached it -- including the
refusals, which matters: a journal left pending after a refusal would
retry a known-bad staging on every boot forever.

The three refusals are the valuable half. The last is the state a power
loss *between* the staging write and the journal write really leaves,
and the corrupt-staging case is the one that would install a broken
application if the bootloader trusted its own journal instead of
re-verifying the slot. It re-verifies
(`recover_pending_install`, `c/bootloader/src/main.c:414`).

```bash
tools/dfu-powerloss-test.sh <good.dfu> <other.dfu>
```

Both signed for the board; `other` should differ visibly from what is
installed -- the C and Rust ports share a VID:PID but not a product
string (`Bruce (C port)` against `<board> PQC`), which turns "did it
install?" into a one-line check.

### Still not exercised

- **RISC-V apps over DFU on this board.** Covered elsewhere at all
  levels; not re-run here, and no longer possible on the secure-booted
  Tiny 2350 whose RISC-V cores are fused off.

## Limitations

- **~944 KiB maximum app image** (`PQF_IMAGE_MAX_LEN`). The map is
  hardcoded to 2 MiB (`PQF_FLASH_SIZE`, overridable), split as 128 KiB
  bootloader + two 948 KiB A/B slots + journal + 16 KiB persisted
  sectors. On a 4 MiB die the top half simply goes unused. The
  ML-DSA-65 build is 206,660 bytes, about a fifth of budget.
- **DFU only ever writes the app slot, never the bootloader.** So the
  bootloader is permanent once provisioned, and recoverable only over
  BOOTSEL. The same fact is what makes a bad app harmless: verification
  fails, the bootloader stays in DFU, and you push another image.
- **The DFU-mode transport is unauthenticated**, as USB DFU always is.
  Anyone with physical access can *offer* an update; only correctly
  signed images install or boot, and the running firmware is untouched
  by a failure. There is no gesture required before accepting a
  download, so an attacker with physical access can repeatedly push
  rubbish and keep the token in DFU mode -- annoying rather than
  dangerous, and `dfu-util -e` clears it. Requiring a button press
  before a download is the obvious hardening.
- **Anti-rollback is a build-time choice** on the bootloader
  (`-DPQF_BOOT_ANTI_ROLLBACK=ON`), off by default so deliberate
  downgrades stay possible.
- **Images are board-pinned** by `pqf_sign.py --board`; `--board any`
  builds a wildcard.
- `picotool info` cannot parse the offset-linked app ELF/bin ("binary
  start" is not `0x10000000`); use `pqf_sign.py info` on signed images,
  or on a 4 KiB read of the slot header taken with `picotool save`.
