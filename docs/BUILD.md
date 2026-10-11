# Build reference

Every build option of both firmwares, side by side. This page is the
reference; the path from an empty machine to a flashed token is
[GETTING-STARTED.md](GETTING-STARTED.md), which also lists the tools
and their version rules. Flashing and per-board detail are in
[FLASHING.md](FLASHING.md).

Contents:

- [The two ports side by side](#the-two-ports-side-by-side)
- [Toolchain (pinned)](#toolchain-pinned)
- [Vendored dependencies](#vendored-dependencies)
- [Rust firmware](#rust-firmware)
- [C firmware](#c-firmware)
- [Identifying an image before flashing it](#identifying-an-image-before-flashing-it)
- [Common build problems](#common-build-problems)
- [Host test suites](#host-test-suites)
- [ASCII only](#ascii-only)

---

## The two ports side by side

Both firmwares expose the same choices; the spelling differs. The
wrappers `./build.sh` (Rust) and `./build-c.sh` (C) take the same
board names and the same environment knobs.

| Choice | Rust (`cargo` feature or env) | C (CMake option) | Wrapper knob |
| --- | --- | --- | --- |
| Board | `board_tiny2350` (default), `board_xiao_rp2350`, `board_feitian_rp2350`, `board_waveshare_rp2350_lcd_1_47`, `board_spotpear_rp2350_lcd_1_28`, `board_feitian_rp2350_usbc` | `-DPQF_BOARD=tiny2350 \| xiao_rp2350 \| feitian_rp2350 \| waveshare_rp2350_lcd_1_47 \| spotpear_rp2350_lcd_1_28 \| feitian_rp2350_usbc` (CMake default: `waveshare_rp2350_lcd_1_47`) | first argument (default `tiny2350` in both wrappers) |
| ML-DSA level | `mldsa44` / `mldsa65` (default) / `mldsa87` | `-DPQF_HYBRID_VARIANT=44 \| 65 \| 87` (default 65) | `MLDSA=44\|65\|87` |
| Ed25519 (COSE `-8`) | `ed25519` | not in the C port | `ED25519=1` (Rust) |
| Instruction set | `--target riscv32imac-unknown-none-elf` (alias `cargo build-riscv`) | `-DPQF_PLATFORM=rp2350-riscv` | `RISCV=1` (C) |
| Mixed ISA (Arm core 0 + RISC-V core 1) | `core1_riscv` | `-DPQF_CORE1_RISCV=ON` | -- |
| Single core | `single_core` | `-DPQF_SINGLE_CORE=ON` (`-DPQF_YIELD_US=` for the tick) | `SINGLE_CORE=1` |
| Discoverable-credential capacity: `N` extra flash sectors of 7 passkeys each (default 0 = 6 in Rust, 7 in C; see [Axis 7](#axis-7-optional-discoverable-credential-capacity)) | `PQF_RESIDENT_EXTRA_SECTORS=N` in the environment (0..8) | `-DPQF_RESIDENT_EXTRA_SECTORS=N` (0..8) | `RK_SECTORS=N` |
| Reboot into BOOTSEL without a touch (only changes the two button boards -- the default is a per-board policy, see [Axis 5](#axis-5-optional-the-reboot-touch-policy-and-reboot_no_up)) | `reboot_no_up` | `-DPQF_REBOOT_NO_UP=ON` | `REBOOT_NO_UP=1` |
| Auto-confirm presence (TEST ONLY, never ship; also removes the reboot touch) | `test_no_user_button` | `-DPQF_TEST_NO_USER_BUTTON=ON` | -- |
| On-token GDB stub (DEBUG ONLY, never ship) | `gdb_stub` | `-DPQF_GDB_STUB=ON` | -- |
| DFU-updatable image | `dfu_runtime` + `PQF_APP_OFFSET=1` in the environment | `-DPQF_BOOTLOADER=ON` (sets `PQF_APP_OFFSET` and `PQF_DFU_RUNTIME_IF`) | -- |
| Quantum RNG on I2C | always probed (except on the Spotpear); wiring fixed in `src/qrng.rs` | `-DPQF_QRNG=ON\|OFF` plus `PQF_QRNG_I2C/_SDA/_SCL/_PD/_BAUD` | `CMAKE_EXTRA="-D..."` (C) |
| AAGUID | `BRUCE_AAGUID=<32 hex>` in the environment | fixed in `c/firmware/src/ctap2.c` (the C port has its own) | -- |
| picotool program URL | none | `-DPQF_PROGRAM_URL=<url>` (empty = none) | -- |
| Output | `target/thumbv8m.main-none-eabihf/release/bruce` (ELF) -> `bruce.uf2` | `c/firmware/build*/bruce_c.elf` and `.uf2` -> `bruce-c.uf2` | |

Within an axis the choices are exclusive: exactly one board, exactly
one ML-DSA level. Both ports refuse anything else at compile time.

---

## Toolchain (pinned)

`rust-toolchain.toml` pins **`nightly-2025-06-23`** plus the
`thumbv8m.main-none-eabihf` and `riscv32imac-unknown-none-elf` targets
and the `rustfmt`, `clippy`, `llvm-tools` components. The first `cargo
build` after cloning auto-installs everything; nothing needs to be
installed by hand, and a hand-installed nightly is the usual cause of
`feature 'inherent_associated_types'` errors.

Why nightly? The low-memory ML-DSA crate uses two unstable language
features:

- `inherent_associated_types` -- for type-level associated constants on each ML-DSA variant
- `generic_const_exprs` -- for the size-parameterised polynomial / vector arithmetic

When either of those stabilises the pin can drop. Until then the
toolchain version is part of the supported configuration -- newer
nightlies may break the build because of unrelated `#![feature]` churn.

The C firmware needs pico-sdk **2.3.1** with its TinyUSB submodule, an
Arm GNU Toolchain **with newlib**, CMake >= 3.13 and a picotool whose
major.minor matches the SDK's. The version rules and install commands
are in [GETTING-STARTED.md](GETTING-STARTED.md#22-for-the-c-firmware-cmake-the-arm-gnu-toolchain-pico-sdk).

---

## Vendored dependencies

One clone is the whole build. Two third-party trees live in the
repository so nothing has to be cloned beside it:

- **Rust**: the ML-DSA, SHA-2, SHA-3, HMAC and HKDF primitives come
  from the Bouncy Castle Rust port (`bc-rust`, upstream at
  https://github.com/bcgit/bc-rust, MIT). The subset the firmware needs
  is vendored under [`crates/bc-rust-mini/`](../crates/bc-rust-mini/README.md)
  as a snapshot of a branch that adds `#![no_std]` support to those
  crates on top of upstream's `release/0.1.3alpha` (the patch is not
  in upstream yet; branch and commit are recorded in
  `crates/bc-rust-mini/UPSTREAM`). The four consumers --
  `crates/firmware`, `crates/signer-core`, `crates/fw-secure`,
  `crates/firmware-hosttest` -- reach it by
  `path = "../bc-rust-mini/crypto/<crate>"` with `default-features = false`.
  The directory is a nested workspace, excluded from the outer one:

  ```
  Bruce/
  |-- Cargo.toml                    <- excludes crates/bc-rust-mini (its own nested workspace)
  +-- crates/
      |-- bc-rust-mini/
      |   |-- Cargo.toml            <- nested workspace root (edition + sibling deps)
      |   |-- LICENSE.md            <- Bouncy Castle Licence (MIT text)
      |   |-- UPSTREAM              <- branch / commit / date of the snapshot
      |   +-- crypto/
      |       |-- core/  mldsa-lowmemory/  sha2/  sha3/  rng/  hmac/  hkdf/  utils/
      |       +-- hex/  core-test-framework/     <- dev-dependencies of the suites only
      +-- firmware/Cargo.toml       <- path = "../bc-rust-mini/crypto/..."
  ```

  To move to a newer bc-rust, run `tools/vendor-bc-rust.sh /path/to/bc-rust`
  and follow the checklist in the README there. Do not patch the
  vendored sources in place.

- **C**: the crypto primitives (SHA-2/3, AES, bignum, P-256, ML-DSA)
  are vendored from OpenSSL 3.5 under
  [`c/firmware/openssl-mini/`](../c/firmware/openssl-mini/README.md).

pico-sdk itself is not vendored; it is a build-time platform dependency
located through `PICO_SDK_PATH`, like any pico project.

---

## Rust firmware

### The wrapper: `build.sh`

```bash
./build.sh [board]           # tiny2350 (default) | xiao_rp2350 | feitian_rp2350 |
                             # waveshare_rp2350_lcd_1_47 | spotpear_rp2350_lcd_1_28 |
                             # feitian_rp2350_usbc (flash only per FLASHING.md, USB-C token)
MLDSA=44 ./build.sh          # or 87; default 65
ED25519=1 ./build.sh         # add EdDSA
SINGLE_CORE=1 ./build.sh     # signer on core 0, timer-driven keepalive
REBOOT_NO_UP=1 ./build.sh    # CMD_REBOOT without a touch on the button boards (flash stations)
RK_SECTORS=3 ./build.sh      # 27 discoverable credentials instead of 6 (Axis 7)
```

It runs `cargo build --release -p bruce --no-default-features
--features <mldsa>,<board>[,...]` and then `picotool uf2 convert`, and
leaves `bruce.uf2` in the repository root. Anything it does not
expose (the RISC-V target, `core1_riscv`, `dfu_runtime`, `gdb_stub`,
the AAGUID override) is a plain `cargo build` per the sections below,
followed by [UF2 conversion](#uf2-conversion).

### Axis 1: ML-DSA variant (mutually exclusive -- pick exactly one)

The default features land on **ML-DSA-65** (security level 3, COSE algorithm `-55` for the hybrid construction):

```bash
cargo build --release
```

That produces an ELF at `target/thumbv8m.main-none-eabihf/release/bruce` -- around 260-420 KB depending on which ML-DSA variant + optional features you chose.

| Feature   | NIST level | COSE alg | Signature size | Notes              |
| ---       | ---        | ---      | ---            | ---                |
| `mldsa44` | 2          | `-54`    | ~2420 B        | smallest, fastest  |
| `mldsa65` | 3          | `-55`    | ~3309 B        | **default**        |
| `mldsa87` | 5          | `-56`    | ~4627 B        | slowest, fits tightly in `maxMsgSize = 7609 B` |

The COSE alg column is the *composite* PQ/T identifier the credential is
labelled with, as requested in draft-ietf-jose-pq-composite-sigs-04 and
still provisional -- not the RFC 9964 pure ML-DSA id, and not the
`-51/-52/-53` of draft -02, which RFC 9864 has since assigned to other
algorithms. Each id is defined once per port
(`crates/signer-core/src/mldsa_alg.rs`, `c/firmware/src/hybrid.h`) -- see
[PROTOCOL.md](PROTOCOL.md#cose-algorithm-identifiers).

Build incantations:

```bash
cargo build --release --no-default-features --features mldsa44,board_tiny2350
cargo build --release                                                          # default = mldsa65,board_tiny2350
cargo build --release --no-default-features --features mldsa87,board_tiny2350
```

The three ML-DSA features are **mutually exclusive**. Building with two of them (`--features mldsa44,mldsa87`) or none (`--no-default-features` with no ML-DSA replacement) fires a `compile_error!` from `crates/firmware/src/mldsa_alg.rs`.

### Axis 2: Board (mutually exclusive -- pick exactly one)

```bash
cargo build --release                                                                  # default = board_tiny2350
cargo build --release --no-default-features --features mldsa65,board_xiao_rp2350      # XIAO RP2350 build
```

| Feature                              | Board                                | Status surface                                   | User presence                                                                                                                       |
| ---                                  | ---                                  | ---                                              | ---                                                                                                                                  |
| `board_tiny2350`                     | Pimoroni Tiny 2350 (**default**)     | RGB LED on GP18 / GP19 / GP20                    | **Real** -- BOOT button sampled via QSPI chip-select (`board/bootsel.rs`), or an external touch button/switch on GP0 with boot-time polarity auto-detect (see [docs/HARDWARE.md](HARDWARE.md#user-presence-buttons)) |
| `board_xiao_rp2350`                  | Seeed Studio XIAO RP2350             | Single dual-colour LED on GP25                   | Auto-confirm. GP23 driven LOW (disables NeoPixel 5V; required for stable USB enumeration -- see [docs/HARDWARE.md](HARDWARE.md#the-gp23-quirk)) |
| `board_feitian_rp2350`               | Feitian RP2350 (Pico 2 ref. design)   | Single green LED on GP25 (**active-high**)       | **Real** -- BOOTSEL button sampled via QSPI chip-select (`board/bootsel.rs`)                                                          |
| `board_waveshare_rp2350_lcd_1_47`    | Waveshare RP2350-LCD-1.47-B / -B-M    | **1.47" ST7789V2 LCD stats panel**; WS2812 chain held dark | Auto-confirm. GP23 driven LOW (holds WS2812 data line in reset)                                                            |
| `board_spotpear_rp2350_lcd_1_28`     | Spotpear RP2350-LCD-1.28              | **Round 1.28" GC9A01 LCD stats panel**           | Auto-confirm. GP23 left untouched (IMU interrupt line on this board)                                                                 |
| `board_feitian_rp2350_usbc`          | Feitian RP2350 USB-C token, **experimental** (sealed: no button, no display, **no power-on BOOTSEL**) | Single green LED on GP25 (**active-high**), as the Feitian RP2350 | **Real** -- capacitive touch pad on QSPI_SS, read by the same sampler (`board/bootsel.rs`); validated on one production token (2026-10-02). `CMD_REBOOT` **never** asks for a touch on this board (Axis 5). Flash only with `tools/flash-usbc.sh` -- see [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token) |

The board features compile-error if zero or more than one are enabled (gated by `compile_error!` in `crates/firmware/src/board/mod.rs`). To add a seventh board, see the recipe in the `crates/firmware/src/board/mod.rs` module doc-comment -- drop a new profile under `crates/firmware/src/board/` + a feature line in `Cargo.toml` + one cfg arm in `mod.rs`. No edits to `main.rs` required.

On the two LCD boards the panel is the status surface -- it shows firmware version, board name, algorithm summary, USB serial, PIN state + retries, resident-credential count, uptime, and the most recent CTAP operation. The Waveshare's WS2812 RGB lamps stay dark (they need a PIO program with strict 800 kHz timing -- a future task documented in the board module).

### Axis 3 (optional): Ed25519

EdDSA over Curve25519 (COSE alg `-8`) is gated behind the **`ed25519`** feature, off by default. Adds ~30 KiB to the release binary (pulls in `curve25519-dalek`'s field-arithmetic backend) and a new credentialID format **v2** alongside the existing v1.

```bash
cargo build --release --features ed25519                                                    # default + EdDSA
cargo build --release --no-default-features --features mldsa87,board_xiao_rp2350,ed25519   # everything
```

Builds **without** `ed25519` reject v2 credentials at decrypt time as `BadFormat` (host falls back to ES256 / hybrid credentials it has on file). Builds **with** `ed25519` decrypt both v1 and v2; new Ed25519 credentials are issued as v2. See [`docs/PROTOCOL.md`](PROTOCOL.md#version-byte-v1-vs-v2) for the format details.

### Axis 4 (optional): Instruction set -- Arm, RISC-V, or one of each

The RP2350 carries two Cortex-M33 **and** two Hazard3 RISC-V cores; the boot ROM runs whichever pair the flashed image declares. Everything above builds for either instruction set, and there's an experimental mixed mode:

```bash
cargo build --release                                          # Arm (default target)
cargo build --release --target riscv32imac-unknown-none-elf    # both cores RISC-V
cargo build --release --features core1_riscv                   # Arm core 0 + RISC-V core 1 (experimental)
```

`cargo build-arm` / `cargo build-riscv` aliases exist too. Same boards, same feature axes, same flash-store layout. See [`docs/RISCV.md`](RISCV.md) for the full story -- linker scripts, the custom core-1 launchers, the mixed-mode payload embedding, C-port instructions (`-DPQF_PLATFORM=rp2350-riscv`), and validation status. A RISC-V image is converted with `--family rp2350-riscv` instead of `rp2350-arm-s`, and `picotool load` accepts the ELF directly (`-t elf`).

### Axis 5 (optional): the reboot touch policy, and `reboot_no_up`

Whether the `CTAPHID_CMD_REBOOT` vendor command (host-driven reboot into BOOTSEL / warm -- see [`docs/REBOOT.md`](REBOOT.md)) asks for a touch is a **per-board policy**, identical in both ports and applied to both reboot modes. Software BOOTSEL is on in every image; the board decides whether a gesture guards it:

```
reboot needs a touch  =  HAS_USER_BUTTON && HAS_POWER_ON_BOOTSEL && !reboot_no_up && !test_no_user_button
```

`HAS_USER_BUTTON` (Rust) / `PQF_BOARD_HAS_USER_BUTTON` (C) says the board has a presence input the firmware can read; `HAS_POWER_ON_BOOTSEL` / `PQF_BOARD_HAS_POWER_ON_BOOTSEL` says it has a BOOT / BOOTSEL button you can hold while plugging in -- true on the other five boards, false on the Feitian RP2350 USB-C token. A touch is demanded only where both hold, because a board that can always fall back to a physical BOOTSEL can afford a gate that might fail to be satisfied; a token whose *only* way back into the bootloader is this command cannot. The defaults that follow:

| Board | FIDO presence (`MakeCredential` / `GetAssertion`) | Software BOOTSEL (`c/hid/reboot bootsel`) |
| --- | --- | --- |
| Tiny 2350 | real, BOOT button (or GP0 pad, Rust) | button-gated: press within 10 s |
| Feitian RP2350 (USB-A) | real, BOOTSEL button | button-gated: press within 10 s |
| Feitian RP2350 USB-C token | real, touch pad (unvalidated) | **no touch, by design**: the token has no power-on BOOTSEL, so the reboot must never depend on a gesture |
| XIAO RP2350, Waveshare LCD 1.47, Spotpear LCD 1.28 | auto-confirm (no readable button) | no touch (buttonless) |
| any board + `reboot_no_up` / `-DPQF_REBOOT_NO_UP=ON` | unchanged | no touch |

FIDO user presence is not changed by any of this: a token stays a real authenticator whatever its reboot policy. Which policy an image carries is readable before it is flashed, from its `pqf-reboot=touch|no-touch` marker (see [Identifying an image before flashing it](#identifying-an-image-before-flashing-it)).

`reboot_no_up` (Rust) / `-DPQF_REBOOT_NO_UP=ON` (C) therefore only changes anything on the two button boards -- the Tiny 2350 and the Feitian RP2350 -- where it drops the press **for `CMD_REBOOT` only**, the flash-station convenience for reflashing many boards hands-free:

```bash
cargo build --release --no-default-features --features mldsa65,board_tiny2350,reboot_no_up
REBOOT_NO_UP=1 ./build.sh tiny2350                            # ...or via the wrapper
```

It is **not** `test_no_user_button` (the never-ship gate that auto-confirms *all* user presence, and with it the reboot). It is also **not** what makes a buttonless or sealed token reflashable: the board profile does that, and the USB-C token's image needs no extra option -- its `pqf-reboot` marker reads `no-touch` from `./build.sh feitian_rp2350_usbc` alone. What such a token does need is the right image in the first place; see the [buttonless-lockout warning](REBOOT.md#warning-buttonless-tokens-can-be-locked-out-of-bootsel) and [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token).

### Axis 6 (optional): single core (`single_core`)

Both ports normally run the hybrid signer on core 1 so that core 0 can keep emitting CTAPHID `KEEPALIVE` frames during the ~1 s signature; Chrome drops the transaction if none arrives for a few hundred milliseconds. `--features single_core` (or `SINGLE_CORE=1 ./build.sh`) leaves core 1 asleep and reaches the same cadence by a different route, because the vendored ML-DSA crate is untouched: its sign is one monolithic call with no yield point, so instead of the crypto calling out to the USB pump, a hardware timer interrupts the crypto. Alarm 0 of `TIMER0` is armed for the duration of each CTAP2 dispatch and fires every 25 ms; its handler (`crates/firmware/src/keepalive_timer.rs`) sends one `KEEPALIVE` on the in-flight channel, services the USB device, and re-arms. The signer runs synchronously on core 0 (`Core1Signer::sign_here`, which parks its result exactly where the dual-core wait loop looks, so the CTAP2 code is otherwise unchanged), and the one piece of main-context code that touches USB inside a dispatch -- the `host` closure behind the presence wait and the dual-core pump -- holds a guard the handler checks before it touches the stack. The two XIP-off windows (flash writes, the BOOTSEL chip-select sampler) already masked interrupts, which is what makes an interrupt-driven pump tolerable at all. Arm takes the alarm through the NVIC; Hazard3 through the HAL's machine-external dispatch, which calls the handler by the interrupt's name.

```bash
cargo build --release --features single_core                                         # Arm
cargo build --release --features single_core --target riscv32imac-unknown-none-elf   # Hazard3
SINGLE_CORE=1 ./build.sh
```

What changes: core 1 is never launched, the 64 KiB core-1 stack goes away, the flash-op guard skips its park handshake (there is nobody to park, and waiting for the ack would hang the first flash write), and the USB product string gains ` 1CORE` so a host can tell which signer an image runs. Exclusive with `core1_riscv` (the mixed build is defined by having a second core) and with `gdb_stub` (which also drives USB from an exception context). The host's view of the result -- keepalives per operation and the longest silence between two frames -- is in [TESTING.md](TESTING.md#the-single-core-signer-and-the-yield-hook).

### Axis 7 (optional): discoverable-credential capacity

How many discoverable credentials (passkeys: resident credentials a
browser can sign in with without a username) a token holds is a
build-time choice, the same in both ports. By default the Rust port
holds **6**, in the main store sector next to the PIN, and the C port
**7**, in its own resident-credential sector. `PQF_RESIDENT_EXTRA_SECTORS=N`
adds `N` overflow sectors of **7** further slots each:

| `N` | Rust slots | C slots | Extra flash | Extra RAM, Rust (heap) | Extra RAM, C (`.bss`) |
| --- | --- | --- | --- | --- | --- |
| 0 (default) | 6 | 7 | none | none | none |
| 1 | 13 | 14 | 4 KiB | 4,060 B | about 5.1 KiB |
| 3 | 27 | 28 | 12 KiB | 12,180 B | about 15.4 KiB |
| 8 (the maximum) | 62 | 63 | 32 KiB | 32,480 B | about 41 KiB |

```bash
RK_SECTORS=3 ./build.sh feitian_rp2350                   # Rust, via the wrapper
PQF_RESIDENT_EXTRA_SECTORS=3 cargo build --release -p bruce \
    --no-default-features --features mldsa87,board_feitian_rp2350
RK_SECTORS=3 ./build-c.sh feitian_rp2350                 # C, via the wrapper
cmake -S c/firmware -B <build-dir> -DPQF_BOARD=feitian_rp2350 -DPQF_RESIDENT_EXTRA_SECTORS=3
```

- **Where they go.** Directly below the master-key sector, one 4 KiB
  sector each, highest first: in Rust from `0x103FC000` down
  (`flash_store::overflow_offset(k)`), in C from
  `PICO_FLASH_SIZE_BYTES - 5 x 4 KiB` down. The sectors above them are
  untouched by the option, so a default build and an enlarged one read
  the main store the same way, byte for byte. The linker reservation
  and its image-overlap `ASSERT` grow with `N` (Rust: `build.rs`
  writes the sector count into the linker scripts; C:
  `flash_reserve_assert.ld` is filled in by CMake).
- **Why a maximum of 8.** Every slot is mirrored in RAM: in Rust on the
  heap (580 B a slot, allocated once at boot), in C in `.bss` (564 B a
  slot, plus the credential-management iterators). 8 sectors keeps that
  a small fraction of what the ML-DSA signer needs. Both ports refuse
  anything outside 0..8 at build time.
- **Not with the DFU layout.** The DFU flash map
  ([`c/common/pqf_image.h`](../c/common/pqf_image.h)) puts its install
  journal and staging slot directly below the persisted sectors, where
  the overflow sectors would go, so `PQF_RESIDENT_EXTRA_SECTORS > 0` is
  refused together with `PQF_APP_OFFSET` (Rust) or
  `PQF_BOOTLOADER` / `PQF_APP_OFFSET` (C).
- **Wear.** A counter bump, registration, deletion or rename rewrites
  only the one sector holding that credential; the PIN lives in the
  main sector and is rewritten only by PIN and configuration changes
  and by credentials in the main sector.
- **Torn writes.** Each overflow sector carries its own header (magic,
  layout version, its index, and a four-byte tag derived from the
  master keys) and is written slots first, header last, so a power loss
  during an overflow write leaves that sector reading as empty and no
  other sector changed -- the same guarantee the main sector gives.
- **Enlarging** (flashing a build with more sectors over a token,
  without erasing): the PIN, configuration and every existing passkey
  and counter are kept; the new sectors come up empty and are written
  only when a passkey lands in them. `getInfo 0x14` counts down from
  the new total.
- **Shrinking** (flashing a build with fewer sectors, a default build
  included): nothing is corrupted -- the main sector is untouched --
  but passkeys that lived in the dropped sectors are no longer
  discoverable: they are not listed by credential management, not
  offered for a username-less sign-in and not counted. They still sign
  where the relying party presents the credential id (an `allowList`),
  as any non-discoverable credential of this firmware does, with a
  signature counter of 0 -- a relying party that checks counters
  strictly may flag that. Their sectors are left as they are:
  enlarging again brings them back, unless an `authenticatorReset` ran
  in between (the reset rotates the master keys, so the old tag no
  longer matches and they read as empty; their ids no longer decrypt
  anyway). A passkey registered again for the same account while it
  was unreachable shows up twice after enlarging; delete the older one.
- **Reset.** `authenticatorReset` erases every overflow sector as well.
- **Identifying the capacity of an image.** Its `pqf-rk-slots=<n>`
  marker ([Identifying an image before flashing it](#identifying-an-image-before-flashing-it)).

The TrustZone split (`build-tz.sh`) keeps its own credential store in
the Secure world (`crates/fw-secure/src/credstore.rs`) and is not
affected by this option.

### Other features

| Feature | What it does | Where it is documented |
| --- | --- | --- |
| `test_no_user_button` | **Test only, never ship.** Auto-confirms every user-presence check, even on a board with a real button, so an automated on-silicon run needs no finger. Removes the presence gate from MakeCredential and GetAssertion, and the touch from `CMD_REBOOT` where a board would otherwise demand one. | [TESTING.md](TESTING.md) |
| `gdb_stub` | **Debug only, never ship.** A GDB remote-serial-protocol stub on a second USB CDC interface, so a cased token can be debugged over the cable with no SWD probe. Arm only. An unauthenticated read/write/execute primitive over USB. | [GDB_DEBUG.md](GDB_DEBUG.md) |
| `dfu_runtime` | The USB DFU *runtime* interface, so `dfu-util -D` can detach a running token into the DFU bootloader. Pair with `PQF_APP_OFFSET=1` in the environment, which relocates the image into the bootloader's app slot; both are needed for a DFU-updatable image. | [DFU.md](DFU.md) |
| `core1_riscv` | The mixed-ISA build: `build.rs` cross-compiles the `pqf-core1-riscv` payload, embeds it, and core 1 runs it as a Hazard3. Leaves core 1's ARCHSEL bit set on the board; run `picotool reboot -a -c arm` before flashing a plain Arm image afterwards. | [RISCV.md](RISCV.md) |

### Full feature matrix

The configurations verified end-to-end against Chrome on macOS (except where the row says otherwise):

| Cargo features                                                          | Use case                                                            |
| ---                                                                     | ---                                                                 |
| `mldsa65,board_tiny2350` (default)                                       | Stock Tiny 2350 build, ML-DSA-65 hybrid + ES256                     |
| `mldsa87,board_tiny2350`                                                 | Tiny 2350 with NIST level 5 hybrid (`-56`)                          |
| `mldsa87,board_xiao_rp2350`                                              | XIAO RP2350 with NIST level 5 hybrid                                |
| `mldsa87,board_xiao_rp2350,ed25519`                                      | XIAO + ML-DSA-87 + EdDSA                                            |
| `mldsa44,board_tiny2350`                                                 | Smallest-signature variant (good for RPs with strict DB column limits) |
| `mldsa65,board_waveshare_rp2350_lcd_1_47`                                | Waveshare RP2350-LCD-1.47-B (LCD stats panel, SD untouched, WS2812 dark) |
| `mldsa87,board_waveshare_rp2350_lcd_1_47,ed25519`                        | Waveshare board with everything turned on                            |
| `mldsa65,board_spotpear_rp2350_lcd_1_28`                                 | Spotpear round-LCD board (GC9A01 stats panel)                        |
| `mldsa65,board_feitian_rp2350_usbc`                                      | Feitian RP2350 USB-C token: touch-pad presence, `CMD_REBOOT` never gated (`pqf-reboot=no-touch`). **Experimental**: one production token has run it (2026-10-02, [TESTING.md](TESTING.md#the-first-production-usb-c-token-2026-10-02)); rehearse on a USB-A Feitian and flash only via `tools/flash-usbc.sh` ([the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token)) |

Every ML-DSA level has also been run on silicon on every instruction-set
shape (Arm, RISC-V, mixed, single core) in both ports; the matrix and
the numbers are in [TESTING.md](TESTING.md).

### AAGUID override

The default AAGUID of the Rust port is `ef80634d-5f41-4a62-b14f-5a6944096a0b`, this project's own id (a random version-4 UUID; the C port and the TrustZone Secure image carry their own fixed ids in `c/firmware/src/ctap2.c` and `crates/fw-secure/src/ctap.rs`). For your own deployment provide one at compile time:

```bash
BRUCE_AAGUID=cafebabecafebabecafebabecafebabe cargo build --release
```

The value must be **exactly 32 hex characters with no separators**. A malformed override is a compile error (caught by the `const fn` decoder in `crates/firmware/src/ctap2.rs`).

Before the public release the default was the OpenSK sample id, `664d9f67-84a2-412a-9ff7-b4f7d8ee6d05`, which a relying party that only trusts the OpenSK PQC reference list recognises. A build for such a relying party sets it explicitly:

```bash
BRUCE_AAGUID=664d9f6784a2412a9ff7b4f7d8ee6d05 ./build.sh feitian_rp2350
```

### Release profile

Notable settings in `Cargo.toml [profile.release]`:

- `codegen-units = 1` -- single LLVM module for best optimisation
- `lto = "fat"` -- link-time optimisation across the whole binary
- `opt-level = "s"` -- optimise the binary for **size** (it's already opt-level 3 for the math-heavy crates, see below). Going to opt-level 3 on the whole binary regressed USB enumeration on the RP2350 in early testing; "s" is the safe pick.
- `panic = "abort"` -- no unwind tables, smaller binary
- `overflow-checks = false`
- Per-crate `opt-level = 3` overrides on the math hotspots: `bouncycastle-mldsa-lowmemory`, `bouncycastle-sha3`, `bouncycastle-sha2`, `bouncycastle-core`, `bouncycastle-utils`, `bouncycastle-hmac`, `bouncycastle-hkdf`, `p256`, `elliptic-curve`, `sha2`. Without these, ML-DSA keygen takes >60 s on the M33 at 125 MHz; with them it's hundreds of ms.

If your build comes out > 4 MiB you've inlined yourself out of flash space -- drop a `codegen-units` bump or trim a per-crate opt-level.

### UF2 conversion

The RP2350 boot ROM accepts UF2 (or pico-boot binary) over BOOTSEL. Convert the release ELF:

```bash
picotool uf2 convert -t elf \
    target/thumbv8m.main-none-eabihf/release/bruce \
    bruce.uf2 \
    --family rp2350-arm-s
```

`-t elf` tells picotool the input is an ELF. `--family rp2350-arm-s` is **ARM-Secure** state, which matches the `ImageDef::secure_exe()` we declare at the top of `crates/firmware/src/main.rs`; a RISC-V image takes `--family rp2350-riscv`. `./build.sh` does this step for you.

---

## C firmware

### The wrapper: `build-c.sh`

```bash
./build-c.sh [board]              # same board names as build.sh; default tiny2350
MLDSA=87 ./build-c.sh             # ML-DSA level
SINGLE_CORE=1 ./build-c.sh        # -DPQF_SINGLE_CORE=ON
REBOOT_NO_UP=1 ./build-c.sh       # -DPQF_REBOOT_NO_UP=ON (button boards only, see Axis 5)
RK_SECTORS=3 ./build-c.sh         # -DPQF_RESIDENT_EXTRA_SECTORS=3: 28 discoverable credentials (Axis 7)
RISCV=1 ./build-c.sh              # -DPQF_PLATFORM=rp2350-riscv (needs riscv32-unknown-elf-gcc)
CMAKE_EXTRA="-DPQF_QRNG=OFF -DPQF_GDB_STUB=ON" ./build-c.sh   # anything else, verbatim
PICOTOOL_FORCE_FETCH_FROM_GIT=1 ./build-c.sh                  # let the SDK build its own picotool
```

It checks `PICO_SDK_PATH` (default `~/pico-sdk`), the TinyUSB
submodule, the compiler and the picotool version, then configures into
`c/firmware/build-<board>[-riscv]/`, builds, and copies the image to
`bruce-c.uf2` in the repository root. The raw form:

```bash
export PICO_SDK_PATH=/path/to/pico-sdk
cmake -S c/firmware -B c/firmware/build -DPQF_BOARD=tiny2350 -DPQF_HYBRID_VARIANT=65
cmake --build c/firmware/build -j
# -> c/firmware/build/bruce_c.uf2 and .elf
```

Note that CMake's own default board is the Waveshare LCD module, not
the Tiny 2350; always pass `-DPQF_BOARD=` in the raw form.

### CMake options

| Option | Default | Meaning |
| --- | --- | --- |
| `PQF_BOARD` | `waveshare_rp2350_lcd_1_47` | Target board: `tiny2350`, `xiao_rp2350`, `feitian_rp2350`, `waveshare_rp2350_lcd_1_47`, `spotpear_rp2350_lcd_1_28` or `feitian_rp2350_usbc`. Selects the pico-sdk board header and the pin profile in `src/board.c`, and with it the `PQF_BOARD_HAS_USER_BUTTON` / `PQF_BOARD_HAS_POWER_ON_BOOTSEL` capabilities that decide the reboot touch policy ([Axis 5](#axis-5-optional-the-reboot-touch-policy-and-reboot_no_up)). A `feitian_rp2350_usbc` image is flashed only with `tools/flash-usbc.sh` ([the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token)). |
| `PQF_HYBRID_VARIANT` | `65` | ML-DSA level: `44`, `65` or `87`. |
| `PQF_PLATFORM` | `rp2350` | Instruction set: `rp2350` (Arm Cortex-M33) or `rp2350-riscv` (Hazard3). Use this, **not** `PICO_PLATFORM`, which the build overwrites silently. |
| `PQF_SINGLE_CORE` | `OFF` | Signer inline on core 0; the crypto's yield hook pumps USB and `KEEPALIVE` every `PQF_YIELD_US`. |
| `PQF_YIELD_US` | `25000` | Single core: microseconds between USB + `KEEPALIVE` ticks from inside the crypto. |
| `PQF_CORE1_RISCV` | `OFF` | Mixed mode: the core-1 signer as a RISC-V blob under an Arm core 0. Needs a riscv32 GCC on `PATH` or `PQF_RISCV_TOOLCHAIN_BIN`. Exclusive with `PQF_SINGLE_CORE`. |
| `PQF_RISCV_TOOLCHAIN_BIN` | found on `PATH` | `bin/` directory of a bare-metal riscv32 GCC, for the blob. |
| `PQF_RESIDENT_EXTRA_SECTORS` | `0` | Extra flash sectors of discoverable credentials, 7 each, 0..8: capacity `7 + 7N` ([Axis 7](#axis-7-optional-discoverable-credential-capacity)). Refused with `PQF_BOOTLOADER` / `PQF_APP_OFFSET`. |
| `PQF_REBOOT_NO_UP` | `OFF` | `CMD_REBOOT` needs no touch on the two button boards (`tiny2350`, `feitian_rp2350`). The other profiles, `feitian_rp2350_usbc` included, never ask for one, so it changes nothing there. FIDO user presence unchanged. |
| `PQF_TEST_NO_USER_BUTTON` | `OFF` | **Test only, never ship.** Auto-confirms every user-presence check, including `CMD_REBOOT`'s. |
| `PQF_GDB_STUB` | `OFF` | **Debug only, never ship.** The on-token GDB stub on a second CDC interface. Arm only. |
| `PQF_QRNG` | `ON` (`OFF` on the Spotpear) | Probe I2C at boot for a quantum RNG and prefer it over the on-die TRNG. |
| `PQF_QRNG_I2C` / `_SDA` / `_SCL` / `_PD` / `_BAUD` | `0` / `12` / `13` / `-1` / `100000` | Its bus: controller, pins, power-down GPIO (`-1` = not wired), clock. |
| `PQF_MLDSA_LOWMEM` | `2` | ML-DSA streaming-A policy: `0` off, `1` always, `2` only at level 87 (where the matrix dominates the heap). |
| `PQF_COPY_TO_RAM` | on, except at level 87 single-ISA | Run the image from SRAM (pico `copy_to_ram`) rather than XIP. The build picks per configuration; the configure log says which. |
| `PQF_SIGN_ARENA_BYTES` | `""` (240 KiB) | Level-87 single-ISA only: the dedicated sign arena size. |
| `PQF_BOOTLOADER` | `OFF` | Link behind the DFU bootloader **and** expose the DFU runtime interface (sets both options below). |
| `PQF_APP_OFFSET` | `OFF` | Link the app at the DFU app-slot offset (`0x10021000`). |
| `PQF_DFU_RUNTIME_IF` | `OFF` | Expose the USB DFU runtime interface. |
| `PQF_PROGRAM_URL` | `""` | URL recorded in the picotool binary-info block; empty records none. |
| `PQF_UP_DEBUG` | `OFF` | Test only: instrument the user-presence read. |
| `PQF_CDC_BOOTSEL_HOOK` | `OFF` | Test only: a reflash hook over the CDC port, independent of the presence gate. |
| `PQF_XIP_STATS` | `OFF` | Diagnostic: XIP cache hit rate per hybrid sign, on the CDC port. |

The configure log prints one `Bruce:` line per decision (board,
platform, level, streaming policy, QRNG wiring, copy_to_ram, signer
placement), which is the quickest way to confirm what a build directory
holds.

### On-token GDB stub (`PQF_GDB_STUB`, DEBUG ONLY)

`-DPQF_GDB_STUB=ON` links a GDB remote-serial-protocol stub into the firmware and adds a second CDC interface to serve it, so a developer can debug a **cased, locked token over the USB cable alone** -- no SWD probe, no opened enclosure:

```bash
cmake -S c/firmware -B c/firmware/build-gdbstub \
      -DPQF_BOARD=feitian_rp2350 -DPQF_GDB_STUB=ON
cmake --build c/firmware/build-gdbstub -j
arm-none-eabi-gdb c/firmware/build-gdbstub/bruce_c.elf \
    -ex 'target remote /dev/cu.usbmodemXXXXXXXX4'
```

Arm only (it's built on the ARMv8-M DebugMonitor exception + FPB; a `rp2350-riscv` build is rejected at configure time). Off by default and **must never ship** -- the stub is an unauthenticated read/write/execute primitive over USB. Full story, constraints, and the RSP command set: [`docs/GDB_DEBUG.md`](GDB_DEBUG.md).

### External quantum RNG on I2C (`PQF_QRNG`)

Both ports probe the I2C bus at boot for a QRNG and, if one answers and calibrates, draw every random byte from it -- SHA-256 conditioned, 64 raw in per 32 out -- with the on-die TRNG completing anything the chip leaves short. Nothing attached means the build behaves exactly as before. Default wiring is the Tiny 2350's **QW/ST connector: I2C0, SDA GP12, SCL GP13**, no PD (the breakout idles it high itself).

The Rust firmware always probes (no feature flag; the wiring is fixed in `crates/firmware/src/qrng.rs`) except on the Spotpear board, whose LCD reset is GP12. The C port exposes it as a CMake option, ON by default (OFF for the Spotpear profile, same reason):

```bash
# default: probe the QW/ST connector, i2c0 GP12/GP13, no PD
cmake -S c/firmware -B <build-dir> -DPQF_BOARD=tiny2350
# the breakout header instead: A0/A1 = GP26/GP27 = i2c1, PD on GP2
cmake -S c/firmware -B <build-dir> -DPQF_BOARD=tiny2350 \
      -DPQF_QRNG_I2C=1 -DPQF_QRNG_SDA=26 -DPQF_QRNG_SCL=27 -DPQF_QRNG_PD=2
# compile the probe out entirely
cmake -S c/firmware -B <build-dir> -DPQF_BOARD=feitian_rp2350 -DPQF_QRNG=OFF
```

Works on all three instruction-set shapes; in the mixed build the RISC-V blob receives 32 bytes of QRNG-first entropy per request through the mailbox and hashes it with its own TRNG block. Wiring, protocol, conditioning and the failure policy are in [`docs/HARDWARE.md`](HARDWARE.md#qrng-over-i2c-optional).

### Single core (`PQF_SINGLE_CORE`)

`-DPQF_SINGLE_CORE=ON` leaves core 1 asleep and runs the signer inline on core 0 (`src/core0_signer.c`), moving the keepalive job **inside the crypto**: the vendored ML-DSA, EC and bignum loops call `pqf_yield()` every few microseconds of work (per sampled matrix element, per NTT, per rejection attempt, per ladder step, per exponent window and inversion step) and so does the QRNG driver between I2C packets, and the single-core signer turns those calls into a USB service + `KEEPALIVE` tick once per `PQF_YIELD_US` (default 25 ms). Measured on the Tiny 2350, the longest stretch of any operation without a yield is under 4 ms on both Arm and RISC-V (see [TESTING.md](TESTING.md#the-single-core-signer-and-the-yield-hook)).

```bash
cmake -S c/firmware -B <build-dir> -DPQF_BOARD=tiny2350 -DPQF_SINGLE_CORE=ON
# Hazard3 too:
cmake -S c/firmware -B <build-dir> -DPQF_BOARD=tiny2350 -DPQF_SINGLE_CORE=ON \
      -DPQF_PLATFORM=rp2350-riscv
# a different tick period
cmake ... -DPQF_SINGLE_CORE=ON -DPQF_YIELD_US=50000
```

What changes: no core-1 stack, no flash-op park handshake (a flash write runs its callback directly), no ARCHSEL games, and the core-0 stack reservation doubles because the USB pump now nests inside the crypto. Level 87 keeps its sign arena, routed by a flag for the duration of each op instead of by core id. Not combinable with `PQF_CORE1_RISCV`, which is defined by having a second core. The CDC banner names the build and its heartbeat carries `[1core] ops= yields= ticks= worst-gap=`, the longest stretch of any op with no yield call, i.e. the worst `KEEPALIVE` gap a host can ever see from this image. In the dual-core builds the hook stays a no-op on both cores.

### RISC-V and mixed-ISA C builds

```bash
RISCV=1 ./build-c.sh tiny2350                                   # both cores Hazard3
cmake -S c/firmware -B c/firmware/build-mixed \
      -DPQF_BOARD=feitian_rp2350 -DPQF_CORE1_RISCV=ON           # Arm core 0 + RISC-V core 1
```

Both need a bare-metal riscv32 GCC (`riscv32-unknown-elf-gcc` on
`PATH`, or `-DPQF_RISCV_TOOLCHAIN_BIN=<its bin dir>` for the mixed
build's blob, `-DPICO_TOOLCHAIN_PATH=` for the pure RISC-V build);
there is no default location. A pure RISC-V image is a
`rp2350-riscv` UF2. Check a RISC-V build really is one with
`readelf -h ... | grep Machine`; passing `-DPICO_PLATFORM` instead of
`-DPQF_PLATFORM` silently yields an Arm build. Everything else --
what the mixed build does, its ARCHSEL trap, the per-ISA numbers -- is
in [RISCV.md](RISCV.md).

### The C port's own tests

```bash
( cd c/firmware/openssl-mini/test && make test )   # crypto known-answer tests
( cd c/firmware/test && make test )                # CTAP2 / PIN / hybrid / ... (needs PICO_SDK_PATH for the USB descriptor tests)
( cd c/bootloader/test && make )                   # signed-image verification
```

`tools/host-tests.sh c` runs them all.

---

## Identifying an image before flashing it

Every image from either port carries four picotool binary-info
"program feature" strings, so a UF2 can be identified **before** it is
flashed -- which board it is for, what its presence policies are, and
how many passkeys it holds:

| Marker | Values | Meaning |
| --- | --- | --- |
| `pqf-board=<board id>` | `tiny2350`, `xiao_rp2350`, `feitian_rp2350`, `waveshare_rp2350_lcd_1_47`, `spotpear_rp2350_lcd_1_28`, `feitian_rp2350_usbc` | The board profile the image was built for |
| `pqf-reboot=` | `touch` or `no-touch` | Whether `CTAPHID_CMD_REBOOT` demands a gesture ([Axis 5](#axis-5-optional-the-reboot-touch-policy-and-reboot_no_up)) |
| `pqf-fido-up=` | `touch` or `auto` | Whether `MakeCredential` / `GetAssertion` wait for a real gesture or auto-confirm (`auto` on a buttonless board and on every `test_no_user_button` build) |
| `pqf-rk-slots=<n>` | `6` / `7` by default (Rust / C), 7 more per extra sector | How many discoverable credentials the image can hold ([Axis 7](#axis-7-optional-discoverable-credential-capacity)). Images built before the option existed carry no such marker; they hold 6 / 7 |

`picotool info -a <file.uf2>` prints them on the `features:` line
(the Rust image's program description also names the board):

```
$ picotool info -a bruce.uf2
...
Program Information
 name:          Bruce
 version:       0.1.0
 description:   Hybrid PQC FIDO2 authenticator on RP2350 (Feitian RP2350 USB-C)
 features:      pqf-board=feitian_rp2350_usbc
                pqf-reboot=no-touch
                pqf-fido-up=touch
                pqf-rk-slots=6
 ...
```

For a script, the markers alone:

```bash
picotool info -a bruce.uf2 | grep -o 'pqf-[a-z-]*=[a-z0-9_-]*'
```

An image that prints none of them was built before the markers
existed; treat its board and policies as unknown.

The markers exist for the Feitian RP2350 USB-C token, where the wrong
image is permanent: `tools/flash-usbc.sh` refuses any UF2 not marked
`pqf-board=feitian_rp2350_usbc` **and** `pqf-reboot=no-touch`, with no
override (`tools/flash-usbc.sh --check <file.uf2>` runs only that
inspection and touches no hardware), and `./flash.sh` prints the board a UF2 was built for, asks for
confirmation, and refuses a USB-C token image. The same line answers the everyday question of which board
a stray `bruce.uf2` in the repository root was built for. See
[REBOOT.md](REBOOT.md#unattended-reflash-workflow) and
[the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token).

---

## Common build problems

Rust:

- **`error: ...feature 'inherent_associated_types'`** -- you're on stable or a too-new nightly that removed the feature. `rustup show` inside the checkout should report `nightly-2025-06-23`; if not, `rustup toolchain install nightly-2025-06-23` and build again from inside the checkout so `rust-toolchain.toml` applies.
- **`error: could not compile getrandom for thumbv8m.main-none-eabihf`** -- a `bouncycastle-*` dependency was added without `default-features = false`. The vendored RNG crate gates `getrandom` behind its `std` feature, which the ML-DSA crate forwards; both are off in every firmware manifest, and `getrandom` has no backend on this target.
- **`error: cannot find macro 'vec' in this scope` inside `crates/bc-rust-mini`** -- same cause (the `std` feature got turned on somewhere in the graph).
- **`compile_error!: Bruce: pick exactly ONE of...`** -- you passed two ML-DSA features or two boards, or none. One of each.
- **`error: evaluation panicked: BRUCE_AAGUID must be exactly 32 hex characters`** -- your AAGUID override is the wrong length or contains a non-hex character. Note: no separators.

C:

- **`Incompatible picotool installation found: Requires version 2.3.0, you have version 2.2.0`** -- pico-sdk insists on a picotool of its own major.minor. Upgrade picotool, or set `PICOTOOL_FORCE_FETCH_FROM_GIT=1` and the SDK builds a private copy in the build directory.
- **`arm-none-eabi-ld: cannot find -lc` / `-lg`** while linking the SDK's `bs2_default.elf` -- the compiler has no newlib. Install the Arm GNU Toolchain (macOS: the `gcc-arm-embedded` cask, not the `arm-none-eabi-gcc` formula; Debian/Ubuntu: `libnewlib-arm-none-eabi`) and put it first on `PATH`.
- **`tusb.h: No such file or directory`** -- the SDK's TinyUSB submodule is not initialised: `git -C $PICO_SDK_PATH submodule update --init lib/tinyusb`.
- **`PICO_SDK_PATH ... is not a pico-sdk checkout`** (from `build-c.sh`) -- the variable points somewhere else, or is unset and `~/pico-sdk` does not exist.
- **A RISC-V build that is the same size as the Arm one** -- you passed `-DPICO_PLATFORM`; use `-DPQF_PLATFORM=rp2350-riscv`.

Either port:

- **`picotool load` says "No accessible RP-series devices in BOOTSEL mode were found"** -- the board isn't in BOOTSEL. Hold BOOT, unplug and replug (or tap RESET), and see [FLASHING.md](FLASHING.md#troubleshooting).
- **The device flashes successfully but doesn't enumerate** -- wait 1-2 seconds; some hosts take longer to re-enumerate USB after a re-attach. If still nothing, see the dark-device note in [FLASHING.md](FLASHING.md#intermittent-dark-device-after-flashing-erase-first).

---

## Host test suites

Everything that needs no board, both ports, one command:

```bash
tools/host-tests.sh          # everything
tools/host-tests.sh rust     # the Rust crates (host target, feature variants, the simulated dies)
tools/host-tests.sh c        # the C firmware, bootloader and crypto suites
```

The C USB-descriptor tests compile against the real TinyUSB macros, so
`PICO_SDK_PATH` (or `~/pico-sdk`) is needed even for host tests. The
script also runs the key guard and the ASCII check below. What the
suites cover, and what only silicon can, is in
[TESTING.md](TESTING.md).

---

## ASCII only

Every text file in this repository is plain ASCII: source, docs, scripts,
build files, and commit messages. A serial console, a hex dump, a diff on a
machine with no fonts and a `grep` under any locale all read it the same
way, and nothing depends on the encoding a tool guesses. The sweep that
established this replaced the usual suspects mechanically: `--` for a dash,
`->` and `<-` for arrows, `x` for a multiplication sign, `sec.` for a
section sign, `<=` and `>=` for the comparison signs, `^` for superscripts
(`2^64`), `||` for concatenation, `yes`/`no` for check marks, `+`, `-` and
`|` for box drawing, and `us`, `ohm`, `deg` for the units. Binary fixtures
are declared in `.gitattributes` so no tool mistakes them for text.

Two hooks keep it that way, and `tools/host-tests.sh` runs the same check
over the whole tree. Install them once per clone:

```bash
ln -sf ../../tools/pre-commit.sh .git/hooks/pre-commit    # key guard + ASCII check on staged files
ln -sf ../../tools/commit-msg.sh .git/hooks/commit-msg    # ASCII check on the message
```

A refused commit names every offending `file:line:column` with its code
point. A byte that is genuinely needed inside a string literal goes in as
an escape (`\xNN` in C, `\u{NNNN}` in Rust). `tools/ascii-check.sh --all`
checks the tree, `tools/ascii-check.sh FILE...` a few files, and
`git commit --no-verify` is the deliberate override.

## Going further

- [GETTING-STARTED.md](GETTING-STARTED.md) -- the linear path: tools, build, BOOTSEL, flash, verify.
- [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token) -- the only procedure for flashing the Feitian RP2350 USB-C token.
- [FLASHING.md](FLASHING.md) -- per-board BOOTSEL recipes, wipe procedures, the dark-device note, troubleshooting.
- [USAGE.md](USAGE.md) -- driving the device from the in-tree client examples and from a browser.
- [PROTOCOL.md](PROTOCOL.md) -- full CTAP2 surface specification.
- [TESTING.md](TESTING.md) -- verifying both halves of the hybrid signature programmatically.
- [c/firmware/README.md](../c/firmware/README.md) -- the C port's own map and history.
