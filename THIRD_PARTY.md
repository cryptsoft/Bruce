# Third-party components

This document lists the third-party Rust crates, C vendored sources,
embedded assets, and reference implementations that `bruce` depends
on or derives from, together with their licenses and (where
applicable) the provenance of any pre-generated artefacts checked into
this tree. The Rust firmware's dependencies come first; the C port's
(`c/firmware/`) follow under "C port".

Inclusion of a crate here is informational -- the authoritative
dependency declarations live in [`Cargo.toml`](Cargo.toml) and the
resolved versions in [`Cargo.lock`](Cargo.lock). If the two disagree,
`Cargo.toml`+`Cargo.lock` win.

Contents:

- [Rust crates (runtime dependencies)](#rust-crates-runtime-dependencies)
- [In-tree crates](#in-tree-crates)
- [Reference implementations](#reference-implementations)
- [C port (`c/firmware/`)](#c-port-cfirmware)
- [Hardware (informational)](#hardware-informational)
- [License summary](#license-summary)

## Rust crates (runtime dependencies)

All crates below are pulled in via [`Cargo.toml`](Cargo.toml). Their
licenses are checked against a conservative permissive-only allow-list
(Apache-2.0 / MIT / BSD-3-Clause / ISC, plus the standard dual-license
combinations and the Unicode-3.0 data-table license some host-side
crates pull transitively) defined in [`deny.toml`](deny.toml); run
`cargo deny check licenses` to re-verify. That allow-list governs
third-party crates; `bruce`'s own crates are Apache-2.0 (see
"License summary" below), which the allow-list already covers, so they
need no exemption. Keeping the third-party set permissive-only is
deliberate: a copyleft dependency would impose reciprocal obligations
on a redistributed firmware image that Apache-2.0 does not, so the
check fails loudly if one ever appears.

| Crate | Version | License | Used for |
|-------|---------|---------|----------|
| `cortex-m` | 0.7 | Apache-2.0 OR MIT | Cortex-M intrinsics (`wfe`, `nop`, `sev`) for cross-core synchronisation between `core1_signer` and the main loop. |
| `cortex-m-rt` | 0.7 | Apache-2.0 OR MIT | `#[entry]` macro + linker glue (`crates/firmware/memory.x`). |
| `rp235x-hal` | 0.4 | Apache-2.0 OR MIT | RP2350-specific HAL -- GPIO, clocks, USB, multicore, TRNG, watchdog, picotool binary-info block. |
| `panic-halt` | 1.0 | Apache-2.0 OR MIT | Minimal panic handler -- currently spins forever. |
| `embedded-hal` | 1.0 | Apache-2.0 OR MIT | GPIO trait abstractions (`OutputPin`, `InputPin`) used by the `leds` module. |
| `usb-device` | 0.3 | Apache-2.0 OR MIT | USB device stack (we implement the FIDO HID class directly on top of it in `crates/firmware/src/fido_hid.rs`). |
| `pqf-cbor` | path: `crates/cbor` | Apache-2.0 OR MIT | CBOR codec used for CTAP2 framing. **In-tree** -- see "In-tree crates" below. |
| `p256` | 0.13 | Apache-2.0 OR MIT | ECDSA-P256 keygen and signing (CTAP2 ES256 path + the user keypair for U2F REGISTER). Features: `ecdsa`, `ecdh`, `sha256`. |
| `sha2` | 0.10 | Apache-2.0 OR MIT | SHA-256 (CBOR canonical hashing, HMAC inner hash, `rp_id_hash`, the U2F initial-value digest). |
| `hmac` | 0.12 | Apache-2.0 OR MIT | HMAC-SHA-256 over (version || IV || ciphertext) for credentialID authentication; derivation of `cred_random` and `largeBlobKey`. |
| `rand_core` | 0.6 | Apache-2.0 OR MIT | Trait surface for the on-chip TRNG. |
| `heapless` | 0.8 | Apache-2.0 OR MIT | Inline Vec / String alternatives for the no_std path. |
| `zeroize` | 1.7 | Apache-2.0 OR MIT | Wipe private-scalar buffers on drop. |
| `aes` | 0.8 | Apache-2.0 OR MIT | AES-256 block cipher (raw, no mode) for the in-house CBC implementation in `credential_id`. |
| `cbc` | 0.1 | Apache-2.0 OR MIT | AES-CBC mode for credentialID encryption. |
| `subtle` | 2.5 | BSD-3-Clause | Constant-time HMAC tag and alg-marker equality (`ct_eq`). |
| `embedded-alloc` | 0.6 | Apache-2.0 OR MIT | Global allocator backed by a fixed-size statically-reserved heap. |
| `bouncycastle-mldsa-lowmemory` | path: `crates/bc-rust-mini/crypto/mldsa-lowmemory` (vendored) | MIT (the Bouncy Castle Licence -- verbatim MIT text, (c) The Legion of the Bouncy Castle Inc.; `crates/bc-rust-mini/LICENSE.md`) | ML-DSA-44 / -65 / -87 keygen + sign (low-memory variant). Phase 1b's core dependency. Code consumed UNMODIFIED (comments transliterated to ASCII and a few non-ASCII characters in test assertion strings escaped, see "Vendored: Bouncy Castle Rust crates" below). Earlier revisions of this file mislabelled it Apache-2.0. |
| `bouncycastle-core` (aliased `bouncycastle-core-interface`) | path: `crates/bc-rust-mini/crypto/core` (vendored) | MIT (Bouncy Castle Licence, as above) | Companion trait crate for `bouncycastle-mldsa-lowmemory`. The bc-rust crates carry no `license` field in their Cargo.tomls, so `deny.toml` clarifies them to MIT by name. |
| `bouncycastle-sha2` / `-sha3` / `-hmac` / `-hkdf` / `-rng` / `-utils` | path: `crates/bc-rust-mini/crypto/*` (vendored) | MIT (Bouncy Castle Licence, as above) | SHA-256, SHA-3 / SHAKE (ML-DSA's XOF), HMAC, HKDF, the Hash DRBG type the seed wrappers use, and constant-time helpers -- the symmetric surface behind `crates/firmware/src/bc_crypto.rs`. |
| `mipidsi` (optional, LCD board features) | 0.9 | MIT | MIPI-DSI / SPI display driver -- used for the ST7789V2 panel on the Waveshare RP2350-LCD-1.47 and the GC9A01 panel on the Spotpear RP2350-LCD-1.28. Same crate covers both controllers. |
| `embedded-graphics` (optional, LCD board features) | 0.8 | Apache-2.0 OR MIT | Text + primitive drawing on top of the LCD framebuffer (device-stats panel). |
| `embedded-hal-bus` (optional, LCD board features) | 0.2 | Apache-2.0 OR MIT | `ExclusiveDevice<SPI, CS, Delay>` adapter so an SPI peripheral + a CS pin satisfies `mipidsi`'s `SpiDevice` bound. |
| `ed25519-dalek` (optional, feature `ed25519`) | 2.x | BSD-3-Clause | EdDSA over Curve25519 -- Phase 11c. Features: `zeroize`, `rand_core`, `alloc` (default features OFF so we don't pull `std`). |

### Feature-gated dependency: `ed25519-dalek`

Pulled in only when the `ed25519` cargo feature is enabled. Brings the
following transitive dependencies (all already in the wider Rust crypto
ecosystem under permissive licenses):

  - `curve25519-dalek` -- BSD-3-Clause -- field arithmetic
  - `ed25519` -- Apache-2.0 OR MIT -- RFC 8032 framing
  - `signature` -- Apache-2.0 OR MIT -- generic signer trait
  - `digest` -- Apache-2.0 OR MIT -- SHA-512 driver (already pulled by sha2)

The `ed25519-dalek` 2.x line uses `core::hint::black_box` to defeat
compiler optimisation on the scalar comparison path, which on stable
Rust >=1.66 is fine; no nightly required.

### Host-side PKCS#11 module dependencies (`crates/pkcs11`)

The Rust PKCS#11 module (`pqf-pkcs11`, a host cdylib -- never built for
the embedded target) pulls two host-only crates on top of the in-tree
`pqf-ctaphid` transport:

  - `cryptoki-sys` 0.5 -- **Apache-2.0** -- the Cryptoki ABI: PKCS#11
    types, constants, and the `CK_FUNCTION_LIST` layout, as prebuilt
    bindgen output (the crate's `generate-bindings` feature is OFF, so
    no bindgen runs at build time). This is the package-managed Rust
    equivalent of the vendored OASIS headers the C module uses; the
    authority is the same OASIS pkcs11 headers.
  - `libloading` 0.8 -- **ISC** -- pulled transitively by `cryptoki-sys`
    (its Cryptoki-*loader* side, which this module does not use).

Both are on the permissive allow-list in `deny.toml`.

## In-tree crates

### Vendored: Bouncy Castle Rust crates (`crates/bc-rust-mini/`)

The `bouncycastle-*` rows above are **vendored source from bc-rust**
(<https://github.com/bcgit/bc-rust>, MIT under the Bouncy Castle
Licence): a subset snapshot of a branch that carries a small
`#![no_std]` patch for embedded consumers on top of upstream's
`release/0.1.3alpha` -- bc-rust 0.1.3, with the ML-DSA bound-keeping
fix for crafted inputs (<https://eprint.iacr.org/2026/1032>); the patch
is not in upstream yet. The branch, commit and date are recorded in
[`crates/bc-rust-mini/UPSTREAM`](crates/bc-rust-mini/UPSTREAM); the
licence text is verbatim in
[`crates/bc-rust-mini/LICENSE.md`](crates/bc-rust-mini/LICENSE.md).
Ten crates are present: the eight the firmware graph resolves plus
`hex` and `core-test-framework`, which only the vendored test suites
use. Those suites carry upstream's Wycheproof ML-DSA test vectors
(Google, Apache-2.0) exactly as bc-rust ships them; they are compiled
only when the vendored suites run and are not part of any image. The directory is a nested Cargo workspace (the manifests inherit
from a workspace root, as upstream's do) and is excluded from the
firmware workspace, so the firmware consumes it purely by `path`.

The code is unmodified. The one deviation is in spelling: this
repository is ASCII only, and `tools/vendor-bc-rust.sh` transliterates
upstream's FIPS 204 notation (mathematical italic letters, Greek,
operator signs) to plain letters and names in comments when it copies
the tree, and turns the few non-ASCII characters inside string
literals (test assertion messages) into `\u{XXXX}` escapes, which
leave the strings' values unchanged; it refuses to run if a non-ASCII
character sits anywhere else. See
[`crates/bc-rust-mini/README.md`](crates/bc-rust-mini/README.md) for
the layout, the consumers and the refresh procedure.

### `pqf-cbor` (`crates/cbor/`)

CBOR codec covering the subset CTAP 2.1 uses, implemented from
RFC 8949 sec. 3 (major types 0-7) + sec. 4.2.1 (shortest-form integer
canonical encoding). Definite-length items only -- indefinite-length
sequences and floats are rejected on read, since CTAP 2.1 doesn't
use them.

The public surface is intentionally narrow:

  - `Value` -- sum type with one variant per supported major type
    (`Uint`, `Nint`, `Bytes`, `Text`, `Array`, `Map`, `Tag`) plus
    direct `Bool` / `Null` / `Undef` variants for the simple values.
  - `encode(&Value, &mut Vec<u8>)` -- append the canonical-form CBOR
    bytes to a buffer.
  - `decode(&[u8]) -> Result<Value, Error>` -- parse exactly one
    item; rejects trailing bytes.
  - `cbor_int!` / `cbor_uint!` / `cbor_text!` / `cbor_bytes!` /
    `cbor_bool!` / `cbor_null!` / `cbor_array!` / `cbor_map!` /
    `cbor_tag!` -- literal-friendly constructor macros.

Zero external dependencies; `no_std` + `alloc`. ~700 LOC in a
single `crates/cbor/src/lib.rs` (code + tests). First-party code,
licensed under Apache-2.0 like the rest of the project.

## Reference implementations

### Google OpenSK

`bruce` mirrors the **OpenSK upstream stable** + **OpenSK PQC fork**
spec surface for CTAP 2.1 commands, extensions, and the hybrid PQC
signing scheme. We don't link against OpenSK at compile time, but we:

  - Reference specific files from OpenSK (`OpenSK/src/ctap/*.rs`) in
    code comments where our implementation follows OpenSK's behaviour
    closely. See
    `crates/firmware/src/credential_management.rs`, `crates/firmware/src/authenticator_config.rs`,
    `crates/firmware/src/large_blobs.rs`, `crates/firmware/src/u2f.rs`, `crates/firmware/src/client_pin.rs`,
    and the `Phase 11a` `AssertionIterState` struct in `crates/firmware/src/ctap2.rs`.
  - Adopted the OpenSK PQC fork's hybrid COSE algorithm assignments
    (`-48` = ML-DSA-44 hybrid, `-49` = ML-DSA-65 hybrid, `-50` =
    ML-DSA-87 hybrid), domain-separation label, and wire format
    (`ecdsa_der || mldsa_raw`). The algorithm ids have since been
    relabelled twice: first to the composite code points `-51` / `-52`
    / `-53` requested in draft-ietf-jose-pq-composite-sigs-02, then,
    after RFC 9864 assigned those numbers to other algorithms, to
    `-54` / `-55` / `-56` as requested in draft -04 (see
    [`docs/PROTOCOL.md`](docs/PROTOCOL.md#cose-algorithm-identifiers));
    the label and the wire format are unchanged.
  - Do **not** vendor any code from OpenSK. The CBOR codec is our
    own implementation per RFC 8949; the CTAP 2.1 command handlers
    are written from the CTAP spec, with OpenSK code paths used only
    as a reference for behaviour matching during development.

OpenSK is (c) 2019-2023 Google LLC, licensed under Apache-2.0. The
upstream licence text is retained in this tree as
[`LICENSE-APACHE-OPENSK`](LICENSE-APACHE-OPENSK); no OpenSK checkout
is needed to build. Code whose behaviour was matched against OpenSK is
annotated with the upstream source path in module / function
doc-comments.

### Raspberry Pi pico-examples (BOOTSEL button sampler)

Both firmware ports carry a port of the BOOTSEL button-reading routine
from **raspberrypi/pico-examples**, `picoboard/button/button.c`:

> Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
>
> SPDX-License-Identifier: BSD-3-Clause

  - **Rust:** `crates/firmware/src/board/bootsel.rs`. The technique --
    float the QSPI chip-select pad via its output-enable override, let
    the pad pull-up (or the button, through its 1 kohm to ground) settle
    the line, read it back through SIO's HI GPIO register bank, restore
    the pad -- is reproduced with the RP2350-specific register positions
    cross-checked against the `rp235x-pac` crate (the Rust firmware
    doesn't use the pico-sdk headers).
  - **C:** `c/firmware/src/bootsel.c`. Reproduced essentially verbatim
    against the pico-sdk (which supplies `__no_inline_not_in_flash_func`,
    the interrupt save/restore, `hw_write_masked`, and the ioqspi/sio
    struct headers), so it stays close to the upstream original. This
    file is kept under **BSD-3-Clause** and combined into the otherwise
    Apache-2.0 C firmware -- BSD-3-Clause is one-way compatible with
    Apache-2.0, so the combined image is Apache-2.0 while the file's
    BSD notice is retained.

Both keep the upstream copyright + SPDX notice in the file header, and
the licence's conditions and disclaimer are reproduced in
[`LICENSE-BSD-3-CLAUSE-PICO-EXAMPLES`](LICENSE-BSD-3-CLAUSE-PICO-EXAMPLES),
which together cover the BSD-3-Clause retention conditions for source
and binary distributions. The Feitian RP2350 board profile (both ports) uses the
routine to turn the board's only button (BOOTSEL, on QSPI_SS) into the
CTAP user-presence button.

copyleft-licensed adaptations of the same routine exist in other FIDO
firmware projects (pico-fido / pico-keys-sdk); they were **not**
consulted or derived from -- the BSD upstream is the sole source.

### Pre-generated U2F batch attestation cert + key

`crates/firmware/src/u2f.rs` ships a **development-only** ECDSA-P256 attestation
keypair + matching X.509 cert as inline constants (`BATCH_KEY` and
`BATCH_CERT_DER`). They were generated once via OpenSSL:

```sh
openssl ecparam -genkey -name prime256v1 -noout -out u2f_batch.key
openssl req -new -x509 -days 3650 -key u2f_batch.key \
    -out u2f_batch.crt \
    -subj "/CN=pqc-fido U2F Dev"
openssl x509 -in u2f_batch.crt -outform der -out u2f_batch.der
xxd -i u2f_batch.der    # -> BATCH_CERT_DER
openssl ec -in u2f_batch.key -text -noout  # -> BATCH_KEY (priv scalar)
```

**These values are NOT suitable for production.** Every device built
from this source ships with the same hardcoded batch attestation key,
which defeats the cloned-token detection that U2F batch attestation is
supposed to provide. Production firmware should provision a per-batch
(or per-device) attestation key + CA-signed cert via the vendor
flashing pipeline, not bake dev values into the binary. Most
post-U2F-era RPs don't verify the batch attestation cert chain
(it's optional under U2F), so the dev cert is "good enough" for the
test matrix.

The dev cert is self-signed and self-issued; subject = issuer =
`CN=pqc-fido U2F Dev`; validity 10 years from the date of
generation (encoded in the DER blob).

## C port (`c/firmware/`)

The C implementation of the firmware has its own dependency set,
disjoint from Cargo:

### Vendored: OpenSSL 3.5 (`c/firmware/openssl-mini/`)

The C port's crypto is **vendored source from OpenSSL 3.5**
(Apache-2.0): SHA-256 / SHA-512, SHA-3 + Keccak-1600 (SHAKE XOF for
ML-DSA), the AES-256 core, the full BN bignum tree, the EC tree
(NIST P-256 group, ECDSA with the hedged deterministic nonce, ECDH),
the ML-DSA (FIPS 204) tree, and the `packet.c` / `buffer.c` support
they rely on. Every vendored file **retains its original OpenSSL
copyright + Apache-2.0 license header**, and the sixteen files that
carry local changes -- the ten `src/ml_dsa/` files with the low-memory
work, `bn_exp.c`, `bn_gcd.c`, `ec_mult.c` and `ecdsa_ossl.c` with the
`pqf_yield` and `pqf_ecdsa_dbg` hooks, and `bn_intern.c`,
`include/crypto/bn.h` and again `ec_mult.c` with the backported fix for
CVE-2026-54872 from OpenSSL 3.5.9 -- say so in a modification notice
under that header (Apache-2.0 section 4(b)); local adaptation shims (the
`pqf_*.c` wrappers, header stubs that replace the provider/EVP
machinery) are first-party. See
[`c/firmware/openssl-mini/README.md`](c/firmware/openssl-mini/README.md)
for the vendoring rules and
[`c/firmware/openssl-mini/P256-VENDORING.md`](c/firmware/openssl-mini/P256-VENDORING.md)
for the file-by-file P-256 provenance.

### Build-time platform dependencies (not vendored)

| Component | License | Used for |
|-----------|---------|----------|
| Raspberry Pi **pico-sdk** (via `PICO_SDK_PATH`) | BSD-3-Clause | RP2350 runtime: clocks, GPIO, flash, multicore, boot ROM glue, board headers. |
| **TinyUSB** (ships inside pico-sdk) | MIT | USB device stack -- the composite CDC + FIDO HID device (`tud_*`). |
| **lwIP** (ships inside pico-sdk as `pico_lwip`) | BSD-3-Clause | TCP/IP stack of the USB network gadget under `c/gadget/` only; not part of either authenticator image. |
| Arm GNU Toolchain (`arm-none-eabi-gcc`) | copyleft (toolchain only) | Cross-compiler; nothing from it is distributed in the firmware image beyond the usual compiler runtime support (libgcc, newlib -- both with linking exceptions). |

### OpenSK-derived constant

`c/firmware/src/hybrid.c` embeds the same 32-byte hybrid
domain-separation label (`PQF_HYBRID_LABEL`) that the Rust firmware
uses -- the constant originates in the **OpenSK PQC fork**
(Apache-2.0, (c) Google LLC) and is attributed in the file header. The
host-side benchmark
(`crates/ctaphid-client/examples/bench.rs::HYBRID_LABEL`) carries the
same constant, for the verifier side of the construction, attributed
the same way. As on the Rust side, no OpenSK *code* is vendored; CTAP
behaviour is written from the CTAP 2.1 spec with the in-repo Rust
firmware as the parity base.

### First-party C components

`c/cbor` (libpqcbor) and `c/hid` (libpqhid) are first-party
components (listed here only for provenance). The CBOR decoder is
implemented from RFC 8949 alone. The C firmware sources under
`c/firmware/src/` are first-party code, as are the PKCS#11 module
sources under `c/pkcs11/` (`pqf_pkcs11.c`, `cryptoki.h`, `smoke.c`,
`proof.c`) and the USB network gadget under `c/gadget/`.

### Vendored: OASIS PKCS#11 v3.01 headers (`c/pkcs11/oasis/`)

| Field    | Value                                                              |
|----------|--------------------------------------------------------------------|
| Files    | `pkcs11.h`, `pkcs11t.h`, `pkcs11f.h` -- vendored verbatim           |
| Source   | <https://github.com/oasis-tcs/pkcs11> (`published/3-01/`)          |
| License  | OASIS IPR Policy -- distribution permitted AS-IS (notice retained in each file's header) |
| Role     | Cryptoki type/constant/prototype definitions for the `pqf-pkcs11` module |

The OASIS terms permit redistribution of the unmodified headers and
are compatible with Apache-2.0 (they impose no copyleft and no
restriction beyond retaining the notice).

## Hardware (informational)

  - **Pimoroni Tiny 2350** (board feature `board_tiny2350`, default) --
    RP2350A in a USB-stick form factor. RGB LED on GP18/19/20
    active-low. The on-board BOOT button (on QSPI_SS, read with the
    pico-examples chip-select sampling technique attributed above) is
    the CTAP user-presence button; an optional external touch/button
    input on GP0 (boot-time polarity auto-detection) also counts.
  - **Feitian RP2350** (board feature `board_feitian_rp2350`) --
    RP2350A board following the Pi Pico 2 reference design
    (schematic `PICO2_G9_QE09_V1.0`). Single user LED on GP25,
    active-HIGH (opposite polarity to the XIAO). The BOOTSEL button
    (on QSPI_SS) doubles as the CTAP user-presence button via the
    pico-examples chip-select sampling technique attributed above.
    The firmware addresses a 4 MiB flash window per the reference
    design; the die on the sample units measured 2 MiB (see
    `docs/DFU.md`).
  - **Seeed Studio XIAO RP2350** (board feature `board_xiao_rp2350`) --
    RP2350A in the XIAO form factor. Dual red/yellow user LED on
    GP25 active-low. NeoPixel WS2812 on GP22 with power-enable on
    GP23 (firmware MUST drive GP23 low to keep VBUS clean during
    USB enumeration).
  - **Waveshare RP2350-LCD-1.47-B / -B-M** (board feature
    `board_waveshare_rp2350_lcd_1_47`) -- Pico-2-footprint RP2350A
    dev board with a 1.47" 172x320 ST7789V2 LCD, a WS2812 RGB chain
    on GP23, and an SD card slot. The firmware drives the LCD as a
    live device-stats panel (firmware version, algorithm, USB serial,
    PIN state, last operation). LCD pin map: SPI0 with SCK=GP18,
    MOSI=GP19, DC=GP16, CS=GP17, RST=GP20, BL=GP21. SD card and
    WS2812 chain are present on the board but unused by the firmware
    today (the WS2812 chain is a future PIO task).
  - **Spotpear RP2350-LCD-1.28** (board feature
    `board_spotpear_rp2350_lcd_1_28`) -- round 1.28" 240x240 GC9A01
    LCD on the same RP2350A SoC. Stats layout is tuned for the
    circular panel -- text confined to a 180x180 inscribed square so
    nothing clips at the corners. LCD pin map: SPI1 with SCK=GP10,
    MOSI=GP11, CS=GP9, DC=GP8, RST=GP12, BL=GP25. The two LCD boards
    share the `mipidsi` + `embedded-graphics` + `embedded-hal-bus`
    dep set (mipidsi 0.9 supports both ST7789 and GC9A01 from the
    same crate).

Schematics for all five boards are publicly available from the
respective vendors; cross-referenced board-config headers live in
`pico-sdk/src/boards/include/boards/` (Raspberry Pi pico-sdk,
BSD-3-Clause). Those headers were consulted while writing the GP25 /
GP23 wiring rationale comments in the board profiles under
`crates/firmware/src/board/` but are not vendored into this repo.

## License summary

`bruce` is licensed under the **Apache License, Version 2.0**
(Apache-2.0) throughout -- full text in [`LICENSE`](LICENSE) at the
repository root.

That covers all first-party code: the Rust firmware and workspace
crates, the C firmware sources under `c/firmware/src/`, the first-party
C libraries (`c/cbor`, `c/hid`) and the vendored-crypto directory
`c/firmware/openssl-mini/`. Every first-party source file -- Rust, C,
headers, linker scripts, build files and scripts -- carries a
`Copyright <year> Cryptsoft Pty Ltd` line and an
`SPDX-License-Identifier: Apache-2.0` tag; the Rust crates also declare
`license = "Apache-2.0"` in their `Cargo.toml`s; and [`NOTICE`](NOTICE)
is the attribution file that Apache-2.0 section 4(d) asks a
redistributor to keep with the work.

Cryptsoft Pty Ltd holds the copyright on all first-party code
(written against the published specifications, with OpenSK consulted
for behaviour and nothing copied from it, as documented throughout
this file); see the copyright line in [`LICENSE`](LICENSE).

Third-party code is NOT relicensed: every component the project
vendors, derives from or depends on keeps the licence its upstream
ships it under. See "Per-file exceptions" below and the per-component
entries throughout this file.

### Per-file exceptions

These derivations are retained under their own (permissive) licences
and are NOT relicensed:

  - The four BOOTSEL-button files derived from Raspberry Pi
    pico-examples (see the pico-examples entry above) -- all
    **BSD-3-Clause**, all keeping the upstream
    `Copyright (c) 2020 Raspberry Pi (Trading) Ltd.` notice, with the
    licence text in
    [`LICENSE-BSD-3-CLAUSE-PICO-EXAMPLES`](LICENSE-BSD-3-CLAUSE-PICO-EXAMPLES):

      - `c/firmware/src/bootsel.c`
      - `c/firmware/src/bootsel.h`
      - `crates/firmware/src/board/bootsel.rs`
      - `crates/fw-secure/src/bootsel.rs`

    BSD-3-Clause and Apache-2.0 are both permissive and combine
    freely, so the firmware images ship under Apache-2.0 while these
    files keep their upstream notice.
  - `c/firmware/pico_sdk_import.cmake` and `c/gadget/pico_sdk_import.cmake`
    -- verbatim copies of pico-sdk's `external/pico_sdk_import.cmake`,
    **BSD-3-Clause**, `Copyright 2020 Raspberry Pi (Trading) Ltd.`, with
    the licence text inline in each file. Build glue only; nothing from
    them is in a firmware image.
  - The OASIS PKCS#11 headers under `c/pkcs11/oasis/`
    (`pkcs11.h`, `pkcs11t.h`, `pkcs11f.h`) -- vendored verbatim under
    the **OASIS IPR Policy**, notice retained in each file.
  - The vendored OpenSSL 3.5 sources under
    `c/firmware/openssl-mini/` -- **Apache-2.0**, upstream copyright
    and licence headers retained.
  - The vendored Bouncy Castle Rust crates under
    `crates/bc-rust-mini/` -- **MIT** (the Bouncy Castle Licence),
    `LICENSE.md` retained verbatim at that directory's root.
  - [`LICENSE-APACHE-OPENSK`](LICENSE-APACHE-OPENSK) -- the upstream
    OpenSK **Apache-2.0** licence, retained to cover the
    OpenSK-derived `PQF_HYBRID_LABEL` constant and the attributed
    protocol-surface ports documented above.

### Third-party compatibility

Every third-party component in both firmware images is permissively
licensed: Apache-2.0 (OpenSSL 3.5 vendored sources, OpenSK-derived
material), MIT (TinyUSB, the Bouncy Castle Licence on the vendored
bc-rust crates,
mipidsi, hidapi), BSD-3-Clause (pico-sdk, pico-examples, subtle,
ed25519-dalek), ISC (riscv/riscv-rt), and Unicode-3.0 (transitive
data tables). Every one of those is compatible with Apache-2.0:

  - **Redistribution**: every licence above is either Apache-2.0
    itself or a notice-retention licence (MIT / BSD-3-Clause / ISC /
    Unicode-3.0) that Apache-2.0 works combine with freely. The
    obligations they add are limited to keeping the upstream notices,
    which this file and the per-file headers do.
  - **No copyleft in the image**: no strong- or network-copyleft
    third-party code is in either firmware image, so a redistributed
    image carries no reciprocal source obligations (the
    cross-compiler's copyleft covers the toolchain only, with the
    usual runtime-library linking exceptions).

The Rust dependency tree is enforced mechanically by
[`deny.toml`](deny.toml) (`cargo deny check licenses`): the allow-list
is permissive-only and any new copyleft dependency fails the check. The C port's vendored
components are not Cargo crates and are audited by hand in this file.

To regenerate the dependency tree for audit:

```sh
cargo tree --no-default-features --features mldsa65,board_tiny2350 -e normal
cargo tree --features ed25519 -e normal       # with EdDSA backend
```
