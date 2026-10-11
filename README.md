# Bruce

A **hybrid post-quantum FIDO2 / WebAuthn authenticator** for RP2350-based USB tokens, with two independent, wire-compatible implementations in this repository: a bare-metal **Rust firmware** under [`crates/firmware/`](crates/firmware) and a **C firmware** under [`c/firmware/`](c/firmware/README.md) on the pico-sdk. They share the credential-id format, the CTAP 2.1 command surface, the extensions, the error-code discipline and the six board profiles, so a relying party cannot tell which one it is talking to. A credential registered under one of its composite COSE algorithms (`-54`, `-55`, `-56` depending on the ML-DSA security level -- the ids requested in `draft-ietf-jose-pq-composite-sigs-04`, still provisional) is signed with both classical ECDSA-P256 **and** ML-DSA -- Module-Lattice-based Digital Signature Algorithm -- under the OpenSK PQC fork's hybrid construction. The hybrid scheme survives even if either half is broken in the future, so credentials issued today stay safe through the post-quantum transition. A relying party that asks only for ES256 (`-7`) gets a classical ES256 credential instead, so sites that do not know the composite ids keep working; the firmware never forces the hybrid on them. Five development boards are supported out of the box -- the [Pimoroni Tiny 2350](https://shop.pimoroni.com/products/tiny-2350) (default), the [Seeed Studio XIAO RP2350](https://www.seeedstudio.com/Seeed-XIAO-RP2350-p-5944.html), the Feitian RP2350 (a Pi Pico 2 reference-design board), the [Waveshare RP2350-LCD-1.47](https://www.waveshare.com/rp2350-lcd-1.47.htm) and the Spotpear RP2350-LCD-1.28 -- picked at compile time (a cargo feature, or a CMake option for the C firmware). A sixth profile, the Feitian RP2350 USB-C token (a sealed token with a capacitive touch pad and no power-on BOOTSEL), is **experimental**: one production token has run this firmware so far, and a wrong image leaves a token permanently unflashable, so read [the USB-C token section of docs/FLASHING.md](docs/FLASHING.md#the-feitian-usb-c-token) before plugging one in. Three of the profiles enforce **real CTAP user presence**: the Tiny 2350 via its BOOT button or an external touch button on GP0, the Feitian RP2350 via its BOOTSEL button sampled at runtime through the QSPI chip-select line, and the USB-C token via its touch pad, read by the same sampler (validated on one production token on 2026-10-02).

> **COMPATIBILITY: a hybrid credential needs a verifier for this construction, not for the IETF draft.** The hybrid credentials carry the composite COSE ids requested in `draft-ietf-jose-pq-composite-sigs-04` (`-54`, `-55`, `-56`), but the algorithm behind them is the OpenSK PQC fork's, not the draft's: the classical half is ECDSA P-256 at every level (the draft's `-56` pairs ML-DSA-87 with P-384), the public key is an EC2 COSE_Key with the ML-DSA key added at label `-4` rather than the draft's AKP key, and the signature is `ecdsa_der || mldsa_sig` bound by OpenSK's label-prefix combiner rather than the draft's. A relying party that implements the draft cannot verify these credentials; it needs a Bruce / OpenSK-construction verifier. [docs/PROTOCOL.md, "Deviations from draft -04"](docs/PROTOCOL.md#deviations-from-draft--04) lists the differences. An ES256 (`-7`) credential is ordinary WebAuthn and verifies anywhere.

The Rust firmware boots directly on the RP2350 with no operating system: a `rp235x-hal` runtime, the `cortex-m-rt` reset vector, and a custom CTAP HID USB class talking straight to the chip's USB controller. ML-DSA signing runs on the chip's second Cortex-M33 core so the first core can keep pumping CTAP HID `KEEPALIVE` frames to the host (Chrome's WebAuthn watchdog will time the transaction out otherwise -- see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the multicore story). The full CTAP 2.1 command surface is implemented, matching OpenSK upstream stable for everything except `authenticatorBioEnrollment` (no fingerprint sensor on RP2350) and vendor-cert enterprise attestation (out of scope for firmware). CTAP1 / U2F is implemented in `u2f.rs` but **deliberately disabled at the transport** -- the CTAPHID layer advertises `NMSG` and refuses `CMD_MSG`, forcing browsers onto CTAP2 so attestation always comes back `fmt="packed"` (browsers that detect a working U2F path prefer it for plain ES256 registrations and emit `fmt="fido-u2f"`, which PQC-aware RPs reject).

The C firmware under [`c/firmware/`](c/firmware/README.md) is built on pico-sdk and TinyUSB with crypto vendored from OpenSSL 3.5, at full CTAP 2.1 command-surface parity with the Rust firmware: the same commands, extensions, error codes, 161-byte credential-id layout and six board profiles. [Its README](c/firmware/README.md#boards) has the board matrix and the few differences; the table below is the short form.

> WARNING: **Research / engineering build.** Wire-compatible with the OpenSK reference implementation byte-for-byte, end-to-end verified against Chrome on macOS and Firefox, but **not** FIPS-validated, not certified, and not yet hardened against side-channel attacks. The U2F batch attestation key + cert shipped in `crates/firmware/src/u2f.rs` is a development-only value; see [`THIRD_PARTY.md`](THIRD_PARTY.md) for provenance. The two signing keys under [`keys/`](keys/README.md) (firmware signing and secure boot) are **public development keys**, committed on purpose: a board provisioned with them has a signature check that anyone with this repository can satisfy, not secure boot. Never ship an image signed with them and never burn the dev boot key into OTP. Use this firmware to learn, prototype RP-side software against, or vendor-test PQC authentication flows. Don't use it as the only line of defence on a production account. [`SECURITY.md`](SECURITY.md) says what this release does and does not promise, and how to report a vulnerability privately.

---

## Rust or C?

| | Rust firmware (`crates/firmware`) | C firmware (`c/firmware`) |
| --- | --- | --- |
| **Toolchain** | `rustup` (the pinned nightly installs itself) and `picotool` | pico-sdk 2.3.1 with TinyUSB, the Arm GNU Toolchain, CMake and `picotool` |
| **Crypto** | the vendored Bouncy Castle Rust crates (ML-DSA, SHA-2, SHA-3, HMAC, HKDF) and the RustCrypto `p256` crate | the vendored OpenSSL 3.5 subset (ML-DSA, EC, bignum, SHA, AES) |
| **Passkey slots** | 6 per flash sector | 7 per flash sector |
| **LCD status panels** (Waveshare, Spotpear) | driven | not driven: LED or nothing |
| **USB serial liveness port** | none | a CDC port with a banner and a heartbeat line |
| **USB product string** | names the board, for example `Tiny 2350 PQC` | `Bruce (C port)` on every board |
| **AAGUID** | `ef80634d-5f41-4a62-b14f-5a6944096a0b` | `35d31127-7725-4b9b-85ab-73049d569636` |

Credentials do not carry over between the two: each firmware keeps its
own master keys, so after switching images (erase first) you register
again. If you have no preference, start with the Rust firmware: it
needs fewer tools. Everything else on this page applies to both unless
it says otherwise.

---

## Status

| Area                         | Supported                                                                                                     |
| ---                          | ---                                                                                                           |
| **CTAP2 commands**           | `MakeCredential` (0x01) / `GetAssertion` (0x02) / `GetNextAssertion` (0x08) / `GetInfo` (0x04) / `ClientPIN` (0x06) / `Reset` (0x07) / `Selection` (0x0B) / `CredentialManagement` (0x0A, 7 subcmds) / `AuthenticatorConfig` (0x0D, 4 subcmds) / `LargeBlobs` (0x0C) |
| **CTAP1 / U2F**              | Implemented in `u2f.rs` (`REGISTER` / `AUTHENTICATE` / `VERSION`, 161-byte keyhandles bidirectional with CTAP2, dev-only batch attestation cert -- see [`THIRD_PARTY.md`](THIRD_PARTY.md)) but **disabled at the transport in a default build**: CTAPHID advertises `NMSG` and refuses `CMD_MSG`, so browsers always use CTAP2 and attestation stays `fmt="packed"`. The whole module is behind the opt-in `u2f` cargo feature, which also keeps the dev-only batch attestation key out of a default image. |
| **COSE algorithms**          | `ES256` (-7) always; one of `MLDSA44-ES256` (-54) / `MLDSA65-ES256` (-55) / `MLDSA87-ES384` (-56) per build feature -- the composite PQ/T code points requested in `draft-ietf-jose-pq-composite-sigs-04` (provisional; see [docs/PROTOCOL.md](docs/PROTOCOL.md#cose-algorithm-identifiers)), not the RFC 9964 pure ML-DSA ids -48/-49/-50, and not -51/-52/-53, which RFC 9864 assigned to ESP384 / ESP512 / Ed448; `EdDSA` (-8 Ed25519) optional behind feature `ed25519` |
| **ML-DSA variant selection** | Compile-time cargo feature (`mldsa44` / `mldsa65` / `mldsa87`). Default: `mldsa65`. `getInfo` advertises all three hybrid variants regardless of which one this build implements (defeats Chrome's `kNoCommonAlgorithms` short-circuit) |
| **WebAuthn extensions**      | `hmac-secret` / `credProtect` / `credBlob` / `minPinLength` / `largeBlobKey` |
| **PIN protocols**            | v1 and v2 (both advertised; Chrome on macOS picks v2 currently)                                              |
| **PIN/UV-token permissions** | RP-scoped + bit-flagged: `mc` (0x01), `ga` (0x02), `cm` (0x04), `lbw` (0x10), `acfg` (0x20) -- granted via `getPinUvAuthTokenUsingPinWithPermissions` (subcmd 0x09) |
| **Credential storage**       | Stateless 161-byte encrypted credentialID (keys + credProtect policy live inside the ID, encrypted under per-device master keys). Format v1 = ES256 / hybrid; format v2 = Ed25519 (only when feature `ed25519` is on) |
| **Resident credentials**     | Yes -- **6** slots in the Rust port, **7** in the C port. Both are `(4096 - header) / slot size` in one flash sector; the slots differ because the Rust record carries a 128-byte `rp_id` where the C record carries 64. `getInfo` reports the free count as `0x14 remainingDiscoverableCredentials` (see the [flash schema table](docs/ARCHITECTURE.md#flash-schema-evolution)) |
| **LargeBlobs**               | Yes -- up to 2 KiB in a dedicated 4 KiB flash sector. Per-credential 32-byte `largeBlobKey` derived deterministically from `HMAC(key_handle_hmac_key, "pqf-large-blob-key" \|\| credentialId)` |
| **CTAP HID transport**       | INIT / PING / WINK / CBOR / CANCEL / KEEPALIVE; `CMD_MSG` refused + `NMSG` advertised (U2F off at the transport -- see the CTAP1 row) |
| **Boards supported**         | Pimoroni Tiny 2350 (`board_tiny2350`, default) / Seeed Studio XIAO RP2350 (`board_xiao_rp2350`) / Feitian RP2350 (`board_feitian_rp2350`, Pico 2 reference design) / Waveshare RP2350-LCD-1.47-B (`board_waveshare_rp2350_lcd_1_47`, stats LCD) / Spotpear RP2350-LCD-1.28 (`board_spotpear_rp2350_lcd_1_28`, round stats LCD) / Feitian RP2350 USB-C token (`board_feitian_rp2350_usbc`, **experimental**: sealed, capacitive touch pad, **no power-on BOOTSEL**, one production token validated so far -- flash only as described in [the USB-C token section of docs/FLASHING.md](docs/FLASHING.md#the-feitian-usb-c-token)) |
| **Instruction sets**         | Arm Cortex-M33 (default, both ports, production) / Hazard3 RISC-V / mixed mode `core1_riscv` (Arm core 0 + RISC-V core 1 signing worker) / **single core** (both ports: core 1 stays asleep and the signer runs on core 0 -- the C port's crypto pumps USB and `KEEPALIVE` from its own yield hook, `-DPQF_SINGLE_CORE=ON`; the Rust port leaves `bc-rust` untouched and lets a 25 ms timer interrupt send them, `--features single_core`). **All three shapes are silicon-validated in both ports** -- see [docs/RISCV.md](docs/RISCV.md). Arm is the production default; TrustZone-M is Arm-only and cannot be combined with the RISC-V cores |
| **User presence**            | Real press-to-confirm on the Tiny 2350 and the Feitian RP2350, both through their **BOOT button** sampled via the QSPI chip-select line (`board/bootsel.rs`, `bootsel.c`); the Tiny additionally accepts an external touch button on GP0 with boot-time polarity auto-detection. The Feitian RP2350 USB-C token reads its **capacitive touch pad** through the same sampler (on QSPI_SS; validated on one production token on 2026-10-02, see [docs/TESTING.md](docs/TESTING.md#the-first-production-usb-c-token-2026-10-02)). Fresh release->press gesture, 20 ms debounce, 10 s timeout -> `CTAP2_ERR_OPERATION_DENIED` (0x27); `KEEPALIVE(UPNEEDED)` pumped so the browser shows "touch your key". Boards without a readable button auto-confirm. The host reboot command (`CTAPHID_CMD_REBOOT`) follows a separate per-board policy: a press on the two button boards, none on the USB-C token or the buttonless boards -- see [docs/REBOOT.md](docs/REBOOT.md#user-presence). |
| **C port**                   | [`c/firmware/`](c/firmware/README.md) -- pico-sdk + TinyUSB + OpenSSL-vendored crypto, full CTAP 2.1 command-surface parity with the Rust firmware, same six boards (CMake `-DPQF_BOARD=...`) incl. the BOOTSEL user-presence gate |
| **Browsers verified**        | Chrome on macOS, Firefox                                                                                       |
| **USB descriptor hygiene**   | Random 8-hex-char serial per boot, drawn from the entropy picker (QRNG when attached, TRNG otherwise); `bcdDevice` derived from `CARGO_PKG_VERSION` |
| **Entropy sources**          | A **quantum RNG on I2C** is preferred over the on-die TRNG when one answers at boot -- SHA-256 conditioned (64 raw -> 32), TRNG completes any shortfall, nothing attached = TRNG as before. Both ports, all three instruction-set shapes (the mixed build ships QRNG-first entropy to the RISC-V blob through the mailbox). C: `PQF_QRNG` (default ON, pins configurable); Rust: always probed. Ask the token which source is live with `make -C c/hid rng && ./c/hid/rng` (vendor `CMD_RNG_STATUS`). See [docs/HARDWARE.md](docs/HARDWARE.md#qrng-over-i2c-optional) |
| **AAGUID**                   | `ef80634d-5f41-4a62-b14f-5a6944096a0b` by default (this project's own id for the Rust port; the C port and the TrustZone build each carry theirs); override at build time with the `BRUCE_AAGUID` env var -- for example with the OpenSK sample id for a relying party that only trusts the OpenSK PQC reference list, see [docs/BUILD.md](docs/BUILD.md#aaguid-override) |

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the full CTAP2 surface and wire-format details. Feature parity with OpenSK upstream stable is achieved across the whole CTAP 2.1 command surface, modulo three out-of-scope items: `authenticatorBioEnrollment` (no fingerprint sensor on RP2350), full vendor-cert enterprise attestation (no flashing pipeline), and the OpenSK PQC fork's `recovery` extension (unstable spec).

---

## Hardware required

Pick one of the supported boards (cargo features `board_tiny2350` / `board_xiao_rp2350` / `board_feitian_rp2350` / `board_waveshare_rp2350_lcd_1_47` / `board_spotpear_rp2350_lcd_1_28` / `board_feitian_rp2350_usbc` select between them at compile time -- see [`crates/firmware/src/board/mod.rs`](crates/firmware/src/board/mod.rs) for the "Adding a new board" recipe):

- **Pimoroni Tiny 2350** ([product page](https://shop.pimoroni.com/products/tiny-2350)) -- RP2350A SoC, USB-C, 4 MiB QSPI flash, 520 KiB SRAM, on-board RGB LED (R = GP18, G = GP19, B = GP20, common-anode active-low), BOOT + RESET buttons. Default board. **No other parts needed.**
- **Seeed Studio XIAO RP2350** ([product page](https://www.seeedstudio.com/Seeed-XIAO-RP2350-p-5944.html)) -- RP2350A SoC, USB-C, 4 MiB QSPI flash, 520 KiB SRAM, single dual-colour (red/yellow) user LED on GP25 (active-low). Build with `cargo build --release --no-default-features -F mldsa65,board_xiao_rp2350`. The firmware drives **GP23 LOW** on this board to keep the WS2812 NeoPixel power switch off; leaving it as a pull-up input causes the floating WS2812 to draw VBUS-disturbing currents and break USB enumeration intermittently. See [docs/HARDWARE.md](docs/HARDWARE.md) for the Seeed schematic reference.
- **Waveshare RP2350-LCD-1.47-B / -B-M** ([product page](https://www.waveshare.com/rp2350-lcd-1.47.htm)) -- RP2350A SoC, USB-C, **16 MB** QSPI flash, 520 KiB SRAM, 1.47" 172x320 ST7789V2 LCD, micro-SD slot (unused), WS2812 RGB LED chain on GP23. Build with `cargo build --release --no-default-features -F mldsa65,board_waveshare_rp2350_lcd_1_47`. The firmware drives the **LCD as a live status panel** (firmware version, algorithms, PIN state, resident-credential count, last CTAP operation); the WS2812 chain is held in reset (data LOW -- RGB needs a PIO driver, a future task). See the module doc in `crates/firmware/src/board/waveshare_rp2350_lcd_1_47/`.
- **Feitian RP2350** -- RP2350A SoC, USB-A, follows the Raspberry Pi Pico 2 reference design (schematic `PICO2_G9_QE09_V1.0`): 4 MiB QSPI flash assumed, single green user LED on GP25 (active-high -- opposite polarity to the XIAO's GP25). Build with `cargo build --release --no-default-features -F mldsa65,board_feitian_rp2350`. Its one button (BOOTSEL, on the flash chip-select line QSPI_SS) **doubles as the CTAP user-presence button**: held while plugging in it still enters the bootloader for flashing; tapped at runtime it confirms presence, sampled by briefly floating the chip-select pad (`crates/firmware/src/board/bootsel.rs`, BSD-3-Clause from Raspberry Pi pico-examples).
- **Spotpear RP2350-LCD-1.28** -- RP2350A SoC, USB-C, 4 MB QSPI flash, round 1.28" 240x240 GC9A01 IPS LCD, QMI8658 IMU (untouched), battery connector. Build with `cargo build --release --no-default-features -F mldsa65,board_spotpear_rp2350_lcd_1_28`. The firmware drives the **round LCD as a centred status panel**; no discrete user LED. See `crates/firmware/src/board/spotpear_rp2350_lcd_1_28/`.
- **Feitian RP2350 USB-C token (experimental)** -- RP2350A SoC in a **sealed USB-C token**: a capacitive touch pad, a single green LED on GP25 (active-high, as the Feitian RP2350), no button, no display, and **no working power-on BOOTSEL** (holding the pad while plugging in does not enter the ROM bootloader). Build with `cargo build --release --no-default-features -F mldsa65,board_feitian_rp2350_usbc`; the USB product string is `Feitian USB-C PQC`. The touch pad is the CTAP user-presence input, read by the same chip-select sampler as the Feitian RP2350's button (the pad sits on QSPI_SS; validated on one production token on 2026-10-02, see [docs/TESTING.md](docs/TESTING.md#the-first-production-usb-c-token-2026-10-02)). Because the only way back into the bootloader is the firmware's own `CTAPHID_CMD_REBOOT`, that command **never asks for a touch on this board**, and the token is flashed only with `tools/flash-usbc.sh`. **Read [the USB-C token section of docs/FLASHING.md](docs/FLASHING.md#the-feitian-usb-c-token) before touching one**: a wrong image makes the token permanently unflashable.

**Optional: a quantum RNG.** Plug a QRNG breakout into the Tiny 2350's **QW/ST connector -- I2C0, SDA GP12, SCL GP13** (3V3 and GND on the same cable; no PD line, the breakout idles it high itself). That is the default in both ports; the breakout header (A0/A1 = GP26/GP27 = I2C1) works too via `-DPQF_QRNG_I2C/_SDA/_SCL/_PD` in the C port. The Spotpear board's LCD reset is GP12, so it gets no QRNG by default. At boot the firmware probes the bus; a chip that answers and calibrates becomes the first entropy source, and the on-die TRNG covers everything else. The C port's CDC banner names the live source; the Rust port appends ` QRNG` to its USB product string.

A USB-A or USB-C cable to the host machine completes the rig. User presence on the Tiny 2350 is its **BOOT button**, no extra parts needed; a touch module or momentary button on **GP0** (any polarity -- the firmware probes the idle level at boot) works as well.

The firmware uses the on-board LED for status (blue heartbeat when idle, red while signing, green flash during the user-presence-wait window and on `wink`) and BOOT / RESET buttons for BOOTSEL flashing. On the single-LED boards (XIAO, both Feitians) the three logical LED channels OR-merge onto the one physical pin -- you lose the colour cue, but the "device is doing something" signal is preserved. The two LCD boards have no discrete status LED; their panel is the status surface. On the boards with a presence input (Tiny 2350, Feitian RP2350, the USB-C token) the LED blinks fast while the device waits for your touch. See [docs/HARDWARE.md](docs/HARDWARE.md) for full GPIO, USB descriptor, TRNG, and memory map specifics on each board.

---

## Quick start

The from-scratch path -- tools, both firmwares, BOOTSEL, flashing,
verification -- is one page: [**docs/GETTING-STARTED.md**](docs/GETTING-STARTED.md).
The short version, once the tools from that page are installed:

```bash
git clone https://github.com/cryptsoft/Bruce && cd Bruce

./build.sh                    # Rust firmware  -> bruce.uf2   (Tiny 2350, ML-DSA-65)
./build-c.sh                  # C firmware     -> bruce-c.uf2 (same board names; needs pico-sdk)

# hold BOOT, plug the board in, release BOOT -- then:
./flash.sh                    # names the board the image is for, asks, flashes;
                              # or ./flash.sh bruce-c.uf2
                              # a blank board: ./flash.sh --board tiny2350
# (NOT for the Feitian RP2350 USB-C token: it has no BOOT button and no
#  power-on BOOTSEL -- see the USB-C token section of docs/FLASHING.md;
#  flash it only with tools/flash-usbc.sh)

./client.sh probe             # any example: ./client.sh list; the long form is
                              # cargo run -p pqf-ctaphid --example probe --target <host triple>
```

`./build.sh feitian_rp2350`, `./build-c.sh xiao_rp2350` and so on pick
another board; `MLDSA=44|87`, `ED25519=1`, `SINGLE_CORE=1` and
`REBOOT_NO_UP=1` pick variants. The blue LED (Tiny 2350) blinks about
once a second when the token has enumerated, and the `probe` example lists it
and dumps its `getInfo`. [docs/USAGE.md](docs/USAGE.md) covers the
end-user flow from there (setting a PIN, registering with a website,
reset); [docs/BUILD.md](docs/BUILD.md) is the complete build reference
for both ports. The Feitian RP2350 USB-C token is the one exception to
this quick start: `./build.sh feitian_rp2350_usbc` builds for it, but
it has no power-on BOOTSEL, so the BOOTSEL and `flash.sh` steps above
do not apply -- [the USB-C token section of docs/FLASHING.md](docs/FLASHING.md#the-feitian-usb-c-token) is the
procedure.

---

## Architecture at a glance (the Rust firmware)

```
                +----------------------- Core 0 ------------------------+
   USB-C  <---->|  rp235x-hal USB peripheral                            |
                |       |                                               |
                |       v                                               |
                |  FidoHidClass  (raw 64-byte CTAP HID frames)          |
                |       |                                               |
                |       v                                               |
                |  CtapHid       (framing, CMD_INIT / PING / WINK /     |
                |       |         CBOR / CANCEL / KEEPALIVE pump)        |
                |       v                                               |
                |  ctap2::handle_cbor                                   |
                |       |                                               |
                |  +----+--- MakeCredential --+                         |
                |  |  GetAssertion       ...    |                         |
                |  |  GetInfo                 |                         |
                |  |  ClientPIN  (v1 / v2)    |                         |
                |  +--+-----------------------+                         |
                |     v                                                  |
                |  opensk_hybrid_sign -- spawn --------------+          |
                |   (also pumps KEEPALIVE every iteration   |          |
                |    while waiting on core 1)               |          |
                |                                           |          |
                +-------------------------------------------+----------+
                                                            |
              +----------------------- Core 1 ------------- v ---------+
              |  core1_signer::worker                                  |
              |    1. ECDSA-P256 RFC-6979 sign over SHA-256(LABEL||m)  |
              |    2. ML-DSA-44 / 65 / 87  keygen_from_seed            |
              |    3. ML-DSA  sign_mu_deterministic_out                |
              |    4. assemble wire: ecdsa_der || mldsa_raw            |
              |    5. publish DONE in shared SRAM, sev() core 0        |
              +--------------------------------------------------------+
                                ^
                                |  embedded-alloc::LlffHeap (256 KiB)
                                |  shared between cores under a
                                |  critical-section spinlock
                                v
              +--------------------------------------------------------+
              |  Flash store (last 4 KiB sector of QSPI @ 0x103FF000)  |
              |    header: SECTOR_MAGIC + version + PIN state +        |
              |            key_handle_aes_key + key_handle_hmac_key    |
              |    6 x StoredCredential slots (Rust; C holds 7)         |
              +--------------------------------------------------------+
```

The first-core <-> second-core handoff is the load-bearing trick. ML-DSA-65 keygen + signing on the low-memory bouncycastle crate takes ~1.3 s on a Cortex-M33 at 125 MHz; if core 0 were doing that work it couldn't service USB, Chrome's CTAP HID watchdog would drop the transaction, and `authenticatorMakeCredential` would never succeed. Offloading to core 1 + emitting `KEEPALIVE` frames from core 0 makes the slowdown invisible to the host. Synchronisation is via shared SRAM + `AtomicU8` state machine + `wfe`/`sev`. The full contract is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

The C firmware has the same shape. TinyUSB supplies the CTAP HID class in place of `usb-device` (`fido_hid.c`, `usb_descriptors.c`), `ctaphid.c` does the framing, `core1_signer.c` is the second-core signing worker and `core1_mailbox.h` the shared-SRAM mailbox it is driven through, and the crypto is the vendored OpenSSL subset instead of Bouncy Castle. [c/firmware/README.md](c/firmware/README.md#source-layout) maps every file.

---

## Documentation map

[**docs/README.md**](docs/README.md) is the index, grouped by what you
want to do. The short form:

| File                                       | What's in it                                                                                                                |
| ---                                        | ---                                                                                                                         |
| [`docs/GETTING-STARTED.md`](docs/GETTING-STARTED.md) | **Start here.** From an empty machine to a flashed, verified token: tools per OS, both firmwares, BOOTSEL per board, flashing, checks, troubleshooting |
| [`docs/FLASHING.md`](docs/FLASHING.md)     | Per-board detail: buttons and connectors, BOOTSEL recipes, what each board shows after a flash, wipe procedures, the dark-device note -- **and the only procedure for the Feitian RP2350 USB-C token ([its section](docs/FLASHING.md#the-feitian-usb-c-token)); read it before touching one**: the token has no power-on BOOTSEL, so rehearse the exact UF2 on a USB-A board and flash the token only with `tools/flash-usbc.sh` |
| [`docs/BUILD.md`](docs/BUILD.md)           | Build reference for both ports: every cargo feature and every CMake option side by side, the toolchain pin, the vendored crates, AAGUID override, release profile |
| [`docs/USAGE.md`](docs/USAGE.md)           | End-user guide: LED meanings, every `getInfo` field, PIN management, Chrome/Firefox flows, troubleshooting                    |
| [`docs/HARDWARE.md`](docs/HARDWARE.md)     | All six supported boards, GPIO + LED state machine, USB descriptor (incl. randomized serial), TRNG, QRNG, memory map            |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Module map, dual-core sync, heap, flash-schema evolution, why-things-are-the-way-they-are                                   |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md)     | Full CTAP2 + CTAP1 surface, getInfo shape, COSE algorithms, hybrid signature wire format, PIN v1/v2 + permissions, extensions |
| [`docs/HMAC-DOMAINS.md`](docs/HMAC-DOMAINS.md) | The normative HMAC domain-separation labels both ports must match byte for byte                                          |
| [`docs/TESTING.md`](docs/TESTING.md)       | Test procedures, the `bench` walkthrough, and the dated record of every silicon validation run                              |
| [`docs/RISCV.md`](docs/RISCV.md)           | RISC-V (Hazard3) builds of both ports, and the mixed mode -- one Arm core + one RISC-V core on the same chip                |
| [`docs/REBOOT.md`](docs/REBOOT.md)         | Host-driven reboot into BOOTSEL (`CTAPHID_CMD_REBOOT`), the per-board touch policy, the `c/hid/reboot` + Rust reboot CLIs, the `reboot_no_up` build option, the `pqf-*` image markers, and the buttonless-lockout warning |
| [`docs/DFU.md`](docs/DFU.md)               | The signed-image DFU bootloader: staging slot, anti-rollback, launch guard, power-loss journal, per-ISA launch      |
| [`docs/SECUREBOOT.md`](docs/SECUREBOOT.md) | OTP provisioning, the boot-key burn, the irreversible fuses and the order they must be blown in                     |
| [`docs/TRUSTZONE.md`](docs/TRUSTZONE.md)   | The TrustZone-M Secure / Non-secure split: gateway surface, what each milestone proved, known weaknesses            |
| [`docs/GDB_DEBUG.md`](docs/GDB_DEBUG.md)   | Debugging a cased/locked token over USB with no SWD probe -- the on-token GDB stub, and why it must never ship enabled |
| [`docs/NETWORK-GADGET.md`](docs/NETWORK-GADGET.md) | Design note for a USB network gadget mode; bring-up firmware under `c/gadget/`                                   |
| [`docs/OVERVIEW.md`](docs/OVERVIEW.md)     | One-page summary of the device's crypto capabilities                                                               |
| [`docs/notes/`](docs/notes/README.md)      | Point-in-time engineering records: the security audits, a withdrawn finding, a superseded handoff                  |
| [`THIRD_PARTY.md`](THIRD_PARTY.md)         | Licence summary (Apache-2.0), third-party compatibility audit, OpenSK + pico-examples attribution, provenance of the U2F dev attestation cert + key |
| [`SECURITY.md`](SECURITY.md)               | What this release does and does not promise, the public development keys, the known limitations, and how to report a vulnerability privately |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)       | The commit hooks, the ASCII rule, the commit-message style, the checks to run before a pull request                         |
| [`crates/ctaphid-client/README.md`](crates/ctaphid-client/README.md) | The host-side client crate and its examples -- the project's test tools                                   |
| [`c/firmware/README.md`](c/firmware/README.md) | The C firmware: pico-sdk/TinyUSB build, board matrix (`-DPQF_BOARD`) and the C-vs-Rust differences, source map, development notes, host test harness |
| [`c/hid/README.md`](c/hid/README.md)       | The C CTAP-over-HID transport library and the `reboot` / `rng` tools                                                |
| [`tools/README.md`](tools/README.md)       | Every script under `tools/`, what it needs, and which ones erase a board                                            |

For the Rust-level API docs (the `//!` doc-comments on each module), run `cargo doc --no-deps --open`.

---

## Source layout

```
Bruce/                              # Cargo workspace root (virtual workspace, no [package])
|-- Cargo.toml                         #   [workspace] only -- members + shared profile / metadata
|-- rust-toolchain.toml                #   nightly-2025-06-23 pin (whole workspace)
|-- .cargo/config.toml                 #   target = thumbv8m.main-none-eabihf, rustflags
|-- README.md
|-- SECURITY.md                        #   release scope, the public dev keys, private vulnerability reporting
|-- THIRD_PARTY.md                     #   crate dependency audit + U2F dev cert provenance + OpenSK attribution
|-- docs/
|   |-- ARCHITECTURE.md
|   |-- HARDWARE.md
|   |-- BUILD.md
|   |-- PROTOCOL.md
|   |-- USAGE.md
|   +-- TESTING.md
|
|-- crates/                            # Rust workspace members
|   |-- firmware/                      #   Bare-metal RP2350A firmware -- the actual `bruce` binary.
|   |   |-- Cargo.toml                 #     features: mldsa44/65/87 (mutex), board_* (mutex), ed25519 (opt-in)
|   |   |-- build.rs                   #     copies memory.x into OUT_DIR for the linker
|   |   |-- memory.x                   #     4 MiB flash + 512 KiB SRAM linker map
|   |   +-- src/
|   |       |-- main.rs                      # USB poll loop, core-1 spawn, randomized USB serial; board-agnostic (delegates to crate::board)
|   |       |-- board/                       # Per-board GPIO configuration (LED, power-gates, user button, status LCDs)
|   |       |   |-- mod.rs                   #   cfg dispatch + interface contract + add-a-board recipe
|   |       |   |-- tiny2350.rs              #   Pimoroni Tiny 2350 (default)
|   |       |   |-- xiao_rp2350.rs           #   Seeed Studio XIAO RP2350
|   |       |   |-- feitian_rp2350.rs        #   Feitian RP2350 (Pico 2 reference design, USB-A)
|   |       |   |-- feitian_rp2350_usbc.rs   #   Feitian RP2350 USB-C token (sealed, touch pad, no power-on BOOTSEL)
|   |       |   |-- bootsel.rs               #   the QSPI chip-select sampler behind the BOOT button / touch pad
|   |       |   |-- waveshare_rp2350_lcd_1_47/   # Waveshare 1.47" -- ST7789V2 status panel
|   |       |   +-- spotpear_rp2350_lcd_1_28/    # Spotpear round 1.28" -- GC9A01 status panel
|   |       |-- ctap2.rs                     # CTAP2 dispatcher (MakeCred, GetAssert, GetInfo, ClientPIN, Reset, Selection)
|   |       |-- ctaphid.rs                   # CTAP HID framing (INIT / PING / WINK / CBOR / CANCEL / KEEPALIVE / MSG)
|   |       |-- fido_hid.rs                  # usb-device HID class for the FIDO usage page
|   |       |-- core1_signer.rs              # core-1 hybrid signing worker + shared SRAM contract
|   |       |-- credential_id.rs             # 161-byte encrypted credentialID (v1 ES256/hybrid, v2 Ed25519; carries credProtect) + cred_random + largeBlobKey derivations
|   |       |-- client_pin.rs                # PIN v1 + v2 (SharedSecret enum), permissions model, stateful iterators (assertion, CM)
|   |       |-- credential_management.rs     # CTAP cmd 0x0A (Phase 8) -- 7 subcommands + RpEnum / CredEnum iterators
|   |       |-- authenticator_config.rs      # CTAP cmd 0x0D (Phase 9) -- alwaysUv / setMinPinLength / enableEntAttestation
|   |       |-- large_blobs.rs               # CTAP cmd 0x0C (Phase 10) -- global blob array in dedicated flash sector
|   |       |-- u2f.rs                       # CTAP1 (Phase 11b) -- REGISTER / AUTHENTICATE / VERSION + dev batch attestation
|   |       |-- ed25519_alg.rs               # COSE alg -8 (Phase 11c, feature-gated) -- ed25519-dalek wrapper + OKP COSE_Key
|   |       |-- flash_store.rs               # QSPI flash credential index (schema v9) + LargeBlobs sector helpers
|   |       |-- mldsa_alg.rs                 # cfg-aliased ML-DSA-44 / 65 / 87 selection
|   |       |-- trng.rs                      # RP2350 ring-oscillator TRNG driver (impls RngCore + CryptoRng)
|   |       |-- qrng.rs                      # external quantum RNG over I2C: probe, framing, SHA-256 conditioning, bounded bus
|   |       +-- entropy.rs                   # the picker: QRNG first, TRNG completes the rest (what main hands to CTAP)
|   |
|   |-- bc-rust-mini/                  #   Vendored Bouncy Castle Rust crates (ML-DSA, SHA-2/3, HMAC, HKDF,
|   |                                  #   DRBG); MIT, own nested workspace, excluded from this one
|   |-- cbor/                          #   `pqf-cbor` -- RFC 8949 CBOR codec (used by firmware + host client)
|   |-- ctaphid-client/                #   `pqf-ctaphid` -- host-side CTAP 2.1 client library (USB HID + CBOR)
|   +-- pkcs11/                        #   `pqf-pkcs11` -- host PKCS#11 module (cdylib): token as an RNG.
|                                      #   Rust sibling of c/pkcs11; built on pqf-ctaphid + cryptoki-sys
|
+-- c/                                 # C-language siblings (own CMake/Makefiles, not Cargo members)
    |-- cbor/                          #   libpqcbor -- same RFC 8949 subset as `crates/cbor`, in C
    |-- hid/                           #   libpqhid  -- CTAP-over-USB-HID transport (Linux hidraw /
    |                                  #   macOS IOKit / Windows SetupAPI backends)
    |-- pkcs11/                        #   pqf-pkcs11 -- PKCS#11 module exposing the token as an
    |                                  #   RNG (C_GenerateRandom over vendor CTAPHID_CMD_RNG);
    |                                  #   works with pkcs11-tool and the OpenSSL pkcs11 provider
    +-- firmware/                      #   FULL C PORT of the firmware -- pico-sdk + TinyUSB +
                                       #   OpenSSL-vendored crypto (openssl-mini/), CTAP 2.1
                                       #   command-surface parity with crates/firmware, same six
                                       #   boards via -DPQF_BOARD. See c/firmware/README.md.
```

The ML-DSA, SHA-2, SHA-3, HMAC and HKDF primitives come from the [Bouncy Castle Rust port](https://github.com/bcgit/bc-rust) (MIT), vendored under [`crates/bc-rust-mini/`](crates/bc-rust-mini/README.md) as a subset snapshot of its no_std branch (`#![no_std]` support for the crypto crates, not in upstream yet). Nothing has to be cloned beside this repository; `tools/vendor-bc-rust.sh` refreshes the snapshot.

---

## Project info

- **Licence:** **Apache License 2.0** ([`LICENSE`](LICENSE)); [`NOTICE`](NOTICE) carries the attribution notices a redistributor keeps, and every first-party source file has an `SPDX-License-Identifier: Apache-2.0` tag. The BOOTSEL sampler files derived from Raspberry Pi pico-examples stay under their upstream BSD-3-Clause (text in [`LICENSE-BSD-3-CLAUSE-PICO-EXAMPLES`](LICENSE-BSD-3-CLAUSE-PICO-EXAMPLES)), and the OpenSK-derived material stays Apache-2.0 -- see [`THIRD_PARTY.md`](THIRD_PARTY.md#license-summary) for the full audit, including why every third-party component is compatible. Contributions are accepted under the same licence, as section 5 of Apache-2.0 provides; [`CONTRIBUTING.md`](CONTRIBUTING.md) has the hooks, the ASCII rule and the checks to run.
