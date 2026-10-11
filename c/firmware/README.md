# Bruce -- C firmware

The C implementation of the `bruce` authenticator: an independent
port of the Rust firmware, built on the Raspberry Pi **pico-sdk** for
the RP2350A. Wire-compatible
with the Rust firmware: same CTAP 2.1 surface, same credentialID
format, same hybrid ECDSA-P256 + ML-DSA signatures -- so a relying
party can't tell which implementation it's talking to.

This is the C port's own map: how to build it, which boards it
supports, where each piece of the source lives, the notes on how it
was built up, and where its crypto comes from. It is for someone working on or
auditing the C code and assumes the tools from
[`docs/GETTING-STARTED.md`](../../docs/GETTING-STARTED.md). Every
CMake option is listed in [`docs/BUILD.md`](../../docs/BUILD.md),
flashing in [`docs/FLASHING.md`](../../docs/FLASHING.md), and use in
[`docs/USAGE.md`](../../docs/USAGE.md).

Contents:

- [Quick start](#quick-start)
- [Source layout](#source-layout)
- [Development notes](#development-notes)
- [Testing without hardware](#testing-without-hardware)
- [Crypto provenance](#crypto-provenance)

## Quick start

Tools (pico-sdk 2.3.1 with TinyUSB, an Arm GNU Toolchain with newlib,
CMake, a matching picotool) and the from-scratch walkthrough are in
[`docs/GETTING-STARTED.md`](../../docs/GETTING-STARTED.md). From the
repository root:

```sh
./build-c.sh waveshare_rp2350_lcd_1_47      # any board from the table below
./flash.sh bruce-c.uf2                   # board in BOOTSEL
```

(Not for `feitian_rp2350_usbc`: that sealed token has no power-on
BOOTSEL and is flashed only with `tools/flash-usbc.sh`, per
[the USB-C token section of `docs/FLASHING.md`](../../docs/FLASHING.md#the-feitian-usb-c-token).)

The raw form the wrapper runs:

```sh
export PICO_SDK_PATH=/path/to/pico-sdk          # once per shell
cmake -S c/firmware -B c/firmware/build \
      -DPQF_BOARD=waveshare_rp2350_lcd_1_47     # see the board table
cmake --build c/firmware/build -j
# -> c/firmware/build/bruce_c.uf2
picotool load -x c/firmware/build/bruce_c.uf2   # device in BOOTSEL (hold BOOT, tap RESET)
```

### Boards

One `-DPQF_BOARD=<name>` selects both the pico-sdk board header and
the firmware's own pin profile in `src/board.c` (status LED + quirk
pins), mirroring the Rust firmware's `board_*` cargo features:

| `PQF_BOARD` | pico-sdk header | LED / quirks |
|---|---|---|
| `tiny2350` | `pimoroni_tiny2350` | RGB GP18/19/20 (active-low); wink drives the green leg |
| `xiao_rp2350` | `seeed_xiao_rp2350` | LED GP25; GP23 WS2812 power gate held LOW before USB |
| `feitian_rp2350` | `pico2` | LED GP25 **active-HIGH**; BOOTSEL = real user-presence button (`src/bootsel.c`, sampled via QSPI chip-select) |
| `feitian_rp2350_usbc` | `pico2` | Sealed USB-C token, as `feitian_rp2350`: LED GP25 **active-HIGH**; capacitive touch pad = real user-presence input through the same `src/bootsel.c` sampler (confirmed on one production token, 2026-10-02); **no power-on BOOTSEL**, so `CMD_REBOOT` is never gated on a touch; 2 MiB flash declared. Flash only per [the USB-C token section of `docs/FLASHING.md`](../../docs/FLASHING.md#the-feitian-usb-c-token) |
| `waveshare_rp2350_lcd_1_47` *(default)* | `pico2` | no LED; GP23 WS2812 data held LOW |
| `spotpear_rp2350_lcd_1_28` | `pico2` | no LED |

On `tiny2350`, `feitian_rp2350` and `feitian_rp2350_usbc` the CTAP
`WaitForUp` gate is real: MakeCredential and the initial GetAssertion
block until you press the BOOT button or touch the pad (fresh press,
20 ms debounce, 10 s timeout -> `0x27`), pumping `KEEPALIVE(UPNEEDED)`
so the browser shows "touch your key". On the other boards (and in the
host tests, where no hook is installed) presence auto-confirms.
`CTAPHID_CMD_REBOOT` follows a separate per-board policy
(`PQF_REBOOT_NEEDS_UP` in `src/board.h`): it waits for a press only
where the board has both a button (`PQF_BOARD_HAS_USER_BUTTON`) and a
power-on BOOTSEL (`PQF_BOARD_HAS_POWER_ON_BOOTSEL`) and the build is not
`-DPQF_REBOOT_NO_UP=ON` -- `tiny2350` and `feitian_rp2350` -- and
never on `feitian_rp2350_usbc`, whose only way back into the bootloader
it is ([`docs/REBOOT.md`](../../docs/REBOOT.md#user-presence)). The
configure log prints the resolved policy, and the image records it with
the board id as the picotool features `pqf-board=`, `pqf-reboot=` and
`pqf-fido-up=` (`picotool info -a bruce_c.uf2`). The status LED
also carries a ~500 ms idle heartbeat on all boards that have one, and
the USB serial number is randomized per boot (macOS HID-cache
workaround, mirroring the Rust port).

CMake's default is the Waveshare module -- the board this port was
first flashed and verified on (the Rust firmware defaults to the Tiny
2350, and so does the `./build-c.sh` wrapper, so the two scripts agree;
pass `-DPQF_BOARD=tiny2350` in the raw form to match); the
`feitian_rp2350` build has also been verified end-to-end on hardware
(the USB-A board; nothing has been run on a USB-C token yet),
including its button-gated register/login, and the Tiny 2350 build's
BOOT-button presence gate was checked on silicon on 2026-09-16 (the
dated note in [`docs/TESTING.md`](../../docs/TESTING.md)). The two LCD
modules and both Feitians have no dedicated pico-sdk board header so they ride the
`pico2` reference profile -- same RP2350A and, importantly, the same
flash-store offsets as every UF2 from before multi-board support
(phase C-11 in the history below), so reflashing never strands
persisted credentials. The LCD panels themselves are not driven by the
C port (the Rust profiles ship an ST7789 / GC9A01 stats screen; that
stays Rust-only for now).

## Source layout

```
c/firmware/
|-- CMakeLists.txt          the build (heavily commented; -DPQF_BOARD selects the board)
|-- pico_sdk_import.cmake    standard SDK locator (verbatim from pico-sdk)
|-- tusb_config.h            TinyUSB: CDC (debug) + FIDO HID composite
|-- src/
|   |-- main.c                    USB poll loop + CDC liveness banner + wink LED pulser
|   |-- board.c / board.h         per-board pin profiles (LED + quirk pins) <- -DPQF_BOARD
|   |-- usb_descriptors.c         composite device descriptors + FIDO HID report
|   |-- fido_hid.c                TinyUSB HID glue -> CTAPHID + long-op tick
|   |-- ctaphid.c                 CTAP-HID transport (INIT/PING/CBOR/WINK/CANCEL,
|   |                              multi-frame, KEEPALIVE pump; CMD_MSG refused + NMSG)
|   |-- ctap2.c                   CTAP2 dispatch: getInfo / MakeCred / GetAssert /
|   |                              GetNextAssertion / Reset / Selection; alg picker;
|   |                              authData + COSE_Key; extension outputs
|   |-- cbor_encode.c             RFC 8949 canonical encoder (+ cbor_w_raw splice)
|   |-- cbor_read.h               decoder helpers + raw-slice locator for
|   |                              pinUvAuthParam sub-command messages
|   |-- credential.c              stateless 161-byte encrypted credentialID
|   |                              (ES256 + hybrid), key recover + sign,
|   |                              cred_random + largeBlobKey derivations
|   |-- client_pin.c              authenticatorClientPIN + PIN/UV-token model
|   |-- pin_protocol.c            PIN/UV-auth protocols v1 + v2
|   |-- authenticator_config.c    authenticatorConfig (0x0D): enableEnt /
|   |                              toggleAlwaysUv / setMinPINLength
|   |-- credential_management.c   authenticatorCredentialManagement (0x0A),
|   |                              7 subcommands + stateful enumeration
|   |-- resident_store.c          discoverable-credential index (7 slots,
|   |                              own flash sector; host build = RAM)
|   |-- large_blobs.c             authenticatorLargeBlobs (0x0C), own sector,
|   |                              SHA-256 trailer validation
|   |-- hybrid.c                  ECDSA-P256 + ML-DSA hybrid signer (+ LABEL)
|   |-- core1_signer.c            core-1 offload for hybrid signs (FIFO +
|   |                              spin-with-tick -> CTAPHID KEEPALIVE)
|   |-- core0_signer.c            -DPQF_SINGLE_CORE=ON: the same API inline
|   |                              on core 0; pqf_yield() (called by the
|   |                              vendored ML-DSA/EC loops) pumps USB +
|   |                              KEEPALIVE every 25 ms from inside the math
|   |-- riscv_trap.c              Hazard3 trap forensics for both cores
|   |                              (empty on Arm)
|   |-- flash_store.c             device master keys + sign counter + PIN +
|   |                              config policy in the last QSPI sector
|   |-- pqf_rand.c                RAND_* -- the entropy picker: QRNG first when
|   |                              present, pico_rand/TRNG completes the rest
|   |-- pqf_qrng.c                external quantum RNG: probe, framing, health,
|   |                              SHA-256 conditioning (64 raw -> 32), fallback
|   |                              policy (ISA-neutral, host-tested)
|   |-- pqf_qrng_hw.c             its bus: pico-sdk hardware_i2c + GPIO, the
|   |                              QW/ST i2c0 GP12/GP13 by default, timeouts +
|   |                              stuck-bus
|   |                              recovery (-DPQF_QRNG=OFF compiles both out)
|   +-- gdbstub.c                 DEBUG ONLY (-DPQF_GDB_STUB): GDB remote-
|                                  serial-protocol stub on a 2nd CDC iface --
|                                  monitor-mode debug (DebugMonitor + FPB), so
|                                  a cased/locked token is debuggable over the
|                                  USB cable with no SWD probe. Never ship;
|                                  see ../../docs/GDB_DEBUG.md
|-- openssl-mini/             vendored OpenSSL crypto (see its own README)
|   |-- src/{bn,ec,ml_dsa}/   BN, P-256 EC + ECDSA/ECDH, ML-DSA-44/65/87
|   |-- src/{sha256,sha512,sha3,keccak1600,aes_core,packet,buffer}.c
|   |-- src/pqf_*.c            pqf_ wrappers (sha/hmac/aes/evp/hkdf/p256/mldsa)
|   |-- include/               public pqf_crypto.h + the openssl/* shims
|   +-- test/                  host KAT tests (SHA/HMAC/AES/BN/P-256/ML-DSA)
+-- test/                     host protocol tests -- 22 programs: test_ctap2,
                              test_pin, test_hybrid, test_hybrid_msgsize,
                              test_extensions, test_config, test_resident,
                              test_credmgmt, test_largeblobs, test_domain,
                              test_blob_alloc, test_gdbstub, test_qrng,
                              test_yield, ...
                              (make test; RAM-backed stubs for TRNG / flash /
                              core-1, a scripted I2C bus for the QRNG driver,
                              and simulated debug MMIO + pty transport for
                              the GDB stub)
```

Flash layout (all boards build against a 4 MB window, so the offsets
are identical everywhere -- including the 16 MB Waveshare):

```
last sector        device master keys + sign counter + PIN + config (flash_store.c)
last sector - 1    resident-credential index, 7 slots               (resident_store.c)
last sector - 2    large-blob array, <= 2048 B + SHA-256 trailer     (large_blobs.c)
```

## Development notes

### Why CMake and not a Makefile

> **Why CMake and not a Makefile?** pico-sdk is CMake-native. The
> RP2350 boot path (the IMAGE_DEF metadata block in the first 4 KiB
> of flash, the `pico_crt0` startup, the `memmap_default.ld` linker
> script, the boot-stage glue) and the TinyUSB integration are all
> wired through `pico_sdk_init()` + the SDK's CMake helpers. A
> standalone Makefile would have to replicate ~12 SDK object files,
> the double-wrapped soft-float `--wrap` link flags, and the
> linker-script selection by hand, and would break every SDK update.
> The CMake build is ~140 lines and self-documenting; that's the
> right tool here. (The *host-side* unit tests under `test/` and
> `openssl-mini/test/` do use plain Makefiles -- they have no SDK or
> boot-path dependency.)

### Build history, by phase

This section is history, kept because the phase codes appear in
commit messages, test names and comments. The firmware was built in
flashable milestones (each ended with a UF2 that worked at that
phase's level); the current tree contains all of them. See the git log
`phase C-N` commits.

| Phase | What | Verify |
|---|---|---|
| C-1 | pico-sdk skeleton + USB CDC | banner on `/dev/cu.usbmodem*` |
| C-2 | TinyUSB FIDO HID + CTAPHID INIT | device enumerates and INITs |
| C-3 | CTAP2 dispatch + getInfo | `getInfo` round trip |
| C-4 | crypto primitives (SHA/HMAC/AES/P-256) | `openssl-mini/test` |
| C-5 | MakeCredential + GetAssertion (ES256) | Chrome register/login |
| C-6 | persistent flash store | survives power cycle |
| C-7 | ClientPIN v1+v2 + permissions | set a PIN, then PIN-gated ops |
| C-8 | ML-DSA + hybrid signing | hybrid creds in Chrome |
| C-9 | extensions: hmac-secret + credProtect | Bitwarden / age |
| C-10a | authenticatorConfig + Selection + Reset + minPinLength ext | `changePIN`, alwaysUv |
| C-10b | U2F / CTAP1 -- parity already met (Rust base refuses CMD_MSG; advertises NMSG) | n/a (disabled by design) |
| C-10r-1 | resident-credential flash store + MakeCred rk + GetAssert discovery (rk=true) | discoverable login |
| C-10r-2 | GetNextAssertion (0x08) + numberOfCredentials | multi-cred RP |
| C-10r-3 | CredentialManagement (0x0A) -- 7 subcommands | enumerate + delete |
| C-10r-4 | credBlob extension | blob round-trip |
| C-10r-5 | LargeBlobs (0x0C) + largeBlobKey extension | blob get/set |
| C-11 | multi-board | flashes on all supported boards |
| C-12 | Feitian RP2350 + real user presence (BOOTSEL via QSPI chip-select, `src/bootsel.c`) + idle LED heartbeat + per-boot random USB serial | register/login gated on a physical tap |

After C-10r-5 the C port reaches **full CTAP 2.1 command-surface parity**
with the Rust firmware: getInfo advertises `rk`, `credMgmt`,
`authnrCfg`, `largeBlobs`, `alwaysUv`, `ep`, the `credBlob` /
`credProtect` / `hmac-secret` / `minPinLength` extensions, and
`pinUvAuthProtocols` [1,2]; every dispatched command (0x01,0x02,0x04,
0x06,0x07,0x08,0x0a,0x0b,0x0c,0x0d) is implemented. Ed25519 (COSE -8) is
feature-gated OFF in the Rust default build, so it's not part of
default-build parity.

The C port mirrors the **Bruce Rust firmware in this repo** (not an
external spec or library) as its parity base: where the Rust firmware's
wire format differs from a literal reading of CTAP 2.1 (e.g. the
authenticatorConfig / credentialManagement `pinUvAuthParam` lives at key
0x03 and `pinUvAuthProtocol` at 0x04), the C port matches the Rust
firmware so a host driving either implementation sees identical bytes.

## Testing without hardware

The protocol layer is host-testable -- the same `ctap2.c` that runs on
the device is driven by host harnesses through platform seams (RAND ->
arc4random, flash -> RAM):

```sh
( cd c/firmware/openssl-mini/test && make test )   # crypto KATs
( cd c/firmware/test && make test )                # CTAP2 / PIN / hybrid (the USB descriptor tests need PICO_SDK_PATH)
tools/host-tests.sh c                              # both, plus the bootloader suite
```

The GDB stub is host-testable the same way: `-DPQF_GDB_HOST`
simulates the ARMv8-M debug MMIO, the target memory and the CDC
transport, so `test_gdbstub` drives the real `src/gdbstub.c` with no
board -- and `make gdbstub-live` serves it on a pty for a real
`arm-none-eabi-gdb` to attach to. See
[`../../docs/GDB_DEBUG.md`](../../docs/GDB_DEBUG.md).

## Crypto provenance

All cryptography is vendored from **OpenSSL 3.5** (Apache-2.0) under
`openssl-mini/` -- classical primitives, NIST P-256, and ML-DSA
(FIPS 204). See [`openssl-mini/README.md`](openssl-mini/README.md) for
the file-by-file vendored-vs-shim breakdown and the licence. The
32-byte hybrid domain-separation label in `src/hybrid.c` is from the
OpenSK PQC fork (Apache-2.0, attributed in the source and in
`LICENSE-APACHE-OPENSK` at the repo root).

`SPDX-License-Identifier: Apache-2.0` (project-original code);
vendored crypto retains its Apache-2.0 licence.
