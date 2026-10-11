# RISC-V (Hazard3) support

How to build and run either firmware on the RP2350's RISC-V cores, or on one Arm core and one RISC-V core at once, and what those builds do differently under the hood. It is for someone who already has the Arm build working from [GETTING-STARTED.md](GETTING-STARTED.md) and has the build knobs of [BUILD.md](BUILD.md) to hand; flashing is as in [FLASHING.md](FLASHING.md), with one extra trap described at the end. What has been verified on silicon is in [TESTING.md](TESTING.md).

The RP2350 ships **two Cortex-M33 (Arm) cores AND two Hazard3 (RISC-V RV32IMAC) cores** on the same die. Which pair runs is decided at boot: the boot ROM reads the flashed image's `IMAGE_DEF` metadata block and switches the per-core `ARCHSEL` registers accordingly -- and because `ARCHSEL` has one live bit **per core**, sampled each time that core leaves reset, the two cores can even run *different* instruction sets simultaneously. `bruce` supports all three shapes, in both the Rust firmware and the C port:

| Mode | Core 0 | Core 1 | Rust build | C build |
| --- | --- | --- | --- | --- |
| **Arm** (default) | Cortex-M33 | Cortex-M33 | `cargo build --release` | `-DPQF_PLATFORM=rp2350` (default) |
| **RISC-V** | Hazard3 | Hazard3 | `cargo build --release --target riscv32imac-unknown-none-elf` (alias: `cargo build-riscv`) | `-DPQF_PLATFORM=rp2350-riscv` |
| **Mixed** | Cortex-M33 | Hazard3 | `cargo build --release --features core1_riscv` | `-DPQF_CORE1_RISCV=ON` |
| **Single core** | Cortex-M33 *or* Hazard3 | asleep | `cargo build --release --features single_core` (either target) | `-DPQF_SINGLE_CORE=ON` |

Same boards, same feature axes (ML-DSA level, `ed25519`, `u2f`), same 161-byte credentialID, same flash-store layout -- an Arm image and a RISC-V image flashed onto the same board find the same persisted credentials (schema-compatible builds assumed, as always).

All three shapes are silicon-validated on the Feitian RP2350, in both the Rust firmware and the C port. USB enumeration, `getInfo` (advertising FIDO 2.0 and 2.1), hybrid MakeCredential / GetAssertion with the ML-DSA-65 signing worker on the second core, ClientPIN, resident-credential flash commits, and `authenticatorReset` all pass, including full browser register / login / PIN-set ceremonies. Every configuration signs in about a second (see [Performance](#performance-expectations)).

The Arm build is the production default. The mixed Arm-core-0 + RISC-V-core-1 shape is the most involved of the three -- it runs a cross-ISA signing blob over a shared-SRAM mailbox -- but it is functional. RISC-V builds carry a few implementation requirements the Arm build does not; see [Implementation notes](#implementation-notes-risc-v-and-mixed-mode) below.

## Pure RISC-V build (Rust)

```bash
cargo build --release --target riscv32imac-unknown-none-elf                    # tiny2350 + mldsa65
cargo build --release --target riscv32imac-unknown-none-elf \
    --no-default-features -F mldsa87,board_feitian_rp2350                      # any feature mix works
picotool load -u -v -x -t elf target/riscv32imac-unknown-none-elf/release/bruce
```

`rust-toolchain.toml` pins the `riscv32imac-unknown-none-elf` target alongside the Arm one, so rustup fetches it automatically. Flashing is identical to the Arm flow ([FLASHING.md](FLASHING.md)) -- the boot ROM sees the RISC-V `IMAGE_DEF` and switches both cores over; `picotool info` shows `image type: RISC-V`.

What differs under the hood:

- **Arch shim** (`crates/signer-core/src/arch.rs`, re-exported as `crate::arch`): `nop` / `sev` / `wfe` / interrupt-mask save+restore as `inline(always)` raw asm for both instruction sets. Hazard3 has no SEV/WFE; the RP2350 wires the equivalent `h3.unblock` / `h3.block` hint instructions (`slt x0, x0, x1` / `slt x0, x0, x0`), which is also what pico-sdk's `__sev()` / `__wfe()` compile to on `rp2350-riscv`. Interrupt masking is PRIMASK (`cpsid`/`cpsie`) on Arm, `csrrci`/`csrsi` on `mstatus.MIE` on RISC-V. The shims are raw inline asm on purpose: the flash-blackout code paths (`ramfunc.rs`, `board/bootsel.rs`) must not call out-of-line `.text` while XIP is suspended, on either instruction set.
- **Linker script** (`crates/firmware/rp235x_riscv.x`): the RISC-V build doesn't use cortex-m-rt's `link.x` + `memory.x` split -- a single self-contained script (derived from rp-hal's reference at the `rp235x-hal-0.4.0` tag) lays out riscv-rt's sections, keeps the `IMAGE_DEF` in the first 4 KiB, and carries the same flash-store reserve ASSERT as `memory.x` (the guard that keeps `.text` out of the persisted sectors). `.data.ramfunc` placement (RAM-resident flash routines) works identically -- riscv-rt copies `.data` at startup just like cortex-m-rt.
- **Core-1 launch** (`crates/firmware/src/core1_launch.rs`): `rp235x_hal::multicore::spawn` is Arm-only in practice -- it reads the Arm-core-local PPB for the VTOR launch word (a Hazard3 load there traps) and passes its trampoline arguments on the stack per the Arm AAPCS (the RISC-V ABI would look for them in registers the boot ROM never sets). We run the documented PSM-reset + SIO-FIFO launch handshake ourselves (`[0, 0, 1, mtvec, sp, pc]`; on RISC-V the "vector table" word initialises MTVEC), with a two-instruction asm entry shim that initialises `gp` before the first static access. None of this runs under `--features single_core`: core 1 stays asleep, the signer runs on core 0 and a `TIMER0` alarm interrupt carries the `KEEPALIVE` cadence -- the same handler symbol on both instruction sets, reached through the NVIC on Arm and through the HAL's machine-external dispatch on Hazard3 ([BUILD.md, Axis 6](BUILD.md#axis-6-optional-single-core-single_core)).
- **Codegen**: `.cargo/config.toml` enables `+zba,+zbb,+zbs,+zbkb` -- Hazard3 implements the bit-manipulation extensions, and Zbb rotates matter for Keccak (ML-DSA's SHAKE). No FPU on Hazard3, so the target is soft-float; the crypto stack is integer-only anyway.

## Pure RISC-V build (C port)

The short form is the wrapper:

```bash
RISCV=1 ./build-c.sh tiny2350        # -> bruce-c.uf2, a 'rp2350-riscv' image
```

which needs `riscv32-unknown-elf-gcc` on `PATH` and configures into `c/firmware/build-<board>-riscv/`. The raw CMake form:

```bash
cmake -S c/firmware -B c/firmware/build-riscv \
    -DPQF_BOARD=tiny2350 -DPQF_PLATFORM=rp2350-riscv \
    -DPICO_TOOLCHAIN_PATH=/path/to/riscv-toolchain
cmake --build c/firmware/build-riscv -j
# -> c/firmware/build-riscv/bruce_c.uf2   (picotool family 'rp2350-riscv')
```

(`PQF_RISCV_TOOLCHAIN_BIN` / `PICO_TOOLCHAIN_PATH` must point at a bare-metal riscv32 GCC; there is no default.)

The pure-RISC-V C build needs a few source-level adaptations beyond the build wiring -- all `#if defined(__riscv)`, so the Arm build is unaffected -- covering alignment-safe string routines, interrupt-free USB, a dedicated core-1 stack, and a RISC-V trap handler. See [Implementation notes](#implementation-notes-risc-v-and-mixed-mode).

> **Use `-DPQF_PLATFORM`, not `-DPICO_PLATFORM`.** `c/firmware/CMakeLists.txt`
> does `set(PICO_PLATFORM ${PQF_PLATFORM})`, so a `-DPICO_PLATFORM=rp2350-riscv`
> on the command line is silently overwritten and you get an **Arm** build with
> no warning. It configures, compiles and links; only `readelf -h` shows
> `Machine: ARM`. This cost a full round of "RISC-V" results on 2026-08-19
> that were in fact Arm builds -- the tell was that the binaries were
> byte-for-byte the same size as the Arm ones. Check with:
>
> ```bash
> readelf -h build-riscv/bruce_c.elf | grep Machine   # want: RISC-V
> ```

**Toolchain**: you need a bare-metal RISC-V GCC with rv32 multilibs **and newlib**. The known-good option is Raspberry Pi's own build from [pico-sdk-tools releases](https://github.com/raspberrypi/pico-sdk-tools/releases) (`riscv-toolchain-15-mac.zip` etc. -- `riscv32-unknown-elf-gcc`, one of pico-sdk's default triples, so `-DPICO_TOOLCHAIN_PATH` is all it takes). The Homebrew `riscv64-elf-gcc` does **not** work: it ships without newlib, so pico-sdk's `--specs=nosys.specs` link fails.

## Mixed mode: Arm core 0 + RISC-V core 1 (`core1_riscv`)

Both ports implement mixed mode and are silicon-validated. The RISC-V-specific requirements (alignment, blob heap sizing) are in [Implementation notes](#implementation-notes-risc-v-and-mixed-mode).

```bash
cargo build --release --features core1_riscv        # Arm target (the default) only
```

One build command produces one image that runs **both instruction sets at once**: core 0 stays the Arm firmware (USB, CTAP, storage -- unchanged), while the hybrid ECDSA + ML-DSA signing worker runs on core 1 as a Hazard3. There is no deep architectural reason a security key needs this -- it exists because the silicon can do it, it exercises the cross-architecture mailbox design, and it gives the project a live testbed for heterogeneous-ISA firmware. Pieces:

1. **Shared worker crate** (`crates/signer-core`, `pqf-signer-core`): the signing worker, its `repr(C)` shared-SRAM mailbox, and the arch shims -- compiled into the firmware for Arm *and* cross-compiled to riscv32 for the payload, from the same source. The mailbox protocol uses plain atomic loads/stores only (never read-modify-write), so cross-ISA synchronisation depends on nothing but the RP2350's uncached, unified SRAM -- no Arm exclusive monitor, no RISC-V AMO.
2. **Core-1 payload** (`crates/fw-core1-riscv`, `pqf-core1-riscv`): a standalone riscv32imac binary -- entry/trap asm, `.data`/`.bss` init, a private 32 KiB heap (core 0's allocator is never shared across ISAs), then the worker in *polling* mode (`worker_poll`: the M33<->Hazard3 event-signal routing is not hardware-verified, so the payload never blocks on an event it might miss). The firmware's `build.rs` cross-compiles it automatically (nested cargo + `llvm-objcopy`) and embeds the flat binary -- `-F core1_riscv` stays a one-step build.
3. **Memory carve-up** (`memory_core1riscv.x` replaces `memory.x` for this build; normative constants in `pqf_signer_core::mixed`): flash `0x1018_0000..0x1020_0000` holds the payload (core 1 executes it via XIP -- the window ends at the 2 MiB mark so picotool accepts the image on unprogrammed-FLASH_DEVINFO boards like the Feitian), RAM shrinks to 384 KiB for core 0 with `0x2006_0000..0x2008_0000` (128 KiB) as core 1's private data/heap/stack window. The flash-store sectors are untouched, so mixed<->Arm reflashes keep credentials.
4. **Runtime switch** (`core1_launch::spawn_core1_signer_riscv_blob`): hold core 1 in PSM reset -> set `OTP.ARCHSEL.CORE1 = RISCV` (a live register, sampled on reset exit -- datasheet sec. 3.9) -> release and verify via `ARCHSEL_STATUS` -> boot-ROM FIFO launch handshake with the payload's fixed MTVEC/SP/PC -> push `&CORE1_SIGNER` through the FIFO as the mailbox rendezvous. A part with the RISC-V cores fused off fails loudly at the `ARCHSEL_STATUS` check instead of handshaking garbage.

The flash-park discipline (core 1 spins in a RAM-resident loop while core 0 has the QSPI out of XIP; audit finding M1 in [AUDIT_FINDINGS.md](notes/audit/AUDIT_FINDINGS.md)) holds in mixed mode: the payload's park-spin loop is `.data.ramfunc` inside its own RAM window, so core 1 fetches nothing from XIP while core 0 holds the QSPI in command mode; `ARCHSEL` only matters at reset, so flash ops need no extra ceremony.

**Why not RISC-V core 0 + Arm core 1?** Nothing prevents it in principle (the ARCHSEL mechanism is symmetric), but there's no payoff: the Arm core is the faster of the two for the crypto inner loops, and the USB/CTAP side is timing-insensitive. The implemented direction also keeps the production-validated Arm boot path untouched.

### C mixed mode

Same shape as the Rust mixed mode (one image, one ARCHSEL flip, one embedded riscv32 payload signing over a shared-SRAM mailbox), built independently for the C port:

1. **Blob** (`c/firmware/core1-riscv-blob/`): a standalone riscv32 binary -- `blob_start.S` (entry at flash-origin+8, trap loop at +0), `blob_main.c` (`_sbrk` heap, a `RAND_bytes` that hashes this core's own TRNG block with the 32 bytes of QRNG-first entropy core 0 puts in the mailbox with every request -- the blob cannot reach the I2C bus -- and a RAM-resident polling worker -- never blocks on an event, same reasoning as the Rust payload's `worker_poll`), linked by `blob.ld` (a dedicated SRAM window holding `.data`/`.bss`, the ML-DSA malloc heap, and the stack -- see [Implementation notes](#implementation-notes-risc-v-and-mixed-mode) for sizing). Cross-compiled by `core1-riscv-blob/build_blob.sh` with a separate bare-metal riscv32 GCC (not the Arm cross-compiler pico-sdk configures) and `.incbin`'d into the Arm image by `src/core1_blob.S`.
2. **Mailbox** (`src/core1_mailbox.h`): a `repr`-C-equivalent shared struct -- state flags, the flash-park handshake fields, and (left in place permanently, cheap) a set of bring-up diagnostic fields (`dbg_stage`/`dbg_val`/`dbg_heap_hw`) that a future debugging session can read out over the existing CDC log without re-inventing instrumentation.
3. **Launch + driver** (`src/core1_signer_riscv.c`): mirrors the Rust sequence exactly -- PSM reset, `OTP.ARCHSEL.CORE1 = RISCV`, `ARCHSEL_STATUS` verification, boot-ROM FIFO launch at the blob's fixed MTVEC/SP/PC, mailbox-pointer handoff. Falls back to signing inline on core 0 if the RISC-V core never comes up (a part with Hazard3 fused off), rather than the Rust path's `.expect()`.
4. **Memory carve-up** (`memmap_core1riscv.ld`): flash `0x1018_0000..~0x1020_0000` holds the blob (XIP, ends below the 2 MiB mark for FLASH_DEVINFO-unprogrammed boards); the SRAM is split between core 0 and the blob's private window (sizing under [Implementation notes](#implementation-notes-risc-v-and-mixed-mode)). In shipping builds the blob is copied to SRAM at launch for performance (see Performance).
5. **CMake** (`-DPQF_CORE1_RISCV=ON`, needs `PQF_PLATFORM=rp2350`): cross-compiles the blob as a custom command, `.incbin`s it, and swaps in the SRAM-carving linker script.

All of the above (launch, mailbox handoff, ARCHSEL flip) is silicon-verified working, and so is the signing that rides on it: the C mixed build passes the conformance suite with a verified ML-DSA-65 signature (see [Silicon: the ARCHSEL paths](#silicon-the-archsel-paths-2026-09-02)). An earlier revision of this section recorded the signing as not yet working; that predates the blob-heap sizing described under [Implementation notes](#implementation-notes-risc-v-and-mixed-mode).

## Performance expectations

Every configuration signs a hybrid ML-DSA-65 credential in about a second. Measured on the Feitian RP2350 (N=10, presence auto-confirmed):

| Config | MakeCredential | GetAssertion |
| --- | --- | --- |
| C Arm (`copy_to_ram`, default) | ~1.0-1.1 s | ~0.65 s |
| C pure RISC-V (`copy_to_ram`, default) | ~1.1 s | ~0.65 s |
| C mixed (Arm core 0 + RISC-V blob in SRAM) | ~1.3 s | ~0.87 s |

The dominant cost is executing the ML-DSA code from the right place, not the ISA or the crypto implementation -- the C `openssl-mini` and RISC-V and Arm builds all land within ~0.1 s of each other and of the Rust port. The lever is the RP2350's **16 KiB direct-mapped XIP cache**: ML-DSA-65's hot working set is ~22 KiB, so running the crypto from flash overflows the cache and the core stalls at roughly CPI 200 (a ~15 s sign). Executing the same code from SRAM removes the thrash and it runs at roughly CPI 1.2 (~1 s). Single-ISA builds therefore default to `copy_to_ram` (`c/firmware/CMakeLists.txt`); the mixed build copies its RISC-V blob into SRAM instead (`core1-riscv-blob/blob.ld`).

The vendored `openssl-mini` crypto is used unmodified -- `copy_to_ram` alone reaches ~1 s, so no local optimizations to the vendored sources are carried. The `KEEPALIVE` pump keeps Chrome's watchdog fed during the sign regardless.

**Level 87 is the exception: single-ISA builds trade `copy_to_ram` away for heap.** The ML-DSA-87 hybrid sign peaks at ~216 KiB of heap -- including one ~138 KiB *contiguous* allocation -- which cannot coexist with a ~292 KiB copied-to-RAM image in 520 KiB of SRAM (the sign OOM'd; with `PICO_MALLOC_PANIC` that was a device wedge on Arm and a trapped-core CTAP error on RISC-V). At `PQF_HYBRID_VARIANT=87` a single-ISA build therefore runs from XIP and gives the signing core a dedicated 240 KiB two-ended arena (`src/core1_arena.c`, the mixed blob's proven `blob_alloc` allocator; reset per op, so the big contiguous allocation is fragmentation-proof -- measured high-water 193.6 KiB). All heavy crypto ops (hybrid sign, ML-DSA keygen, P-256 keygen/sign) route through core 1 so KEEPALIVEs flow during the multi-second XIP-speed compute (Arm/87: MakeCredential ~7 s, GetAssertion ~9 s). Arena OOMs and core-0 heap OOMs report over CDC instead of panicking. Levels 44/65 are unaffected (`copy_to_ram`, newlib, ~1 s).

## Implementation notes (RISC-V and mixed mode)

The RISC-V and mixed builds carry a handful of requirements the Arm build does not. These are load-bearing -- the configurations do not work correctly without them.

**Alignment (all RISC-V code).** The Hazard3 cores do not implement misaligned scalar access -- a misaligned load or store traps (`mcause` 4 / 6). The prebuilt newlib in the RISC-V toolchain, however, is built assuming misaligned access is merely slow, so its `memcmp` and `strcmp` issue unchecked word-sized loads. The firmware therefore ships alignment-safe replacements in `c/firmware/src/pqf_align_str.c` (strong symbols that override the newlib copies; RISC-V only) and compiles with `-mstrict-align` on both the firmware target and the mixed-mode blob, so the compiler never emits an unchecked misaligned access either. The other newlib routines (`memcpy`/`memmove`/`memset`/`strlen`) align their operands first and are safe as-is.

**Interrupt-free operation (pure RISC-V).** The pure RISC-V build runs with no enabled interrupts, matching the Rust port: USB is polled via `pqf_usb_task()` (which calls `tud_int_handler(0)`) with the USBCTRL IRQ disabled, and the SDK alarm pool is disabled (`PICO_TIME_DEFAULT_ALARM_POOL_DISABLED=1`). This avoids a race in which an interrupt burst -- pended while interrupts are masked across a flash erase/program window -- is delivered into the boot-ROM flash path. The Arm build is interrupt-driven and unaffected.

**Core-1 stack.** The signing core gets a dedicated 16 KiB stack via `multicore_launch_core1_with_stack`; the pico-sdk default (2 KiB) is too small for the ML-DSA signing call chain.

**RAM-resident idle and flash paths.** Core 1's idle-wait and flash-park routines, and the flash erase/program sequence itself, execute from SRAM rather than XIP flash. This keeps them off the flash bus during the windows when XIP is unavailable -- both the BOOTSEL user-presence sampler (which briefly floats the flash chip-select) and the flash erase/program itself. Flash commits call the boot ROM's flash routines directly (`flash_op_cb` in `flash_store.c`), matching the sequence the Rust port uses.

**Trap handler.** A machine-exception handler (`isr_riscv_machine_exception`) records `mcause`/`mepc` per core and reports it over the CDC serial, so a fault is diagnosable rather than a silent wedge; a trapped signing core fails the sign cleanly instead of hanging the device.

**Mixed-mode blob heap.** The core-1 blob has its own SRAM heap. ML-DSA-65 signing does a single large contiguous allocation (~89 KiB) on top of an already-fragmented heap, for a peak near 170 KiB, so the blob is given a large SRAM window. The SRAM is split between core 0 and the blob in `memmap_core1riscv.ld` / `core1-riscv-blob/blob.ld`, with the window size mirrored in `core1_mailbox.h`'s `PQF_BLOB_RAM_*` constants. The pure RISC-V build does not need this -- there the signing core uses the main firmware heap.

The blob and its mailbox carry CDC-gated diagnostic fields (dormant unless a serial terminal is attached) that report the signing stage and heap high-water mark; see `core1_mailbox.h` and `core1_signer_riscv.c`.

## File map

| File | Role |
| --- | --- |
| `crates/signer-core/` | shared worker + mailbox + arch shims (both ISAs) |
| `crates/fw-core1-riscv/` | mixed-mode core-1 payload (riscv32 only) |
| `crates/firmware/rp235x_riscv.x` | pure-RISC-V linker script |
| `crates/firmware/memory_core1riscv.x` | Arm memory map for the mixed build |
| `crates/firmware/src/core1_launch.rs` | RISC-V + mixed core-1 launchers |
| `crates/firmware/src/arch.rs`, `core1_signer.rs`, `mldsa_alg.rs` | thin re-exports into the firmware's module tree |
| `c/firmware/CMakeLists.txt` (`PQF_PLATFORM`, `PQF_CORE1_RISCV`) | C-port instruction-set + mixed-mode selection |
| `c/firmware/core1-riscv-blob/` | C mixed-mode core-1 payload (riscv32 only) |
| `c/firmware/src/core1_mailbox.h` | C mixed-mode shared mailbox (`PQF_BLOB_RAM_*` sizing + CDC diagnostic fields) |
| `c/firmware/src/core1_blob.S` | embeds the cross-compiled blob into the Arm image |
| `c/firmware/memmap_core1riscv.ld` | Arm memory map for the C mixed build |
| `c/firmware/src/core1_signer_riscv.c` | C mixed-mode core-1 launcher + driver |
| `c/firmware/src/core1_signer.c` | C pure-RISC-V (and Arm) same-arch core-1 worker |

## Silicon: the ARCHSEL paths, 2026-09-02

`core1_launch.rs` (Rust) and `core1_signer_riscv.c` (C) are the only code
in the tree that touches OTP -- the `ARCHSEL` write that flips core 1 to
its Hazard3 incarnation. Both were re-validated on an unfused RP2350
(chipid `0xc792ce67556a32e3`) after the primary test board had its
RISC-V cores fused off permanently by secure boot:

| build | result |
|---|---|
| Rust mixed (`core1_riscv`) | conformance suite, `-52`: 77 passed, 0 failed |
| C mixed (`PQF_CORE1_RISCV=ON`) | conformance suite, `-52`: 77 passed, 0 failed |

Both conformance runs (an external CTAP 2.1 suite, not part of this
repository) verified a real ML-DSA-65 signature, which is the point: the signer
runs on core 1, so a composite that verifies is proof the ARCHSEL write
took, the Hazard3 launched, and the mailbox handshake worked. Mere
enumeration would have proved none of that.

> Note for anyone repeating this: a secure-booted part cannot run these
> builds at all. `CRIT1.SECURE_BOOT_ENABLE` disables the RISC-V cores
> permanently, so mixed and pure-RISC-V configurations need a board that
> has not been secured.

The transition trap bit again, in a new way. Going from a mixed image to
another image, the arch flag belongs on the reboot **after** the load:

```bash
./c/hid/reboot bootsel     # into BOOTSEL
picotool load <image>      # then load
picotool reboot -a -c arm  # and force Arm on the way out
```

Issuing `picotool reboot -a -c arm` *before* the load simply leaves
BOOTSEL and boots the old image, so the load never happens and the next
check reports the previous firmware still running -- which reads like a
flash that silently failed.
