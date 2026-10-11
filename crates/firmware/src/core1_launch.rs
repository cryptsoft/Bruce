// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Core-1 launch paths that `rp235x_hal::multicore` can't cover:
//!
//! * [`spawn_core1_signer`] (RISC-V firmware builds) -- same-
//!   architecture launch, replacing the HAL's Arm-only `spawn`.
//! * [`spawn_core1_signer_riscv_blob`] (Arm builds with the
//!   `core1_riscv` feature) -- the mixed-architecture launch: flip
//!   core 1 to a Hazard3 via OTP ARCHSEL and run the embedded
//!   riscv32 payload on it.
//!
//! ## Why the HAL spawn can't be used for either
//!
//! `rp235x_hal::multicore` (0.4.0) has two Arm assumptions baked into
//! `spawn`:
//!
//! 1. It reads `ppb.vtor()` for the launch handshake's vector-table
//!    word. The PPB (0xE000_0000) is a Cortex-M33 core-local region --
//!    a Hazard3 load there goes out on the bus fabric and traps.
//! 2. Its `core1_startup` trampoline receives `entry` / `stack_limit`
//!    as arguments 3 and 4 after two dummy `u64`s, relying on the Arm
//!    AAPCS to pass them ON THE STACK (which core 0 pre-loads). The
//!    RISC-V ABI passes all six words in `a0..a5` registers, which the
//!    boot ROM launch protocol does not populate -- the trampoline would
//!    read garbage.
//!
//! And for the mixed mode it obviously has no ARCHSEL/payload notion at
//! all.
//!
//! ## The launch protocol
//!
//! The RP2350 boot ROM parks core 1 in a wait-for-launch loop after
//! reset, listening on the inter-core SIO FIFO for the documented
//! sequence `[0, 0, 1, vector_table, stack_pointer, entry_point]`
//! (datasheet sec. 5.3; each word is echoed back by core 1). On a RISC-V
//! core the `vector_table` word initialises MTVEC -- exactly how
//! pico-sdk's `multicore_launch_core1_raw` uses it. The protocol is
//! identical whichever instruction set core 1 wakes up in: after a PSM
//! reset the core re-enters the (dual-architecture) boot ROM, which
//! samples the OTP ARCHSEL register on the way out of reset -- that
//! sampling is what makes the runtime architecture switch possible.

use crate::hal;

/// PSM-reset core 1 so it re-enters the boot ROM's wait-for-launch
/// loop, then run the documented FIFO handshake. Common tail of both
/// launch paths.
fn psm_reset_and_launch(
    psm: &mut hal::pac::PSM,
    fifo: &mut hal::sio::SioFifo,
    cmd_seq: &[u32; 6],
) -> Result<(), &'static str> {
    psm.frce_off().modify(|_, w| w.proc1().set_bit());
    while !psm.frce_off().read().proc1().bit_is_set() {
        crate::arch::nop();
    }
    psm.frce_off().modify(|_, w| w.proc1().clear_bit());

    let mut seq = 0;
    let mut fails = 0;
    while seq < cmd_seq.len() {
        let cmd = cmd_seq[seq];
        if cmd == 0 {
            // Always drain the read FIFO before sending a 0, and SEV in
            // case core 1 is blocked waiting for FIFO space.
            fifo.drain();
            crate::arch::sev();
        }
        fifo.write_blocking(cmd);
        let response = fifo.read_blocking();
        if response == cmd {
            seq += 1;
        } else {
            seq = 0;
            fails += 1;
            if fails > 16 {
                return Err("core 1 not responding to launch handshake");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Same-architecture RISC-V launch (pure RISC-V firmware builds).
// ---------------------------------------------------------------------

/// Stack size for core 1 in `usize` words -- mirrors
/// `core1_signer::CORE1_STACK_WORDS` (64 KiB), same sizing rationale.
#[cfg(target_arch = "riscv32")]
use crate::core1_signer::CORE1_STACK_WORDS;

/// Dedicated core-1 stack. `align(16)`: RISC-V psABI stack alignment.
#[cfg(target_arch = "riscv32")]
#[repr(C, align(16))]
struct Core1Stack([usize; CORE1_STACK_WORDS]);

/// Lives in `.bss` like the HAL's `multicore::Stack` did on Arm.
#[cfg(target_arch = "riscv32")]
static mut CORE1_STACK_RV: Core1Stack = Core1Stack([0; CORE1_STACK_WORDS]);

// Core 1 entry shim. The boot ROM launch protocol sets PC and SP (and
// MTVEC via the handshake) but nothing else -- in particular `gp` is
// whatever reset left it as. rust-lld applies global-pointer
// relaxation against `__global_pointer$` (defined in rp235x_riscv.x),
// so `gp` must be valid before the first static/global access. Set it
// exactly the way riscv-rt's `_start` does (relaxation disabled around
// the load -- otherwise the assembler would "relax" `la gp, ...` into a
// gp-relative load of gp itself), then tail-jump into Rust.
#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(
    ".section .text._pqf_core1_entry_rv, \"ax\"",
    ".global _pqf_core1_entry_rv",
    ".align 2",
    "_pqf_core1_entry_rv:",
    ".option push",
    ".option norelax",
    "la gp, __global_pointer$",
    ".option pop",
    "j {main}",
    main = sym core1_main_rv,
);

/// Rust side of the core-1 shim: run the signer worker forever.
#[cfg(target_arch = "riscv32")]
extern "C" fn core1_main_rv() -> ! {
    crate::core1_signer::CORE1_SIGNER.worker()
}

/// Reset core 1 and launch the signer worker on it (RISC-V build --
/// both cores Hazard3; the boot ROM already switched ARCHSEL for the
/// whole chip when it booted this RISC-V image).
#[cfg(target_arch = "riscv32")]
pub fn spawn_core1_signer(
    psm: &mut hal::pac::PSM,
    fifo: &mut hal::sio::SioFifo,
) -> Result<(), &'static str> {
    extern "C" {
        // riscv-rt's trap entry (linked via rp235x-hal's riscv-rt dep);
        // becomes core 1's MTVEC through the launch handshake.
        fn _start_trap();
        fn _pqf_core1_entry_rv();
    }

    // Top of the dedicated stack, 16-byte aligned (the array start is
    // align(16) and the length is a multiple of 4 words, so the end is
    // too -- the mask is belt-and-braces).
    let stack_top = (core::ptr::addr_of!(CORE1_STACK_RV) as usize
        + core::mem::size_of::<Core1Stack>())
        & !15usize;

    let cmd_seq: [u32; 6] = [
        0,
        0,
        1,
        _start_trap as usize as u32, // MTVEC (direct mode, 4-byte aligned)
        stack_top as u32,
        _pqf_core1_entry_rv as usize as u32,
    ];
    psm_reset_and_launch(psm, fifo, &cmd_seq)
}

// ---------------------------------------------------------------------
// Mixed-architecture launch: Arm core 0 + RISC-V core 1 (feature
// `core1_riscv`).
// ---------------------------------------------------------------------

/// The riscv32 core-1 payload, compiled from `crates/fw-core1-riscv`
/// by build.rs. The `.core1_blob` section is pinned at
/// `mixed::BLOB_FLASH_ORIGIN` by memory_core1riscv.x, so the bytes
/// execute (XIP) at exactly the addresses the payload was linked for.
#[cfg(all(target_arch = "arm", feature = "core1_riscv"))]
#[link_section = ".core1_blob"]
#[used]
static CORE1_BLOB: [u8; include_bytes!(concat!(env!("OUT_DIR"), "/core1_blob.bin")).len()] =
    *include_bytes!(concat!(env!("OUT_DIR"), "/core1_blob.bin"));

/// Switch core 1 to its Hazard3 (RISC-V) incarnation and launch the
/// embedded signing payload on it, then hand it the mailbox address
/// through the FIFO.
///
/// Sequence (RP2350 datasheet sec. 3.9 "Processor architecture select",
/// sec. 5.3 core-1 launch):
///  1. hold core 1 in reset via PSM FRCE_OFF;
///  2. set OTP.ARCHSEL.CORE1 = RISC-V -- each core samples its ARCHSEL
///     bit as it comes OUT of reset, so the write must precede the
///     release;
///  3. release the reset; core 1 re-enters the boot ROM as a Hazard3
///     and parks in the wait-for-launch loop; verify via
///     OTP.ARCHSEL_STATUS;
///  4. FIFO launch handshake with the payload's fixed MTVEC / SP / PC
///     (`pqf_signer_core::mixed`);
///  5. push `&CORE1_SIGNER` -- the payload's startup reads it as its
///     first action and enters the polling worker.
#[cfg(all(target_arch = "arm", feature = "core1_riscv"))]
pub fn spawn_core1_signer_riscv_blob(
    otp: &mut hal::pac::OTP,
    psm: &mut hal::pac::PSM,
    fifo: &mut hal::sio::SioFifo,
) -> Result<(), &'static str> {
    use pqf_signer_core::mixed::{
        BLOB_ENTRY_OFFSET, BLOB_FLASH_LEN, BLOB_FLASH_ORIGIN, BLOB_STACK_TOP, BLOB_TRAP_OFFSET,
    };

    // Tripwires for a mis-built payload, cheap enough to keep in
    // release: it must fit its flash window, and its first word must
    // be the trap loop's `wfi` (0x10500073) -- anything else means the
    // blob.x layout contract broke.
    if CORE1_BLOB.len() > BLOB_FLASH_LEN as usize {
        return Err("core-1 payload larger than its flash window");
    }
    if CORE1_BLOB[..4] != [0x73, 0x00, 0x50, 0x10] {
        return Err("core-1 payload doesn't start with the trap loop (blob.x layout broke)");
    }

    // 1) Hold core 1 in reset while we change its architecture.
    psm.frce_off().modify(|_, w| w.proc1().set_bit());
    while !psm.frce_off().read().proc1().bit_is_set() {
        crate::arch::nop();
    }

    // 2) ARCHSEL is a live OTP-block register (not a fuse); the core
    //    samples its bit on reset exit.
    otp.archsel().modify(|_, w| w.core1().riscv());

    // 3) Release + verify. If the switch didn't take (e.g. a part with
    //    the RISC-V cores fused off via OTP CRIT), fail loudly rather
    //    than handshake an Arm boot ROM with RISC-V launch words.
    //    (psm_reset_and_launch pulses FRCE_OFF again -- harmless, the
    //    ARCHSEL sampling repeats on every reset exit.)
    psm.frce_off().modify(|_, w| w.proc1().clear_bit());
    let mut spins: u32 = 0;
    while !otp.archsel_status().read().core1().is_riscv() {
        spins += 1;
        if spins > 1_000_000 {
            return Err("ARCHSEL: core 1 refused to switch to RISC-V (RISC-V fused off?)");
        }
        crate::arch::nop();
    }

    // 4) Launch the payload at its fixed addresses.
    let cmd_seq: [u32; 6] = [
        0,
        0,
        1,
        BLOB_FLASH_ORIGIN + BLOB_TRAP_OFFSET, // MTVEC -> payload trap loop
        BLOB_STACK_TOP,
        BLOB_FLASH_ORIGIN + BLOB_ENTRY_OFFSET,
    ];
    psm_reset_and_launch(psm, fifo, &cmd_seq)?;

    // 5) Rendezvous: the payload's first action after runtime init is
    //    one blocking FIFO read -- this word. The handshake left the
    //    FIFO empty, so it can't be misread.
    fifo.write_blocking(&crate::core1_signer::CORE1_SIGNER as *const _ as u32);
    Ok(())
}
