// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Architecture shim -- the handful of CPU primitives this firmware
//! needs, as raw inline `asm!` for both RP2350 instruction sets.
//!
//! The RP2350 has two Cortex-M33 (Arm) AND two Hazard3 (RISC-V) cores;
//! which pair runs is selected at boot (per core, via the OTP ARCHSEL
//! register). This firmware builds for either instruction set:
//!
//!   * `thumbv8m.main-none-eabihf` -- Arm Cortex-M33 (the default)
//!   * `riscv32imac-unknown-none-elf` -- Hazard3 RISC-V
//!
//! ## Why not `cortex_m::asm` / `rp235x_hal::arch`?
//!
//! Two reasons:
//!
//! 1. Portability: `cortex_m::*` obviously doesn't exist on RISC-V.
//!    `rp235x_hal::arch` does abstract most of this, but...
//! 2. RAM-residency: several callers (`ramfunc.rs`, `board/bootsel.rs`)
//!    execute while the XIP flash window is unreadable. They must not
//!    call ANY out-of-line function that could live in `.text` (flash).
//!    `cortex_m::asm::*` and some `rp235x_hal::arch` helpers compile to
//!    out-of-line `.text` functions; everything in this module is
//!    `#[inline(always)]` raw `asm!`, so it is emitted in place inside
//!    whatever (RAM-resident) function calls it.
//!
//! ## The Hazard3 event pair
//!
//! Arm's SEV/WFE inter-core event signalling has a Hazard3 counterpart:
//! the custom `h3.unblock` / `h3.block` hint instructions, encoded as
//! `slt x0, x0, x1` and `slt x0, x0, x0` (writes to x0 are no-ops, so
//! these are architectural hints -- exactly how the RP2350 datasheet and
//! pico-sdk's `__sev()`/`__wfe()` implement them). `h3.unblock` on one
//! core releases the other core's `h3.block`, matching SEV/WFE pairing
//! (including the "event latches if it arrives before the wait" edge).
//!
//! ## Interrupt mask save/restore
//!
//! Arm masks with PRIMASK (`cpsid i` / `cpsie i`); RISC-V clears the
//! MIE bit (bit 3) of `mstatus` (`csrrci` is the atomic read-and-clear).
//! [`irq_save_disable`] returns an opaque per-arch word that only
//! [`irq_restore`] interprets -- call sites stay identical on both
//! architectures.

#![allow(dead_code)]

/// One `nop`, emitted in place -- never a call into `.text` (XIP).
/// The mnemonic is valid on both Arm and RISC-V.
#[inline(always)]
pub fn nop() {
    // SAFETY: `nop` has no operands and no memory/flag effects.
    #[cfg(any(target_arch = "arm", target_arch = "riscv32"))]
    unsafe {
        core::arch::asm!("nop", options(nomem, nostack, preserves_flags));
    }
}

/// Send event: wake the other core out of [`wfe`]. Emitted in place.
#[inline(always)]
pub fn sev() {
    #[cfg(target_arch = "arm")]
    // SAFETY: `sev` is a hint instruction with no operands.
    unsafe {
        core::arch::asm!("sev", options(nomem, nostack, preserves_flags));
    }
    #[cfg(target_arch = "riscv32")]
    // SAFETY: `slt x0, x0, x1` is the `h3.unblock` hint -- rd is the
    // zero register, so architecturally a no-op apart from the
    // cross-core unblock side channel.
    unsafe {
        core::arch::asm!("slt x0, x0, x1", options(nomem, nostack, preserves_flags));
    }
}

/// Wait for event: park this core until the other core issues [`sev`]
/// (or any other event source fires). Emitted in place.
#[inline(always)]
pub fn wfe() {
    #[cfg(target_arch = "arm")]
    // SAFETY: `wfe` is a hint instruction with no operands.
    unsafe {
        core::arch::asm!("wfe", options(nomem, nostack, preserves_flags));
    }
    #[cfg(target_arch = "riscv32")]
    // SAFETY: `slt x0, x0, x0` is the `h3.block` hint -- rd is the zero
    // register; the core stalls until unblocked, with no other effects.
    unsafe {
        core::arch::asm!("slt x0, x0, x0", options(nomem, nostack, preserves_flags));
    }
}

/// Atomically save the interrupt-enable state and mask interrupts on
/// this core. Returns an opaque word for [`irq_restore`]. Emitted in
/// place -- safe inside RAM-resident flash-blackout windows.
#[inline(always)]
pub fn irq_save_disable() -> u32 {
    let saved: u32;
    #[cfg(target_arch = "arm")]
    // SAFETY: `mrs`/`cpsid` read PRIMASK and mask interrupts; no memory
    // effects we need the compiler to order beyond the fences the
    // callers' atomics already provide.
    unsafe {
        core::arch::asm!(
            "mrs {0}, PRIMASK",
            "cpsid i",
            out(reg) saved,
            options(nomem, nostack, preserves_flags),
        );
    }
    #[cfg(target_arch = "riscv32")]
    // SAFETY: `csrrci` atomically reads `mstatus` and clears MIE
    // (bit 3) in one instruction -- the RISC-V analogue of
    // `mrs`+`cpsid`.
    unsafe {
        core::arch::asm!(
            "csrrci {0}, mstatus, 0x8",
            out(reg) saved,
            options(nomem, nostack, preserves_flags),
        );
    }
    // Neither RP2350 instruction set: a host build, which exists so the
    // rest of this crate can be unit-tested off-target. There is nothing
    // to mask, and the zero travels straight back into `irq_restore`,
    // whose arms are equally absent -- so the pair is a no-op rather
    // than a lie about having masked anything.
    #[cfg(not(any(target_arch = "arm", target_arch = "riscv32")))]
    {
        saved = 0;
    }
    saved
}

/// Restore the interrupt-enable state saved by [`irq_save_disable`].
/// Interrupts are re-enabled only if they were enabled at save time.
/// Emitted in place.
#[inline(always)]
pub fn irq_restore(saved: u32) {
    #[cfg(target_arch = "arm")]
    if saved & 1 == 0 {
        // PRIMASK bit 0 clear = interrupts were enabled before.
        // SAFETY: restoring the prior interrupt-enable state.
        unsafe {
            core::arch::asm!("cpsie i", options(nomem, nostack, preserves_flags));
        }
    }
    #[cfg(target_arch = "riscv32")]
    if saved & 0x8 != 0 {
        // mstatus.MIE was set = interrupts were enabled before.
        // SAFETY: restoring the prior interrupt-enable state.
        unsafe {
            core::arch::asm!(
                "csrsi mstatus, 0x8",
                options(nomem, nostack, preserves_flags)
            );
        }
    }
    // Host build: nothing was masked, so nothing is restored. See the
    // matching arm in `irq_save_disable`.
    #[cfg(not(any(target_arch = "arm", target_arch = "riscv32")))]
    let _ = saved;
}
