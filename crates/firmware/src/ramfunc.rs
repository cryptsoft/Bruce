// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! RAM-resident flash-operation core and the multicore park handshake
//! it relies on (M1).
//!
//! ## Why this has to run from RAM
//!
//! Per the RP2350 datasheet, a flash erase/program takes the QSPI
//! device out of XIP (execute-in-place) mode and drives it in serial
//! command mode. While XIP is suspended the flash window (0x1000_0000..)
//! is NOT readable: ANY instruction fetch or data load from it -- on
//! EITHER core -- hangs or bus-faults.
//!
//! The firmware normally runs `.text` from XIP. So the code that
//! performs the flash sequence, and the code core 1 spins in while it
//! waits, must both live in RAM. The standard bare-metal idiom is to
//! put the function in a `.data.*` sub-section: the runtime's linker
//! script (cortex-m-rt's `link.x` on Arm, our `rp235x_riscv.x` on
//! RISC-V) globs `*(.data .data.*)` into the `RAM` region and the
//! startup code copies it there from its flash load address (the
//! `__sdata`/`__edata`/`__sidata` mechanism). A function so placed
//! therefore has a RAM (0x2000_xxxx) virtual address and is fetched
//! from RAM at run time.
//!
//! NOTE: `#[link_section = ".data"]` on a *function* item is the right
//! attribute here precisely because it lands the symbol in the
//! relocated-to-RAM `.data` image. (An earlier revision of the flash
//! module claimed LLVM places `static`-marked code in RAM "by default";
//! that was incorrect -- only an explicit `.data.*` placement that the
//! linker copies to RAM achieves it, which is what this module does.)
//!
//! ## Self-containment requirement
//!
//! A RAM function must not, while XIP is suspended, call or fetch
//! anything that lives in flash. This is subtle: the `cortex_m::asm` /
//! `rp235x_hal::arch` helpers (`nop`, `sev`, interrupt masking) can
//! compile to OUT-OF-LINE functions that the linker places in `.text`
//! (XIP) -- a branch-and-link to one of them from a RAM spin loop while
//! XIP is suspended would fault the very core we're trying to protect.
//! So this module uses the raw `core::arch::asm!` shims from
//! `crate::arch` (all `#[inline(always)]`, both instruction sets) for
//! every primitive in the hot path
//! (the only thing that remains a call is the boot-ROM `rom_data::*`
//! flash routine reached via a function pointer in the mask ROM at
//! 0x0000_xxxx -- never via XIP). [`flash_op_locked`]:
//!   * takes the flash sequence as a `FnMut` the caller supplies -- the
//!     two call sites in `flash_store` pass closures whose only calls
//!     are to the boot-ROM `rom_data::flash_*` routines, which inline
//!     into this RAM frame as a register-loaded `blx` to ROM;
//!   * does the park handshake, interrupt mask/restore, and spins with
//!     inline `asm!` only -- no out-of-line `.text` calls in the window
//!     where XIP is suspended;
//!   * is `#[inline(never)]` so it is emitted as exactly one symbol we
//!     can confirm landed in RAM with `objdump -t`.
//!
//! ## Park handshake
//!
//! Core 0 (this code):
//!   1. set `PARK_REQUEST`, `sev()` to wake core 1 out of any `wfe`;
//!   2. spin until `PARK_ACK` is observed (core 1 has reached its
//!      RAM-resident park loop and will not fetch XIP);
//!   3. disable interrupts, run the flash sequence, re-enable;
//!   4. clear `PARK_REQUEST`, `sev()` to release core 1.
//!
//! Core 1's worker idle loop (in `core1_signer`) observes
//! `PARK_REQUEST`, sets `PARK_ACK`, and spins in its OWN RAM-resident
//! loop (`Core1Signer::park_spin`) until `PARK_REQUEST` clears. Flash writes
//! only ever happen while core 1 is IDLE (the signer reserves itself
//! before signing), so the worker is always in its idle loop, able to
//! observe the request.
//!
//! ## Startup ordering and liveness (reasoned, not hardware-verified)
//!
//! Core 1 is spawned in `main` BEFORE `CredStore::load` runs, and the
//! worker's first action is its idle loop, so the first flash op (the
//! first-boot key-sector write) always finds core 1 able to ack. The
//! handshake's `flash_op_locked` step 2 waits for the ack BEFORE
//! suspending XIP, so XIP is never suspended while core 1 could still
//! be fetching its (XIP-resident) idle loop.
//!
//! KNOWN LIMITATION (shared with audit item M11, out of scope here): if
//! core 1 has died (a `panic_halt` halt, or an OOM abort in the ML-DSA
//! signer), it can no longer ack a park, so `flash_op_locked` would
//! spin forever. That is a pre-existing core-1-liveness hazard; this
//! park handshake does not introduce the death, only an additional
//! place it would manifest. A bounded ack timeout would need a timer
//! handle plumbed into the flash path and is left for the M11 work.
//!
//! HARDWARE-UNVERIFIED: the bus-fault-on-XIP-during-command-mode
//! behaviour, and that the boot-ROM `rom_data` routines remain callable
//! throughout, are reasoned from the RP2350 datasheet. The objdump
//! evidence confirms the symbols are RAM-resident and contain no
//! out-of-line `.text` calls in the locked window, but the actual
//! dual-core fault avoidance can only be confirmed on silicon.

#[cfg(not(feature = "single_core"))]
use core::sync::atomic::Ordering;

use rp235x_hal::pac;

use crate::arch::{irq_restore, irq_save_disable};
#[cfg(not(feature = "single_core"))]
use crate::arch::{nop as ram_nop, sev as ram_sev};
#[cfg(not(feature = "single_core"))]
use crate::core1_signer::CORE1_SIGNER;

// NOTE: core 1's counterpart of this handshake -- the RAM-resident
// park spin loop -- lives in `pqf_signer_core::signer::Core1Signer::
// park_spin` now, so the mixed-architecture build's RISC-V core-1
// blob carries its own copy in its own RAM window. This module keeps
// the core-0 side only.

/// Run `op` (a flash erase/program sequence built from boot-ROM calls)
/// with core 1 parked in RAM and interrupts disabled on this core.
///
/// # Safety
///
/// `op` MUST NOT touch the XIP flash window (read code or data from
/// 0x1000_0000..) while it runs -- it may only call the boot-ROM
/// `rom_data::flash_*` routines and operate on RAM. Must be called from
/// core 0, from a non-interrupt context, and only while core 1 is in
/// its idle worker loop (true whenever a flash write is issued, since
/// the signer reserves itself before signing).
#[inline(never)]
// Gated the same way `pqf_signer_core::signer`'s RAM-resident functions
// are: identical on both board targets, and omitted off-target so the
// module can be built and tested on a host. `.data.ramfunc` is not a
// section name a host linker accepts.
#[cfg_attr(
    any(target_arch = "arm", target_arch = "riscv32"),
    link_section = ".data.ramfunc"
)]
pub unsafe fn flash_op_locked<F: FnMut()>(mut op: F) {
    // 1) Request the park and wake core 1 if it's in `wfe`.
    //    Single-core builds have nobody to park: core 1 never started,
    //    so an ack would never come and this would be the boot deadlock
    //    main.rs warns about. Skip straight to the flash sequence.
    #[cfg(not(feature = "single_core"))]
    {
        CORE1_SIGNER.park_request.store(true, Ordering::Release);
        ram_sev();
        // 2) Wait until core 1 acknowledges it has reached its RAM spin
        //    loop. Until then core 1 might still be fetching its idle
        //    loop from XIP, so we must not suspend XIP yet.
        while !CORE1_SIGNER.park_ack.load(Ordering::Acquire) {
            ram_nop();
        }
    }
    // 3) Disable interrupts on this core for the flash sequence (an ISR
    //    fetched from XIP would fault), run it, then restore. Save and
    //    restore the mask state (PRIMASK on Arm, mstatus.MIE on RISC-V)
    //    so a caller that already had interrupts masked stays masked.
    //    The `crate::arch` shims are inline(always) raw asm, so nothing
    //    here is an out-of-line `.text` (XIP) call -- only the boot-ROM
    //    `rom_data` pointer inside `op()` is called, and that lives in
    //    the mask ROM.
    //    Snapshot the QMI window-0 read configuration around `op()`.
    //    The boot-ROM `flash_enter_cmd_xip()` that every caller ends
    //    with restores XIP as slow single-bit 03h serial reads,
    //    discarding the fast quad setup boot stage 2 installed. This
    //    image executes from XIP and bumps the signature counter (a
    //    flash write) around every signature, so without putting the
    //    fast configuration back, each post-write instruction fetch
    //    pays for it. Measured on the C port, which had the identical
    //    gap: 1327 cycles per 8-byte cache line, ~0.9 MB/s, turning a
    //    ~1.3 s ML-DSA-65 sign into ~13 s. pico-sdk has the same gap on
    //    RP2350 (its RP2040 path re-runs boot2; the RP2350 path only
    //    calls the ROM helper). Register reads/writes only, and the
    //    cache is flushed inside `op()`, so the next fetch refills
    //    through the restored window.
    let qmi = pac::QMI::ptr();
    let (t, rf, rc) = unsafe {
        (
            (*qmi).m0_timing().read().bits(),
            (*qmi).m0_rfmt().read().bits(),
            (*qmi).m0_rcmd().read().bits(),
        )
    };
    let saved = irq_save_disable();
    op();
    unsafe {
        (*qmi).m0_timing().write(|w| w.bits(t));
        (*qmi).m0_rfmt().write(|w| w.bits(rf));
        (*qmi).m0_rcmd().write(|w| w.bits(rc));
    }
    irq_restore(saved);
    // 4) Release core 1.
    #[cfg(not(feature = "single_core"))]
    {
        CORE1_SIGNER.park_request.store(false, Ordering::Release);
        ram_sev();
        // Wait for core 1 to leave its spin loop before returning, so a
        // back-to-back flash op can't observe a stale `park_ack`.
        while CORE1_SIGNER.park_ack.load(Ordering::Acquire) {
            ram_nop();
        }
    }
}
