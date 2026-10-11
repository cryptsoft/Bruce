// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The one place this image suspends XIP to talk to flash.
//!
//! Shared by the key store and the signature counter, because getting
//! this wrong is subtle and there should be exactly one copy of it.

use core::sync::atomic::{AtomicBool, Ordering};
use hal::pac;
use rp235x_hal as hal;

/// Set once core 1 is actually running its worker loop.
///
/// The key store and the signature counter both write flash during
/// bring-up, BEFORE core 1 is launched. Parking a core that has not
/// started would wait forever on an acknowledgement nobody will send.
static CORE1_RUNNING: AtomicBool = AtomicBool::new(false);

/// Called from `main` right after core 1 is spawned.
pub fn note_core1_running() {
    CORE1_RUNNING.store(true, Ordering::Release);
}

/// Run `f` with core 1 held in its RAM-resident spin loop.
///
/// Both callers -- a flash erase/program and the BOOTSEL sampler --
/// make the XIP window unreadable for a while: the flash is in command
/// mode, or its chip select is floated. An instruction fetch from
/// either core during that window is undefined, and on the sampler the
/// failure is quiet rather than loud -- core 1 fetching re-asserts CS
/// through the QMI and the read simply comes back "released", forever.
///
/// This was missed when core 1 arrived: the flash path was written when
/// the Secure image ran one core and its comment said so, and launching
/// core 1 for the ML-DSA signer did not revisit it.
pub fn with_core1_parked<R>(f: impl FnOnce() -> R) -> R {
    if !CORE1_RUNNING.load(Ordering::Acquire) {
        return f();
    }
    let s = &crate::signer::CORE1_SIGNER;
    s.park_request.store(true, Ordering::Release);
    cortex_m::asm::sev();
    while !s.park_ack.load(Ordering::Acquire) {
        cortex_m::asm::nop();
    }
    let r = f();
    s.park_request.store(false, Ordering::Release);
    cortex_m::asm::sev();
    while s.park_ack.load(Ordering::Acquire) {
        cortex_m::asm::nop();
    }
    r
}

/// Run a flash sequence with XIP suspended.
///
/// Lives in RAM (`.data.ramfunc`, gathered into `.data` by the default
/// `.data.*` rule) because this image executes from the very flash it
/// is about to put into command mode -- an instruction fetch during the
/// sequence would fault.
///
/// Simpler than the Non-secure firmware's `flash_op_locked`: the Secure
/// image never starts core 1, so there is no second core to park.
///
/// The QMI save/restore is NOT optional. `flash_enter_cmd_xip()` brings
/// XIP back as slow single-bit 03h serial reads, discarding the fast
/// quad configuration boot stage 2 installed. On the C port that same
/// gap measured 1327 cycles per 8-byte cache line and turned a 1.3 s
/// sign into 13 s. It costs one write here, but the setting is global
/// and would slow every fetch afterwards.
///
/// # Safety
/// `op` must touch neither the XIP window nor any code outside RAM and
/// the boot ROM.
/// Run a flash sequence with core 1 parked and XIP suspended.
///
/// The parking is here rather than at each call site so no caller can
/// forget it -- and one already had, for the whole of M4f.
///
/// # Safety
/// `op` must touch neither the XIP window nor any code outside RAM and
/// the boot ROM.
pub unsafe fn flash_op<F: FnMut()>(op: F) {
    // SAFETY: forwarded to the caller's contract.
    with_core1_parked(|| unsafe { flash_op_inner(op) });
}

#[inline(never)]
// Gated to the board targets so the module can also be built and tested
// on a host: `.data.ramfunc` is not a section name a Mach-O linker
// accepts. Identical on target. Matches the Non-secure port's ramfunc.rs
// and `pqf_signer_core::signer`.
#[cfg_attr(
    any(target_arch = "arm", target_arch = "riscv32"),
    link_section = ".data.ramfunc"
)]
unsafe fn flash_op_inner<F: FnMut()>(mut op: F) {
    let qmi = pac::QMI::ptr();
    // SAFETY: register reads; the QMI block is Secure-owned.
    let (t, rf, rc) = unsafe {
        (
            (*qmi).m0_timing().read().bits(),
            (*qmi).m0_rfmt().read().bits(),
            (*qmi).m0_rcmd().read().bits(),
        )
    };
    let masked = cortex_m::register::primask::read().is_active();
    cortex_m::interrupt::disable();
    op();
    // SAFETY: restoring the snapshot taken above; the cache was flushed
    // inside `op`, so the next fetch refills through this window.
    unsafe {
        (*qmi).m0_timing().write(|w| w.bits(t));
        (*qmi).m0_rfmt().write(|w| w.bits(rf));
        (*qmi).m0_rcmd().write(|w| w.bits(rc));
    }
    if masked {
        // SAFETY: re-enabling only because the caller had them enabled.
        unsafe { cortex_m::interrupt::enable() };
    }
}
