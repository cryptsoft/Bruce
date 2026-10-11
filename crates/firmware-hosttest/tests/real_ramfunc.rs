// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `flash_op_locked` -- the guard around every flash write.
//!
//! Two jobs, and both have cost real time on silicon.
//!
//! It parks core 1 in RAM before suspending XIP, because a core still
//! fetching its idle loop from flash during an erase faults. And it
//! snapshots the QMI window-0 read configuration around the operation,
//! because the boot ROM's `flash_enter_cmd_xip()` leaves XIP in slow
//! single-bit 03h serial mode on the way out -- discarding the fast quad
//! setup boot stage 2 installed. A signature-counter write precedes
//! every signature, so without putting it back, every post-write
//! instruction fetch pays: 1327 cycles per 8-byte cache line, which
//! turned a ~1.3 s ML-DSA-65 signature into ~13 s. pico-sdk has the same
//! gap on RP2350.
//!
//! Core 1 is simulated as cooperative here -- it acks whatever is
//! requested -- so this cannot say anything about the dual-core race
//! itself. What it can check is the *order* and the *restore*, which is
//! where the bug was.

use pqf_firmware_hosttest as fw;

use fw::arch;
use fw::core1_signer::{trace, trace_clear, Ev, CORE1_SIGNER};
use fw::real_ramfunc::flash_op_locked;
use rp235x_hal::pac::qmi;

use core::sync::atomic::Ordering;

/// A window with recognisable values, standing in for the fast quad
/// configuration boot stage 2 installs.
fn fast_window() -> qmi::Window {
    qmi::Window {
        timing: 0x6000_0204,
        rfmt: 0x0000_1002,
        rcmd: 0x0000_eb03,
    }
}

fn fresh() -> fw::testlock::Guard {
    let g = fw::testlock::acquire();
    qmi::reset();
    trace_clear();
    CORE1_SIGNER.park_request.store(false, Ordering::Release);
    arch::set_irqs_masked(false);
    g
}

// ---- the QMI restore --------------------------------------------------

#[test]
fn the_qmi_window_is_restored_after_the_flash_op() {
    // The regression test for the 13-second signature. `op` here does
    // exactly what the boot ROM does on its way out: drops the window
    // back to slow serial reads. It must not survive the call.
    let _g = fresh();
    qmi::set(fast_window());

    unsafe {
        flash_op_locked(|| qmi::clobber_like_boot_rom());
    }

    assert_eq!(
        qmi::get(),
        fast_window(),
        "the fast XIP window was not restored -- every instruction fetch after \
         a flash write would pay 1327 cycles per cache line"
    );
}

#[test]
fn all_three_window_registers_are_restored() {
    // Restoring two of the three would be a subtler version of the same
    // bug and would look fine in a quick check.
    let _g = fresh();
    for (name, w) in [
        (
            "timing",
            qmi::Window {
                timing: 0x1111_1111,
                rfmt: 0,
                rcmd: 0,
            },
        ),
        (
            "rfmt",
            qmi::Window {
                timing: 0,
                rfmt: 0x2222_2222,
                rcmd: 0,
            },
        ),
        (
            "rcmd",
            qmi::Window {
                timing: 0,
                rfmt: 0,
                rcmd: 0x3333_3333,
            },
        ),
    ] {
        qmi::set(w);
        unsafe {
            flash_op_locked(|| qmi::clobber_like_boot_rom());
        }
        assert_eq!(qmi::get(), w, "{name} was not restored");
    }
}

#[test]
fn a_flash_op_that_leaves_the_window_alone_still_ends_with_it_intact() {
    // The restore must be unconditional, not "only if it changed" --
    // there is no way to tell from outside whether the ROM touched it.
    let _g = fresh();
    qmi::set(fast_window());
    unsafe {
        flash_op_locked(|| {});
    }
    assert_eq!(
        qmi::get(),
        fast_window(),
        "an untouched window came back changed"
    );
}

#[test]
fn the_window_is_written_back_every_call() {
    // Three registers, once per call. A restore that was skipped on a
    // second back-to-back write would show as a signature that is fast
    // once and slow afterwards -- which is exactly how the original bug
    // presented.
    let _g = fresh();
    qmi::set(fast_window());
    for i in 1..=3u32 {
        unsafe {
            flash_op_locked(|| qmi::clobber_like_boot_rom());
        }
        assert_eq!(qmi::get(), fast_window(), "call {i} did not restore");
        assert!(
            qmi::writes() >= i * 3,
            "call {i} wrote {} registers in total, want at least {}",
            qmi::writes(),
            i * 3
        );
    }
}

// ---- the core-1 park handshake ---------------------------------------

#[test]
fn core_one_is_parked_before_the_op_and_released_after() {
    // The ordering is the safety property: XIP must not be suspended
    // until core 1 has acknowledged it is spinning in RAM. Running the
    // op first would be a dual-core fault waiting for the right timing.
    let _g = fresh();
    trace_clear();

    unsafe {
        flash_op_locked(|| fw::core1_signer::trace_push(Ev::OpRan));
    }

    let t = trace();
    let op_at = t
        .iter()
        .position(|e| *e == Ev::OpRan)
        .expect("the op never ran");
    let ack_before = t[..op_at].iter().any(|e| *e == Ev::AckObservedSet);
    assert!(
        ack_before,
        "the flash op ran before core 1 acknowledged the park: {t:?}"
    );
    let released = t[op_at..].iter().any(|e| *e == Ev::AckObservedClear);
    assert!(
        released,
        "core 1 was never observed leaving its spin loop after the op: {t:?}"
    );
}

#[test]
fn the_park_request_is_clear_when_the_call_returns() {
    // Left set, core 1 would spin in RAM forever and never sign again.
    let _g = fresh();
    unsafe {
        flash_op_locked(|| {});
    }
    assert!(
        !CORE1_SIGNER.park_request.load(Ordering::Acquire),
        "core 1 was left parked after the flash op"
    );
}

#[test]
fn back_to_back_flash_ops_each_park_and_release() {
    // The comment in ramfunc.rs is explicit about waiting for core 1 to
    // *leave* its spin loop before returning, so a second op cannot
    // observe a stale ack. Two in a row is the case that guards.
    let _g = fresh();
    for i in 0..4 {
        unsafe {
            flash_op_locked(|| {});
        }
        assert!(
            !CORE1_SIGNER.park_request.load(Ordering::Acquire),
            "op {i} left core 1 parked"
        );
    }
}

// ---- interrupt masking ------------------------------------------------

#[test]
fn interrupts_are_masked_across_the_op_and_restored_after() {
    // An ISR fetched from XIP during the flash sequence would fault.
    let _g = fresh();
    arch::set_irqs_masked(false);
    let mut seen = false;
    unsafe {
        flash_op_locked(|| seen = arch::irqs_masked());
    }
    assert!(seen, "interrupts were not masked while the flash op ran");
    assert!(
        !arch::irqs_masked(),
        "interrupts were left masked after the flash op"
    );
}

#[test]
fn a_caller_that_had_interrupts_masked_stays_masked() {
    // The reason the mask is *saved* rather than just cleared. A caller
    // inside its own critical section must not have it silently reopened
    // underneath it.
    let _g = fresh();
    arch::set_irqs_masked(true);
    unsafe {
        flash_op_locked(|| {});
    }
    assert!(
        arch::irqs_masked(),
        "a caller's interrupt mask was dropped by the flash op"
    );
}

#[test]
fn the_op_runs_exactly_once() {
    let _g = fresh();
    let mut n = 0u32;
    unsafe {
        flash_op_locked(|| n += 1);
    }
    assert_eq!(n, 1, "the flash op ran {n} times, not once");
}
