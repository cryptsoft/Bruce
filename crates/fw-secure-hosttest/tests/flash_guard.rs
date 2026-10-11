// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The Secure world's flash guard.
//!
//! `with_core1_parked` holds core 1 in a RAM-resident spin loop while
//! the caller makes the XIP window unreadable -- a flash erase or
//! program, or the BOOTSEL sampler floating the chip select. An
//! instruction fetch from either core during that window is undefined,
//! and on the sampler the failure is *quiet*: core 1 fetching re-asserts
//! CS through the QMI and the read comes back "released", forever.
//!
//! The module's own comment records that this was missed when core 1
//! arrived -- the flash path was written when the Secure image ran one
//! core, and launching core 1 for the ML-DSA signer did not revisit it.
//! So the guard exists because its absence was a real bug, which is
//! reason enough to check it holds.
//!
//! Core 1 is a thread here. That is not the real thing -- no XIP, no
//! second instruction stream -- but it does exercise the handshake as
//! two independent parties, which a single-threaded stub cannot.

use pqf_fw_secure_hosttest as fw;

use fw::real_flash::{note_core1_running, with_core1_parked};
use fw::signer::CORE1_SIGNER;
use rp235x_hal::pac::qmi;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// These share process-global state: the QMI window, the signer's park
/// atomics, and `CORE1_RUNNING`, which is one-way.
static SERIAL: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn fast_window() -> qmi::Window {
    qmi::Window {
        timing: 0x6000_0204,
        rfmt: 0x0000_1002,
        rcmd: 0x0000_eb03,
    }
}

/// Core 1, for the lifetime of the process.
///
/// It must not be stopped between tests. `CORE1_RUNNING` is one-way, so
/// once any test has called `note_core1_running` every later park waits
/// for an acknowledgement -- and a thread that has exited never sends
/// one. Stopping it per-test hung the suite, which is a harness bug that
/// looks exactly like the firmware deadlock the guard exists to avoid.
static CORE1_UP: std::sync::Once = std::sync::Once::new();

/// How long simulated core 1 takes to notice a park request, in
/// milliseconds. A test raises this to show the guard waits for the
/// *acknowledgement* rather than proceeding on its own request.
static ACK_DELAY_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// When the acknowledgement was last raised.
static LAST_ACK: Mutex<Option<Instant>> = Mutex::new(None);

fn core1_running() {
    CORE1_UP.call_once(|| {
        std::thread::spawn(|| loop {
            let want = CORE1_SIGNER.park_request.load(Ordering::Acquire);
            let have = CORE1_SIGNER.park_ack.load(Ordering::Acquire);
            if want != have {
                if want {
                    let d = ACK_DELAY_MS.load(Ordering::Acquire);
                    if d > 0 {
                        std::thread::sleep(Duration::from_millis(d));
                        // Re-check: the request may have been withdrawn.
                        if !CORE1_SIGNER.park_request.load(Ordering::Acquire) {
                            continue;
                        }
                    }
                    *LAST_ACK.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
                }
                CORE1_SIGNER.park_ack.store(want, Ordering::Release);
            }
            std::thread::yield_now();
        });
        note_core1_running();
    });
}

// ---- with core 1 up --------------------------------------------------

#[test]
fn core_one_is_parked_for_the_operation_and_released_after() {
    let _g = lock();
    core1_running();

    let mut parked_during = false;
    with_core1_parked(|| {
        parked_during = CORE1_SIGNER.park_request.load(Ordering::Acquire);
    });

    assert!(
        parked_during,
        "the operation ran without core 1 being asked to park -- an \
         instruction fetch during an XIP-down window is undefined"
    );
    assert!(
        !CORE1_SIGNER.park_request.load(Ordering::Acquire),
        "core 1 was left parked, so it would spin in RAM and never sign again"
    );
}

#[test]
fn the_guard_waits_for_the_acknowledgement_not_just_the_request() {
    // Setting `park_request` is not enough: until core 1 answers, it may
    // still be fetching its idle loop from XIP, and that fetch during an
    // XIP-down window is exactly the undefined behaviour the guard
    // exists to prevent. So the guard must block on the acknowledgement,
    // not on having asked.
    //
    // Core 1 is slowed to 50 ms here so the two events are far enough
    // apart to order confidently.
    let _g = lock();
    core1_running();
    *LAST_ACK.lock().unwrap_or_else(|e| e.into_inner()) = None;
    ACK_DELAY_MS.store(50, Ordering::Release);

    let mut ran_at = None;
    with_core1_parked(|| ran_at = Some(Instant::now()));
    ACK_DELAY_MS.store(0, Ordering::Release);

    let acked = LAST_ACK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .expect("core 1 never acknowledged");
    let ran = ran_at.expect("the operation never ran");
    assert!(
        ran >= acked,
        "the operation ran before core 1 acknowledged the park"
    );
}

#[test]
fn back_to_back_operations_each_park_and_release() {
    // The guard waits for core 1 to LEAVE its spin loop before
    // returning, so a second operation cannot observe a stale ack and
    // proceed while core 1 is still parked from the first.
    let _g = lock();
    core1_running();

    for i in 0..8 {
        let mut parked = false;
        with_core1_parked(|| parked = CORE1_SIGNER.park_request.load(Ordering::Acquire));
        assert!(parked, "operation {i} did not park core 1");
        assert!(
            !CORE1_SIGNER.park_request.load(Ordering::Acquire),
            "operation {i} left core 1 parked"
        );
    }
}

#[test]
fn the_guarded_operation_runs_exactly_once_and_its_value_comes_back() {
    let _g = lock();
    core1_running();

    let mut n = 0u32;
    let out = with_core1_parked(|| {
        n += 1;
        0xabcd_u32
    });
    assert_eq!(n, 1, "the operation ran {n} times, not once");
    assert_eq!(out, 0xabcd, "the operation's value was not returned");
}

// ---- the QMI window ---------------------------------------------------

#[test]
fn the_qmi_window_survives_a_flash_op() {
    // Same hazard as the Non-secure port: the boot ROM leaves XIP in
    // slow serial mode on the way out of a flash operation, and this
    // image executes from XIP. Without the restore every instruction
    // fetch afterwards pays for it.
    let _g = lock();
    core1_running();

    qmi::reset();
    qmi::set(fast_window());
    unsafe {
        fw::real_flash::flash_op(|| qmi::clobber_like_boot_rom());
    }
    assert_eq!(
        qmi::get(),
        fast_window(),
        "the fast XIP window was not restored after a flash operation"
    );
}

#[test]
fn the_qmi_window_is_restored_even_when_the_op_leaves_it_alone() {
    // The restore has to be unconditional: there is no way to tell from
    // outside whether the ROM touched it.
    let _g = lock();
    core1_running();

    qmi::reset();
    qmi::set(fast_window());
    unsafe {
        fw::real_flash::flash_op(|| {});
    }
    assert_eq!(
        qmi::get(),
        fast_window(),
        "an untouched window came back changed"
    );
}
