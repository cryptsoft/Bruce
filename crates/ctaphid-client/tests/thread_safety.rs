// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The pattern that used to kill the process.
//!
//! `hidapi`'s macOS backend keeps CoreFoundation state behind the C
//! library's globals, and CF objects are not safe to touch from more than
//! one thread. Before all hidapi use was confined to one worker thread,
//! enumerating from two threads -- even strictly one after the other
//! under a mutex -- corrupted that state and the process died inside
//! `__CFCheckCFInfoPACSignature` with `EXC_BREAKPOINT`: no panic, no
//! message, and every test that had already passed still printed as
//! having passed.
//!
//! That is the failure mode these guard against. They need no token: the
//! crash was in enumeration itself and reproduced with nothing plugged
//! in. Any token that *is* present simply makes the counts non-zero.
//!
//! A regression here does not fail politely. It aborts the whole test
//! binary, so a run that ends early with tests unaccounted for is the
//! symptom to look for.

use pqf_ctaphid::hid;
use std::sync::{Arc, Barrier};

#[test]
fn enumerating_from_many_threads_at_once_is_safe() {
    // All released together, so the calls genuinely overlap rather than
    // being serialised by thread start-up latency.
    let threads = 8;
    let gate = Arc::new(Barrier::new(threads));
    let mut handles = Vec::new();
    for _ in 0..threads {
        let gate = Arc::clone(&gate);
        handles.push(std::thread::spawn(move || {
            gate.wait();
            hid::enumerate().map(|v| v.len())
        }));
    }
    let counts: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for c in &counts {
        assert!(c.is_ok(), "enumerate failed on a worker thread: {c:?}");
    }
    // Every thread saw the same bus.
    let first = counts[0].as_ref().unwrap();
    for c in &counts {
        assert_eq!(
            c.as_ref().unwrap(),
            first,
            "threads disagree about the device count"
        );
    }
}

#[test]
fn repeated_enumeration_across_short_lived_threads_is_safe() {
    // The harness's own shape: a thread per unit of work, each one
    // touching hidapi and then exiting. Thread teardown was the other
    // half of the original crash.
    for _ in 0..12 {
        let n = std::thread::spawn(|| hid::enumerate().map(|v| v.len()))
            .join()
            .unwrap();
        assert!(n.is_ok(), "enumerate failed: {n:?}");
    }
}

#[test]
fn list_all_and_enumerate_can_race() {
    // Two different jobs, so the worker is switching between kinds of
    // work rather than repeating one.
    let gate = Arc::new(Barrier::new(2));
    let g1 = Arc::clone(&gate);
    let a = std::thread::spawn(move || {
        g1.wait();
        hid::list_all().map(|v| v.len())
    });
    let g2 = Arc::clone(&gate);
    let b = std::thread::spawn(move || {
        g2.wait();
        hid::enumerate().map(|v| v.len())
    });
    let all = a.join().unwrap().expect("list_all failed");
    let fido = b.join().unwrap().expect("enumerate failed");
    assert!(
        fido <= all,
        "the FIDO-filtered list ({fido}) cannot be longer than every HID device ({all})"
    );
}

#[test]
fn enumerating_succeeds_whether_or_not_a_token_is_present() {
    // Guards the distinction the PKCS#11 module depends on: no devices
    // is CKR_OK with a count of zero, while a failure to scan the bus is
    // CKR_DEVICE_ERROR. Conflating them makes an empty slot list look
    // like a broken driver.
    //
    // It used to assert one fixed `vendor_id` on every entry, which was
    // the wrong field and the wrong number -- `enumerate` filters on the
    // FIDO usage page, not the vendor, and this project's token is
    // 0xcafe. `DeviceInfo` does not carry the usage page, so there was
    // never anything per-device to check there. The test passed only
    // because no token was plugged in when it ran, and failed the first
    // time one was. A check that holds only on an empty bus is not a
    // check.
    //
    // What is actually true either way: the scan succeeds, and every
    // entry it returns can be opened.
    let list = hid::enumerate().expect("enumerate must succeed even with nothing plugged in");
    for d in &list {
        assert!(
            !d.path.is_empty(),
            "enumerate returned {:04x}:{:04x} with no path, so nothing could open it",
            d.vendor_id,
            d.product_id
        );
    }

    // And it is stable: two scans in a row must agree on how many FIDO
    // devices are on the bus. A count that moves on its own is what a
    // caller sees as a slot appearing and vanishing.
    let again = hid::enumerate().expect("a second enumerate must succeed too");
    assert_eq!(
        list.len(),
        again.len(),
        "two consecutive scans disagreed: {} then {}",
        list.len(),
        again.len()
    );
}
