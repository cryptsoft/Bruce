// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The one Secure flash-guard case that needs its own process.
//!
//! `CORE1_RUNNING` is a one-way global: once `note_core1_running` has
//! been called, nothing sets it back. So the boot-time behaviour -- what
//! the guard does *before* core 1 exists -- can only be observed once
//! per process, and it has to be alone in its binary. Putting it beside
//! the others made the suite hang, which is the same shape as the
//! firmware bug it is checking for.

use pqf_fw_secure_hosttest as fw;

use fw::real_flash::with_core1_parked;
use fw::signer::CORE1_SIGNER;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[test]
fn before_core_one_starts_the_guard_does_not_wait_for_it() {
    // The key store and the signature counter both write flash during
    // bring-up, BEFORE core 1 is launched. Parking a core that has not
    // started would wait forever on an acknowledgement nobody will send
    // -- a token that never finishes booting.
    //
    // Alone in this binary, so `CORE1_RUNNING` is guaranteed false --
    // there is no ordering to get wrong.
    let start = Instant::now();
    let mut ran = false;
    with_core1_parked(|| ran = true);
    assert!(ran, "the guarded operation never ran");
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "the guard waited for a core that was never started -- on a token \
         this is a boot that never completes"
    );
    assert!(
        !CORE1_SIGNER.park_request.load(Ordering::Acquire),
        "a park was requested from a core that is not running"
    );
}
