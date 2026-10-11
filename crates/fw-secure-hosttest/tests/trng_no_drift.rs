// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The two TRNG drivers must not drift apart.
//!
//! `crates/fw-secure/src/trng.rs` and `crates/firmware/src/trng.rs` are
//! the same file, copied. That is not a problem in itself -- the Secure
//! world and the FIDO firmware are separate images and neither can
//! depend on the other's crate -- but a copy is only safe while both
//! copies stay the same.
//!
//! This module is the root of trust for both worlds: every credential
//! key, every IV, every pinUvAuthToken. A fix applied to one copy and
//! not the other means one image quietly keeps whatever the bug was, and
//! nothing else in either test suite would notice.
//!
//! So rather than duplicating the thirteen behavioural checks in
//! `crates/firmware-hosttest/tests/real_trng.rs`, this asserts the two
//! files are the same and points at those checks. If they ever need to
//! diverge, this test is where that decision gets made deliberately.

/// Both files, embedded at compile time -- no runtime path dependency.
const SECURE: &str = include_str!("../../fw-secure/src/trng.rs");
const FIRMWARE: &str = include_str!("../../firmware/src/trng.rs");

/// Strip comments and blank lines: the two copies are allowed to explain
/// themselves differently, and a doc comment that mentions the Secure
/// world would otherwise be a false alarm. What must match is the code.
fn code_of(src: &str) -> Vec<String> {
    src.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .map(|l| l.to_string())
        .collect()
}

#[test]
fn the_secure_and_firmware_trng_drivers_are_the_same_code() {
    let a = code_of(SECURE);
    let b = code_of(FIRMWARE);

    if a == b {
        return;
    }

    // Report the first divergence rather than "they differ", so the
    // failure names what changed.
    let n = a.len().min(b.len());
    for i in 0..n {
        if a[i] != b[i] {
            panic!(
                "the TRNG drivers have drifted at code line {i}:\n  \
                 fw-secure: {}\n  firmware:  {}\n\n\
                 These are copies of one file and both are the root of \
                 trust for their image. A fix applied to one and not the \
                 other leaves that bug in the other world. If the \
                 divergence is deliberate, change this test and say why.",
                a[i], b[i]
            );
        }
    }
    panic!(
        "the TRNG drivers have drifted in length: fw-secure has {} code \
         lines, firmware has {}. The first {n} match, so something was \
         added to or removed from one copy only.",
        a.len(),
        b.len()
    );
}

#[test]
fn the_behavioural_checks_live_with_the_firmware_copy() {
    // A signpost, not a check on the firmware. The thirteen behavioural
    // tests -- health-test failures discarded, a stuck source bailing
    // rather than hanging, a dead source refusing to operate rather than
    // producing weak keys -- are in
    // crates/firmware-hosttest/tests/real_trng.rs and apply equally to
    // this copy for exactly as long as the test above passes.
    //
    // This asserts the file it points at still exists, so the reference
    // cannot rot silently.
    const POINTER: &str = include_str!("../../firmware-hosttest/tests/real_trng.rs");
    assert!(
        POINTER.contains("a_permanently_dead_source_refuses_to_operate"),
        "the TRNG behavioural suite has moved or been renamed -- update \
         the pointer in this file"
    );
}
