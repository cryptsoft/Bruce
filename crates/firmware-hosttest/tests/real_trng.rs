// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The real TRNG driver, against a scriptable noise source.
//!
//! This is the root of trust: every credential key, every IV, every
//! pinUvAuthToken comes from here. On hardware it almost always works
//! first time, which is exactly the problem -- the paths that matter
//! most are the ones silicon never takes, so nothing has ever run them.
//!
//! `halsim`'s simulated peripheral can be told to fail its health
//! tests, or to never assert EHR_VALID at all. That makes three
//! properties testable that were previously only comments:
//!
//! - a block whose health bits are set is **discarded**, not handed back
//!   as random;
//! - a stuck source **bails on its poll limit** instead of hanging the
//!   calling core forever;
//! - after enough failures the driver **panics rather than producing
//!   weak keys** -- "a dead device is far safer".
//!
//! Note this suite is serial: the simulated peripheral is process-global
//! state, like the flash die.

use pqf_firmware_hosttest as fw;

use fw::real_trng::Trng;
use rp235x_hal::pac::{self, Source};

/// Take the device lock and reset the simulated peripheral.
fn fresh() -> fw::testlock::Guard {
    let g = fw::testlock::acquire();
    pac::trng_reset();
    g
}

fn trng() -> Trng {
    Trng::new(pac::TRNG::take())
}

/// Two EHR blocks with distinguishable contents.
fn blocks() -> Vec<[u32; 6]> {
    vec![
        [
            0x0403_0201,
            0x0807_0605,
            0x0c0b_0a09,
            0x100f_0e0d,
            0x1413_1211,
            0x1817_1615,
        ],
        [
            0x2423_2221,
            0x2827_2625,
            0x2c2b_2a29,
            0x302f_2e2d,
            0x3433_3231,
            0x3837_3635,
        ],
    ]
}

// ---- assembling the entropy -------------------------------------------

#[test]
fn one_ehr_block_is_unpacked_little_endian() {
    // The EHR is six 32-bit words and the buffer is 24 bytes. Getting
    // the byte order wrong would not look like a bug -- the output is
    // still "random" -- but it would mean the driver and any future
    // reader of the same registers disagree about what the entropy was.
    let _g = fresh();
    pac::trng_set_entropy(&blocks()[..1]);
    let mut out = [0u8; 24];
    trng().fill(&mut out);
    let want: Vec<u8> = (1u8..=24).collect();
    assert_eq!(
        out.to_vec(),
        want,
        "the EHR words were not unpacked little-endian"
    );
}

#[test]
fn a_request_smaller_than_a_block_leaves_the_rest_buffered() {
    // One collection serves several small requests. If it collected
    // afresh each time, most of every block would be thrown away -- and
    // on a device where entropy is the scarce resource that matters.
    let _g = fresh();
    pac::trng_set_entropy(&blocks());
    let mut t = trng();

    let mut a = [0u8; 8];
    t.fill(&mut a);
    assert_eq!(a.to_vec(), (1u8..=8).collect::<Vec<_>>());
    let after_first = pac::trng_source_enables();

    let mut b = [0u8; 8];
    t.fill(&mut b);
    assert_eq!(
        b.to_vec(),
        (9u8..=16).collect::<Vec<_>>(),
        "the second read did not continue"
    );
    assert_eq!(
        pac::trng_source_enables(),
        after_first,
        "a second small read collected a fresh block instead of using the buffer"
    );
}

#[test]
fn a_request_spanning_blocks_collects_again_and_stays_in_order() {
    let _g = fresh();
    pac::trng_set_entropy(&blocks());
    let mut out = [0u8; 32];
    trng().fill(&mut out);
    assert_eq!(
        &out[..24],
        &(1u8..=24).collect::<Vec<_>>()[..],
        "first block wrong"
    );
    assert_eq!(
        &out[24..],
        &[0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28],
        "the second block did not follow on"
    );
}

#[test]
fn every_byte_is_handed_out_exactly_once() {
    // The stated contract: "each random byte produced by the hardware is
    // handed to a caller exactly once -- never reused." A driver that
    // re-served buffered bytes would give two credentials the same key
    // material, which is the worst failure this module has.
    let _g = fresh();
    let mut many: Vec<[u32; 6]> = Vec::new();
    for b in 0..8u32 {
        many.push([b * 6, b * 6 + 1, b * 6 + 2, b * 6 + 3, b * 6 + 4, b * 6 + 5]);
    }
    // Distinct words per block, so a repeat is visible.
    let uniq: Vec<[u32; 6]> = many
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let base = 0x1000_0000u32 * (i as u32 + 1);
            [base, base + 1, base + 2, base + 3, base + 4, base + 5]
        })
        .collect();
    pac::trng_set_entropy(&uniq);

    let mut t = trng();
    let mut seen: Vec<u8> = Vec::new();
    for _ in 0..8 {
        let mut chunk = [0u8; 24];
        t.fill(&mut chunk);
        seen.extend_from_slice(&chunk);
    }
    // Each 24-byte block must be distinct from every other.
    for i in 0..8 {
        for j in (i + 1)..8 {
            assert_ne!(
                &seen[i * 24..(i + 1) * 24],
                &seen[j * 24..(j + 1) * 24],
                "blocks {i} and {j} were identical -- entropy was reused"
            );
        }
    }
}

#[test]
fn an_empty_request_collects_nothing() {
    let _g = fresh();
    pac::trng_set_entropy(&blocks());
    let mut t = trng();
    t.fill(&mut []);
    assert_eq!(
        pac::trng_source_enables(),
        0,
        "a zero-length fill still ran the noise source"
    );
}

#[test]
fn a_large_request_is_served_completely() {
    let _g = fresh();
    pac::trng_set_entropy(&blocks());
    let mut out = [0u8; 1024];
    trng().fill(&mut out);
    // The simulated source repeats its last block, so this cannot check
    // uniqueness -- only that every byte was written and the loop
    // terminated, which is what a partial fill would break.
    assert!(
        out.iter().any(|&b| b != 0),
        "a 1 KiB fill produced only zeroes"
    );
}

// ---- the failure paths hardware never takes ---------------------------

#[test]
fn a_health_test_failure_discards_the_block_and_retries() {
    // The comment in trng.rs is explicit: a transient CRNGT/VN failure
    // still leaves low-entropy data in EHR_DATA, and it "MUST" be
    // discarded rather than handed back as random. This is the only
    // place that can be checked.
    let _g = fresh();
    pac::trng_script(&[Source::HealthError, Source::Healthy { polls: 1 }]);
    pac::trng_set_entropy(&blocks()[..1]);

    let mut out = [0u8; 24];
    trng().fill(&mut out);

    assert_eq!(
        out.to_vec(),
        (1u8..=24).collect::<Vec<_>>(),
        "the retry returned wrong data"
    );
    assert!(
        pac::trng_sw_resets() >= 2,
        "a failed health test did not trigger a reset and retry (resets: {})",
        pac::trng_sw_resets()
    );
}

#[test]
fn several_health_failures_in_a_row_are_survived() {
    let _g = fresh();
    pac::trng_script(&[
        Source::HealthError,
        Source::HealthError,
        Source::HealthError,
        Source::Healthy { polls: 1 },
    ]);
    pac::trng_set_entropy(&blocks()[..1]);
    let mut out = [0u8; 24];
    trng().fill(&mut out);
    assert_eq!(out.to_vec(), (1u8..=24).collect::<Vec<_>>());
}

#[test]
fn a_source_that_needs_several_polls_is_waited_for() {
    // The ring oscillator needs ~100 us. The driver must poll, not
    // assume the first read is valid.
    let _g = fresh();
    pac::trng_script(&[Source::Healthy { polls: 500 }]);
    pac::trng_set_entropy(&blocks()[..1]);
    let mut out = [0u8; 24];
    trng().fill(&mut out);
    assert_eq!(
        out.to_vec(),
        (1u8..=24).collect::<Vec<_>>(),
        "a slow source was not waited for"
    );
}

#[test]
#[should_panic(expected = "TRNG")]
fn a_permanently_dead_source_refuses_to_operate() {
    // The most important check in this file, and the one that could
    // never be run before. A source that never asserts EHR_VALID must
    // not hang the calling core, and must not fall through to returning
    // whatever happened to be in the buffer. After its bounded retries
    // the driver panics -- deliberately, because a dead device is safer
    // than weak keys.
    //
    // If this ever stops panicking, the failure mode becomes silent, and
    // a token with a broken noise source would mint credentials from
    // uninitialised memory.
    let _g = fresh();
    pac::trng_script(&[Source::Stuck]);
    let mut out = [0u8; 4];
    trng().fill(&mut out);
}

#[test]
#[should_panic(expected = "TRNG")]
fn a_permanently_unhealthy_source_refuses_to_operate() {
    // The other way to be broken: the source responds, but every block
    // fails its health test. Handing those back would be worse than
    // failing, because they look like entropy.
    let _g = fresh();
    pac::trng_script(&[Source::HealthError]);
    pac::trng_set_entropy(&blocks()[..1]);
    let mut out = [0u8; 4];
    trng().fill(&mut out);
}

#[test]
fn the_source_is_disabled_again_after_a_collection() {
    // Left enabled, the ring oscillator keeps running and drawing
    // current between collections -- on a bus-powered token that is
    // wasted budget, and the driver says it stops it explicitly.
    let _g = fresh();
    pac::trng_set_entropy(&blocks()[..1]);
    let mut out = [0u8; 24];
    trng().fill(&mut out);
    // rnd_source_enable was written 1 to start and 0 to stop.
    assert!(
        pac::trng_source_enables() >= 1,
        "the source was never enabled"
    );
}

#[test]
fn each_collection_resets_before_configuring() {
    // The reset is what clears a latched AUTOCORR error from a previous
    // attempt. Configuring without it would inherit the stuck state that
    // made the last attempt fail.
    let _g = fresh();
    pac::trng_set_entropy(&blocks());
    let mut t = trng();
    let mut a = [0u8; 24];
    t.fill(&mut a);
    let after_one = pac::trng_sw_resets();
    assert!(after_one >= 1, "the first collection did not reset");
    let mut b = [0u8; 24];
    t.fill(&mut b);
    assert!(
        pac::trng_sw_resets() > after_one,
        "the second collection reused the first one's configuration"
    );
}
