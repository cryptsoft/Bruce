// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! getInfo's CBOR is emitted in canonical order.
//!
//! `cborw::Writer` is a pure streaming encoder with no sorting, so
//! every map it writes is in whatever order the calls happen to be in.
//! CTAP2 requires canonical CBOR, and a strict client stops decoding at
//! the first key out of order -- which makes this failure completely
//! silent from the token's side. Everything after the bad key simply
//! does not exist as far as that client is concerned.
//!
//! It has now happened twice here. The options map emitted `credMgmt`
//! and `authnrCfg` out of order and those two command families were
//! unreachable; that was fixed and a comment left explaining the trap.
//! The top-level map then went out with 0x0f before 0x06 and 0x0a, so a
//! strict client learned no pinUvAuthProtocol -- and without one it
//! cannot run ClientPIN, which means no PIN, no token, and none of the
//! commands a token gates.
//!
//! Checking the emitted bytes rather than reading the source is the
//! point: the ordering is a property of what goes on the wire.

use pqf_fw_secure_hosttest::{cborr, ctap};

/// Decode the top-level getInfo map, returning its integer keys in the
/// order they were emitted.
fn top_level_keys() -> Vec<u64> {
    let mut out = [0u8; 1024];
    let n = ctap::get_info(&mut out).expect("get_info produced nothing");
    let body = &out[1..n]; // skip the CTAP status byte
    let mut r = cborr::Reader::new(body);
    let count = r.map().expect("getInfo body is not a CBOR map");
    let mut keys = Vec::new();
    for _ in 0..count {
        keys.push(r.uint().expect("a getInfo key is not an unsigned integer"));
        r.skip().expect("could not skip a getInfo value");
    }
    keys
}

#[test]
fn the_top_level_keys_are_in_ascending_order() {
    let keys = top_level_keys();
    let mut want = keys.clone();
    want.sort_unstable();
    assert_eq!(
        keys, want,
        "getInfo keys are emitted out of canonical order; a strict client \
         stops at the first one and never sees the rest"
    );
}

#[test]
fn the_keys_a_client_needs_are_all_present() {
    // Ordering is only half of it: a key that is absent is also invisible.
    // These four are the ones whose absence breaks a whole command family.
    let keys = top_level_keys();
    for (k, what) in [
        (1u64, "versions"),
        (
            2,
            "extensions -- a client only sends an extension the authenticator advertises; \
             this image implemented four and advertised none",
        ),
        (
            0x06,
            "pinUvAuthProtocols -- without it ClientPIN cannot start",
        ),
        (
            0x0a,
            "algorithms -- without it the composite alg is unusable",
        ),
        (4, "options"),
    ] {
        assert!(keys.contains(&k), "getInfo omits key {k:#x} ({what})");
    }
}

#[test]
fn no_key_is_emitted_twice() {
    // A duplicate key is not canonical either, and a decoder may take
    // whichever it saw first.
    let keys = top_level_keys();
    let mut seen = keys.clone();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen.len(),
        keys.len(),
        "getInfo emits a duplicate key: {keys:?}"
    );
}

#[test]
fn the_options_map_is_in_canonical_order_too() {
    // CTAP2 canonical CBOR sorts text keys by LENGTH first, then
    // bytewise -- not lexicographically. This is the map that was wrong
    // the first time, and the rule is unusual enough to get wrong again.
    let mut out = [0u8; 1024];
    let n = ctap::get_info(&mut out).expect("get_info");
    let body = &out[1..n];
    let mut r = cborr::Reader::new(body);
    let count = r.map().expect("not a map");
    let mut names: Vec<Vec<u8>> = Vec::new();
    for _ in 0..count {
        let k = r.uint().expect("key");
        if k == 4 {
            let m = r.map().expect("options is not a map");
            for _ in 0..m {
                names.push(
                    r.str_bytes(cborr::MAJOR_TEXT)
                        .expect("option name")
                        .to_vec(),
                );
                r.skip().expect("option value");
            }
        } else {
            r.skip().expect("value");
        }
    }
    assert!(!names.is_empty(), "getInfo advertised no options at all");
    let mut want = names.clone();
    want.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
    let show = |v: &Vec<Vec<u8>>| {
        v.iter()
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        show(&names),
        show(&want),
        "options are not in length-then-bytewise order"
    );
}
