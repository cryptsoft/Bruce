// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP2 request parsing in the Non-secure world.
//!
//! This is the code that turns attacker-controlled CBOR into the
//! fixed-layout byte arrays handed across the TrustZone boundary. It
//! runs Non-secure on purpose -- a bug here cannot reach a key -- but
//! "cannot reach a key" is not "cannot matter": everything Secure acts
//! on arrives through these six functions, and until now none of them
//! had ever been executed off silicon.
//!
//! `cborr` underneath is covered separately. What is tested here is the
//! layer above: required fields, type discipline, length ceilings, and
//! the CTAP2 MUSTs that are policy rather than syntax.
//!
//! The encoders below are deliberately hand-rolled rather than shared
//! with `tests/cborr.rs` -- the two are separate test binaries and
//! cannot share a private helper without a module, and writing the
//! bytes out longhand keeps the tests from being written against the
//! same code they check.

use pqf_fw_secure_hosttest::ctapreq::{self, *};

// ---------- CBOR encoders ----------

fn hdr(major: u8, arg: u64) -> Vec<u8> {
    let m = major << 5;
    if arg <= 23 {
        vec![m | arg as u8]
    } else if arg <= u8::MAX as u64 {
        vec![m | 24, arg as u8]
    } else if arg <= u16::MAX as u64 {
        let a = (arg as u16).to_be_bytes();
        vec![m | 25, a[0], a[1]]
    } else if arg <= u32::MAX as u64 {
        let mut v = vec![m | 26];
        v.extend_from_slice(&(arg as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![m | 27];
        v.extend_from_slice(&arg.to_be_bytes());
        v
    }
}
const UINT: u8 = 0;
const NINT: u8 = 1;
const BYTES: u8 = 2;
const TEXT: u8 = 3;
const ARRAY: u8 = 4;
const MAP: u8 = 5;

fn bstr(b: &[u8]) -> Vec<u8> {
    let mut v = hdr(BYTES, b.len() as u64);
    v.extend_from_slice(b);
    v
}
fn tstr(s: &str) -> Vec<u8> {
    let mut v = hdr(TEXT, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    v
}
fn nint(n: i64) -> Vec<u8> {
    hdr(NINT, (-1 - n) as u64)
}

/// A request message: the CTAP2 command byte then the CBOR map. The
/// parsers skip byte 0 themselves (`&msg[1..]`).
fn msg(parts: Vec<Vec<u8>>) -> Vec<u8> {
    let mut v = vec![0x01u8];
    for p in parts {
        v.extend_from_slice(&p);
    }
    v
}

/// A minimal well-formed MakeCredential: clientDataHash, rp, user,
/// pubKeyCredParams with ES256.
fn good_make_cred() -> Vec<u8> {
    let mut m = hdr(MAP, 4);
    m.extend(hdr(UINT, 1));
    m.extend(bstr(&[0x42; 32]));
    m.extend(hdr(UINT, 2));
    {
        let mut rp = hdr(MAP, 1);
        rp.extend(tstr("id"));
        rp.extend(tstr("example.com"));
        m.extend(rp);
    }
    m.extend(hdr(UINT, 3));
    {
        let mut u = hdr(MAP, 1);
        u.extend(tstr("id"));
        u.extend(bstr(&[0x01; 16]));
        m.extend(u);
    }
    m.extend(hdr(UINT, 4));
    {
        let mut arr = hdr(ARRAY, 1);
        let mut e = hdr(MAP, 2);
        e.extend(tstr("alg"));
        e.extend(nint(-7)); // ES256
        e.extend(tstr("type"));
        e.extend(tstr("public-key"));
        arr.extend(e);
        m.extend(arr);
    }
    msg(vec![m])
}

fn never_ours(_rp: &[u8], _id: &[u8; 64]) -> bool {
    false
}

fn parse_mc(m: &[u8]) -> Result<[u8; REQ_LEN], u8> {
    let mut req = [0u8; REQ_LEN];
    ctapreq::parse_make_credential(m, None, &mut req, &mut never_ours)?;
    Ok(req)
}

// ---------- MakeCredential ----------

#[test]
fn a_well_formed_request_parses_and_lands_in_the_right_slots() {
    let req = parse_mc(&good_make_cred()).expect("a valid request was rejected");
    assert_eq!(
        req[REQ_OFF_RP_LEN] as usize,
        "example.com".len(),
        "rp id length landed wrong"
    );
    assert_eq!(
        &req[REQ_OFF_RP..REQ_OFF_RP + 11],
        b"example.com",
        "rp id landed wrong"
    );
    assert_eq!(
        &req[REQ_OFF_CDH..REQ_OFF_CDH + 32],
        &[0x42u8; 32],
        "clientDataHash landed wrong"
    );
}

#[test]
fn a_truncated_request_is_refused_at_every_length() {
    // Every prefix of a valid request. None may parse, and none may
    // panic -- this is the shape a hostile or merely broken host
    // produces most easily.
    let full = good_make_cred();
    for n in 1..full.len() {
        let r = parse_mc(&full[..n]);
        assert!(
            r.is_err(),
            "a request truncated to {n} bytes parsed as valid"
        );
    }
}

#[test]
fn a_missing_required_field_is_refused() {
    // clientDataHash and rp are both required. Dropping either must
    // fail rather than leave a zeroed slot Secure would then sign over.
    let mut m = hdr(MAP, 1);
    m.extend(hdr(UINT, 1));
    m.extend(bstr(&[0x42; 32])); // cdh only, no rp
    assert!(
        parse_mc(&msg(vec![m])).is_err(),
        "a request with no rp was accepted"
    );

    let mut m = hdr(MAP, 1);
    m.extend(hdr(UINT, 2));
    let mut rp = hdr(MAP, 1);
    rp.extend(tstr("id"));
    rp.extend(tstr("example.com"));
    m.extend(rp);
    assert!(
        parse_mc(&msg(vec![m])).is_err(),
        "a request with no clientDataHash was accepted"
    );
}

#[test]
fn a_wrong_length_client_data_hash_is_refused() {
    // 32 bytes exactly. A short one would leave the tail of the slot
    // holding whatever was there before.
    for len in [0usize, 16, 31, 33, 64] {
        let mut m = hdr(MAP, 2);
        m.extend(hdr(UINT, 1));
        m.extend(bstr(&vec![0x42; len]));
        m.extend(hdr(UINT, 2));
        let mut rp = hdr(MAP, 1);
        rp.extend(tstr("id"));
        rp.extend(tstr("example.com"));
        m.extend(rp);
        assert!(
            parse_mc(&msg(vec![m])).is_err(),
            "a {len}-byte clientDataHash was accepted"
        );
    }
}

#[test]
fn a_field_of_the_wrong_cbor_type_is_refused() {
    // clientDataHash as a text string rather than a byte string. The
    // length would be right; only the type is wrong.
    let mut m = hdr(MAP, 2);
    m.extend(hdr(UINT, 1));
    m.extend(tstr(&"x".repeat(32)));
    m.extend(hdr(UINT, 2));
    let mut rp = hdr(MAP, 1);
    rp.extend(tstr("id"));
    rp.extend(tstr("example.com"));
    m.extend(rp);
    assert!(
        parse_mc(&msg(vec![m])).is_err(),
        "a text clientDataHash was taken for a byte string"
    );
}

#[test]
fn an_oversized_rp_id_is_refused_rather_than_truncated() {
    // The slot is fixed; a longer rp id must be refused, not silently
    // cut down to fit. A truncated rp id is a different relying party.
    let long = "a".repeat(300);
    let mut m = hdr(MAP, 2);
    m.extend(hdr(UINT, 1));
    m.extend(bstr(&[0x42; 32]));
    m.extend(hdr(UINT, 2));
    let mut rp = hdr(MAP, 1);
    rp.extend(tstr("id"));
    rp.extend(tstr(&long));
    m.extend(rp);
    assert!(
        parse_mc(&msg(vec![m])).is_err(),
        "a 300-byte rp id was accepted"
    );
}

#[test]
fn the_exclude_list_must_is_enforced_in_both_directions() {
    // CTAP2 MUST: refuse when the excludeList names a credential we
    // hold. This is why the predicate is injected -- with the veneer
    // wired in directly, only one direction is reachable from a test.
    let mut m = hdr(MAP, 5);
    m.extend(hdr(UINT, 1));
    m.extend(bstr(&[0x42; 32]));
    m.extend(hdr(UINT, 2));
    let mut rp = hdr(MAP, 1);
    rp.extend(tstr("id"));
    rp.extend(tstr("example.com"));
    m.extend(rp);
    m.extend(hdr(UINT, 3));
    let mut u = hdr(MAP, 1);
    u.extend(tstr("id"));
    u.extend(bstr(&[0x01; 16]));
    m.extend(u);
    m.extend(hdr(UINT, 4));
    let mut arr = hdr(ARRAY, 1);
    let mut e = hdr(MAP, 2);
    e.extend(tstr("alg"));
    e.extend(nint(-7));
    e.extend(tstr("type"));
    e.extend(tstr("public-key"));
    arr.extend(e);
    m.extend(arr);
    // excludeList with one descriptor
    m.extend(hdr(UINT, 5));
    let mut ex = hdr(ARRAY, 1);
    let mut d = hdr(MAP, 2);
    d.extend(tstr("id"));
    d.extend(bstr(&[0xAB; 64]));
    d.extend(tstr("type"));
    d.extend(tstr("public-key"));
    ex.extend(d);
    m.extend(ex);
    let request = msg(vec![m]);

    let mut req = [0u8; REQ_LEN];
    let r = ctapreq::parse_make_credential(&request, None, &mut req, &mut never_ours);
    assert!(
        r.is_ok(),
        "a credential we do not hold was excluded anyway: {r:?}"
    );

    let mut req = [0u8; REQ_LEN];
    let r = ctapreq::parse_make_credential(&request, None, &mut req, &mut |_rp, _id| true);
    assert_eq!(
        r,
        Err(CTAP2_ERR_CREDENTIAL_EXCLUDED),
        "a credential we DO hold was not excluded -- CTAP2 requires it"
    );
}

/// A MakeCredential whose excludeList holds `n` entries; entry
/// `ours_at`, if given, carries the id `is_ours` will recognise.
fn mc_with_exclude(n: usize, ours_at: Option<usize>) -> Vec<u8> {
    let mut m = hdr(MAP, 5);
    m.extend(hdr(UINT, 1));
    m.extend(bstr(&[0x42; 32]));
    m.extend(hdr(UINT, 2));
    let mut rp = hdr(MAP, 1);
    rp.extend(tstr("id"));
    rp.extend(tstr("example.com"));
    m.extend(rp);
    m.extend(hdr(UINT, 3));
    let mut u = hdr(MAP, 1);
    u.extend(tstr("id"));
    u.extend(bstr(&[0x01; 16]));
    m.extend(u);
    m.extend(hdr(UINT, 4));
    let mut arr = hdr(ARRAY, 1);
    let mut e = hdr(MAP, 2);
    e.extend(tstr("alg"));
    e.extend(nint(-7));
    e.extend(tstr("type"));
    e.extend(tstr("public-key"));
    arr.extend(e);
    m.extend(arr);
    m.extend(hdr(UINT, 5));
    let mut ex = hdr(ARRAY, n as u64);
    for i in 0..n {
        let mut d = hdr(MAP, 2);
        d.extend(tstr("id"));
        // 0xFF marks the one the predicate below will claim.
        d.extend(bstr(&[if Some(i) == ours_at { 0xFF } else { i as u8 }; 64]));
        d.extend(tstr("type"));
        d.extend(tstr("public-key"));
        ex.extend(d);
    }
    m.extend(ex);
    msg(vec![m])
}

fn ours_is_all_ff(_rp: &[u8], id: &[u8; 64]) -> bool {
    id.iter().all(|&b| b == 0xFF)
}

#[test]
fn an_exclude_list_is_checked_past_its_eighth_entry() {
    // The defect. The list was collected into a fixed array of eight and
    // silently truncated, so a credential named at index 8 or later was
    // never asked about: the registration succeeded and the user was
    // enrolled twice at that relying party. A user with credentials on a
    // phone, two laptops and a couple of keys passes eight routinely.
    //
    // The old test here built exactly this input and then asserted
    // nothing at all -- `let _ = parse(...)`, with a comment saying
    // either verdict was acceptable policy. It was the input that would
    // have caught this, thrown away.
    let mut req = [0u8; REQ_LEN];
    for (n, at) in [(9usize, 8usize), (12, 11), (20, 15), (40, 39)] {
        let e = ctapreq::parse_make_credential(
            &mc_with_exclude(n, Some(at)),
            None,
            &mut req,
            &mut ours_is_all_ff,
        )
        .expect_err(&format!(
            "a {n}-entry excludeList naming our credential at index {at} was accepted"
        ));
        assert_eq!(e, CTAP2_ERR_CREDENTIAL_EXCLUDED, "index {at} of {n}");
    }
}

#[test]
fn every_exclude_list_entry_is_offered_in_order() {
    // Not merely "the long list works": each entry must be asked about,
    // once, in the order the relying party sent them.
    let mut req = [0u8; REQ_LEN];
    let mut seen: Vec<u8> = Vec::new();
    let r = ctapreq::parse_make_credential(
        &mc_with_exclude(20, None),
        None,
        &mut req,
        &mut |_rp, id| {
            seen.push(id[0]);
            false
        },
    );
    assert!(r.is_ok(), "a list naming none of ours was refused: {r:?}");
    assert_eq!(
        seen,
        (0..20u8).collect::<Vec<_>>(),
        "entries were skipped or reordered"
    );
}

#[test]
fn a_long_exclude_list_naming_nothing_of_ours_still_registers() {
    // The accept half. Refusing every long list would pass the test
    // above and break registration for anyone with a lot of passkeys.
    let mut req = [0u8; REQ_LEN];
    ctapreq::parse_make_credential(&mc_with_exclude(64, None), None, &mut req, &mut never_ours)
        .expect("a 64-entry excludeList naming none of ours was refused");
}

#[test]
fn an_exclude_list_that_is_not_an_array_is_refused() {
    // Same rule as the allowList: present but the wrong type is a
    // malformed request, not an absent parameter. Reading it as absent
    // would skip the CTAP2 MUST entirely and register anyway.
    let mut m = hdr(MAP, 5);
    m.extend(hdr(UINT, 1));
    m.extend(bstr(&[0x42; 32]));
    m.extend(hdr(UINT, 2));
    let mut rp = hdr(MAP, 1);
    rp.extend(tstr("id"));
    rp.extend(tstr("example.com"));
    m.extend(rp);
    m.extend(hdr(UINT, 3));
    let mut u = hdr(MAP, 1);
    u.extend(tstr("id"));
    u.extend(bstr(&[0x01; 16]));
    m.extend(u);
    m.extend(hdr(UINT, 4));
    let mut arr = hdr(ARRAY, 1);
    let mut e = hdr(MAP, 2);
    e.extend(tstr("alg"));
    e.extend(nint(-7));
    e.extend(tstr("type"));
    e.extend(tstr("public-key"));
    arr.extend(e);
    m.extend(arr);
    m.extend(hdr(UINT, 5));
    m.extend(tstr("not-a-list"));
    let mut req = [0u8; REQ_LEN];
    let e = ctapreq::parse_make_credential(&msg(vec![m]), None, &mut req, &mut never_ours)
        .expect_err("an excludeList that is a text string was accepted");
    assert_eq!(e, CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
}

#[test]
fn a_declared_array_count_far_larger_than_the_data_is_refused() {
    // The count is the attacker's field. A parser that trusted it would
    // walk off the end of the message.
    let mut m = hdr(MAP, 2);
    m.extend(hdr(UINT, 1));
    m.extend(bstr(&[0x42; 32]));
    m.extend(hdr(UINT, 4));
    m.extend(hdr(ARRAY, u64::MAX)); // and then nothing
    let r = parse_mc(&msg(vec![m]));
    assert!(
        r.is_err(),
        "an array claiming u64::MAX entries was accepted"
    );
}

// ---------- GetAssertion ----------

#[test]
fn get_assertion_requires_both_rp_and_client_data_hash() {
    let mut req = [0u8; REQ_LEN];

    let mut m = hdr(MAP, 1);
    m.extend(hdr(UINT, 1));
    m.extend(tstr("example.com"));
    assert!(
        ctapreq::parse_get_assertion(&msg(vec![m]), &mut req, &mut |_, _| 1u8).is_err(),
        "GetAssertion with no clientDataHash was accepted"
    );

    let mut m = hdr(MAP, 1);
    m.extend(hdr(UINT, 2));
    m.extend(bstr(&[0x42; 32]));
    assert!(
        ctapreq::parse_get_assertion(&msg(vec![m]), &mut req, &mut |_, _| 1u8).is_err(),
        "GetAssertion with no rpId was accepted"
    );
}

#[test]
fn get_assertion_accepts_a_well_formed_request() {
    let mut m = hdr(MAP, 2);
    m.extend(hdr(UINT, 1));
    m.extend(tstr("example.com"));
    m.extend(hdr(UINT, 2));
    m.extend(bstr(&[0x42; 32]));
    let mut req = [0u8; REQ_LEN];
    ctapreq::parse_get_assertion(&msg(vec![m]), &mut req, &mut |_, _| 1u8)
        .expect("a valid request was rejected");
    assert_eq!(&req[REQ_OFF_RP..REQ_OFF_RP + 11], b"example.com");
    assert_eq!(&req[REQ_OFF_CDH..REQ_OFF_CDH + 32], &[0x42u8; 32]);
}

#[test]
fn get_assertion_refuses_every_truncation() {
    let mut m = hdr(MAP, 2);
    m.extend(hdr(UINT, 1));
    m.extend(tstr("example.com"));
    m.extend(hdr(UINT, 2));
    m.extend(bstr(&[0x42; 32]));
    let full = msg(vec![m]);
    for n in 1..full.len() {
        let mut req = [0u8; REQ_LEN];
        assert!(
            ctapreq::parse_get_assertion(&full[..n], &mut req, &mut |_, _| 1u8).is_err(),
            "GetAssertion truncated to {n} bytes parsed as valid"
        );
    }
}

// ---------- the other three parsers ----------

#[test]
fn cred_mgmt_config_and_client_pin_all_refuse_a_non_map() {
    // Each takes a CBOR map. Handed something else -- here a byte
    // string, which a fuzzer finds immediately -- they must refuse
    // rather than read a length out of it.
    let junk = msg(vec![bstr(&[0xFF; 8])]);
    let mut cm = [0u8; CM_REQ_LEN];
    assert!(ctapreq::parse_cred_mgmt(&junk, &mut cm).is_err());
    let mut cfg = [0u8; CONFIG_REQ_LEN];
    assert!(ctapreq::parse_config(&junk, &mut cfg).is_err());
    let mut pin = [0u8; PIN_REQ_LEN];
    assert!(ctapreq::parse_client_pin(&junk, &mut pin).is_err());
}

#[test]
fn no_parser_panics_on_an_empty_or_one_byte_message() {
    // The parsers all index `&msg[1..]`. A one-byte message makes that
    // an empty slice, and a zero-byte one would panic on the slice
    // itself if anything indexed before checking.
    for m in [vec![0x01u8], vec![0x0Au8], vec![0x06u8]] {
        let mut req = [0u8; REQ_LEN];
        let _ = ctapreq::parse_make_credential(&m, None, &mut req, &mut never_ours);
        let _ = ctapreq::parse_get_assertion(&m, &mut req, &mut |_, _| 1u8);
        let mut cm = [0u8; CM_REQ_LEN];
        let _ = ctapreq::parse_cred_mgmt(&m, &mut cm);
        let mut cfg = [0u8; CONFIG_REQ_LEN];
        let _ = ctapreq::parse_config(&m, &mut cfg);
        let mut pin = [0u8; PIN_REQ_LEN];
        let _ = ctapreq::parse_client_pin(&m, &mut pin);
    }
}

#[test]
fn every_parser_survives_a_sweep_of_mutated_valid_requests() {
    // Not a fuzzer, but the same idea cheaply: take a valid request and
    // corrupt one byte at a time. None may panic. Anything that parses
    // is fine; anything that returns an error is fine; a panic in the
    // Non-secure world is a denial of service reachable by any host.
    let full = good_make_cred();
    for i in 0..full.len() {
        for delta in [0x01u8, 0x7F, 0xFF] {
            let mut m = full.clone();
            m[i] ^= delta;
            let mut req = [0u8; REQ_LEN];
            let _ = ctapreq::parse_make_credential(&m, None, &mut req, &mut never_ours);
        }
    }
}

// ---------- allowList: every entry, and only an array ----------
//
// Two defects, both in the same parameter.
//
// The loop took the first id that was 64 bytes long and stopped, and the
// Secure side then tried that one id exactly once. A relying party lists
// a user's credentials in its own order, so if the first belonged to
// another authenticator -- or was one this token minted before a reset
// rotated its keys -- it was the only one tried and a credential listed
// second was unreachable. Both other ports loop until one recovers.
//
// And a key 0x03 that was present but not an array read as absent, which
// sent the request into discoverable-credential selection: the token
// signed with whichever resident credential it held for that rpId rather
// than the one the relying party named.

/// A GetAssertion carrying `ids` as its allowList.
fn ga_with_allow(ids: &[Vec<u8>]) -> Vec<u8> {
    let mut m = hdr(MAP, 3);
    m.extend(hdr(UINT, 1));
    m.extend(tstr("example.com"));
    m.extend(hdr(UINT, 2));
    m.extend(bstr(&[0x42; 32]));
    m.extend(hdr(UINT, 3));
    m.extend(hdr(ARRAY, ids.len() as u64));
    for id in ids {
        m.extend(hdr(MAP, 2));
        m.extend(tstr("id"));
        m.extend(bstr(id));
        m.extend(tstr("type"));
        m.extend(tstr("public-key"));
    }
    msg(vec![m])
}

fn id_of(n: u8) -> Vec<u8> {
    let mut v = vec![0u8; 64];
    v[0] = n;
    v
}

#[test]
fn a_credential_listed_after_one_that_is_not_ours_is_still_found() {
    // The defect. Three entries, ours is last.
    let mut req = [0u8; REQ_LEN];
    let mut asked: Vec<u8> = Vec::new();
    ctapreq::parse_get_assertion(
        &ga_with_allow(&[id_of(1), id_of(2), id_of(3)]),
        &mut req,
        &mut |_rp, id| {
            asked.push(id[0]);
            u8::from(id[0] == 3)
        },
    )
    .expect("a request naming one of our credentials was refused");
    assert_eq!(
        asked,
        vec![1, 2, 3],
        "entries were not tried in order until one matched"
    );
    assert_eq!(
        req[REQ_OFF_CRED], 3,
        "the wrong allowList entry was selected"
    );
}

#[test]
fn the_walk_stops_at_the_first_match() {
    // Order matters: the relying party's first usable entry is the one
    // to sign with, and asking about the rest would be wasted veneer
    // calls on a token that has already answered.
    let mut req = [0u8; REQ_LEN];
    let mut asked = 0;
    ctapreq::parse_get_assertion(
        &ga_with_allow(&[id_of(7), id_of(8), id_of(9)]),
        &mut req,
        &mut |_rp, _id| {
            asked += 1;
            1u8
        },
    )
    .expect("valid request refused");
    assert_eq!(asked, 1, "kept asking after a match");
    assert_eq!(req[REQ_OFF_CRED], 7);
}

#[test]
fn an_allow_list_naming_nothing_of_ours_is_a_miss_not_a_discovery() {
    // A list was given and held none of our credentials. That is
    // NO_CREDENTIALS -- never a fall-through to whatever resident
    // credential the token has for this relying party.
    let mut req = [0u8; REQ_LEN];
    let e = ctapreq::parse_get_assertion(
        &ga_with_allow(&[id_of(1), id_of(2)]),
        &mut req,
        &mut |_, _| 0u8,
    )
    .expect_err("an allowList naming nothing of ours was accepted");
    assert_eq!(e, CTAP2_ERR_NO_CREDENTIALS);
}

#[test]
fn entries_of_the_wrong_length_are_skipped_not_asked_about() {
    // A credential id this token issues is 64 bytes. A shorter one
    // cannot be ours, and handing it to the gateway would be a pointless
    // crossing of the boundary with attacker-chosen length.
    let mut req = [0u8; REQ_LEN];
    let mut asked: Vec<usize> = Vec::new();
    ctapreq::parse_get_assertion(
        &ga_with_allow(&[vec![9u8; 16], vec![9u8; 65], id_of(4)]),
        &mut req,
        &mut |_rp, id| {
            asked.push(id.len());
            u8::from(id[0] == 4)
        },
    )
    .expect("a valid entry after two malformed ones was not found");
    assert_eq!(
        asked,
        vec![64],
        "a wrong-length id was passed to the gateway"
    );
    assert_eq!(req[REQ_OFF_CRED], 4);
}

#[test]
fn the_relying_party_id_reaches_the_predicate() {
    // The gateway checks the id against this rpId. Passing the wrong one
    // -- or an empty slice -- would make every entry look foreign.
    let mut req = [0u8; REQ_LEN];
    let mut seen: Vec<u8> = Vec::new();
    let _ = ctapreq::parse_get_assertion(&ga_with_allow(&[id_of(1)]), &mut req, &mut |rp, _| {
        seen.extend_from_slice(rp);
        1u8
    });
    assert_eq!(
        seen,
        b"example.com".to_vec(),
        "the predicate got the wrong rpId"
    );
}

#[test]
fn an_allow_list_that_is_not_an_array_is_refused() {
    // Present but the wrong type. Reading it as absent is what made the
    // token answer from its resident store instead.
    let mut req = [0u8; REQ_LEN];
    for (name, v) in [
        ("a text string", tstr("x")),
        ("a byte string", bstr(&[1, 2, 3])),
        ("an integer", hdr(UINT, 4)),
        ("a map", {
            let mut m = hdr(MAP, 1);
            m.extend(tstr("id"));
            m.extend(bstr(&[7; 64]));
            m
        }),
    ] {
        let mut m = hdr(MAP, 3);
        m.extend(hdr(UINT, 1));
        m.extend(tstr("example.com"));
        m.extend(hdr(UINT, 2));
        m.extend(bstr(&[0x42; 32]));
        m.extend(hdr(UINT, 3));
        m.extend(v);
        let e = ctapreq::parse_get_assertion(&msg(vec![m]), &mut req, &mut |_, _| 1u8)
            .expect_err(&format!("an allowList that is {name} was accepted"));
        assert_eq!(
            e, CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
            "an allowList that is {name} gave {e:#04x}"
        );
    }
}

#[test]
fn an_empty_allow_list_still_falls_through_to_discovery() {
    // CTAP 2.1 sec. 6.2 branches on "present and non-empty", so an empty
    // array is the one non-absent value that legitimately means
    // discovery. Refusing it would break a client that sends `[]`.
    let mut req = [0u8; REQ_LEN];
    ctapreq::parse_get_assertion(&ga_with_allow(&[]), &mut req, &mut |_, _| 1u8)
        .expect("an empty allowList was refused");
    assert_eq!(
        req[REQ_OFF_FLAGS] & 0x08,
        0,
        "an empty allowList set the have-list flag"
    );
}

// ---------- the three parsers that had only ever seen junk ----------
//
// parse_cred_mgmt, parse_config and parse_client_pin were handed a byte
// string and asserted to refuse it, and handed a one-byte message and
// asserted not to panic. Nothing ever gave them a VALID request. A
// parser that returned Err for everything would have passed both of
// those, and the three of them are what fills the fixed-layout arrays
// the Secure gateways read by offset -- so a field landing in the wrong
// place is a field Secure reads as something else entirely.
//
// These check that a well-formed request parses AND that each value
// arrives at the offset the other side expects.

#[test]
fn cred_mgmt_parses_a_valid_request_into_the_right_offsets() {
    // enumerateCredentialsBegin: subCommand 0x04, params {1: rpIdHash},
    // with a pinUvAuthParam. The rpIdHash is what selects which relying
    // party's credentials get enumerated.
    let rp_hash = [0x5Au8; 32];
    let auth = [0xC3u8; 16];
    let mut m = hdr(MAP, 4);
    m.extend(hdr(UINT, 1));
    m.extend(hdr(UINT, 4)); // subCommand
    m.extend(hdr(UINT, 2)); // subCommandParams
    let mut params = hdr(MAP, 1);
    params.extend(hdr(UINT, 1));
    params.extend(bstr(&rp_hash));
    m.extend(params);
    m.extend(hdr(UINT, 3));
    m.extend(hdr(UINT, 1)); // pinUvAuthProtocol
    m.extend(hdr(UINT, 4));
    m.extend(bstr(&auth));

    let mut cm = [0u8; CM_REQ_LEN];
    ctapreq::parse_cred_mgmt(&msg(vec![m]), &mut cm)
        .expect("a valid credentialManagement request was refused");
    assert_eq!(cm[CM_OFF_SUB], 4, "subCommand landed wrong");
    assert_eq!(
        cm[CM_OFF_HAVE_RP], 1,
        "the rpIdHash was not recorded as present"
    );
    assert_eq!(
        &cm[CM_OFF_RP_HASH..CM_OFF_RP_HASH + 32],
        &rp_hash,
        "rpIdHash landed wrong"
    );
    assert_eq!(
        cm[CM_OFF_AUTH_LEN] as usize,
        auth.len(),
        "pinUvAuthParam length"
    );
    assert_eq!(
        &cm[CM_OFF_AUTH..CM_OFF_AUTH + auth.len()],
        &auth,
        "pinUvAuthParam landed wrong"
    );
}

#[test]
fn cred_mgmt_carries_a_credential_id_for_delete() {
    // deleteCredential: subCommand 0x06, params {2: {id, type}}. The
    // have-flag matters as much as the bytes -- Secure refuses the
    // subcommand outright when it is clear.
    let id = [0x77u8; 64];
    let mut m = hdr(MAP, 2);
    m.extend(hdr(UINT, 1));
    m.extend(hdr(UINT, 6));
    m.extend(hdr(UINT, 2));
    let mut params = hdr(MAP, 1);
    params.extend(hdr(UINT, 2));
    let mut desc = hdr(MAP, 2);
    desc.extend(tstr("id"));
    desc.extend(bstr(&id));
    desc.extend(tstr("type"));
    desc.extend(tstr("public-key"));
    params.extend(desc);
    m.extend(params);

    let mut cm = [0u8; CM_REQ_LEN];
    ctapreq::parse_cred_mgmt(&msg(vec![m]), &mut cm).expect("a valid delete was refused");
    assert_eq!(cm[CM_OFF_SUB], 6);
    assert_eq!(
        cm[CM_OFF_HAVE_CRED], 1,
        "the credential id was not recorded as present"
    );
    assert_eq!(
        &cm[CM_OFF_CRED..CM_OFF_CRED + 64],
        &id,
        "credential id landed wrong"
    );
}

#[test]
fn config_parses_set_min_pin_length_into_the_right_offsets() {
    // setMinPINLength with all three parameters: the new minimum, the
    // relying parties allowed to learn it, and forceChangePin.
    let mut m = hdr(MAP, 2);
    m.extend(hdr(UINT, 1));
    m.extend(hdr(UINT, 3)); // subCommand setMinPINLength
    m.extend(hdr(UINT, 2));
    let mut params = hdr(MAP, 3);
    params.extend(hdr(UINT, 1));
    params.extend(hdr(UINT, 8)); // newMinPINLength
    params.extend(hdr(UINT, 2));
    let mut rps = hdr(ARRAY, 2);
    rps.extend(tstr("one.example"));
    rps.extend(tstr("two.example"));
    params.extend(rps);
    params.extend(hdr(UINT, 3));
    params.extend(vec![0xF5]); // forceChangePin: true
    m.extend(params);

    let mut cfg = [0u8; CONFIG_REQ_LEN];
    ctapreq::parse_config(&msg(vec![m]), &mut cfg).expect("a valid config request was refused");
    assert_eq!(cfg[CFG_OFF_SUB], 3, "subCommand landed wrong");
    assert_eq!(cfg[CFG_OFF_NEW_LEN], 8, "newMinPINLength landed wrong");
    assert_eq!(
        cfg[CFG_OFF_FORCE], 2,
        "forceChangePin true should encode as 2"
    );
    assert_eq!(cfg[CFG_OFF_RP_COUNT], 2, "wrong rpId count");
    assert_eq!(cfg[CFG_OFF_RPS] as usize, "one.example".len());
    assert_eq!(
        &cfg[CFG_OFF_RPS + 1..CFG_OFF_RPS + 1 + 11],
        b"one.example",
        "the first rpId landed wrong"
    );
    assert_eq!(
        &cfg[CFG_OFF_RPS + 129 + 1..CFG_OFF_RPS + 129 + 1 + 11],
        b"two.example",
        "the second rpId is not one stride along"
    );
}

#[test]
fn config_distinguishes_force_change_false_from_absent() {
    // The offset carries three states, and collapsing false into absent
    // would make "stop forcing a change" unsayable.
    let build = |force: Option<bool>| {
        let mut m = hdr(MAP, 2);
        m.extend(hdr(UINT, 1));
        m.extend(hdr(UINT, 3));
        m.extend(hdr(UINT, 2));
        let n = if force.is_some() { 2 } else { 1 };
        let mut params = hdr(MAP, n);
        params.extend(hdr(UINT, 1));
        params.extend(hdr(UINT, 6));
        if let Some(f) = force {
            params.extend(hdr(UINT, 3));
            params.extend(vec![if f { 0xF5 } else { 0xF4 }]);
        }
        m.extend(params);
        msg(vec![m])
    };
    for (force, want) in [(None, 0u8), (Some(false), 1), (Some(true), 2)] {
        let mut cfg = [0u8; CONFIG_REQ_LEN];
        ctapreq::parse_config(&build(force), &mut cfg).expect("refused");
        assert_eq!(
            cfg[CFG_OFF_FORCE], want,
            "forceChangePin {force:?} encoded wrong"
        );
    }
}

#[test]
fn client_pin_parses_a_set_pin_request_into_the_right_offsets() {
    // The one that matters most: every field here feeds the PIN
    // protocol, and a key-agreement coordinate landing at the wrong
    // offset produces a shared secret that silently does not match.
    let kx = [0x11u8; 32];
    let ky = [0x22u8; 32];
    let auth = [0x33u8; 16];
    let new_pin = [0x44u8; 64];
    let hash = [0x55u8; 16];

    let mut m = hdr(MAP, 6);
    m.extend(hdr(UINT, 1));
    m.extend(hdr(UINT, 1)); // pinUvAuthProtocol
    m.extend(hdr(UINT, 2));
    m.extend(hdr(UINT, 3)); // subCommand setPIN
    m.extend(hdr(UINT, 3)); // keyAgreement COSE_Key
    let mut cose = hdr(MAP, 2);
    cose.extend(nint(-2));
    cose.extend(bstr(&kx));
    cose.extend(nint(-3));
    cose.extend(bstr(&ky));
    m.extend(cose);
    m.extend(hdr(UINT, 4));
    m.extend(bstr(&auth));
    m.extend(hdr(UINT, 5));
    m.extend(bstr(&new_pin));
    m.extend(hdr(UINT, 6));
    m.extend(bstr(&hash));

    let mut pin = [0u8; PIN_REQ_LEN];
    ctapreq::parse_client_pin(&msg(vec![m]), &mut pin)
        .expect("a valid clientPIN request was refused");
    assert_eq!(pin[PIN_OFF_PROTO], 1, "protocol landed wrong");
    assert_eq!(pin[PIN_OFF_SUB], 3, "subCommand landed wrong");
    assert_eq!(
        pin[PIN_OFF_FLAGS] & 0x01,
        0x01,
        "keyAgreement not flagged present"
    );
    assert_eq!(
        &pin[PIN_OFF_KX..PIN_OFF_KX + 32],
        &kx,
        "the x coordinate landed wrong"
    );
    assert_eq!(
        &pin[PIN_OFF_KY..PIN_OFF_KY + 32],
        &ky,
        "the y coordinate landed wrong"
    );
    assert_eq!(pin[PIN_OFF_AUTH_LEN] as usize, auth.len());
    assert_eq!(&pin[PIN_OFF_AUTH..PIN_OFF_AUTH + auth.len()], &auth);
    assert_eq!(pin[PIN_OFF_NEW_LEN] as usize, new_pin.len());
    assert_eq!(&pin[PIN_OFF_NEW..PIN_OFF_NEW + new_pin.len()], &new_pin);
    assert_eq!(pin[PIN_OFF_HASH_LEN] as usize, hash.len());
    assert_eq!(&pin[PIN_OFF_HASH..PIN_OFF_HASH + hash.len()], &hash);
}

#[test]
fn client_pin_does_not_confuse_the_two_key_agreement_coordinates() {
    // -2 is x and -3 is y. Swapping them yields a valid-looking point
    // that agrees with nothing, and the failure surfaces as a PIN that
    // is simply always wrong.
    let kx = [0xAAu8; 32];
    let ky = [0xBBu8; 32];
    let mut m = hdr(MAP, 2);
    m.extend(hdr(UINT, 2));
    m.extend(hdr(UINT, 2)); // subCommand: required, or the parser refuses
    m.extend(hdr(UINT, 3));
    let mut cose = hdr(MAP, 2);
    cose.extend(nint(-3)); // y FIRST, to check the label and not the order
    cose.extend(bstr(&ky));
    cose.extend(nint(-2));
    cose.extend(bstr(&kx));
    m.extend(cose);
    let mut pin = [0u8; PIN_REQ_LEN];
    ctapreq::parse_client_pin(&msg(vec![m]), &mut pin).expect("refused");
    assert_eq!(
        &pin[PIN_OFF_KX..PIN_OFF_KX + 32],
        &kx,
        "x taken from the -3 label"
    );
    assert_eq!(
        &pin[PIN_OFF_KY..PIN_OFF_KY + 32],
        &ky,
        "y taken from the -2 label"
    );
}

#[test]
fn client_pin_refuses_a_key_agreement_coordinate_of_the_wrong_length() {
    // A short coordinate would be zero-extended into a different point.
    for len in [0usize, 31, 33, 64] {
        let mut m = hdr(MAP, 2);
        m.extend(hdr(UINT, 2));
        m.extend(hdr(UINT, 2)); // subCommand
        m.extend(hdr(UINT, 3));
        let mut cose = hdr(MAP, 2);
        cose.extend(nint(-2));
        cose.extend(bstr(&vec![0xAAu8; len]));
        cose.extend(nint(-3));
        cose.extend(bstr(&[0xBBu8; 32]));
        m.extend(cose);
        let mut pin = [0u8; PIN_REQ_LEN];
        assert!(
            ctapreq::parse_client_pin(&msg(vec![m]), &mut pin).is_err(),
            "a {len}-byte x coordinate was accepted"
        );
    }
}

#[test]
fn parse_extensions_is_reachable_and_records_what_it_reads() {
    // Never called directly by any test before this. It runs on both
    // MakeCredential (key 6) and GetAssertion (key 4), and it is what
    // decides whether credProtect, credBlob and minPinLength are
    // honoured -- credProtect being the one that now gates assertions.
    let mut ext = hdr(MAP, 3);
    ext.extend(tstr("credProtect"));
    ext.extend(hdr(UINT, 3));
    ext.extend(tstr("credBlob"));
    ext.extend(bstr(&[0x9Au8; 16]));
    ext.extend(tstr("minPinLength"));
    ext.extend(vec![0xF5]);

    let mut req = [0u8; REQ_LEN];
    let mut r = pqf_fw_secure_hosttest::cborr::Reader::new(&ext);
    ctapreq::parse_extensions(&mut r, &mut req).expect("a valid extensions map was refused");
    assert_eq!(req[REQ_OFF_CRED_PROTECT], 3, "credProtect did not land");
    assert_eq!(req[REQ_OFF_BLOB_LEN], 16, "credBlob length did not land");
    assert_eq!(
        &req[REQ_OFF_BLOB..REQ_OFF_BLOB + 16],
        &[0x9Au8; 16],
        "credBlob bytes"
    );
    assert_ne!(req[REQ_OFF_FLAGS] & 0x10, 0, "minPinLength was not flagged");
}

#[test]
fn parse_extensions_refuses_a_credprotect_level_outside_one_to_three() {
    // The level gates assertions now. A value outside 1..=3 has no
    // defined meaning, and storing it would make usable_for fall through
    // to its permissive arm.
    for bad in [0u64, 4, 255] {
        let mut ext = hdr(MAP, 1);
        ext.extend(tstr("credProtect"));
        ext.extend(hdr(UINT, bad));
        let mut req = [0u8; REQ_LEN];
        let mut r = pqf_fw_secure_hosttest::cborr::Reader::new(&ext);
        let res = ctapreq::parse_extensions(&mut r, &mut req);
        assert!(
            res.is_err() || req[REQ_OFF_CRED_PROTECT] == 0,
            "credProtect {bad} was stored as a policy level"
        );
    }
}

// ---------- pinUvAuthParam: present, empty, over-long ----------

fn mc_with_puat(puat: Option<&[u8]>) -> Vec<u8> {
    let n = 4 + usize::from(puat.is_some());
    let mut m = hdr(MAP, n as u64);
    m.extend(hdr(UINT, 1));
    m.extend(bstr(&[0x42; 32]));
    m.extend(hdr(UINT, 2));
    let mut rp = hdr(MAP, 1);
    rp.extend(tstr("id"));
    rp.extend(tstr("example.com"));
    m.extend(rp);
    m.extend(hdr(UINT, 3));
    let mut u = hdr(MAP, 1);
    u.extend(tstr("id"));
    u.extend(bstr(&[0x01; 16]));
    m.extend(u);
    m.extend(hdr(UINT, 4));
    let mut arr = hdr(ARRAY, 1);
    let mut e = hdr(MAP, 2);
    e.extend(tstr("alg"));
    e.extend(nint(-7));
    e.extend(tstr("type"));
    e.extend(tstr("public-key"));
    arr.extend(e);
    m.extend(arr);
    if let Some(p) = puat {
        m.extend(hdr(UINT, 8));
        m.extend(bstr(p));
    }
    msg(vec![m])
}

#[test]
fn an_empty_pin_uv_auth_param_is_recorded_as_present() {
    // The PIN probe. Length zero, but PRESENT -- and that bit is the
    // whole difference between answering the probe and serving it.
    let mut req = [0u8; REQ_LEN];
    parse_make_credential(&mc_with_puat(Some(&[])), None, &mut req, &mut never_ours)
        .expect("refused");
    assert_ne!(
        req[REQ_OFF_FLAGS] & FLAG_PUAT_PRESENT,
        0,
        "an empty pinUvAuthParam was not flagged present"
    );
    assert_eq!(req[REQ_OFF_FLAGS] & FLAG_PUAT_MALFORMED, 0);
    assert_eq!(req[REQ_OFF_PUAT_LEN], 0);
}

#[test]
fn an_absent_pin_uv_auth_param_is_not_flagged() {
    let mut req = [0u8; REQ_LEN];
    parse_make_credential(&mc_with_puat(None), None, &mut req, &mut never_ours).expect("refused");
    assert_eq!(
        req[REQ_OFF_FLAGS] & (FLAG_PUAT_PRESENT | FLAG_PUAT_MALFORMED),
        0
    );
}

#[test]
fn an_over_long_pin_uv_auth_param_is_flagged_malformed_not_dropped() {
    let mut req = [0u8; REQ_LEN];
    parse_make_credential(
        &mc_with_puat(Some(&[0xAB; 40])),
        None,
        &mut req,
        &mut never_ours,
    )
    .expect("refused");
    assert_ne!(req[REQ_OFF_FLAGS] & FLAG_PUAT_PRESENT, 0);
    assert_ne!(
        req[REQ_OFF_FLAGS] & FLAG_PUAT_MALFORMED,
        0,
        "a 40-byte param was silently dropped"
    );
}

#[test]
fn a_real_sized_pin_uv_auth_param_is_present_and_carried() {
    let mut req = [0u8; REQ_LEN];
    parse_make_credential(
        &mc_with_puat(Some(&[0xCD; 16])),
        None,
        &mut req,
        &mut never_ours,
    )
    .expect("refused");
    assert_ne!(req[REQ_OFF_FLAGS] & FLAG_PUAT_PRESENT, 0);
    assert_eq!(req[REQ_OFF_FLAGS] & FLAG_PUAT_MALFORMED, 0);
    assert_eq!(req[REQ_OFF_PUAT_LEN], 16);
    assert_eq!(&req[REQ_OFF_PUAT..REQ_OFF_PUAT + 16], &[0xCD; 16]);
}

// ---------- the second allowList candidate ----------

#[test]
fn a_level_three_credential_listed_first_does_not_hide_a_usable_one() {
    // The predicate returns 1 + credProtect level. Entry 1 is ours at
    // level 3 (4), entry 2 is ours at level 1 (2). Both must cross the
    // boundary so Secure can pick once it knows whether UV happened.
    let mut req = [0u8; REQ_LEN];
    ctapreq::parse_get_assertion(
        &ga_with_allow(&[id_of(9), id_of(1), id_of(2)]),
        &mut req,
        &mut |_rp, id| match id[0] {
            1 => 4,
            2 => 2,
            _ => 0,
        },
    )
    .expect("refused");
    assert_eq!(
        req[REQ_OFF_CRED], 1,
        "the first of ours is still the primary"
    );
    assert_eq!(
        req[REQ_OFF_HAVE_CRED2], 1,
        "no second candidate was carried"
    );
    assert_eq!(
        req[REQ_OFF_CRED2], 2,
        "the wrong entry was carried as the second candidate"
    );
}

#[test]
fn no_second_candidate_when_the_first_is_usable_without_uv() {
    let mut req = [0u8; REQ_LEN];
    ctapreq::parse_get_assertion(
        &ga_with_allow(&[id_of(1), id_of(2)]),
        &mut req,
        &mut |_rp, id| match id[0] {
            1 => 2,
            2 => 2,
            _ => 0,
        },
    )
    .expect("refused");
    assert_eq!(req[REQ_OFF_CRED], 1);
    assert_eq!(
        req[REQ_OFF_HAVE_CRED2], 0,
        "a second candidate was carried needlessly"
    );
}

#[test]
fn a_second_level_three_entry_is_not_offered_as_the_fallback() {
    // Two level-3 credentials and nothing usable without UV: the primary
    // stays, no fallback -- Secure will refuse without UV, correctly.
    let mut req = [0u8; REQ_LEN];
    ctapreq::parse_get_assertion(
        &ga_with_allow(&[id_of(1), id_of(2)]),
        &mut req,
        &mut |_rp, id| match id[0] {
            1 | 2 => 4,
            _ => 0,
        },
    )
    .expect("refused");
    assert_eq!(req[REQ_OFF_CRED], 1);
    assert_eq!(req[REQ_OFF_HAVE_CRED2], 0);
}
