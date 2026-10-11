// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Credential management -- phase 5 of the CTAP2 surface.
//!
//! 627 lines. This is how a browser shows a user their passkeys and how
//! they delete one, so it enumerates and destroys the most sensitive
//! state on the device. Every subcommand is behind a `pinUvAuthToken`
//! carrying the `cm` permission; the stateful `GetNext` flows are not,
//! because they ride the iterator their `Begin` set up.
//!
//! Requests here are framed as CTAP 2.1 numbers them. That was not
//! always true: `pinUvAuthProtocol` and `pinUvAuthParam` were swapped,
//! which made the whole command unreachable by any client but our own.

use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

use fw::client_pin::{
    PERM_CREDENTIAL_MGMT, PERM_GET_ASSERTION, PERM_LARGE_BLOB_WRITE, PERM_MAKE_CREDENTIAL,
};
use fw::ctap2::{CTAP2_CREDENTIAL_MANAGEMENT as CM, CTAP2_GET_ASSERTION, CTAP2_OK};
use fw::testclient::{auth_param, Device, TEST_PIN};

const ERR_INVALID_SUBCOMMAND: u8 = 0x3e;
const ERR_NO_CREDENTIALS: u8 = 0x2e;
const ERR_NOT_ALLOWED: u8 = 0x30;
const ERR_PIN_AUTH_INVALID: u8 = 0x33;
const ERR_PUAT_REQUIRED: u8 = 0x36;

const METADATA: u64 = 0x01;
const RPS_BEGIN: u64 = 0x02;
const RPS_NEXT: u64 = 0x03;
const CREDS_BEGIN: u64 = 0x04;
const CREDS_NEXT: u64 = 0x05;
const DELETE: u64 = 0x06;
const UPDATE_USER: u64 = 0x07;

const RP_A: &str = "a.example";
const RP_B: &str = "b.example";

/// A token that can both register and manage -- most tests need both.
fn manager() -> Device {
    Device::authenticated(
        (PERM_CREDENTIAL_MGMT | PERM_MAKE_CREDENTIAL | PERM_GET_ASSERTION) as u64,
        None,
    )
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}
fn rp_hash_param(rp: &str) -> Value {
    Value::Map(vec![(
        Value::Uint(1),
        Value::Bytes(fw::bc_crypto::sha256(rp.as_bytes()).to_vec()),
    )])
}
fn cred_param(id: &[u8]) -> Value {
    Value::Map(vec![(
        Value::Uint(2),
        Value::Map(vec![(text("id"), Value::Bytes(id.to_vec()))]),
    )])
}
fn uint(resp: &[u8], key: u64) -> u64 {
    match Device::field(resp, key) {
        Some(Value::Uint(n)) => n,
        other => panic!("field {key:#04x} is {other:?}, not an integer"),
    }
}
fn bytes(resp: &[u8], key: u64) -> Vec<u8> {
    match Device::field(resp, key) {
        Some(Value::Bytes(b)) => b,
        other => panic!("field {key:#04x} is {other:?}, not a byte string"),
    }
}
/// A named text field out of a nested map in the response.
fn nested_text(resp: &[u8], key: u64, name: &str) -> Option<String> {
    match Device::field(resp, key)? {
        Value::Map(m) => m.iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(a), Value::Text(b)) if a == name => Some(b.clone()),
            _ => None,
        }),
        _ => None,
    }
}

// ---- the authentication gate -----------------------------------------

#[test]
fn a_request_with_no_token_is_refused() {
    // Every subcommand but the two GetNext flows needs a freshly
    // verified param. Without the gate, anything that can open a CTAPHID
    // channel could enumerate and delete the user's passkeys.
    let mut d = manager();
    for sub in [METADATA, RPS_BEGIN, CREDS_BEGIN, DELETE, UPDATE_USER] {
        let r = d.send(CM, &Value::Map(vec![(Value::Uint(1), Value::Uint(sub))]));
        assert_eq!(
            r[0], ERR_PUAT_REQUIRED,
            "subcommand {sub:#04x} ran with no pinUvAuthParam"
        );
    }
}

#[test]
fn a_forged_auth_param_is_refused() {
    let mut d = manager();
    for forged in [vec![0u8; 16], vec![0xff; 16], vec![], vec![0u8; 32]] {
        let r = d.send(
            CM,
            &Value::Map(vec![
                (Value::Uint(1), Value::Uint(METADATA)),
                (Value::Uint(3), Value::Uint(1)),
                (Value::Uint(4), Value::Bytes(forged.clone())),
            ]),
        );
        assert_eq!(
            r[0], ERR_PIN_AUTH_INVALID,
            "auth param {forged:?} was accepted"
        );
    }
}

#[test]
fn a_token_without_the_management_permission_is_refused() {
    // The reason permissions exist. A browser holding a token for
    // assertions must not be able to delete the credentials it just
    // used.
    let mut d = Device::authenticated(PERM_GET_ASSERTION as u64, Some(RP_A));
    assert_eq!(d.subcommand(CM, METADATA, None)[0], ERR_PIN_AUTH_INVALID);
}

#[test]
fn a_token_scoped_to_one_rp_cannot_read_device_wide_state() {
    // getCredsMetadata and enumerateRPs are about the whole device, so
    // sec. 6.8.2 requires an unscoped token. A scoped one would let a single
    // relying party count and list every other site the user has.
    let mut d = Device::authenticated(PERM_CREDENTIAL_MGMT as u64, Some(RP_A));
    assert_eq!(
        d.subcommand(CM, METADATA, None)[0],
        ERR_PIN_AUTH_INVALID,
        "an RP-scoped token read device-wide metadata"
    );
    assert_eq!(
        d.subcommand(CM, RPS_BEGIN, None)[0],
        ERR_PIN_AUTH_INVALID,
        "an RP-scoped token enumerated every relying party"
    );
}

#[test]
fn an_unknown_subcommand_is_refused() {
    let mut d = manager();
    for sub in [0x00u64, 0x08, 0x42, 0xff] {
        assert_eq!(
            d.subcommand(CM, sub, None)[0],
            ERR_INVALID_SUBCOMMAND,
            "subcommand {sub:#04x} was accepted"
        );
    }
}

// ---- metadata ---------------------------------------------------------

#[test]
fn metadata_counts_what_is_stored_and_what_is_left() {
    // A browser shows "3 of 6 used" from these two numbers, and refuses
    // to start a registration it thinks cannot fit.
    let mut d = manager();
    let r = d.subcommand(CM, METADATA, None);
    assert_eq!(r[0], CTAP2_OK);
    let (existing, remaining) = (uint(&r, 0x01), uint(&r, 0x02));
    assert_eq!(existing, 0, "a fresh device claims stored credentials");
    assert!(remaining > 0, "a fresh device claims no room");

    d.register(RP_A, 1, "alice");
    let r = d.subcommand(CM, METADATA, None);
    assert_eq!(uint(&r, 0x01), 1, "the count did not rise");
    assert_eq!(
        uint(&r, 0x02),
        remaining - 1,
        "the remaining count did not fall"
    );

    d.register(RP_B, 2, "bob");
    let r = d.subcommand(CM, METADATA, None);
    assert_eq!(uint(&r, 0x01), 2);
    assert_eq!(uint(&r, 0x02), remaining - 2);
}

// ---- enumerating relying parties -------------------------------------

#[test]
fn enumerating_relying_parties_on_an_empty_device_finds_none() {
    let mut d = manager();
    assert_eq!(d.subcommand(CM, RPS_BEGIN, None)[0], ERR_NO_CREDENTIALS);
}

#[test]
fn every_relying_party_is_enumerated_exactly_once() {
    // The list a browser shows the user. A missing entry hides a passkey
    // they cannot then delete; a duplicate is a confusing lie.
    let mut d = manager();
    d.register(RP_A, 1, "alice");
    d.register(RP_B, 2, "bob");

    let first = d.subcommand(CM, RPS_BEGIN, None);
    assert_eq!(first[0], CTAP2_OK);
    assert_eq!(uint(&first, 0x05), 2, "totalRPs is wrong");

    let second = d.subcommand(CM, RPS_NEXT, None);
    assert_eq!(second[0], CTAP2_OK);

    let mut seen = vec![bytes(&first, 0x04), bytes(&second, 0x04)];
    seen.sort();
    let mut want = vec![
        fw::bc_crypto::sha256(RP_A.as_bytes()).to_vec(),
        fw::bc_crypto::sha256(RP_B.as_bytes()).to_vec(),
    ];
    want.sort();
    assert_eq!(
        seen, want,
        "the enumerated RP hashes are not the ones registered"
    );

    assert_eq!(
        d.subcommand(CM, RPS_NEXT, None)[0],
        ERR_NOT_ALLOWED,
        "the iterator ran past its end"
    );
}

#[test]
fn two_credentials_at_one_relying_party_are_one_entry_in_the_rp_list() {
    // The list is of sites, not credentials. Two accounts at one site
    // must not show as two sites.
    let mut d = manager();
    d.register(RP_A, 1, "alice");
    d.register(RP_A, 2, "bob");
    let r = d.subcommand(CM, RPS_BEGIN, None);
    assert_eq!(r[0], CTAP2_OK);
    assert_eq!(uint(&r, 0x05), 1, "one site was listed twice");
    assert_eq!(d.subcommand(CM, RPS_NEXT, None)[0], ERR_NOT_ALLOWED);
}

#[test]
fn get_next_without_a_begin_is_refused() {
    // GetNext is the one flow that does not reauthenticate, precisely
    // because it rides an iterator. With no iterator there is nothing to
    // ride, and answering would be an unauthenticated read.
    let mut d = manager();
    d.register(RP_A, 1, "alice");
    assert_eq!(d.subcommand(CM, RPS_NEXT, None)[0], ERR_NOT_ALLOWED);
    assert_eq!(d.subcommand(CM, CREDS_NEXT, None)[0], ERR_NOT_ALLOWED);
}

// ---- enumerating credentials -----------------------------------------

#[test]
fn enumerating_credentials_returns_what_a_browser_needs_to_show_them() {
    // user, credentialID and publicKey are what a management UI renders
    // and what it passes back to delete. A missing publicKey is what the
    // C port had to be fixed for.
    let mut d = manager();
    let id = d.register(RP_A, 1, "alice");
    let r = d.subcommand(CM, CREDS_BEGIN, Some(rp_hash_param(RP_A)));
    assert_eq!(r[0], CTAP2_OK);
    assert_eq!(uint(&r, 0x09), 1, "totalCredentials is wrong");
    assert_eq!(
        nested_text(&r, 0x06, "name").as_deref(),
        Some("alice"),
        "the user name did not come back"
    );
    assert!(
        matches!(Device::field(&r, 0x08), Some(Value::Map(_))),
        "no publicKey in the enumeration"
    );
    let listed = match Device::field(&r, 0x07).expect("no credentialID") {
        Value::Map(m) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Text(s), Value::Bytes(b)) if s == "id" => Some(b.clone()),
                _ => None,
            })
            .expect("the credential descriptor has no id"),
        other => panic!("credentialID is {other:?}"),
    };
    assert_eq!(listed, id, "the enumeration named a different credential");
}

#[test]
fn credentials_are_enumerated_per_relying_party() {
    let mut d = manager();
    d.register(RP_A, 1, "alice");
    d.register(RP_A, 2, "bob");
    d.register(RP_B, 3, "carol");

    let r = d.subcommand(CM, CREDS_BEGIN, Some(rp_hash_param(RP_A)));
    assert_eq!(
        uint(&r, 0x09),
        2,
        "the wrong number of credentials for {RP_A}"
    );
    assert_eq!(d.subcommand(CM, CREDS_NEXT, None)[0], CTAP2_OK);
    assert_eq!(d.subcommand(CM, CREDS_NEXT, None)[0], ERR_NOT_ALLOWED);

    let r = d.subcommand(CM, CREDS_BEGIN, Some(rp_hash_param(RP_B)));
    assert_eq!(
        uint(&r, 0x09),
        1,
        "the wrong number of credentials for {RP_B}"
    );
}

#[test]
fn enumerating_a_relying_party_with_nothing_stored_finds_none() {
    // And says so rather than leaking that some *other* site has one.
    let mut d = manager();
    d.register(RP_A, 1, "alice");
    assert_eq!(
        d.subcommand(CM, CREDS_BEGIN, Some(rp_hash_param("unknown.example")))[0],
        ERR_NO_CREDENTIALS
    );
}

// ---- deleting ---------------------------------------------------------

#[test]
fn deleting_a_credential_removes_it_everywhere() {
    // Not just from the enumeration: the credential must stop
    // authenticating. A delete that only hid it from the management UI
    // would leave a live passkey the user believes is gone.
    let mut d = manager();
    let id = d.register(RP_A, 1, "alice");
    let ga = Value::Map(vec![
        (Value::Uint(1), text(RP_A)),
        (Value::Uint(2), Value::Bytes(vec![0x22; 32])),
    ]);
    assert_eq!(
        d.send(CTAP2_GET_ASSERTION, &ga)[0],
        CTAP2_OK,
        "setup: it should work first"
    );

    assert_eq!(d.subcommand(CM, DELETE, Some(cred_param(&id)))[0], CTAP2_OK);
    assert_eq!(d.store.active_count(), 0, "the slot was not freed");
    assert_eq!(
        d.send(CTAP2_GET_ASSERTION, &ga)[0],
        ERR_NO_CREDENTIALS,
        "a deleted credential still authenticates"
    );
    assert_eq!(
        d.subcommand(CM, RPS_BEGIN, None)[0],
        ERR_NO_CREDENTIALS,
        "a deleted credential still appears in the RP list"
    );
}

#[test]
fn deleting_one_credential_leaves_the_others_alone() {
    let mut d = manager();
    let a = d.register(RP_A, 1, "alice");
    d.register(RP_A, 2, "bob");
    d.register(RP_B, 3, "carol");
    assert_eq!(d.subcommand(CM, DELETE, Some(cred_param(&a)))[0], CTAP2_OK);
    assert_eq!(d.store.active_count(), 2, "the wrong number survived");
    let r = d.subcommand(CM, CREDS_BEGIN, Some(rp_hash_param(RP_A)));
    assert_eq!(uint(&r, 0x09), 1);
    let r = d.subcommand(CM, CREDS_BEGIN, Some(rp_hash_param(RP_B)));
    assert_eq!(uint(&r, 0x09), 1, "deleting at one site touched another");
}

#[test]
fn deleting_a_credential_this_token_does_not_hold_finds_nothing() {
    // A well-formed id that this device never minted -- another token's,
    // or a forgery. It must miss, and it must not take something else
    // with it.
    let mut d = manager();
    d.register(RP_A, 1, "alice");
    let len = fw::credential_id::CRED_ID_LEN;
    for forged in [vec![0xABu8; len], vec![0u8; len], vec![0xff; len]] {
        assert_eq!(
            d.subcommand(CM, DELETE, Some(cred_param(&forged)))[0],
            ERR_NO_CREDENTIALS,
            "a foreign credential id was deleted"
        );
    }
    assert_eq!(
        d.store.active_count(),
        1,
        "a foreign delete removed something"
    );
}

#[test]
fn deleting_with_a_malformed_id_is_refused_without_deleting_anything() {
    // Wrong-length and wrong-typed ids are answered
    // CTAP2_ERR_MISSING_PARAMETER rather than "no such credential" --
    // the id is unusable as a lookup key, so the device treats the
    // parameter as absent. Either answer would be defensible; what
    // matters is that nothing is destroyed, and that none of these
    // shapes panics.
    let mut d = manager();
    d.register(RP_A, 1, "alice");
    for bad in [
        Value::Bytes(vec![]),
        Value::Bytes(vec![0u8; 1]),
        Value::Bytes(vec![0u8; 16]),
        Value::Bytes(vec![0u8; 4096]),
        Value::Text("not-an-id".into()),
        Value::Uint(7),
    ] {
        let p = Value::Map(vec![(
            Value::Uint(2),
            Value::Map(vec![(text("id"), bad.clone())]),
        )]);
        let r = d.subcommand(CM, DELETE, Some(p));
        assert_ne!(r[0], CTAP2_OK, "a malformed id {bad:?} reported a deletion");
        assert_eq!(
            d.store.active_count(),
            1,
            "a malformed id {bad:?} deleted something"
        );
    }
}

#[test]
fn deleting_the_same_credential_twice_fails_the_second_time() {
    let mut d = manager();
    let id = d.register(RP_A, 1, "alice");
    assert_eq!(d.subcommand(CM, DELETE, Some(cred_param(&id)))[0], CTAP2_OK);
    assert_eq!(
        d.subcommand(CM, DELETE, Some(cred_param(&id)))[0],
        ERR_NO_CREDENTIALS,
        "a second delete reported success"
    );
}

#[test]
fn a_deleted_slot_is_reusable() {
    // Otherwise a device fills up permanently after enough churn, which
    // is what the compaction path exists to prevent.
    let mut d = manager();
    let before = uint(&d.subcommand(CM, METADATA, None), 0x02);
    let id = d.register(RP_A, 1, "alice");
    assert_eq!(d.subcommand(CM, DELETE, Some(cred_param(&id)))[0], CTAP2_OK);
    assert_eq!(
        uint(&d.subcommand(CM, METADATA, None), 0x02),
        before,
        "the freed slot was not returned to the pool"
    );
}

// ---- updating user information ---------------------------------------

#[test]
fn user_information_can_be_updated_in_place() {
    // A user renames an account and expects the token's own list to
    // agree with the site's.
    let mut d = manager();
    let id = d.register(RP_A, 1, "alice");
    let mut p = match cred_param(&id) {
        Value::Map(m) => m,
        _ => unreachable!(),
    };
    p.push((
        Value::Uint(3),
        Value::Map(vec![
            (text("id"), Value::Bytes(vec![1; 4])),
            (text("name"), text("alice.renamed")),
            (text("displayName"), text("Alice Renamed")),
        ]),
    ));
    p.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
    assert_eq!(
        d.subcommand(CM, UPDATE_USER, Some(Value::Map(p)))[0],
        CTAP2_OK
    );

    let r = d.subcommand(CM, CREDS_BEGIN, Some(rp_hash_param(RP_A)));
    assert_eq!(
        nested_text(&r, 0x06, "name").as_deref(),
        Some("alice.renamed")
    );
    assert_eq!(
        nested_text(&r, 0x06, "displayName").as_deref(),
        Some("Alice Renamed")
    );
    assert_eq!(
        d.store.active_count(),
        1,
        "an update created a second credential"
    );
}

#[test]
fn updating_a_credential_this_token_does_not_hold_finds_nothing() {
    let mut d = manager();
    d.register(RP_A, 1, "alice");
    let mut p = match cred_param(&[0xAB; 161]) {
        Value::Map(m) => m,
        _ => unreachable!(),
    };
    p.push((
        Value::Uint(3),
        Value::Map(vec![(text("name"), text("intruder"))]),
    ));
    p.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
    assert_eq!(
        d.subcommand(CM, UPDATE_USER, Some(Value::Map(p)))[0],
        ERR_NO_CREDENTIALS
    );
    let r = d.subcommand(CM, CREDS_BEGIN, Some(rp_hash_param(RP_A)));
    assert_eq!(nested_text(&r, 0x06, "name").as_deref(), Some("alice"));
}

// ---- the deviation ----------------------------------------------------

#[test]
fn a_spec_conformant_request_is_understood() {
    // This used to record a deviation. CTAP 2.1 sec. 6.8 numbers the
    // parameters subCommand 0x01, subCommandParams 0x02,
    // pinUvAuthProtocol 0x03 (unsigned) and pinUvAuthParam 0x04 (byte
    // string); both firmware ports had the last two the other way round.
    // Because the types differ as well as the keys a conformant request
    // matched neither arm -- protocol and param both stayed absent, every
    // subcommand answered CTAP2_ERR_PUAT_REQUIRED, and getInfo
    // advertised the command as available regardless.
    //
    // Kept rather than deleted: this is the literal request shape a
    // conformant platform sends, built by hand rather than through the
    // shared helper, so it stays a check on the wire format even if that
    // helper changes.
    let mut d = manager();
    let conformant = Value::Map(vec![
        (Value::Uint(1), Value::Uint(METADATA)),
        (Value::Uint(3), Value::Uint(1)),
        (
            Value::Uint(4),
            Value::Bytes(auth_param(&d.token, &[METADATA as u8])),
        ),
    ]);
    let r = d.send(CM, &conformant);
    assert_eq!(r[0], CTAP2_OK, "a spec-conformant request was refused");
    assert_eq!(uint(&r, 0x01), 0, "the metadata response is wrong");
}
#[test]
fn the_pin_used_here_is_the_one_the_harness_documents() {
    // Guards the shared helper rather than the firmware: every test above
    // depends on `authenticated()` having actually set a PIN, and a
    // helper that silently stopped doing so would make the whole file
    // pass against an unauthenticated device.
    let mut d = Device::authenticated(PERM_LARGE_BLOB_WRITE as u64, None);
    assert_eq!(d.store.pin.pin_set, 1, "the harness did not set a PIN");
    assert_eq!(
        d.store.pin.pin_hash[..],
        fw::bc_crypto::sha256(TEST_PIN)[..16],
        "the harness set a different PIN than it documents"
    );
    assert_eq!(d.token.len(), 32, "the minted token is not 32 bytes");
}
