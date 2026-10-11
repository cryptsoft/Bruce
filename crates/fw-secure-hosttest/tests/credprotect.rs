// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! credProtect enforcement in the Secure world.
//!
//! The policy was stored at MakeCredential, echoed back to the relying
//! party in the signed authData extension map -- which is what tells a
//! WebAuthn client with `enforceCredentialProtectionPolicy` that the
//! authenticator applied it -- and reported by credentialManagement.
//! Nothing ever consulted it. A credential registered
//! `userVerificationRequired` was handed out on a bare touch.
//!
//! Enforcement now lives in one place, `credstore::usable_for`, because
//! there are three call sites (discovery, the allowList path, and
//! GetNextAssertion) and the defect was that all three had none. These
//! tests drive that predicate and the two filtered accessors built on
//! it; `tests/storage.rs` covers the store itself.
//!
//! CTAP 2.1 sec. 12.1:
//!   1  userVerificationOptional                      -- always usable
//!   2  userVerificationOptionalWithCredentialIDList  -- without UV only
//!      when the client named it in an allowList; discovery must not
//!      surface it
//!   3  userVerificationRequired                      -- only with UV

use pqf_fw_secure_hosttest as fws;
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());

fn fresh() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fws::fresh_die();
    g
}

fn rp_hash(n: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = n;
    h[31] = 0xa5;
    h
}

fn cred_id(n: u8) -> [u8; 64] {
    let mut c = [0u8; 64];
    c[0] = n;
    c[63] = 0x5a;
    c
}

/// Store one credential for `rp` with the given credProtect level.
fn put(rp: u8, user: u8, level: u8) -> bool {
    fws::credstore::store(
        &rp_hash(rp),
        &cred_id(user),
        &[user],
        b"example.test",
        &[],
        b"n",
        b"d",
        level,
    )
}

fn rec(rp: u8, user: u8, level: u8) -> fws::credstore::Resident {
    assert!(put(rp, user, level), "store refused a credential");
    fws::credstore::find_by_id(&cred_id(user)).expect("stored credential vanished")
}

// ---------- the predicate ----------

#[test]
fn level_three_needs_user_verification_and_an_allow_list_does_not_substitute() {
    // The defect, stated as itself. A credential registered
    // userVerificationRequired was returned on presence alone, so the
    // relying party's guarantee was worth nothing. Naming it in an
    // allowList must not help: knowing a credential id is not verifying
    // a user, and a stolen token's ids are knowable.
    let _g = fresh();
    let r = rec(1, 1, 3);
    assert!(
        !fws::credstore::usable_for(&r, false, false),
        "level 3 used with no UV"
    );
    assert!(
        !fws::credstore::usable_for(&r, false, true),
        "level 3 used with no UV because it was named in an allowList"
    );
    assert!(
        fws::credstore::usable_for(&r, true, false),
        "level 3 refused WITH UV"
    );
    assert!(fws::credstore::usable_for(&r, true, true));
}

#[test]
fn level_two_is_reachable_by_name_but_not_by_discovery() {
    // sec. 12.1's whole point: the credential still works for a client that
    // was told its id, and stays invisible to one that just asks the
    // token what it holds.
    let _g = fresh();
    let r = rec(1, 2, 2);
    assert!(
        fws::credstore::usable_for(&r, false, true),
        "level 2 refused when the client named it"
    );
    assert!(
        !fws::credstore::usable_for(&r, false, false),
        "level 2 surfaced by discovery with no UV"
    );
    assert!(
        fws::credstore::usable_for(&r, true, false),
        "level 2 refused with UV"
    );
}

#[test]
fn level_one_and_an_unset_policy_are_always_usable() {
    // The accept half. A predicate that refused everything would pass
    // both tests above and break every ordinary passkey on the token.
    let _g = fresh();
    for level in [0u8, 1] {
        let r = rec(1, 10 + level, level);
        for uv in [false, true] {
            for named in [false, true] {
                assert!(
                    fws::credstore::usable_for(&r, uv, named),
                    "level {level} refused (uv={uv}, named={named})"
                );
            }
        }
    }
}

// ---------- the filtered accessors ----------

#[test]
fn discovery_skips_protected_credentials_without_uv() {
    let _g = fresh();
    assert!(put(1, 1, 1), "store 1");
    assert!(put(1, 2, 2), "store 2");
    assert!(put(1, 3, 3), "store 3");

    let visible: Vec<u8> = (0..8)
        .filter_map(|i| fws::credstore::nth_discoverable(&rp_hash(1), i, false))
        .map(|r| r.cred_id[0])
        .collect();
    assert_eq!(
        visible,
        vec![1],
        "discovery without UV surfaced {visible:?}, want only the level-1"
    );

    let all: Vec<u8> = (0..8)
        .filter_map(|i| fws::credstore::nth_discoverable(&rp_hash(1), i, true))
        .map(|r| r.cred_id[0])
        .collect();
    assert_eq!(
        all.len(),
        3,
        "discovery WITH UV should surface all three, got {all:?}"
    );
}

#[test]
fn the_count_matches_what_the_walk_will_actually_yield() {
    // numberOfCredentials comes from the count and GetNextAssertion
    // walks with the index. If they disagree the token promises
    // assertions it then refuses -- the client shows an account picker
    // with a row that errors when chosen. This is why the count is
    // filtered too, and not merely `count()`.
    let _g = fresh();
    assert!(put(1, 1, 1));
    assert!(put(1, 2, 3));
    assert!(put(1, 3, 2));

    for uv in [false, true] {
        let n = fws::credstore::count_discoverable(&rp_hash(1), uv);
        let walked = (0..16)
            .take_while(|i| fws::credstore::nth_discoverable(&rp_hash(1), *i, uv).is_some())
            .count();
        assert_eq!(
            n, walked,
            "uv={uv}: count says {n}, the walk yields {walked}"
        );
        assert!(
            fws::credstore::nth_discoverable(&rp_hash(1), n, uv).is_none(),
            "uv={uv}: index {n} yielded a credential past the count"
        );
    }
}

#[test]
fn the_filter_does_not_leak_across_relying_parties() {
    // The filter is applied on top of the rp match, not instead of it.
    let _g = fresh();
    assert!(put(1, 1, 1));
    assert!(put(2, 2, 1));
    assert_eq!(fws::credstore::count_discoverable(&rp_hash(1), false), 1);
    assert_eq!(fws::credstore::count_discoverable(&rp_hash(2), false), 1);
    assert_eq!(
        fws::credstore::nth_discoverable(&rp_hash(1), 0, false)
            .unwrap()
            .cred_id[0],
        1
    );
}

#[test]
fn a_store_holding_only_protected_credentials_looks_empty_without_uv() {
    // The edge that decides whether the token says NO_CREDENTIALS or
    // hands out something it should not.
    let _g = fresh();
    assert!(put(1, 1, 3));
    assert!(put(1, 2, 3));
    assert_eq!(fws::credstore::count_discoverable(&rp_hash(1), false), 0);
    assert!(fws::credstore::nth_discoverable(&rp_hash(1), 0, false).is_none());
    assert_eq!(fws::credstore::count_discoverable(&rp_hash(1), true), 2);
}

#[test]
fn the_policy_rule_over_a_bare_level_matches_the_stored_credential_rule() {
    // GetAssertion's allowList path applies the rule to a level recovered
    // from the credential id, so it works for non-resident credentials;
    // discovery applies it to a stored record. They must be the same rule.
    let _g = fresh();
    for level in 0..=3u8 {
        let r = rec(1, 20 + level, level);
        for uv in [false, true] {
            for named in [false, true] {
                assert_eq!(
                    fws::credstore::policy_allows(level, uv, named),
                    fws::credstore::usable_for(&r, uv, named),
                    "level {level} uv={uv} named={named}: the two rules disagree"
                );
            }
        }
    }
    // And the level that matters most, stated on its own.
    assert!(
        !fws::credstore::policy_allows(3, false, true),
        "level 3 usable by name without UV"
    );
    assert!(
        !fws::credstore::policy_allows(2, false, false),
        "level 2 discoverable without UV"
    );
}

#[test]
fn the_second_allow_list_candidate_is_used_only_without_uv() {
    // Layout comes from the NS constants so the ABI is what is checked.
    use fws::ctapreq::{
        REQ_OFF_CDH, REQ_OFF_CRED, REQ_OFF_CRED2, REQ_OFF_HAVE_CRED2, REQ_OFF_RP, REQ_OFF_RP_LEN,
    };
    let _g = fresh();
    let build = || {
        let mut b = [0u8; fws::ctap::REQ_LEN];
        b[REQ_OFF_RP_LEN] = 3;
        b[REQ_OFF_RP..REQ_OFF_RP + 3].copy_from_slice(b"rp1");
        for i in 0..32 {
            b[REQ_OFF_CDH + i] = 7;
        }
        b[REQ_OFF_CRED] = 0xA1;
        b[REQ_OFF_CRED2] = 0xB2;
        b[REQ_OFF_HAVE_CRED2] = 1;
        b
    };
    // No UV: the level-3 primary is unusable, the fallback is chosen.
    let mut r = fws::ctap::parse(&build()).unwrap();
    r.uv = false;
    fws::ctap::choose_allow_list_credential(&mut r);
    assert_eq!(
        r.cred_id[0], 0xB2,
        "without UV the usable fallback was not chosen"
    );
    // With UV: the primary -- the relying party's first choice -- stays.
    let mut r = fws::ctap::parse(&build()).unwrap();
    r.uv = true;
    fws::ctap::choose_allow_list_credential(&mut r);
    assert_eq!(r.cred_id[0], 0xA1, "with UV the primary was replaced");
    // No fallback carried: nothing changes either way.
    let mut b = build();
    b[REQ_OFF_HAVE_CRED2] = 0;
    let mut r = fws::ctap::parse(&b).unwrap();
    r.uv = false;
    fws::ctap::choose_allow_list_credential(&mut r);
    assert_eq!(r.cred_id[0], 0xA1);
}
