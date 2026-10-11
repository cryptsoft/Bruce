// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! authenticatorConfig -- phase 5 of the CTAP2 surface.
//!
//! 299 lines and the smallest of the three, but it is the command that
//! changes device-wide *policy*: whether user verification is always
//! required, how short a PIN may be, whether enterprise attestation is
//! on. Everything it sets is persistent, so a bug here outlives the
//! session that caused it, and two of the three settings are one-way by
//! design -- the only way back is a factory reset.
//!
//! Requests are framed as CTAP 2.1 numbers them. That was not always
//! true: `pinUvAuthProtocol` and `pinUvAuthParam` were swapped, which
//! made the whole command unreachable by any client but our own.

use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

use fw::client_pin::{PERM_AUTHENTICATOR_CFG, PERM_GET_ASSERTION, PERM_MAKE_CREDENTIAL};
use fw::ctap2::{CTAP2_CONFIG as CFG, CTAP2_GET_INFO, CTAP2_OK};
use fw::testclient::{auth_param, Device};

const ERR_INVALID_PARAM: u8 = 0x02;
const ERR_INVALID_SUBCOMMAND: u8 = 0x3e;
const ERR_PIN_AUTH_INVALID: u8 = 0x33;
const ERR_PUAT_REQUIRED: u8 = 0x36;

const ENABLE_ENT_ATTESTATION: u64 = 0x01;
const TOGGLE_ALWAYS_UV: u64 = 0x02;
const SET_MIN_PIN_LENGTH: u64 = 0x03;
const VENDOR_PROTOTYPE: u64 = 0xFF;

fn configurer() -> Device {
    Device::authenticated(PERM_AUTHENTICATOR_CFG as u64, None)
}

fn min_pin_param(n: u64) -> Value {
    Value::Map(vec![(Value::Uint(1), Value::Uint(n))])
}

/// A named boolean out of getInfo's options map, read over the wire so
/// the test sees what a platform sees rather than a struct field.
fn get_info_option(d: &mut Device, name: &str) -> Option<bool> {
    let r = d.send(CTAP2_GET_INFO, &Value::Map(vec![]));
    assert_eq!(r[0], CTAP2_OK, "getInfo returned {:#04x}", r[0]);
    let map = match pqf_cbor::decode(&r[1..]).ok()? {
        Value::Map(m) => m,
        _ => return None,
    };
    let opts = map.iter().find_map(|(k, v)| match (k, v) {
        (Value::Uint(4), Value::Map(o)) => Some(o.clone()),
        _ => None,
    })?;
    opts.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(t), Value::Bool(b)) if t == name => Some(*b),
        _ => None,
    })
}

fn get_info_min_pin(d: &mut Device) -> u64 {
    let r = d.send(CTAP2_GET_INFO, &Value::Map(vec![]));
    let map = match pqf_cbor::decode(&r[1..]).expect("getInfo is not CBOR") {
        Value::Map(m) => m,
        other => panic!("getInfo is {other:?}"),
    };
    match map.iter().find_map(|(k, v)| match k {
        Value::Uint(0x0d) => Some(v.clone()),
        _ => None,
    }) {
        Some(Value::Uint(n)) => n,
        other => panic!("minPINLength is {other:?}"),
    }
}

// ---- the authentication gate -----------------------------------------

#[test]
fn a_request_with_no_token_is_refused() {
    // Without the gate, anything that can open a CTAPHID channel could
    // turn on alwaysUv and lock the user out of their own token, or
    // raise the minimum PIN length past the PIN they already have.
    let mut d = configurer();
    for sub in [ENABLE_ENT_ATTESTATION, TOGGLE_ALWAYS_UV, SET_MIN_PIN_LENGTH] {
        let r = d.send(CFG, &Value::Map(vec![(Value::Uint(1), Value::Uint(sub))]));
        assert_eq!(
            r[0], ERR_PUAT_REQUIRED,
            "subcommand {sub:#04x} ran with no pinUvAuthParam"
        );
    }
    assert!(!d.store.always_uv, "policy changed anyway");
}

#[test]
fn a_forged_auth_param_is_refused() {
    let mut d = configurer();
    for forged in [vec![0u8; 16], vec![0xff; 16], vec![], vec![0u8; 32]] {
        let r = d.send(
            CFG,
            &Value::Map(vec![
                (Value::Uint(1), Value::Uint(TOGGLE_ALWAYS_UV)),
                (Value::Uint(3), Value::Uint(1)),
                (Value::Uint(4), Value::Bytes(forged.clone())),
            ]),
        );
        assert_eq!(
            r[0], ERR_PIN_AUTH_INVALID,
            "auth param {forged:?} was accepted"
        );
    }
    assert!(!d.store.always_uv, "policy changed anyway");
}

#[test]
fn a_token_without_the_config_permission_is_refused() {
    let mut d = Device::authenticated(PERM_GET_ASSERTION as u64, None);
    assert_eq!(
        d.subcommand(CFG, TOGGLE_ALWAYS_UV, None)[0],
        ERR_PIN_AUTH_INVALID
    );
    assert!(
        !d.store.always_uv,
        "an assertion token changed device policy"
    );
}

#[test]
fn the_signed_message_covers_the_subcommand() {
    // sec. 6.11: the param is over 32 bytes of 0xff, the command byte 0x0d,
    // the subcommand and its params. A param captured from one
    // subcommand must not authorise a different one -- otherwise
    // observing a harmless setMinPINLength would let an attacker replay
    // it as a toggleAlwaysUv.
    let mut d = configurer();
    let mut msg = vec![0xffu8; 32];
    msg.push(0x0d);
    msg.push(ENABLE_ENT_ATTESTATION as u8);
    let for_other_sub = auth_param(&d.token, &msg);
    let r = d.send(
        CFG,
        &Value::Map(vec![
            (Value::Uint(1), Value::Uint(TOGGLE_ALWAYS_UV)),
            (Value::Uint(3), Value::Uint(1)),
            (Value::Uint(4), Value::Bytes(for_other_sub)),
        ]),
    );
    assert_eq!(
        r[0], ERR_PIN_AUTH_INVALID,
        "a param for one subcommand authorised another"
    );
    assert!(!d.store.always_uv);
}

#[test]
fn an_unknown_subcommand_is_refused() {
    let mut d = configurer();
    for sub in [0x00u64, 0x04, 0x09, 0x42] {
        assert_eq!(
            d.subcommand(CFG, sub, None)[0],
            ERR_INVALID_SUBCOMMAND,
            "subcommand {sub:#04x} was accepted"
        );
    }
}

#[test]
fn the_vendor_prototype_subcommand_is_not_implemented() {
    // sec. 6.11.3 reserves 0xFF for vendor experimentation. This device
    // implements nothing there, and says so rather than silently
    // succeeding -- a platform probing it must not conclude a vendor
    // channel exists.
    let mut d = configurer();
    assert_eq!(
        d.subcommand(CFG, VENDOR_PROTOTYPE, None)[0],
        ERR_INVALID_SUBCOMMAND
    );
}

// ---- alwaysUv ---------------------------------------------------------

#[test]
fn toggling_always_uv_flips_it_and_getinfo_says_so() {
    // A platform reads the option to decide whether to collect a PIN
    // before every ceremony. If getInfo disagreed with the stored
    // policy, a browser would skip verification the device then demands.
    let mut d = configurer();
    assert_eq!(get_info_option(&mut d, "alwaysUv"), Some(false));

    assert_eq!(d.subcommand(CFG, TOGGLE_ALWAYS_UV, None)[0], CTAP2_OK);
    assert!(d.store.always_uv, "the stored policy did not change");
    assert_eq!(
        get_info_option(&mut d, "alwaysUv"),
        Some(true),
        "getInfo did not notice alwaysUv being enabled"
    );

    assert_eq!(d.subcommand(CFG, TOGGLE_ALWAYS_UV, None)[0], CTAP2_OK);
    assert!(!d.store.always_uv, "the toggle did not toggle back");
    assert_eq!(get_info_option(&mut d, "alwaysUv"), Some(false));
}

// ---- setMinPINLength --------------------------------------------------

#[test]
fn the_minimum_pin_length_can_be_raised_and_getinfo_says_so() {
    let mut d = configurer();
    assert_eq!(get_info_min_pin(&mut d), 4, "the CTAP default is 4");
    assert_eq!(
        d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(min_pin_param(8)))[0],
        CTAP2_OK
    );
    assert_eq!(
        d.store.min_pin_length, 8,
        "the stored minimum did not change"
    );
    assert_eq!(get_info_min_pin(&mut d), 8, "getInfo did not notice");
}

#[test]
fn the_minimum_pin_length_cannot_be_lowered() {
    // sec. 6.11.4 makes it one-way: an administrator raising it must not be
    // undone by a later command. Otherwise the policy is advisory, and
    // an attacker who reaches the config command undoes it silently.
    let mut d = configurer();
    assert_eq!(
        d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(min_pin_param(8)))[0],
        CTAP2_OK
    );
    // sec. 6.11.4: CTAP2_ERR_PIN_POLICY_VIOLATION (0x37) for a newMinPINLength
    // below the current one -- the code C, the TrustZone port and OpenSK
    // answer. This port said 0x02 and this test used to pin that.
    for lower in [0u64, 4, 6, 7] {
        assert_eq!(
            d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(min_pin_param(lower)))[0],
            0x37,
            "the minimum was lowered to {lower}"
        );
        assert_eq!(d.store.min_pin_length, 8, "the stored minimum moved");
    }
    assert_eq!(
        d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(min_pin_param(8)))[0],
        CTAP2_OK,
        "setting it to the value it already has was refused"
    );
}

#[test]
fn a_raised_minimum_is_enforced_on_the_next_pin() {
    // The setting is only worth having if the PIN path reads it, and
    // that link -- authenticatorConfig writing a value client_pin then
    // enforces -- is the only thing making this subcommand more than a
    // number in a struct.
    const ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
    let mut d = configurer(); // PIN is four characters
    assert_eq!(
        d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(min_pin_param(8)))[0],
        CTAP2_OK
    );
    assert_eq!(get_info_min_pin(&mut d), 8);

    assert_eq!(
        d.change_pin(b"1234", b"1234567")[0],
        ERR_PIN_POLICY_VIOLATION,
        "a seven-character PIN was accepted under a minimum of eight"
    );
    assert_eq!(
        d.change_pin(b"1234", b"12345678")[0],
        CTAP2_OK,
        "an eight-character PIN was refused under a minimum of eight"
    );
}

#[test]
fn a_pin_change_can_be_forced_and_gates_new_tokens_until_it_happens() {
    // sec. 6.11.4: with `forceChangePin` true the device answers
    // CTAP2_ERR_PIN_POLICY_VIOLATION to token requests until a changePIN
    // succeeds. That is the mechanism an administrator uses to retire a
    // weak PIN across a fleet.
    const ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
    let mut d = configurer();
    let params = Value::Map(vec![
        (Value::Uint(1), Value::Uint(8)),
        (Value::Uint(3), Value::Bool(true)),
    ]);
    assert_eq!(
        d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(params))[0],
        CTAP2_OK
    );
    assert!(d.store.force_pin_change, "the flag was not set");

    let r = d.send(CTAP2_GET_INFO, &Value::Map(vec![]));
    let map = match pqf_cbor::decode(&r[1..]).expect("getInfo is not CBOR") {
        Value::Map(m) => m,
        other => panic!("getInfo is {other:?}"),
    };
    assert_eq!(
        map.iter().find_map(|(k, v)| match k {
            Value::Uint(0x0c) => Some(v.clone()),
            _ => None,
        }),
        Some(Value::Bool(true)),
        "getInfo does not report the forced change"
    );

    // A token that would let the user *authenticate* is refused...
    assert_eq!(
        d.mint(PERM_MAKE_CREDENTIAL as u64, Some("example.com"))[0],
        ERR_PIN_POLICY_VIOLATION,
        "a registration token was issued while a PIN change was outstanding"
    );
    assert_eq!(
        d.mint(PERM_GET_ASSERTION as u64, Some("example.com"))[0],
        ERR_PIN_POLICY_VIOLATION,
        "an assertion token was issued while a PIN change was outstanding"
    );

    // ...but one scoped purely to device management is still granted, so
    // the platform can keep configuring the device while the change is
    // pending. That carve-out is deliberate and commented in the
    // firmware. The spec's getInfo text reads more absolutely --
    // "getPinToken and getPinUvAuthTokenUsingPinWithPermissions will
    // return errors until after a successful PIN Change" -- with no
    // exception by permission, so this is a documented divergence rather
    // than an accident.
    assert_eq!(
        d.mint(PERM_AUTHENTICATOR_CFG as u64, None)[0],
        CTAP2_OK,
        "the management carve-out is gone -- update this note"
    );

    assert_eq!(d.change_pin(b"1234", b"12345678")[0], CTAP2_OK);
    assert!(!d.store.force_pin_change, "the flag survived the change");
    assert_eq!(
        d.mint(PERM_MAKE_CREDENTIAL as u64, Some("example.com"))[0],
        CTAP2_OK,
        "registration tokens are still refused after the change was made"
    );
}

#[test]
fn raising_the_floor_does_not_by_itself_force_a_pin_change() {
    // A deviation with a cause worth writing down. sec. 6.11.4: "If the
    // value of PINCodePointLength is less than newMinPINLength and the
    // value of clientPIN is true then let the value of the
    // forcePINChange member ... be true" -- the force is meant to be
    // automatic, not only on request.
    //
    // This device cannot do it. It stores SHA-256(PIN)[..16], `pin_set`
    // and a retry count, and nothing else; the PIN's length is not
    // recoverable from any of that. So the automatic rule needs a new
    // persisted field, which is a storage-format change, not a
    // one-liner.
    //
    // The practical gap: an administrator raises the floor to eight, the
    // user keeps their four-digit PIN, and nothing makes them change it
    // -- while getInfo reports minPINLength 8, so the platform believes
    // the policy is in force. A platform that also sends
    // `forceChangePin: true` closes it, and the test above shows that
    // path works.
    let mut d = configurer(); // PIN is four characters
    assert_eq!(
        d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(min_pin_param(8)))[0],
        CTAP2_OK
    );
    assert_eq!(get_info_min_pin(&mut d), 8, "the floor was raised");
    assert!(
        !d.store.force_pin_change,
        "the floor now forces a change on its own -- update this test and \
         the deviation note in docs/TESTING.md"
    );
    assert_eq!(
        d.mint(PERM_AUTHENTICATOR_CFG as u64, None)[0],
        CTAP2_OK,
        "a token was refused, so something does force a change"
    );
}

#[test]
fn changing_the_pin_invalidates_an_outstanding_token() {
    // A token is minted against a PIN. Once that PIN changes, anything
    // still holding the old token must lose it -- otherwise a session
    // authorised under a PIN the user has just revoked keeps working.
    let mut d = configurer();
    assert_eq!(
        d.subcommand(CFG, TOGGLE_ALWAYS_UV, None)[0],
        CTAP2_OK,
        "setup: the token should work before the PIN changes"
    );
    assert_eq!(d.change_pin(b"1234", b"567890")[0], CTAP2_OK);
    assert_eq!(
        d.subcommand(CFG, TOGGLE_ALWAYS_UV, None)[0],
        ERR_PUAT_REQUIRED,
        "a token minted under the old PIN still authorised a config change"
    );
}

#[test]
fn a_minimum_pin_length_request_with_no_parameters_changes_nothing() {
    // The subcommand takes either newMinPINLength or minPinLengthRPIDs
    // or both. Neither present is a request that asks for nothing, and
    // must not be read as "set it to zero".
    let mut d = configurer();
    assert_eq!(
        d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(min_pin_param(8)))[0],
        CTAP2_OK
    );
    let r = d.subcommand(CFG, SET_MIN_PIN_LENGTH, None);
    assert!(!r.is_empty(), "no answer at all");
    assert_eq!(
        d.store.min_pin_length, 8,
        "an empty request reset the minimum"
    );
    assert_eq!(get_info_min_pin(&mut d), 8);
}

#[test]
fn an_absurd_minimum_pin_length_does_not_lock_the_device_out_of_bounds() {
    // The value lands in a u8 and is compared against PIN lengths. A
    // value past what any PIN can be would make every future setPIN
    // impossible; whether it is refused or accepted, it must not
    // corrupt anything or panic.
    let mut d = configurer();
    for n in [64u64, 255, 256, 65535, u64::MAX] {
        let r = d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(min_pin_param(n)));
        assert!(!r.is_empty(), "no answer for a minimum of {n}");
    }
}

// ---- enterprise attestation -------------------------------------------

#[test]
fn enterprise_attestation_can_be_enabled_and_is_one_way() {
    // sec. 6.11.1: once on, it stays on until a reset. It changes what
    // identifying information leaves the device, so a command that could
    // silently turn it back off would make the state unauditable.
    let mut d = configurer();
    assert!(!d.store.enterprise_attestation, "on by default");
    assert_eq!(d.subcommand(CFG, ENABLE_ENT_ATTESTATION, None)[0], CTAP2_OK);
    assert!(d.store.enterprise_attestation, "it did not turn on");
    assert_eq!(
        d.subcommand(CFG, ENABLE_ENT_ATTESTATION, None)[0],
        CTAP2_OK,
        "enabling it twice was refused"
    );
    assert!(
        d.store.enterprise_attestation,
        "the second call turned it off"
    );
}

// ---- persistence and malformed input ---------------------------------

#[test]
fn configuration_survives_being_reloaded_from_flash() {
    // All three settings are persistent. If they lived only in RAM the
    // policy would silently lapse at the next replug -- which is exactly
    // the failure an administrator would never notice.
    let mut d = configurer();
    assert_eq!(d.subcommand(CFG, TOGGLE_ALWAYS_UV, None)[0], CTAP2_OK);
    assert_eq!(
        d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(min_pin_param(9)))[0],
        CTAP2_OK
    );
    assert_eq!(d.subcommand(CFG, ENABLE_ENT_ATTESTATION, None)[0], CTAP2_OK);

    let reloaded = fw::ctap2::CredStore::load(&mut d.trng);
    assert!(reloaded.always_uv, "alwaysUv did not survive a reload");
    assert_eq!(
        reloaded.min_pin_length, 9,
        "the minimum did not survive a reload"
    );
    assert!(
        reloaded.enterprise_attestation,
        "enterprise attestation did not survive a reload"
    );
}

#[test]
fn malformed_config_bodies_are_refused_without_panicking() {
    let mut d = configurer();
    for body in [
        vec![],
        vec![0xff],
        vec![0xa1],
        vec![0xa1, 0x01],
        vec![0x81, 0x01],
        vec![0xff; 200],
    ] {
        let mut msg = vec![CFG];
        msg.extend_from_slice(&body);
        let mut host = |_op: fw::ctap2::HostOp| true;
        let r = fw::ctap2::handle_cbor(
            &msg,
            &mut d.trng,
            &mut d.session,
            &mut d.store,
            &mut host,
            0,
            [0, 0, 0, 1],
        );
        assert!(!r.is_empty(), "an empty response to {body:?}");
        assert_ne!(r[0], CTAP2_OK, "{body:?} was accepted");
    }
    assert!(!d.store.always_uv, "a malformed body changed policy");
}

// ---- the deviation ----------------------------------------------------

#[test]
fn a_spec_conformant_request_is_understood() {
    // This used to record a deviation. CTAP 2.1 sec. 6.11 numbers the
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
    let mut d = configurer();
    let mut msg = vec![0xffu8; 32];
    msg.push(0x0d);
    msg.push(TOGGLE_ALWAYS_UV as u8);
    let conformant = Value::Map(vec![
        (Value::Uint(1), Value::Uint(TOGGLE_ALWAYS_UV)),
        (Value::Uint(3), Value::Uint(1)),
        (Value::Uint(4), Value::Bytes(auth_param(&d.token, &msg))),
    ]);
    let r = d.send(CFG, &conformant);
    assert_eq!(r[0], CTAP2_OK, "a spec-conformant request was refused");
    assert!(d.store.always_uv, "the subcommand did not take effect");
}

#[test]
fn a_min_pin_length_that_no_pin_could_satisfy_is_a_policy_violation_not_a_no_op() {
    // 260 was truncated to a byte -- 4 -- which then passed the "may only
    // raise" check as a no-op and answered OK. The PIN wire format caps a
    // PIN at 63 bytes, so anything above that is unsatisfiable and must be
    // refused with the policy code.
    let mut d = configurer();
    for bad in [64u64, 260, 4 + 256, u64::MAX] {
        assert_eq!(
            d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(min_pin_param(bad)))[0],
            0x37,
            "newMinPINLength {bad} was not refused as a policy violation"
        );
        assert_eq!(
            d.store.min_pin_length, 0,
            "the stored minimum changed on a refused request"
        );
    }
}

#[test]
fn an_empty_min_pin_length_rp_id_list_clears_the_list() {
    // Present-and-empty is how a relying party withdraws the list. It used
    // to be indistinguishable from absent, so the list could never be
    // cleared once set.
    let mut d = configurer();
    let set = Value::Map(vec![(
        Value::Uint(2),
        Value::Array(vec![
            Value::Text("one.example".into()),
            Value::Text("two.example".into()),
        ]),
    )]);
    assert_eq!(
        d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(set))[0],
        CTAP2_OK
    );
    assert_eq!(
        d.store.min_pin_length_rpid_count, 2,
        "the list was not stored"
    );
    let clear = Value::Map(vec![(Value::Uint(2), Value::Array(vec![]))]);
    assert_eq!(
        d.subcommand(CFG, SET_MIN_PIN_LENGTH, Some(clear))[0],
        CTAP2_OK
    );
    assert_eq!(
        d.store.min_pin_length_rpid_count, 0,
        "an empty list did not clear the stored one"
    );
}
