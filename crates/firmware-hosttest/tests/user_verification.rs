// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The UV flag in a registration's authenticator data.
//!
//! A browser that creates a passkey with the PIN sends a pinUvAuthParam;
//! once the token has checked it, the authData it signs must say so
//! (UV, bit 2). A relying party that requires user verification reads
//! only that bit: without it the registration looks as if no PIN was
//! checked and is refused, although the PIN was. GetAssertion always
//! reported UV this way; MakeCredential did not.

use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

use fw::client_pin::{PERM_GET_ASSERTION, PERM_MAKE_CREDENTIAL};
use fw::ctap2::{CTAP2_MAKE_CREDENTIAL, CTAP2_OK};
use fw::testclient::{auth_param, Device};

const RP: &str = "uv.example";
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

/// MakeCredential for `RP`, discoverable or not, with a pinUvAuthParam
/// when the device holds a token. Returns authData's flags byte.
fn register_flags(d: &mut Device, rk: bool) -> u8 {
    let txt = |s: &str| Value::Text(s.into());
    let cdh = [0x11u8; 32];
    let mut e = vec![
        (Value::Uint(1), Value::Bytes(cdh.to_vec())),
        (Value::Uint(2), Value::Map(vec![(txt("id"), txt(RP))])),
        (
            Value::Uint(3),
            Value::Map(vec![
                (txt("id"), Value::Bytes(vec![7; 4])),
                (txt("name"), txt("attendee-uv00")),
                (txt("displayName"), txt("attendee-uv00")),
            ]),
        ),
        (
            Value::Uint(4),
            Value::Array(vec![Value::Map(vec![
                (txt("alg"), Value::Nint(-7)),
                (txt("type"), txt("public-key")),
            ])]),
        ),
    ];
    if rk {
        e.push((
            Value::Uint(7),
            Value::Map(vec![(txt("rk"), Value::Bool(true))]),
        ));
    }
    if !d.token.is_empty() {
        e.push((Value::Uint(8), Value::Bytes(auth_param(&d.token, &cdh))));
        e.push((Value::Uint(9), Value::Uint(1)));
    }
    let r = d.send(CTAP2_MAKE_CREDENTIAL, &Value::Map(e));
    assert_eq!(r[0], CTAP2_OK, "the registration failed: {:#04x}", r[0]);
    match Device::field(&r, 2).expect("no authData") {
        Value::Bytes(ad) => ad[32],
        other => panic!("authData is {other:?}"),
    }
}

#[test]
fn a_passkey_registered_with_the_pin_reports_user_verification() {
    let mut d = Device::authenticated((PERM_MAKE_CREDENTIAL | PERM_GET_ASSERTION) as u64, None);
    let flags = register_flags(&mut d, true);
    assert_eq!(
        flags & (FLAG_UP | FLAG_UV | FLAG_AT),
        FLAG_UP | FLAG_UV | FLAG_AT,
        "flags {flags:#04x}: a checked PIN must show as UV"
    );
}

#[test]
fn a_non_discoverable_registration_with_the_pin_reports_it_too() {
    // UV says a PIN was checked, whatever kind of credential it made.
    let mut d = Device::authenticated((PERM_MAKE_CREDENTIAL | PERM_GET_ASSERTION) as u64, None);
    let flags = register_flags(&mut d, false);
    assert_ne!(
        flags & FLAG_UV,
        0,
        "flags {flags:#04x}: UV missing after a checked PIN"
    );
}

#[test]
fn a_registration_without_a_pin_does_not_claim_user_verification() {
    // No PIN on the token, so nothing was verified: a UV bit here would
    // be a silent downgrade for an RP that trusts it.
    let mut d = Device::bare();
    let flags = register_flags(&mut d, true);
    assert_eq!(
        flags & FLAG_UV,
        0,
        "flags {flags:#04x}: UV set with no PIN checked"
    );
    assert_ne!(flags & FLAG_UP, 0, "flags {flags:#04x}: UP missing");
}
