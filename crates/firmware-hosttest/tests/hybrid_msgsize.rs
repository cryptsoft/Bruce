// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! How close a hybrid MakeCredential comes to the CTAP HID ceiling.
//!
//! `emit_make_credential` suppresses the credProtect extension output
//! on hybrid builds, and the comment gives a specific reason: the
//! ML-DSA-87 signature and public key "already consume nearly all of
//! the 7609 B CTAP HID maxMsgSize budget", so the 14-byte extension
//! would tip the response over and get it truncated mid-signature.
//!
//! Nothing measured that. It is a claim about a number, the number has
//! moved with every change to the attestation format, and the cost of
//! being wrong in one direction is a truncated response while the cost
//! in the other is a relying party using enforceCredentialProtectionPolicy
//! never being told the policy was applied.
//!
//! So: measure. These tests fail if the headroom changes enough to
//! change the answer, in either direction.

use fw::ctap2::{CTAP2_MAKE_CREDENTIAL, CTAP2_OK};
use fw::testclient::Device;
use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

/// What CTAP HID can carry in one command: 57 + 128 * 59.
const CTAPHID_CEILING: usize = 7609;
/// The credProtect extension output, encoded: the text key plus a
/// one-byte integer, inside an already-present extensions map.
const CREDPROTECT_COST: usize = 14;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

/// A hybrid MakeCredential with credProtect requested and a resident
/// credential, which is the largest shape this command produces.
fn largest_hybrid_request() -> Value {
    Value::Map(vec![
        (Value::Uint(1), Value::Bytes(vec![0x11; 32])),
        (
            Value::Uint(2),
            Value::Map(vec![(t("id"), t("example.com"))]),
        ),
        (
            Value::Uint(3),
            Value::Map(vec![
                (t("id"), Value::Bytes(vec![0x01; 64])),
                (t("name"), t(&"n".repeat(64))),
                (t("displayName"), t(&"d".repeat(64))),
            ]),
        ),
        (
            Value::Uint(4),
            Value::Array(vec![Value::Map(vec![
                (t("alg"), Value::Nint(fw::mldsa_alg::COSE_ALG_HYBRID_MLDSA)),
                (t("type"), t("public-key")),
            ])]),
        ),
        (
            Value::Uint(6),
            Value::Map(vec![(t("credProtect"), Value::Uint(3))]),
        ),
        (
            Value::Uint(7),
            Value::Map(vec![(t("rk"), Value::Bool(true))]),
        ),
    ])
}

fn hybrid_response_len() -> usize {
    let mut d = Device::bare();
    let resp = d.send(CTAP2_MAKE_CREDENTIAL, &largest_hybrid_request());
    assert_eq!(
        resp[0], CTAP2_OK,
        "the largest hybrid MakeCredential was refused: {:#04x}",
        resp[0]
    );
    resp.len()
}

#[test]
fn the_largest_hybrid_make_credential_fits_the_transport() {
    // The property that actually matters. A response over the ceiling is
    // truncated mid-signature and the client reports corrupt CBOR.
    let n = hybrid_response_len();
    assert!(
        n <= CTAPHID_CEILING,
        "a hybrid MakeCredential is {n} bytes, over the {CTAPHID_CEILING}-byte ceiling"
    );
}

#[test]
fn the_headroom_is_recorded_so_the_credprotect_decision_can_be_checked() {
    // The suppression in emit_make_credential rests on there being less
    // than CREDPROTECT_COST bytes of room. Print the number and assert
    // which side of the line we are on, so that a change to the
    // attestation format shows up here as a decision to revisit rather
    // than as a silently wrong comment.
    let n = hybrid_response_len();
    let headroom = CTAPHID_CEILING - n;
    println!(
        "hybrid MakeCredential: {n} bytes, ceiling {CTAPHID_CEILING}, \
         headroom {headroom}, credProtect output would cost {CREDPROTECT_COST}"
    );
    assert!(
        headroom >= CREDPROTECT_COST,
        "headroom is {headroom} bytes, under the {CREDPROTECT_COST} the credProtect \
         output costs -- the suppression in emit_make_credential is still needed, \
         and this test should be inverted rather than deleted"
    );
}
