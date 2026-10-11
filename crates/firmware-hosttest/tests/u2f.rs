// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The CTAP1/U2F back-compat surface.
//!
//! Off by default, and it has form: the command was once structurally
//! unreachable -- the CTAPHID dispatch refused `CMD_MSG` while getInfo
//! advertised `NMSG` unconditionally, so building the feature linked a
//! hardcoded attestation key and nothing else. That is exactly the kind
//! of thing a test finds and a demo does not, so what it does when it
//! *is* built in is worth pinning.
//!
//! U2F is an ISO 7816 APDU protocol, not CBOR: `CLA INS P1 P2` then an
//! extended-length `Lc`, and a two-byte status word on the way back. It
//! predates everything else on this token and is the only surface here
//! with no PIN, no CBOR and no CTAP2 error codes.
//!
//! Signature validity is not asserted -- the signing key is real ECDSA
//! but verification is a silicon claim like everywhere else in this
//! harness. What is asserted is the wire format a browser parses.

#![cfg(feature = "u2f")]

use pqf_firmware_hosttest as fw;

use fw::ctap2::{CredStore, HostOp};
use fw::trng::Trng;
use fw::u2f;

// ISO 7816 status words, spelled out so a wrong expectation reads as a
// number rather than a name.
const SW_NO_ERROR: u16 = 0x9000;
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
const SW_WRONG_DATA: u16 = 0x6a80;
const SW_WRONG_LENGTH: u16 = 0x6700;
const SW_CLA_NOT_SUPPORTED: u16 = 0x6e00;
const SW_INS_NOT_SUPPORTED: u16 = 0x6d00;

const INS_REGISTER: u8 = 0x01;
const INS_AUTHENTICATE: u8 = 0x02;
const INS_VERSION: u8 = 0x03;

const AUTH_CHECK_ONLY: u8 = 0x07;
const AUTH_ENFORCE_UP_AND_SIGN: u8 = 0x03;
const AUTH_DONT_ENFORCE_UP_AND_SIGN: u8 = 0x08;

struct Device {
    _guard: fw::testlock::Guard,
    trng: Trng,
    store: CredStore,
}

impl Device {
    fn new() -> Self {
        let guard = fw::testlock::acquire();
        rp235x_hal::reset();
        rp235x_hal::reset_counts();
        let mut trng = Trng::new_for_test();
        let store = CredStore::load(&mut trng);
        Device {
            _guard: guard,
            trng,
            store,
        }
    }

    fn send_with(&mut self, apdu: &[u8], present: bool) -> Vec<u8> {
        let mut host = |_op: HostOp| present;
        u2f::handle(apdu, &mut self.trng, &self.store, &mut host).to_vec()
    }
    fn send(&mut self, apdu: &[u8]) -> Vec<u8> {
        self.send_with(apdu, true)
    }
}

/// An extended-length APDU: `CLA INS P1 P2 00 Lc_hi Lc_lo data`.
fn apdu(ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, ins, p1, 0x00];
    v.push(0x00);
    v.push((data.len() >> 8) as u8);
    v.push((data.len() & 0xff) as u8);
    v.extend_from_slice(data);
    v
}

/// The trailing status word, and the payload before it.
fn split(resp: &[u8]) -> (u16, &[u8]) {
    assert!(resp.len() >= 2, "a U2F response is at least a status word");
    let n = resp.len();
    (
        u16::from_be_bytes([resp[n - 2], resp[n - 1]]),
        &resp[..n - 2],
    )
}
fn sw(resp: &[u8]) -> u16 {
    split(resp).0
}

fn challenge() -> [u8; 32] {
    [0x11; 32]
}
fn application() -> [u8; 32] {
    [0x22; 32]
}

/// Register, and return (key handle, user public key).
fn register(d: &mut Device) -> (Vec<u8>, Vec<u8>) {
    let mut req = Vec::new();
    req.extend_from_slice(&challenge());
    req.extend_from_slice(&application());
    let r = d.send(&apdu(INS_REGISTER, 0x00, &req));
    assert_eq!(sw(&r), SW_NO_ERROR, "registration failed: {:#06x}", sw(&r));
    let (_, body) = split(&r);
    // 0x05 || pubkey(65) || kh_len(1) || kh || cert || sig
    assert_eq!(body[0], 0x05, "the legacy byte is not 0x05");
    let pk = body[1..66].to_vec();
    let kh_len = body[66] as usize;
    let kh = body[67..67 + kh_len].to_vec();
    (kh, pk)
}

/// An AUTHENTICATE request body: challenge || application || khLen || kh.
fn auth_body(kh: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&challenge());
    v.extend_from_slice(&application());
    v.push(kh.len() as u8);
    v.extend_from_slice(kh);
    v
}

// ---- the APDU envelope ------------------------------------------------

#[test]
fn only_class_zero_is_accepted() {
    // CLA is the first byte a reader looks at. U2F defines only 0x00;
    // anything else is another applet's traffic and must be refused
    // rather than parsed as U2F.
    let mut d = Device::new();
    for cla in [0x01u8, 0x80, 0xa0, 0xff] {
        let mut a = apdu(INS_VERSION, 0x00, &[]);
        a[0] = cla;
        assert_eq!(
            sw(&d.send(&a)),
            SW_CLA_NOT_SUPPORTED,
            "class {cla:#04x} was accepted"
        );
    }
}

#[test]
fn an_unknown_instruction_is_refused() {
    let mut d = Device::new();
    for ins in [0x00u8, 0x04, 0x40, 0xc0, 0xff] {
        assert_eq!(
            sw(&d.send(&apdu(ins, 0x00, &[]))),
            SW_INS_NOT_SUPPORTED,
            "instruction {ins:#04x} was accepted"
        );
    }
}

#[test]
fn a_truncated_apdu_is_refused_without_panicking() {
    // Fewer than four bytes has no complete header. This arrives from
    // any host that can send a short HID message, before anything is
    // authenticated.
    let mut d = Device::new();
    for n in 0..4usize {
        let r = d.send(&vec![0u8; n]);
        assert_eq!(sw(&r), SW_WRONG_LENGTH, "a {n}-byte APDU was accepted");
    }
    // Five and six bytes are a header plus a partial extended Lc.
    for n in [5usize, 6] {
        let r = d.send(&vec![0u8; n]);
        assert_eq!(sw(&r), SW_WRONG_LENGTH, "a {n}-byte APDU was accepted");
    }
}

#[test]
fn a_declared_length_that_disagrees_with_the_body_is_refused() {
    // Lc is host-controlled and is what bounds every slice below it.
    let mut d = Device::new();
    let body = vec![0u8; 64];
    for lie in [0usize, 1, 32, 63, 65, 128, 0xffff] {
        let mut a = vec![0x00, INS_REGISTER, 0x00, 0x00, 0x00];
        a.push((lie >> 8) as u8);
        a.push((lie & 0xff) as u8);
        a.extend_from_slice(&body);
        let r = d.send(&a);
        assert_ne!(
            sw(&r),
            SW_NO_ERROR,
            "a declared length of {lie} with a 64-byte body was accepted"
        );
    }
}

#[test]
fn every_response_ends_in_a_status_word() {
    // A host reads the last two bytes and nothing else on an error. A
    // response without them is unparseable, and a payload left behind
    // after a failure would be read as part of the status.
    let mut d = Device::new();
    for a in [
        apdu(INS_VERSION, 0x00, &[]),
        apdu(INS_REGISTER, 0x00, &[]),
        apdu(0x99, 0x00, &[]),
        vec![0u8; 4],
    ] {
        let r = d.send(&a);
        assert!(r.len() >= 2, "a response was {} bytes", r.len());
    }
    // And an error carries no payload with it.
    let r = d.send(&apdu(0x99, 0x00, &[1, 2, 3, 4]));
    assert_eq!(
        r.len(),
        2,
        "an error response carried {} extra bytes",
        r.len() - 2
    );
}

// ---- VERSION ----------------------------------------------------------

#[test]
fn version_answers_the_fixed_string() {
    // A browser reads this to decide whether to speak U2F at all. It is
    // the one U2F command with a constant answer.
    let mut d = Device::new();
    let r = d.send(&apdu(INS_VERSION, 0x00, &[]));
    let (status, body) = split(&r);
    assert_eq!(status, SW_NO_ERROR);
    assert_eq!(body, b"U2F_V2", "VERSION answered {body:?}");
}

#[test]
fn version_needs_no_user_presence() {
    // It is a capability query, not an operation. Demanding a touch
    // would make every page load flash the token.
    let mut d = Device::new();
    let r = d.send_with(&apdu(INS_VERSION, 0x00, &[]), false);
    assert_eq!(sw(&r), SW_NO_ERROR, "VERSION asked for a gesture");
}

// ---- REGISTER ---------------------------------------------------------

#[test]
fn registration_returns_the_legacy_response_shape() {
    // U2F Raw Message Formats sec. 4.3: 0x05, a 65-byte uncompressed point,
    // a one-byte key-handle length, the handle, the attestation
    // certificate and the signature. A browser walks these offsets
    // literally, so a wrong length field shifts everything after it.
    let mut d = Device::new();
    let mut req = Vec::new();
    req.extend_from_slice(&challenge());
    req.extend_from_slice(&application());
    let r = d.send(&apdu(INS_REGISTER, 0x00, &req));
    let (status, body) = split(&r);
    assert_eq!(status, SW_NO_ERROR);

    assert_eq!(body[0], 0x05, "the reserved legacy byte is not 0x05");
    assert_eq!(
        body[1], 0x04,
        "the user public key is not an uncompressed point"
    );
    let kh_len = body[66] as usize;
    assert!(kh_len > 0, "the key handle is empty");
    assert!(
        67 + kh_len < body.len(),
        "the response ends before the attestation certificate"
    );
    // What follows the handle is a DER SEQUENCE (the certificate).
    assert_eq!(
        body[67 + kh_len],
        0x30,
        "no DER certificate after the key handle"
    );
}

#[test]
fn registration_needs_a_gesture() {
    // The whole security model of U2F is that a key is only minted when
    // a human touches the token.
    let mut d = Device::new();
    let mut req = Vec::new();
    req.extend_from_slice(&challenge());
    req.extend_from_slice(&application());
    let r = d.send_with(&apdu(INS_REGISTER, 0x00, &req), false);
    assert_eq!(
        sw(&r),
        SW_CONDITIONS_NOT_SATISFIED,
        "a registration completed with no gesture"
    );
    assert_eq!(r.len(), 2, "a refused registration still returned a key");
}

#[test]
fn a_registration_request_must_be_exactly_sixty_four_bytes() {
    // Challenge and application are 32 bytes each. Anything else is a
    // malformed request, and accepting a short one would sign over
    // whatever followed it in the buffer.
    let mut d = Device::new();
    for n in [0usize, 32, 63, 65, 96, 128] {
        let r = d.send(&apdu(INS_REGISTER, 0x00, &vec![0x33; n]));
        assert_eq!(
            sw(&r),
            SW_WRONG_LENGTH,
            "a {n}-byte registration request was accepted"
        );
    }
}

#[test]
fn two_registrations_produce_different_key_handles() {
    let mut d = Device::new();
    let (a, _) = register(&mut d);
    let (b, _) = register(&mut d);
    assert_ne!(a, b, "two registrations returned the same key handle");
}

// ---- AUTHENTICATE ------------------------------------------------------

#[test]
fn a_registered_handle_authenticates() {
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    let r = d.send(&apdu(
        INS_AUTHENTICATE,
        AUTH_ENFORCE_UP_AND_SIGN,
        &auth_body(&kh),
    ));
    let (status, body) = split(&r);
    assert_eq!(
        status, SW_NO_ERROR,
        "a freshly registered handle did not authenticate"
    );
    // sec. 4.4: user presence byte, 4-byte counter, signature.
    assert_eq!(body[0] & 0x01, 0x01, "the user-presence byte is clear");
    assert!(body.len() > 5, "no signature after the counter");
    assert_eq!(body[5], 0x30, "the signature is not DER");
}

#[test]
fn authentication_needs_a_gesture() {
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    let r = d.send_with(
        &apdu(INS_AUTHENTICATE, AUTH_ENFORCE_UP_AND_SIGN, &auth_body(&kh)),
        false,
    );
    assert_eq!(
        sw(&r),
        SW_CONDITIONS_NOT_SATISFIED,
        "an assertion was produced with no gesture"
    );
    assert_eq!(
        r.len(),
        2,
        "a refused authentication still signed something"
    );
}

#[test]
fn check_only_reports_ownership_without_signing() {
    // P1 = 0x07 is how a browser asks "is this handle yours?" before
    // prompting the user. sec. 4.4 says the answer for a handle we own is
    // the *error* 0x6985 -- counter-intuitive, and a device that answered
    // 0x9000 would make every browser skip the ceremony.
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    let r = d.send(&apdu(INS_AUTHENTICATE, AUTH_CHECK_ONLY, &auth_body(&kh)));
    assert_eq!(
        sw(&r),
        SW_CONDITIONS_NOT_SATISFIED,
        "check-only did not report ownership the way the spec spells it"
    );
    assert_eq!(r.len(), 2, "check-only produced a signature");
}

#[test]
fn check_only_rejects_a_handle_this_token_did_not_mint() {
    // The other half, and the one that matters: a foreign handle must
    // answer WRONG_DATA so the browser moves on to the next
    // authenticator rather than prompting for this one.
    let mut d = Device::new();
    register(&mut d);
    for forged in [vec![0xABu8; 64], vec![0u8; 64], vec![0xff; 200]] {
        let r = d.send(&apdu(
            INS_AUTHENTICATE,
            AUTH_CHECK_ONLY,
            &auth_body(&forged),
        ));
        assert_eq!(
            sw(&r),
            SW_WRONG_DATA,
            "a foreign key handle was claimed as ours"
        );
    }
}

#[test]
fn a_handle_is_bound_to_the_application_that_registered_it() {
    // The U2F equivalent of rpId scoping, and the same bypass if it
    // fails: a handle usable under another application id lets one site
    // authenticate as the user at another.
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    let mut body = Vec::new();
    body.extend_from_slice(&challenge());
    body.extend_from_slice(&[0x99; 32]); // a different application
    body.push(kh.len() as u8);
    body.extend_from_slice(&kh);
    let r = d.send(&apdu(INS_AUTHENTICATE, AUTH_ENFORCE_UP_AND_SIGN, &body));
    assert_eq!(
        sw(&r),
        SW_WRONG_DATA,
        "a key handle authenticated under a different application id"
    );
}

#[test]
fn a_tampered_handle_is_rejected() {
    // One bit. The authentication tag over the sealed handle is the only
    // thing between the host and a handle it can steer.
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    assert_eq!(
        sw(&d.send(&apdu(
            INS_AUTHENTICATE,
            AUTH_ENFORCE_UP_AND_SIGN,
            &auth_body(&kh)
        ))),
        SW_NO_ERROR,
        "setup: the untampered handle works"
    );
    for pos in [0usize, 1, kh.len() / 2, kh.len() - 1] {
        let mut bad = kh.clone();
        bad[pos] ^= 0x01;
        let r = d.send(&apdu(
            INS_AUTHENTICATE,
            AUTH_ENFORCE_UP_AND_SIGN,
            &auth_body(&bad),
        ));
        assert_eq!(
            sw(&r),
            SW_WRONG_DATA,
            "a handle with byte {pos} flipped was accepted"
        );
    }
}

#[test]
fn an_authenticate_request_shorter_than_its_header_is_refused() {
    let mut d = Device::new();
    for n in [0usize, 32, 64] {
        let r = d.send(&apdu(
            INS_AUTHENTICATE,
            AUTH_ENFORCE_UP_AND_SIGN,
            &vec![0u8; n],
        ));
        assert_eq!(sw(&r), SW_WRONG_LENGTH, "a {n}-byte request was accepted");
    }
}

#[test]
fn a_key_handle_length_that_disagrees_with_the_body_is_refused() {
    // The length byte sits between the fixed header and the handle, and
    // is what the slice bound comes from.
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    for lie in [0u8, 1, 16, 255] {
        if lie as usize == kh.len() {
            continue;
        }
        let mut body = Vec::new();
        body.extend_from_slice(&challenge());
        body.extend_from_slice(&application());
        body.push(lie);
        body.extend_from_slice(&kh);
        let r = d.send(&apdu(INS_AUTHENTICATE, AUTH_ENFORCE_UP_AND_SIGN, &body));
        assert_ne!(
            sw(&r),
            SW_NO_ERROR,
            "a declared handle length of {lie} with a {}-byte handle was accepted",
            kh.len()
        );
    }
}

#[test]
fn an_unknown_control_byte_is_refused() {
    // P1 selects between check-only, sign, and sign-without-presence.
    // An unrecognised value must not fall through to any of them.
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    for p1 in [0x00u8, 0x01, 0x02, 0x04, 0x06, 0x09, 0xff] {
        let r = d.send(&apdu(INS_AUTHENTICATE, p1, &auth_body(&kh)));
        assert_ne!(sw(&r), SW_NO_ERROR, "control byte {p1:#04x} was accepted");
    }
}

#[test]
fn the_dont_enforce_presence_mode_signs_without_a_gesture() {
    // 0x08 exists for silent pre-flight: the host asks "would this
    // handle work?" without making the user touch anything.
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    let r = d.send_with(
        &apdu(
            INS_AUTHENTICATE,
            AUTH_DONT_ENFORCE_UP_AND_SIGN,
            &auth_body(&kh),
        ),
        false,
    );
    assert_eq!(sw(&r), SW_NO_ERROR, "silent authentication was refused");
}

#[test]
fn the_presence_byte_is_set_even_on_a_silent_authentication() {
    // A deviation, deliberate and commented in the firmware rather than
    // an accident. The U2F response carries a user-presence byte, and
    // this device returns 0x01 unconditionally -- including for the
    // 0x08 "don't enforce presence" mode, where by construction nobody
    // touched anything. The stated reason is that some clients do not
    // tolerate the spec's 0x00, legacy YubiKey firmware included.
    //
    // The blast radius is small and worth stating: 0x08 is only reached
    // when the *host* explicitly asked for a silent signature, so the
    // party told "a human was present" is the same party that asked for
    // no human. A browser doing pre-flight does not forward that
    // assertion to the relying party. It is still a security-relevant
    // field carrying a value that is not true, on a surface that is off
    // by default.
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    let r = d.send_with(
        &apdu(
            INS_AUTHENTICATE,
            AUTH_DONT_ENFORCE_UP_AND_SIGN,
            &auth_body(&kh),
        ),
        false,
    );
    let (_, body) = split(&r);
    assert_eq!(
        body[0] & 0x01,
        0x01,
        "the presence byte now reports the truth -- if that is deliberate, \
         update this test and the note in docs/TESTING.md"
    );
}

#[test]
fn the_counter_advances_with_every_assertion() {
    // A relying party watching this go backwards concludes the token has
    // been cloned.
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    let mut last = 0u32;
    for i in 0..4 {
        let r = d.send(&apdu(
            INS_AUTHENTICATE,
            AUTH_ENFORCE_UP_AND_SIGN,
            &auth_body(&kh),
        ));
        let (status, body) = split(&r);
        assert_eq!(status, SW_NO_ERROR);
        let c = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
        assert!(c > last, "assertion {i}: counter went {last} -> {c}");
        last = c;
    }
}

#[test]
fn two_assertions_over_one_challenge_are_not_byte_identical() {
    // The counter is inside the signed message, so two signatures over
    // the same challenge must differ. Identical bytes would mean the
    // counter never reached the signature.
    let mut d = Device::new();
    let (kh, _) = register(&mut d);
    let a = d.send(&apdu(
        INS_AUTHENTICATE,
        AUTH_ENFORCE_UP_AND_SIGN,
        &auth_body(&kh),
    ));
    let b = d.send(&apdu(
        INS_AUTHENTICATE,
        AUTH_ENFORCE_UP_AND_SIGN,
        &auth_body(&kh),
    ));
    assert_ne!(a, b, "two assertions over one challenge were identical");
}
