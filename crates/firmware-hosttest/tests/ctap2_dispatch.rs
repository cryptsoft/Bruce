// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP2 command dispatch -- phase 1 of reaching the command surface.
//!
//! This is the front door: `handle_cbor` takes whatever the host sent,
//! looks at the first byte, and routes. Everything downstream depends on
//! it getting that right, and nothing until now has exercised it except
//! the conformance suite driving well-formed commands at a real token.
//!
//! **What is faked, and what that costs.** The signing runs on core 1
//! behind a mailbox; here it is stubbed (see
//! `pqf_firmware_hosttest::core1_signer`) and returns a signature of the
//! right shape and no validity. So these tests cover what the token
//! *says* -- dispatch, CBOR shaping, request parsing, policy -- and never
//! what it signs. Signature validity is a silicon claim and stays one:
//! `pqc_roundtrip` across all six port x ISA configurations, and the
//! conformance suite verifying attestation against the credential's own key.
//!
//! Anything here that asserts on a signature asserts on its *shape*
//! only, and says so.

use pqf_firmware_hosttest as fw;

use fw::client_pin::PinSession;
use fw::ctap2::{
    self, CredStore, HostOp, CTAP2_CLIENT_PIN, CTAP2_CONFIG, CTAP2_CREDENTIAL_MANAGEMENT,
    CTAP2_ERR_INVALID_COMMAND, CTAP2_ERR_NOT_IMPLEMENTED, CTAP2_GET_ASSERTION, CTAP2_GET_INFO,
    CTAP2_GET_NEXT_ASSERTION, CTAP2_LARGE_BLOBS, CTAP2_MAKE_CREDENTIAL, CTAP2_RESET_CMD,
    CTAP2_SELECTION,
};
use fw::trng::Trng;

/// The whole device: a blank die, a fresh store, a fresh PIN session.
struct Device {
    _guard: fw::testlock::Guard,
    trng: Trng,
    session: PinSession,
    store: CredStore,
}

impl Device {
    fn new() -> Self {
        let guard = fw::testlock::acquire();
        rp235x_hal::reset();
        rp235x_hal::reset_counts();
        fw::core1_signer::CORE1_SIGNER.reset_for_test();
        let mut trng = Trng::new_for_test();
        let store = CredStore::load(&mut trng);
        let session = PinSession::new(&mut trng);
        Self {
            _guard: guard,
            trng,
            session,
            store,
        }
    }

    /// Send one CTAP2 command. `host` answers every pump with "keep
    /// going" and every presence request with "confirmed", which is the
    /// generous case -- a test that wants a refusal says so.
    fn send(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut host = |_op: HostOp| true;
        ctap2::handle_cbor(
            bytes,
            &mut self.trng,
            &mut self.session,
            &mut self.store,
            &mut host,
            0,
            [0, 0, 0, 1],
        )
        .to_vec()
    }

    /// Send with a host that refuses everything: no presence, and a
    /// cancel on the first pump.
    fn send_refusing(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut host = |_op: HostOp| false;
        ctap2::handle_cbor(
            bytes,
            &mut self.trng,
            &mut self.session,
            &mut self.store,
            &mut host,
            0,
            [0, 0, 0, 1],
        )
        .to_vec()
    }
}

/// Every CTAP2 response leads with a status byte.
fn status(r: &[u8]) -> u8 {
    assert!(!r.is_empty(), "a CTAP2 response must not be empty");
    r[0]
}

// ---- the front door --------------------------------------------------

#[test]
fn an_empty_request_is_rejected_rather_than_indexed() {
    // `handle_cbor` reads input[0] to find the command. An empty request
    // arrives from any host that can send a zero-length CTAPHID message.
    let mut d = Device::new();
    assert_eq!(status(&d.send(&[])), CTAP2_ERR_INVALID_COMMAND);
}

#[test]
fn an_unknown_command_is_rejected() {
    // Two different refusals, and the distinction is deliberate: an
    // *empty* request has no command byte to look at and is
    // CTAP1_ERR_INVALID_COMMAND, while a command byte the dispatch
    // table does not carry is CTAP2_ERR_NOT_IMPLEMENTED. A client can
    // tell "I sent nothing" from "you do not do that".
    let mut d = Device::new();
    for cmd in [0x00u8, 0x7f, 0x80, 0xff] {
        let st = status(&d.send(&[cmd]));
        assert_ne!(st, 0x00, "command {cmd:#04x} was accepted");
        assert_eq!(
            st, CTAP2_ERR_NOT_IMPLEMENTED,
            "command {cmd:#04x} was refused with {st:#04x}, not NOT_IMPLEMENTED"
        );
    }
}

#[test]
fn every_dispatched_command_answers_with_a_status_byte() {
    // The dispatch table has ten entries. Each must return *something*
    // well formed even with no parameters -- an error is a fine answer, a
    // panic or an empty buffer is not, and a panic here would take the
    // transport core down on the device.
    let commands = [
        ("getInfo", CTAP2_GET_INFO),
        ("makeCredential", CTAP2_MAKE_CREDENTIAL),
        ("getAssertion", CTAP2_GET_ASSERTION),
        ("getNextAssertion", CTAP2_GET_NEXT_ASSERTION),
        ("reset", CTAP2_RESET_CMD),
        ("clientPin", CTAP2_CLIENT_PIN),
        ("credentialManagement", CTAP2_CREDENTIAL_MANAGEMENT),
        ("largeBlobs", CTAP2_LARGE_BLOBS),
        ("config", CTAP2_CONFIG),
        ("selection", CTAP2_SELECTION),
    ];
    for (name, cmd) in commands {
        let mut d = Device::new();
        let r = d.send(&[cmd]);
        assert!(!r.is_empty(), "{name} returned no response at all");
        let _ = status(&r);
    }
}

#[test]
fn a_command_with_truncated_cbor_parameters_is_rejected_not_panicked() {
    // Every one of these is a prefix of a legal request. A parser that
    // indexed past the end would fault the transport core, and any host
    // can send them.
    let commands = [
        CTAP2_MAKE_CREDENTIAL,
        CTAP2_GET_ASSERTION,
        CTAP2_CLIENT_PIN,
        CTAP2_CREDENTIAL_MANAGEMENT,
        CTAP2_LARGE_BLOBS,
        CTAP2_CONFIG,
    ];
    // A CBOR map header claiming entries that are not there, then
    // increasingly truncated bodies.
    let bodies: [&[u8]; 6] = [
        &[0xa1],
        &[0xa1, 0x01],
        &[0xa2, 0x01, 0x58],
        &[0xa1, 0x01, 0x58, 0xff],
        &[0xbf],
        &[0xa1, 0x09, 0x9f],
    ];
    for cmd in commands {
        for body in bodies {
            let mut d = Device::new();
            let mut req = vec![cmd];
            req.extend_from_slice(body);
            let r = d.send(&req);
            assert!(
                !r.is_empty(),
                "command {cmd:#04x} with body {body:02x?} returned nothing"
            );
            assert_ne!(
                status(&r),
                0x00,
                "command {cmd:#04x} accepted truncated CBOR {body:02x?} as valid"
            );
        }
    }
}

#[test]
fn a_very_long_parameter_block_is_rejected_rather_than_accepted() {
    // The transport caps a message at 7609 bytes, so this is what the
    // largest hostile request looks like once it reaches CTAP2.
    let mut d = Device::new();
    let mut req = vec![CTAP2_MAKE_CREDENTIAL];
    req.extend(std::iter::repeat(0xffu8).take(7000));
    let r = d.send(&req);
    assert!(!r.is_empty());
    assert_ne!(
        status(&r),
        0x00,
        "7000 bytes of 0xff parsed as a credential request"
    );
}

// ---- the two that answer without parameters --------------------------

#[test]
fn get_info_answers_with_a_cbor_map() {
    let mut d = Device::new();
    let r = d.send(&[CTAP2_GET_INFO]);
    assert_eq!(status(&r), 0x00, "getInfo failed on a fresh device");
    assert!(
        r.len() > 1,
        "getInfo returned a status byte and nothing else"
    );
    assert_eq!(r[1] & 0xe0, 0xa0, "the getInfo body is not a CBOR map");
}

#[test]
fn selection_reflects_what_the_host_said_about_presence() {
    // authenticatorSelection exists to ask "are you there?". It must
    // collect a real gesture, so a host that reports no presence has to
    // get a refusal rather than an OK.
    {
        let mut d = Device::new();
        assert_eq!(
            status(&d.send(&[CTAP2_SELECTION])),
            0x00,
            "a confirmed presence was refused"
        );
    }
    let mut d = Device::new();
    let r = d.send_refusing(&[CTAP2_SELECTION]);
    assert_ne!(
        status(&r),
        0x00,
        "selection succeeded with a host that reported no user presence"
    );
}

// ---- the signer seam itself ------------------------------------------

#[test]
fn the_stub_signer_is_wired_in_and_produces_the_documented_shape() {
    // Takes the device lock like every other test: CORE1_SIGNER is a
    // process global, and a parallel Device::new() resets it.
    let _g = fw::testlock::acquire();
    // Not a claim about the firmware -- a check that the *harness* is
    // honest about what it fakes. A stub returning the wrong length
    // would make every downstream size assertion meaningless.
    use pqf_signer_core::mldsa_alg::MLDSA_SIG_LEN;
    let s = &fw::core1_signer::CORE1_SIGNER;
    s.reset_for_test();
    assert!(
        !s.is_done(),
        "the stub reported a result before being asked"
    );
    s.submit(&[1u8; 32], &[2u8; 32], b"message").unwrap();
    assert!(s.is_done());
    assert!(!s.errored());
    let mut out = Vec::new();
    s.take_result(&mut out);
    assert_eq!(
        out.len(),
        72 + MLDSA_SIG_LEN,
        "the stub signature is not DER-plus-ML-DSA sized"
    );
    assert_eq!(out[0], 0x30, "a DER sequence starts 0x30");
    assert_eq!(s.submits(), 1);
}

#[test]
fn the_stub_signer_can_be_made_to_fail() {
    let _g = fw::testlock::acquire();
    // So the firmware's error path is reachable at all. On the board
    // this is core 1 panicking or the shared heap running out.
    let s = &fw::core1_signer::CORE1_SIGNER;
    s.reset_for_test();
    s.fail_next_submit();
    s.submit(&[1u8; 32], &[2u8; 32], b"message").unwrap();
    assert!(s.is_done());
    assert!(s.errored(), "a forced failure did not report as errored");
    let mut out = Vec::new();
    s.take_result(&mut out);
    assert!(out.is_empty(), "a failed sign still produced bytes");
}

#[test]
fn different_credentials_produce_different_stub_signatures() {
    let _g = fw::testlock::acquire();
    // So a later test can tell two signatures apart. A stub returning a
    // constant would let "these differ" pass vacuously.
    let s = &fw::core1_signer::CORE1_SIGNER;
    s.reset_for_test();
    s.submit(&[1u8; 32], &[2u8; 32], b"m").unwrap();
    let mut a = Vec::new();
    s.take_result(&mut a);
    s.submit(&[9u8; 32], &[2u8; 32], b"m").unwrap();
    let mut b = Vec::new();
    s.take_result(&mut b);
    assert_ne!(
        a, b,
        "two different scalars produced identical stub signatures"
    );
}

// ---- state hygiene ---------------------------------------------------

#[test]
fn a_fresh_device_has_no_credentials_and_no_pin() {
    // The starting point every other test assumes. If `CredStore::load`
    // read something out of an erased die, every downstream assertion
    // would be measuring the wrong device.
    let d = Device::new();
    assert_eq!(
        d.store.active_count(),
        0,
        "a blank die had credentials on it"
    );
    assert_eq!(d.store.pin.pin_set, 0, "a blank die reported a PIN");
}

#[test]
fn dispatch_does_not_leave_the_signer_holding_a_result() {
    // The mailbox has one slot and a caller that abandoned a result
    // would wedge the next signature on the real device -- `submit`
    // spins until the state returns to IDLE.
    let mut d = Device::new();
    d.send(&[CTAP2_GET_INFO]);
    d.send(&[CTAP2_SELECTION]);
    assert!(
        !fw::core1_signer::CORE1_SIGNER.is_done(),
        "a command left an unclaimed result in the signer mailbox"
    );
}
