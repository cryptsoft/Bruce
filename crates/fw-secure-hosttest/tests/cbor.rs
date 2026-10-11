// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The Secure world's CBOR writer and the CTAP2 responses built with it.
//!
//! Everything the Non-secure world sees from the Secure world goes
//! through this encoder, so a malformed byte here is a malformed byte on
//! the wire -- and the failure mode is a client that rejects the response
//! rather than anything that looks like a crash. The conformance suite
//! catches that at the level of "the whole ceremony failed"; these check
//! the bytes.
//!
//! The writer is deliberately overflow-tolerant: every method is a no-op
//! once the buffer is full, so a caller writes a whole structure and
//! checks once at the end. That contract is only useful if it actually
//! holds, which is most of what is tested here.

use fws::cborw::Writer;
use pqf_fw_secure_hosttest as fws;

/// Encode with `f` into a buffer of exactly `cap` bytes.
fn enc(cap: usize, f: impl FnOnce(&mut Writer)) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; cap];
    let n = {
        let mut w = Writer::new(&mut buf);
        f(&mut w);
        w.finish()
    }?;
    buf.truncate(n);
    Some(buf)
}

// ---- integers --------------------------------------------------------

#[test]
fn small_unsigned_integers_are_a_single_byte() {
    // RFC 8949 3.1: 0..=23 live in the initial byte.
    for v in 0..=23u64 {
        let out = enc(8, |w| w.uint(v)).expect("small uint did not fit in 8 bytes");
        assert_eq!(out, vec![v as u8], "uint({v}) should be one byte");
    }
}

#[test]
fn unsigned_integers_use_the_shortest_form_at_every_boundary() {
    // A decoder will accept a longer form, but a CTAP2 response is
    // canonical CBOR and a client is entitled to reject one that is not.
    let cases: &[(u64, &[u8])] = &[
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (255, &[0x18, 0xff]),
        (256, &[0x19, 0x01, 0x00]),
        (65535, &[0x19, 0xff, 0xff]),
        (65536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (0xffff_ffff, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
    ];
    for (v, want) in cases {
        let out = enc(16, |w| w.uint(*v)).expect("uint did not fit");
        assert_eq!(&out[..], *want, "uint({v}) is not the shortest form");
    }
}

#[test]
fn negative_integers_encode_as_cbor_major_type_one() {
    // The COSE algorithm ids are all negative, and getting the encoding
    // wrong there means every relying party sees the wrong algorithm.
    // -1 is 0x20, and -n is encoded as (n - 1) in major type 1.
    let cases: &[(i64, &[u8])] = &[
        (-1, &[0x20]),
        (-7, &[0x26]), // ES256
        (-24, &[0x37]),
        (-25, &[0x38, 0x18]),
        (-51, &[0x38, 0x32]), // ESP384 (RFC 9864), once draft -02's MLDSA44-ES256
        (-54, &[0x38, 0x35]), // MLDSA44-ES256 (draft -04 request)
        (-55, &[0x38, 0x36]), // MLDSA65-ES256 (draft -04 request)
        (-56, &[0x38, 0x37]), // MLDSA87-ES384 (draft -04 request)
    ];
    for (v, want) in cases {
        let out = enc(16, |w| w.nint(*v)).expect("nint did not fit");
        assert_eq!(&out[..], *want, "nint({v}) encoded wrongly");
    }
}

#[test]
fn the_cose_algorithm_ids_round_trip_to_the_values_relying_parties_expect() {
    // Belt and braces on the one encoding nobody notices being wrong
    // until a relying party rejects every credential.
    let out = enc(4, |w| w.nint(fws::ctap::COSE_ALG_ES256)).unwrap();
    assert_eq!(out, vec![0x26], "ES256 must encode as 0x26");
    let out = enc(4, |w| w.nint(fws::ctap::COSE_ALG_HYBRID)).unwrap();
    assert_eq!(
        out.len(),
        2,
        "the composite id needs the one-byte-argument form"
    );
    assert_eq!(out[0], 0x38);
    // The draft -04 ids: 0x38 0x35 / 0x36 / 0x37 for ML-DSA-44/65/87.
    // Never 0x32..0x34 -- those are -51..-53, which RFC 9864 gave to
    // ESP384 / ESP512 / Ed448.
    assert!(
        (0x35..=0x37).contains(&out[1]),
        "the composite id {} is not a draft -04 id",
        fws::ctap::COSE_ALG_HYBRID
    );
    assert_eq!(
        fws::ctap::COSE_ALG_HYBRID,
        pqf_signer_core::mldsa_alg::COSE_ALG_HYBRID_MLDSA,
        "the Secure image and the FIDO firmware disagree on the composite id"
    );
}

// ---- strings and containers -----------------------------------------

#[test]
fn byte_strings_carry_their_length_then_their_bytes() {
    let out = enc(64, |w| w.bytes(&[1, 2, 3])).unwrap();
    assert_eq!(out, vec![0x43, 1, 2, 3]);

    let long = vec![0xAAu8; 40];
    let out = enc(64, |w| w.bytes(&long)).unwrap();
    assert_eq!(out[0], 0x58, "40 bytes needs the one-byte-length form");
    assert_eq!(out[1], 40);
    assert_eq!(&out[2..], &long[..]);
}

#[test]
fn empty_strings_and_containers_encode() {
    // Empty is a real case: a token with no credentials returns an empty
    // array, and an empty credBlob is legal.
    assert_eq!(enc(4, |w| w.bytes(&[])).unwrap(), vec![0x40]);
    assert_eq!(enc(4, |w| w.text("")).unwrap(), vec![0x60]);
    assert_eq!(enc(4, |w| w.array(0)).unwrap(), vec![0x80]);
    assert_eq!(enc(4, |w| w.map(0)).unwrap(), vec![0xa0]);
}

#[test]
fn text_strings_are_major_type_three() {
    let out = enc(32, |w| w.text("usb")).unwrap();
    assert_eq!(out, vec![0x63, b'u', b's', b'b']);
}

#[test]
fn containers_announce_their_length_in_the_header() {
    // Definite-length only: an indefinite-length container is legal CBOR
    // and not canonical, and CTAP2 asks for canonical.
    assert_eq!(enc(4, |w| w.array(3)).unwrap(), vec![0x83]);
    assert_eq!(enc(4, |w| w.map(3)).unwrap(), vec![0xa3]);
    assert_eq!(enc(8, |w| w.array(24)).unwrap(), vec![0x98, 24]);
    assert_eq!(enc(8, |w| w.map(300)).unwrap(), vec![0xb9, 0x01, 0x2c]);
}

// ---- the overflow contract ------------------------------------------

#[test]
fn a_buffer_one_byte_short_reports_overflow_rather_than_truncating() {
    // The whole point of the deferred check. A writer that truncated
    // silently would hand the Non-secure world a half-formed response
    // and no way to know.
    assert!(
        enc(3, |w| w.bytes(&[1, 2, 3])).is_none(),
        "a 4-byte encoding fitted into 3 bytes"
    );
    assert!(
        enc(4, |w| w.bytes(&[1, 2, 3])).is_some(),
        "4 bytes should fit exactly"
    );
}

#[test]
fn everything_after_an_overflow_is_a_no_op() {
    // The contract that lets a caller write a whole structure and check
    // once. If a later write could still land, an overflowing response
    // would be corrupt rather than merely rejected.
    let mut buf = [0u8; 2];
    let mut w = Writer::new(&mut buf);
    w.bytes(&[1, 2, 3, 4, 5]); // overflows
    w.uint(7);
    w.text("more");
    w.array(2);
    assert!(
        w.finish().is_none(),
        "overflow was forgotten by the time finish ran"
    );
}

#[test]
fn a_zero_length_buffer_overflows_on_the_first_byte() {
    let mut buf = [0u8; 0];
    let mut w = Writer::new(&mut buf);
    w.uint(0);
    assert!(w.finish().is_none());
}

// ---- responses -------------------------------------------------------

#[test]
fn an_error_response_is_one_status_byte() {
    // CTAP2 returns the status byte alone, with no CBOR body. A client
    // reading a body that is not there gets a decode failure instead of
    // the error the token meant to report.
    let mut out = [0xffu8; 64];
    let n = fws::ctap::error(fws::ctap::CTAP2_ERR_NO_CREDENTIALS, &mut out);
    assert_eq!(n, 1, "an error response should be exactly one byte");
    assert_eq!(out[0], fws::ctap::CTAP2_ERR_NO_CREDENTIALS);
}

#[test]
fn get_info_is_a_well_formed_map_that_advertises_the_composite() {
    let mut out = [0u8; fws::ctap::RESP_MAX];
    let n = fws::ctap::get_info(&mut out).expect("getInfo did not fit RESP_MAX");
    assert!(n > 1, "getInfo produced no body");
    assert_eq!(
        out[0],
        fws::ctap::CTAP2_OK,
        "getInfo must lead with a status byte"
    );
    let body = &out[1..n];
    assert_eq!(body[0] & 0xe0, 0xa0, "the getInfo body must be a CBOR map");

    // The composite this build advertises has to be in there, or a PQ
    // relying party never offers it.
    let alg = enc(4, |w| w.nint(fws::ctap::COSE_ALG_HYBRID)).unwrap();
    assert!(
        body.windows(alg.len()).any(|c| c == &alg[..]),
        "getInfo does not mention the hybrid algorithm id"
    );
}

#[test]
fn get_info_refuses_a_buffer_it_cannot_fill() {
    // Rather than writing what fits. A truncated getInfo is a token that
    // appears to support nothing.
    let mut small = [0u8; 16];
    assert!(
        fws::ctap::get_info(&mut small).is_none(),
        "getInfo squeezed itself into 16 bytes"
    );
}

#[test]
fn pin_retries_reports_the_count_it_was_given() {
    for retries in [0u8, 1, 8] {
        let mut out = [0u8; 64];
        let n = fws::ctap::pin_retries(retries, &mut out).expect("pinRetries did not fit");
        assert_eq!(out[0], fws::ctap::CTAP2_OK);
        let body = &out[1..n];
        assert_eq!(body[0] & 0xe0, 0xa0, "the body must be a map");
        assert!(
            body.contains(&retries) || retries > 23,
            "the retry count {retries} does not appear in the response"
        );
    }
}

#[test]
fn key_agreement_carries_both_coordinates_verbatim() {
    // The client derives the shared secret from these. A truncated or
    // swapped coordinate produces a shared secret that differs from the
    // token's, and the only symptom is that every PIN operation fails.
    let x: [u8; 32] = core::array::from_fn(|i| i as u8);
    let y: [u8; 32] = core::array::from_fn(|i| 0xff - i as u8);
    let mut out = [0u8; 256];
    let n = fws::ctap::pin_key_agreement(&x, &y, &mut out).expect("keyAgreement did not fit");
    let body = &out[1..n];
    assert!(
        body.windows(32).any(|c| c == &x[..]),
        "the x coordinate is not in the response"
    );
    assert!(
        body.windows(32).any(|c| c == &y[..]),
        "the y coordinate is not in the response"
    );
}

#[test]
fn a_pin_token_is_returned_as_a_byte_string_of_its_own_length() {
    for len in [16usize, 32] {
        let token: Vec<u8> = (0..len).map(|i| i as u8 ^ 0x5a).collect();
        let mut out = [0u8; 128];
        let n = fws::ctap::pin_token(&token, &mut out).expect("pinToken did not fit");
        let body = &out[1..n];
        assert!(
            body.windows(len).any(|c| c == &token[..]),
            "the {len}-byte token is not in the response verbatim"
        );
    }
}

#[test]
fn responses_that_do_not_fit_report_it_instead_of_writing_a_prefix() {
    // Every builder returns Option for the same reason the writer does.
    let x = [0u8; 32];
    let mut tiny = [0u8; 8];
    assert!(fws::ctap::pin_key_agreement(&x, &x, &mut tiny).is_none());
    assert!(fws::ctap::pin_token(&[0u8; 32], &mut tiny).is_none());
    assert!(fws::ctap::pin_retries(8, &mut [0u8; 1]).is_none());
}
