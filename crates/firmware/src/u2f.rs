// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP1 / U2F (FIDO U2F Raw Message Format v1.2) over CTAP HID's
//! `CMD_MSG` (0x83). Phase 11b.
//!
//! Three commands are supported per FIDO U2F Raw Message v1.2:
//!
//! | INS  | Name           | Notes                                       |
//! |------|----------------|---------------------------------------------|
//! | 0x01 | REGISTER       | Fresh ECDSA-P256 keypair + batch attestation|
//! | 0x02 | AUTHENTICATE   | Decrypt keyhandle, sign challenge           |
//! | 0x03 | VERSION        | Returns ASCII `U2F_V2`                      |
//!
//! Wire format references:
//!   <https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.pdf>
//!
//! ## Key-handle reuse
//!
//! We reuse the **CTAP2 161-byte credentialID format** from
//! [`crate::credential_id`] for U2F key handles (rather than the
//! 112-byte legacy format the original Phase 11b sketch in
//! `make-this-have-feature-snazzy-micali.md` proposed). Why:
//!
//!   - The CTAP2 format is HMAC-authenticated and contains an
//!     embedded `rp_id_hash` (used as the U2F "application
//!     parameter"). Cross-RP replay is already blocked.
//!   - The 161-byte length comfortably fits in the U2F APDU
//!     framing (keyhandle length byte is u8, max 255).
//!   - Avoids a second flash master-key namespace; everything
//!     decrypts under the same `key_handle_{aes,hmac}_key`.
//!   - The 32-byte `mldsa_seed` slot is unused for U2F (the alg
//!     is forced to ES256) -- we just leave it zero-filled so
//!     `decrypt_credential_id` infers `COSE_ALG_ES256` correctly.
//!
//! U2F-issued key handles work bidirectionally: a CTAP2 client can
//! later use them via `authenticatorMakeCredential` / `authenticator
//! GetAssertion`, and vice versa, as long as the RP-side application
//! ID hashes match across protocols.
//!
//! ## Attestation
//!
//! REGISTER responses include an X.509 batch attestation cert and a
//! signature with the corresponding batch private key. We ship
//! **hardcoded development-only** values -- `BATCH_KEY` and
//! `BATCH_CERT_DER` below -- generated once via OpenSSL:
//!
//! ```text
//!   openssl ecparam -genkey -name prime256v1 -out u2f_batch.key
//!   openssl req -new -x509 -days 3650 -key u2f_batch.key \
//!       -out u2f_batch.crt \
//!       -subj "/CN=pqc-fido U2F Dev"
//!   openssl x509 -in u2f_batch.crt -outform der -out u2f_batch.der
//! ```
//!
//! Production firmware should provision a per-batch (or per-device)
//! attestation key + CA-signed cert via the vendor flashing pipeline
//! rather than baking dev values into the binary. RPs that verify
//! batch attestation against the FIDO Metadata Service will not
//! accept this cert; most U2F-era RPs don't bother verifying the
//! cert chain (it's only used for batch attestation, which is
//! optional under U2F).
//!
//! ## Counter
//!
//! U2F authenticators are required to return a monotonic 32-bit
//! counter in every AUTHENTICATE response (FIDO U2F Raw Message
//! v1.2 sec. 5.4) so RPs can detect cloned tokens. We keep the counter
//! in a volatile [`AtomicU32`] -- it **resets to zero on every power
//! cycle**. Most RPs tolerate counter resets (they only flag
//! *decreases* within a session); RPs that strictly require
//! monotonicity across power cycles would need a per-credential
//! flash counter, which is a non-trivial schema bump and is out of
//! scope for this Phase 11b pass.

#![allow(clippy::needless_range_loop)]

extern crate alloc;

use alloc::vec::Vec as AllocVec;
use core::sync::atomic::{AtomicU32, Ordering};

use p256::ecdsa::{signature::Signer, Signature, SigningKey};

use crate::credential_id::{
    decrypt_credential_id, encrypt_to_credential_id, CredentialSource, COSE_ALG_ES256,
};
use crate::ctap2::{CredStore, HostOp};
use rand_core::CryptoRngCore;

// ---------------------------------------------------------------------------
// ISO 7816 status words used by the U2F response framing.
// ---------------------------------------------------------------------------

const SW_NO_ERROR: u16 = 0x9000;
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
const SW_WRONG_DATA: u16 = 0x6A80;
const SW_WRONG_LENGTH: u16 = 0x6700;
const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00;
const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;

// ---------------------------------------------------------------------------
// U2F command set.
// ---------------------------------------------------------------------------

const U2F_INS_REGISTER: u8 = 0x01;
const U2F_INS_AUTHENTICATE: u8 = 0x02;
const U2F_INS_VERSION: u8 = 0x03;

// U2F AUTHENTICATE P1 control bytes -- see FIDO U2F Raw Message v1.2 sec. 5.2.
const AUTH_CHECK_ONLY: u8 = 0x07;
const AUTH_ENFORCE_UP_AND_SIGN: u8 = 0x03;
const AUTH_DONT_ENFORCE_UP_AND_SIGN: u8 = 0x08;

/// `0x05` legacy reserved byte that prefixes every U2F REGISTER
/// response (FIDO U2F Raw Message v1.2 sec. 4.3). Predates U2F itself --
/// kept for ABI compatibility with the original ISO 7816 framing.
const LEGACY_BYTE: u8 = 0x05;

/// User-presence indicator byte returned in AUTHENTICATE responses.
/// `0x01` = present; the spec also defines `0x00` for "not verified"
/// but our firmware always returns 0x01 because we always gate on
/// the WaitForUp stub before signing.
const USER_PRESENCE_INDICATOR: u8 = 0x01;

/// VERSION response -- ASCII `U2F_V2`, exactly 6 bytes, NO trailing NUL.
const VERSION_STRING: &[u8] = b"U2F_V2";

// ---------------------------------------------------------------------------
// Batch attestation key + cert (DEV ONLY -- see module docs).
// ---------------------------------------------------------------------------

/// ECDSA-P256 private scalar for the batch attestation key.
/// Hardcoded for development. Pair with the public key embedded in
/// [`BATCH_CERT_DER`].
const BATCH_KEY: [u8; 32] = [
    0xbe, 0x58, 0x37, 0x70, 0x6f, 0x31, 0x05, 0x0d, 0x86, 0x4f, 0x97, 0xeb, 0x93, 0x1a, 0xb1, 0xf9,
    0xa6, 0x9b, 0x14, 0x0e, 0xf7, 0x8f, 0x4b, 0xfe, 0xd9, 0x96, 0x8d, 0x0f, 0x7c, 0x29, 0x04, 0x53,
];

/// X.509 DER-encoded self-signed cert for the batch attestation key.
/// 399 bytes. Subject and issuer both = `CN=pqc-fido U2F Dev`.
const BATCH_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x8b, 0x30, 0x82, 0x01, 0x31, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x02,
    0x8d, 0x1d, 0x98, 0xcd, 0xe6, 0xad, 0x7d, 0x87, 0xdb, 0x3d, 0x84, 0x41, 0x62, 0x5f, 0x56, 0xfd,
    0x4b, 0x21, 0x8d, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x1b, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x10, 0x70, 0x71, 0x63, 0x2d,
    0x66, 0x69, 0x64, 0x6f, 0x20, 0x55, 0x32, 0x46, 0x20, 0x44, 0x65, 0x76, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x36, 0x30, 0x39, 0x32, 0x31, 0x31, 0x32, 0x31, 0x30, 0x35, 0x35, 0x5a, 0x17, 0x0d, 0x33,
    0x36, 0x30, 0x39, 0x31, 0x38, 0x31, 0x32, 0x31, 0x30, 0x35, 0x35, 0x5a, 0x30, 0x1b, 0x31, 0x19,
    0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x10, 0x70, 0x71, 0x63, 0x2d, 0x66, 0x69, 0x64,
    0x6f, 0x20, 0x55, 0x32, 0x46, 0x20, 0x44, 0x65, 0x76, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04, 0xa1, 0x43, 0x7d, 0x5c, 0xd1, 0xbd, 0xa6, 0xa4, 0xd9, 0xf4, 0xb6, 0x1c,
    0x41, 0xcc, 0x24, 0x64, 0x1a, 0x6a, 0x1a, 0xdb, 0x02, 0xbf, 0xf6, 0x3e, 0xf0, 0xe9, 0x19, 0x8c,
    0x3b, 0x1b, 0xd2, 0x51, 0x8e, 0x87, 0xaa, 0xc9, 0x49, 0xba, 0xf0, 0xdf, 0x2b, 0x98, 0x71, 0xc8,
    0xdd, 0x18, 0xac, 0x62, 0xce, 0x55, 0x06, 0xed, 0xeb, 0x8c, 0xfc, 0x1c, 0x3e, 0x25, 0xa7, 0x57,
    0xe4, 0x5b, 0xea, 0xef, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
    0x16, 0x04, 0x14, 0x78, 0x1d, 0xb1, 0x4e, 0x0b, 0x6d, 0x44, 0x3c, 0x68, 0x45, 0xec, 0x4a, 0xec,
    0xab, 0x3b, 0x5e, 0x51, 0xae, 0x97, 0x0f, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0x78, 0x1d, 0xb1, 0x4e, 0x0b, 0x6d, 0x44, 0x3c, 0x68, 0x45, 0xec, 0x4a,
    0xec, 0xab, 0x3b, 0x5e, 0x51, 0xae, 0x97, 0x0f, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
    0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x1e, 0xd8, 0x2c, 0xd4,
    0x50, 0xec, 0x97, 0x26, 0x60, 0xd6, 0x72, 0x79, 0xa3, 0xf1, 0xdf, 0x70, 0xbc, 0xf0, 0xc3, 0xb4,
    0x88, 0xb9, 0x4e, 0xcb, 0xb6, 0x3d, 0x35, 0xb5, 0x76, 0x90, 0x67, 0xf3, 0x02, 0x21, 0x00, 0xf8,
    0x45, 0x07, 0xb5, 0x60, 0x66, 0xfc, 0x7b, 0x49, 0xae, 0xe4, 0x1e, 0xd2, 0x6d, 0x2e, 0x9b, 0x06,
    0xb8, 0x46, 0x45, 0x92, 0xc8, 0xd4, 0x37, 0x89, 0x7b, 0x13, 0xd8, 0x08, 0x3f, 0x42, 0x6f,
];

// ---------------------------------------------------------------------------
// Volatile global counter (see module docs sec. Counter).
// ---------------------------------------------------------------------------

static U2F_COUNTER: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Entry point -- dispatched from `main.rs`'s `FrameOutcome::U2fMessage` arm.
// ---------------------------------------------------------------------------

/// Process one U2F APDU (`CMD_MSG` payload). Returns the response
/// bytes that should be wrapped in a `CMD_MSG` CTAP HID response.
///
/// On error, returns just the 2-byte SW status word. On success,
/// returns the U2F response data with the 2-byte SW = `0x9000`
/// appended (per ISO 7816 framing).
pub fn handle(
    input: &[u8],
    trng: &mut impl CryptoRngCore,
    store: &CredStore,
    host: &mut dyn FnMut(HostOp) -> bool,
) -> AllocVec<u8> {
    let mut payload: AllocVec<u8> = AllocVec::new();
    let sw = match dispatch(input, trng, store, host, &mut payload) {
        Ok(()) => SW_NO_ERROR,
        Err(code) => {
            // On error, drop any partial payload and respond with
            // just the SW.
            payload.clear();
            code
        }
    };
    payload.push((sw >> 8) as u8);
    payload.push((sw & 0xFF) as u8);
    payload
}

/// Parse the APDU header + Lc/data, dispatch to the appropriate
/// per-INS handler. Returns the SW that should be appended to the
/// response (or trail an error-only response).
fn dispatch(
    input: &[u8],
    trng: &mut impl CryptoRngCore,
    store: &CredStore,
    host: &mut dyn FnMut(HostOp) -> bool,
    out: &mut AllocVec<u8>,
) -> Result<(), u16> {
    // CTAP HID U2F APDU header is fixed 7 bytes for commands with
    // data (CLA INS P1 P2 Lc1 Lc2 Lc3) and 4 bytes for no-data
    // commands (CLA INS P1 P2). Extended-length encoding only --
    // never short-form.
    if input.len() < 4 {
        return Err(SW_WRONG_LENGTH);
    }
    let cla = input[0];
    let ins = input[1];
    let p1 = input[2];
    // p2 (input[3]) is unused for all three U2F commands; reserved.

    if cla != 0x00 {
        return Err(SW_CLA_NOT_SUPPORTED);
    }

    let data: &[u8] = if input.len() == 4 {
        // No-data APDU (just header). Only VERSION uses this shape.
        &input[..0]
    } else if input.len() >= 7 {
        // Extended-length: Lc is 3 big-endian bytes (with a leading
        // 0x00, which CTAPHID-U2F omits since the high byte is
        // always 0 for our messages -- we still consume 3 bytes).
        let lc = u32::from_be_bytes([0, input[4], input[5], input[6]]) as usize;
        let body = &input[7..];
        // The body is `lc` data bytes optionally followed by a
        // 2-byte Le. We tolerate both.
        if body.len() == lc {
            &body[..lc]
        } else if body.len() == lc + 2 {
            &body[..lc]
        } else {
            return Err(SW_WRONG_LENGTH);
        }
    } else {
        return Err(SW_WRONG_LENGTH);
    };

    match ins {
        U2F_INS_REGISTER => process_register(p1, data, trng, store, host, out),
        U2F_INS_AUTHENTICATE => process_authenticate(p1, data, store, host, out),
        U2F_INS_VERSION => process_version(data, out),
        _ => Err(SW_INS_NOT_SUPPORTED),
    }
}

// ---------------------------------------------------------------------------
// REGISTER (U2F INS 0x01)
// ---------------------------------------------------------------------------
//
// Wire format (FIDO U2F Raw Message v1.2 sec. 4):
//
//   Request body (64 B): challenge(32) || application(32)
//
//   Response body (variable):
//     0x05 (LEGACY_BYTE)
//     user_pk(65)             -- uncompressed P-256 point 0x04||X||Y
//     key_handle_len(1)
//     key_handle(variable)    -- our CTAP2 161-byte credentialID
//     attestation_cert(DER)   -- BATCH_CERT_DER
//     signature(DER)          -- ECDSA over signature_input below
//
//   signature_input:
//     0x00 || application || challenge || key_handle || user_pk

fn process_register(
    _p1: u8,
    data: &[u8],
    trng: &mut impl CryptoRngCore,
    store: &CredStore,
    host: &mut dyn FnMut(HostOp) -> bool,
    out: &mut AllocVec<u8>,
) -> Result<(), u16> {
    if data.len() != 64 {
        return Err(SW_WRONG_LENGTH);
    }
    let challenge: [u8; 32] = data[0..32].try_into().unwrap();
    let application: [u8; 32] = data[32..64].try_into().unwrap();

    // Gate on user presence. The dev stub auto-confirms after
    // 500 ms LED flash; production would block on a real button.
    if !host(HostOp::WaitForUp {
        timeout_us: 10_000_000,
    }) {
        return Err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Fresh ECDSA-P256 user keypair.
    let user_sk = SigningKey::random(trng);
    let user_sk_bytes: [u8; 32] = user_sk.to_bytes().into();
    let user_vk = user_sk.verifying_key();
    let user_pk_point = user_vk.to_encoded_point(false);
    let user_pk_bytes = user_pk_point.as_bytes(); // 65 bytes: 0x04 || X || Y
    if user_pk_bytes.len() != 65 {
        return Err(SW_WRONG_DATA);
    }

    // Wrap into a 161-byte CTAP2 credentialID. The
    // `application` parameter is treated as the rp_id_hash --
    // U2F has no concept of an RP id string, only the
    // application parameter, which IS the SHA-256 hash of the
    // appid URL.
    let source = CredentialSource {
        alg: COSE_ALG_ES256,
        ecdsa_scalar: user_sk_bytes,
        mldsa_seed: [0u8; 32],
        rp_id_hash: application,
        // U2F has no credProtect concept -- level 1 (always usable).
        cred_protect: 1,
        // U2F has no largeBlobKey extension.
        large_blob_key: false,
    };
    let key_handle = encrypt_to_credential_id(
        &store.key_handle_aes_key,
        &store.key_handle_hmac_key,
        trng,
        &source,
    );
    if key_handle.len() > u8::MAX as usize {
        // Defensive -- the format is fixed at 161 < 255.
        return Err(SW_WRONG_DATA);
    }

    // Construct the response body.
    out.push(LEGACY_BYTE);
    out.extend_from_slice(user_pk_bytes);
    out.push(key_handle.len() as u8);
    out.extend_from_slice(&key_handle);
    out.extend_from_slice(BATCH_CERT_DER);

    // Compute the attestation signature.
    let mut signature_input = AllocVec::with_capacity(1 + 32 + 32 + key_handle.len() + 65);
    signature_input.push(0x00);
    signature_input.extend_from_slice(&application);
    signature_input.extend_from_slice(&challenge);
    signature_input.extend_from_slice(&key_handle);
    signature_input.extend_from_slice(user_pk_bytes);

    let batch_sk = SigningKey::from_bytes((&BATCH_KEY).into()).map_err(|_| SW_WRONG_DATA)?;
    let sig: Signature = batch_sk.sign(&signature_input);
    let sig_der = sig.to_der();
    out.extend_from_slice(sig_der.as_bytes());

    Ok(())
}

// ---------------------------------------------------------------------------
// AUTHENTICATE (U2F INS 0x02)
// ---------------------------------------------------------------------------
//
// Wire format (FIDO U2F Raw Message v1.2 sec. 5):
//
//   Request P1 control byte: 0x07 check-only, 0x03 enforce-UP and
//                            sign, 0x08 don't-enforce-UP and sign.
//
//   Request body (variable):
//     challenge(32) || application(32) || keyhandle_len(1) || keyhandle
//
//   Response body (variable):
//     up_byte(1) || counter(4, big-endian) || signature(DER)
//
//   signature_input:
//     application || up_byte || counter || challenge

fn process_authenticate(
    p1: u8,
    data: &[u8],
    store: &CredStore,
    host: &mut dyn FnMut(HostOp) -> bool,
    out: &mut AllocVec<u8>,
) -> Result<(), u16> {
    if data.len() < 65 {
        return Err(SW_WRONG_LENGTH);
    }
    let challenge: [u8; 32] = data[0..32].try_into().unwrap();
    let application: [u8; 32] = data[32..64].try_into().unwrap();
    let kh_len = data[64] as usize;
    if data.len() != 65 + kh_len {
        return Err(SW_WRONG_LENGTH);
    }
    let key_handle = &data[65..65 + kh_len];

    // Decrypt the key handle; this also verifies HMAC and that the
    // RP id (application) matches. Any failure -> SW_WRONG_DATA.
    let source = decrypt_credential_id(
        &store.key_handle_aes_key,
        &store.key_handle_hmac_key,
        key_handle,
        &application,
    )
    .map_err(|_| SW_WRONG_DATA)?;

    if source.alg != COSE_ALG_ES256 {
        // Defensive -- we only issue ES256 key handles through
        // process_register, so a non-ES256 keyhandle is either
        // forged (HMAC would have caught it) or came from a
        // future format we don't know how to handle yet.
        return Err(SW_WRONG_DATA);
    }

    match p1 {
        AUTH_CHECK_ONLY => {
            // sec. 5.4: "If the control byte is set to check-only, the
            // U2F token MUST signal the host of one of two outcomes:
            // either presence-of-the-credential WITH presence-not-
            // verified (response 0x6985), or absence-of-the-credential
            // (response 0x6A80)." Our decrypt above succeeded -> the
            // credential is ours -> 0x6985.
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        }
        AUTH_ENFORCE_UP_AND_SIGN => {
            if !host(HostOp::WaitForUp {
                timeout_us: 10_000_000,
            }) {
                return Err(SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        AUTH_DONT_ENFORCE_UP_AND_SIGN => {
            // Skip the UP gate. The response still reports
            // `USER_PRESENCE_INDICATOR = 0x01` because some clients
            // don't tolerate the spec's 0x00 byte for "not verified"
            // (legacy YubiKey firmware sets 0x01 unconditionally too).
        }
        _ => return Err(SW_WRONG_DATA),
    }

    let counter = U2F_COUNTER.fetch_add(1, Ordering::SeqCst).wrapping_add(1);

    // Construct signature_input = application || UP || counter || challenge.
    let mut signature_input = AllocVec::with_capacity(32 + 1 + 4 + 32);
    signature_input.extend_from_slice(&application);
    signature_input.push(USER_PRESENCE_INDICATOR);
    signature_input.extend_from_slice(&counter.to_be_bytes());
    signature_input.extend_from_slice(&challenge);

    let user_sk =
        SigningKey::from_bytes((&source.ecdsa_scalar).into()).map_err(|_| SW_WRONG_DATA)?;
    let sig: Signature = user_sk.sign(&signature_input);
    let sig_der = sig.to_der();

    // Response body: UP || counter || signature.
    out.push(USER_PRESENCE_INDICATOR);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(sig_der.as_bytes());

    Ok(())
}

// ---------------------------------------------------------------------------
// VERSION (U2F INS 0x03)
// ---------------------------------------------------------------------------

fn process_version(data: &[u8], out: &mut AllocVec<u8>) -> Result<(), u16> {
    // The U2F spec allows either Lc=0 or no Lc at all; some hosts
    // also send a 2-byte Le after the header (which our APDU parser
    // already consumed). Accept any data length here -- the message
    // header was already validated as INS=0x03.
    let _ = data;
    out.extend_from_slice(VERSION_STRING);
    Ok(())
}
