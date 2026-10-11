// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 (COSE alg `-8`) -- Phase 11c, feature-gated `ed25519` (off
//! by default).
//!
//! Thin wrapper over `ed25519-dalek` 2.x that mirrors the surface
//! `ctap2.rs` already uses for ECDSA-P256 / hybrid:
//!
//! | Helper                       | Returns                              |
//! |------------------------------|--------------------------------------|
//! | [`gen_seed`]                 | A fresh 32-byte seed from the TRNG.  |
//! | [`derive_public_bytes`]      | 32-byte raw public key from a seed.  |
//! | [`sign_with_seed`]           | 64-byte raw signature over a message |
//! | [`cose_key`]                 | COSE_Key map for the public key.     |
//!
//! ## Credential ID interop
//!
//! Ed25519 credentials use the v2 credentialID format (see
//! `credential_id.rs`'s [`VERSION_V2`]). The 32-byte seed lives in
//! the `ecdsa_scalar` slot of the [`CredentialSource`] plaintext;
//! the `mldsa_seed` slot stays zero (reserved). Decryption flips
//! the `alg` field to [`crate::credential_id::COSE_ALG_ED25519`]
//! based on the version byte.
//!
//! ## COSE_Key shape (RFC 8152 sec. 8.2)
//!
//! ```text
//!   1 (kty)   = 1 (OKP)
//!   3 (alg)   = -8 (EdDSA)
//!  -1 (crv)   = 6 (Ed25519)
//!  -2 (x)     = 32-byte raw public key
//! ```
//!
//! Notably `kty = 1 (OKP)` -- Ed25519 is an **Octet Key Pair**, not
//! an EC2 curve like P-256. This is the one place where our COSE
//! emission shape differs structurally from the ES256 / hybrid
//! paths in `ctap2.rs::emit_make_credential`.

#![cfg(feature = "ed25519")]

extern crate alloc;

use alloc::vec::Vec as AllocVec;

use ed25519_dalek::{Signer, SigningKey};
use pqf_cbor::{cbor_int, cbor_map, Value};

use rand_core::CryptoRngCore;

/// Generate a fresh 32-byte Ed25519 seed from the TRNG. The seed is
/// what we store in the [`CredentialSource::ecdsa_scalar`] slot of
/// a v2 credentialID; the matching [`SigningKey`] is rebuilt on
/// demand via `SigningKey::from_bytes(&seed)` (it's a deterministic
/// SHA-512-based key expansion per RFC 8032 sec. 5.1.5).
pub fn gen_seed(trng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut seed = [0u8; 32];
    trng.fill_bytes(&mut seed);
    seed
}

/// Recover the 32-byte raw Ed25519 public key from a seed. Pure
/// derivation -- no randomness involved.
pub fn derive_public_bytes(seed: &[u8; 32]) -> [u8; 32] {
    let sk = SigningKey::from_bytes(seed);
    sk.verifying_key().to_bytes()
}

/// Sign `message` with the Ed25519 private key derived from `seed`.
/// Returns the 64-byte raw signature (R || s). Ed25519 signatures
/// are deterministic per RFC 8032, so the same `(seed, message)`
/// pair always produces the same 64 bytes.
pub fn sign_with_seed(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let sk = SigningKey::from_bytes(seed);
    sk.sign(message).to_bytes()
}

/// Build the COSE_Key (RFC 8152 sec. 8.2) for an Ed25519 public key
/// suitable for embedding in `authenticatorData.attestedCredentialData`.
/// The encoded CBOR is what an RP feeds to its Ed25519 verifier on
/// each subsequent `getAssertion` round trip.
pub fn cose_key(public: &[u8; 32]) -> Value {
    cbor_map! {
        // kty = 1 (OKP -- Octet Key Pair, RFC 8152 sec. 13)
        cbor_int!(1) => cbor_int!(1),
        // alg = -8 (EdDSA)
        cbor_int!(3) => cbor_int!(-8),
        // crv = 6 (Ed25519, RFC 8152 sec. 13.2 + IANA COSE registry)
        cbor_int!(-1) => cbor_int!(6),
        // x = 32-byte public key
        cbor_int!(-2) => Value::Bytes({
            let mut v = AllocVec::with_capacity(32);
            v.extend_from_slice(public);
            v
        }),
    }
}
