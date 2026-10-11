// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! SHA-256 / HMAC-SHA-256 / HKDF-SHA-256 / constant-time compare, backed by
//! the Bouncy Castle Rust port.
//!
//! Why this module exists
//! ----------------------
//! These primitives used to come from the RustCrypto stack (`sha2`, `hmac`,
//! `subtle`, plus a hand-rolled HKDF). Everything the firmware hashes or MACs
//! now goes through here instead, so that the symmetric side of the CTAP2
//! stack has a single provider -- the same one that supplies ML-DSA.
//!
//! `p256` still pulls RustCrypto `sha2` and `digest` in transitively for its
//! own RFC 6979 / prehash internals, so this swap does not remove those crates
//! from the binary; ECDSA-P256 has no bc-rust equivalent (bc-rust's roadmap
//! declines ECDSA and ECDH outright). What it does buy is that *our* code has
//! one hashing provider rather than two.
//!
//! Equivalence
//! -----------
//! Every function here was checked byte-for-byte against the RustCrypto
//! implementation it replaced, across empty / 1-byte / block-boundary (55, 56,
//! 64) / multi-block inputs, 32-byte MAC keys including the all-zero key,
//! streaming and one-shot forms, and the two PIN-protocol-v2 HKDF info strings.
//!
//! Allocation
//! ----------
//! The bc-rust one-shot APIs (`Hash::hash`, `MAC::mac`) return `Vec`. Every
//! function here uses the `*_out` variants that write into a caller-provided
//! buffer, so no output buffer is heap-allocated. The hashes are then
//! allocation-free; HMAC (and HKDF through it) still allocates a few small
//! `Vec`s per operation inside bc-rust for the padded key and the inner
//! hash (an upstream TODO), which the 32 KiB CTAP2 heap absorbs.
//!
//! Keying
//! ------
//! bc-rust wraps MAC keys in a `KeyMaterial` carrying a `KeyType` and a
//! security-strength tag, and `MAC::new` rejects keys weaker than the hash.
//! CTAP legitimately MACs with an all-zero HKDF salt and with 32-byte keys
//! derived from a P-256 ECDH shared secret, so these helpers use
//! `new_allow_weak_key`, which skips that tag check. All MAC keys in the
//! firmware are exactly 32 bytes, matching `KeyMaterial::<32>`.

use bouncycastle_core_interface::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core_interface::traits::{Hash, MAC};
// Since bc-rust 0.1.3 the SHA-256 instantiations of HMAC and HKDF live in
// the sha2 crate; `bouncycastle-hmac` / `-hkdf` are the generic crates
// behind them and are reached only transitively.
use bouncycastle_sha2::hkdf::HKDF_SHA256;
use bouncycastle_sha2::hmac::HMAC_SHA256;
use bouncycastle_sha2::SHA256;

/// One-shot SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    SHA256::default().hash_out(data, &mut out);
    out
}

/// Streaming SHA-256, for callers that hash several pieces in sequence.
pub struct Sha256Ctx(SHA256);

impl Sha256Ctx {
    pub fn new() -> Self {
        Self(SHA256::default())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.do_update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.do_final_out(&mut out);
        out
    }
}

impl Default for Sha256Ctx {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrap a 32-byte MAC key. See the "Keying" note in the module docs for why
/// this is `new_allow_weak_key` rather than `new`.
fn mac_key(key: &[u8; 32]) -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(key, KeyType::MACKey).expect("32-byte MAC key")
}

/// One-shot HMAC-SHA-256.
pub fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mac = <HMAC_SHA256 as MAC>::new_allow_weak_key(&mac_key(key)).expect("hmac init");
    mac.mac_out(data, &mut out).expect("hmac output length");
    out
}

/// Streaming HMAC-SHA-256, for callers that MAC several pieces in sequence.
pub struct HmacCtx(HMAC_SHA256);

impl HmacCtx {
    pub fn new(key: &[u8; 32]) -> Self {
        Self(<HMAC_SHA256 as MAC>::new_allow_weak_key(&mac_key(key)).expect("hmac init"))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.do_update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.do_final_out(&mut out).expect("hmac output length");
        out
    }
}

/// HKDF-SHA-256 with an all-zero 32-byte salt and a 32-byte output, which is
/// the shape CTAP 2.1 PIN protocol v2 specifies for deriving the AES and HMAC
/// halves of the shared secret (sec. 6.5.6).
pub fn hkdf_sha256(ikm: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let salt =
        KeyMaterial::<32>::from_bytes_as_type(&[0u8; 32], KeyType::MACKey).expect("zero salt");
    let ikm_km = KeyMaterial::<32>::from_bytes_as_type(ikm, KeyType::CryptographicRandom)
        .expect("32-byte IKM");
    let mut okm = KeyMaterial::<32>::new();
    HKDF_SHA256::extract_and_expand_out(&salt, &ikm_km, info, 32, &mut okm).expect("hkdf derive");
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm.ref_to_bytes()[..32]);
    out
}

/// Constant-time byte comparison. Unequal lengths compare false, matching the
/// `subtle::ConstantTimeEq` behaviour this replaced (`ct_eq` there requires
/// equal-length slices; callers length-check first).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    bouncycastle_utils::ct::ct_eq_bytes(a, b)
}
