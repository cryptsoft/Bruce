// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Stateless encrypted credential IDs -- compact 161-byte format.
//!
//! Background
//! ----------
//!
//! Pre-Phase-2 the credentialId was a 32-byte random handle and all key
//! material lived in the flash store. That capped the device at
//! ~19 credentials. OpenSK's solution is to put the key material
//! **inside the credentialId itself**, encrypted under a device-wide
//! master key. The RP sends the credentialId back on every login; we
//! decrypt it, recover the keys, and sign.
//!
//! Our first cut of Phase 2 mirrored OpenSK's CBOR v1 format
//! byte-for-byte at 241 bytes (1 ver + 16 IV + 192 CBOR ciphertext + 32
//! HMAC). That format is generous: it pads the CBOR plaintext to a
//! fixed 192 B so future extensions (CredProtect / CredBlob /
//! hmac-secret cred_random) can be added without changing the wire
//! length. Trouble is, base64url(241) = 322 chars, which doesn't fit
//! relying parties whose `credential_id` column is `VARCHAR(255)`
//! (the PQC-aware RP this firmware was developed against among them).
//!
//! Compact 161-byte format
//! -----------------------
//!
//! We sidestep the OpenSK CBOR + padding overhead by laying out the
//! plaintext as fixed-length raw fields, no CBOR. base64url(161) = 215
//! chars, still under the 255-char RP database column budget.
//!
//! ```text
//!   offset  length  field
//!   ------  ------  ------------------------------------------------
//!     0       1     version = 0x01
//!     1      16     AES-256-CBC IV (random per credential)
//!    17     112     ciphertext of the 112-byte plaintext
//!   129      32     HMAC-SHA-256(hmac_key, bytes[0..129])
//!   ------  ------
//!   total: 161 bytes
//! ```
//!
//! Plaintext (112 B exactly -- 7 AES blocks, no padding):
//!
//! ```text
//!   [0..32]   ECDSA-P256 private scalar
//!   [32..64]  ML-DSA-65 seed (all-zero iff alg == ES256)
//!   [64..96]  rp_id_hash (SHA-256(rp.id), no truncation)
//!   [96]      credProtect policy (1/2/3; 0 => level 1)
//!   [97]      largeBlobKey flag (1 iff minted with the extension)
//!   [98..112] reserved (zero)
//! ```
//!
//! `alg` is recovered by zero-checking `mldsa_seed`:
//!   - all-zero  -> ES256  (COSE alg -7)
//!   - otherwise -> hybrid (`mldsa_alg::COSE_ALG_HYBRID_MLDSA`, this
//!     build's composite id -- -54 / -55 / -56 by cargo feature)
//!
//! The COSE id itself is never stored, so relabelling the composite
//! ids changes no credential: an id minted under an older label is
//! reported with the current one.
//!
//! The probability of a real ML-DSA seed being all-zero is
//! 2^(-256) -- effectively never -- so this is unambiguous in practice.
//! Future ML-DSA-44 / ML-DSA-87 variants (Phase 3) have the same
//! 32-byte seed size and are distinguished by cargo feature at build
//! time, not by runtime introspection.
//!
//! What about future extensions?
//! -----------------------------
//!
//! CredProtect / CredBlob / hmac-secret-cred-random (Phase 4) won't fit
//! in this format's fixed plaintext. The plan is:
//!   - For resident-key credentials (Chrome's typical rk=true flow),
//!     stash the extension data in the per-credential flash slot.
//!   - For non-resident credentials, derive deterministic per-credential
//!     secrets via `HMAC(master_key, credentialId)` so we don't have to
//!     store anything extra in the credentialId itself.
//!
//! Both approaches keep the credentialId at 161 bytes for the
//! foreseeable future.

#![allow(clippy::needless_range_loop)]

use crate::bc_crypto::{ct_eq, HmacCtx};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use zeroize::Zeroize;

use rand_core::CryptoRngCore;

/// COSE algorithm identifiers. ES256 is constant; the hybrid alg is
/// a re-export of `mldsa_alg::COSE_ALG_HYBRID_MLDSA` (which resolves
/// to the composite id of this build's ML-DSA level, defined once in
/// `pqf_signer_core::mldsa_alg`). The `65` in the alias is historical:
/// it is the hybrid id for whichever level is compiled in. credential_id has no choice
/// here -- the firmware can only emit one ML-DSA variant at a time,
/// and the plaintext layout is variant-agnostic (32 B scalar + 32 B
/// seed + 32 B rp_id_hash) because all three ML-DSA seeds are 32 B
/// per FIPS 204 sec. 6.1.
pub const COSE_ALG_ES256: i64 = -7;
pub use crate::mldsa_alg::COSE_ALG_HYBRID_MLDSA as COSE_ALG_HYBRID_MLDSA65;

/// COSE alg -8 = EdDSA over Curve25519 (Ed25519). Only meaningful
/// when the `ed25519` cargo feature is enabled (Phase 11c). The
/// constant itself is always defined so `ctap2.rs`'s algorithm
/// picker can reference it unconditionally; the feature gate
/// controls whether we actually issue / accept this alg.
pub const COSE_ALG_ED25519: i64 = -8;

/// On-wire credential ID size -- fixed 161 bytes
/// (`1 ver + 16 IV + 112 ct + 32 HMAC`). base64url = 215 chars, still
/// < the 255-char RP column budget. Grew from 145 in the credProtect
/// pass: the plaintext now carries the credProtect policy byte so the
/// policy is enforceable on non-resident / evicted credentials too
/// (matching the C port's 161-byte layout). Credentials minted under
/// the old 145-byte format no longer decrypt (length check rejects
/// them) -- a one-time re-registration after flashing this build.
pub const CRED_ID_LEN: usize = 161;
/// AES-CBC plaintext / ciphertext size in bytes. Fixed at 112 = 7 AES
/// blocks (no padding) so the layout is deterministic on both encode
/// and decode.
pub const PLAIN_LEN: usize = 112;

/// CredentialID version byte for ES256-only and OpenSK-PQC-fork hybrid
/// credentials. Plaintext layout:
///
/// ```text
///   [0..32]   ECDSA-P256 private scalar
///   [32..64]  ML-DSA seed (all-zero iff alg == ES256, otherwise hybrid)
///   [64..96]  rp_id_hash
/// ```
const VERSION_V1: u8 = 0x01;

/// CredentialID version byte for Ed25519 (COSE alg -8) credentials.
/// Phase 11c. Plaintext layout:
///
/// ```text
///   [0..32]   Ed25519 seed (becomes the SigningKey via from_bytes)
///   [32..64]  reserved, MUST be all-zero
///   [64..96]  rp_id_hash
/// ```
///
/// Same 112 B plaintext / 161 B credentialID length as v1 -- the
/// version byte is what disambiguates. Builds without `ed25519`
/// feature still recognise the version byte but reject v2
/// credentials with `BadFormat` (`emit_get_assertion` then maps
/// that to `CTAP2_ERR_NO_CREDENTIALS`).
const VERSION_V2: u8 = 0x02;

const IV_LEN: usize = 16;

/// HMAC domain-separation tags (X11).
///
/// Three independent secrets are derived by HMAC-SHA-256 keyed on the
/// *single* device master MAC key (`hmac_key`): the credentialId
/// integrity tag, the hmac-secret `cred_random`, and the `largeBlobKey`.
/// To guarantee these can never collide -- regardless of credentialId
/// length or content -- every HMAC keyed on the master MAC key prepends
/// a distinct ASCII domain label as the FIRST bytes of the HMAC
/// message. The labels carry no NUL terminator. They diverge within
/// their first five bytes (`c` / `h` / `l` at index 4) and none is a
/// prefix of another, so no two HMAC inputs can ever be equal -> the
/// separation is rigorous and length-independent. These exact byte
/// strings are shared verbatim with the C port so the two derivations
/// are byte-for-byte mirrors.
const DOMAIN_CRED_ID: &[u8] = b"pqf-cred-id";
const DOMAIN_CRED_RANDOM: &[u8] = b"pqf-hmac-secret";
const DOMAIN_LARGE_BLOB_KEY: &[u8] = b"pqf-large-blob-key";

const OFF_ECDSA_SCALAR: usize = 0;
const OFF_MLDSA_SEED: usize = 32;
const OFF_RP_ID_HASH: usize = 64;
/// credProtect policy byte (1/2/3; 0 treated as level 1). Carried in
/// the plaintext so the policy survives on non-resident credentials.
/// [97] is the flags byte (bit 0 = largeBlobKey); [98..112] are
/// reserved (zero).
const OFF_CRED_PROTECT: usize = 96;
const OFF_LARGE_BLOB_KEY: usize = 97;

/// The plaintext payload we round-trip through encryption.
#[derive(Clone, Debug)]
pub struct CredentialSource {
    /// COSE algorithm code (`COSE_ALG_ES256` or `COSE_ALG_HYBRID_MLDSA65`).
    pub alg: i64,
    /// ECDSA-P256 private scalar. Always present.
    pub ecdsa_scalar: [u8; 32],
    /// ML-DSA-65 seed. Only meaningful for hybrid creds; for ES256-only
    /// creds set to `[0u8; 32]` and just don't read it later.
    pub mldsa_seed: [u8; 32],
    /// SHA-256(rp.id). Re-checked on decrypt as a cross-RP-replay guard:
    /// even with a valid HMAC, a credentialId issued for RP_A won't be
    /// accepted as a credential for RP_B.
    pub rp_id_hash: [u8; 32],
    /// credProtect policy (1/2/3; 0 => default level 1). Carried in the
    /// credentialId plaintext so GetAssertion can enforce the policy
    /// even for a non-resident / FIFO-evicted credential that has no
    /// flash slot to read it from (CTAP 2.1 sec. 12.1.1).
    pub cred_protect: u8,
    /// True iff this credential was minted with the `largeBlobKey`
    /// extension. Carried in plaintext flags byte [97] (bit 0) so GetAssertion
    /// can return the credential's largeBlobKey even for a non-resident
    /// credential that has no flash slot to read it from (WebAuthn L3 /
    /// CTAP 2.1 sec. 6.1.3). Authenticated by the credentialId HMAC; old
    /// credentialIds (byte 97 == 0) decrypt as `false`, so the format is
    /// backward compatible.
    pub large_blob_key: bool,
}

/// Wipe the recovered private key material when a [`CredentialSource`]
/// is dropped. The ECDSA-P256 scalar (or Ed25519 seed) and the ML-DSA
/// seed are the root signing secrets; `zeroize()` performs a volatile
/// write that the optimiser may not elide, so the cleartext keys do not
/// linger on the stack after the signing borrow ends. `Zeroize` is the
/// trait-only API (no derive feature pulled in).
impl Drop for CredentialSource {
    fn drop(&mut self) {
        self.ecdsa_scalar.zeroize();
        self.mldsa_seed.zeroize();
    }
}

/// Errors decryption can produce. Encryption is infallible (we control
/// all the inputs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// Wrong length or wrong version byte.
    BadFormat,
    /// HMAC over `ver || IV || ciphertext` didn't match -- the
    /// credentialId wasn't produced by this device, or it's been
    /// tampered with.
    BadHmac,
    /// rp_id_hash in the decrypted payload didn't match the rp the
    /// current request is for -- cross-RP replay attempt or stale
    /// credential ID.
    RpMismatch,
}

/// Encrypt a [`CredentialSource`] into a 161-byte credentialId. The 16
/// IV bytes come from `trng` so every credentialId is unique even when
/// the underlying keys are not (a defence-in-depth measure -- our flow
/// always generates fresh keys per credential, but a future code path
/// that re-encrypts the same keys would benefit).
///
/// **Version routing** (`credential_id[0]`):
///   - `source.alg == COSE_ALG_ED25519` (-8) -> emit a v2 credential
///     (`version = 0x02`). The `ecdsa_scalar` slot holds the Ed25519
///     seed; the `mldsa_seed` slot MUST be zero (reserved) and is
///     checked on decrypt.
///   - Everything else (ES256 or OpenSK PQC hybrid) -> emit a v1
///     credential (`version = 0x01`). Layout unchanged from the
///     pre-Phase-11c format.
pub fn encrypt_to_credential_id(
    aes_key: &[u8; 32],
    hmac_key: &[u8; 32],
    trng: &mut impl CryptoRngCore,
    source: &CredentialSource,
) -> [u8; CRED_ID_LEN] {
    // 1) Lay out the 96-byte plaintext. For both versions the layout
    //    is the same -- the `ecdsa_scalar` field carries whatever
    //    32-byte key material the alg uses (ECDSA-P256 scalar OR
    //    Ed25519 seed), and `mldsa_seed` is either the actual ML-DSA
    //    seed (v1 hybrid) or zero (v1 ES256, v2 Ed25519).
    // Alg discriminator (X11): for a v1 credential the ES256-vs-hybrid
    // distinction is recovered on decrypt by zero-checking the ML-DSA
    // seed (an all-zero seed => ES256). This is an internal,
    // HMAC-authenticated discriminator, NOT a wire guarantee. A hybrid
    // credential minted with an all-zero seed would therefore be
    // mis-decoded as ES256; assert that never happens. (A real ML-DSA
    // seed being all-zero is a 2^-256 event, so this only fires on a
    // programming error.) ES256 and Ed25519 (v2) creds carry an
    // intentionally zero seed and are exempt.
    debug_assert!(
        source.alg == COSE_ALG_ES256
            || source.alg == COSE_ALG_ED25519
            || source.mldsa_seed != [0u8; 32],
        "hybrid credential minted with an all-zero ML-DSA seed would decode as ES256",
    );

    let mut plaintext = [0u8; PLAIN_LEN];
    plaintext[OFF_ECDSA_SCALAR..OFF_ECDSA_SCALAR + 32].copy_from_slice(&source.ecdsa_scalar);
    // For a v2 (Ed25519) credential the mldsa_seed slot is RESERVED and
    // decrypt rejects a non-zero value as BadFormat; force it zero here
    // (rather than copy source.mldsa_seed) so encode can never mint a
    // blob its own decode would reject (L21). For v1 it carries the real
    // ML-DSA seed (hybrid) or is already zero (ES256).
    if source.alg != COSE_ALG_ED25519 {
        plaintext[OFF_MLDSA_SEED..OFF_MLDSA_SEED + 32].copy_from_slice(&source.mldsa_seed);
    }
    plaintext[OFF_RP_ID_HASH..OFF_RP_ID_HASH + 32].copy_from_slice(&source.rp_id_hash);
    plaintext[OFF_CRED_PROTECT] = source.cred_protect;
    plaintext[OFF_LARGE_BLOB_KEY] = source.large_blob_key as u8; // [98..112] stay zero

    // 2) Random IV.
    let mut iv = [0u8; IV_LEN];
    trng.fill_bytes(&mut iv);

    // 3) AES-256-CBC encrypt the plaintext in place.
    cbc_encrypt_inplace(aes_key, &iv, &mut plaintext);

    // 4) Assemble [ver || IV || ciphertext], HMAC, append. The
    //    version byte is part of the HMAC input so a v1 and a v2
    //    credential with otherwise identical ciphertext have
    //    distinct HMAC tags.
    let mut credential_id = [0u8; CRED_ID_LEN];
    credential_id[0] = if source.alg == COSE_ALG_ED25519 {
        VERSION_V2
    } else {
        VERSION_V1
    };
    credential_id[1..1 + IV_LEN].copy_from_slice(&iv);
    credential_id[1 + IV_LEN..1 + IV_LEN + PLAIN_LEN].copy_from_slice(&plaintext);
    let hmac_in_len = 1 + IV_LEN + PLAIN_LEN; // 129 (= 1 + IV_LEN + PLAIN_LEN)
    let mut mac = HmacCtx::new(hmac_key);
    // X11: domain-separate the integrity tag by prepending DOMAIN_CRED_ID
    // to the signed region. MUST mirror decrypt exactly, or no
    // credential will verify.
    mac.update(DOMAIN_CRED_ID);
    mac.update(&credential_id[..hmac_in_len]);
    let tag = mac.finalize();
    credential_id[hmac_in_len..].copy_from_slice(&tag);
    credential_id
}

/// Decrypt and authenticate `blob` against this device's master keys.
/// `expected_rp_id_hash` is matched against the embedded one; pass the
/// SHA-256 of the request's `rp.id`.
///
/// Constant-time-ish behaviour: HMAC tag comparison uses
/// `bc_crypto::ct_eq`. The rp_id_hash mismatch check is after
/// HMAC passes, so it can't act as an oracle on unauthenticated inputs.
pub fn decrypt_credential_id(
    aes_key: &[u8; 32],
    hmac_key: &[u8; 32],
    blob: &[u8],
    expected_rp_id_hash: &[u8; 32],
) -> Result<CredentialSource, DecryptError> {
    if blob.len() != CRED_ID_LEN {
        return Err(DecryptError::BadFormat);
    }
    let version = blob[0];
    // Phase 11c: we recognise v1 (ES256 / hybrid) and v2 (Ed25519,
    // only when the `ed25519` cargo feature is enabled). v2 blobs
    // from other firmware get rejected as BadFormat by builds that
    // don't have the feature, so the host falls back to whatever
    // other credential it has on file for the user.
    if version != VERSION_V1 && version != VERSION_V2 {
        return Err(DecryptError::BadFormat);
    }
    #[cfg(not(feature = "ed25519"))]
    if version == VERSION_V2 {
        return Err(DecryptError::BadFormat);
    }
    let hmac_in_len = 1 + IV_LEN + PLAIN_LEN; // 129 (= 1 + IV_LEN + PLAIN_LEN)
    let (signed, tag) = blob.split_at(hmac_in_len);
    let mut mac = HmacCtx::new(hmac_key);
    // X11: prepend DOMAIN_CRED_ID exactly as encrypt does -- these two
    // sites MUST stay symmetric or the tag will never match.
    mac.update(DOMAIN_CRED_ID);
    mac.update(signed);
    let expected = mac.finalize();
    if !ct_eq(&expected, tag) {
        return Err(DecryptError::BadHmac);
    }

    let iv: [u8; IV_LEN] = signed[1..1 + IV_LEN].try_into().unwrap();
    let mut plaintext = [0u8; PLAIN_LEN];
    plaintext.copy_from_slice(&signed[1 + IV_LEN..]);
    cbc_decrypt_inplace(aes_key, &iv, &mut plaintext);

    let mut ecdsa_scalar = [0u8; 32];
    let mut mldsa_seed = [0u8; 32];
    let mut rp_id_hash = [0u8; 32];
    ecdsa_scalar.copy_from_slice(&plaintext[OFF_ECDSA_SCALAR..OFF_ECDSA_SCALAR + 32]);
    mldsa_seed.copy_from_slice(&plaintext[OFF_MLDSA_SEED..OFF_MLDSA_SEED + 32]);
    rp_id_hash.copy_from_slice(&plaintext[OFF_RP_ID_HASH..OFF_RP_ID_HASH + 32]);
    let cred_protect = plaintext[OFF_CRED_PROTECT];
    let large_blob_key = plaintext[OFF_LARGE_BLOB_KEY] != 0;
    // The decrypted plaintext holds the private scalar / ML-DSA seed; we
    // have copied out every field we need, so wipe the buffer before any
    // return path (volatile write, not elidable). The returned typed
    // copies are themselves cleared by `CredentialSource`'s Drop.
    plaintext.zeroize();

    if &rp_id_hash != expected_rp_id_hash {
        // Wipe the recovered key material on the reject path too -- it is
        // not handed to a `CredentialSource` whose Drop would clear it.
        ecdsa_scalar.zeroize();
        mldsa_seed.zeroize();
        return Err(DecryptError::RpMismatch);
    }

    // Alg dispatch:
    //   v1: a real ML-DSA seed being all-zero is a 2^-256 event,
    //       so the zero-check is a reliable ES256 / hybrid
    //       discriminator. This all-zero-seed => ES256 mapping is an
    //       internal discriminator authenticated by the integrity tag
    //       above, NOT a wire-format guarantee -- encrypt asserts a
    //       hybrid cred is never minted with an all-zero seed (X11).
    //       Constant-time to avoid timing oracle on
    //       authenticated-but-not-yet-validated plaintext.
    //   v2: the `ecdsa_scalar` slot is actually the Ed25519 seed
    //       and the `mldsa_seed` slot is reserved (MUST be zero).
    //       If the reserved slot is non-zero the blob is malformed
    //       and we treat it as BadFormat -- but only AFTER HMAC has
    //       passed, so this can't act as an oracle on attacker-
    //       controlled inputs.
    let alg = match version {
        VERSION_V1 => {
            if ct_eq(&mldsa_seed, &[0u8; 32]) {
                COSE_ALG_ES256
            } else {
                COSE_ALG_HYBRID_MLDSA65
            }
        }
        VERSION_V2 => {
            if !ct_eq(&mldsa_seed, &[0u8; 32]) {
                // Malformed-but-authenticated v2 blob: wipe the recovered
                // key material before bailing (no `CredentialSource` to
                // carry its Drop here).
                ecdsa_scalar.zeroize();
                mldsa_seed.zeroize();
                return Err(DecryptError::BadFormat);
            }
            COSE_ALG_ED25519
        }
        _ => unreachable!("version byte was validated above"),
    };

    Ok(CredentialSource {
        alg,
        ecdsa_scalar,
        mldsa_seed,
        rp_id_hash,
        cred_protect,
        large_blob_key,
    })
}

/// Derive the per-credential `cred_random` value used by the
/// `hmac-secret` extension (CTAP 2.1 sec. 12.5.3) deterministically from
/// the device's HMAC master key and the credentialId. This avoids
/// having to persist a per-credential `cred_random` byte string --
/// regenerating it from the same `(hmac_key, credentialId, uv_byte)`
/// triple always yields the same 32 B output, so the RP gets stable
/// HMAC results across power cycles and across non-resident
/// credentials (which have no flash slot at all).
///
/// `uv_present` selects between two independent `cred_random`s per
/// credential:
///   - `false` (uv_byte = 0x00) -> `cred_random_no_uv`
///   - `true`  (uv_byte = 0x01) -> `cred_random_with_uv`
/// This matches OpenSK's `generate_cred_random` (`OpenSK/src/ctap/
/// mod.rs`) and is what lets an RP distinguish "user presence only"
/// secrets from "user-verified" secrets.
pub fn derive_cred_random(hmac_key: &[u8; 32], credential_id: &[u8], uv_present: bool) -> [u8; 32] {
    let mut mac = HmacCtx::new(hmac_key);
    // X11: domain-separate from the integrity tag and largeBlobKey by
    // prepending DOMAIN_CRED_RANDOM as the first bytes of the message.
    mac.update(DOMAIN_CRED_RANDOM);
    mac.update(credential_id);
    mac.update(&[if uv_present { 0x01 } else { 0x00 }]);
    let tag = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Derive the per-credential `largeBlobKey` value used by the
/// `largeBlobKey` extension (CTAP 2.1 sec. 6.10, sec. 11.4) deterministically
/// from the device's HMAC master key and the credentialId. Same
/// trick as [`derive_cred_random`] -- avoids stashing yet another
/// 32-byte secret per credential.
///
/// The key is returned as 32 raw bytes; the RP uses it as an AEAD
/// key (typically AES-GCM) to encrypt blob data they then upload to
/// the device via `authenticatorLargeBlobs`.
pub fn derive_large_blob_key(hmac_key: &[u8; 32], credential_id: &[u8]) -> [u8; 32] {
    let mut mac = HmacCtx::new(hmac_key);
    // X11: domain-separate by prepending DOMAIN_LARGE_BLOB_KEY as the
    // first bytes of the message. (The previous trailing "lbk" suffix is
    // replaced by this prefix -- a prefix tag gives length-independent
    // separation, unlike a suffix.)
    mac.update(DOMAIN_LARGE_BLOB_KEY);
    mac.update(credential_id);
    let tag = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// AES-256-CBC encrypt in place. Buffer length must be a multiple of 16.
fn cbc_encrypt_inplace(key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8]) {
    debug_assert!(buf.len() % 16 == 0);
    let cipher = Aes256::new(key.into());
    let mut prev: [u8; 16] = *iv;
    for chunk in buf.chunks_mut(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev[i];
        }
        cipher.encrypt_block((&mut block).into());
        chunk.copy_from_slice(&block);
        prev = block;
    }
}

/// AES-256-CBC decrypt in place. Buffer length must be a multiple of 16.
fn cbc_decrypt_inplace(key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8]) {
    debug_assert!(buf.len() % 16 == 0);
    let cipher = Aes256::new(key.into());
    let mut prev: [u8; 16] = *iv;
    for chunk in buf.chunks_mut(16) {
        let cipher_block: [u8; 16] = chunk.try_into().unwrap();
        let mut block = cipher_block;
        cipher.decrypt_block((&mut block).into());
        for i in 0..16 {
            chunk[i] = block[i] ^ prev[i];
        }
        prev = cipher_block;
    }
}

// ---- X11 domain separation: how this is regression-tested ----
//
// This crate is a `#![no_std] #![no_main]` firmware binary (custom
// `panic_halt` handler + ARM-only HAL items), so it cannot host a
// `cargo test` harness: `std`'s harness collides on `panic_impl` and the
// host target configures out the HAL. The three master-MAC-keyed
// derivations here (the credentialId integrity tag in
// `encrypt_to_credential_id`/`decrypt_credential_id`, `derive_cred_random`,
// and `derive_large_blob_key`) are instead regression-tested by the C
// port's `c/firmware/test/test_domain.c`, which exercises the
// BYTE-IDENTICAL scheme -- the same `pqf-cred-id` / `pqf-hmac-secret` /
// `pqf-large-blob-key` domain prefixes and input layout, confirmed a
// byte-for-byte mirror of this module by adversarial cross-port review --
// asserting round-trip recovery (ES256 + hybrid), pairwise domain
// distinctness, single-byte-tamper rejection, and cross-RP rejection.
// Encrypt/decrypt symmetry and the all-zero-seed alg-discriminator
// invariant were likewise confirmed by review; on-device registration +
// hmac-secret use is the end-to-end check.
