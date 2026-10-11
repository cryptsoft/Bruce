// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP2 PIN Protocol v1, implemented to mirror OpenSK's
//! `src/ctap/{pin_protocol.rs, client_pin.rs}` so Chrome's
//! WebAuthn-with-PIN path behaves the same against our device as it
//! does against an OpenSK-firmware Feitian token.
//!
//! Spec ref: CTAP 2.1 sec. 6.5 (authenticatorClientPin). Only Protocol v1
//! is supported -- that's what Chrome on macOS uses for legacy keys,
//! and v2 brings little additional value for our threat model.
//!
//! Crypto chain:
//!   key_agreement_key:  ephemeral ECDH P-256 secret (regenerated on
//!                       every reset or change-pin; persists across
//!                       getKeyAgreement calls within one session)
//!   shared secret:      SHA-256(ECDH(client_pub, our_priv).x)
//!   AES key:            shared secret (32 B) used directly as AES-256
//!   HMAC key:           shared secret used as HMAC-SHA-256 key
//!   pin_uv_auth_token:  32 random bytes, returned encrypted to the
//!                       host on successful PIN verification
//!
//! Wire formats use CBOR maps with integer keys, per CTAP 2.1 sec. 6.5.5.

extern crate alloc;

use alloc::vec::Vec as AllocVec;

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use pqf_cbor::{cbor_int, cbor_map, Value};
use zeroize::Zeroize;

use crate::bc_crypto::{ct_eq, hkdf_sha256, hmac_sha256, sha256};
use rand_core::CryptoRngCore;

/// PIN protocol identifiers (CTAP 2.1 sec. 6.5.4 / sec. 6.5.6). v1 is what
/// Chrome on macOS picks; v2 is offered by some Linux browsers and
/// is required by FIDO Alliance certification.
pub const PIN_PROTOCOL_V1: u64 = 1;
pub const PIN_PROTOCOL_V2: u64 = 2;

pub const PIN_TOKEN_LEN: usize = 32;
pub const PIN_HASH_LEN: usize = 16;
pub const PIN_MAX_RETRIES: u8 = 8;
pub const PIN_MIN_LENGTH_BYTES: usize = 4; // CTAP requires >=4 chars
/// The padded block is 64 bytes and must end in at least one NUL, so a
/// PIN is at most 63 bytes encoded. C has had this ceiling since it was
/// written; this port accepted a 64-byte PIN that filled the block.
pub const PIN_MAX_LENGTH_BYTES: usize = 63;

/// Length of the PIN inside its 64-byte padded block, or None if it
/// violates policy. Scans forward to the first NUL, as C and the
/// TrustZone port do: `rposition(!= 0)` measured to the LAST non-zero
/// byte, so "1234\0\0\0X" counted as 8 and passed a minimum of 8 with a
/// four-character PIN.
fn pin_padded_length(plain: &[u8], min_pin_length: usize) -> Option<usize> {
    let len = plain.iter().position(|&b| b == 0).unwrap_or(plain.len());
    if len < min_pin_length || len > PIN_MAX_LENGTH_BYTES {
        return None;
    }
    Some(len)
}
/// CTAP 2.1 sec. 6.5.5.6: in addition to the persistent `pinRetries`
/// counter, the authenticator keeps a *volatile* per-power-cycle count
/// of consecutive failed PIN attempts. After this many failures within
/// a single power cycle PIN entry is blocked with
/// `CTAP2_ERR_PIN_AUTH_BLOCKED` (0x34) until the device is power-cycled,
/// forcing an attacker to physically replug between batches of guesses
/// rather than burning the whole `pinRetries` budget in one session.
pub const MAX_CONSECUTIVE_PIN_FAILURES: u8 = 3;

/// PIN/UV-token permission bits (CTAP 2.1 sec. 6.5.5.7.1). The host
/// requests a subset of these when calling
/// `getPinUvAuthTokenUsingPinWithPermissions` (subcmd 0x09); the
/// returned token is then *scoped* to those operations. The legacy
/// `getPinToken` (subcmd 0x05) returns an all-permissions token with
/// no RP scope -- kept around for Chrome on macOS which still uses v1.
pub const PERM_MAKE_CREDENTIAL: u8 = 0x01;
pub const PERM_GET_ASSERTION: u8 = 0x02;
pub const PERM_CREDENTIAL_MGMT: u8 = 0x04;
#[allow(dead_code)] // reserved for Phase 11+ / never granted on this device
pub const PERM_BIO_ENROLLMENT: u8 = 0x08;
pub const PERM_LARGE_BLOB_WRITE: u8 = 0x10;
pub const PERM_AUTHENTICATOR_CFG: u8 = 0x20;
/// Permission mask granted by the legacy `getPinToken` (0x05). Per
/// CTAP 2.1 sec. 6.5.5.7.1 the legacy token is scoped to `mc` + `ga`
/// ONLY (not credMgmt / largeBlobWrite / authenticatorConfig -- those
/// require an explicit `getPinUvAuthTokenUsingPinWithPermissions`
/// (0x09) grant). Previously this over-granted all five bits, which
/// let a 0x05 token drive CredentialManagement / LargeBlobs / Config;
/// the C port already scoped it correctly.
pub const PERM_LEGACY_TOKEN: u8 = PERM_MAKE_CREDENTIAL | PERM_GET_ASSERTION;

/// CTAP2 subcommand codes.
const SUB_GET_PIN_RETRIES: u64 = 0x01;
const SUB_GET_KEY_AGREEMENT: u64 = 0x02;
const SUB_SET_PIN: u64 = 0x03;
const SUB_CHANGE_PIN: u64 = 0x04;
const SUB_GET_PIN_TOKEN: u64 = 0x05;
/// `getUVRetries` (CTAP 2.1 sec. 6.5.5.2). Reports the remaining built-in
/// user-verification (e.g. fingerprint) attempts. This device has no
/// built-in UV modality -- getInfo advertises no `uv` option -- so the
/// subcommand is not applicable here.
const SUB_GET_UV_RETRIES: u64 = 0x07;
const SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMS: u64 = 0x09;

/// CTAP2 status codes -- only the ones the PIN flow uses. Mirrors
/// OpenSK status codes.
pub const ERR_INVALID_PARAM: u8 = 0x02;
pub const ERR_MISSING_PARAMETER: u8 = 0x14;
/// CTAP2_ERR_INVALID_CBOR: the body did not decode at all.
pub const ERR_INVALID_CBOR: u8 = 0x12;
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE: it decoded, and a field is the wrong
/// CBOR type. Distinct from INVALID_CBOR, and from a field being absent.
pub const ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
pub const ERR_PIN_INVALID: u8 = 0x31;
pub const ERR_PIN_BLOCKED: u8 = 0x32;
pub const ERR_PIN_AUTH_INVALID: u8 = 0x33;
pub const ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
pub const ERR_PIN_NOT_SET: u8 = 0x35;
pub const ERR_PUAT_REQUIRED: u8 = 0x36;
pub const ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
/// CTAP 2.1 sec. 8.1: CTAP2_ERR_INVALID_SUBCOMMAND is 0x3E. 0x16 is
/// CTAP2_ERR_UNSUPPORTED_EXTENSION, which is a statement about an
/// extension the client did not send. All six in-house declarations of
/// this constant said 0x16 -- they agreed with each other and not with
/// the spec, so every test passed and no client could act on the answer.
pub const ERR_INVALID_SUBCOMMAND: u8 = 0x3e;
pub const ERR_UNAUTHORIZED_PERMISSION: u8 = 0x40;

/// Persistent PIN state -- lives in flash alongside credentials.
#[derive(Clone, Copy)]
pub struct PinPersistent {
    /// 16 bytes of SHA-256(utf8(pin))[..16], or [0; 16] if no PIN set.
    pub pin_hash: [u8; PIN_HASH_LEN],
    /// 1 if a PIN has been set, 0 otherwise.
    pub pin_set: u8,
    /// Remaining retries before the PIN is permanently blocked.
    pub retries_left: u8,
}

impl PinPersistent {
    pub const fn empty() -> Self {
        Self {
            pin_hash: [0; PIN_HASH_LEN],
            pin_set: 0,
            retries_left: PIN_MAX_RETRIES,
        }
    }
}

/// Volatile PIN-protocol state. Reset on every boot.
pub struct PinSession {
    /// Ephemeral ECDH key for key agreement with the host.
    key_agreement: SecretKey,
    /// 32-byte random token returned on successful PIN auth, used by
    /// the host as the HMAC key for `pinUvAuthParam` on subsequent
    /// MakeCred / GetAssert. Re-generated on every successful auth.
    pin_uv_auth_token: [u8; PIN_TOKEN_LEN],
    /// True after a successful getPinToken in this session -- controls
    /// whether subsequent MakeCred / GetAssert can use pinUvAuthParam.
    pub token_active: bool,
    /// CTAP 2.1 sec. 6.5.5.7 permission bitmask the *current* token is
    /// authorised for. Zero when `!token_active`. Set by
    /// `getPinToken` (legacy -> `PERM_LEGACY_TOKEN`) and by
    /// `getPinUvAuthTokenUsingPinWithPermissions` (host-requested
    /// subset). Checked by [`check_token_permission`] at every
    /// dispatch site that uses `pinUvAuthParam`.
    pub permissions: u8,
    /// Optional RP-scope on the token. When `Some`, the token may
    /// only be used with operations whose request includes the
    /// matching `rp_id_hash`; when `None`, the token isn't
    /// RP-scoped. CTAP 2.1 says the `mc`/`ga` bits *require* an RP
    /// scope; `cm`/`lbw`/`acfg` may be unscoped.
    pub permissions_rp_id_hash: Option<[u8; 32]>,
    /// Stateful CredentialManagement `enumerateRPs` iterator (CTAP
    /// 2.1 sec. 6.8). `Some` between `enumerateRPsBegin` and the final
    /// `enumerateRPsGetNextRP` or 30-second timeout.
    pub cm_rp_iter: Option<crate::credential_management::RpEnumState>,
    /// Stateful CredentialManagement `enumerateCredentials` iterator
    /// (same lifecycle, scoped to one RP).
    pub cm_cred_iter: Option<crate::credential_management::CredEnumState>,
    /// In-flight `authenticatorGetNextAssertion` iterator (CTAP 2.1
    /// sec. 6.3). Populated by `emit_get_assertion` when more than one
    /// credential matches the request (no allowList, multiple
    /// resident creds for the RP); popped by `emit_get_next_assertion`.
    pub assertion_iter: Option<crate::ctap2::AssertionIterState>,
    /// Volatile count of consecutive failed PIN verifications in THIS
    /// power cycle (CTAP 2.1 sec. 6.5.5.6). Reset to 0 on boot
    /// (`PinSession::new`), on `authenticatorReset`, and on any correct
    /// PIN. Once it reaches [`MAX_CONSECUTIVE_PIN_FAILURES`] the PIN
    /// paths return `ERR_PIN_AUTH_BLOCKED` until the next power cycle.
    consecutive_pin_failures: u8,
}

impl PinSession {
    pub fn new(trng: &mut impl CryptoRngCore) -> Self {
        Self {
            key_agreement: gen_secret(trng),
            pin_uv_auth_token: gen_32(trng),
            token_active: false,
            permissions: 0,
            permissions_rp_id_hash: None,
            cm_rp_iter: None,
            cm_cred_iter: None,
            assertion_iter: None,
            consecutive_pin_failures: 0,
        }
    }

    pub fn pin_uv_auth_token(&self) -> &[u8; PIN_TOKEN_LEN] {
        &self.pin_uv_auth_token
    }

    /// True once [`MAX_CONSECUTIVE_PIN_FAILURES`] wrong PINs have been
    /// seen in this power cycle (CTAP 2.1 sec. 6.5.5.6). While set, the PIN
    /// verification paths refuse with `ERR_PIN_AUTH_BLOCKED` until the
    /// device is power-cycled.
    pub(crate) fn pin_auth_blocked(&self) -> bool {
        self.consecutive_pin_failures >= MAX_CONSECUTIVE_PIN_FAILURES
    }

    /// Record one wrong-PIN attempt against the volatile per-power-cycle
    /// counter (saturating so it can never wrap on the 32-bit target).
    pub(crate) fn note_pin_failure(&mut self) {
        self.consecutive_pin_failures = self.consecutive_pin_failures.saturating_add(1);
    }

    /// Clear the volatile per-power-cycle failure counter after a
    /// verified-correct PIN.
    pub(crate) fn clear_pin_failures(&mut self) {
        self.consecutive_pin_failures = 0;
    }

    /// Activate a freshly-issued token with the requested permission
    /// bitmask + optional RP scope. Called from `sub_get_pin_token`
    /// (legacy path, full perms, no scope) and from
    /// `sub_get_pin_uv_auth_token_perms` (scoped path).
    pub(crate) fn activate_token(&mut self, perms: u8, rp_id_hash: Option<[u8; 32]>) {
        self.token_active = true;
        self.permissions = perms;
        self.permissions_rp_id_hash = rp_id_hash;
    }

    /// Invalidate the current token (e.g. on PIN change). Called by
    /// the PIN subcommands that rotate state.
    pub(crate) fn deactivate_token(&mut self) {
        self.token_active = false;
        self.permissions = 0;
        self.permissions_rp_id_hash = None;
    }

    /// Invalidate all PIN/UV session state on authenticatorReset (CTAP
    /// 2.1 sec. 6.6): drop the pinUvAuthToken + its permissions, clear every
    /// stateful iterator (CM enumeration + GetNextAssertion), and rotate
    /// the key-agreement key so any shared secret the platform already
    /// derived is dead.
    pub fn reset(&mut self, trng: &mut impl CryptoRngCore) {
        self.deactivate_token();
        self.cm_rp_iter = None;
        self.cm_cred_iter = None;
        self.assertion_iter = None;
        self.key_agreement = gen_secret(trng);
        self.consecutive_pin_failures = 0;
    }

    /// Protocol-aware shared secret. Returns `None` for unsupported
    /// protocol values OR an invalid peer point. Used by every
    /// `authenticatorClientPin` subcommand that needs to en/decrypt
    /// or HMAC under the shared key.
    pub fn shared_secret_for_protocol(
        &self,
        peer_x: &[u8; 32],
        peer_y: &[u8; 32],
        protocol: u64,
    ) -> Option<SharedSecret> {
        let handshake = ecdh_x_coord(&self.key_agreement, peer_x, peer_y)?;
        SharedSecret::from_handshake(handshake, protocol)
    }
}

fn gen_secret(trng: &mut impl CryptoRngCore) -> SecretKey {
    // P-256 scalars are 256-bit. Rejection-sample by retrying via the
    // crate's own validator until we get a valid one. With TRNG-quality
    // entropy this almost always succeeds first try.
    loop {
        let mut bytes = [0u8; 32];
        trng.fill_bytes(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}

fn gen_32(trng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut b = [0u8; 32];
    trng.fill_bytes(&mut b);
    b
}

/// PIN-protocol shared secret. Wraps both v1 (`SHA-256(ECDH.x)`) and
/// v2 (`(HKDF(ECDH.x, "CTAP2 AES key"), HKDF(ECDH.x, "CTAP2 HMAC key"))`)
/// behind a single `encrypt` / `decrypt` / `verify` surface so the
/// PIN subcommands and `hmac-secret` don't have to branch internally.
///
/// Mirrors OpenSK's `SharedSecret` trait
/// (`OpenSK/src/ctap/pin_protocol.rs:170-228`) -- we just enum the two
/// variants instead of using dyn dispatch.
#[derive(Clone, Copy)]
pub enum SharedSecret {
    /// v1: 32-byte key reused for both AES (zero IV) and HMAC (truncated to 16 B).
    V1([u8; 32]),
    /// v2: separate AES-256 and HMAC-SHA-256 keys via HKDF.
    V2 {
        aes_key: [u8; 32],
        hmac_key: [u8; 32],
    },
}

impl SharedSecret {
    /// Derive from the ECDH `(handshake_x)` shared point. The handshake
    /// is just the X coordinate of `ECDH(our_sk, peer_pk)` -- same input
    /// for v1 and v2, different post-processing.
    pub fn from_handshake(handshake: [u8; 32], protocol: u64) -> Option<Self> {
        match protocol {
            PIN_PROTOCOL_V1 => Some(SharedSecret::V1(sha256(&handshake))),
            PIN_PROTOCOL_V2 => Some(SharedSecret::V2 {
                aes_key: hkdf_extract_then_expand(&handshake, b"CTAP2 AES key"),
                hmac_key: hkdf_extract_then_expand(&handshake, b"CTAP2 HMAC key"),
            }),
            _ => None,
        }
    }

    /// AES-CBC encrypt the plaintext. v1 uses a zero IV and returns
    /// the ciphertext only; v2 generates a fresh random IV from `trng`
    /// and returns `IV || ciphertext`. `plaintext.len()` must be a
    /// multiple of 16 -- the PIN-protocol uses are all
    /// already-padded fixed-size inputs.
    pub fn encrypt(&self, trng: &mut impl CryptoRngCore, plaintext: &[u8]) -> AllocVec<u8> {
        match self {
            SharedSecret::V1(k) => aes_cbc_encrypt_with_iv(k, &[0u8; 16], plaintext),
            SharedSecret::V2 { aes_key, .. } => {
                let mut iv = [0u8; 16];
                trng.fill_bytes(&mut iv);
                let mut out = AllocVec::with_capacity(16 + plaintext.len());
                out.extend_from_slice(&iv);
                let ct = aes_cbc_encrypt_with_iv(aes_key, &iv, plaintext);
                out.extend_from_slice(&ct);
                out
            }
        }
    }

    /// Inverse of `encrypt`. v1 expects bare ciphertext; v2 expects
    /// `IV || ciphertext` and strips the leading IV.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<AllocVec<u8>> {
        match self {
            SharedSecret::V1(k) => aes_cbc_decrypt_with_iv(k, &[0u8; 16], ciphertext),
            SharedSecret::V2 { aes_key, .. } => {
                if ciphertext.len() < 16 || (ciphertext.len() - 16) % 16 != 0 {
                    return None;
                }
                let (iv, body) = ciphertext.split_at(16);
                let iv: &[u8; 16] = iv.try_into().ok()?;
                aes_cbc_decrypt_with_iv(aes_key, iv, body)
            }
        }
    }

    /// HMAC-SHA-256(key, message), truncated as per the protocol:
    ///   v1 -> first 16 bytes,
    ///   v2 -> full 32 bytes.
    pub fn authenticate(&self, message: &[u8]) -> AllocVec<u8> {
        let key = match self {
            SharedSecret::V1(k) => *k,
            SharedSecret::V2 { hmac_key, .. } => *hmac_key,
        };
        let full = hmac_sha256(&key, message);
        let mut out = AllocVec::with_capacity(32);
        match self {
            SharedSecret::V1(_) => out.extend_from_slice(&full[..16]),
            SharedSecret::V2 { .. } => out.extend_from_slice(&full),
        }
        out
    }

    /// Constant-time verify of `signature` against
    /// `authenticate(message)`. Returns `false` on length mismatch
    /// (not the spec's required behaviour, but functionally
    /// equivalent -- the host either sent the right length or the
    /// auth was invalid).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let want_len = match self {
            SharedSecret::V1(_) => 16,
            SharedSecret::V2 { .. } => 32,
        };
        if signature.len() != want_len {
            return false;
        }
        let computed = self.authenticate(message);
        ct_eq(&computed, signature)
    }

    /// Volatile-wipe the derived key material. `SharedSecret` is `Copy`
    /// (so it can't carry a `Drop`), but the per-attempt secret derived
    /// from the ECDH handshake should not linger on the stack once the
    /// PIN subcommand is done with it. Callers wipe their local copy at
    /// end of use; `zeroize()` is a non-elidable volatile write.
    pub fn cleanse(&mut self) {
        match self {
            SharedSecret::V1(k) => k.zeroize(),
            SharedSecret::V2 { aes_key, hmac_key } => {
                aes_key.zeroize();
                hmac_key.zeroize();
            }
        }
    }
}

/// HKDF-Extract-then-Expand with an all-zero 32-byte salt, output
/// L = 32 bytes (so HKDF-Expand needs only one iteration:
/// `T(1) = HMAC(PRK, info || 0x01)`).
///
/// This used to be hand-rolled over `hmac` two calls deep; it now goes
/// through the Bouncy Castle HKDF, which was checked to produce
/// byte-identical output for both PIN-protocol-v2 info strings.
fn hkdf_extract_then_expand(ikm: &[u8; 32], info: &[u8]) -> [u8; 32] {
    hkdf_sha256(ikm, info)
}

/// AES-256-CBC encrypt with an explicit IV, no padding. `plaintext.len()`
/// must be a multiple of 16. Hand-rolled like the existing helpers
/// so the firmware doesn't pull a third AES crate just for CBC modes.
fn aes_cbc_encrypt_with_iv(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> AllocVec<u8> {
    // Enforce the documented block-multiple precondition in release, not
    // just debug: a short final chunk would otherwise index `chunk[i]` out
    // of bounds (panic=abort) or silently truncate. Mirror the `% 16`
    // guard the decrypt helpers already have and refuse non-aligned input.
    if plaintext.len() % 16 != 0 {
        return AllocVec::new();
    }
    let cipher = Aes256::new(key.into());
    let mut prev: [u8; 16] = *iv;
    let mut out = AllocVec::with_capacity(plaintext.len());
    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev[i];
        }
        cipher.encrypt_block((&mut block).into());
        out.extend_from_slice(&block);
        prev = block;
    }
    out
}

fn aes_cbc_decrypt_with_iv(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Option<AllocVec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return None;
    }
    let cipher = Aes256::new(key.into());
    let mut prev: [u8; 16] = *iv;
    let mut out = AllocVec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let mut dec_block = block;
        cipher.decrypt_block((&mut dec_block).into());
        for i in 0..16 {
            out.push(dec_block[i] ^ prev[i]);
        }
        prev = block;
    }
    Some(out)
}

/// Run the raw ECDH and return the resulting point's X coordinate as
/// 32 raw bytes -- the input to *both* v1's `SHA-256(x)` and v2's
/// HKDF-driven key derivation.
fn ecdh_x_coord(our_sk: &SecretKey, peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Option<[u8; 32]> {
    // Re-assemble the peer's COSE point into an uncompressed SEC1
    // representation: 0x04 || X || Y.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(peer_x);
    sec1[33..].copy_from_slice(peer_y);
    let peer_pk = PublicKey::from_sec1_bytes(&sec1).ok()?;
    let shared = diffie_hellman(our_sk.to_nonzero_scalar(), peer_pk.as_affine());
    Some((*shared.raw_secret_bytes()).into())
}

/// Check the current `pinUvAuthToken` is valid for the operation
/// identified by `permission_bit` against the given `rp_id_hash`.
///
/// Returns:
///   - `Ok(())` if the token is active, has the bit set, and either
///     has no RP scope OR the scope matches `rp_id_hash`.
///   - `Err(ERR_PUAT_REQUIRED)` if no token is active.
///   - `Err(ERR_PIN_AUTH_INVALID)` if the bit isn't granted or the
///     RP scope doesn't match.
///
/// Called from `ctap2` at every dispatch site that uses
/// `pinUvAuthParam` (MakeCred, GetAssert, CredentialManagement,
/// AuthenticatorConfig, LargeBlobs).
pub fn check_token_permission(
    session: &PinSession,
    permission_bit: u8,
    rp_id_hash: &[u8; 32],
) -> Result<(), u8> {
    if !session.token_active {
        return Err(ERR_PUAT_REQUIRED);
    }
    if (session.permissions & permission_bit) == 0 {
        return Err(ERR_PIN_AUTH_INVALID);
    }
    if let Some(scope) = &session.permissions_rp_id_hash {
        if scope != rp_id_hash {
            return Err(ERR_PIN_AUTH_INVALID);
        }
    }
    Ok(())
}

/// Verify `pinUvAuthParam` from a MakeCred / GetAssertion request
/// against the session's `pin_uv_auth_token`. Length and truncation
/// vary by PIN protocol:
///   - v1: signature is 16 bytes, compared to HMAC(token, msg)[..16]
///   - v2: signature is 32 bytes, compared to full HMAC(token, msg)
/// Returns false on any length / protocol mismatch.
pub fn verify_pin_uv_auth_param(
    token: &[u8; PIN_TOKEN_LEN],
    message: &[u8],
    sig: &[u8],
    protocol: u64,
) -> bool {
    let want_len = match protocol {
        PIN_PROTOCOL_V1 => 16,
        PIN_PROTOCOL_V2 => 32,
        _ => return false,
    };
    if sig.len() != want_len {
        return false;
    }
    let full = hmac_sha256(token, message);
    match protocol {
        PIN_PROTOCOL_V1 => ct_eq(&full[..16], sig),
        PIN_PROTOCOL_V2 => ct_eq(&full, sig),
        _ => false,
    }
}

/// Parsed authenticatorClientPin input map. Owned byte vectors so the
/// caller can drop the CBOR parse tree without losing data.
struct PinParams {
    pin_uv_auth_protocol: u64,
    sub_command: u64,
    key_agreement: Option<([u8; 32], [u8; 32])>, // (x, y) of the host's ECDH pub key
    pin_uv_auth_param: Option<AllocVec<u8>>,
    new_pin_enc: Option<AllocVec<u8>>,
    pin_hash_enc: Option<AllocVec<u8>>,
    /// CTAP2 ClientPIN map key `0x09` -- permission bitmask requested
    /// for the issued `pinUvAuthToken`. Only meaningful for subcmd
    /// `0x09 getPinUvAuthTokenUsingPinWithPermissions`.
    permissions: Option<u64>,
    /// CTAP2 ClientPIN map key `0x0A` -- RP id that scopes the
    /// issued token. We hash it (SHA-256) at parse time so the
    /// dispatch sites can compare against `rp_id_hash` directly.
    rp_id_hash: Option<[u8; 32]>,
}

fn map_get<'a>(map: &'a [(Value, Value)], key: i64) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| match k {
            Value::Uint(u) => *u as i64 == key,
            Value::Nint(n) => *n == key,
            _ => false,
        })
        .map(|(_, v)| v)
}

/// Parse the clientPIN parameter map.
///
/// `Err` carries the status to send, because the four ways this fails
/// are four different things to tell a client and they used to collapse
/// into one. `Option` made undecodable CBOR, a non-map body, an absent
/// pinUvAuthProtocol and an absent subCommand all come back as
/// INVALID_PARAM, which says "your parameters are wrong" to a client
/// whose CBOR did not decode and to one that simply omitted a field.
/// The C port has distinguished them all along.
///
/// Which requests are ACCEPTED is unchanged. pinUvAuthProtocol stays
/// required: the C port defaults it to v1 for getPinRetries and this one
/// does not, which is a real divergence, but it is a decision about
/// behaviour rather than about status codes and the stance here was
/// taken deliberately -- defaulting picks a protocol the platform never
/// named. Left as it is, and written down.
fn parse_input(input: &[u8]) -> Result<PinParams, u8> {
    let value = pqf_cbor::decode(input).map_err(|_| ERR_INVALID_CBOR)?;
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
    };
    let pin_uv_auth_protocol = match map_get(&map, 0x01) {
        Some(Value::Uint(u)) => *u,
        Some(_) => return Err(ERR_CBOR_UNEXPECTED_TYPE),
        None => return Err(ERR_MISSING_PARAMETER),
    };
    let sub_command = match map_get(&map, 0x02) {
        Some(Value::Uint(u)) => *u,
        Some(_) => return Err(ERR_CBOR_UNEXPECTED_TYPE),
        None => return Err(ERR_MISSING_PARAMETER),
    };
    let key_agreement = match map_get(&map, 0x03) {
        Some(Value::Map(km)) => {
            let x_v = match map_get(km, -2) {
                Some(Value::Bytes(b)) if b.len() == 32 => b.clone(),
                _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
            };
            let y_v = match map_get(km, -3) {
                Some(Value::Bytes(b)) if b.len() == 32 => b.clone(),
                _ => return Err(ERR_CBOR_UNEXPECTED_TYPE),
            };
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(&x_v);
            y.copy_from_slice(&y_v);
            Some((x, y))
        }
        _ => None,
    };
    let pin_uv_auth_param = match map_get(&map, 0x04) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let new_pin_enc = match map_get(&map, 0x05) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let pin_hash_enc = match map_get(&map, 0x06) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let permissions = match map_get(&map, 0x09) {
        Some(Value::Uint(u)) => Some(*u),
        _ => None,
    };
    let rp_id_hash = match map_get(&map, 0x0A) {
        Some(Value::Text(s)) => {
            let h: [u8; 32] = sha256(s.as_bytes());
            Some(h)
        }
        _ => None,
    };
    Ok(PinParams {
        pin_uv_auth_protocol,
        sub_command,
        key_agreement,
        pin_uv_auth_param,
        new_pin_enc,
        pin_hash_enc,
        permissions,
        rp_id_hash,
    })
}

/// Top-level dispatch for `authenticatorClientPin` (CTAP2 cmd 0x06).
/// `input` is the CBOR-encoded subcommand-parameters map.
pub fn handle_client_pin(
    input: &[u8],
    trng: &mut impl CryptoRngCore,
    session: &mut PinSession,
    persistent: &mut PinPersistent,
    min_pin_length: usize,
    persist_cb: &mut dyn FnMut(&PinPersistent),
    // Set true iff a `changePIN` (0x04) completes successfully, so the
    // caller can clear the persistent `force_pin_change` flag (X13). The
    // flag lives on `CredStore`, which this layer deliberately doesn't see.
    pin_changed: &mut bool,
    // True iff the device currently demands a PIN change (X13
    // forcePINChange). While set, a token authorising mc/ga must not be
    // issued -- the host has to run changePIN first (CTAP 2.1 sec. 6.5.5.7).
    force_pin_change: bool,
) -> AllocVec<u8> {
    let mut out = AllocVec::new();
    *pin_changed = false;
    let params = match parse_input(input) {
        Ok(p) => p,
        Err(status) => {
            out.push(status);
            return out;
        }
    };
    if params.pin_uv_auth_protocol != PIN_PROTOCOL_V1
        && params.pin_uv_auth_protocol != PIN_PROTOCOL_V2
    {
        out.push(ERR_INVALID_PARAM);
        return out;
    }
    match params.sub_command {
        SUB_GET_PIN_RETRIES => sub_get_pin_retries(persistent, session, &mut out),
        SUB_GET_KEY_AGREEMENT => sub_get_key_agreement(session, &mut out),
        SUB_SET_PIN => sub_set_pin(
            &params,
            trng,
            session,
            persistent,
            min_pin_length,
            persist_cb,
            &mut out,
        ),
        SUB_CHANGE_PIN => sub_change_pin(
            &params,
            trng,
            session,
            persistent,
            min_pin_length,
            persist_cb,
            pin_changed,
            &mut out,
        ),
        SUB_GET_PIN_TOKEN => sub_get_pin_token(
            &params,
            trng,
            session,
            persistent,
            persist_cb,
            force_pin_change,
            &mut out,
        ),
        SUB_GET_UV_RETRIES => {
            // Built-in UV (CTAP 2.1 sec. 6.5.5.2). This is a PIN-only
            // authenticator with no built-in UV method (getInfo
            // advertises no `uv` option), so there is no uvRetries
            // counter to report. A spec-compliant host queries this only
            // when a UV modality is advertised; we make the no-UV posture
            // explicit rather than letting 0x07 fall through silently.
            out.push(ERR_INVALID_SUBCOMMAND);
        }
        SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMS => sub_get_pin_uv_auth_token_perms(
            &params,
            trng,
            session,
            persistent,
            persist_cb,
            force_pin_change,
            &mut out,
        ),
        _ => out.push(ERR_INVALID_SUBCOMMAND),
    }
    out
}

/// CTAP 2.1 sec. 6.5.5.2. `pinRetries` (0x03) is the persistent budget;
/// `powerCycleState` (0x04) is "present and true if the authenticator
/// requires a power cycle before any future PIN operation", so it is
/// emitted only while the volatile per-boot lockout is engaged and the
/// common-case response stays a one-entry map.
///
/// Reporting it matters more than it looks. While blocked the device
/// refuses every PIN -- including the correct one -- but `pinRetries`
/// still reads whatever is left, so a client with only that number tells
/// the user to keep typing. The flag is the only thing on the wire that
/// says "replug".
fn sub_get_pin_retries(p: &PinPersistent, session: &PinSession, out: &mut AllocVec<u8>) {
    let map = if session.pin_auth_blocked() {
        cbor_map! {
            cbor_int!(3) => cbor_int!(p.retries_left as i64),
            cbor_int!(4) => Value::Bool(true),
        }
    } else {
        cbor_map! {
            cbor_int!(3) => cbor_int!(p.retries_left as i64),
        }
    };
    let mut enc = AllocVec::new();
    pqf_cbor::encode(&map, &mut enc);
    out.push(0); // CTAP2_OK
    out.extend_from_slice(&enc);
}

fn our_pub_cose_value(session: &PinSession) -> Value {
    let pk = session.key_agreement.public_key();
    let ep = pk.to_encoded_point(false);
    let bytes = ep.as_bytes();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    cbor_map! {
        cbor_int!(1) => cbor_int!(2),         // kty = EC2
        cbor_int!(3) => cbor_int!(-25),       // alg = ECDH-ES + HKDF-256 (per CTAP)
        cbor_int!(-1) => cbor_int!(1),        // crv = P-256
        cbor_int!(-2) => Value::Bytes(x.to_vec()),
        cbor_int!(-3) => Value::Bytes(y.to_vec()),
    }
}

fn sub_get_key_agreement(session: &PinSession, out: &mut AllocVec<u8>) {
    let map = cbor_map! {
        cbor_int!(1) => our_pub_cose_value(session),
    };
    let mut enc = AllocVec::new();
    pqf_cbor::encode(&map, &mut enc);
    out.push(0);
    out.extend_from_slice(&enc);
}

/// Common: derive the protocol-aware shared secret from the incoming
/// key_agreement. Reads `params.pin_uv_auth_protocol` to pick v1 vs
/// v2 -- both branches share the same ECDH X-coordinate but differ in
/// the post-processing (SHA-256 vs HKDF) and the on-wire framing of
/// the encrypted PIN / pin_hash.
fn derive_shared(session: &PinSession, params: &PinParams) -> Result<SharedSecret, u8> {
    let (x, y) = params.key_agreement.ok_or(ERR_MISSING_PARAMETER)?;
    session
        .shared_secret_for_protocol(&x, &y, params.pin_uv_auth_protocol)
        .ok_or(ERR_INVALID_PARAM)
}

/// Per-protocol byte-length of `newPinEnc` (subcommand 0x03 / 0x04).
/// v1: 64 (the AES-CBC ciphertext of the 64-byte zero-padded PIN).
/// v2: 80 (16-byte IV prepended).
fn new_pin_enc_len(protocol: u64) -> usize {
    match protocol {
        PIN_PROTOCOL_V2 => 80,
        _ => 64,
    }
}

/// Per-protocol byte-length of `pinHashEnc`. v1: 16, v2: 32.
fn pin_hash_enc_len(protocol: u64) -> usize {
    match protocol {
        PIN_PROTOCOL_V2 => 32,
        _ => 16,
    }
}

fn sub_set_pin(
    params: &PinParams,
    _trng: &mut impl CryptoRngCore,
    _session: &mut PinSession,
    persistent: &mut PinPersistent,
    min_pin_length: usize,
    persist: &mut dyn FnMut(&PinPersistent),
    out: &mut AllocVec<u8>,
) {
    if persistent.pin_set != 0 {
        out.push(ERR_PIN_AUTH_INVALID); // PIN already set; use changePIN
        return;
    }
    let pin_auth = match &params.pin_uv_auth_param {
        Some(b) => b.clone(),
        None => {
            out.push(ERR_MISSING_PARAMETER);
            return;
        }
    };
    let expected_len = new_pin_enc_len(params.pin_uv_auth_protocol);
    let new_pin_enc = match &params.new_pin_enc {
        Some(b) if b.len() == expected_len => b.clone(),
        _ => {
            out.push(ERR_MISSING_PARAMETER);
            return;
        }
    };
    let mut secret = match derive_shared(_session, params) {
        Ok(s) => s,
        Err(e) => {
            out.push(e);
            return;
        }
    };
    if !secret.verify(&new_pin_enc, &pin_auth) {
        secret.cleanse();
        out.push(ERR_PIN_AUTH_INVALID);
        return;
    }
    let mut plain = match secret.decrypt(&new_pin_enc) {
        Some(p) => p,
        None => {
            secret.cleanse();
            out.push(ERR_INVALID_PARAM);
            return;
        }
    };
    secret.cleanse();
    let actual_len = match pin_padded_length(&plain, min_pin_length) {
        Some(n) => n,
        None => {
            plain[..].zeroize();
            out.push(ERR_PIN_POLICY_VIOLATION);
            return;
        }
    };
    // Store SHA-256(pin)[..16] as the pin_hash.
    let mut h: [u8; 32] = sha256(&plain[..actual_len]);
    plain[..].zeroize();
    persistent.pin_hash.copy_from_slice(&h[..16]);
    h.zeroize();
    persistent.pin_set = 1;
    persistent.retries_left = PIN_MAX_RETRIES;
    persist(persistent);
    out.push(0);
}

fn sub_change_pin(
    params: &PinParams,
    trng: &mut impl CryptoRngCore,
    session: &mut PinSession,
    persistent: &mut PinPersistent,
    min_pin_length: usize,
    persist: &mut dyn FnMut(&PinPersistent),
    pin_changed: &mut bool,
    out: &mut AllocVec<u8>,
) {
    if persistent.pin_set == 0 {
        // No PIN to change (CTAP 2.1 sec. 6.5.5.5 -> CTAP2_ERR_PIN_NOT_SET).
        // The C port guards this; without it, a changePIN whose
        // pinHashEnc decrypts to the all-zero empty stored hash would
        // set a PIN with no prior authentication.
        out.push(ERR_PIN_NOT_SET);
        return;
    }
    // CTAP 2.1 sec. 6.5.5.6 per-power-cycle lockout: once this boot has seen
    // MAX_CONSECUTIVE_PIN_FAILURES wrong PINs, refuse further attempts
    // with ERR_PIN_AUTH_BLOCKED until a power cycle clears the volatile
    // counter -- even if persistent retries remain. Checked before the
    // persistent counter, as C and OpenSK do: a device that is both
    // locked for this boot and out of retries reports the lockout.
    if session.pin_auth_blocked() {
        out.push(ERR_PIN_AUTH_BLOCKED);
        return;
    }
    if persistent.retries_left == 0 {
        out.push(ERR_PIN_BLOCKED);
        return;
    }
    let pin_auth = match &params.pin_uv_auth_param {
        Some(b) => b.clone(),
        None => {
            out.push(ERR_MISSING_PARAMETER);
            return;
        }
    };
    let new_pin_enc_expected = new_pin_enc_len(params.pin_uv_auth_protocol);
    let pin_hash_enc_expected = pin_hash_enc_len(params.pin_uv_auth_protocol);
    let new_pin_enc = match &params.new_pin_enc {
        Some(b) if b.len() == new_pin_enc_expected => b.clone(),
        _ => {
            out.push(ERR_MISSING_PARAMETER);
            return;
        }
    };
    let pin_hash_enc = match &params.pin_hash_enc {
        Some(b) if b.len() == pin_hash_enc_expected => b.clone(),
        _ => {
            out.push(ERR_MISSING_PARAMETER);
            return;
        }
    };
    let mut secret = match derive_shared(session, params) {
        Ok(s) => s,
        Err(e) => {
            out.push(e);
            return;
        }
    };
    // HMAC over (new_pin_enc || pin_hash_enc).
    let mut combined = AllocVec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
    combined.extend_from_slice(&new_pin_enc);
    combined.extend_from_slice(&pin_hash_enc);
    if !secret.verify(&combined, &pin_auth) {
        secret.cleanse();
        out.push(ERR_PIN_AUTH_INVALID);
        return;
    }
    // Decrement retries first so an in-flight failure consumes one.
    persistent.retries_left = persistent.retries_left.saturating_sub(1);
    persist(persistent);

    // Verify pin_hash_enc decrypts to our stored pin_hash.
    let mut supplied_hash = match secret.decrypt(&pin_hash_enc) {
        Some(h) if h.len() == 16 => h,
        // Structural decrypt failure (undecryptable / wrong length):
        // rotate the key-agreement key too, matching the value-mismatch
        // path below, so the platform must re-handshake before the next
        // attempt (L25). The retry counter was already decremented above.
        _ => {
            secret.cleanse();
            session.note_pin_failure();
            session.key_agreement = gen_secret(trng);
            out.push(ERR_PIN_INVALID);
            return;
        }
    };
    // Constant-time compare: a plain `!=` early-exits and leaks, via
    // timing, the matching-prefix length of SHA-256(PIN)[..16].
    if !ct_eq(&supplied_hash[..], &persistent.pin_hash[..]) {
        // PIN was wrong -- already decremented, bump the per-power-cycle
        // failure count, regen ECDH so the attacker has to re-handshake
        // before each guess.
        supplied_hash[..].zeroize();
        secret.cleanse();
        session.note_pin_failure();
        session.key_agreement = gen_secret(trng);
        out.push(ERR_PIN_INVALID);
        return;
    }
    supplied_hash[..].zeroize();
    // PIN correct -- clear the volatile failure counter and immediately
    // restore the persistent retry counter before touching the new PIN.
    // The current PIN authenticated, so the attempt was genuine; the
    // remaining steps (new-PIN decrypt + length policy) are parameter
    // validation, not PIN guesses, and must not burn a persistent retry
    // (a malformed new PIN could otherwise march the counter to zero and
    // permanently brick the device). Restore + persist here so the
    // early returns below leave retries_left at PIN_MAX_RETRIES.
    session.clear_pin_failures();
    persistent.retries_left = PIN_MAX_RETRIES;
    persist(persistent);
    let mut plain = match secret.decrypt(&new_pin_enc) {
        Some(p) => p,
        None => {
            secret.cleanse();
            out.push(ERR_INVALID_PARAM);
            return;
        }
    };
    secret.cleanse();
    let actual_len = match pin_padded_length(&plain, min_pin_length) {
        Some(n) => n,
        None => {
            plain[..].zeroize();
            out.push(ERR_PIN_POLICY_VIOLATION);
            return;
        }
    };
    let mut h: [u8; 32] = sha256(&plain[..actual_len]);
    plain[..].zeroize();
    persistent.pin_hash.copy_from_slice(&h[..16]);
    h.zeroize();
    persistent.retries_left = PIN_MAX_RETRIES;
    persistent.pin_set = 1;
    persist(persistent);
    session.pin_uv_auth_token = gen_32(trng);
    session.deactivate_token();
    // Signal the caller to clear any persistent forcePINChange (X13): the
    // user has now satisfied the forced change with an authenticated new PIN.
    *pin_changed = true;
    out.push(0);
}

fn sub_get_pin_token(
    params: &PinParams,
    trng: &mut impl CryptoRngCore,
    session: &mut PinSession,
    persistent: &mut PinPersistent,
    persist: &mut dyn FnMut(&PinPersistent),
    force_pin_change: bool,
    out: &mut AllocVec<u8>,
) {
    do_get_pin_token(
        params,
        trng,
        session,
        persistent,
        persist,
        out,
        /*with_perms*/ false,
        force_pin_change,
    );
}

fn sub_get_pin_uv_auth_token_perms(
    params: &PinParams,
    trng: &mut impl CryptoRngCore,
    session: &mut PinSession,
    persistent: &mut PinPersistent,
    persist: &mut dyn FnMut(&PinPersistent),
    force_pin_change: bool,
    out: &mut AllocVec<u8>,
) {
    do_get_pin_token(
        params,
        trng,
        session,
        persistent,
        persist,
        out,
        true,
        force_pin_change,
    );
}

fn do_get_pin_token(
    params: &PinParams,
    trng: &mut impl CryptoRngCore,
    session: &mut PinSession,
    persistent: &mut PinPersistent,
    persist: &mut dyn FnMut(&PinPersistent),
    out: &mut AllocVec<u8>,
    with_perms: bool,
    force_pin_change: bool,
) {
    if persistent.pin_set == 0 {
        out.push(ERR_PIN_NOT_SET);
        return;
    }
    // CTAP 2.1 sec. 6.5.5.6 per-power-cycle lockout (see sub_change_pin),
    // before the persistent counter as in C and OpenSK.
    if session.pin_auth_blocked() {
        out.push(ERR_PIN_AUTH_BLOCKED);
        return;
    }
    if persistent.retries_left == 0 {
        out.push(ERR_PIN_BLOCKED);
        return;
    }
    let pin_hash_enc_expected = pin_hash_enc_len(params.pin_uv_auth_protocol);
    let pin_hash_enc = match &params.pin_hash_enc {
        Some(b) if b.len() == pin_hash_enc_expected => b.clone(),
        _ => {
            out.push(ERR_MISSING_PARAMETER);
            return;
        }
    };
    let mut secret = match derive_shared(session, params) {
        Ok(s) => s,
        Err(e) => {
            out.push(e);
            return;
        }
    };
    persistent.retries_left = persistent.retries_left.saturating_sub(1);
    persist(persistent);

    let mut supplied_hash = match secret.decrypt(&pin_hash_enc) {
        Some(h) if h.len() == 16 => h,
        // Structural decrypt failure (undecryptable / wrong length):
        // rotate the key-agreement key too, matching the value-mismatch
        // path below, so the platform must re-handshake before the next
        // attempt (L25). The retry counter was already decremented above.
        _ => {
            secret.cleanse();
            session.note_pin_failure();
            session.key_agreement = gen_secret(trng);
            out.push(ERR_PIN_INVALID);
            return;
        }
    };
    // Constant-time compare (see sub_change_pin) -- no early-exit timing leak.
    if !ct_eq(&supplied_hash[..], &persistent.pin_hash[..]) {
        supplied_hash[..].zeroize();
        secret.cleanse();
        session.note_pin_failure();
        session.key_agreement = gen_secret(trng);
        out.push(ERR_PIN_INVALID);
        return;
    }
    supplied_hash[..].zeroize();
    // PIN correct -- clear the volatile per-power-cycle failure counter.
    session.clear_pin_failures();
    persistent.retries_left = PIN_MAX_RETRIES;
    persist(persistent);

    // forcePINChange (X13, sec. 6.5.5.7.2), AFTER the PIN is verified: while a
    // change is pending, no token may carry makeCredential or
    // getAssertion -- the legacy getPinToken always grants both -- so the
    // host must run changePIN first. A token scoped only to cm/lbw/acfg is
    // still issued, or the host could never make the change it is being
    // told to make. This gate used to sit before verification, so a WRONG
    // PIN answered 0x37 and spent no retry; C and OpenSK verify first.
    let wants_mc_ga = !with_perms
        || params.permissions.map_or(false, |p| {
            p & (PERM_MAKE_CREDENTIAL as u64 | PERM_GET_ASSERTION as u64) != 0
        });
    if force_pin_change && wants_mc_ga {
        secret.cleanse();
        out.push(ERR_PIN_POLICY_VIOLATION);
        return;
    }

    // Fresh token for this session, with the right permission scope.
    //   - legacy `getPinToken` (0x05) issues a token with ALL bits
    //     except `BioEnrollment` set and no RP scope (matches Chrome
    //     v1 behaviour).
    //   - `getPinUvAuthTokenUsingPinWithPermissions` (0x09) honours
    //     the host's requested bitmask + optional RP scope. CTAP 2.1
    //     sec. 6.5.5.7 makes `rpId` OPTIONAL even for the `mc`/`ga` bits --
    //     an absent rpId yields an unscoped token (bound to the RP on
    //     first use). We accept it rather than rejecting, matching the
    //     C port. (True bind-on-first-use is unimplemented in both; an
    //     unscoped mc/ga token is usable across RPs for its lifetime --
    //     a possible future hardening, but spec-permitted.)
    let (perms, scope_hash) = if with_perms {
        let requested = match params.permissions {
            Some(p) if p != 0 => p,
            _ => {
                secret.cleanse();
                out.push(ERR_MISSING_PARAMETER);
                return;
            }
        };
        // Reject any bit outside the set we actually support (CTAP 2.1
        // sec. 6.5.5.7 -> CTAP2_ERR_UNAUTHORIZED_PERMISSION). Checked against
        // the full u64 so a high bit can't be silently dropped by the u8
        // narrowing, and so BioEnrollment (0x08, never granted here) is
        // refused rather than accepted.
        const SUPPORTED_PERMS: u64 = (PERM_MAKE_CREDENTIAL
            | PERM_GET_ASSERTION
            | PERM_CREDENTIAL_MGMT
            | PERM_LARGE_BLOB_WRITE
            | PERM_AUTHENTICATOR_CFG) as u64;
        if requested & !SUPPORTED_PERMS != 0 {
            secret.cleanse();
            out.push(ERR_UNAUTHORIZED_PERMISSION);
            return;
        }
        (requested as u8, params.rp_id_hash)
    } else {
        (PERM_LEGACY_TOKEN, None)
    };
    session.pin_uv_auth_token = gen_32(trng);
    session.activate_token(perms, scope_hash);
    let token_enc = secret.encrypt(trng, &session.pin_uv_auth_token);
    // The shared secret has served its purpose (token transport
    // encryption); wipe the derived key material from the stack (M2).
    secret.cleanse();

    let map = cbor_map! {
        cbor_int!(2) => Value::Bytes(token_enc),
    };
    let mut enc = AllocVec::new();
    pqf_cbor::encode(&map, &mut enc);
    out.push(0);
    out.extend_from_slice(&enc);
}
