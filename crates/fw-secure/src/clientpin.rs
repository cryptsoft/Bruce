// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP2 `authenticatorClientPIN`, protocol v1, Secure-side.
//!
//! Everything here has to be Secure. The shared secret, the PIN hash,
//! the retry counter and the pinUvAuthToken are each enough on their
//! own to undo the PIN if the Non-secure world could reach them --
//! the retry counter most of all, since a rollback turns a 4-digit PIN
//! from 8 guesses into unlimited ones.
//!
//! Protocol **v1 only**: shared secret is `SHA-256(ECDH.x)`, encryption
//! is AES-256-CBC with a zero IV, and authentication is the left 16
//! bytes of HMAC-SHA-256. v2 (random IVs, HKDF-separated keys) is a
//! larger change and is not pretended here -- getInfo advertises v1
//! alone, so a client negotiates down rather than guessing.

use crate::pinstore::{self, PinState, MAX_RETRIES};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use alloc::vec::Vec;

pub const PIN_PROTOCOL_V1: u64 = 1;

/// Subcommands (CTAP2.1 sec. 6.5.1).
pub const SUB_GET_RETRIES: u64 = 0x01;
pub const SUB_GET_KEY_AGREEMENT: u64 = 0x02;
pub const SUB_SET_PIN: u64 = 0x03;
pub const SUB_CHANGE_PIN: u64 = 0x04;
pub const SUB_GET_PIN_TOKEN: u64 = 0x05;
pub const SUB_GET_TOKEN_WITH_PERMS: u64 = 0x09;

/// Permission bits carried by a pinUvAuthToken.
pub const PERM_MAKE_CREDENTIAL: u8 = 0x01;
pub const PERM_GET_ASSERTION: u8 = 0x02;
pub const PERM_CREDENTIAL_MGMT: u8 = 0x04;
pub const PERM_AUTHENTICATOR_CFG: u8 = 0x20;

/// CTAP2 minimum PIN length, in Unicode code points.
const MIN_PIN_CODEPOINTS: usize = 4;
/// The padded block is 64 bytes and must end in at least one NUL, so a
/// PIN can be at most 63 bytes encoded. The C port has had this ceiling
/// since it was written; neither Rust port did.
const PIN_MAX_BYTES: usize = 63;
/// Padded plaintext length CTAP2 mandates for newPinEnc.
const PIN_PAD_LEN: usize = 64;
/// Consecutive failures inside one boot before the token demands a
/// power cycle -- separate from, and stricter than, the 8-attempt
/// lifetime limit.
const MAX_FAILURES_PER_BOOT: u8 = 3;

/// Per-boot session state. All of it is regenerated on reset, which is
/// what makes a power cycle clear a soft-blocked PIN.
struct Session {
    /// This boot's ECDH key agreement key.
    secret: p256::SecretKey,
    /// The token a successful PIN entry hands out.
    token: [u8; 32],
    token_valid: bool,
    permissions: u8,
    /// rpId the token is scoped to, if any.
    rp_id_hash: Option<[u8; 32]>,
    failures_this_boot: u8,
}

static mut SESSION: Option<Session> = None;

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    use hmac::{Mac, SimpleHmac};
    let mut m = <SimpleHmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("any key length");
    m.update(msg);
    let d = m.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// CBC over the raw block cipher, zero IV, no padding -- PIN protocol
/// v1 semantics. Built by hand for the same reason the FIDO firmware
/// does: the padding-mode wrappers want features this image does not
/// otherwise need, and the loop is four lines.
///
/// Refuses non-block-multiple input rather than truncating.
fn aes_cbc_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return Vec::new();
    }
    let cipher = Aes256::new(key.into());
    let mut prev = [0u8; 16];
    let mut out = Vec::with_capacity(plaintext.len());
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

fn aes_cbc_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return None;
    }
    let cipher = Aes256::new(key.into());
    let mut prev = [0u8; 16];
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let cipher_block = block;
        cipher.decrypt_block((&mut block).into());
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        out.extend_from_slice(&block);
        prev = cipher_block;
    }
    Some(out)
}

/// Start (or restart) the session. Called once at boot.
pub fn init(trng: &mut crate::trng::Trng) {
    let secret = loop {
        // P-256 scalars are rejection-sampled; with TRNG-quality
        // entropy this virtually always succeeds first time.
        let mut bytes = [0u8; 32];
        trng.fill(&mut bytes);
        if let Ok(sk) = p256::SecretKey::from_slice(&bytes) {
            break sk;
        }
    };
    let mut token = [0u8; 32];
    trng.fill(&mut token);
    // SAFETY: single-threaded, before NS runs.
    unsafe {
        SESSION = Some(Session {
            secret,
            token,
            token_valid: false,
            permissions: 0,
            rp_id_hash: None,
            failures_this_boot: 0,
        });
    }
}

fn session() -> &'static mut Session {
    // SAFETY: single-threaded; initialised in `main` before NS exists.
    unsafe {
        (&mut *(&raw mut SESSION))
            .as_mut()
            .expect("session initialised")
    }
}

/// This boot's key-agreement public point, as x and y.
pub fn key_agreement_public() -> ([u8; 32], [u8; 32]) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let pt = session().secret.public_key().to_encoded_point(false);
    let b = pt.as_bytes();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&b[1..33]);
    y.copy_from_slice(&b[33..65]);
    (x, y)
}

/// v1 shared secret from the platform's key-agreement point.
fn shared_secret(peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Option<[u8; 32]> {
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(peer_x);
    sec1[33..65].copy_from_slice(peer_y);
    let pt = p256::EncodedPoint::from_bytes(sec1).ok()?;
    let affine = Option::<p256::AffinePoint>::from(p256::AffinePoint::from_encoded_point(&pt))?;
    let shared =
        p256::elliptic_curve::ecdh::diffie_hellman(session().secret.to_nonzero_scalar(), &affine);
    let mut x = [0u8; 32];
    x.copy_from_slice(shared.raw_secret_bytes().as_slice());
    Some(sha256(&x))
}

/// Left 16 bytes of HMAC, compared in constant time.
fn verify_auth(key: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if sig.len() < 16 {
        return false;
    }
    let full = hmac_sha256(key, msg);
    bool::from(full[..16].ct_eq(&sig[..16]))
}

/// Outcome of a subcommand, as a CTAP2 status plus optional payload.
pub enum PinReply {
    Err(u8),
    Retries(u8),
    KeyAgreement([u8; 32], [u8; 32]),
    Token(Vec<u8>),
    Ok,
}

/// Everything a ClientPIN request can carry, already parsed by NS.
pub struct PinRequest<'a> {
    pub protocol: u64,
    pub subcommand: u64,
    pub key_agreement: Option<([u8; 32], [u8; 32])>,
    pub auth_param: &'a [u8],
    pub new_pin_enc: &'a [u8],
    pub pin_hash_enc: &'a [u8],
    pub permissions: u8,
    pub rp_id_hash: Option<[u8; 32]>,
}

/// CTAP2 errors this module returns.
pub const ERR_INVALID_PARAM: u8 = 0x02;
pub const ERR_MISSING_PARAMETER: u8 = 0x14;
/// CTAP 2.1 sec. 8.1. 0x16 is UNSUPPORTED_EXTENSION; see client_pin.rs.
pub const ERR_INVALID_SUBCOMMAND: u8 = 0x3e;
pub const ERR_PIN_INVALID: u8 = 0x31;
pub const ERR_PIN_BLOCKED: u8 = 0x32;
pub const ERR_PIN_AUTH_INVALID: u8 = 0x33;
pub const ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
pub const ERR_PIN_NOT_SET: u8 = 0x35;
pub const ERR_PIN_POLICY_VIOLATION: u8 = 0x37;

/// Count the code points in the padded PIN and strip the padding.
///
/// CTAP2 pads with zero bytes to 64; the PIN itself must be at least
/// four code points and must not contain a NUL.
/// Unpad and validate a new PIN against the policy in force.
///
/// `min_pin_length` is the authenticator's configured minimum, which
/// authenticatorConfig setMinPINLength can raise. It used to be stored,
/// reported to relying parties in the minPinLength extension, and never
/// consulted here -- so an enterprise that set a minimum of 8 was told
/// it applied while the token went on accepting four.
fn unpad_pin(padded: &[u8]) -> Option<&[u8]> {
    let end = padded.iter().position(|&b| b == 0).unwrap_or(padded.len());
    let pin = &padded[..end];
    if pin.is_empty() {
        return None;
    }
    let text = core::str::from_utf8(pin).ok()?;
    let n = text.chars().count();
    // CTAP 2.1 sec. 6.5.5.7 counts code points, not bytes, and the ceiling
    // is on the encoded length: the padded block is 64 bytes and must
    // end in at least one NUL.
    if n < MIN_PIN_CODEPOINTS || n < min_pin_length() as usize || pin.len() > PIN_MAX_BYTES {
        return None;
    }
    Some(pin)
}

fn pin_hash_left16(pin: &[u8]) -> [u8; 16] {
    let full = sha256(pin);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn handle(req: &PinRequest) -> PinReply {
    if req.protocol != PIN_PROTOCOL_V1 && req.subcommand != SUB_GET_RETRIES {
        return PinReply::Err(ERR_INVALID_PARAM);
    }
    match req.subcommand {
        SUB_GET_RETRIES => PinReply::Retries(pinstore::get().retries),
        SUB_GET_KEY_AGREEMENT => {
            let (x, y) = key_agreement_public();
            PinReply::KeyAgreement(x, y)
        }
        SUB_SET_PIN => set_pin(req),
        SUB_CHANGE_PIN => change_pin(req),
        SUB_GET_PIN_TOKEN => get_token(req, PERM_MAKE_CREDENTIAL | PERM_GET_ASSERTION, None),
        SUB_GET_TOKEN_WITH_PERMS => get_token(req, req.permissions, req.rp_id_hash),
        _ => PinReply::Err(ERR_INVALID_SUBCOMMAND),
    }
}

fn set_pin(req: &PinRequest) -> PinReply {
    let st = pinstore::get();
    if st.is_set {
        // Already set: the client must use changePIN, which proves it
        // knows the current one.
        return PinReply::Err(ERR_PIN_AUTH_INVALID);
    }
    let (px, py) = match req.key_agreement {
        Some(v) => v,
        None => return PinReply::Err(ERR_MISSING_PARAMETER),
    };
    let secret = match shared_secret(&px, &py) {
        Some(s) => s,
        None => return PinReply::Err(ERR_INVALID_PARAM),
    };
    if !verify_auth(&secret, req.new_pin_enc, req.auth_param) {
        return PinReply::Err(ERR_PIN_AUTH_INVALID);
    }
    if req.new_pin_enc.len() != PIN_PAD_LEN {
        return PinReply::Err(ERR_PIN_POLICY_VIOLATION);
    }
    let padded = match aes_cbc_decrypt(&secret, req.new_pin_enc) {
        Some(p) => p,
        None => return PinReply::Err(ERR_INVALID_PARAM),
    };
    let pin = match unpad_pin(&padded) {
        Some(p) => p,
        None => return PinReply::Err(ERR_PIN_POLICY_VIOLATION),
    };
    // A token issued under the old PIN must not outlive it (sec. 6.5.5.7):
    // the whole point of changing a PIN is that what the old one
    // authorised stops working. The token was boot-constant and
    // survived both setPIN and changePIN, which also meant the
    // forceChangePin gate governed only tokens minted after the flag.
    session().token_valid = false;
    session().permissions = 0;
    pinstore::put(PinState {
        is_set: true,
        retries: MAX_RETRIES,
        hash: pin_hash_left16(pin),
        // Whatever change was being forced has now happened.
        force_change: false,
        ..st
    });
    PinReply::Ok
}

fn change_pin(req: &PinRequest) -> PinReply {
    let st = pinstore::get();
    if !st.is_set {
        return PinReply::Err(ERR_PIN_NOT_SET);
    }
    if st.retries == 0 {
        return PinReply::Err(ERR_PIN_BLOCKED);
    }
    let (px, py) = match req.key_agreement {
        Some(v) => v,
        None => return PinReply::Err(ERR_MISSING_PARAMETER),
    };
    let secret = match shared_secret(&px, &py) {
        Some(s) => s,
        None => return PinReply::Err(ERR_INVALID_PARAM),
    };
    // The auth covers newPinEnc || pinHashEnc.
    let mut msg = Vec::with_capacity(req.new_pin_enc.len() + req.pin_hash_enc.len());
    msg.extend_from_slice(req.new_pin_enc);
    msg.extend_from_slice(req.pin_hash_enc);
    if !verify_auth(&secret, &msg, req.auth_param) {
        return PinReply::Err(ERR_PIN_AUTH_INVALID);
    }
    match check_pin_hash(&secret, req.pin_hash_enc, st) {
        Ok(()) => {}
        Err(e) => return PinReply::Err(e),
    }
    if req.new_pin_enc.len() != PIN_PAD_LEN {
        return PinReply::Err(ERR_PIN_POLICY_VIOLATION);
    }
    let padded = match aes_cbc_decrypt(&secret, req.new_pin_enc) {
        Some(p) => p,
        None => return PinReply::Err(ERR_INVALID_PARAM),
    };
    let pin = match unpad_pin(&padded) {
        Some(p) => p,
        None => return PinReply::Err(ERR_PIN_POLICY_VIOLATION),
    };
    // A token issued under the old PIN must not outlive it (sec. 6.5.5.7):
    // the whole point of changing a PIN is that what the old one
    // authorised stops working. The token was boot-constant and
    // survived both setPIN and changePIN, which also meant the
    // forceChangePin gate governed only tokens minted after the flag.
    session().token_valid = false;
    session().permissions = 0;
    pinstore::put(PinState {
        is_set: true,
        retries: MAX_RETRIES,
        hash: pin_hash_left16(pin),
        // Whatever change was being forced has now happened.
        force_change: false,
        ..st
    });
    PinReply::Ok
}

/// Verify the encrypted PIN hash, spending a retry on failure.
///
/// The decrement is written to flash *before* the comparison result is
/// acted on, so yanking power on a wrong guess still costs the attempt.
fn check_pin_hash(secret: &[u8; 32], pin_hash_enc: &[u8], st: PinState) -> Result<(), u8> {
    use subtle::ConstantTimeEq;
    if pin_hash_enc.len() != 16 {
        return Err(ERR_INVALID_PARAM);
    }
    let s = session();
    if s.failures_this_boot >= MAX_FAILURES_PER_BOOT {
        return Err(ERR_PIN_AUTH_BLOCKED);
    }
    let decrypted = aes_cbc_decrypt(secret, pin_hash_enc).ok_or(ERR_INVALID_PARAM)?;
    if decrypted.len() != 16 {
        return Err(ERR_INVALID_PARAM);
    }
    // Spend the attempt first: a power cut between here and the
    // comparison must not hand back a free guess.
    pinstore::put(PinState {
        retries: st.retries.saturating_sub(1),
        ..st
    });
    if bool::from(decrypted[..16].ct_eq(&st.hash)) {
        s.failures_this_boot = 0;
        pinstore::put(PinState {
            retries: MAX_RETRIES,
            ..st
        });
        Ok(())
    } else {
        s.failures_this_boot += 1;
        if st.retries <= 1 {
            Err(ERR_PIN_BLOCKED)
        } else if s.failures_this_boot >= MAX_FAILURES_PER_BOOT {
            Err(ERR_PIN_AUTH_BLOCKED)
        } else {
            Err(ERR_PIN_INVALID)
        }
    }
}

fn get_token(req: &PinRequest, permissions: u8, rp_id_hash: Option<[u8; 32]>) -> PinReply {
    let st = pinstore::get();
    if !st.is_set {
        return PinReply::Err(ERR_PIN_NOT_SET);
    }
    if st.retries == 0 {
        return PinReply::Err(ERR_PIN_BLOCKED);
    }
    if permissions == 0 {
        return PinReply::Err(ERR_INVALID_PARAM);
    }
    // forceChangePin (sec. 6.5.5.7.2): while a change is pending, refuse a
    // token carrying makeCredential or getAssertion, so the host has to
    // run changePIN first. Tokens scoped only to credMgmt / authnrCfg
    // are still issued -- otherwise the host cannot drive the change it
    // is being told to make. This flag was settable and did nothing.
    if st.force_change && permissions & (PERM_MAKE_CREDENTIAL | PERM_GET_ASSERTION) != 0 {
        return PinReply::Err(ERR_PIN_POLICY_VIOLATION);
    }
    let (px, py) = match req.key_agreement {
        Some(v) => v,
        None => return PinReply::Err(ERR_MISSING_PARAMETER),
    };
    let secret = match shared_secret(&px, &py) {
        Some(s) => s,
        None => return PinReply::Err(ERR_INVALID_PARAM),
    };
    if let Err(e) = check_pin_hash(&secret, req.pin_hash_enc, st) {
        return PinReply::Err(e);
    }
    let s = session();
    s.token_valid = true;
    s.permissions = permissions;
    s.rp_id_hash = rp_id_hash;
    PinReply::Token(aes_cbc_encrypt(&secret, &s.token))
}

/// Check a pinUvAuthParam supplied with a command.
///
/// `message` is whatever CTAP2 says that command authenticates over.
pub fn verify_token(message: &[u8], sig: &[u8], permission: u8, rp: Option<&[u8; 32]>) -> bool {
    use subtle::ConstantTimeEq;
    let s = session();
    if !s.token_valid || s.permissions & permission == 0 {
        return false;
    }
    if let (Some(scoped), Some(actual)) = (s.rp_id_hash, rp) {
        if !bool::from(scoped.ct_eq(actual)) {
            return false;
        }
    }
    verify_auth(&s.token, message, sig)
}

/// Is a PIN currently configured? Reported through getInfo.
pub fn pin_is_set() -> bool {
    pinstore::get().is_set
}

/// Fixed-layout ClientPIN request, as NS hands it over.
///
///   0        pinUvAuthProtocol
///   1        subCommand
///   2        flags: bit0 keyAgreement present, bit1 rpId present
///   3        permissions
///   4..68    keyAgreement x, y
///   68       pinUvAuthParam length
///   69..101  pinUvAuthParam
///   101      pinHashEnc length
///   102..134 pinHashEnc
///   134      newPinEnc length
///   135..215 newPinEnc
///   215      rpId length
///   216..344 rpId
pub const PIN_REQ_LEN: usize = 344;

/// Decode the fixed layout and dispatch.
pub fn handle_raw(req: &[u8; PIN_REQ_LEN]) -> PinReply {
    let mut kx = [0u8; 32];
    let mut ky = [0u8; 32];
    kx.copy_from_slice(&req[4..36]);
    ky.copy_from_slice(&req[36..68]);
    let key_agreement = if req[2] & 0x01 != 0 {
        Some((kx, ky))
    } else {
        None
    };
    let auth_len = (req[68] as usize).min(32);
    let hash_len = (req[101] as usize).min(32);
    let new_len = (req[134] as usize).min(80);
    let rp_len = (req[215] as usize).min(128);
    let rp_id_hash = if req[2] & 0x02 != 0 && rp_len > 0 {
        Some(sha256(&req[216..216 + rp_len]))
    } else {
        None
    };
    handle(&PinRequest {
        protocol: req[0] as u64,
        subcommand: req[1] as u64,
        key_agreement,
        auth_param: &req[69..69 + auth_len],
        new_pin_enc: &req[135..135 + new_len],
        pin_hash_enc: &req[102..102 + hash_len],
        permissions: req[3],
        rp_id_hash,
    })
}

/// The configured minimum PIN length.
pub fn min_pin_length() -> u8 {
    pinstore::get().min_pin_length
}

/// May this relying party see the minPinLength extension?
pub fn min_pin_rp_allowed(rp_id_hash: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    let st = pinstore::get();
    st.min_pin_rps
        .iter()
        .take(st.min_pin_rp_count as usize)
        .any(|rp| bool::from(rp.ct_eq(rp_id_hash)))
}

/// authenticatorConfig subcommand: setMinPINLength.
///
/// Authenticated with a pinUvAuthToken carrying the config permission,
/// over `0xff * 32 || 0x0d || subCommand || subCommandParams` as CTAP2
/// specifies. NS supplies the already-hashed rpIds it parsed.
pub fn set_min_pin_length(
    new_len: Option<u8>,
    rp_hashes: &[[u8; 32]],
    force_change: Option<bool>,
) -> u8 {
    let st = pinstore::get();
    let mut next = st;
    if let Some(l) = new_len {
        // CTAP2: the minimum may only ever increase.
        if l < st.min_pin_length {
            return ERR_PIN_POLICY_VIOLATION;
        }
        next.min_pin_length = l;
    }
    if !rp_hashes.is_empty() {
        let n = rp_hashes.len().min(pinstore::MAX_MIN_PIN_RPS);
        next.min_pin_rps = [[0u8; 32]; pinstore::MAX_MIN_PIN_RPS];
        next.min_pin_rps[..n].copy_from_slice(&rp_hashes[..n]);
        next.min_pin_rp_count = n as u8;
    }
    if let Some(f) = force_change {
        next.force_change = f;
    }
    pinstore::put(next);
    0x00
}

/// Verify a pinUvAuthParam for authenticatorConfig.
pub fn verify_config_auth(subcommand: u8, params: &[u8], sig: &[u8]) -> bool {
    let mut msg = Vec::with_capacity(32 + 2 + params.len());
    msg.extend_from_slice(&[0xffu8; 32]);
    msg.push(0x0d);
    msg.push(subcommand);
    msg.extend_from_slice(params);
    verify_token(&msg, sig, PERM_AUTHENTICATOR_CFG, None)
}

/// hmac-secret (CTAP 2.1 sec. 12.5): evaluate the credential's HMAC secret
/// over one or two salts.
///
/// The salts arrive encrypted under the same PIN-protocol shared secret
/// as everything else, and the output goes back encrypted the same way.
/// The per-credential secret (`cred_random`) is derived from the master
/// key inside Secure and never leaves -- which is the whole reason this
/// cannot be a Non-secure extension.
///
/// Returns the encrypted output, or a CTAP2 error.
pub fn hmac_secret(
    cred_random: &[u8; 32],
    peer_x: &[u8; 32],
    peer_y: &[u8; 32],
    salt_enc: &[u8],
    salt_auth: &[u8],
) -> Result<Vec<u8>, u8> {
    // One salt is 32 bytes, two are 64; anything else is malformed.
    if salt_enc.len() != 32 && salt_enc.len() != 64 {
        return Err(ERR_INVALID_PARAM);
    }
    let secret = shared_secret(peer_x, peer_y).ok_or(ERR_INVALID_PARAM)?;
    if !verify_auth(&secret, salt_enc, salt_auth) {
        return Err(ERR_PIN_AUTH_INVALID);
    }
    let salts = aes_cbc_decrypt(&secret, salt_enc).ok_or(ERR_INVALID_PARAM)?;
    let mut out = Vec::with_capacity(salts.len());
    for chunk in salts.chunks(32) {
        out.extend_from_slice(&hmac_sha256(cred_random, chunk));
    }
    Ok(aes_cbc_encrypt(&secret, &out))
}
