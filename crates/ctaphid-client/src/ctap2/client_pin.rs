// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorClientPin` (CTAP 2.1 sec. 6.5) -- PIN management +
//! `pinUvAuthToken` acquisition.
//!
//! Eight subcommands per sec. 6.5.5.7 Table 8:
//!
//!   0x01 getPinRetries
//!   0x02 getKeyAgreement
//!   0x03 setPin
//!   0x04 changePin
//!   0x05 getPinToken                              (v1 only, legacy)
//!   0x06 getPinUvAuthTokenUsingUvWithPermissions  (UV-only devices)
//!   0x07 getUvRetries
//!   0x09 getPinUvAuthTokenUsingPinWithPermissions
//!
//! The host crate exposes one Rust fn per subcommand plus a
//! `PinUvAuth` "session" type that owns the PIN/UV-auth-token after
//! a successful PIN exchange so callers can plug it into subsequent
//! MakeCredential / GetAssertion calls.
//!
//! See [`super::pin_protocol`] for the v1 / v2 crypto primitives
//! these subcommands use.

use pqf_cbor::Value;

use crate::hid::Device;

use super::pin_protocol::{pad_new_pin, pin_hash, Protocol, Session};
use super::{
    cbor_call, map_get_int, want_bool, want_bytes, want_map, want_uint, Error, CMD_CLIENT_PIN,
};

/// Bit positions in the `permissions` field of a
/// `pinUvAuthToken` request (CTAP 2.1 sec. 6.5.5.7.1). Combine with
/// bitwise OR.
#[allow(missing_docs)]
pub mod permission {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const CREDENTIAL_MANAGEMENT: u8 = 0x04;
    pub const BIO_ENROLLMENT: u8 = 0x08;
    pub const LARGE_BLOB_WRITE: u8 = 0x10;
    pub const AUTHENTICATOR_CONFIGURATION: u8 = 0x20;
}

// ---------- Subcommand wrappers ----------

/// 0x01 `getPinRetries` -- query how many PIN-entry attempts the
/// device has left before locking. CTAP 2.1 sec. 6.5.5.2.
pub fn get_pin_retries(dev: &Device) -> Result<PinRetries, Error> {
    let req = Value::Map(vec![
        (
            Value::Uint(0x01),
            Value::Uint(Protocol::V2.as_byte() as u64),
        ),
        (Value::Uint(0x02), Value::Uint(0x01)),
    ]);
    let resp = cbor_call(dev, CMD_CLIENT_PIN, Some(&req))?
        .ok_or_else(|| Error::Decode("getPinRetries: empty response".into()))?;
    let map = want_map(&resp, "(top-level)")?;
    let retries = map_get_int(map, 0x03)
        .ok_or_else(|| Error::Decode("getPinRetries: missing 0x03 (pinRetries)".into()))?;
    let retries = want_uint(retries, "pinRetries")?;
    let power_cycle_state = match map_get_int(map, 0x04) {
        Some(v) => Some(want_bool(v, "powerCycleState")?),
        None => None,
    };
    Ok(PinRetries {
        retries,
        power_cycle_state,
    })
}

/// Response shape of [`get_pin_retries`]. The `powerCycleState`
/// signals whether the device has used up its single per-power-cycle
/// retry budget and needs a replug before further attempts.
#[derive(Clone, Debug)]
pub struct PinRetries {
    /// Remaining PIN-entry attempts before the device locks
    /// (0..=8 for the `bruce` firmware; varies per device).
    pub retries: u64,
    /// `true` if the device has exhausted its current power-cycle
    /// retry budget. Caller should ask the user to replug.
    pub power_cycle_state: Option<bool>,
}

/// 0x02 `getKeyAgreement` -- fetch the device's ephemeral
/// `keyAgreement` COSE_Key. CTAP 2.1 sec. 6.5.5.3.
///
/// You normally call this through [`establish_session`], which
/// chains it with the host's ECDH step.
pub fn get_key_agreement(dev: &Device, proto: Protocol) -> Result<Value, Error> {
    let req = Value::Map(vec![
        (Value::Uint(0x01), Value::Uint(proto.as_byte() as u64)),
        (Value::Uint(0x02), Value::Uint(0x02)),
    ]);
    let resp = cbor_call(dev, CMD_CLIENT_PIN, Some(&req))?
        .ok_or_else(|| Error::Decode("getKeyAgreement: empty response".into()))?;
    let map = want_map(&resp, "(top-level)")?;
    let key_agreement = map_get_int(map, 0x01)
        .ok_or_else(|| Error::Decode("getKeyAgreement: missing 0x01 (keyAgreement)".into()))?;
    Ok(key_agreement.clone())
}

/// Convenience: do steps 1+2 of the PIN protocol setup in one go.
/// Returns a [`Session`] ready to encrypt / authenticate.
pub fn establish_session(dev: &Device, proto: Protocol) -> Result<Session, Error> {
    let mut session = Session::initiate(proto);
    let device_key = get_key_agreement(dev, proto)?;
    session.complete(&device_key)?;
    Ok(session)
}

/// 0x03 `setPin` -- initial PIN set on a fresh device. CTAP 2.1
/// sec. 6.5.5.4. The PIN is provided as a UTF-8 byte slice; the
/// caller is responsible for length validation (per the device's
/// `minPINLength` advertisement from `getInfo`).
pub fn set_pin(dev: &Device, session: &Session, new_pin: &[u8]) -> Result<(), Error> {
    // newPinEnc = encrypt(LEFT(PIN || zero-pad, 64))
    let padded = pad_new_pin(new_pin)?;
    let new_pin_enc = session.encrypt(&padded)?;
    let pin_uv_auth_param = session.authenticate(&new_pin_enc)?;

    let req = Value::Map(vec![
        (
            Value::Uint(0x01),
            Value::Uint(session.protocol().as_byte() as u64),
        ),
        (Value::Uint(0x02), Value::Uint(0x03)),
        (Value::Uint(0x03), session.public_key_cbor()),
        (Value::Uint(0x04), Value::Bytes(pin_uv_auth_param)),
        (Value::Uint(0x05), Value::Bytes(new_pin_enc)),
    ]);
    let _ = cbor_call(dev, CMD_CLIENT_PIN, Some(&req))?;
    Ok(())
}

/// 0x04 `changePin` -- update the PIN on a device that already has
/// one set. CTAP 2.1 sec. 6.5.5.5. Caller provides both the old PIN
/// (used to derive `pinHashEnc`) and the new PIN.
pub fn change_pin(
    dev: &Device,
    session: &Session,
    old_pin: &[u8],
    new_pin: &[u8],
) -> Result<(), Error> {
    let old_hash = pin_hash(old_pin);
    let pin_hash_enc = session.encrypt(&old_hash)?;

    let padded = pad_new_pin(new_pin)?;
    let new_pin_enc = session.encrypt(&padded)?;

    // pinUvAuthParam = HMAC(shared, newPinEnc || pinHashEnc)
    let mut combined = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
    combined.extend_from_slice(&new_pin_enc);
    combined.extend_from_slice(&pin_hash_enc);
    let pin_uv_auth_param = session.authenticate(&combined)?;

    let req = Value::Map(vec![
        (
            Value::Uint(0x01),
            Value::Uint(session.protocol().as_byte() as u64),
        ),
        (Value::Uint(0x02), Value::Uint(0x04)),
        (Value::Uint(0x03), session.public_key_cbor()),
        (Value::Uint(0x04), Value::Bytes(pin_uv_auth_param)),
        (Value::Uint(0x05), Value::Bytes(new_pin_enc)),
        (Value::Uint(0x06), Value::Bytes(pin_hash_enc)),
    ]);
    let _ = cbor_call(dev, CMD_CLIENT_PIN, Some(&req))?;
    Ok(())
}

/// 0x09 `getPinUvAuthTokenUsingPinWithPermissions` -- fetch a
/// `pinUvAuthToken` from the device, gated by the user's PIN.
/// CTAP 2.1 sec. 6.5.5.7. Returns a [`PinUvAuth`] handle the caller
/// can plug into MakeCredential / GetAssertion.
///
/// `permissions` is a bitwise OR of [`permission::*`] constants.
/// `rp_id` is optional; setting it pins the resulting token to a
/// single RP (recommended for least-privilege usage).
pub fn get_pin_uv_auth_token_using_pin(
    dev: &Device,
    session: Session,
    pin: &[u8],
    permissions: u8,
    rp_id: Option<&str>,
) -> Result<PinUvAuth, Error> {
    let hash = pin_hash(pin);
    let pin_hash_enc = session.encrypt(&hash)?;

    let mut req_entries: Vec<(Value, Value)> = vec![
        (
            Value::Uint(0x01),
            Value::Uint(session.protocol().as_byte() as u64),
        ),
        (Value::Uint(0x02), Value::Uint(0x09)),
        (Value::Uint(0x03), session.public_key_cbor()),
        (Value::Uint(0x06), Value::Bytes(pin_hash_enc)),
        (Value::Uint(0x09), Value::Uint(permissions as u64)),
    ];
    if let Some(rp) = rp_id {
        req_entries.push((Value::Uint(0x0a), Value::Text(rp.to_string())));
    }
    let req = Value::Map(req_entries);

    let resp = cbor_call(dev, CMD_CLIENT_PIN, Some(&req))?
        .ok_or_else(|| Error::Decode("getPinUvAuthTokenUsingPin: empty response".into()))?;
    let map = want_map(&resp, "(top-level)")?;
    let token_enc = map_get_int(map, 0x02).ok_or_else(|| {
        Error::Decode("getPinUvAuthTokenUsingPin: missing 0x02 (pinUvAuthToken-enc)".into())
    })?;
    let token_ct = want_bytes(token_enc, "pinUvAuthToken-enc")?;
    let token = session.decrypt(&token_ct)?;
    Ok(PinUvAuth {
        protocol: session.protocol(),
        token,
        session,
    })
}

/// 0x07 `getUvRetries` -- query the device's biometric retry
/// counter. Returns `None` if the device doesn't implement UV;
/// callers can use that to skip UV-based flows.
pub fn get_uv_retries(dev: &Device) -> Result<Option<u64>, Error> {
    let req = Value::Map(vec![
        (
            Value::Uint(0x01),
            Value::Uint(Protocol::V2.as_byte() as u64),
        ),
        (Value::Uint(0x02), Value::Uint(0x07)),
    ]);
    match cbor_call(dev, CMD_CLIENT_PIN, Some(&req)) {
        Ok(Some(v)) => {
            let map = want_map(&v, "(top-level)")?;
            match map_get_int(map, 0x05) {
                Some(r) => Ok(Some(want_uint(r, "uvRetries")?)),
                None => Ok(None),
            }
        }
        Ok(None) => Ok(None),
        Err(Error::Ctap(super::Status::InvalidSubcommand))
        | Err(Error::Ctap(super::Status::UnsupportedOption)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Owned, decrypted `pinUvAuthToken` plus the session that produced
/// it. Pass [`PinUvAuth::sign`] the byte string (typically a
/// clientDataHash) and feed the result into the MakeCredential /
/// GetAssertion `pinUvAuthParam` field; pass [`PinUvAuth::protocol`]
/// as `pinUvAuthProtocol`.
///
/// The session is retained so callers that re-up the token via
/// [`get_pin_uv_auth_token_using_pin`] don't have to redo ECDH from
/// scratch.
pub struct PinUvAuth {
    /// PIN protocol the token was minted under. Always matches
    /// `session.protocol()`.
    pub protocol: Protocol,
    token: Vec<u8>,
    session: Session,
}

impl PinUvAuth {
    /// HMAC the given payload with the `pinUvAuthToken`, returning
    /// the bytes to plug into the `pinUvAuthParam` field of
    /// MakeCredential / GetAssertion / etc.
    ///
    /// Uses the same truncation rule as the underlying protocol:
    /// 16 bytes for v1, 32 bytes for v2.
    pub fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.token)
            .map_err(|e| Error::Decode(format!("HMAC init: {e}")))?;
        mac.update(payload);
        let tag = mac.finalize().into_bytes();
        match self.protocol {
            Protocol::V1 => Ok(tag[..16].to_vec()),
            Protocol::V2 => Ok(tag.to_vec()),
        }
    }

    /// Borrow the underlying [`Session`] -- useful for callers that
    /// want to issue another PIN-protocol-protected command on the
    /// same ECDH derivation.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Raw decrypted token bytes. Exposed for inspection / testing;
    /// production callers should use [`Self::sign`] instead of
    /// re-implementing HMAC on top.
    pub fn token(&self) -> &[u8] {
        &self.token
    }
}
