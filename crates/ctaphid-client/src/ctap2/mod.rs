// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP 2.1 command layer.
//!
//! Each authenticator command (CTAP 2.1 sec. 6) is exposed as a method
//! on [`crate::hid::Device`] that:
//!
//! 1. Builds the request CBOR map from a typed struct,
//! 2. Sends it via `CTAPHID_CBOR` (cmd 0x90),
//! 3. Receives the response -- a status byte followed by an
//!    optional CBOR-encoded payload,
//! 4. Maps the status byte to [`Error::Ctap`] on failure or parses
//!    the payload into a typed response on success.
//!
//! Module layout:
//!
//! - [`error`]       -- [`Status`] (CTAP 2.1 sec. 6 Table 1) + [`Error`].
//! - [`types`]       -- Shared WebAuthn-shaped structs (RP, User,
//!                     PubKeyCredParam, CredentialDescriptor,
//!                     AuthOptions) and COSE alg constants.
//! - [`get_info`]    -- `authenticatorGetInfo` (0x04).
//! - [`make_credential`] -- `authenticatorMakeCredential` (0x01).
//! - [`get_assertion`]   -- `authenticatorGetAssertion` (0x02).
//! - [`reset`]       -- `authenticatorReset` (0x07).
//! - [`selection`]   -- `authenticatorSelection` (0x0B).
//!
//! Subsequent commits will add `clientPin` (0x06) with both PIN
//! protocols, `credentialManagement` (0x0A), `largeBlobs` (0x0C),
//! `config` (0x0D), and `getNextAssertion` (0x08).

use crate::hid::{Cmd, Device};
use pqf_cbor::Value;

pub mod client_pin;
pub mod config;
pub mod credential_management;
mod error;
pub mod get_assertion;
pub mod get_info;
pub mod get_next_assertion;
pub mod large_blobs;
pub mod make_credential;
pub mod pin_protocol;
pub mod reset;
pub mod selection;
pub mod types;

pub use error::{Error, Status};

// ---------- CTAP2 command bytes (sec. 6 Table 2) ----------

/// `authenticatorMakeCredential` -- register a new credential.
pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
/// `authenticatorGetAssertion` -- sign a challenge with an existing credential.
pub const CMD_GET_ASSERTION: u8 = 0x02;
/// `authenticatorGetInfo` -- return capability + version info.
pub const CMD_GET_INFO: u8 = 0x04;
/// `authenticatorClientPin` -- PIN protocol subcommands. Wired up in a later commit.
pub const CMD_CLIENT_PIN: u8 = 0x06;
/// `authenticatorReset` -- wipe all credentials + secrets.
pub const CMD_RESET: u8 = 0x07;
/// `authenticatorGetNextAssertion` -- companion to GetAssertion for multi-cred RPs.
pub const CMD_GET_NEXT_ASSERTION: u8 = 0x08;
/// `authenticatorCredentialManagement` -- list / delete resident creds.
pub const CMD_CREDENTIAL_MANAGEMENT: u8 = 0x0a;
/// `authenticatorSelection` -- let the user confirm this physical authenticator.
pub const CMD_SELECTION: u8 = 0x0b;
/// `authenticatorLargeBlobs` -- RP-side blob storage.
pub const CMD_LARGE_BLOBS: u8 = 0x0c;
/// `authenticatorConfig` -- alwaysUv / setMinPINLength / enableEnterpriseAttestation.
pub const CMD_CONFIG: u8 = 0x0d;

// ---------- Dispatch helper ----------

/// Send a CTAP2 command over the already-open [`Device`] and return
/// the parsed response CBOR (or `None` if the device returned an
/// empty payload with status OK -- e.g. `authenticatorReset`).
///
/// `request` is optional: commands like `authenticatorGetInfo` and
/// `authenticatorReset` take no parameter map and send just the
/// 1-byte command code.
///
/// On a non-zero status byte, returns `Err(Error::Ctap(status))`.
/// On a malformed response (truncated, non-CBOR payload after OK),
/// returns `Err(Error::Decode(...))`.
pub fn cbor_call(dev: &Device, cmd: u8, request: Option<&Value>) -> Result<Option<Value>, Error> {
    // Wire format (CTAP 2.1 sec. 8.2): `cmd_byte || optional_cbor_payload`.
    let mut wire: Vec<u8> = Vec::with_capacity(64);
    wire.push(cmd);
    if let Some(v) = request {
        pqf_cbor::encode(v, &mut wire);
    }
    dev.send_msg(Cmd::Cbor, &wire)?;
    let resp = dev.recv_msg(Cmd::Cbor)?;
    if resp.is_empty() {
        return Err(Error::Decode("empty CTAP2 response".into()));
    }
    let status = Status::from_byte(resp[0]);
    if status != Status::Ok {
        return Err(Error::Ctap(status));
    }
    if resp.len() == 1 {
        return Ok(None);
    }
    let value = pqf_cbor::decode(&resp[1..])
        .map_err(|e| Error::Decode(format!("response CBOR: {:?}", e)))?;
    Ok(Some(value))
}

// ---------- Small CBOR-accessor helpers ----------
//
// Shared across the per-command modules. Lifting them into one
// place keeps each command file focused on the spec's request +
// response shape rather than CBOR-traversal boilerplate.

/// Find the entry in `map` whose key is an integer (positive or
/// negative) equal to `key`. Returns `None` if the key isn't there
/// or if the value at that key has the wrong CBOR major type.
pub(crate) fn map_get_int(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| match k {
            Value::Uint(u) => *u as i64 == key,
            Value::Nint(n) => *n == key,
            _ => false,
        })
        .map(|(_, v)| v)
}

/// Find the entry in `map` whose key is a text string equal to `key`.
pub(crate) fn map_get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .map(|(_, v)| v)
}

/// Convenience: extract a `Vec<u8>` (CBOR byte string) from a CBOR
/// value, or return a `Decode` error citing the field name.
pub(crate) fn want_bytes(v: &Value, field: &str) -> Result<Vec<u8>, Error> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(Error::Decode(format!(
            "field `{field}` was expected to be a byte string"
        ))),
    }
}

/// Convenience: extract a `String` (CBOR text string).
pub(crate) fn want_text(v: &Value, field: &str) -> Result<String, Error> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(Error::Decode(format!(
            "field `{field}` was expected to be a text string"
        ))),
    }
}

/// Convenience: extract a u64 (CBOR unsigned int).
pub(crate) fn want_uint(v: &Value, field: &str) -> Result<u64, Error> {
    match v {
        Value::Uint(u) => Ok(*u),
        _ => Err(Error::Decode(format!(
            "field `{field}` was expected to be an unsigned integer"
        ))),
    }
}

/// Convenience: extract a signed int (CBOR uint OR nint).
pub(crate) fn want_int(v: &Value, field: &str) -> Result<i64, Error> {
    match v {
        Value::Uint(u) => Ok(*u as i64),
        Value::Nint(n) => Ok(*n),
        _ => Err(Error::Decode(format!(
            "field `{field}` was expected to be an integer"
        ))),
    }
}

/// Convenience: extract a bool.
pub(crate) fn want_bool(v: &Value, field: &str) -> Result<bool, Error> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(Error::Decode(format!(
            "field `{field}` was expected to be a boolean"
        ))),
    }
}

/// Convenience: borrow a CBOR map's entries.
pub(crate) fn want_map<'a>(v: &'a Value, field: &str) -> Result<&'a [(Value, Value)], Error> {
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(Error::Decode(format!(
            "field `{field}` was expected to be a map"
        ))),
    }
}

/// Convenience: borrow a CBOR array's entries.
pub(crate) fn want_array<'a>(v: &'a Value, field: &str) -> Result<&'a [Value], Error> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(Error::Decode(format!(
            "field `{field}` was expected to be an array"
        ))),
    }
}
