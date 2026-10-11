// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorGetAssertion` (CTAP 2.1 sec. 6.2) -- sign a challenge
//! with an existing credential.
//!
//! Request layout (CTAP 2.1 sec. 6.2.1 Table 5):
//!
//!   0x01 rpId                   (text)
//!   0x02 clientDataHash         (32 bytes)
//!   0x03 allowList              (optional array of CredentialDescriptor)
//!   0x04 extensions             (optional map)
//!   0x05 options                (optional AuthOptions)
//!   0x06 pinUvAuthParam         (optional bytes)
//!   0x07 pinUvAuthProtocol      (optional uint)
//!
//! Response layout (CTAP 2.1 sec. 6.2.6):
//!
//!   0x01 credential             (optional CredentialDescriptor; present
//!                                when allowList had > 1 entry or was
//!                                absent and a resident cred was found)
//!   0x02 authData               (bytes)
//!   0x03 signature              (bytes)
//!   0x04 user                   (optional User, for resident creds)
//!   0x05 numberOfCredentials    (optional uint; > 1 -> caller should
//!                                follow up with GetNextAssertion)
//!   0x06 userSelected           (optional bool)
//!   0x07 largeBlobKey           (optional bytes)

use crate::hid::Device;
use pqf_cbor::Value;

use super::types::{AuthOptions, CredentialDescriptor, User};
use super::{
    cbor_call, map_get_int, map_get_str, want_array, want_bool, want_bytes, want_map, want_text,
    want_uint, Error, CMD_GET_ASSERTION,
};

/// `authenticatorGetAssertion` request parameters.
#[derive(Clone, Debug)]
pub struct GetAssertionRequest {
    /// 0x01 `rpId` -- relying party ID. Same string the RP gave to
    /// MakeCredential.
    pub rp_id: String,
    /// 0x02 `clientDataHash` -- SHA-256 of the client data JSON.
    pub client_data_hash: [u8; 32],
    /// 0x03 `allowList` -- when present, the authenticator returns
    /// an assertion only for one of these credentials. Absent on
    /// "passwordless" / discoverable-credential flows.
    pub allow_list: Option<Vec<CredentialDescriptor>>,
    /// 0x04 `extensions` -- raw CBOR for forwards-compat.
    pub extensions: Option<Value>,
    /// 0x05 `options` -- `up` / `uv`. `rk` is meaningless for
    /// GetAssertion (only used on MakeCredential).
    pub options: Option<AuthOptions>,
    /// 0x06 `pinUvAuthParam`.
    pub pin_uv_auth_param: Option<Vec<u8>>,
    /// 0x07 `pinUvAuthProtocol`.
    pub pin_uv_auth_protocol: Option<u64>,
}

/// `authenticatorGetAssertion` response.
#[derive(Clone, Debug)]
pub struct GetAssertionResponse {
    /// 0x01 `credential` -- descriptor of the credential that
    /// produced this assertion. Present when the allowList had more
    /// than one entry or when no allowList was given.
    pub credential: Option<CredentialDescriptor>,
    /// 0x02 `authData` -- raw bytes per WebAuthn sec. 6.1.
    pub auth_data: Vec<u8>,
    /// 0x03 `signature` -- raw signature bytes. Format depends on
    /// the credential's COSE alg (DER ECDSA for `-7`, hybrid blob
    /// for the ML-DSA variants).
    pub signature: Vec<u8>,
    /// 0x04 `user` -- populated when the credential is resident.
    /// Allows passwordless flows that need to know which user the
    /// authenticator picked.
    pub user: Option<User>,
    /// 0x05 `numberOfCredentials` -- when > 1, the RP should call
    /// `authenticatorGetNextAssertion` to pull subsequent matches.
    pub number_of_credentials: Option<u64>,
    /// 0x06 `userSelected` -- `true` if the user chose this
    /// credential on the authenticator's own display (rare).
    pub user_selected: Option<bool>,
    /// 0x07 `largeBlobKey`.
    pub large_blob_key: Option<Vec<u8>>,
}

impl GetAssertionRequest {
    /// Encode this request to the CTAP 2.1 sec. 6.2.1 CBOR map that
    /// [`get_assertion`] puts on the wire. Public for the same
    /// reason as [`super::make_credential::MakeCredentialRequest::to_cbor`]
    /// -- inspecting or sizing the request without sending it.
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(7);
        entries.push((Value::Uint(0x01), Value::Text(self.rp_id.clone())));
        entries.push((
            Value::Uint(0x02),
            Value::Bytes(self.client_data_hash.to_vec()),
        ));
        if let Some(ref al) = self.allow_list {
            let arr: Vec<Value> = al.iter().map(|d| d.to_cbor()).collect();
            entries.push((Value::Uint(0x03), Value::Array(arr)));
        }
        if let Some(ref ext) = self.extensions {
            entries.push((Value::Uint(0x04), ext.clone()));
        }
        if let Some(ref opts) = self.options {
            if !opts.is_empty() {
                entries.push((Value::Uint(0x05), opts.to_cbor()));
            }
        }
        if let Some(ref pup) = self.pin_uv_auth_param {
            entries.push((Value::Uint(0x06), Value::Bytes(pup.clone())));
        }
        if let Some(proto) = self.pin_uv_auth_protocol {
            entries.push((Value::Uint(0x07), Value::Uint(proto)));
        }
        Value::Map(entries)
    }
}

/// Send `authenticatorGetAssertion` (command 0x02).
pub fn get_assertion(
    dev: &Device,
    req: &GetAssertionRequest,
) -> Result<GetAssertionResponse, Error> {
    let payload = req.to_cbor();
    let resp = cbor_call(dev, CMD_GET_ASSERTION, Some(&payload))?
        .ok_or_else(|| Error::Decode("GetAssertion returned empty payload".into()))?;
    parse_assertion(&resp)
}

/// Parse a CTAP2 `GetAssertion` (or `GetNextAssertion`) response
/// CBOR map. Exposed because `authenticatorGetNextAssertion`
/// (command 0x08) uses the same response shape and the future
/// `getNextAssertion` module will reuse this parser.
pub(crate) fn parse_assertion(resp: &Value) -> Result<GetAssertionResponse, Error> {
    let map = want_map(resp, "(top-level)")?;

    let credential = match map_get_int(map, 0x01) {
        Some(v) => {
            let inner = want_map(v, "credential")?;
            let id = inner
                .iter()
                .find_map(|(k, val)| match k {
                    Value::Text(s) if s == "id" => Some(val),
                    _ => None,
                })
                .ok_or_else(|| Error::Decode("credential.id missing".into()))?;
            let id_bytes = want_bytes(id, "credential.id")?;
            // `transports` is optional per spec and never emitted in
            // GetAssertion responses we've seen, but parse if present.
            let transports = inner
                .iter()
                .find_map(|(k, val)| match k {
                    Value::Text(s) if s == "transports" => Some(val),
                    _ => None,
                })
                .map(|v| -> Result<Vec<String>, Error> {
                    let arr = want_array(v, "credential.transports")?;
                    arr.iter()
                        .enumerate()
                        .map(|(i, e)| want_text(e, &format!("credential.transports[{i}]")))
                        .collect()
                })
                .transpose()?;
            Some(CredentialDescriptor {
                id: id_bytes,
                transports,
            })
        }
        None => None,
    };

    let auth_data = {
        let v = map_get_int(map, 0x02)
            .ok_or_else(|| Error::Decode("missing required field 0x02 (authData)".into()))?;
        want_bytes(v, "authData")?
    };
    let signature = {
        let v = map_get_int(map, 0x03)
            .ok_or_else(|| Error::Decode("missing required field 0x03 (signature)".into()))?;
        want_bytes(v, "signature")?
    };
    let user = match map_get_int(map, 0x04) {
        Some(v) => {
            let inner = want_map(v, "user")?;
            let id =
                map_get_str(inner, "id").ok_or_else(|| Error::Decode("user.id missing".into()))?;
            let id_bytes = want_bytes(id, "user.id")?;
            let name = match map_get_str(inner, "name") {
                Some(v) => Some(want_text(v, "user.name")?),
                None => None,
            };
            let display_name = match map_get_str(inner, "displayName") {
                Some(v) => Some(want_text(v, "user.displayName")?),
                None => None,
            };
            Some(User {
                id: id_bytes,
                name,
                display_name,
            })
        }
        None => None,
    };
    let number_of_credentials = match map_get_int(map, 0x05) {
        Some(v) => Some(want_uint(v, "numberOfCredentials")?),
        None => None,
    };
    let user_selected = match map_get_int(map, 0x06) {
        Some(v) => Some(want_bool(v, "userSelected")?),
        None => None,
    };
    let large_blob_key = match map_get_int(map, 0x07) {
        Some(v) => Some(want_bytes(v, "largeBlobKey")?),
        None => None,
    };

    Ok(GetAssertionResponse {
        credential,
        auth_data,
        signature,
        user,
        number_of_credentials,
        user_selected,
        large_blob_key,
    })
}
