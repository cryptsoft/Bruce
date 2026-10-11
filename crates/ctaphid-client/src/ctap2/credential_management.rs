// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorCredentialManagement` (CTAP 2.1 sec. 6.8) -- list,
//! enumerate, delete, and update resident credentials.
//!
//! Seven subcommands per sec. 6.8.2 Table 14:
//!
//!   0x01 getCredsMetadata
//!   0x02 enumerateRPsBegin
//!   0x03 enumerateRPsGetNextRP
//!   0x04 enumerateCredentialsBegin
//!   0x05 enumerateCredentialsGetNextCredential
//!   0x06 deleteCredential
//!   0x07 updateUserInformation
//!
//! All seven require a `pinUvAuthToken` with the
//! [`super::client_pin::permission::CREDENTIAL_MANAGEMENT`] bit set.
//!
//! The pinUvAuthParam input is `32 x 0xFF || 0x0a (cmd) ||
//! subCmd_byte || subCmdParams_cbor` per sec. 6.8.2 -- subcommands that
//! take no params (metadata, enumerate-*-begin) sign just the
//! prefix + subcommand byte; subcommands that DO take params sign
//! prefix + subcommand + canonical-CBOR of the subCommandParams
//! map.

use pqf_cbor::Value;

use crate::hid::Device;

use super::client_pin::PinUvAuth;
use super::types::{CredentialDescriptor, RelyingParty, User};
use super::{
    cbor_call, map_get_int, want_bytes, want_int, want_map, want_text, want_uint, Error,
    CMD_CREDENTIAL_MANAGEMENT,
};

// ---------- Subcommand IDs ----------

const SUB_GET_CREDS_METADATA: u8 = 0x01;
const SUB_ENUMERATE_RPS_BEGIN: u8 = 0x02;
const SUB_ENUMERATE_RPS_GET_NEXT: u8 = 0x03;
const SUB_ENUMERATE_CREDS_BEGIN: u8 = 0x04;
const SUB_ENUMERATE_CREDS_GET_NEXT: u8 = 0x05;
const SUB_DELETE_CREDENTIAL: u8 = 0x06;
const SUB_UPDATE_USER_INFO: u8 = 0x07;

// ---------- 0x01 getCredsMetadata ----------

/// Response shape of `getCredsMetadata`.
#[derive(Clone, Debug)]
pub struct CredsMetadata {
    /// 0x01 `existingResidentCredentialsCount` -- how many resident
    /// credentials are currently stored.
    pub existing_resident_credentials_count: u64,
    /// 0x02 `maxPossibleRemainingResidentCredentialsCount` -- upper
    /// bound on additional credentials that could fit in the
    /// remaining storage.
    pub max_possible_remaining: u64,
}

/// 0x01 -- count resident credentials + remaining storage budget.
pub fn get_creds_metadata(dev: &Device, auth: &PinUvAuth) -> Result<CredsMetadata, Error> {
    let resp = submit(dev, auth, SUB_GET_CREDS_METADATA, None)?
        .ok_or_else(|| Error::Decode("getCredsMetadata: empty response".into()))?;
    let map = want_map(&resp, "(top-level)")?;
    Ok(CredsMetadata {
        existing_resident_credentials_count: map_get_int(map, 0x01)
            .map(|v| want_uint(v, "existingResidentCredentialsCount"))
            .transpose()?
            .unwrap_or(0),
        max_possible_remaining: map_get_int(map, 0x02)
            .map(|v| want_uint(v, "maxPossibleRemainingResidentCredentialsCount"))
            .transpose()?
            .unwrap_or(0),
    })
}

// ---------- 0x02 / 0x03 enumerateRPs ----------

/// One entry in the device's "RPs with at least one resident
/// credential" iterator.
#[derive(Clone, Debug)]
pub struct RpEntry {
    /// `rp` -- the relying-party entity (id + optional name).
    pub rp: RelyingParty,
    /// `rpIDHash` -- SHA-256 of the RP id, 32 bytes.
    pub rp_id_hash: Vec<u8>,
    /// `totalRPs` -- only set on the first response (subcommand
    /// 0x02). Tells the caller how many getNextRP calls to expect.
    pub total_rps: Option<u64>,
}

/// 0x02 -- start the RPs iterator. Returns the first RP plus the
/// total count; subsequent entries come from [`enumerate_rps_next`].
pub fn enumerate_rps_begin(dev: &Device, auth: &PinUvAuth) -> Result<RpEntry, Error> {
    let resp = submit(dev, auth, SUB_ENUMERATE_RPS_BEGIN, None)?
        .ok_or_else(|| Error::Decode("enumerateRPsBegin: empty response".into()))?;
    parse_rp_entry(&resp, true)
}

/// 0x03 -- get the next RP in the iterator. Caller drives this
/// based on the `total_rps` from `enumerate_rps_begin`.
pub fn enumerate_rps_next(dev: &Device) -> Result<RpEntry, Error> {
    let resp = cbor_call(
        dev,
        CMD_CREDENTIAL_MANAGEMENT,
        Some(&Value::Map(vec![(
            Value::Uint(0x01),
            Value::Uint(SUB_ENUMERATE_RPS_GET_NEXT as u64),
        )])),
    )?
    .ok_or_else(|| Error::Decode("enumerateRPsGetNextRP: empty response".into()))?;
    parse_rp_entry(&resp, false)
}

fn parse_rp_entry(resp: &Value, with_total: bool) -> Result<RpEntry, Error> {
    let map = want_map(resp, "(top-level)")?;
    let rp_value =
        map_get_int(map, 0x03).ok_or_else(|| Error::Decode("RP entry missing 0x03 (rp)".into()))?;
    let rp_map = want_map(rp_value, "rp")?;
    let id = rp_map
        .iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == "id" => Some(v),
            _ => None,
        })
        .ok_or_else(|| Error::Decode("rp.id missing".into()))?;
    let id_str = want_text(id, "rp.id")?;
    let name = rp_map
        .iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == "name" => Some(v),
            _ => None,
        })
        .map(|v| want_text(v, "rp.name"))
        .transpose()?;
    let rp_id_hash = map_get_int(map, 0x04)
        .ok_or_else(|| Error::Decode("RP entry missing 0x04 (rpIDHash)".into()))?;
    let rp_id_hash = want_bytes(rp_id_hash, "rpIDHash")?;
    let total_rps = if with_total {
        match map_get_int(map, 0x05) {
            Some(v) => Some(want_uint(v, "totalRPs")?),
            None => None,
        }
    } else {
        None
    };
    Ok(RpEntry {
        rp: RelyingParty { id: id_str, name },
        rp_id_hash,
        total_rps,
    })
}

// ---------- 0x04 / 0x05 enumerateCredentials ----------

/// One entry in the per-RP credential iterator.
#[derive(Clone, Debug)]
pub struct CredentialEntry {
    /// 0x06 `user` -- the user entity stored with this credential.
    pub user: User,
    /// 0x07 `credentialID` -- the descriptor (always type=public-key).
    pub credential: CredentialDescriptor,
    /// 0x08 `publicKey` -- raw COSE_Key bytes. Caller decodes
    /// further depending on the COSE alg id contained therein.
    pub public_key_cose: Value,
    /// 0x09 `totalCredentials` -- only set on the first response
    /// (subcommand 0x04).
    pub total_credentials: Option<u64>,
    /// 0x0a `credProtect` -- credential-protect policy:
    /// 1 = userVerificationOptional (default), 2 = userVerificationOptionalWithCredentialIDList,
    /// 3 = userVerificationRequired.
    pub cred_protect: Option<u64>,
    /// 0x0b `largeBlobKey` -- 32-byte key, when the credential was
    /// created with the largeBlobKey extension.
    pub large_blob_key: Option<Vec<u8>>,
}

/// 0x04 -- start the credential iterator for a particular RP.
/// `rp_id_hash` comes from a prior [`enumerate_rps_begin`] /
/// [`enumerate_rps_next`] call.
pub fn enumerate_credentials_begin(
    dev: &Device,
    auth: &PinUvAuth,
    rp_id_hash: &[u8],
) -> Result<CredentialEntry, Error> {
    let sub_params = Value::Map(vec![(Value::Uint(0x01), Value::Bytes(rp_id_hash.to_vec()))]);
    let resp = submit(dev, auth, SUB_ENUMERATE_CREDS_BEGIN, Some(&sub_params))?
        .ok_or_else(|| Error::Decode("enumerateCredentialsBegin: empty response".into()))?;
    parse_credential_entry(&resp, true)
}

/// 0x05 -- get the next credential for the RP whose iterator was
/// started by `enumerate_credentials_begin`.
pub fn enumerate_credentials_next(dev: &Device) -> Result<CredentialEntry, Error> {
    let resp = cbor_call(
        dev,
        CMD_CREDENTIAL_MANAGEMENT,
        Some(&Value::Map(vec![(
            Value::Uint(0x01),
            Value::Uint(SUB_ENUMERATE_CREDS_GET_NEXT as u64),
        )])),
    )?
    .ok_or_else(|| Error::Decode("enumerateCredentialsGetNextCredential: empty response".into()))?;
    parse_credential_entry(&resp, false)
}

fn parse_credential_entry(resp: &Value, with_total: bool) -> Result<CredentialEntry, Error> {
    let map = want_map(resp, "(top-level)")?;

    let user_value = map_get_int(map, 0x06)
        .ok_or_else(|| Error::Decode("credential entry missing 0x06 (user)".into()))?;
    let user_map = want_map(user_value, "user")?;
    let user_id = user_map
        .iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == "id" => Some(v),
            _ => None,
        })
        .ok_or_else(|| Error::Decode("user.id missing".into()))?;
    let user_id = want_bytes(user_id, "user.id")?;
    let user_name = user_map
        .iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == "name" => Some(v),
            _ => None,
        })
        .map(|v| want_text(v, "user.name"))
        .transpose()?;
    let user_display_name = user_map
        .iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == "displayName" => Some(v),
            _ => None,
        })
        .map(|v| want_text(v, "user.displayName"))
        .transpose()?;

    let cred_value = map_get_int(map, 0x07)
        .ok_or_else(|| Error::Decode("credential entry missing 0x07 (credentialID)".into()))?;
    let cred_map = want_map(cred_value, "credentialID")?;
    let cred_id = cred_map
        .iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == "id" => Some(v),
            _ => None,
        })
        .ok_or_else(|| Error::Decode("credentialID.id missing".into()))?;
    let cred_id_bytes = want_bytes(cred_id, "credentialID.id")?;

    let public_key_cose = map_get_int(map, 0x08)
        .ok_or_else(|| Error::Decode("credential entry missing 0x08 (publicKey)".into()))?
        .clone();

    let total_credentials = if with_total {
        match map_get_int(map, 0x09) {
            Some(v) => Some(want_uint(v, "totalCredentials")?),
            None => None,
        }
    } else {
        None
    };

    let cred_protect = match map_get_int(map, 0x0a) {
        Some(v) => Some(want_int(v, "credProtect")? as u64),
        None => None,
    };

    let large_blob_key = match map_get_int(map, 0x0b) {
        Some(v) => Some(want_bytes(v, "largeBlobKey")?),
        None => None,
    };

    Ok(CredentialEntry {
        user: User {
            id: user_id,
            name: user_name,
            display_name: user_display_name,
        },
        credential: CredentialDescriptor {
            id: cred_id_bytes,
            transports: None,
        },
        public_key_cose,
        total_credentials,
        cred_protect,
        large_blob_key,
    })
}

// ---------- 0x06 deleteCredential ----------

/// 0x06 -- delete a resident credential by its credentialID.
pub fn delete_credential(
    dev: &Device,
    auth: &PinUvAuth,
    credential_id: &[u8],
) -> Result<(), Error> {
    let sub_params = Value::Map(vec![(
        Value::Uint(0x02),
        Value::Map(vec![
            (
                Value::Text("id".into()),
                Value::Bytes(credential_id.to_vec()),
            ),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ]),
    )]);
    let _ = submit(dev, auth, SUB_DELETE_CREDENTIAL, Some(&sub_params))?;
    Ok(())
}

// ---------- 0x07 updateUserInformation ----------

/// 0x07 -- mutate the user.{name, displayName} stored with a
/// resident credential. The `user.id` field is immutable;
/// `credential_id` selects the credential to update.
pub fn update_user_information(
    dev: &Device,
    auth: &PinUvAuth,
    credential_id: &[u8],
    user: &User,
) -> Result<(), Error> {
    let sub_params = Value::Map(vec![
        (
            Value::Uint(0x02),
            Value::Map(vec![
                (
                    Value::Text("id".into()),
                    Value::Bytes(credential_id.to_vec()),
                ),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ]),
        ),
        (Value::Uint(0x03), user.to_cbor()),
    ]);
    let _ = submit(dev, auth, SUB_UPDATE_USER_INFO, Some(&sub_params))?;
    Ok(())
}

// ---------- Shared submit path ----------

/// Common pinUvAuthParam + dispatch wrapper. The pinUvAuthParam
/// input per CTAP 2.1 sec. 6.8.2 is:
///
///   32 x 0xFF || 0x0a (cmd) || subCmd || subCmdParams_cbor?
///
/// For subcommands that take no parameters, the SHA / HMAC input
/// is just the 32 x 0xFF prefix + 0x0a + subCmd byte. For
/// subcommands with parameters, append the canonical-CBOR encoding
/// of the subCommandParams map.
fn submit(
    dev: &Device,
    auth: &PinUvAuth,
    sub_cmd: u8,
    sub_params: Option<&Value>,
) -> Result<Option<Value>, Error> {
    let sub_params_cbor: Option<Vec<u8>> = sub_params.map(|p| {
        let mut buf = Vec::new();
        pqf_cbor::encode(p, &mut buf);
        buf
    });

    let mut auth_input = Vec::with_capacity(34 + sub_params_cbor.as_ref().map_or(0, |v| v.len()));
    auth_input.extend_from_slice(&[0xff; 32]);
    auth_input.push(CMD_CREDENTIAL_MANAGEMENT);
    auth_input.push(sub_cmd);
    if let Some(ref bytes) = sub_params_cbor {
        auth_input.extend_from_slice(bytes);
    }
    let pin_uv_auth_param = auth.sign(&auth_input)?;

    let mut req: Vec<(Value, Value)> = Vec::with_capacity(5);
    req.push((Value::Uint(0x01), Value::Uint(sub_cmd as u64)));
    if let Some(p) = sub_params {
        req.push((Value::Uint(0x02), p.clone()));
    }
    req.push((
        Value::Uint(0x03),
        Value::Uint(auth.protocol.as_byte() as u64),
    ));
    req.push((Value::Uint(0x04), Value::Bytes(pin_uv_auth_param)));

    cbor_call(dev, CMD_CREDENTIAL_MANAGEMENT, Some(&Value::Map(req)))
}
