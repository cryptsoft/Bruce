// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorGetInfo` (CTAP 2.1 sec. 6.4) -- query the authenticator's
//! supported features, advertised algorithms, AAGUID, PIN state,
//! and storage limits.
//!
//! Takes no request parameters. The response is a 15-field CBOR map.

use crate::hid::Device;
use pqf_cbor::Value;

use super::{
    cbor_call, map_get_int, want_array, want_bool, want_bytes, want_int, want_map, want_text,
    want_uint, Error, CMD_GET_INFO,
};

/// One entry in `pubKeyCredParams` / `algorithms` -- `(alg, type)`.
#[derive(Clone, Debug)]
pub struct AlgorithmEntry {
    /// COSE algorithm identifier (e.g. -7 for ES256, -55 for
    /// ML-DSA-65 hybrid).
    pub alg: i64,
    /// Credential type. Always `"public-key"` per CTAP 2.1 sec. 6.4
    /// -- preserved here for completeness.
    pub credential_type: String,
}

/// Result of [`get_info`] / [`Device::get_info`].
///
/// Field numbers correspond to CTAP 2.1 sec. 6.4 Table 7 (the keys in
/// the authenticator's response map):
///
/// - 0x01 `versions`              -- list of supported FIDO versions.
/// - 0x02 `extensions`            -- list of supported extensions.
/// - 0x03 `aaguid`                -- 16-byte AAGUID.
/// - 0x04 `options`               -- map of option-name -> bool.
/// - 0x05 `maxMsgSize`            -- max CBOR request size in bytes.
/// - 0x06 `pinUvAuthProtocols`    -- supported PIN/UV protocols.
/// - 0x07 `maxCredentialCountInList` -- allowList / excludeList cap.
/// - 0x08 `maxCredentialIdLength` -- longest credentialID the device emits.
/// - 0x09 `transports`            -- `["usb"]` for this device.
/// - 0x0a `algorithms`            -- algs the device can sign with.
/// - 0x0b `maxSerializedLargeBlobArray`
/// - 0x0c `forcePINChange`
/// - 0x0d `minPINLength`
/// - 0x0e `firmwareVersion`
/// - 0x0f `maxCredBlobLength`
///
/// CTAP 2.1 defines additional fields (0x10..0x15) for biometric
/// enrollment and uvModality; this authenticator doesn't implement
/// biometrics so we don't expose those fields here.
#[derive(Clone, Debug)]
pub struct GetInfo {
    /// `versions` -- e.g. `["FIDO_2_0", "FIDO_2_1"]`.
    pub versions: Vec<String>,
    /// `extensions` -- extension identifiers the device understands.
    pub extensions: Vec<String>,
    /// 16-byte AAGUID. Spec mandates non-zero on a CTAP2.x device.
    pub aaguid: [u8; 16],
    /// `options` -- option-name -> bool. Common keys: `plat`, `rk`,
    /// `up`, `uv`, `clientPin`, `pinUvAuthToken`, `noMcGaPermissionsWithClientPin`,
    /// `largeBlobs`, `ep`, `bioEnroll`, `userVerificationMgmtPreview`,
    /// `uvBioEnroll`, `authnrCfg`, `uvAcfg`, `credMgmt`, `credentialMgmtPreview`,
    /// `setMinPINLength`, `makeCredUvNotRqd`, `alwaysUv`.
    pub options: Vec<(String, bool)>,
    /// `maxMsgSize` -- biggest CBOR request payload the device accepts.
    pub max_msg_size: Option<u64>,
    /// `pinUvAuthProtocols` -- `[1]`, `[2]`, or `[1, 2]`.
    pub pin_uv_auth_protocols: Option<Vec<u64>>,
    /// `maxCredentialCountInList`.
    pub max_credential_count_in_list: Option<u64>,
    /// `maxCredentialIdLength`.
    pub max_credential_id_length: Option<u64>,
    /// `transports` -- typically `["usb"]`.
    pub transports: Option<Vec<String>>,
    /// `algorithms` -- algorithms the device will sign with on
    /// MakeCredential. Includes both alg id (negative i64) and the
    /// credential type string.
    pub algorithms: Option<Vec<AlgorithmEntry>>,
    /// `maxSerializedLargeBlobArray`.
    pub max_serialized_large_blob_array: Option<u64>,
    /// `forcePINChange` -- `true` when the device wants the client
    /// to rotate the PIN before further use.
    pub force_pin_change: Option<bool>,
    /// `minPINLength` -- minimum acceptable PIN length, in bytes.
    pub min_pin_length: Option<u64>,
    /// `firmwareVersion` -- 32-bit firmware version.
    pub firmware_version: Option<u64>,
    /// `maxCredBlobLength` -- maximum `credBlob` extension bytes
    /// the device will store per credential.
    pub max_cred_blob_length: Option<u64>,
}

/// Send `authenticatorGetInfo` (command byte 0x04) and parse the
/// response. See [`GetInfo`] for the resulting field set.
pub fn get_info(dev: &Device) -> Result<GetInfo, Error> {
    let resp = cbor_call(dev, CMD_GET_INFO, None)?
        .ok_or_else(|| Error::Decode("authenticatorGetInfo returned empty payload".into()))?;
    let map = want_map(&resp, "(top-level)")?;

    // 0x01 versions -- required.
    let versions = {
        let v = map_get_int(map, 0x01)
            .ok_or_else(|| Error::Decode("missing required field 0x01 (versions)".into()))?;
        let arr = want_array(v, "versions")?;
        let mut out = Vec::with_capacity(arr.len());
        for (i, entry) in arr.iter().enumerate() {
            out.push(want_text(entry, &format!("versions[{i}]"))?);
        }
        out
    };

    // 0x02 extensions -- optional, but every authenticator we care
    // about emits it. Default to empty if absent.
    let extensions = match map_get_int(map, 0x02) {
        Some(v) => {
            let arr = want_array(v, "extensions")?;
            arr.iter()
                .enumerate()
                .map(|(i, e)| want_text(e, &format!("extensions[{i}]")))
                .collect::<Result<Vec<_>, _>>()?
        }
        None => Vec::new(),
    };

    // 0x03 aaguid -- required, exactly 16 bytes.
    let aaguid = {
        let v = map_get_int(map, 0x03)
            .ok_or_else(|| Error::Decode("missing required field 0x03 (aaguid)".into()))?;
        let bytes = want_bytes(v, "aaguid")?;
        if bytes.len() != 16 {
            return Err(Error::Decode(format!(
                "aaguid was {} bytes, expected 16",
                bytes.len()
            )));
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&bytes);
        a
    };

    // 0x04 options -- map of (text, bool). Optional.
    let options = match map_get_int(map, 0x04) {
        Some(v) => {
            let inner = want_map(v, "options")?;
            let mut out = Vec::with_capacity(inner.len());
            for (k, val) in inner {
                let key = want_text(k, "options.key")?;
                let b = want_bool(val, &format!("options.{key}"))?;
                out.push((key, b));
            }
            out
        }
        None => Vec::new(),
    };

    // 0x05..0x0f -- all optional, all scalars or arrays.
    let max_msg_size = match map_get_int(map, 0x05) {
        Some(v) => Some(want_uint(v, "maxMsgSize")?),
        None => None,
    };

    let pin_uv_auth_protocols = match map_get_int(map, 0x06) {
        Some(v) => {
            let arr = want_array(v, "pinUvAuthProtocols")?;
            let mut out = Vec::with_capacity(arr.len());
            for (i, e) in arr.iter().enumerate() {
                out.push(want_uint(e, &format!("pinUvAuthProtocols[{i}]"))?);
            }
            Some(out)
        }
        None => None,
    };

    let max_credential_count_in_list = match map_get_int(map, 0x07) {
        Some(v) => Some(want_uint(v, "maxCredentialCountInList")?),
        None => None,
    };

    let max_credential_id_length = match map_get_int(map, 0x08) {
        Some(v) => Some(want_uint(v, "maxCredentialIdLength")?),
        None => None,
    };

    let transports = match map_get_int(map, 0x09) {
        Some(v) => {
            let arr = want_array(v, "transports")?;
            let mut out = Vec::with_capacity(arr.len());
            for (i, e) in arr.iter().enumerate() {
                out.push(want_text(e, &format!("transports[{i}]"))?);
            }
            Some(out)
        }
        None => None,
    };

    let algorithms = match map_get_int(map, 0x0a) {
        Some(v) => {
            let arr = want_array(v, "algorithms")?;
            let mut out = Vec::with_capacity(arr.len());
            for (i, e) in arr.iter().enumerate() {
                let inner = want_map(e, &format!("algorithms[{i}]"))?;
                let alg = inner
                    .iter()
                    .find_map(|(k, val)| match k {
                        Value::Text(s) if s == "alg" => Some(val),
                        _ => None,
                    })
                    .ok_or_else(|| Error::Decode(format!("algorithms[{i}] missing `alg`")))?;
                let ty = inner
                    .iter()
                    .find_map(|(k, val)| match k {
                        Value::Text(s) if s == "type" => Some(val),
                        _ => None,
                    })
                    .ok_or_else(|| Error::Decode(format!("algorithms[{i}] missing `type`")))?;
                out.push(AlgorithmEntry {
                    alg: want_int(alg, &format!("algorithms[{i}].alg"))?,
                    credential_type: want_text(ty, &format!("algorithms[{i}].type"))?,
                });
            }
            Some(out)
        }
        None => None,
    };

    let max_serialized_large_blob_array = match map_get_int(map, 0x0b) {
        Some(v) => Some(want_uint(v, "maxSerializedLargeBlobArray")?),
        None => None,
    };

    let force_pin_change = match map_get_int(map, 0x0c) {
        Some(v) => Some(want_bool(v, "forcePINChange")?),
        None => None,
    };

    let min_pin_length = match map_get_int(map, 0x0d) {
        Some(v) => Some(want_uint(v, "minPINLength")?),
        None => None,
    };

    let firmware_version = match map_get_int(map, 0x0e) {
        Some(v) => Some(want_uint(v, "firmwareVersion")?),
        None => None,
    };

    let max_cred_blob_length = match map_get_int(map, 0x0f) {
        Some(v) => Some(want_uint(v, "maxCredBlobLength")?),
        None => None,
    };

    Ok(GetInfo {
        versions,
        extensions,
        aaguid,
        options,
        max_msg_size,
        pin_uv_auth_protocols,
        max_credential_count_in_list,
        max_credential_id_length,
        transports,
        algorithms,
        max_serialized_large_blob_array,
        force_pin_change,
        min_pin_length,
        firmware_version,
        max_cred_blob_length,
    })
}

impl GetInfo {
    /// Look up an option by name, returning its bool value if the
    /// device sets it. Common keys are documented on [`GetInfo::options`].
    pub fn option(&self, name: &str) -> Option<bool> {
        self.options
            .iter()
            .find_map(|(k, v)| if k == name { Some(*v) } else { None })
    }

    /// Returns true if the device advertises CTAP 2.1 in its versions list.
    pub fn is_ctap21(&self) -> bool {
        self.versions.iter().any(|v| v == "FIDO_2_1")
    }

    /// Returns true if a PIN is currently set on the device. Per
    /// CTAP 2.1 sec. 6.4, the `clientPin` option is `false` when the
    /// device supports PIN but none is set, `true` when one is set,
    /// and absent when the device doesn't support PIN at all.
    pub fn pin_set(&self) -> bool {
        self.option("clientPin").unwrap_or(false)
    }
}
