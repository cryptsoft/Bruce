// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorConfig` (CTAP 2.1 sec. 6.11) -- device-wide policy
//! toggles.
//!
//! Four subcommands per sec. 6.11.1 Table 22:
//!
//!   0x01 enableEnterpriseAttestation
//!   0x02 toggleAlwaysUv
//!   0x03 setMinPINLength
//!   0xFF vendorPrototype  (not exposed by this crate -- by design)
//!
//! All three exposed subcommands require a `pinUvAuthToken` with
//! the `authenticatorConfiguration` permission bit (0x20) set.
//! Caller mints one via
//! [`super::client_pin::get_pin_uv_auth_token_using_pin`] with
//! [`super::client_pin::permission::AUTHENTICATOR_CONFIGURATION`].
//!
//! Per CTAP 2.1 sec. 6.11, the `pinUvAuthParam` is HMAC'd over a
//! protocol-version-specific input: `pinUvAuthToken` keyed HMAC of
//! `32x0xFF || 0x0d || subCmd || subCmdParams_cbor`. The 32 0xFF
//! prefix is the "context separator" defined in sec. 6.5.5.7.

use pqf_cbor::Value;

use crate::hid::Device;

use super::client_pin::PinUvAuth;
use super::pin_protocol::Protocol;
use super::{cbor_call, Error, CMD_CONFIG};

// ---------- Subcommand IDs ----------

const SUB_ENABLE_ENTERPRISE_ATTESTATION: u8 = 0x01;
const SUB_TOGGLE_ALWAYS_UV: u8 = 0x02;
const SUB_SET_MIN_PIN_LENGTH: u8 = 0x03;

// ---------- Public API ----------

/// 0x01 `enableEnterpriseAttestation`. Once enabled, MakeCredential
/// requests carrying `enterpriseAttestation = 1` or `2` will get
/// enterprise-style attestation back (vendor-or-platform-managed).
/// Stays on across reboots once set.
pub fn enable_enterprise_attestation(dev: &Device, auth: &PinUvAuth) -> Result<(), Error> {
    submit(dev, auth, SUB_ENABLE_ENTERPRISE_ATTESTATION, None)
}

/// 0x02 `toggleAlwaysUv`. Flips the `alwaysUv` option exposed in
/// `getInfo`. When set, every MakeCredential / GetAssertion requires
/// PIN/UV regardless of the request's `options.uv`. Persistent.
pub fn toggle_always_uv(dev: &Device, auth: &PinUvAuth) -> Result<(), Error> {
    submit(dev, auth, SUB_TOGGLE_ALWAYS_UV, None)
}

/// 0x03 `setMinPINLength` parameter map per CTAP 2.1 sec. 6.11.4.
#[derive(Clone, Debug, Default)]
pub struct SetMinPinLengthParams {
    /// `newMinPINLength` -- the new minimum PIN length in bytes.
    /// 0 means "keep the current value"; the host can use this to
    /// update only `minPinLengthRPIDs` or `forceChangePin` without
    /// touching the length itself.
    pub new_min_pin_length: Option<u8>,
    /// `minPinLengthRPIDs` -- RP-id allowlist for the `minPinLength`
    /// MakeCred extension. Devices that see a MakeCredential with
    /// the `minPinLength` extension input AND an RP id matching
    /// this allowlist will include the configured minimum in the
    /// attested authData extensions output.
    pub min_pin_length_rp_ids: Option<Vec<String>>,
    /// `forceChangePin` -- request the user rotate their PIN on the
    /// next ClientPin operation.
    pub force_change_pin: Option<bool>,
}

/// 0x03 `setMinPINLength`. Updates one or more of the three params
/// (length, RP-id allowlist, force-change flag).
pub fn set_min_pin_length(
    dev: &Device,
    auth: &PinUvAuth,
    params: &SetMinPinLengthParams,
) -> Result<(), Error> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(3);
    if let Some(n) = params.new_min_pin_length {
        entries.push((Value::Uint(0x01), Value::Uint(n as u64)));
    }
    if let Some(ref rpids) = params.min_pin_length_rp_ids {
        let arr: Vec<Value> = rpids.iter().map(|s| Value::Text(s.clone())).collect();
        entries.push((Value::Uint(0x02), Value::Array(arr)));
    }
    if let Some(b) = params.force_change_pin {
        entries.push((Value::Uint(0x03), Value::Bool(b)));
    }
    let sub_params = if entries.is_empty() {
        None
    } else {
        Some(Value::Map(entries))
    };
    submit(dev, auth, SUB_SET_MIN_PIN_LENGTH, sub_params.as_ref())
}

// ---------- Shared submit path ----------

/// All authenticatorConfig subcommands share a common wrapper
/// shape -- `subCommand`, optional `subCommandParams`,
/// `pinUvAuthProtocol`, and `pinUvAuthParam` computed over the
/// CTAP 2.1 sec. 6.5.5.7 context-prefix `32 x 0xFF || cmd || subCmd ||
/// subCmdParams_cbor`.
fn submit(
    dev: &Device,
    auth: &PinUvAuth,
    sub_cmd: u8,
    sub_params: Option<&Value>,
) -> Result<(), Error> {
    // Encode the optional subCommandParams once -- we'll feed the
    // encoded bytes into both the request map and the HMAC input
    // verbatim, to match the device's own canonical-CBOR view of
    // the parameters.
    let sub_params_cbor: Option<Vec<u8>> = sub_params.map(|p| {
        let mut buf = Vec::new();
        pqf_cbor::encode(p, &mut buf);
        buf
    });

    // pinUvAuthParam input (sec. 6.11):
    //   32 x 0xFF || 0x0d (config cmd byte) || subCmd || subCmdParams_cbor
    let mut auth_input = Vec::with_capacity(34 + sub_params_cbor.as_ref().map_or(0, |v| v.len()));
    auth_input.extend_from_slice(&[0xff; 32]);
    auth_input.push(CMD_CONFIG);
    auth_input.push(sub_cmd);
    if let Some(ref bytes) = sub_params_cbor {
        auth_input.extend_from_slice(bytes);
    }
    let pin_uv_auth_param = auth.sign(&auth_input)?;

    // Build the request map.
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
    let _ = Protocol::V2; // keep the import alive even if Protocol::*::as_byte() trail differs.

    let _ = cbor_call(dev, CMD_CONFIG, Some(&Value::Map(req)))?;
    Ok(())
}
