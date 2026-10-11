// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorMakeCredential` (CTAP 2.1 sec. 6.1) -- register a new
//! credential against an RP.
//!
//! Request layout (CTAP 2.1 sec. 6.1.1 Table 4):
//!
//!   0x01 clientDataHash         (32 bytes)
//!   0x02 rp                     (PublicKeyCredentialRpEntity)
//!   0x03 user                   (PublicKeyCredentialUserEntity)
//!   0x04 pubKeyCredParams       (array of PubKeyCredParam)
//!   0x05 excludeList            (optional array of CredentialDescriptor)
//!   0x06 extensions             (optional map; we leave as raw Value)
//!   0x07 options                (optional AuthOptions map)
//!   0x08 pinUvAuthParam         (optional bytes, PIN protocol)
//!   0x09 pinUvAuthProtocol      (optional uint, PIN protocol id)
//!   0x0a enterpriseAttestation  (optional uint, 1 or 2)
//!
//! Response layout (CTAP 2.1 sec. 6.1.5):
//!
//!   0x01 fmt           (text; "packed", "fido-u2f", "none", ...)
//!   0x02 authData      (bytes; the auth-data structure incl. attested cred data)
//!   0x03 attStmt       (map; format-specific attestation statement)
//!   0x04 epAtt         (optional bool; enterprise-attestation indicator)
//!   0x05 largeBlobKey  (optional bytes)

use crate::hid::Device;
use pqf_cbor::Value;

use super::types::{AuthOptions, CredentialDescriptor, PubKeyCredParam, RelyingParty, User};
use super::{cbor_call, map_get_int, want_bytes, want_map, want_text, Error, CMD_MAKE_CREDENTIAL};

/// `authenticatorMakeCredential` request parameters.
#[derive(Clone, Debug)]
pub struct MakeCredentialRequest {
    /// 0x01 `clientDataHash` -- SHA-256 of the client data JSON the
    /// browser would have built. The RP server later checks this
    /// hash matches what it expects.
    pub client_data_hash: [u8; 32],
    /// 0x02 `rp` -- the relying party making the request.
    pub rp: RelyingParty,
    /// 0x03 `user` -- the user account being registered.
    pub user: User,
    /// 0x04 `pubKeyCredParams` -- acceptable credential algorithms,
    /// in RP-preference order.
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    /// 0x05 `excludeList` -- credentials that, if already present on
    /// the device, must cause this MakeCredential to fail. RP uses
    /// it to avoid double-registering the same authenticator.
    pub exclude_list: Option<Vec<CredentialDescriptor>>,
    /// 0x06 `extensions` -- CTAP2 extensions map. Left as a raw
    /// `Value` for forwards-compat; callers wanting strongly-typed
    /// extension support can build the map by hand.
    pub extensions: Option<Value>,
    /// 0x07 `options` -- `rk` / `up` / `uv`.
    pub options: Option<AuthOptions>,
    /// 0x08 `pinUvAuthParam` -- HMAC-SHA-256(pinUvAuthToken, clientDataHash),
    /// truncated per protocol version. Required when a PIN is set
    /// and `uv != true`. PIN protocol module wires this up in a
    /// later commit.
    pub pin_uv_auth_param: Option<Vec<u8>>,
    /// 0x09 `pinUvAuthProtocol` -- 1 or 2.
    pub pin_uv_auth_protocol: Option<u64>,
    /// 0x0a `enterpriseAttestation` -- 1 = vendor-facilitated, 2 = platform-managed.
    pub enterprise_attestation: Option<u64>,
}

/// `authenticatorMakeCredential` response.
#[derive(Clone, Debug)]
pub struct MakeCredentialResponse {
    /// 0x01 `fmt` -- attestation statement format (WebAuthn sec. 6.5.2).
    /// For the `bruce` firmware this is `"packed"` for a CTAP2
    /// `authenticatorMakeCredential`, and `"fido-u2f"` for the
    /// legacy U2F registration path a client falls back to when it
    /// does not drive the CTAP2 command directly.
    pub fmt: String,
    /// 0x02 `authData` -- raw bytes per WebAuthn sec. 6.1. Contains
    /// the rpIdHash, flags, sign counter, AAGUID, credentialID,
    /// and COSE_Key. The session-level helpers parse this further;
    /// at this layer we hand back the bytes verbatim.
    pub auth_data: Vec<u8>,
    /// 0x03 `attStmt` -- format-specific. For `"packed"`:
    /// `{ "alg": i64, "sig": bytes, "x5c": [bytes]? }`. Left as a
    /// CBOR `Value` because the inner shape depends on `fmt`.
    pub att_stmt: Value,
    /// 0x04 `epAtt` -- `true` if the device used an enterprise
    /// attestation cert (vs the default batch attestation).
    pub ep_att: Option<bool>,
    /// 0x05 `largeBlobKey` -- 32-byte key, returned when the RP
    /// included the `largeBlobKey` extension input.
    pub large_blob_key: Option<Vec<u8>>,
}

impl MakeCredentialRequest {
    /// Encode this request to the CTAP 2.1 sec. 6.1.1 CBOR map that
    /// [`make_credential`] puts on the wire. Public so callers can
    /// inspect or size the exact request bytes without sending
    /// them -- the offline half of `examples/bench.rs` checks its
    /// request shapes this way.
    pub fn to_cbor(&self) -> Value {
        // Build the entries in field-id order. `pqf-cbor`
        // canonicalises on encode so the wire bytes come out in
        // the spec-mandated canonical-CBOR order regardless of
        // what we push here.
        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(10);
        entries.push((
            Value::Uint(0x01),
            Value::Bytes(self.client_data_hash.to_vec()),
        ));
        entries.push((Value::Uint(0x02), self.rp.to_cbor()));
        entries.push((Value::Uint(0x03), self.user.to_cbor()));
        let cred_params: Vec<Value> = self
            .pub_key_cred_params
            .iter()
            .map(|p| p.to_cbor())
            .collect();
        entries.push((Value::Uint(0x04), Value::Array(cred_params)));
        if let Some(ref excl) = self.exclude_list {
            let arr: Vec<Value> = excl.iter().map(|d| d.to_cbor()).collect();
            entries.push((Value::Uint(0x05), Value::Array(arr)));
        }
        if let Some(ref ext) = self.extensions {
            entries.push((Value::Uint(0x06), ext.clone()));
        }
        if let Some(ref opts) = self.options {
            if !opts.is_empty() {
                entries.push((Value::Uint(0x07), opts.to_cbor()));
            }
        }
        if let Some(ref pup) = self.pin_uv_auth_param {
            entries.push((Value::Uint(0x08), Value::Bytes(pup.clone())));
        }
        if let Some(proto) = self.pin_uv_auth_protocol {
            entries.push((Value::Uint(0x09), Value::Uint(proto)));
        }
        if let Some(ep) = self.enterprise_attestation {
            entries.push((Value::Uint(0x0a), Value::Uint(ep)));
        }
        Value::Map(entries)
    }
}

/// Send `authenticatorMakeCredential` (command 0x01) and parse the
/// response.
pub fn make_credential(
    dev: &Device,
    req: &MakeCredentialRequest,
) -> Result<MakeCredentialResponse, Error> {
    let payload = req.to_cbor();
    let resp = cbor_call(dev, CMD_MAKE_CREDENTIAL, Some(&payload))?
        .ok_or_else(|| Error::Decode("MakeCredential returned empty payload".into()))?;
    let map = want_map(&resp, "(top-level)")?;

    let fmt = {
        let v = map_get_int(map, 0x01)
            .ok_or_else(|| Error::Decode("missing required field 0x01 (fmt)".into()))?;
        want_text(v, "fmt")?
    };
    let auth_data = {
        let v = map_get_int(map, 0x02)
            .ok_or_else(|| Error::Decode("missing required field 0x02 (authData)".into()))?;
        want_bytes(v, "authData")?
    };
    let att_stmt = map_get_int(map, 0x03)
        .ok_or_else(|| Error::Decode("missing required field 0x03 (attStmt)".into()))?
        .clone();
    let ep_att = match map_get_int(map, 0x04) {
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err(Error::Decode("field 0x04 (epAtt) not a bool".into())),
        None => None,
    };
    let large_blob_key = match map_get_int(map, 0x05) {
        Some(v) => Some(want_bytes(v, "largeBlobKey")?),
        None => None,
    };

    Ok(MakeCredentialResponse {
        fmt,
        auth_data,
        att_stmt,
        ep_att,
        large_blob_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::types::{ALG_ES256, ALG_HYBRID_MLDSA65};

    #[test]
    fn request_round_trip_minimum() {
        // Build a minimum-viable request, encode it via `to_cbor`,
        // pull it back through `pqf_cbor::decode`, and verify the
        // shape and the required field count.
        let req = MakeCredentialRequest {
            client_data_hash: [0x42; 32],
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: None,
            },
            user: User {
                id: vec![1, 2, 3],
                name: None,
                display_name: None,
            },
            pub_key_cred_params: vec![
                PubKeyCredParam::new(ALG_HYBRID_MLDSA65),
                PubKeyCredParam::new(ALG_ES256),
            ],
            exclude_list: None,
            extensions: None,
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
            enterprise_attestation: None,
        };
        let mut buf = Vec::new();
        pqf_cbor::encode(&req.to_cbor(), &mut buf);
        let decoded = pqf_cbor::decode(&buf).expect("decode");
        let map = match decoded {
            Value::Map(m) => m,
            _ => panic!("top-level was not a map"),
        };
        // Should have exactly four entries: clientDataHash, rp,
        // user, pubKeyCredParams. Optional fields all absent.
        assert_eq!(map.len(), 4);
        // Verify clientDataHash bytes survive the round-trip.
        let cdh = map_get_int(&map, 0x01).expect("clientDataHash");
        match cdh {
            Value::Bytes(b) => assert_eq!(b.len(), 32),
            _ => panic!("clientDataHash not bytes"),
        }
        // pubKeyCredParams should preserve insertion order -- that
        // matters because the authenticator's picker uses the
        // RP-supplied order for Pass 1 PQC preference.
        let params = map_get_int(&map, 0x04).expect("pubKeyCredParams");
        let arr = match params {
            Value::Array(a) => a,
            _ => panic!("not array"),
        };
        assert_eq!(arr.len(), 2);
    }
}
