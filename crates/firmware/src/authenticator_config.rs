// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorConfig` (CTAP 2.1 sec. 6.11) -- device-wide policy
//! settings the host can toggle.
//!
//! Subcommands (CTAP 2.1 sec. 6.11.1, table 5-11):
//!
//! | Code | Name                            | Persistent? | Notes |
//! |------|---------------------------------|-------------|-------|
//! | 0x01 | `enableEnterpriseAttestation`   | yes (flag only) | accepted, but stays no-op since we don't ship a vendor cert chain |
//! | 0x02 | `toggleAlwaysUv`                | yes           | gates MakeCred / GetAssert behind PIN auth |
//! | 0x03 | `setMinPINLength`               | yes           | overrides the default 4-byte minimum + maintains an RP-id allowlist for the MakeCred `minPinLength` extension |
//! | 0xFF | `vendorPrototype`               | n/a         | rejected with `ERR_INVALID_SUBCOMMAND` |
//!
//! All subcommands require an active PIN token with the
//! `PERM_AUTHENTICATOR_CFG` (0x20) bit. The `pinUvAuthParam` is
//! verified over the byte sequence:
//!     `[0xFF; 32] || 0x0D || subcommand_byte || subcommand_params_cbor`
//! per sec. 6.11.2 step 3.

extern crate alloc;

use crate::bc_crypto::sha256;
use alloc::vec::Vec as AllocVec;
use pqf_cbor::Value;

use crate::client_pin::{self, PinSession, PERM_AUTHENTICATOR_CFG};
use crate::ctap2::{CredStore, CtapResponse, CTAP2_ERR_INVALID_CBOR, CTAP2_OK};

/// AC subcommand identifiers (CTAP 2.1 sec. 6.11.1).
const SUB_ENABLE_ENT_ATTESTATION: u64 = 0x01;
const SUB_TOGGLE_ALWAYS_UV: u64 = 0x02;
const SUB_SET_MIN_PIN_LENGTH: u64 = 0x03;
#[allow(dead_code)]
const SUB_VENDOR_PROTOTYPE: u64 = 0xFF;

/// Status codes used by this module.
/// CTAP 2.1 sec. 6.11.4: a newMinPINLength that lowers the minimum, or one
/// no PIN could ever satisfy, is a POLICY violation -- the same code C,
/// the TrustZone port and OpenSK answer. This port said INVALID_PARAM.
const ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
/// 0x3E. See the note in `client_pin.rs`; 0x16 is UNSUPPORTED_EXTENSION.
const ERR_INVALID_SUBCOMMAND: u8 = 0x3e;

/// Parsed AC request.
struct AcRequest {
    sub_command: u64,
    sub_command_params_cbor: AllocVec<u8>,
    /// Kept at full width: `as u8` truncated 260 to 4, which then passed
    /// the "may only raise" check as a no-op instead of being refused.
    new_min_pin_length: Option<u64>,
    /// minPinLengthRPIDs was PRESENT, even if empty. An empty array is how
    /// a relying party clears the list, and "present and empty" used to
    /// be indistinguishable from absent, so the list could never be
    /// cleared once set.
    min_pin_length_rpids_present: bool,
    /// Up to MAX_MIN_PIN_LEN_RPIDS UTF-8 RP ids; we hash each at
    /// parse time so the dispatch site never has to touch the
    /// allocator inside an interrupt-free section.
    min_pin_length_rpid_hashes: AllocVec<[u8; 32]>,
    force_change_pin: Option<bool>,
    pin_uv_auth_param: Option<AllocVec<u8>>,
    pin_uv_auth_protocol: Option<u64>,
}

fn parse_request(input: &[u8]) -> Option<AcRequest> {
    use pqf_cbor::Value as V;
    let value = pqf_cbor::decode(input).ok()?;
    let map = match value {
        V::Map(m) => m,
        _ => return None,
    };
    let mut sub_command: Option<u64> = None;
    let mut sub_params_value: Option<Value> = None;
    let mut pin_uv_auth_param = None;
    let mut pin_uv_auth_protocol = None;
    for (k, v) in &map {
        let key = match k {
            V::Uint(u) => *u as i64,
            V::Nint(n) => *n,
            _ => continue,
        };
        match (key, v) {
            (0x01, V::Uint(u)) => sub_command = Some(*u),
            (0x02, _) => sub_params_value = Some(v.clone()),
            // CTAP 2.1: protocol at 0x03 (uint), param at 0x04 (bytes).
            (0x03, V::Uint(u)) => pin_uv_auth_protocol = Some(*u),
            (0x04, V::Bytes(b)) => pin_uv_auth_param = Some(b.clone()),
            _ => {}
        }
    }
    let sub_command = sub_command?;

    let mut sub_command_params_cbor: AllocVec<u8> = AllocVec::new();
    if let Some(ref v) = sub_params_value {
        pqf_cbor::encode(v, &mut sub_command_params_cbor);
    }

    let mut new_min_pin_length: Option<u64> = None;
    let mut min_pin_length_rpid_hashes: AllocVec<[u8; 32]> = AllocVec::new();
    let mut min_pin_length_rpids_present = false;
    let mut force_change_pin: Option<bool> = None;

    if let Some(V::Map(params)) = &sub_params_value {
        for (k, v) in params {
            let key = match k {
                V::Uint(u) => *u as i64,
                V::Nint(n) => *n,
                _ => continue,
            };
            match (key, v) {
                // 0x01: newMinPINLength
                (0x01, V::Uint(u)) => new_min_pin_length = Some(*u),
                // 0x02: minPinLengthRPIDs (array of text strings).
                (0x02, V::Array(arr)) => {
                    min_pin_length_rpids_present = true;
                    for elem in arr {
                        if let V::Text(s) = elem {
                            let h: [u8; 32] = sha256(s.as_bytes());
                            min_pin_length_rpid_hashes.push(h);
                        }
                    }
                }
                // 0x03: forceChangePin (bool).
                (0x03, V::Bool(true)) => {
                    force_change_pin = Some(true);
                }
                (0x03, V::Bool(false)) => {
                    force_change_pin = Some(false);
                }
                _ => {}
            }
        }
    }

    Some(AcRequest {
        sub_command,
        sub_command_params_cbor,
        new_min_pin_length,
        min_pin_length_rpids_present,
        min_pin_length_rpid_hashes,
        force_change_pin,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
    })
}

/// Build the byte sequence the host signs for `pinUvAuthParam` on
/// CTAP2 AuthenticatorConfig (CTAP 2.1 sec. 6.11.2):
///     `[0xFF; 32] || 0x0D || subCommand_byte || subCommandParams_cbor`
fn pin_auth_message(sub_command: u8, sub_params_cbor: &[u8]) -> AllocVec<u8> {
    let mut buf = AllocVec::with_capacity(34 + sub_params_cbor.len());
    buf.extend_from_slice(&[0xFFu8; 32]);
    buf.push(0x0D);
    buf.push(sub_command);
    buf.extend_from_slice(sub_params_cbor);
    buf
}

/// Entry point -- called from `ctap2::handle_cbor` for command 0x0D.
pub fn handle(
    input: &[u8],
    session: &mut PinSession,
    store: &mut CredStore,
    out: &mut CtapResponse,
) {
    let req = match parse_request(input) {
        Some(r) => r,
        None => {
            out.push(CTAP2_ERR_INVALID_CBOR);
            return;
        }
    };

    // VendorPrototype gets short-shrift -- we don't define one.
    if req.sub_command == SUB_VENDOR_PROTOTYPE {
        out.push(ERR_INVALID_SUBCOMMAND);
        return;
    }

    // PIN-token authentication (CTAP 2.1 sec. 6.11.2 step 1).
    //
    // Special-case (step 1 sub-bullet 1): `toggleAlwaysUv` may
    // execute *without* a PIN token if no PIN is set AND alwaysUv
    // is currently off (this is how a fresh device opts into
    // alwaysUv as the first configuration step). All other paths
    // require a properly-scoped token.
    let needs_auth =
        !(req.sub_command == SUB_TOGGLE_ALWAYS_UV && store.pin.pin_set == 0 && !store.always_uv);

    if needs_auth {
        let auth_param = match &req.pin_uv_auth_param {
            Some(b) => b,
            None => {
                // Token required but none supplied -> PUAT_REQUIRED (0x36),
                // not MISSING_PARAMETER (0x14), matching the MakeCred /
                // GetAssert discipline (CTAP 2.1 sec. 6.11).
                out.push(client_pin::ERR_PUAT_REQUIRED);
                return;
            }
        };
        let proto = match req.pin_uv_auth_protocol {
            Some(p) if p == client_pin::PIN_PROTOCOL_V1 || p == client_pin::PIN_PROTOCOL_V2 => p,
            _ => {
                out.push(client_pin::ERR_PIN_AUTH_INVALID);
                return;
            }
        };
        // AC tokens shouldn't be RP-scoped -- they affect device-wide
        // policy. `check_token_permission` accepts an unscoped
        // token; if the host issued a scoped token and somehow
        // pointed it at AC, the mismatch with our zero `rp_id_hash`
        // sentinel will reject.
        if let Err(e) =
            client_pin::check_token_permission(session, PERM_AUTHENTICATOR_CFG, &[0u8; 32])
        {
            // Scoped tokens are explicitly *not* allowed for AC.
            if session.permissions_rp_id_hash.is_some() {
                out.push(client_pin::ERR_PIN_AUTH_INVALID);
                return;
            }
            out.push(e);
            return;
        }
        let msg = pin_auth_message(req.sub_command as u8, &req.sub_command_params_cbor);
        if !client_pin::verify_pin_uv_auth_param(
            session.pin_uv_auth_token(),
            &msg,
            auth_param,
            proto,
        ) {
            out.push(client_pin::ERR_PIN_AUTH_INVALID);
            return;
        }
    }

    match req.sub_command {
        SUB_ENABLE_ENT_ATTESTATION => {
            // Store the bit, but MakeCred attestation stays
            // self-attestation since we don't ship a vendor
            // certificate chain. Hosts that toggle this expect a
            // bare CTAP2_OK.
            store.enterprise_attestation = true;
            store.persist();
            out.push(CTAP2_OK);
        }
        SUB_TOGGLE_ALWAYS_UV => {
            store.always_uv = !store.always_uv;
            store.persist();
            out.push(CTAP2_OK);
        }
        SUB_SET_MIN_PIN_LENGTH => {
            // Either or both of newMinPinLength / minPinLengthRPIDs
            // can be present. CTAP 2.1 sec. 6.11.4 disallows lowering
            // newMinPinLength (only raise) -- enforce that.
            if let Some(new_len) = req.new_min_pin_length {
                // Reject an unsatisfiable floor: the PIN wire encoding caps
                // a usable PIN at 63 bytes, so a higher minimum would make
                // it impossible to ever set a PIN again -- a permanent brick
                // recoverable only by authenticatorReset (CTAP 2.1 sec. 6.11.4).
                if new_len > 63 {
                    out.push(ERR_PIN_POLICY_VIOLATION);
                    return;
                }
                let current = if store.min_pin_length == 0 {
                    client_pin::PIN_MIN_LENGTH_BYTES as u8
                } else {
                    store.min_pin_length
                };
                if new_len < u64::from(current) {
                    out.push(ERR_PIN_POLICY_VIOLATION);
                    return;
                }
                store.min_pin_length = new_len as u8; // <= 63, checked above
                                                      // sec. 6.11.4: if the new min exceeds the current PIN's
                                                      // length, the device SHOULD set `forcePINChange = true`
                                                      // so the host runs an old-PIN-authenticated changePIN.
                                                      // That flag is set explicitly below via the
                                                      // `forceChangePin` parameter; raising the minimum on its
                                                      // own does not remove PIN protection.
            }
            if req.min_pin_length_rpids_present {
                let n = req
                    .min_pin_length_rpid_hashes
                    .len()
                    .min(flash_store::MAX_MIN_PIN_LEN_RPIDS);
                for (i, h) in req.min_pin_length_rpid_hashes.iter().take(n).enumerate() {
                    store.min_pin_length_rpid_hashes[i] = *h;
                }
                store.min_pin_length_rpid_count = n as u8;
            }
            // sec. 6.11.4 forceChangePin (X13): mark the PIN as needing a
            // change WITHOUT removing PIN protection. The PIN stays
            // active (pin_set unchanged); we set the persistent
            // `force_pin_change` flag, which getInfo surfaces as
            // `0x0C forcePINChange = true` so the host runs an
            // old-PIN-authenticated changePIN. The previous behaviour
            // (clearing `pin_set`) converted "must change PIN" into
            // "PIN protection removed until re-set", letting an
            // unauthenticated setPIN through -- fixed here. The flag is
            // cleared by a successful changePIN (see the clientPin dispatch).
            if req.force_change_pin == Some(true) {
                store.force_pin_change = true;
            }
            store.persist();
            out.push(CTAP2_OK);
        }
        _ => out.push(ERR_INVALID_SUBCOMMAND),
    }
}

use crate::flash_store;
