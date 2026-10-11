// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorCredentialManagement` (CTAP 2.1 sec. 6.8) -- on-device
//! credential admin. Seven subcommands let the host enumerate which
//! credentials are stored, see their RPs / user info / pubkey,
//! delete them, and rename them.
//!
//! All seven subcommands require:
//!   1. An active `pinUvAuthToken` (via `getPinUvAuthTokenUsingPin*`).
//!   2. The token must carry the `CM` permission bit
//!      ([`PERM_CREDENTIAL_MGMT`] = 0x04).
//!   3. The `pinUvAuthParam` over the subcommand body must verify.
//!   4. Some subcommands further require that the token *not* be
//!      RP-scoped (`getCredsMetadata`, `enumerateRPsBegin`) since
//!      they enumerate across all RPs; others are happy with
//!      an unscoped *or* matching-RP-scoped token.
//!
//! ### Subcommand wire codes (CTAP 2.1 sec. 6.8.1, table 5-9)
//!
//! | Code | Name                                            |
//! |------|-------------------------------------------------|
//! | 0x01 | `getCredsMetadata`                              |
//! | 0x02 | `enumerateRPsBegin`                             |
//! | 0x03 | `enumerateRPsGetNextRP`                         |
//! | 0x04 | `enumerateCredentialsBegin`                     |
//! | 0x05 | `enumerateCredentialsGetNextCredential`         |
//! | 0x06 | `deleteCredential`                              |
//! | 0x07 | `updateUserInformation`                         |
//!
//! Enumeration subcommands are stateful: `Begin` sets up an
//! iterator on the `PinSession`; `GetNextRP` / `GetNextCredential`
//! pop the next entry. State times out after 30 s of inactivity
//! and is invalidated by any other CTAP command on a different
//! HID channel, matching OpenSK's `STATEFUL_COMMAND_TIMEOUT_DURATION`.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec as AllocVec;
use pqf_cbor::{cbor_array, cbor_bytes, cbor_int, cbor_map, cbor_text, Value};

use crate::client_pin::{self, PinSession, PERM_CREDENTIAL_MGMT};
use crate::credential_id::decrypt_credential_id;
use crate::ctap2::{
    es256_cose_public_key, CredStore, CtapResponse, CTAP2_ERR_INVALID_CBOR,
    CTAP2_ERR_NO_CREDENTIALS, CTAP2_OK,
};
use crate::flash_store::{STATE_ACTIVE, STORED_CRED_ID_LEN};

/// CM subcommand identifiers.
const SUB_GET_CREDS_METADATA: u64 = 0x01;
const SUB_ENUMERATE_RPS_BEGIN: u64 = 0x02;
const SUB_ENUMERATE_RPS_GET_NEXT: u64 = 0x03;
const SUB_ENUMERATE_CREDS_BEGIN: u64 = 0x04;
const SUB_ENUMERATE_CREDS_GET_NEXT: u64 = 0x05;
const SUB_DELETE_CREDENTIAL: u64 = 0x06;
const SUB_UPDATE_USER_INFORMATION: u64 = 0x07;

/// Generic CTAP2 status codes that the CM module emits -- pulled into
/// scope so we don't have to qualify every push.
const ERR_MISSING_PARAMETER: u8 = 0x14;
/// 0x3E. See the note in `client_pin.rs`; 0x16 is UNSUPPORTED_EXTENSION.
const ERR_INVALID_SUBCOMMAND: u8 = 0x3e;
const ERR_NOT_ALLOWED: u8 = 0x30;

/// CTAP 2.1 sec. 6.8 sec. 5.10 -- stateful iterator timeout for the `Begin`
/// -> `GetNext...` flow. OpenSK uses the same 30-second window.
const STATEFUL_TIMEOUT_US: u64 = 30_000_000;

/// In-flight RP enumeration. `next_idx` is an index into the
/// deduplicated RP-id-hash list we built at `Begin` time, sorted by
/// the earliest `creation_order` for each RP.
#[derive(Clone, Debug)]
pub struct RpEnumState {
    /// Distinct RPs (their 32-byte ID hashes + text RP id from the
    /// first credential seen for that RP). Sorted by creation_order
    /// for OpenSK-compatibility.
    pub rps: AllocVec<([u8; 32], alloc::string::String)>,
    /// Index of the next RP to return on `GetNextRP`.
    pub next_idx: usize,
    /// Deadline (timer.get_counter().ticks() result) after which the
    /// iterator is discarded.
    pub deadline_us: u64,
    /// CTAP HID channel ID this iteration was started on. State is
    /// dropped if the next request arrives on a different channel.
    pub _cid: [u8; 4],
}

/// In-flight credential enumeration scoped to one RP.
#[derive(Clone, Debug)]
pub struct CredEnumState {
    /// RP id hash this iteration is scoped to.
    pub rp_id_hash: [u8; 32],
    /// Slot indices of credentials for this RP, sorted by
    /// `creation_order`. Popped from the front on each `GetNext`.
    pub slot_idxs: AllocVec<usize>,
    /// Index of the next credential to return.
    pub next_idx: usize,
    /// Deadline (microseconds since boot).
    pub deadline_us: u64,
    pub _cid: [u8; 4],
}

/// Parsed `authenticatorCredentialManagement` request map.
struct CmRequest {
    sub_command: u64,
    /// Subcommand parameters map. For `EnumerateCredentialsBegin` /
    /// `DeleteCredential` / `UpdateUserInformation`. CBOR-encoded
    /// here as bytes so the PIN auth check sees what the host
    /// signed (subcommand byte || params bytes).
    sub_command_params_cbor: AllocVec<u8>,
    /// Parsed view of those params (only the fields we need).
    rp_id_hash: Option<[u8; 32]>,
    credential_id: Option<AllocVec<u8>>,
    user_name: Option<alloc::string::String>,
    user_display_name: Option<alloc::string::String>,
    pin_uv_auth_param: Option<AllocVec<u8>>,
    pin_uv_auth_protocol: Option<u64>,
}

fn parse_request(input: &[u8]) -> Option<CmRequest> {
    use pqf_cbor::Value as V;
    let value = pqf_cbor::decode(input).ok()?;
    let map = match value {
        V::Map(m) => m,
        _ => return None,
    };
    let mut sub_command = None;
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

    // Re-serialise the subcommand-params map so we can rebuild the
    // exact byte sequence the host signed for the pinUvAuthParam.
    let mut sub_command_params_cbor: AllocVec<u8> = AllocVec::new();
    if let Some(ref v) = sub_params_value {
        pqf_cbor::encode(v, &mut sub_command_params_cbor);
    }

    let mut rp_id_hash: Option<[u8; 32]> = None;
    let mut credential_id: Option<AllocVec<u8>> = None;
    let mut user_name: Option<alloc::string::String> = None;
    let mut user_display_name: Option<alloc::string::String> = None;

    if let Some(V::Map(params)) = &sub_params_value {
        for (k, v) in params {
            let key = match k {
                V::Uint(u) => *u as i64,
                V::Nint(n) => *n,
                _ => continue,
            };
            match (key, v) {
                // 0x01: rpIDHash (bytes, 32)
                (0x01, V::Bytes(b)) if b.len() == 32 => {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(b);
                    rp_id_hash = Some(h);
                }
                // 0x02: credentialID (PublicKeyCredentialDescriptor map
                // with "id" key).
                (0x02, V::Map(desc)) => {
                    for (kk, vv) in desc {
                        if let (V::Text(s), V::Bytes(b)) = (kk, vv) {
                            if s == "id" {
                                credential_id = Some(b.clone());
                            }
                        }
                    }
                }
                // 0x03: user (PublicKeyCredentialUserEntity map).
                (0x03, V::Map(u)) => {
                    for (kk, vv) in u {
                        if let V::Text(s_key) = kk {
                            match (s_key.as_str(), vv) {
                                ("name", V::Text(s)) => {
                                    user_name = Some(s.clone());
                                }
                                ("displayName", V::Text(s)) => {
                                    user_display_name = Some(s.clone());
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Some(CmRequest {
        sub_command,
        sub_command_params_cbor,
        rp_id_hash,
        credential_id,
        user_name,
        user_display_name,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
    })
}

/// Build the byte sequence the host signs for `pinUvAuthParam` on
/// CTAP2 CredentialManagement, per CTAP 2.1 sec. 6.8.2:
///     `[0x0A | subCommand_byte | subCommandParams_cbor]`
/// -- where `0x0A` is the `authenticatorCredentialManagement` cmd
/// identifier.
fn pin_auth_message(sub_command: u8, sub_params_cbor: &[u8]) -> AllocVec<u8> {
    let mut buf = AllocVec::with_capacity(2 + sub_params_cbor.len());
    buf.push(sub_command);
    buf.extend_from_slice(sub_params_cbor);
    buf
}

/// Entry point -- called from `ctap2::handle_cbor` for command 0x0A.
pub fn handle(
    input: &[u8],
    session: &mut PinSession,
    store: &mut CredStore,
    now_us: u64,
    cid: [u8; 4],
    out: &mut CtapResponse,
) {
    let req = match parse_request(input) {
        Some(r) => r,
        None => {
            out.push(CTAP2_ERR_INVALID_CBOR);
            return;
        }
    };

    // Every subcommand except `GetNext*` requires a freshly-verified
    // pinUvAuthParam. The `GetNext*` flows piggy-back on the iterator
    // state set up by their `Begin` counterpart and don't reauth.
    let needs_auth = !matches!(
        req.sub_command,
        SUB_ENUMERATE_RPS_GET_NEXT | SUB_ENUMERATE_CREDS_GET_NEXT
    );
    if needs_auth {
        let auth_param = match &req.pin_uv_auth_param {
            Some(b) => b,
            None => {
                // Token required but none supplied -> PUAT_REQUIRED (0x36),
                // not MISSING_PARAMETER (0x14), matching the MakeCred /
                // GetAssert discipline (CTAP 2.1 sec. 6.8).
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
        // CM tokens may be RP-scoped OR unscoped. The permission
        // helper rejects scoped tokens whose scope doesn't match --
        // for subcommands that take an `rp_id_hash` (CredsBegin,
        // Delete, UpdateUserInfo) we check against that hash;
        // otherwise we check against a zero hash and the helper
        // treats scoped tokens as "doesn't apply" -> reject. CTAP
        // 2.1 sec. 6.8.2 step 5 spells this out.
        let cm_rp_for_check = req.rp_id_hash.unwrap_or([0u8; 32]);
        if client_pin::check_token_permission(session, PERM_CREDENTIAL_MGMT, &cm_rp_for_check)
            .is_err()
        {
            // pinUvAuthParam IS present in this branch, so every
            // permission / RP-scope failure is reported as
            // PIN_AUTH_INVALID (0x33) -- not the raw helper code (which
            // can be 0x36) -- matching the MakeCred / GetAssert discipline
            // (CTAP 2.1 sec. 6.8). check_token_permission already rejects a
            // scoped token checked against the zero `rp_id_hash`, so the
            // "metadata / enumerateRPs must be unscoped" rule is covered
            // without a special case.
            out.push(client_pin::ERR_PIN_AUTH_INVALID);
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
        SUB_GET_CREDS_METADATA => sub_get_creds_metadata(store, out),
        SUB_ENUMERATE_RPS_BEGIN => sub_enumerate_rps_begin(store, session, now_us, cid, out),
        SUB_ENUMERATE_RPS_GET_NEXT => sub_enumerate_rps_get_next(session, now_us, cid, out),
        SUB_ENUMERATE_CREDS_BEGIN => {
            sub_enumerate_creds_begin(&req, store, session, now_us, cid, out)
        }
        SUB_ENUMERATE_CREDS_GET_NEXT => {
            sub_enumerate_creds_get_next(store, session, now_us, cid, out)
        }
        SUB_DELETE_CREDENTIAL => sub_delete_credential(&req, store, out),
        SUB_UPDATE_USER_INFORMATION => sub_update_user_information(&req, store, out),
        _ => out.push(ERR_INVALID_SUBCOMMAND),
    }
}

fn sub_get_creds_metadata(store: &CredStore, out: &mut CtapResponse) {
    let existing = store.active_count() as u64;
    let remaining = (store.max_slots() as u64).saturating_sub(existing);
    let map = cbor_map! {
        cbor_int!(0x01) => cbor_int!(existing as i64),
        cbor_int!(0x02) => cbor_int!(remaining as i64),
    };
    let mut enc = AllocVec::new();
    pqf_cbor::encode(&map, &mut enc);
    out.push(CTAP2_OK);
    out.extend_from_slice(&enc);
}

fn sub_enumerate_rps_begin(
    store: &CredStore,
    session: &mut PinSession,
    now_us: u64,
    cid: [u8; 4],
    out: &mut CtapResponse,
) {
    // Collect distinct (rp_id_hash, rp_id_text) pairs in
    // creation_order. (F4) The text RP id is now persisted on the slot
    // (`rp_id`/`rp_id_len`, captured at MakeCredential time), so we can
    // return the real string per CTAP 2.1 sec. 6.8.2's
    // PublicKeyCredentialRpEntity instead of "". A slot minted before
    // the field existed (rp_id_len == 0) still yields the empty string.
    let mut rps: AllocVec<([u8; 32], alloc::string::String)> = AllocVec::new();
    for (_idx, s) in store.iter_active_by_creation() {
        if !rps.iter().any(|(h, _)| h == &s.rp_id_hash) {
            let len = (s.rp_id_len as usize).min(crate::flash_store::MAX_RP_ID_LEN);
            let id_text = core::str::from_utf8(&s.rp_id[..len])
                .map(alloc::string::String::from)
                .unwrap_or_default();
            rps.push((s.rp_id_hash, id_text));
        }
    }
    if rps.is_empty() {
        out.push(CTAP2_ERR_NO_CREDENTIALS);
        return;
    }
    let total = rps.len() as u64;
    let first = rps[0].clone();
    session.cm_rp_iter = Some(RpEnumState {
        rps,
        next_idx: 1,
        deadline_us: now_us.saturating_add(STATEFUL_TIMEOUT_US),
        _cid: cid,
    });
    emit_rp_response(first, Some(total), out);
}

fn sub_enumerate_rps_get_next(
    session: &mut PinSession,
    now_us: u64,
    cid: [u8; 4],
    out: &mut CtapResponse,
) {
    // CTAP 2.1 sec. 6.8/sec. 11.2: the enumeration is bound to the channel that
    // began it. A getNext on any other channel (or past the deadline) is
    // refused and the iterator dropped, so a second host process can't
    // drive -- or read -- another channel's in-flight enumeration.
    let state = match session.cm_rp_iter.as_mut() {
        Some(s) if now_us < s.deadline_us && s._cid == cid => s,
        _ => {
            session.cm_rp_iter = None;
            out.push(ERR_NOT_ALLOWED);
            return;
        }
    };
    if state.next_idx >= state.rps.len() {
        session.cm_rp_iter = None;
        out.push(ERR_NOT_ALLOWED);
        return;
    }
    let entry = state.rps[state.next_idx].clone();
    state.next_idx += 1;
    state.deadline_us = now_us.saturating_add(STATEFUL_TIMEOUT_US);
    emit_rp_response(entry, None, out);
}

fn emit_rp_response(
    entry: ([u8; 32], alloc::string::String),
    total: Option<u64>,
    out: &mut CtapResponse,
) {
    let (hash, id_text) = entry;
    let mut entries: AllocVec<(Value, Value)> = AllocVec::new();
    entries.push((
        cbor_int!(0x03), // rp (PublicKeyCredentialRpEntity)
        cbor_map! {
            cbor_text!("id") => cbor_text!(id_text),
        },
    ));
    entries.push((cbor_int!(0x04), Value::Bytes(hash.to_vec())));
    if let Some(t) = total {
        entries.push((cbor_int!(0x05), cbor_int!(t as i64)));
    }
    let mut enc = AllocVec::new();
    pqf_cbor::encode(&Value::Map(entries), &mut enc);
    out.push(CTAP2_OK);
    out.extend_from_slice(&enc);
}

fn sub_enumerate_creds_begin(
    req: &CmRequest,
    store: &CredStore,
    session: &mut PinSession,
    now_us: u64,
    cid: [u8; 4],
    out: &mut CtapResponse,
) {
    let rp_id_hash = match req.rp_id_hash {
        Some(h) => h,
        None => {
            out.push(ERR_MISSING_PARAMETER);
            return;
        }
    };
    let mut idxs: AllocVec<usize> = AllocVec::new();
    for (i, s) in store.iter_active_by_creation() {
        if s.rp_id_hash == rp_id_hash {
            idxs.push(i);
        }
    }
    if idxs.is_empty() {
        out.push(CTAP2_ERR_NO_CREDENTIALS);
        return;
    }
    let total = idxs.len() as u32;
    let first_idx = idxs[0];
    session.cm_cred_iter = Some(CredEnumState {
        rp_id_hash,
        slot_idxs: idxs,
        next_idx: 1,
        deadline_us: now_us.saturating_add(STATEFUL_TIMEOUT_US),
        _cid: cid,
    });
    emit_credential_response(first_idx, store, Some(total as u64), out);
}

fn sub_enumerate_creds_get_next(
    store: &CredStore,
    session: &mut PinSession,
    now_us: u64,
    cid: [u8; 4],
    out: &mut CtapResponse,
) {
    // Bound to the originating channel (see sub_enumerate_rps_get_next).
    let state = match session.cm_cred_iter.as_mut() {
        Some(s) if now_us < s.deadline_us && s._cid == cid => s,
        _ => {
            session.cm_cred_iter = None;
            out.push(ERR_NOT_ALLOWED);
            return;
        }
    };
    // Advance to the next slot that is STILL active and still belongs to
    // this RP. A credential deleted (tombstoned) or its slot reused
    // between Begin and this getNext must not surface stale user.id /
    // name / credentialId data, so skip past such slots in the frozen
    // index list rather than emit them.
    loop {
        if state.next_idx >= state.slot_idxs.len() {
            session.cm_cred_iter = None;
            out.push(ERR_NOT_ALLOWED);
            return;
        }
        let idx = state.slot_idxs[state.next_idx];
        state.next_idx += 1;
        let s = store.slot(idx);
        if s.state == STATE_ACTIVE && s.rp_id_hash == state.rp_id_hash {
            state.deadline_us = now_us.saturating_add(STATEFUL_TIMEOUT_US);
            emit_credential_response(idx, store, None, out);
            return;
        }
    }
}

fn emit_credential_response(
    idx: usize,
    store: &CredStore,
    total: Option<u64>,
    out: &mut CtapResponse,
) {
    let s = store.slot(idx);
    let mut user_map_entries: AllocVec<(Value, Value)> = AllocVec::new();
    user_map_entries.push((
        cbor_text!("id"),
        Value::Bytes(s.user_id[..s.user_id_len as usize].to_vec()),
    ));
    if s.user_name_len > 0 {
        if let Ok(t) = core::str::from_utf8(&s.user_name[..s.user_name_len as usize]) {
            user_map_entries.push((cbor_text!("name"), cbor_text!(t.to_string())));
        }
    }
    if s.user_display_name_len > 0 {
        if let Ok(t) =
            core::str::from_utf8(&s.user_display_name[..s.user_display_name_len as usize])
        {
            user_map_entries.push((cbor_text!("displayName"), cbor_text!(t.to_string())));
        }
    }
    let cred_desc = cbor_map! {
        cbor_text!("id") => Value::Bytes(s.credential_id.to_vec()),
        cbor_text!("type") => cbor_text!("public-key"),
    };

    let mut entries: AllocVec<(Value, Value)> = AllocVec::new();
    entries.push((cbor_int!(0x06), Value::Map(user_map_entries)));
    entries.push((cbor_int!(0x07), cred_desc));
    // 0x08 publicKey -- populating this honestly requires re-deriving
    // the COSE pubkey from the encrypted credentialID's plaintext.
    // We decrypt with our master keys (we generated it) to do so.
    if let Ok(src) = decrypt_credential_id(
        &store.key_handle_aes_key,
        &store.key_handle_hmac_key,
        &s.credential_id,
        &s.rp_id_hash,
    ) {
        // 0x08 publicKey (CTAP 2.1 sec. 6.8.3): the COSE_Key re-derived from
        // the credential's stored secrets, emitted between 0x07 and the
        // credProtect / total keys. Hybrid creds show the ES256 half.
        if let Some(cose) = es256_cose_public_key(src.alg, &src.ecdsa_scalar) {
            entries.push((cbor_int!(0x08), cose));
        }
    }
    // 0x09 credProtect
    if s.cred_protect > 0 {
        entries.push((cbor_int!(0x0A), cbor_int!(s.cred_protect as i64)));
    }
    if let Some(t) = total {
        entries.push((cbor_int!(0x09), cbor_int!(t as i64)));
    }

    let mut enc = AllocVec::new();
    pqf_cbor::encode(&Value::Map(entries), &mut enc);
    out.push(CTAP2_OK);
    out.extend_from_slice(&enc);
}

fn sub_delete_credential(req: &CmRequest, store: &mut CredStore, out: &mut CtapResponse) {
    let cred_id = match &req.credential_id {
        Some(b) if b.len() == STORED_CRED_ID_LEN => b,
        _ => {
            out.push(ERR_MISSING_PARAMETER);
            return;
        }
    };
    let idx = match store
        .iter_active_by_creation()
        .find(|(_, s)| s.credential_id[..] == cred_id[..])
        .map(|(i, _)| i)
    {
        Some(i) => i,
        None => {
            out.push(CTAP2_ERR_NO_CREDENTIALS);
            return;
        }
    };
    store.delete_slot(idx);
    out.push(CTAP2_OK);
}

fn sub_update_user_information(req: &CmRequest, store: &mut CredStore, out: &mut CtapResponse) {
    let cred_id = match &req.credential_id {
        Some(b) if b.len() == STORED_CRED_ID_LEN => b,
        _ => {
            out.push(ERR_MISSING_PARAMETER);
            return;
        }
    };
    let idx = match store
        .iter_active_by_creation()
        .find(|(_, s)| s.credential_id[..] == cred_id[..])
        .map(|(i, _)| i)
    {
        Some(i) => i,
        None => {
            out.push(CTAP2_ERR_NO_CREDENTIALS);
            return;
        }
    };
    let new_name = req.user_name.as_ref().map(|s| s.as_bytes());
    let new_disp = req.user_display_name.as_ref().map(|s| s.as_bytes());
    store.update_user_info(idx, new_name, new_disp);
    out.push(CTAP2_OK);
}

// Suppress unused-import warnings when the convenience cbor_*
// macros aren't all referenced (e.g. cbor_array / cbor_bytes when
// the codepath is later trimmed).
#[allow(dead_code)]
fn _suppress_warnings(_: AllocVec<u8>) -> Value {
    cbor_array![cbor_bytes!(AllocVec::<u8>::new())]
}
