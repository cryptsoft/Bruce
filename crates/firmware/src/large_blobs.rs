// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorLargeBlobs` (CTAP 2.1 sec. 6.10) -- a single global
//! byte array the host can read / write in chunks via offset+length
//! semantics.
//!
//! Use cases (per spec): RPs store passkey-vault data, hmac-secret
//! salt envelopes, or any per-credential blob too big for the
//! credentialID's 192-byte ciphertext budget. Each RP encrypts its
//! contribution with a per-credential `largeBlobKey` (extension --
//! see [`crate::credential_id::derive_large_blob_key`]) so the
//! array itself is just opaque bytes on our side.
//!
//! ## Storage
//!
//! A dedicated 4 KiB flash sector (see
//! [`crate::flash_store::LARGE_BLOB_OFFSET`]) sitting immediately
//! below the credential-store sector. 16-byte header (magic +
//! version + array_len + padding) followed by up to
//! [`MAX_LARGE_BLOB_LEN = 2048`] bytes of array payload. On cold
//! boot / fresh-sector the device reports the spec-mandated
//! initial value: `0x80` (CBOR empty-array) followed by the first
//! 16 bytes of `SHA-256("\x80")`.
//!
//! ## Wire format
//!
//! Request (CBOR map keyed by u8):
//!
//!   0x01 get?     (u32, length to read -- exclusive with `set`)
//!   0x02 set?     (bytes, write payload -- exclusive with `get`)
//!   0x03 offset   (u32, REQUIRED)
//!   0x04 length?  (u32, total length of the array being written,
//!                  REQUIRED on first chunk of a write at offset 0)
//!   0x05 pinUvAuthParam? (bytes -- required for writes if PIN is set)
//!   0x06 pinUvAuthProtocol? (1 or 2)
//!
//! Response on read: `0x01 config` (bytes) -- the requested slice.
//! Response on write: empty (just CTAP2_OK status byte).
//!
//! Writes are authenticated under the active `pinUvAuthToken`
//! (CTAP 2.1 sec. 6.10.5) -- the message the host signs is
//!     `[0xFF; 32] || 0x0C || 0x00 || offset_4LE || sha256(set)`
//! where `set` is the entire intended array contents (the host
//! re-builds the whole array per write batch).

extern crate alloc;

use crate::bc_crypto::sha256;
use alloc::vec;
use alloc::vec::Vec as AllocVec;
use pqf_cbor::{cbor_int, cbor_map, Value};

use crate::client_pin::{self, PinSession, PERM_LARGE_BLOB_WRITE};
use crate::ctap2::{CredStore, CtapResponse, CTAP2_ERR_INVALID_CBOR, CTAP2_OK};
use crate::flash_store::{self, MAX_LARGE_BLOB_LEN};

const ERR_INVALID_PARAM: u8 = 0x02;
/// CTAP1_ERR_INVALID_LENGTH. 0x29 is CTAP2_ERR_NOT_BUSY -- both ports
/// declared it as the length error and agreed with each other.
const ERR_INVALID_LENGTH: u8 = 0x03;
/// CTAP2_ERR_LARGE_BLOB_STORAGE_FULL: an array too big to ever store,
/// which a client can act on by freeing space rather than by giving up.
const ERR_LARGE_BLOB_STORAGE_FULL: u8 = 0x18;
const ERR_MISSING_PARAMETER: u8 = 0x14;

/// (F5) Multi-fragment write assembly buffer (CTAP 2.1 sec. 6.10.3).
///
/// A `set` write may arrive in several CTAP transactions: the first
/// chunk carries `offset == 0` and a `0x04 length` giving the total
/// number of bytes the host intends to write; later chunks omit
/// `length` and append at the running offset. We buffer the bytes in
/// this fixed RAM staging area and only validate the SHA-256 trailer
/// and persist once the full `length` has been assembled.
///
/// Safety / concurrency: the CTAP2 dispatch that reaches
/// `large_blobs::handle` runs only on core 0 and is strictly
/// non-reentrant (the transport serialises one CTAP transaction at a
/// time), so this `static mut` has a single accessor at a time. All
/// access goes through `handle` below, which is on that path.
struct WriteAssembly {
    /// Bytes staged so far (`written` valid bytes of the eventual
    /// `expected` total).
    buf: [u8; MAX_LARGE_BLOB_LEN],
    /// Total length the in-progress write will contain (from the
    /// first chunk's `0x04 length`). 0 means "no write in progress".
    expected: usize,
    /// Number of bytes assembled so far == the offset the next chunk
    /// must arrive at.
    written: usize,
}

static mut WRITE_ASSEMBLY: WriteAssembly = WriteAssembly {
    buf: [0u8; MAX_LARGE_BLOB_LEN],
    expected: 0,
    written: 0,
};

/// Obtain the single mutable handle to the assembly buffer.
///
/// SAFETY: the CTAP2 dispatch that reaches `large_blobs::handle` runs
/// only on core 0 and is strictly non-reentrant (one CTAP transaction
/// at a time), so there is never more than one live borrow of the
/// `static mut` at once. All access goes through this function.
#[allow(static_mut_refs)]
fn assembly() -> &'static mut WriteAssembly {
    unsafe { &mut WRITE_ASSEMBLY }
}

/// Reset the in-progress write state. Called on a fresh `offset == 0`
/// chunk and after a completed / rejected write so a later write
/// starts clean.
/// Abandon any in-progress multi-fragment write.
///
/// Public because authenticatorReset has to call it. `reset` erases the
/// stored array, but the staging buffer is a separate static: a write
/// begun before the reset would otherwise be completed after it, and
/// committed with no authentication, because the fragment that carries
/// the pinUvAuthParam is the first one.
pub fn abandon_write() {
    reset_assembly();
}

fn reset_assembly() {
    let asm = assembly();
    asm.expected = 0;
    asm.written = 0;
}

/// Parsed request map.
struct LbRequest {
    /// `0x01 offset`.
    offset: u32,
    /// `0x02 get` -- Some on read.
    get_len: Option<u32>,
    /// `0x03 set` -- Some on write.
    set_data: Option<AllocVec<u8>>,
    /// `0x04 length` -- total array length, REQUIRED on first chunk.
    total_length: Option<u32>,
    pin_uv_auth_param: Option<AllocVec<u8>>,
    pin_uv_auth_protocol: Option<u64>,
}

fn parse_request(input: &[u8]) -> Option<LbRequest> {
    use pqf_cbor::Value as V;
    let value = pqf_cbor::decode(input).ok()?;
    let map = match value {
        V::Map(m) => m,
        _ => return None,
    };
    let mut offset = 0u32;
    let mut get_len = None;
    let mut set_data = None;
    let mut total_length = None;
    let mut pin_uv_auth_param = None;
    let mut pin_uv_auth_protocol = None;
    for (k, v) in &map {
        let key = match k {
            V::Uint(u) => *u as i64,
            V::Nint(n) => *n,
            _ => continue,
        };
        match (key, v) {
            (0x01, V::Uint(u)) => get_len = Some(*u as u32),
            (0x02, V::Bytes(b)) => set_data = Some(b.clone()),
            (0x03, V::Uint(u)) => offset = *u as u32,
            (0x04, V::Uint(u)) => total_length = Some(*u as u32),
            (0x05, V::Bytes(b)) => pin_uv_auth_param = Some(b.clone()),
            (0x06, V::Uint(u)) => pin_uv_auth_protocol = Some(*u),
            _ => {}
        }
    }
    Some(LbRequest {
        offset,
        get_len,
        set_data,
        total_length,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
    })
}

/// Build the byte sequence the host signs for a LargeBlobs write
/// (CTAP 2.1 sec. 6.10.5 step 3):
///     `[0xFF; 32] || 0x0C || 0x00 || offset_4LE || SHA-256(set)`
fn pin_auth_message(offset: u32, set_data: &[u8]) -> AllocVec<u8> {
    let mut buf = AllocVec::with_capacity(32 + 2 + 4 + 32);
    buf.extend_from_slice(&[0xFFu8; 32]);
    // CTAP 2.1 sec. 6.10: the literal two bytes h'0c00' -- the command byte
    // followed by a zero, NOT the `set` parameter's key.
    buf.push(0x0C);
    buf.push(0x00);
    buf.extend_from_slice(&offset.to_le_bytes());
    let h: [u8; 32] = sha256(set_data);
    buf.extend_from_slice(&h);
    buf
}

/// Return the current array contents -- either what's in flash, or
/// the spec's initial value if the sector hasn't been written yet.
fn current_array() -> AllocVec<u8> {
    if let Some(a) = flash_store::read_large_blob_sector() {
        return a;
    }
    // Initial value: 0x80 (CBOR empty array) || SHA-256("\x80")[..16]
    let mut v = AllocVec::with_capacity(17);
    v.push(0x80);
    let h: [u8; 32] = sha256(&[0x80u8]);
    v.extend_from_slice(&h[..16]);
    v
}

/// Entry point -- called from `ctap2::handle_cbor` for command 0x0C.
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

    let is_write = req.set_data.is_some();
    if is_write && req.get_len.is_some() {
        out.push(ERR_INVALID_PARAM);
        return;
    }

    if is_write {
        // PIN/UV auth is required for a write when a PIN is set OR the
        // device-wide alwaysUv policy is on (CTAP 2.1 sec. 6.10.4). On this
        // hardware no UV method exists without a PIN, so an alwaysUv=true
        // device with no PIN simply can't write the large-blob array --
        // which is the correct outcome: the write stays authenticated
        // rather than slipping through unauthenticated.
        if store.pin.pin_set != 0 || store.always_uv {
            let auth_param = match &req.pin_uv_auth_param {
                Some(b) => b,
                None => {
                    // PIN set but no token supplied: PUAT_REQUIRED (0x36),
                    // not MISSING_PARAMETER (0x14), so the host knows to
                    // obtain a token and retry (CTAP 2.1 sec. 6.10).
                    out.push(client_pin::ERR_PUAT_REQUIRED);
                    return;
                }
            };
            let proto = match req.pin_uv_auth_protocol {
                Some(p) if p == client_pin::PIN_PROTOCOL_V1 || p == client_pin::PIN_PROTOCOL_V2 => {
                    p
                }
                _ => {
                    out.push(client_pin::ERR_PIN_AUTH_INVALID);
                    return;
                }
            };
            // LB writes need the `lbw` permission. The token must
            // be unscoped (the array is device-wide).
            if let Err(e) =
                client_pin::check_token_permission(session, PERM_LARGE_BLOB_WRITE, &[0u8; 32])
            {
                if session.permissions_rp_id_hash.is_some() {
                    out.push(client_pin::ERR_PIN_AUTH_INVALID);
                    return;
                }
                out.push(e);
                return;
            }
            let set_data = req.set_data.as_ref().unwrap();
            let msg = pin_auth_message(req.offset, set_data);
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

        let set_data = req.set_data.as_ref().unwrap();
        let chunk_len = set_data.len();
        let offset = req.offset as usize;

        // Multi-fragment assembly (CTAP 2.1 sec. 6.10.3). A write of
        // `length` total bytes may span several CTAP transactions:
        //
        //   - offset == 0 STARTS a write: `0x04 length` is REQUIRED and
        //     gives the total; we (re)initialise the staging buffer and
        //     copy the first chunk in at position 0. A fresh offset==0
        //     always resets any partially-buffered prior write.
        //   - offset != 0 APPENDS: `0x04 length` MUST be absent, and the
        //     offset MUST equal exactly how many bytes we've assembled
        //     so far (writes are strictly sequential).
        //
        // Every chunk is bounded so neither the running offset nor the
        // total can index past the buffer (overflow-checks=false: use
        // checked/saturating arithmetic, never a bare `+`).
        if offset == 0 {
            let total = match req.total_length {
                Some(t) => t as usize,
                None => {
                    // First chunk MUST declare the total length.
                    out.push(ERR_MISSING_PARAMETER);
                    return;
                }
            };
            // sec. 6.10.3: a valid serialized large-blob array is at least
            // the 16-byte SHA-256 trailer; cap at MAX_LARGE_BLOB_LEN so
            // the staging buffer can never overflow.
            // Too big to ever store is a different answer from
            // malformed: a client can free space and retry one and not
            // the other. Same split as the C port.
            if total > MAX_LARGE_BLOB_LEN {
                reset_assembly();
                out.push(ERR_LARGE_BLOB_STORAGE_FULL);
                return;
            }
            if total < 17 {
                reset_assembly();
                out.push(ERR_INVALID_LENGTH);
                return;
            }
            // The first chunk can't be longer than the declared total.
            if chunk_len > total {
                reset_assembly();
                out.push(ERR_INVALID_LENGTH);
                return;
            }
            // `chunk_len <= total <= MAX_LARGE_BLOB_LEN`, so the slice
            // index stays in bounds.
            let asm = assembly();
            asm.expected = total;
            asm.written = chunk_len;
            asm.buf[..chunk_len].copy_from_slice(set_data);
        } else {
            // Appending chunk. A write must already be in progress and
            // declare no new total length.
            if req.total_length.is_some() {
                reset_assembly();
                out.push(ERR_INVALID_PARAM);
                return;
            }
            let asm = assembly();
            if asm.expected == 0 {
                // No write in progress -- an append with nothing started.
                out.push(ERR_INVALID_PARAM);
                return;
            }
            // Strictly sequential: the offset must be exactly where we
            // are. (Equality also rules out an offset past the buffer.)
            if offset != asm.written {
                reset_assembly();
                out.push(ERR_INVALID_PARAM);
                return;
            }
            // The chunk must not overrun the declared total. `offset`
            // already equals `written <= expected <= MAX_LARGE_BLOB_LEN`,
            // so `end` (saturating) stays within the buffer.
            let end = offset.saturating_add(chunk_len);
            if end > asm.expected {
                reset_assembly();
                out.push(ERR_INVALID_LENGTH);
                return;
            }
            asm.buf[offset..end].copy_from_slice(set_data);
            asm.written = end;
        }

        // Not yet complete -- ACK this fragment and wait for more.
        let (expected, written) = {
            let asm = assembly();
            (asm.expected, asm.written)
        };
        if written < expected {
            out.push(CTAP2_OK);
            return;
        }

        // Full payload assembled: validate the SHA-256 trailer per
        // sec. 6.10.3 -- the last 16 bytes must equal the first 16 bytes of
        // SHA-256 over the preceding body -- then persist. `expected` is
        // bounded to [17, MAX_LARGE_BLOB_LEN] above, so the slice
        // indices below are valid.
        let trailer_ok = {
            let assembled = &assembly().buf[..expected];
            let body = &assembled[..expected - 16];
            let trailer = &assembled[expected - 16..];
            let full: [u8; 32] = sha256(body);
            full[..16] == *trailer
        };
        if !trailer_ok {
            reset_assembly();
            out.push(ERR_INVALID_PARAM);
            return;
        }
        flash_store::write_large_blob_sector(&assembly().buf[..expected]);
        reset_assembly();
        out.push(CTAP2_OK);
        return;
    }

    // Read path (`0x02 get`).
    let len = match req.get_len {
        Some(l) => l as usize,
        None => {
            out.push(ERR_MISSING_PARAMETER);
            return;
        }
    };
    let arr = current_array();
    let off = req.offset as usize;
    if off > arr.len() {
        out.push(ERR_INVALID_LENGTH);
        return;
    }
    // `off + len` is attacker-controlled (len comes straight from the
    // u32 `get` field); a plain add wraps on the 32-bit target
    // (overflow-checks=false) and `arr[off..end]` would then panic with
    // start>end -- a no-auth panic-abort DoS. saturating_add keeps
    // end >= off (off is already bounded above), so the slice is valid.
    let end = off.saturating_add(len).min(arr.len());
    let chunk = arr[off..end].to_vec();
    let map = cbor_map! {
        cbor_int!(0x01) => Value::Bytes(chunk),
    };
    let mut enc = AllocVec::new();
    pqf_cbor::encode(&map, &mut enc);
    out.push(CTAP2_OK);
    out.extend_from_slice(&enc);
}

#[allow(dead_code)]
fn _suppress_unused() -> AllocVec<u8> {
    vec![0u8; 0]
}
