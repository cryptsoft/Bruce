// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorLargeBlobs` (CTAP 2.1 sec. 6.10) -- read / write the
//! single device-wide large-blob array.
//!
//! The "large blob array" is a server-side blob the RP stores via
//! the authenticator. Reads are unauthenticated; writes require a
//! `pinUvAuthToken` with the [`super::client_pin::permission::LARGE_BLOB_WRITE`]
//! bit set.
//!
//! Wire format (request map, sec. 6.10.1 Table 19):
//!
//!   0x01 get?                  (optional uint -- max bytes to read)
//!   0x02 set?                  (optional bytes -- chunk being written)
//!   0x03 offset                (uint -- byte offset into the array)
//!   0x04 length?               (optional uint -- total set length, first chunk only)
//!   0x05 pinUvAuthParam?       (optional bytes -- required for writes)
//!   0x06 pinUvAuthProtocol?    (optional uint)
//!
//! Both reads and writes are paged: each call carries at most
//! `getInfo.maxMsgSize - 64` bytes. This module exposes
//! [`read_array`] and [`write_array`] convenience wrappers that
//! do the paging for the caller.

use pqf_cbor::Value;

use crate::hid::Device;

use super::client_pin::PinUvAuth;
use super::get_info::GetInfo;
use super::{cbor_call, map_get_int, want_bytes, want_map, Error, CMD_LARGE_BLOBS};

/// Conservative read chunk -- leaves headroom for the CBOR map
/// overhead inside the CTAPHID 7609-byte message cap.
const READ_CHUNK_DEFAULT: u64 = 1024;

// ---------- Reads ----------

/// Single-call large-blob read: fetch up to `max_fragment_length`
/// bytes starting at `offset`. Returns the bytes the device emits.
/// On `offset = 0`, the device additionally writes the array's
/// total length as the first response -- caller can use that to
/// know how many follow-up reads to issue.
pub fn read_fragment(
    dev: &Device,
    offset: u64,
    max_fragment_length: u64,
) -> Result<Vec<u8>, Error> {
    let req = Value::Map(vec![
        (Value::Uint(0x01), Value::Uint(max_fragment_length)),
        (Value::Uint(0x03), Value::Uint(offset)),
    ]);
    let resp = cbor_call(dev, CMD_LARGE_BLOBS, Some(&req))?
        .ok_or_else(|| Error::Decode("LargeBlobs read returned empty payload".into()))?;
    let map = want_map(&resp, "(top-level)")?;
    let cfg = map_get_int(map, 0x01)
        .ok_or_else(|| Error::Decode("LargeBlobs read: missing 0x01 (config bytes)".into()))?;
    want_bytes(cfg, "largeBlobArray fragment")
}

/// Read the entire large-blob array, paging as needed. Uses the
/// device's `maxMsgSize` from getInfo to size each chunk, falling
/// back to a conservative 1 KiB if unavailable.
pub fn read_array(dev: &Device, info: &GetInfo) -> Result<Vec<u8>, Error> {
    let chunk_size = info
        .max_msg_size
        .map(|m| m.saturating_sub(64).min(2048))
        .unwrap_or(READ_CHUNK_DEFAULT)
        .max(64);
    let total_cap = info
        .max_serialized_large_blob_array
        .unwrap_or(2048)
        .max(1024);
    let mut out: Vec<u8> = Vec::new();
    let mut offset = 0u64;
    loop {
        let want = chunk_size.min(total_cap.saturating_sub(offset));
        if want == 0 {
            break;
        }
        let frag = read_fragment(dev, offset, want)?;
        if frag.is_empty() {
            break;
        }
        let new_len = frag.len();
        out.extend_from_slice(&frag);
        offset += new_len as u64;
        // The device signals end-of-array by emitting a smaller-
        // than-requested fragment.
        if (new_len as u64) < want {
            break;
        }
    }
    Ok(out)
}

// ---------- Writes ----------

/// Write a single fragment to the large-blob array at `offset`.
/// On the first chunk, set `total_length = Some(total)` so the
/// device can pre-validate the final array size; on subsequent
/// chunks pass `None`.
///
/// `auth` is a `pinUvAuthToken` with the `largeBlobWrite` permission
/// bit set; the function computes the `pinUvAuthParam` over the
/// CTAP 2.1 sec. 6.10.5 input: `32 x 0xFF || 0x0c || 0x02 ||
/// offset(LE u32) || SHA-256(set_bytes)`.
pub fn write_fragment(
    dev: &Device,
    auth: &PinUvAuth,
    offset: u64,
    fragment: &[u8],
    total_length: Option<u64>,
) -> Result<(), Error> {
    use sha2::{Digest, Sha256};
    // sec. 6.10.5 binds-to-channel input. The offset is its own 4-byte
    // little-endian field (NOT folded into the digest), and the
    // SHA-256 covers only the `set` fragment bytes:
    //   32 x 0xFF || 0x0c (largeBlobs cmd) || 0x02 ||
    //   offset(LE u32) || SHA-256(set_fragment_bytes)
    let digest = Sha256::digest(fragment);

    let mut auth_input = Vec::with_capacity(32 + 1 + 1 + 4 + 32);
    auth_input.extend_from_slice(&[0xff; 32]);
    auth_input.push(CMD_LARGE_BLOBS);
    auth_input.push(0x02);
    auth_input.extend_from_slice(&(offset as u32).to_le_bytes());
    auth_input.extend_from_slice(&digest);
    let pin_uv_auth_param = auth.sign(&auth_input)?;

    let mut req: Vec<(Value, Value)> = Vec::with_capacity(6);
    req.push((Value::Uint(0x02), Value::Bytes(fragment.to_vec())));
    req.push((Value::Uint(0x03), Value::Uint(offset)));
    if let Some(total) = total_length {
        req.push((Value::Uint(0x04), Value::Uint(total)));
    }
    req.push((Value::Uint(0x05), Value::Bytes(pin_uv_auth_param)));
    req.push((
        Value::Uint(0x06),
        Value::Uint(auth.protocol.as_byte() as u64),
    ));

    let _ = cbor_call(dev, CMD_LARGE_BLOBS, Some(&Value::Map(req)))?;
    Ok(())
}

/// Write the entire large-blob array, paging as needed. The
/// authenticator validates that the bytes form a valid serialised
/// LargeBlobArray (CBOR array tagged with a SHA-256 truncation
/// trailer per sec. 6.10.2); shape that yourself if you're calling
/// this directly. The session helpers in [`crate::session`] will
/// wrap that for you in a later commit.
pub fn write_array(
    dev: &Device,
    auth: &PinUvAuth,
    info: &GetInfo,
    array: &[u8],
) -> Result<(), Error> {
    let chunk_size = info
        .max_msg_size
        .map(|m| m.saturating_sub(64).min(2048))
        .unwrap_or(READ_CHUNK_DEFAULT)
        .max(64) as usize;
    let total = array.len() as u64;
    let mut offset = 0u64;
    let mut sent = 0usize;
    while sent < array.len() {
        let end = (sent + chunk_size).min(array.len());
        let chunk = &array[sent..end];
        let total_first = if sent == 0 { Some(total) } else { None };
        write_fragment(dev, auth, offset, chunk, total_first)?;
        offset += chunk.len() as u64;
        sent = end;
    }
    Ok(())
}
