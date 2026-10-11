// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorReset` (CTAP 2.1 sec. 6.5) -- wipe every credential,
//! the PIN, the per-device master keys, and the alwaysUv flag.
//!
//! No request parameters. The authenticator returns an empty
//! payload with status 0x00 on success.
//!
//! Spec note: the authenticator MUST require user presence
//! AND a recent power-up (within 10 seconds typically) before
//! accepting reset. If the call returns `Status::OperationDenied`
//! or `Status::UserActionTimeout`, replug the device and retry
//! within the 10 s window.

use crate::hid::Device;

use super::{cbor_call, Error, CMD_RESET};

/// Send `authenticatorReset` (command 0x07). The function returns
/// `Ok(())` on success; the device's persistent state is gone.
///
/// The user-experience side of this is intentionally manual on the
/// host. After the call returns the device's PIN, all resident
/// credentials, all large blobs, and the per-device key-handle keys
/// have been overwritten. Any previously-issued credentialIDs that
/// the RP server still holds will fail to decrypt and the device
/// will respond with `NoCredentials` to GetAssertion. There is no
/// rollback.
pub fn reset(dev: &Device) -> Result<(), Error> {
    let _ = cbor_call(dev, CMD_RESET, None)?;
    Ok(())
}
