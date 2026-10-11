// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorSelection` (CTAP 2.1 sec. 6.9) -- let the client ask
//! the user to confirm *this specific* authenticator.
//!
//! Used during multi-token flows (account-recovery, "tap the right
//! key" UI). The device blocks until the user touches it, then
//! returns status 0x00. No request parameters, no response payload.
//!
//! Some authenticators don't have a user-touch button, in which
//! case they return immediately (the Bruce firmware on the Tiny
//! 2350 returns OK immediately; the Waveshare uses the BOOTSEL
//! button if exposed).

use crate::hid::Device;

use super::{cbor_call, Error, CMD_SELECTION};

/// Send `authenticatorSelection` (command 0x0B). Blocks until the
/// user touches the device (or -- on devices without a user-touch
/// button -- returns immediately with `Ok(())`).
///
/// Spec mandates the authenticator return `Status::UserActionTimeout`
/// after 30 s without a touch; surface that to the user as "try
/// the other key".
pub fn selection(dev: &Device) -> Result<(), Error> {
    let _ = cbor_call(dev, CMD_SELECTION, None)?;
    Ok(())
}
