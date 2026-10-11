// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `authenticatorGetNextAssertion` (CTAP 2.1 sec. 6.3) -- fetch the next
//! credential's assertion after a `GetAssertion` reported more than
//! one match.
//!
//! No request parameters. The response uses the same shape as the
//! `GetAssertion` response -- we delegate parsing to
//! [`super::get_assertion::parse_assertion`].
//!
//! Typical usage:
//!
//! 1. Call `GetAssertion` without an `allowList` (or with a list
//!    that matches multiple resident creds for the RP).
//! 2. Inspect `response.number_of_credentials`. If it's `Some(n)`
//!    with `n > 1`, call `get_next_assertion` `n - 1` more times,
//!    each within 30 seconds of the previous reply (the device
//!    holds the iterator in volatile state and the spec mandates
//!    a 30-second stale-state timeout).

use crate::hid::Device;

use super::get_assertion::{parse_assertion, GetAssertionResponse};
use super::{cbor_call, Error, CMD_GET_NEXT_ASSERTION};

/// Send `authenticatorGetNextAssertion` (command 0x08). The
/// returned shape matches that of [`super::get_assertion`], so the
/// caller can stack the results into a single `Vec<...>`.
pub fn get_next_assertion(dev: &Device) -> Result<GetAssertionResponse, Error> {
    let resp = cbor_call(dev, CMD_GET_NEXT_ASSERTION, None)?
        .ok_or_else(|| Error::Decode("GetNextAssertion returned empty payload".into()))?;
    parse_assertion(&resp)
}
