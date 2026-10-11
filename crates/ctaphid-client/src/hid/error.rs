// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Transport-layer errors.
//!
//! These are produced by the [`super`] module; the higher
//! application-layer errors (CTAP2 status bytes, malformed CBOR,
//! ...) live in [`crate::ctap2`].

use core::fmt;

/// Anything that can go wrong below the CTAP 2.1 application layer.
#[derive(Debug)]
pub enum Error {
    /// The host's USB-HID layer surfaced an error (device disconnected,
    /// permissions, OS API failure). Wraps the underlying `hidapi`
    /// error message -- we don't translate the text, only re-categorise.
    Transport(String),

    /// No FIDO HID device matched the criteria passed to
    /// [`super::enumerate`] / [`super::Device::open`]. Distinct from
    /// `Transport` because the user-facing action is different
    /// ("plug a security key in" vs. "something's wrong with the
    /// USB stack").
    NoDevice,

    /// Initial-byte BCNT field declared a payload longer than the
    /// CTAPHID maximum (~7.6 KiB per FIDO U2F HID v1.2 sec. 6.2).
    /// Either the authenticator misbehaved or a stray write
    /// scrambled the frame.
    OversizedMessage {
        /// The byte count the init frame advertised.
        announced: usize,
        /// The cap we enforce -- 1 init frame's payload (57 bytes)
        /// plus 128 continuation frames at 59 bytes each.
        max: usize,
    },

    /// A continuation frame arrived with a sequence byte that didn't
    /// match the next expected value. Either a frame was dropped or
    /// a foreign packet bled through (e.g. another process speaking
    /// to the same device).
    SequenceMismatch {
        /// Expected SEQ value (0-based, wraps at 0x80).
        expected: u8,
        /// SEQ value that actually arrived in the frame.
        got: u8,
    },

    /// The CTAPHID INIT response's nonce echo didn't match the nonce
    /// we sent. A different conversation on the broadcast channel
    /// took our slot -- caller can retry.
    NonceMismatch,

    /// Authenticator returned `CTAPHID_ERROR` (cmd 0xBF) with a
    /// one-byte error code. See FIDO U2F HID v1.2 sec. 6.2.4 Table 4.
    /// We preserve the raw byte so callers that need the exact
    /// code (e.g. for retry decisions on `CHANNEL_BUSY`) can switch
    /// on it.
    HidError(u8),

    /// The authenticator wrote less than a full report on a read,
    /// or returned an empty buffer. We expect strictly 64-byte
    /// reports per FIDO U2F HID v1.2 sec. 6.1.
    ShortRead(usize),

    /// We waited [`super::READ_TIMEOUT_MS`] milliseconds without
    /// receiving any frame from the authenticator. Distinct from
    /// `Transport` so callers can re-arm a longer timeout for
    /// commands that may legitimately run for many seconds (e.g.
    /// large-blob writes, on-device key generation).
    Timeout,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(s) => write!(f, "USB HID transport error: {}", s),
            Error::NoDevice => f.write_str("no matching FIDO HID device"),
            Error::OversizedMessage { announced, max } => write!(
                f,
                "CTAPHID init frame announced {announced} bytes, cap is {max}"
            ),
            Error::SequenceMismatch { expected, got } => write!(
                f,
                "CTAPHID continuation seq mismatch: expected {expected}, got {got}"
            ),
            Error::NonceMismatch => f.write_str("CTAPHID INIT nonce echo did not match"),
            Error::HidError(code) => write!(f, "CTAPHID_ERROR response, code 0x{code:02x}"),
            Error::ShortRead(n) => write!(f, "CTAPHID read returned {n} bytes (expected 64)"),
            Error::Timeout => f.write_str("CTAPHID read timed out"),
        }
    }
}

impl std::error::Error for Error {}

impl From<hidapi::HidError> for Error {
    fn from(e: hidapi::HidError) -> Self {
        Error::Transport(e.to_string())
    }
}

/// CTAPHID error codes per FIDO U2F HID v1.2 sec. 6.2.4 Table 4. Returned
/// in the one-byte payload of a `CTAPHID_ERROR` (0xBF) response.
#[allow(missing_docs)]
pub mod hid_err {
    pub const INVALID_CMD: u8 = 0x01;
    pub const INVALID_PAR: u8 = 0x02;
    pub const INVALID_LEN: u8 = 0x03;
    pub const INVALID_SEQ: u8 = 0x04;
    pub const MSG_TIMEOUT: u8 = 0x05;
    pub const CHANNEL_BUSY: u8 = 0x06;
    pub const LOCK_REQUIRED: u8 = 0x0a;
    pub const INVALID_CHANNEL: u8 = 0x0b;
    pub const OTHER: u8 = 0x7f;
}
