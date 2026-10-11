// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP 2.1 status codes and the host-side `Error` type.
//!
//! CTAP2 wraps every response in a single leading status byte
//! followed by an optional CBOR-encoded payload. A status byte of
//! `0x00` (`CTAP2_OK`) means "success"; anything else means the
//! request failed, and the rest of the response is undefined.
//!
//! Reference: CTAP 2.1 sec. 6 Table 1 ("Status code definitions").
//! The full set is preserved here so callers that need exact-
//! variant handling (e.g. "retry on PIN_INVALID, give up on
//! NO_CREDENTIALS") can switch on [`Status`].

use core::fmt;

use crate::hid;

/// Wire-level CTAP2 status codes per CTAP 2.1 sec. 6 Table 1.
///
/// The numeric discriminants are the bytes that appear on the wire,
/// so `Status::Ok as u8 == 0x00`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Status {
    Ok = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0a,
    InvalidChannel = 0x0b,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    FpDatabaseFull = 0x17,
    LargeBlobStorageFull = 0x18,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UserActionPending = 0x23,
    OperationPending = 0x24,
    NoOperations = 0x25,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    NotBusy = 0x29,
    NoOperationPending = 0x2a,
    UnsupportedOption = 0x2b,
    InvalidOption = 0x2c,
    KeepaliveCancel = 0x2d,
    NoCredentials = 0x2e,
    UserActionTimeout = 0x2f,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x35,
    PuatRequired = 0x36,
    PinPolicyViolation = 0x37,
    // 0x38 reserved.
    RequestTooLarge = 0x39,
    ActionTimeout = 0x3a,
    UpRequired = 0x3b,
    UvBlocked = 0x3c,
    IntegrityFailure = 0x3d,
    InvalidSubcommand = 0x3e,
    UvInvalid = 0x3f,
    UnauthorizedPermission = 0x40,
    Other = 0x7f,
    SpecLast = 0xdf,
    ExtensionFirst = 0xe0,
    ExtensionLast = 0xef,
    VendorFirst = 0xf0,
    VendorLast = 0xff,
}

impl Status {
    /// Decode a raw response byte into [`Status`]. Unknown values
    /// land in [`Status::Other`] so callers can still surface them
    /// as errors without panicking.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Status::Ok,
            0x01 => Status::InvalidCommand,
            0x02 => Status::InvalidParameter,
            0x03 => Status::InvalidLength,
            0x04 => Status::InvalidSeq,
            0x05 => Status::Timeout,
            0x06 => Status::ChannelBusy,
            0x0a => Status::LockRequired,
            0x0b => Status::InvalidChannel,
            0x11 => Status::CborUnexpectedType,
            0x12 => Status::InvalidCbor,
            0x14 => Status::MissingParameter,
            0x15 => Status::LimitExceeded,
            0x17 => Status::FpDatabaseFull,
            0x18 => Status::LargeBlobStorageFull,
            0x19 => Status::CredentialExcluded,
            0x21 => Status::Processing,
            0x22 => Status::InvalidCredential,
            0x23 => Status::UserActionPending,
            0x24 => Status::OperationPending,
            0x25 => Status::NoOperations,
            0x26 => Status::UnsupportedAlgorithm,
            0x27 => Status::OperationDenied,
            0x28 => Status::KeyStoreFull,
            0x29 => Status::NotBusy,
            0x2a => Status::NoOperationPending,
            0x2b => Status::UnsupportedOption,
            0x2c => Status::InvalidOption,
            0x2d => Status::KeepaliveCancel,
            0x2e => Status::NoCredentials,
            0x2f => Status::UserActionTimeout,
            0x30 => Status::NotAllowed,
            0x31 => Status::PinInvalid,
            0x32 => Status::PinBlocked,
            0x33 => Status::PinAuthInvalid,
            0x34 => Status::PinAuthBlocked,
            0x35 => Status::PinNotSet,
            0x36 => Status::PuatRequired,
            0x37 => Status::PinPolicyViolation,
            0x39 => Status::RequestTooLarge,
            0x3a => Status::ActionTimeout,
            0x3b => Status::UpRequired,
            0x3c => Status::UvBlocked,
            0x3d => Status::IntegrityFailure,
            0x3e => Status::InvalidSubcommand,
            0x3f => Status::UvInvalid,
            0x40 => Status::UnauthorizedPermission,
            0x7f => Status::Other,
            0xdf => Status::SpecLast,
            0xe0 => Status::ExtensionFirst,
            0xef => Status::ExtensionLast,
            0xf0 => Status::VendorFirst,
            0xff => Status::VendorLast,
            _ => Status::Other,
        }
    }
}

/// Failure modes from an end-to-end CTAP2 call.
///
/// Three categories:
///
/// 1. [`Error::Hid`] -- the transport layer failed (cable yanked,
///    `CTAPHID_ERROR` returned, frame parsing went sideways).
///    The CTAP2 conversation never reached the authenticator's
///    application layer.
///
/// 2. [`Error::Ctap`] -- the conversation reached the application
///    layer and the authenticator rejected it with a non-zero
///    status byte. Carries the structured [`Status`].
///
/// 3. [`Error::Decode`] -- the authenticator answered `OK` but the
///    response CBOR didn't match what we expected (missing
///    required field, wrong type, ...). Almost always a firmware
///    bug; surface as a debug print and file an issue.
#[derive(Debug)]
pub enum Error {
    /// Transport-layer failure. See [`hid::Error`].
    Hid(hid::Error),

    /// Application-layer rejection from the authenticator. The byte
    /// is preserved so callers can decode it via [`Status::from_byte`]
    /// or compare against the wire value directly.
    Ctap(Status),

    /// Response CBOR didn't match the spec -- either we couldn't
    /// parse it, or a required field was missing / had the wrong
    /// type. The string is a human-readable hint for the
    /// developer.
    Decode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Hid(e) => write!(f, "CTAPHID transport: {e}"),
            Error::Ctap(s) => write!(f, "CTAP2 status {:?} (0x{:02x})", s, *s as u8),
            Error::Decode(msg) => write!(f, "CTAP2 response decode: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<hid::Error> for Error {
    fn from(e: hid::Error) -> Self {
        Error::Hid(e)
    }
}
