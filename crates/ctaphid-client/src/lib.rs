// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! `pqf-ctaphid` -- host-side library for talking to CTAP 2.1
//! authenticators over USB HID.
//!
//! This crate is the host counterpart to the firmware that lives in
//! the workspace root. The firmware implements the device side of
//! CTAP 2.1; `pqf-ctaphid` implements the host side and lets a
//! desktop / server program enumerate, register against, and
//! authenticate with FIDO2 / WebAuthn authenticators.
//!
//! # Layering
//!
//! The crate is organised in three layers, bottom-up:
//!
//! 1. **CTAPHID transport** ([`hid`]) -- open a HID device, do the
//!    INIT handshake, frame / reassemble multi-packet messages,
//!    handle KEEPALIVE polling. Implemented against FIDO U2F HID
//!    v1.2 (the canonical CTAPHID framing spec).
//!
//! 2. **CTAP2 commands** ([`ctap2`]) -- encode CBOR request maps,
//!    send via the transport, decode the response CBOR. Implemented
//!    against CTAP 2.1 sec. 6. Every command (0x01-0x0D) has a typed
//!    request struct + a typed response struct.
//!
//! 3. **High-level helpers** ([`session`]) -- `register()` /
//!    `authenticate()` convenience wrappers that chain the
//!    CTAP2 commands together for the common WebAuthn flows.
//!
//! # Specs
//!
//! - FIDO CTAP 2.1, PS-20210615 -- application-layer commands.
//! - FIDO U2F HID v1.2 -- transport framing.
//! - W3C WebAuthn Level 2 -- attestation statement formats, COSE_Key
//!   structures.
//! - RFC 8949 -- CBOR encoding (via the in-tree `pqf-cbor` codec).
//! - RFC 8152 -- COSE algorithm identifiers.
//!
//! # Status
//!
//! v0.1.0 is the workspace + skeleton scaffold. Subsequent commits
//! flesh out [`hid`], [`ctap2`], and [`session`] in that order.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// The `pqf-cbor` construction macros (`cbor_map!`, `cbor_array!`, ...)
// expand to `::alloc::vec::Vec` to stay no_std-friendly for the
// firmware. On the host that crate is implicitly behind `std`;
// pull it in explicitly so the macro paths resolve.
extern crate alloc;

// Re-export the CBOR types so callers don't need to import the
// underlying `pqf_cbor` crate directly when building CTAP2 maps.
pub use pqf_cbor::{cbor_array, cbor_bytes, cbor_int, cbor_map, cbor_text, decode, encode, Value};

pub mod ctap2;
pub mod hid;
pub mod hybrid;
pub mod session;
