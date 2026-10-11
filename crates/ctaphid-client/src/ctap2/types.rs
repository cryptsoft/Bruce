// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! WebAuthn / CTAP 2.1 common types referenced by multiple commands.
//!
//! The CTAP map field names are spelled by integer keys on the wire
//! and by WebAuthn string keys inside nested maps (rp, user,
//! pubKeyCredParams entries, ...). These Rust types are the host-side
//! mirror -- strongly typed structs the caller fills in, encoded to
//! the spec-defined CBOR shape by the request builders in each
//! command module.

use pqf_cbor::{cbor_map, cbor_text, Value};

// ---------- COSE algorithm identifiers (RFC 8152 sec. 8) ----------

/// COSE alg id for ECDSA over P-256 with SHA-256.
pub const ALG_ES256: i64 = -7;
/// COSE alg id for EdDSA over Curve25519. Defined in RFC 8152 sec. 8.2.
pub const ALG_ED25519: i64 = -8;
// The composite PQ/T ids for the hybrid (ECDSA + ML-DSA) credentials,
// as requested in draft-ietf-jose-pq-composite-sigs-04. Provisional
// until IANA registers them, so each level is one named constant and a
// relabel is a one-line change per level. This host crate cannot link
// the firmware's definition (pqf_signer_core::mldsa_alg), so it keeps
// its own copy; the two must agree. -51/-52/-53, requested by draft
// -02, now belong to ESP384 / ESP512 / Ed448 (RFC 9864) and are NOT
// hybrid ids.

/// COSE alg id for ML-DSA-44 hybrid (composite MLDSA44-ES256).
pub const ALG_HYBRID_MLDSA44: i64 = -54;
/// COSE alg id for ML-DSA-65 hybrid (composite MLDSA65-ES256).
pub const ALG_HYBRID_MLDSA65: i64 = -55;
/// COSE alg id for ML-DSA-87 hybrid (composite MLDSA87-ES384; the
/// firmware pairs ML-DSA-87 with P-256).
pub const ALG_HYBRID_MLDSA87: i64 = -56;

// ---------- Relying party / user entities ----------

/// `PublicKeyCredentialRpEntity` per WebAuthn sec. 5.4.2 -- the relying
/// party making the request. CTAP MakeCredential 0x02 carries one.
#[derive(Clone, Debug)]
pub struct RelyingParty {
    /// `rp.id` -- the RP's effective domain, e.g. `"example.com"`.
    /// Used as the RP-id-hash that's bound into the credential.
    pub id: String,
    /// `rp.name` -- human-readable name. Optional; only used in
    /// UI on the authenticator (e.g. credential management
    /// browsers).
    pub name: Option<String>,
}

impl RelyingParty {
    pub(crate) fn to_cbor(&self) -> Value {
        let mut m: alloc_compat::Vec<(Value, Value)> = alloc_compat::Vec::new();
        m.push((cbor_text!("id"), cbor_text!(self.id.clone())));
        if let Some(ref name) = self.name {
            m.push((cbor_text!("name"), cbor_text!(name.clone())));
        }
        Value::Map(m)
    }
}

/// `PublicKeyCredentialUserEntity` per WebAuthn sec. 5.4.3 -- identifies
/// the user account being registered. The authenticator stores
/// these strings (id, name, displayName) verbatim for resident
/// credentials and returns them on `GetAssertion`.
#[derive(Clone, Debug)]
pub struct User {
    /// Opaque user-handle, 1..=64 bytes. Spec: the RP picks this
    /// and treats it as the primary key for the credential
    /// server-side. Never user-readable.
    pub id: Vec<u8>,
    /// `user.name` -- typically a username / email. Optional.
    pub name: Option<String>,
    /// `user.displayName` -- friendly name shown in UI. Optional.
    pub display_name: Option<String>,
}

impl User {
    pub(crate) fn to_cbor(&self) -> Value {
        let mut m: alloc_compat::Vec<(Value, Value)> = alloc_compat::Vec::new();
        m.push((cbor_text!("id"), Value::Bytes(self.id.clone())));
        if let Some(ref name) = self.name {
            m.push((cbor_text!("name"), cbor_text!(name.clone())));
        }
        if let Some(ref display_name) = self.display_name {
            m.push((cbor_text!("displayName"), cbor_text!(display_name.clone())));
        }
        Value::Map(m)
    }
}

/// `PublicKeyCredentialParameters` entry -- one `(type, alg)` pair
/// in the RP's list of acceptable credential algorithms.
/// WebAuthn sec. 5.3 / CTAP 2.1 sec. 6.1.1 `pubKeyCredParams`.
#[derive(Clone, Debug)]
pub struct PubKeyCredParam {
    /// COSE algorithm identifier. Typically [`ALG_ES256`] (-7) or
    /// one of the hybrid PQC variants.
    pub alg: i64,
}

impl PubKeyCredParam {
    /// Construct an entry. `type` is always `"public-key"` per CTAP
    /// 2.1 sec. 6.1.1; we don't expose it as a field because there's
    /// only one valid value.
    pub fn new(alg: i64) -> Self {
        Self { alg }
    }

    pub(crate) fn to_cbor(&self) -> Value {
        cbor_map! {
            "alg" => self.alg,
            "type" => "public-key",
        }
    }
}

/// `PublicKeyCredentialDescriptor` -- names an existing credential
/// by its credentialID (and optionally the transports the device
/// supports). WebAuthn sec. 5.10.3 / CTAP 2.1 sec. 6.1.1 `excludeList`
/// and `allowList` entries.
#[derive(Clone, Debug)]
pub struct CredentialDescriptor {
    /// 145-byte (or whatever the authenticator emitted) credential
    /// id, raw bytes.
    pub id: Vec<u8>,
    /// Transports the RP knows the credential is available on.
    /// Optional; CTAP authenticators ignore this field, it's a
    /// hint for the client.
    pub transports: Option<Vec<String>>,
}

impl CredentialDescriptor {
    pub(crate) fn to_cbor(&self) -> Value {
        let mut m: alloc_compat::Vec<(Value, Value)> = alloc_compat::Vec::new();
        m.push((cbor_text!("id"), Value::Bytes(self.id.clone())));
        m.push((cbor_text!("type"), cbor_text!("public-key")));
        if let Some(ref t) = self.transports {
            let arr: alloc_compat::Vec<Value> = t.iter().map(|s| cbor_text!(s.clone())).collect();
            m.push((cbor_text!("transports"), Value::Array(arr)));
        }
        Value::Map(m)
    }
}

/// MakeCredential / GetAssertion `options` map (CTAP 2.1 sec. 6.1.1 /
/// sec. 6.2.1). The keys are tri-state (absent / true / false), so each
/// field is `Option<bool>` rather than `bool`.
#[derive(Clone, Debug, Default)]
pub struct AuthOptions {
    /// `rk` -- request a resident (server-side discoverable)
    /// credential. MakeCredential only.
    pub rk: Option<bool>,
    /// `up` -- require user presence (a button press / touch).
    /// Defaults to true at the device.
    pub up: Option<bool>,
    /// `uv` -- require user verification (PIN / biometric).
    pub uv: Option<bool>,
}

impl AuthOptions {
    /// `true` when no fields are set -- caller can skip emitting
    /// the options map entirely.
    pub fn is_empty(&self) -> bool {
        self.rk.is_none() && self.up.is_none() && self.uv.is_none()
    }

    pub(crate) fn to_cbor(&self) -> Value {
        let mut m: alloc_compat::Vec<(Value, Value)> = alloc_compat::Vec::new();
        // Spec map order is fixed (rk, up, uv) and the authenticator
        // must accept any subset of these keys. `pqf-cbor` reorders
        // canonically on emission so the source order here doesn't
        // matter for the wire bytes.
        if let Some(v) = self.rk {
            m.push((cbor_text!("rk"), Value::Bool(v)));
        }
        if let Some(v) = self.up {
            m.push((cbor_text!("up"), Value::Bool(v)));
        }
        if let Some(v) = self.uv {
            m.push((cbor_text!("uv"), Value::Bool(v)));
        }
        Value::Map(m)
    }
}

// ---------- Tiny compat module ----------
//
// The methods above use `Vec<...>` builders that need to live in
// `alloc::vec::Vec` so the `pqf_cbor::cbor_map!` macro accepts them.
// On the host, that's just `std::vec::Vec` -- but the macro expansion
// uses `::alloc::vec::Vec` to stay no_std-friendly for the firmware.
// Re-exporting under `alloc_compat` keeps this file readable.

#[allow(missing_docs)]
mod alloc_compat {
    pub use std::vec::Vec;
}
