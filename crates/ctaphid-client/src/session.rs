// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! High-level WebAuthn-style register / authenticate flows.
//!
//! Wraps the low-level CTAP 2.1 command modules into one-shot
//! operations that handle the common ceremonial steps a host
//! application would otherwise need to glue together itself:
//!
//!   1. Run `authenticatorGetInfo` (cached per-`Device`).
//!   2. If the device has a PIN set, prompt for it and mint a
//!      `pinUvAuthToken` with the right permissions and RP-id
//!      scope.
//!   3. Compute the WebAuthn `clientDataHash` from the
//!      caller-supplied challenge + origin + type fields.
//!   4. Issue the CBOR command.
//!   5. Parse `authData` into a structured form so the caller can
//!      pull out the credentialID, sign counter, and COSE_Key
//!      without re-implementing WebAuthn sec. 6.1.
//!
//! The flows are deliberately opinionated:
//!
//!   - `pubKeyCredParams` defaults to all four algs the firmware
//!     supports (-56, -55, -54, -7), in RP-preference order, so
//!     the device picks the strongest PQC option the request
//!     carries (WebAuthn sec. 5.4 leaves alg preference to the caller's
//!     list order).
//!   - PIN auth uses CTAP 2.1 PIN protocol v2 if both v1 and v2
//!     are advertised; v1 is only used on devices that advertise
//!     only v1 (none of the Bruce boards).
//!   - `clientDataHash` follows the WebAuthn sec. 5.10.1 byte-exact
//!     JSON shape: `{"type": ..., "challenge": <b64url>, "origin":
//!     ..., "crossOrigin": false}` with keys in insertion order.
//!
//! Caller is expected to plumb the PIN through a closure rather
//! than hand-handle PIN-protocol setup. See [`PinSource`].

use sha2::{Digest, Sha256};

use crate::ctap2::client_pin::{establish_session, get_pin_uv_auth_token_using_pin, permission};
use crate::ctap2::get_info::GetInfo;
use crate::ctap2::make_credential::{MakeCredentialRequest, MakeCredentialResponse};
use crate::ctap2::pin_protocol::Protocol as PinProtocol;
use crate::ctap2::types::{
    AuthOptions, CredentialDescriptor, PubKeyCredParam, RelyingParty, User, ALG_ES256,
    ALG_HYBRID_MLDSA44, ALG_HYBRID_MLDSA65, ALG_HYBRID_MLDSA87,
};
use crate::ctap2::{client_pin, get_assertion, get_info, make_credential, Error};
use crate::hid::Device;

// ---------- WebAuthn client-data hashing ----------

/// One of the two WebAuthn `clientData.type` strings, per
/// WebAuthn sec. 5.10.1 step 7. Used by [`client_data_hash`] to build
/// the byte-exact JSON the RP server will recompute and compare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebAuthnType {
    /// `"webauthn.create"` -- passed to MakeCredential.
    Create,
    /// `"webauthn.get"` -- passed to GetAssertion.
    Get,
}

impl WebAuthnType {
    fn as_str(self) -> &'static str {
        match self {
            WebAuthnType::Create => "webauthn.create",
            WebAuthnType::Get => "webauthn.get",
        }
    }
}

/// Compute the WebAuthn `clientDataHash` from its three component
/// fields. Serialises a small JSON object byte-exactly the way the
/// browser would and returns SHA-256 of the JSON bytes.
///
/// The JSON shape, per WebAuthn sec. 5.10.1:
///
/// ```text
/// {"type": "<webauthn.create|webauthn.get>",
///  "challenge": "<base64url no-padding of challenge>",
///  "origin": "<origin URL>",
///  "crossOrigin": false}
/// ```
///
/// Insertion order matters because the RP server hashes its own
/// serialisation of the same fields and compares; differing key
/// order yields a different SHA-256.
pub fn client_data_hash(ty: WebAuthnType, challenge: &[u8], origin: &str) -> [u8; 32] {
    let json = build_client_data_json(ty, challenge, origin);
    let h = Sha256::digest(json.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

fn build_client_data_json(ty: WebAuthnType, challenge: &[u8], origin: &str) -> String {
    let mut out = String::with_capacity(96 + origin.len() + challenge.len() * 2);
    out.push_str(r#"{"type":""#);
    out.push_str(ty.as_str());
    out.push_str(r#"","challenge":""#);
    base64url_into(challenge, &mut out);
    out.push_str(r#"","origin":""#);
    json_escape_into(origin, &mut out);
    out.push_str(r#"","crossOrigin":false}"#);
    out
}

/// Append `bytes` to `out` as base64url **without** padding, per
/// WebAuthn sec. 5.10.1 (`base64url(...)` references RFC 4648 sec. 5 with
/// the no-padding variant).
fn base64url_into(bytes: &[u8], out: &mut String) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = bytes[i + 1] as u32;
        let b2 = bytes[i + 2] as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        1 => {
            let n = (bytes[i] as u32) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => {}
    }
}

/// Minimal JSON string escape covering the characters that can
/// appear in a typical RP origin (`"`, `\`, control chars). Origin
/// URLs don't contain `\u` sequences in practice, but we guard
/// against them anyway.
fn json_escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

// ---------- PIN-source callback ----------

/// Provider for the user's PIN, invoked by [`register`] /
/// [`authenticate`] only when the device's `getInfo` shows a PIN
/// is set. Returning `Ok(None)` aborts the flow with
/// [`Error::Ctap(Status::PuatRequired)`] so the caller can
/// distinguish "user declined to enter a PIN" from "device errored".
pub type PinSource = dyn FnMut() -> Result<Option<Vec<u8>>, Error>;

// ---------- Parsed authData ----------

/// Decoded `authenticatorData` structure per WebAuthn sec. 6.1. Returned
/// as part of [`RegisterResponse`] / [`AuthenticateResponse`].
#[derive(Clone, Debug)]
pub struct AuthData {
    /// 32-byte SHA-256 of the RP id.
    pub rp_id_hash: [u8; 32],
    /// `flags` byte: bit 0 = UP, bit 2 = UV, bit 3 = BE, bit 4 = BS,
    /// bit 6 = AT, bit 7 = ED.
    pub flags: u8,
    /// Signature counter (big-endian on the wire, decoded here).
    pub sign_count: u32,
    /// Attested credential data -- present iff flags & 0x40 (AT bit) set.
    /// Always set for MakeCredential responses; absent for
    /// GetAssertion responses.
    pub attested_credential: Option<AttestedCredential>,
    /// Raw extension-data bytes -- present iff flags & 0x80 (ED bit)
    /// set. Left as bytes; callers decode the inner CBOR map themselves.
    pub extensions_cbor: Option<Vec<u8>>,
}

/// `attestedCredentialData` inside `authData` (WebAuthn sec. 6.5.1).
#[derive(Clone, Debug)]
pub struct AttestedCredential {
    /// 16-byte AAGUID.
    pub aaguid: [u8; 16],
    /// Variable-length credential id.
    pub credential_id: Vec<u8>,
    /// Raw COSE_Key bytes (caller decodes via `pqf_cbor::decode`).
    pub credential_public_key_cose: Vec<u8>,
}

impl AuthData {
    /// Parse the raw authData byte string from a MakeCredential or
    /// GetAssertion response.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 37 {
            return Err(Error::Decode(format!(
                "authData too short: {} bytes (need >=37)",
                bytes.len()
            )));
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&bytes[0..32]);
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
        let mut off = 37;
        let attested_credential = if flags & 0x40 != 0 {
            if bytes.len() < off + 16 + 2 {
                return Err(Error::Decode(
                    "authData truncated in attestedCredentialData".into(),
                ));
            }
            let mut aaguid = [0u8; 16];
            aaguid.copy_from_slice(&bytes[off..off + 16]);
            off += 16;
            let cred_id_len = u16::from_be_bytes([bytes[off], bytes[off + 1]]) as usize;
            off += 2;
            if bytes.len() < off + cred_id_len {
                return Err(Error::Decode("authData truncated in credentialID".into()));
            }
            let credential_id = bytes[off..off + cred_id_len].to_vec();
            off += cred_id_len;
            // The remainder is the COSE_Key plus optional extensions.
            // The COSE_Key is one CBOR data item; we decode it just
            // to find its byte length, then keep the bytes.
            let remainder = &bytes[off..];
            let (key_len, _) = scan_cbor_item_length(remainder)?;
            let credential_public_key_cose = remainder[..key_len].to_vec();
            off += key_len;
            Some(AttestedCredential {
                aaguid,
                credential_id,
                credential_public_key_cose,
            })
        } else {
            None
        };
        let extensions_cbor = if flags & 0x80 != 0 {
            Some(bytes[off..].to_vec())
        } else {
            None
        };
        Ok(AuthData {
            rp_id_hash,
            flags,
            sign_count,
            attested_credential,
            extensions_cbor,
        })
    }

    /// Convenience: returns `true` if the User Presence (UP) flag
    /// is set (bit 0).
    pub fn user_present(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Convenience: returns `true` if the User Verified (UV) flag
    /// is set (bit 2).
    pub fn user_verified(&self) -> bool {
        self.flags & 0x04 != 0
    }
}

/// Find the byte length of the first CBOR data item in `buf`.
/// Returns `(item_len, total_bytes_consumed)` -- equal in this
/// minimal scanner since we don't yet support tagged items here.
///
/// In an `authData` with the ED flag (bit 7) set, the COSE_Key is
/// followed by the extensions map (WebAuthn sec. 6.1), so `buf` here is
/// `COSE_Key || extensions_map`. `pqf_cbor::decode` is a
/// whole-buffer decoder that rejects any leftover bytes with
/// `Error::Trailing`, so we cannot hand it the full slice and
/// measure the result. Instead we locate the COSE_Key as the
/// shortest prefix of `buf` that decodes cleanly: that prefix is
/// exactly the first data item, and the remaining bytes are the
/// extensions map the caller keeps verbatim.
fn scan_cbor_item_length(buf: &[u8]) -> Result<(usize, usize), Error> {
    // Fast path: the whole buffer is a single item (no ED flag, so
    // no trailing extensions map). Decode + re-encode confirms the
    // length and that the input is canonical.
    match pqf_cbor::decode(buf) {
        Ok(v) => {
            let mut re = Vec::new();
            pqf_cbor::encode(&v, &mut re);
            if re.len() == buf.len() {
                return Ok((buf.len(), buf.len()));
            }
            // Re-encode shorter than the input would mean a
            // non-canonical first item; canonical CTAP CBOR never
            // hits this, but downgrade safely by consuming all.
            return Ok((buf.len(), buf.len()));
        }
        Err(pqf_cbor::Error::Trailing) => {
            // Bytes remain after the first item -- the ED-flag case.
            // Fall through to the prefix search below.
        }
        Err(e) => {
            return Err(Error::Decode(format!("authData COSE_Key CBOR: {e:?}")));
        }
    }

    // Grow a prefix until it decodes to exactly one item. The COSE_Key
    // is the first item, so the shortest `len` for which `decode`
    // returns `Ok` (rather than `Truncated`) marks its boundary. Any
    // other decode error on a complete prefix is a genuinely malformed
    // COSE_Key and is surfaced.
    let mut len = 1;
    while len <= buf.len() {
        match pqf_cbor::decode(&buf[..len]) {
            Ok(v) => {
                // Confirm the boundary with the canonical re-encode
                // trick on just the consumed prefix.
                let mut re = Vec::new();
                pqf_cbor::encode(&v, &mut re);
                if re.len() == len {
                    return Ok((len, len));
                }
                // Non-canonical COSE_Key: keep the measured prefix
                // length anyway (re-encode only differs in length for
                // non-canonical inputs, which CTAP authenticators
                // don't emit).
                return Ok((len, len));
            }
            // Still inside the first item -- need more bytes.
            Err(pqf_cbor::Error::Truncated) => len += 1,
            // A complete-but-invalid prefix means the COSE_Key itself
            // is malformed.
            Err(e) => {
                return Err(Error::Decode(format!("authData COSE_Key CBOR: {e:?}")));
            }
        }
    }
    Err(Error::Decode(
        "authData COSE_Key CBOR: no complete item before end of buffer".into(),
    ))
}

// ---------- Register flow ----------

/// Caller-supplied options for [`register`]. Everything except `rp`,
/// `user`, and `challenge` has a sensible default.
pub struct RegisterRequest<'a> {
    /// Relying party. `rp.id` becomes the rpIdHash bound into the
    /// credential.
    pub rp: RelyingParty,
    /// User entity being registered.
    pub user: User,
    /// The challenge bytes the RP server provided. Embedded in
    /// `clientData.challenge` (base64url) before hashing.
    pub challenge: &'a [u8],
    /// `clientData.origin` -- typically the RP's origin URL
    /// (`https://example.com`).
    pub origin: &'a str,
    /// Override `pubKeyCredParams` if you need a non-default set.
    /// `None` (default) lists all four algs the firmware supports
    /// in RP-preference order: `-56, -55, -54, -7` (the
    /// `ctap2::types::ALG_HYBRID_*` constants, then ES256).
    pub pub_key_cred_params: Option<Vec<PubKeyCredParam>>,
    /// `excludeList` -- credentials the RP knows about; the device
    /// will refuse to register over them.
    pub exclude_list: Option<Vec<CredentialDescriptor>>,
    /// `options` -- typically `rk = Some(true)` for a passkey flow.
    /// Default: empty.
    pub options: AuthOptions,
}

/// Result of a successful [`register`] call.
#[derive(Clone, Debug)]
pub struct RegisterResponse {
    /// Raw MakeCredential response from the device.
    pub raw: MakeCredentialResponse,
    /// Parsed `authData` for caller convenience.
    pub auth_data: AuthData,
    /// The `clientDataJSON` we computed and hashed. RP servers
    /// typically want this verbatim so they can re-verify the hash.
    pub client_data_json: String,
}

/// One-shot MakeCredential flow.
///
/// Calls getInfo to check PIN state, mints a `pinUvAuthToken` via
/// `client_pin` when needed, builds the clientDataHash, sends
/// MakeCredential, parses authData.
pub fn register(
    dev: &Device,
    req: &RegisterRequest<'_>,
    pin_source: &mut PinSource,
) -> Result<RegisterResponse, Error> {
    let info = get_info::get_info(dev)?;
    let cdj = build_client_data_json(WebAuthnType::Create, req.challenge, req.origin);
    let cdh = sha256(cdj.as_bytes());

    let pub_key_cred_params = req
        .pub_key_cred_params
        .clone()
        .unwrap_or_else(default_pub_key_cred_params);

    let (pin_uv_auth_param, pin_uv_auth_protocol) = maybe_mint_token(
        dev,
        &info,
        pin_source,
        &cdh,
        permission::MAKE_CREDENTIAL,
        &req.rp.id,
    )?;

    let mc = MakeCredentialRequest {
        client_data_hash: cdh,
        rp: req.rp.clone(),
        user: req.user.clone(),
        pub_key_cred_params,
        exclude_list: req.exclude_list.clone(),
        extensions: None,
        options: if req.options.is_empty() {
            None
        } else {
            Some(req.options.clone())
        },
        pin_uv_auth_param,
        pin_uv_auth_protocol,
        enterprise_attestation: None,
    };
    let raw = make_credential::make_credential(dev, &mc)?;
    let auth_data = AuthData::parse(&raw.auth_data)?;
    Ok(RegisterResponse {
        raw,
        auth_data,
        client_data_json: cdj,
    })
}

// ---------- Authenticate flow ----------

/// Caller-supplied options for [`authenticate`].
pub struct AuthenticateRequest<'a> {
    /// `rpId` the credential was registered against.
    pub rp_id: String,
    /// Challenge bytes from the RP server.
    pub challenge: &'a [u8],
    /// `clientData.origin`.
    pub origin: &'a str,
    /// `allowList` -- restrict assertion to one of these credential
    /// ids. None / empty means "passwordless / any resident
    /// credential for this RP".
    pub allow_list: Option<Vec<CredentialDescriptor>>,
    /// `options` -- typically `up = Some(true)`. Default: empty.
    pub options: AuthOptions,
}

/// Result of a successful [`authenticate`] call.
#[derive(Clone, Debug)]
pub struct AuthenticateResponse {
    /// Raw GetAssertion response from the device.
    pub raw: get_assertion::GetAssertionResponse,
    /// Parsed `authData`.
    pub auth_data: AuthData,
    /// `clientDataJSON` for RP-side re-verification.
    pub client_data_json: String,
}

/// One-shot GetAssertion flow.
pub fn authenticate(
    dev: &Device,
    req: &AuthenticateRequest<'_>,
    pin_source: &mut PinSource,
) -> Result<AuthenticateResponse, Error> {
    let info = get_info::get_info(dev)?;
    let cdj = build_client_data_json(WebAuthnType::Get, req.challenge, req.origin);
    let cdh = sha256(cdj.as_bytes());

    let (pin_uv_auth_param, pin_uv_auth_protocol) = maybe_mint_token(
        dev,
        &info,
        pin_source,
        &cdh,
        permission::GET_ASSERTION,
        &req.rp_id,
    )?;

    let ga = get_assertion::GetAssertionRequest {
        rp_id: req.rp_id.clone(),
        client_data_hash: cdh,
        allow_list: req.allow_list.clone(),
        extensions: None,
        options: if req.options.is_empty() {
            None
        } else {
            Some(req.options.clone())
        },
        pin_uv_auth_param,
        pin_uv_auth_protocol,
    };
    let raw = get_assertion::get_assertion(dev, &ga)?;
    let auth_data = AuthData::parse(&raw.auth_data)?;
    Ok(AuthenticateResponse {
        raw,
        auth_data,
        client_data_json: cdj,
    })
}

// ---------- Shared internals ----------

/// Pick the PIN protocol to use: prefer v2 if the device advertises
/// it, fall back to v1 otherwise. Both Bruce boards advertise
/// `[1, 2]`, so v2 is the typical pick.
fn pick_pin_protocol(info: &GetInfo) -> Option<PinProtocol> {
    let protos = info.pin_uv_auth_protocols.as_ref()?;
    if protos.contains(&2) {
        Some(PinProtocol::V2)
    } else if protos.contains(&1) {
        Some(PinProtocol::V1)
    } else {
        None
    }
}

/// Mint a `pinUvAuthToken` and HMAC the clientDataHash with it,
/// only when the device has a PIN set. Returns `(None, None)` if
/// no PIN auth is needed.
///
/// `permission_bits` is the OR of permission constants for the
/// operation being authorised; `rp_id` scopes the token (CTAP 2.1
/// sec. 6.5.5.7 strongly recommends this).
fn maybe_mint_token(
    dev: &Device,
    info: &GetInfo,
    pin_source: &mut PinSource,
    client_data_hash: &[u8; 32],
    permission_bits: u8,
    rp_id: &str,
) -> Result<(Option<Vec<u8>>, Option<u64>), Error> {
    if !info.pin_set() {
        return Ok((None, None));
    }
    let proto = pick_pin_protocol(info).ok_or_else(|| {
        Error::Decode("device has PIN but no pinUvAuthProtocol advertised".into())
    })?;
    let session = establish_session(dev, proto)?;
    let pin = pin_source()?.ok_or_else(|| {
        // Device requires PIN, user declined -> surface as PUAT
        // required so callers can distinguish from device errors.
        Error::Ctap(crate::ctap2::Status::PuatRequired)
    })?;
    let auth = get_pin_uv_auth_token_using_pin(dev, session, &pin, permission_bits, Some(rp_id))?;
    let pin_uv_auth_param = auth.sign(client_data_hash)?;
    Ok((
        Some(pin_uv_auth_param),
        Some(auth.protocol.as_byte() as u64),
    ))
}

/// Default `pubKeyCredParams`: all four algs the firmware supports,
/// in strongest-to-weakest order. The firmware-side picker prefers
/// the first hybrid PQC alg the request carries; this ordering
/// offers the strongest available PQC suite first while keeping
/// ES256 (-7) as the ultimate fallback for hosts that only
/// negotiate the classical alg (WebAuthn sec. 5.4 honours list order).
fn default_pub_key_cred_params() -> Vec<PubKeyCredParam> {
    vec![
        PubKeyCredParam::new(ALG_HYBRID_MLDSA87),
        PubKeyCredParam::new(ALG_HYBRID_MLDSA65),
        PubKeyCredParam::new(ALG_HYBRID_MLDSA44),
        PubKeyCredParam::new(ALG_ES256),
    ]
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let h = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

// Keep `client_pin` named in `use` even if Rust thinks it's unused --
// some helpers above reference module-level items through the
// `client_pin::permission` path.
const _: fn() = || {
    let _ = client_pin::permission::MAKE_CREDENTIAL;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_no_padding() {
        let mut out = String::new();
        base64url_into(b"foo", &mut out);
        assert_eq!(out, "Zm9v"); // length 3 -> 4 chars, no padding.
        let mut out = String::new();
        base64url_into(b"foob", &mut out);
        assert_eq!(out, "Zm9vYg"); // length 4 -> 6 chars (no = pad).
        let mut out = String::new();
        base64url_into(b"fooba", &mut out);
        assert_eq!(out, "Zm9vYmE"); // length 5 -> 7 chars.
    }

    #[test]
    fn client_data_json_shape() {
        let json =
            build_client_data_json(WebAuthnType::Create, b"\x01\x02\x03", "https://example.com");
        // Byte-exact shape WebAuthn sec. 5.10.1 mandates: type ->
        // challenge -> origin -> crossOrigin, no spaces.
        assert_eq!(
            json,
            r#"{"type":"webauthn.create","challenge":"AQID","origin":"https://example.com","crossOrigin":false}"#
        );
    }

    #[test]
    fn auth_data_with_attested_cred_and_extensions() {
        use pqf_cbor::Value;
        // Build authData = rpIdHash(32) || flags || signCount(4) ||
        // aaguid(16) || credIdLen(2) || credId || COSE_Key ||
        // extensions_map, with both AT (0x40) and ED (0x80) set.
        let cose = Value::Map(vec![
            (Value::int(1), Value::int(2)),                 // kty: EC2
            (Value::int(3), Value::int(-7)),                // alg: ES256
            (Value::int(-1), Value::int(1)),                // crv: P-256
            (Value::int(-2), Value::Bytes(vec![0xAA; 32])), // x
            (Value::int(-3), Value::Bytes(vec![0xBB; 32])), // y
        ]);
        let mut cose_bytes = Vec::new();
        pqf_cbor::encode(&cose, &mut cose_bytes);

        let ext = Value::Map(vec![(Value::Text("credProtect".into()), Value::int(2))]);
        let mut ext_bytes = Vec::new();
        pqf_cbor::encode(&ext, &mut ext_bytes);

        let cred_id = vec![0x11u8; 20];

        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]); // rpIdHash
        buf.push(0x40 | 0x80 | 0x01); // AT | ED | UP
        buf.extend_from_slice(&3u32.to_be_bytes()); // signCount
        buf.extend_from_slice(&[0x42u8; 16]); // aaguid
        buf.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(&cred_id);
        buf.extend_from_slice(&cose_bytes);
        buf.extend_from_slice(&ext_bytes);

        let ad = AuthData::parse(&buf).unwrap();
        assert_eq!(ad.sign_count, 3);
        let att = ad.attested_credential.expect("AT flag set");
        assert_eq!(att.aaguid, [0x42u8; 16]);
        assert_eq!(att.credential_id, cred_id);
        // COSE_Key must stop exactly at the extensions boundary.
        assert_eq!(att.credential_public_key_cose, cose_bytes);
        // Extensions map must be carried through verbatim.
        assert_eq!(ad.extensions_cbor.as_deref(), Some(ext_bytes.as_slice()));
    }

    #[test]
    fn auth_data_attested_cred_no_extensions() {
        use pqf_cbor::Value;
        // AT set, ED clear: COSE_Key is the entire trailing slice.
        let cose = Value::Map(vec![
            (Value::int(1), Value::int(2)),
            (Value::int(3), Value::int(-7)),
            (Value::int(-1), Value::int(1)),
            (Value::int(-2), Value::Bytes(vec![0xAA; 32])),
            (Value::int(-3), Value::Bytes(vec![0xBB; 32])),
        ]);
        let mut cose_bytes = Vec::new();
        pqf_cbor::encode(&cose, &mut cose_bytes);
        let cred_id = vec![0x11u8; 20];

        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0x40 | 0x01); // AT | UP, no ED
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(&[0x42u8; 16]);
        buf.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(&cred_id);
        buf.extend_from_slice(&cose_bytes);

        let ad = AuthData::parse(&buf).unwrap();
        let att = ad.attested_credential.expect("AT flag set");
        assert_eq!(att.credential_public_key_cose, cose_bytes);
        assert!(ad.extensions_cbor.is_none());
    }

    #[test]
    fn auth_data_minimum_size() {
        // Exactly 37 bytes -- rpIdHash + flags + signCount with no
        // attested cred data and no extensions.
        let mut buf = [0u8; 37];
        buf[32] = 0x01; // UP only.
        buf[33..37].copy_from_slice(&7u32.to_be_bytes());
        let ad = AuthData::parse(&buf).unwrap();
        assert_eq!(ad.flags, 0x01);
        assert!(ad.user_present());
        assert!(!ad.user_verified());
        assert_eq!(ad.sign_count, 7);
        assert!(ad.attested_credential.is_none());
        assert!(ad.extensions_cbor.is_none());
    }
}
