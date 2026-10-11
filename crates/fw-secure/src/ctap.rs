// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! M4e -- CTAP2 MakeCredential / GetAssertion, handled Secure-side.
//!
//! The M4c veneers proved the key never crosses the boundary, but spoke
//! a private binary protocol, so no real client could drive them. These
//! build the actual CTAP2 responses.
//!
//! The split follows design point 1: NS parses the request CBOR -- the
//! historical CVE surface -- and hands over a fixed-layout struct of
//! copied values. Secure hashes the rp id, derives the key, builds
//! `authData` and signs. Nothing Secure touches is a pointer into
//! memory NS can still write.
//!
//! `authData` is built here, not in NS, because it is the thing being
//! signed: an NS-built `authData` would let NS choose what a Secure key
//! attests to.

use crate::cborw::Writer;
use pqf_signer_core::mldsa_alg::{MLDSA_PK_LEN, MLDSA_SIG_LEN};

/// Buffer sizes, derived from the compiled ML-DSA level rather than
/// guessed, so switching level cannot silently overflow a response.
pub const MLDSA_PK_MAX: usize = MLDSA_PK_LEN;
/// ECDSA DER (<=72) plus the ML-DSA signature.
pub const SIG_MAX: usize = 80 + MLDSA_SIG_LEN;
/// authData: rpIdHash + flags + counter + AAGUID + idLen + credId +
/// COSE key (which for a hybrid credential carries the ML-DSA key) +
/// the extension map.
///
/// The extension allowance is deliberate rather than incidental: a
/// registration can carry credBlob (32), credProtect, hmac-secret and
/// minPinLength at once, with their CBOR keys. The old 128 bytes of
/// slack covered the COSE encoding alone and silently overflowed the
/// moment extensions landed on a hybrid credential -- which showed up
/// as MakeCredential failing only for ML-DSA, only with extensions.
const EXT_MAX: usize = 192;
pub const AUTH_MAX: usize = 32 + 1 + 4 + 16 + 2 + 64 + 128 + EXT_MAX + MLDSA_PK_MAX;
/// Whole response: status + CBOR wrapper + the largest of the above.
pub const RESP_MAX: usize = 128 + AUTH_MAX + SIG_MAX;

/// COSE algorithm identifier for the composite PQ/T construction at
/// this build's ML-DSA level. Taken from the one definition the FIDO
/// firmware also uses (`pqf_signer_core::mldsa_alg`, -54/-55/-56 for
/// ML-DSA-44/65/87 paired with ECDSA), so a credential means the same
/// thing on both images and a relabel cannot leave them apart.
pub const COSE_ALG_HYBRID: i64 = pqf_signer_core::mldsa_alg::COSE_ALG_HYBRID_MLDSA;
pub const COSE_ALG_ES256: i64 = -7;

/// CTAP2 status codes we can return.
pub const CTAP2_OK: u8 = 0x00;
pub const CTAP2_ERR_INVALID_PARAMETER: u8 = 0x02;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
pub const CTAP2_ERR_UP_REQUIRED: u8 = 0x27;
pub const CTAP2_ERR_KEY_STORE_FULL: u8 = 0x28;
pub const CTAP2_ERR_NOT_ALLOWED: u8 = 0x30;
/// sec. 6.1.2: `options.uv` requested with no UV method configured.
pub const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2b;
/// sec. 6.1.2: UV requested, a PIN exists, but no token was presented.
pub const CTAP2_ERR_PUAT_REQUIRED: u8 = 0x36;

/// Authenticator flags (WebAuthn sec. 6.1).
const FLAG_UP: u8 = 0x01; // user present
const FLAG_UV: u8 = 0x04; // user verified
const FLAG_AT: u8 = 0x40; // attested credential data included
const FLAG_ED: u8 = 0x80; // extension data included

/// Longest rp id we accept. WebAuthn rp ids are domain names.
pub const MAX_RP_ID: usize = 128;

/// This authenticator's AAGUID: 0e4a1e5b-0751-4129-9b76-261b71480557, a
/// random version-4 UUID allocated for the TrustZone build. Distinct
/// from the FIDO firmware's and the C port's, so a relying party can
/// tell the three apart.
const AAGUID: [u8; 16] = [
    0x0e, 0x4a, 0x1e, 0x5b, 0x07, 0x51, 0x41, 0x29, 0x9b, 0x76, 0x26, 0x1b, 0x71, 0x48, 0x05, 0x57,
];

/// Fixed-layout request NS hands in. Not CBOR: the whole point is that
/// Secure does not parse attacker-shaped input.
///
/// Laid out by hand rather than `repr(C)` on a struct so the wire format
/// is explicit and cannot drift with compiler padding.
///
///   0       rp_id_len (1)
///   1..129  rp_id (128, only rp_id_len meaningful)
///   129     flags: bit0 uv, bit1 hybrid, bit2 rk, bit3 allowList given,
///           bit4 minPinLength wanted, bit5 credBlob wanted
///   130..162  client_data_hash (32)
///   162..226  credential_id (64, GetAssertion only)
///   226       user_id_len (1, MakeCredential only)
///   227..291  user_id (64, MakeCredential only)
///   291       credBlob length
///   292..324  credBlob
///   324       user name length
///   325..389  user name
///   389       display name length
///   390..454  display name
///   454       hmac-secret: 1 = requested (MakeCredential)
///   455..519  hmac-secret keyAgreement x, y (GetAssertion)
///   519       saltEnc length
///   520..584  saltEnc
///   584       saltAuth length
///   585..617  saltAuth
///   617       credProtect policy (0 = not requested)
///   618       pinUvAuthParam length (0 = none supplied)
///   619..651  pinUvAuthParam
///   651       pinUvAuthProtocol
///   652..716  second allowList candidate (GetAssertion; see cred_id2)
///   716       1 if the second candidate is present
pub const REQ_LEN: usize = 717;
const OFF_RP_LEN: usize = 0;
const OFF_RP: usize = 1;
const OFF_FLAGS: usize = 129;
const OFF_CDH: usize = 130;
const OFF_CRED: usize = 162;
const OFF_USER_LEN: usize = 226;
const OFF_USER: usize = 227;
const OFF_BLOB_LEN: usize = 291;
const OFF_BLOB: usize = 292;
const OFF_NAME_LEN: usize = 324;
const OFF_NAME: usize = 325;
const OFF_DISPLAY_LEN: usize = 389;
const OFF_DISPLAY: usize = 390;
const OFF_HS_FLAG: usize = 454;
const OFF_HS_KX: usize = 455;
const OFF_HS_KY: usize = 487;
const OFF_HS_SALT_LEN: usize = 519;
const OFF_HS_SALT: usize = 520;
const OFF_HS_AUTH_LEN: usize = 584;
const OFF_HS_AUTH: usize = 585;
const OFF_CRED_PROTECT: usize = 617;
const OFF_PUAT_LEN: usize = 618;
const OFF_PUAT: usize = 619;
const OFF_PUAT_PROTO: usize = 651;
const OFF_CRED2: usize = 652;
const OFF_HAVE_CRED2: usize = 716;

pub struct Request {
    pub rp_id_hash: [u8; 32],
    pub client_data_hash: [u8; 32],
    pub cred_id: [u8; 64],
    /// User verification actually happened: a pinUvAuthParam was
    /// supplied and verified against this device's pinUvAuthToken.
    ///
    /// Only `resolve_uv` sets this. `parse` leaves it false, because
    /// parse works from bytes Non-secure handed over and none of those
    /// bytes can constitute proof -- which is exactly the mistake this
    /// field used to embody: it was `options.uv`, the client's own
    /// request, copied into the signed authenticator data as though the
    /// device had verified someone.
    pub uv: bool,
    /// The client asked for `options.uv`. A request, not evidence.
    pub uv_requested: bool,
    /// pinUvAuthParam as supplied, empty if none was.
    pub puat: [u8; 32],
    pub puat_len: usize,
    /// The client sent a pinUvAuthParam at all -- distinct from it being
    /// non-empty, because an empty one is the PIN probe (sec. 6.1.2 step 1).
    pub puat_present: bool,
    /// It was present and longer than any protocol produces.
    pub puat_malformed: bool,
    /// pinUvAuthProtocol the client says the param is built under.
    /// Zero when the client sent none.
    pub puat_proto: u8,
    /// Second allowList candidate: the first entry that is ours and
    /// usable WITHOUT user verification, present only when `cred_id`
    /// (the first of ours) is credProtect level 3. `choose_allow_list_
    /// credential` swaps it in when no UV happened.
    pub cred_id2: Option<[u8; 64]>,
    /// NS saw the composite PQ/T algorithm in pubKeyCredParams and this
    /// credential should be hybrid. MakeCredential only -- for an
    /// assertion the algorithm comes from the credential id, which is
    /// authenticated, rather than from anything the caller says.
    pub hybrid: bool,
    /// Client asked for a discoverable credential (`options.rk`).
    pub rk: bool,
    /// Client supplied a non-empty allowList. When it did not, an
    /// assertion has to be answered from the resident store.
    pub have_allow_list: bool,
    pub user_id: [u8; crate::credstore::MAX_USER_ID],
    pub user_id_len: usize,
    /// Client asked for the minPinLength extension.
    pub want_min_pin: bool,
    /// credBlob to store (MakeCredential) or a request to return it
    /// (GetAssertion, signalled by `want_cred_blob`).
    pub cred_blob: [u8; crate::credstore::MAX_CRED_BLOB],
    pub cred_blob_len: usize,
    pub want_cred_blob: bool,
    /// rpId text, needed verbatim so CredentialManagement can enumerate
    /// relying parties by name rather than by hash.
    pub rp_id: [u8; MAX_RP_ID],
    pub rp_id_len: usize,
    pub name: [u8; crate::credstore::MAX_NAME],
    pub name_len: usize,
    pub display: [u8; crate::credstore::MAX_NAME],
    pub display_len: usize,
    /// hmac-secret was requested. On MakeCredential that is all there
    /// is; on GetAssertion the salts and key agreement follow.
    pub want_hmac_secret: bool,
    pub hs_kx: [u8; 32],
    pub hs_ky: [u8; 32],
    pub hs_salt: [u8; 64],
    pub hs_salt_len: usize,
    pub hs_auth: [u8; 32],
    pub hs_auth_len: usize,
    /// credProtect policy 1..3, or 0 if the client did not ask.
    pub cred_protect: u8,
}

/// Decode the fixed layout and hash the rp id. Returns None only for a
/// length NS should never have sent.
pub fn parse(req: &[u8; REQ_LEN]) -> Option<Request> {
    use sha2::Digest;
    let rp_len = req[OFF_RP_LEN] as usize;
    if rp_len == 0 || rp_len > MAX_RP_ID {
        return None;
    }
    let mut h = sha2::Sha256::new();
    h.update(&req[OFF_RP..OFF_RP + rp_len]);
    let digest = h.finalize();
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&digest);

    let mut client_data_hash = [0u8; 32];
    client_data_hash.copy_from_slice(&req[OFF_CDH..OFF_CDH + 32]);
    let mut cred_id = [0u8; 64];
    cred_id.copy_from_slice(&req[OFF_CRED..OFF_CRED + 64]);
    let user_id_len = (req[OFF_USER_LEN] as usize).min(crate::credstore::MAX_USER_ID);
    let cred_blob_len = (req[OFF_BLOB_LEN] as usize).min(crate::credstore::MAX_CRED_BLOB);
    let mut cred_blob = [0u8; crate::credstore::MAX_CRED_BLOB];
    cred_blob.copy_from_slice(&req[OFF_BLOB..OFF_BLOB + crate::credstore::MAX_CRED_BLOB]);
    let mut rp_id = [0u8; MAX_RP_ID];
    rp_id[..rp_len].copy_from_slice(&req[OFF_RP..OFF_RP + rp_len]);
    let name_len = (req[OFF_NAME_LEN] as usize).min(crate::credstore::MAX_NAME);
    let mut name = [0u8; crate::credstore::MAX_NAME];
    name.copy_from_slice(&req[OFF_NAME..OFF_NAME + crate::credstore::MAX_NAME]);
    let mut hs_kx = [0u8; 32];
    let mut hs_ky = [0u8; 32];
    let mut hs_salt = [0u8; 64];
    let mut hs_auth = [0u8; 32];
    hs_kx.copy_from_slice(&req[OFF_HS_KX..OFF_HS_KX + 32]);
    hs_ky.copy_from_slice(&req[OFF_HS_KY..OFF_HS_KY + 32]);
    hs_salt.copy_from_slice(&req[OFF_HS_SALT..OFF_HS_SALT + 64]);
    hs_auth.copy_from_slice(&req[OFF_HS_AUTH..OFF_HS_AUTH + 32]);
    let display_len = (req[OFF_DISPLAY_LEN] as usize).min(crate::credstore::MAX_NAME);
    let mut display = [0u8; crate::credstore::MAX_NAME];
    display.copy_from_slice(&req[OFF_DISPLAY..OFF_DISPLAY + crate::credstore::MAX_NAME]);
    let mut user_id = [0u8; crate::credstore::MAX_USER_ID];
    user_id.copy_from_slice(&req[OFF_USER..OFF_USER + crate::credstore::MAX_USER_ID]);

    Some(Request {
        rp_id_hash,
        client_data_hash,
        cred_id,
        uv: false,
        uv_requested: req[OFF_FLAGS] & 0x01 != 0,
        puat: {
            let mut b = [0u8; 32];
            let n = (req[OFF_PUAT_LEN] as usize).min(32);
            b[..n].copy_from_slice(&req[OFF_PUAT..OFF_PUAT + n]);
            b
        },
        puat_len: (req[OFF_PUAT_LEN] as usize).min(32),
        puat_present: req[OFF_FLAGS] & 0x40 != 0,
        puat_malformed: req[OFF_FLAGS] & 0x80 != 0,
        puat_proto: req[OFF_PUAT_PROTO],
        cred_id2: if req[OFF_HAVE_CRED2] == 1 {
            let mut c = [0u8; 64];
            c.copy_from_slice(&req[OFF_CRED2..OFF_CRED2 + 64]);
            Some(c)
        } else {
            None
        },
        hybrid: req[OFF_FLAGS] & 0x02 != 0,
        rk: req[OFF_FLAGS] & 0x04 != 0,
        have_allow_list: req[OFF_FLAGS] & 0x08 != 0,
        want_min_pin: req[OFF_FLAGS] & 0x10 != 0,
        want_cred_blob: req[OFF_FLAGS] & 0x20 != 0,
        cred_blob,
        cred_blob_len,
        rp_id,
        rp_id_len: rp_len,
        name,
        name_len,
        display,
        display_len,
        want_hmac_secret: req[OFF_HS_FLAG] != 0,
        hs_kx,
        hs_ky,
        hs_salt,
        hs_salt_len: (req[OFF_HS_SALT_LEN] as usize).min(64),
        hs_auth,
        hs_auth_len: (req[OFF_HS_AUTH_LEN] as usize).min(32),
        cred_protect: req[OFF_CRED_PROTECT],
        user_id,
        user_id_len,
    })
}

/// Signature counter -- now persistent; see [`crate::counter`].
///
/// Was in RAM, restarting at 1 each boot, which is precisely the
/// "counter went backwards" signal WebAuthn tells a relying party to
/// read as a cloned authenticator.
fn next_sign_count() -> u32 {
    crate::counter::next()
}

/// COSE_Key for the credential's public key.
///
/// ES256:  `{1:2, 3:-7,  -1:1, -2:x, -3:y}`
/// Hybrid: `{1:2, 3:alg, -1:1, -2:x, -3:y, -4:mldsa_pk}`
///
/// The hybrid shape matches the FIDO firmware byte for byte -- kty
/// stays EC2 and the ML-DSA key rides in the -4 slot -- so a relying
/// party cannot tell a TrustZone-issued credential from a normal one.
fn write_cose(w: &mut Writer, x: &[u8; 32], y: &[u8; 32], mldsa_pk: &[u8]) {
    let hybrid = !mldsa_pk.is_empty();
    w.map(if hybrid { 6 } else { 5 });
    w.uint(1);
    w.uint(2); // kty: EC2
    w.uint(3);
    w.nint(if hybrid {
        COSE_ALG_HYBRID
    } else {
        COSE_ALG_ES256
    });
    w.nint(-1);
    w.uint(1); // crv: P-256
    w.nint(-2);
    w.bytes(x);
    w.nint(-3);
    w.bytes(y);
    if hybrid {
        w.nint(-4);
        w.bytes(mldsa_pk);
    }
}

/// Build `authData`. With `attested`, appends the attested credential
/// data block (AAGUID, credential id, COSE public key).
fn write_auth_data(
    out: &mut [u8],
    rp_id_hash: &[u8; 32],
    uv: bool,
    attested: Option<(&[u8; 64], &[u8; 32], &[u8; 32], &[u8])>,
    // Extension outputs, if any were both requested and permitted.
    min_pin: Option<u8>,
    // MakeCredential echoes a bool; GetAssertion returns the bytes.
    cred_blob: Option<CredBlobOut<'_>>,
    hmac_secret: Option<HmacSecretOut<'_>>,
    cred_protect: Option<u8>,
) -> Option<usize> {
    let mut w = Writer::new(out);
    w.raw(rp_id_hash);
    let mut flags = FLAG_UP;
    if uv {
        flags |= FLAG_UV;
    }
    if attested.is_some() {
        flags |= FLAG_AT;
    }
    if min_pin.is_some() || cred_blob.is_some() || hmac_secret.is_some() || cred_protect.is_some() {
        flags |= FLAG_ED;
    }
    w.raw(&[flags]);
    w.raw(&next_sign_count().to_be_bytes());
    if let Some((cred_id, x, y, mldsa_pk)) = attested {
        w.raw(&AAGUID);
        w.raw(&(cred_id.len() as u16).to_be_bytes());
        w.raw(cred_id);
        write_cose(&mut w, x, y, mldsa_pk);
    }
    // Extension outputs follow the attested credential data, per
    // WebAuthn 6.1 -- order matters, the client parses positionally.
    let ext_count = usize::from(min_pin.is_some())
        + usize::from(cred_blob.is_some())
        + usize::from(hmac_secret.is_some())
        + usize::from(cred_protect.is_some());
    if ext_count > 0 {
        w.map(ext_count);
        // CTAP2 canonical order: "credBlob" sorts before "minPinLength".
        // Canonical order: credBlob(8) < credProtect(11) =
        // hmac-secret(11) < minPinLength(12); "credProtect" sorts
        // before "hmac-secret" bytewise.
        match cred_blob {
            Some(CredBlobOut::Stored(ok)) => {
                w.text("credBlob");
                w.raw(&[if ok { 0xf5 } else { 0xf4 }]);
            }
            Some(CredBlobOut::Value(v)) => {
                w.text("credBlob");
                w.bytes(v);
            }
            None => {}
        }
        // Canonical order: credBlob(8) < hmac-secret(11) <
        // minPinLength(12) -- length first, then bytewise.
        if let Some(p) = cred_protect {
            w.text("credProtect");
            w.uint(p as u64);
        }
        match hmac_secret {
            Some(HmacSecretOut::Enabled(v)) => {
                w.text("hmac-secret");
                w.raw(&[if v { 0xf5 } else { 0xf4 }]);
            }
            Some(HmacSecretOut::Output(v)) => {
                w.text("hmac-secret");
                w.bytes(v);
            }
            None => {}
        }
        if let Some(len) = min_pin {
            w.text("minPinLength");
            w.uint(len as u64);
        }
    }
    w.finish()
}

/// What the credBlob extension puts in authData.
///
/// MakeCredential answers with a boolean saying whether the blob was
/// kept; GetAssertion answers with the bytes themselves.
/// hmac-secret's authData output: a flag at registration, the encrypted
/// evaluation at assertion.
pub enum HmacSecretOut<'a> {
    Enabled(bool),
    Output(&'a [u8]),
}

pub enum CredBlobOut<'a> {
    Stored(bool),
    Value(&'a [u8]),
}

/// The minPinLength output, if this relying party may see it.
///
/// CTAP2 gates the extension on an explicit allow-list set through
/// authenticatorConfig: the PIN policy is not something every site gets
/// to read.
fn min_pin_output(req: &Request) -> Option<u8> {
    if req.want_min_pin && crate::clientpin::min_pin_rp_allowed(&req.rp_id_hash) {
        Some(crate::clientpin::min_pin_length())
    } else {
        None
    }
}

/// Decide whether user verification actually happened, per CTAP 2.1
/// sec. 6.1.2 (MakeCredential) and sec. 6.2.2 (GetAssertion).
///
/// This is the check the TrustZone port did not have. `options.uv` was
/// copied from the request into the flags byte by Non-secure, read back
/// here as `Request::uv`, and written straight into the signed
/// authenticator data -- so any client could ask for the UV bit and get
/// it, with no PIN configured and nothing verified. A relying party that
/// requires user verification accepted the result, because the flag is
/// how it is supposed to know.
///
/// The decision belongs on this side of the boundary for the reason the
/// whole split exists: the pinUvAuthToken lives here, so only here can a
/// claim about it be checked. Non-secure carries the bytes and judges
/// nothing.
///
/// `rp` scopes the token to a relying party when one was bound at
/// getPinToken time; passing it is what stops a token minted for one RP
/// authenticating a ceremony for another.
/// After `resolve_uv`: pick which allowList candidate to assert with.
///
/// Non-secure forwards the first credential that is ours and, when that
/// one is credProtect level 3, also the first that is usable without
/// UV. Level 3 is usable only WITH user verification, so if UV happened
/// the first stays; if it did not, the second replaces it. Without this
/// a level-3 credential listed first made every later usable credential
/// unreachable for a client with no PIN token -- the spec's "locate all
/// denoted credentials, then filter" was being done as "locate the
/// first, then refuse".
pub fn choose_allow_list_credential(r: &mut Request) {
    if !r.uv {
        if let Some(second) = r.cred_id2.take() {
            r.cred_id = second;
        }
    }
}

pub fn resolve_uv(r: &mut Request, permission: u8) -> Result<(), u8> {
    // sec. 6.1.2 step 1: a pinUvAuthParam that is present and EMPTY is the
    // PIN probe. The platform is asking whether a PIN is set, and the
    // whole point is that the answer is a status, not a credential.
    // Served as an ordinary request -- which is what happened when only
    // a length crossed the boundary -- it minted a credential on every
    // probe, and Chrome probes on every registration.
    if r.puat_present && r.puat_len == 0 && !r.puat_malformed {
        return Err(if crate::clientpin::pin_is_set() {
            crate::clientpin::ERR_PIN_INVALID
        } else {
            crate::clientpin::ERR_PIN_NOT_SET
        });
    }
    // Present but longer than either protocol produces: a claim that
    // cannot be checked is a failed claim, not an absent one.
    if r.puat_malformed {
        return Err(crate::clientpin::ERR_PIN_AUTH_INVALID);
    }
    if r.puat_len > 0 {
        // Only protocol v1 exists in this image, and getInfo advertises
        // only v1. A param built under v2 would still be 32 bytes and
        // would verify under the wrong rules if the byte went unchecked
        // -- the failure mode being a v2 client whose parameters are
        // silently reinterpreted rather than refused. Matching the C and
        // Rust ports, an unusable protocol is PIN_AUTH_INVALID rather
        // than INVALID_PARAMETER: from the client's side the proof it
        // offered could not be accepted, which is what that code says.
        if u64::from(r.puat_proto) != crate::clientpin::PIN_PROTOCOL_V1 {
            return Err(crate::clientpin::ERR_PIN_AUTH_INVALID);
        }
        // Present but wrong is a different answer from absent (sec. 6.5.5.7),
        // and the difference matters: a client probing with an empty
        // pinUvAuthParam is asking whether a PIN is set, and must not be
        // told "no user verification" when the real answer is "that proof
        // is invalid".
        if !crate::clientpin::verify_token(
            &r.client_data_hash,
            &r.puat[..r.puat_len],
            permission,
            Some(&r.rp_id_hash),
        ) {
            return Err(crate::clientpin::ERR_PIN_AUTH_INVALID);
        }
        r.uv = true;
        return Ok(());
    }

    if r.uv_requested {
        // Asked for, not proven. This device has no built-in user
        // verification -- no fingerprint reader, no keypad -- so a PIN
        // is the only UV method there is. With no PIN configured there
        // is nothing that could ever satisfy the request; with one
        // configured the client simply has to get a token first.
        //
        // Refusing rather than downgrading is the point. Serving the
        // ceremony with uv=false would look like success to a client
        // that asked for verification and would not get it.
        return Err(if crate::clientpin::pin_is_set() {
            CTAP2_ERR_PUAT_REQUIRED
        } else {
            CTAP2_ERR_UNSUPPORTED_OPTION
        });
    }

    r.uv = false;
    Ok(())
}

/// CTAP2 MakeCredential response: status byte then
/// `{1: "none", 2: authData, 3: {}}`.
///
/// Attestation format "none" (WebAuthn sec. 8.7) -- there is no attestation
/// key in this image, and inventing a self-attestation would say
/// something untrue about provenance.
pub fn make_credential(
    req: &Request,
    cred_id: &[u8; 64],
    pub_x: &[u8; 32],
    pub_y: &[u8; 32],
    mldsa_pk: &[u8],
    // Did the credBlob actually get stored? Only meaningful when one
    // was supplied.
    blob_stored: Option<bool>,
    hmac_enabled: bool,
    out: &mut [u8],
) -> Option<usize> {
    let mut auth = [0u8; AUTH_MAX];
    let n = write_auth_data(
        &mut auth,
        &req.rp_id_hash,
        req.uv,
        Some((cred_id, pub_x, pub_y, mldsa_pk)),
        min_pin_output(req),
        blob_stored.map(CredBlobOut::Stored),
        if hmac_enabled {
            Some(HmacSecretOut::Enabled(true))
        } else {
            None
        },
        if req.cred_protect > 0 {
            Some(req.cred_protect)
        } else {
            None
        },
    )?;

    let mut w = Writer::new(out);
    w.raw(&[CTAP2_OK]);
    w.map(3);
    w.uint(1);
    w.text("none");
    w.uint(2);
    w.bytes(&auth[..n]);
    w.uint(3);
    w.map(0);
    w.finish()
}

/// Build the `authData` an assertion signs, and the message to sign.
///
/// Returns (authData bytes written, signed message bytes written). The
/// signature covers `authData || clientDataHash` (WebAuthn sec. 6.3.3).
pub fn assertion_signed_message(
    req: &Request,
    // The stored credBlob, when the client asked for it back.
    cred_blob: Option<&[u8]>,
    hmac_out: Option<&[u8]>,
    // Sized for the worst case: a 64-byte two-salt hmac-secret output
    // and a 32-byte credBlob alongside the fixed header. 128 was enough
    // for one salt and silently short for two.
    auth: &mut [u8; 256],
    msg: &mut [u8; 320],
) -> Option<(usize, usize)> {
    let n = write_auth_data(
        auth,
        &req.rp_id_hash,
        req.uv,
        None,
        min_pin_output(req),
        cred_blob.map(CredBlobOut::Value),
        hmac_out.map(HmacSecretOut::Output),
        None,
    )?;
    if n + 32 > msg.len() {
        return None;
    }
    msg[..n].copy_from_slice(&auth[..n]);
    msg[n..n + 32].copy_from_slice(&req.client_data_hash);
    Some((n, n + 32))
}

/// CTAP2 GetAssertion response: status byte then
/// `{1: {id, type}, 2: authData, 3: signature}`.
pub fn get_assertion(
    cred_id: &[u8; 64],
    auth: &[u8],
    sig: &[u8],
    // Present only for a discoverable credential: CTAP2 returns the
    // user handle so the client can show who it just signed as.
    user: Option<&[u8]>,
    // numberOfCredentials, which CTAP2 puts in the FIRST response only
    // -- a GetNextAssertion reply must omit it.
    total: Option<usize>,
    out: &mut [u8],
) -> Option<usize> {
    let mut w = Writer::new(out);
    w.raw(&[CTAP2_OK]);
    w.map(3 + usize::from(user.is_some()) + usize::from(total.is_some()));
    w.uint(1);
    w.map(2);
    w.text("id");
    w.bytes(cred_id);
    w.text("type");
    w.text("public-key");
    w.uint(2);
    w.bytes(auth);
    w.uint(3);
    w.bytes(sig);
    if let Some(user_id) = user {
        w.uint(4);
        w.map(1);
        w.text("id");
        w.bytes(user_id);
    }
    if let Some(n) = total {
        w.uint(5);
        w.uint(n as u64);
    }
    w.finish()
}

/// A bare CTAP2 error response: just the status byte.
pub fn error(status: u8, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    out[0] = status;
    1
}

/// Build the `authenticatorGetInfo` response (status byte + CBOR).
///
/// Built with the writer rather than hand-encoded as it was in M3. It
/// has to name the algorithms this build actually supports, and the
/// composite identifier moves with the compiled ML-DSA level, so a
/// constant would go stale the first time the level changed.
///
/// `rk` is reported **true** as of the resident-credential store. It
/// was briefly false and accurate; before that it was true and a lie.
pub fn get_info(out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.raw(&[CTAP2_OK]);
    w.map(8);

    w.uint(1); // versions
    w.array(1);
    w.text("FIDO_2_0");

    // Extensions this image implements. A client only sends an extension
    // the authenticator advertises, so with this key absent the
    // credProtect, hmac-secret, credBlob and minPinLength code below was
    // reachable only by a client that ignored getInfo. Key 2 sits
    // between 1 and 3 because the map is canonical.
    w.uint(2); // extensions
    w.array(4);
    w.text("credBlob");
    w.text("credProtect");
    w.text("hmac-secret");
    w.text("minPinLength");

    w.uint(3); // aaguid
    w.bytes(&AAGUID);

    w.uint(4); // options
    w.map(7);
    // CTAP2 canonical CBOR orders map keys by LENGTH first, then
    // bytewise -- not by insertion. Getting this wrong is silent: a
    // strict client stops reading at the first out-of-order key, so
    // the options after it simply do not exist as far as it is
    // concerned, and the commands they gate are never sent. That is
    // exactly what hid authnrCfg and credMgmt here.
    w.text("rk"); // 2
    w.raw(&[0xf5]);
    w.text("up"); // 2
    w.raw(&[0xf5]);
    w.text("credMgmt"); // 8
    w.raw(&[0xf5]);
    w.text("authnrCfg"); // 9
    w.raw(&[0xf5]);
    w.text("clientPin"); // 9
                         // Present-and-false means "supported, none set yet"; absent would
                         // mean "not supported at all", a different claim.
    w.raw(&[if crate::clientpin::pin_is_set() {
        0xf5
    } else {
        0xf4
    }]);
    // Without this the client has no way to know
    // getPinUvAuthTokenUsingPinWithPermissions (subcommand 0x09) is
    // available, so it falls back to the legacy getPinToken -- which
    // grants only MakeCredential|GetAssertion and can never carry the
    // credMgmt or authnrCfg permission. Those two command families
    // then fail authentication no matter how correctly they are
    // implemented, which is precisely what happened here.
    w.text("pinUvAuthToken"); // 14
    w.raw(&[0xf5]);
    w.text("setMinPINLength"); // 15
    w.raw(&[0xf5]);

    w.uint(5); // maxMsgSize -- must not exceed the NS reassembly buffer
    w.uint(MAX_MSG_SIZE as u64);

    w.uint(0x06); // pinUvAuthProtocols
    w.array(1);
    w.uint(1); // v1 only -- v2 is not implemented, so do not claim it

    w.uint(0x0a); // algorithms
    w.array(2);
    w.map(2);
    w.text("alg");
    w.nint(COSE_ALG_ES256);
    w.text("type");
    w.text("public-key");
    w.map(2);
    w.text("alg");
    w.nint(COSE_ALG_HYBRID);
    w.text("type");
    w.text("public-key");

    // Last, because 15 is the largest key here. CTAP2 canonical CBOR
    // orders map keys ascending, and a strict client stops reading at
    // the first one out of order -- so emitting 0x0f before 0x06 and
    // 0x0a, as this did, hid pinUvAuthProtocols and algorithms
    // entirely. A client that never learns a pinUvAuthProtocol cannot
    // run ClientPIN at all. The inner options map below carries a
    // comment about this exact trap; the outer map was left wrong.
    w.uint(0x0f); // maxCredBlobLength
    w.uint(crate::credstore::MAX_CRED_BLOB as u64);

    w.finish()
}

/// Largest CTAP message either side will handle. Must match
/// `MAX_MSG` in the Non-secure image: advertising more than NS can
/// reassemble invites a request it will reject at the transport layer.
pub const MAX_MSG_SIZE: usize = 7609;

/// ClientPIN response: `{3: retries}`.
pub fn pin_retries(retries: u8, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.raw(&[CTAP2_OK]);
    w.map(1);
    w.uint(3);
    w.uint(retries as u64);
    w.finish()
}

/// ClientPIN response: `{1: COSE_Key}` for the key agreement point.
///
/// alg is -25 (ECDH-ES + HKDF-256) rather than -7: this key is for key
/// agreement, and a client that checks will reject -7 here.
pub fn pin_key_agreement(x: &[u8; 32], y: &[u8; 32], out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.raw(&[CTAP2_OK]);
    w.map(1);
    w.uint(1);
    w.map(5);
    w.uint(1);
    w.uint(2); // kty: EC2
    w.uint(3);
    w.nint(-25); // alg: ECDH-ES + HKDF-256
    w.nint(-1);
    w.uint(1); // crv: P-256
    w.nint(-2);
    w.bytes(x);
    w.nint(-3);
    w.bytes(y);
    w.finish()
}

/// ClientPIN response: `{2: encrypted pinUvAuthToken}`.
pub fn pin_token(token: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.raw(&[CTAP2_OK]);
    w.map(1);
    w.uint(2);
    w.bytes(token);
    w.finish()
}

/// authenticatorConfig request layout, built by NS.
///
///   0        subCommand
///   1        pinUvAuthParam length
///   2..34    pinUvAuthParam
///   34..36   subCommandParams length (big endian)
///   36..292  subCommandParams, verbatim
///   292      newMinPINLength, 0 = absent
///   293      forceChangePin: 0 absent, 1 false, 2 true
///   294      rpId count
///   295..    rpId entries: length byte then 128 bytes, x4
pub const CONFIG_REQ_LEN: usize = 295 + 4 * 129;
const CFG_OFF_SUB: usize = 0;
const CFG_OFF_AUTH_LEN: usize = 1;
const CFG_OFF_AUTH: usize = 2;
const CFG_OFF_PARAMS_LEN: usize = 34;
const CFG_OFF_PARAMS: usize = 36;
const CFG_MAX_PARAMS: usize = 256;
const CFG_OFF_NEW_LEN: usize = 292;
const CFG_OFF_FORCE: usize = 293;
const CFG_OFF_RP_COUNT: usize = 294;
const CFG_OFF_RPS: usize = 295;

/// authenticatorConfig subcommands we implement.
const CFG_SET_MIN_PIN_LENGTH: u8 = 0x03;

pub fn handle_config(req: &[u8; CONFIG_REQ_LEN]) -> u8 {
    use sha2::Digest;
    let sub = req[CFG_OFF_SUB];
    if sub != CFG_SET_MIN_PIN_LENGTH {
        return CTAP2_ERR_INVALID_SUBCOMMAND;
    }
    let auth_len = (req[CFG_OFF_AUTH_LEN] as usize).min(32);
    let params_len = (((req[CFG_OFF_PARAMS_LEN] as usize) << 8)
        | req[CFG_OFF_PARAMS_LEN + 1] as usize)
        .min(CFG_MAX_PARAMS);
    let params = &req[CFG_OFF_PARAMS..CFG_OFF_PARAMS + params_len];
    if !crate::clientpin::verify_config_auth(
        sub,
        params,
        &req[CFG_OFF_AUTH..CFG_OFF_AUTH + auth_len],
    ) {
        return crate::clientpin::ERR_PIN_AUTH_INVALID;
    }

    let new_len = match req[CFG_OFF_NEW_LEN] {
        0 => None,
        n => Some(n),
    };
    let force = match req[CFG_OFF_FORCE] {
        1 => Some(false),
        2 => Some(true),
        _ => None,
    };
    // Hash the rpIds here rather than trusting a hash from NS: these
    // decide which relying parties learn the PIN policy.
    let count = (req[CFG_OFF_RP_COUNT] as usize).min(crate::pinstore::MAX_MIN_PIN_RPS);
    let mut hashes = [[0u8; 32]; crate::pinstore::MAX_MIN_PIN_RPS];
    for i in 0..count {
        let base = CFG_OFF_RPS + i * 129;
        let l = (req[base] as usize).min(128);
        let mut h = sha2::Sha256::new();
        h.update(&req[base + 1..base + 1 + l]);
        hashes[i].copy_from_slice(&h.finalize());
    }
    crate::clientpin::set_min_pin_length(new_len, &hashes[..count], force)
}

/// CTAP 2.1 sec. 8.1. 0x16 is UNSUPPORTED_EXTENSION; see client_pin.rs.
pub const CTAP2_ERR_INVALID_SUBCOMMAND: u8 = 0x3e;

/// authenticatorCredentialManagement request, built by NS.
///
///   0        subCommand
///   1        pinUvAuthParam length
///   2..34    pinUvAuthParam
///   34..36   subCommandParams length (big endian)
///   36..292  subCommandParams, verbatim (the MAC covers these bytes)
///   292..324 rpIdHash
///   324      rpIdHash present
///   325..389 credentialId
///   389      credentialId present
///   390      user id length
///   391..455 user id
///   455      user name length
///   456..520 user name
///   520      display name length
///   521..585 display name
pub const CM_REQ_LEN: usize = 585;
const CM_OFF_SUB: usize = 0;
const CM_OFF_AUTH_LEN: usize = 1;
const CM_OFF_AUTH: usize = 2;
const CM_OFF_PARAMS_LEN: usize = 34;
const CM_OFF_PARAMS: usize = 36;
const CM_MAX_PARAMS: usize = 256;
const CM_OFF_RP_HASH: usize = 292;
const CM_OFF_HAVE_RP: usize = 324;
const CM_OFF_CRED: usize = 325;
const CM_OFF_HAVE_CRED: usize = 389;
const CM_OFF_USER_LEN: usize = 390;
const CM_OFF_USER: usize = 391;
const CM_OFF_NAME_LEN: usize = 455;
const CM_OFF_NAME: usize = 456;
const CM_OFF_DISPLAY_LEN: usize = 520;
const CM_OFF_DISPLAY: usize = 521;

const CM_GET_METADATA: u8 = 0x01;
const CM_ENUM_RPS_BEGIN: u8 = 0x02;
const CM_ENUM_RPS_NEXT: u8 = 0x03;
const CM_ENUM_CREDS_BEGIN: u8 = 0x04;
const CM_ENUM_CREDS_NEXT: u8 = 0x05;
const CM_DELETE: u8 = 0x06;
const CM_UPDATE_USER: u8 = 0x07;

/// Where an enumeration got to. CTAP2 walks these with a Begin call
/// followed by repeated Next calls, so the cursor lives here rather
/// than in the request -- an NS-supplied index would let it walk the
/// store at will.
static mut CM_RP_CURSOR: usize = 0;
static mut CM_CRED_CURSOR: usize = 0;
static mut CM_CRED_RP: [u8; 32] = [0u8; 32];
/// Which enumeration, if any, is in progress. The auth-exempt Next
/// subcommands are only exempt while their Begin is live; see
/// `handle_cred_mgmt`.
static mut CM_LIVE: u8 = 0;
const CM_LIVE_RPS: u8 = 0x01;
const CM_LIVE_CREDS: u8 = 0x02;

/// End any credentialManagement enumeration. Called by every other
/// CTAP command's gateway (CTAP 2.1 sec. 6.8 abandons the enumeration
/// context on any intervening command) and by the terminal states of
/// the enumeration itself.
pub fn cm_abandon() {
    // SAFETY: single-threaded; Secure-only.
    unsafe {
        CM_LIVE = 0;
        CM_RP_CURSOR = 0;
        CM_CRED_CURSOR = 0;
    }
}

fn cm_write_rp(
    rec: &crate::credstore::Resident,
    total: Option<usize>,
    out: &mut [u8],
) -> Option<usize> {
    use sha2::Digest;
    let mut w = Writer::new(out);
    w.raw(&[CTAP2_OK]);
    w.map(2 + usize::from(total.is_some()));
    w.uint(3); // rp
    w.map(1);
    w.text("id");
    // The rpId text, which is why the store keeps it verbatim.
    let name = core::str::from_utf8(&rec.rp_id[..rec.rp_id_len]).ok()?;
    w.text(name);
    w.uint(4); // rpIDHash
    let mut h = sha2::Sha256::new();
    h.update(&rec.rp_id[..rec.rp_id_len]);
    let digest = h.finalize();
    w.bytes(&digest);
    if let Some(n) = total {
        w.uint(5);
        w.uint(n as u64);
    }
    w.finish()
}

fn cm_write_cred(
    rec: &crate::credstore::Resident,
    x: &[u8; 32],
    y: &[u8; 32],
    mldsa_pk: &[u8],
    total: Option<usize>,
    out: &mut [u8],
) -> Option<usize> {
    let mut w = Writer::new(out);
    w.raw(&[CTAP2_OK]);
    let protect = rec.cred_protect;
    w.map(3 + usize::from(total.is_some()) + usize::from(protect > 0));
    w.uint(6); // user
    let has_name = rec.name_len > 0;
    let has_display = rec.display_len > 0;
    w.map(1 + usize::from(has_name) + usize::from(has_display));
    w.text("id");
    w.bytes(&rec.user_id[..rec.user_id_len]);
    // Canonical order: "id" (2), "name" (4), "displayName" (11).
    if has_name {
        w.text("name");
        match core::str::from_utf8(&rec.name[..rec.name_len]) {
            Ok(t) => w.text(t),
            Err(_) => w.text(""),
        }
    }
    if has_display {
        w.text("displayName");
        match core::str::from_utf8(&rec.display[..rec.display_len]) {
            Ok(t) => w.text(t),
            Err(_) => w.text(""),
        }
    }
    w.uint(7); // credentialID
    w.map(2);
    w.text("id");
    w.bytes(&rec.cred_id);
    w.text("type");
    w.text("public-key");
    w.uint(8); // publicKey
    write_cose(&mut w, x, y, mldsa_pk);
    if let Some(n) = total {
        w.uint(9);
        w.uint(n as u64);
    }
    if protect > 0 {
        w.uint(0x0a); // credProtect
        w.uint(protect as u64);
    }
    w.finish()
}

/// Outcome of a CredentialManagement subcommand.
pub enum CmReply {
    Err(u8),
    Bytes(usize),
}

pub fn handle_cred_mgmt(
    req: &[u8; CM_REQ_LEN],
    resp: &mut [u8],
    // The scratch is handed TO the lookup rather than filled beside it:
    // deriving a hybrid credential's ML-DSA public key needs the master
    // key, which lives in the caller, and the closure cannot borrow a
    // buffer this function also holds. Returning a length with nothing
    // written is what made every enumerated hybrid credential come back
    // as a bare P-256 key.
    lookup: &dyn Fn(&[u8; 32], &[u8; 64], &mut [u8]) -> Option<([u8; 32], [u8; 32], usize)>,
    mldsa_scratch: &mut [u8],
) -> CmReply {
    let sub = req[CM_OFF_SUB];
    let auth_len = (req[CM_OFF_AUTH_LEN] as usize).min(32);
    let params_len = (((req[CM_OFF_PARAMS_LEN] as usize) << 8)
        | req[CM_OFF_PARAMS_LEN + 1] as usize)
        .min(CM_MAX_PARAMS);

    // A Next call carries no auth of its own -- CTAP2 treats it as a
    // continuation of the Begin that was authenticated. That exemption
    // is only sound if a Begin actually ran, on this power cycle, and
    // nothing else has happened since. Without the CM_LIVE check a cold
    // token would answer `{1: 3}` from anyone with the first stored RP,
    // and keep answering: the auth-exempt subcommands enumerated the
    // whole store to a caller who had never presented a token.
    let needs_auth = !matches!(sub, CM_ENUM_RPS_NEXT | CM_ENUM_CREDS_NEXT);
    if !needs_auth {
        // SAFETY: single-threaded; Secure-only.
        let live = unsafe { CM_LIVE };
        let want = if sub == CM_ENUM_RPS_NEXT {
            CM_LIVE_RPS
        } else {
            CM_LIVE_CREDS
        };
        if live & want == 0 {
            return CmReply::Err(CTAP2_ERR_NOT_ALLOWED);
        }
    } else {
        // Any authenticated subcommand other than a Begin ends whatever
        // enumeration was in progress (sec. 6.8: the context is abandoned on
        // any other command). Begin re-arms its own below.
        cm_abandon();
    }
    let mut rp_hash = [0u8; 32];
    rp_hash.copy_from_slice(&req[CM_OFF_RP_HASH..CM_OFF_RP_HASH + 32]);

    if needs_auth {
        // No token at all is PUAT_REQUIRED -- retriable, "go and get
        // one" -- not PIN_AUTH_INVALID, which says the one you sent was
        // wrong. Same correction the C port got for these two commands.
        if auth_len == 0 {
            return CmReply::Err(CTAP2_ERR_PUAT_REQUIRED);
        }
        // The token's RP scope, if it has one, must be honoured
        // (sec. 6.5.5.7.1). enumerateCredentialsBegin may use a token scoped
        // to the RP it names; everything else needs an unscoped token,
        // which the zero hash enforces -- no token can be scoped to it,
        // so a scoped token fails and an unscoped one passes. It used to
        // pass `None`, which skips the scope check entirely, so a token
        // scoped to one relying party managed every credential on the
        // device.
        let scope: [u8; 32] = if sub == CM_ENUM_CREDS_BEGIN && req[CM_OFF_HAVE_RP] == 1 {
            rp_hash
        } else {
            [0u8; 32]
        };
        let mut msg = alloc::vec::Vec::with_capacity(1 + params_len);
        msg.push(sub);
        msg.extend_from_slice(&req[CM_OFF_PARAMS..CM_OFF_PARAMS + params_len]);
        if !crate::clientpin::verify_token(
            &msg,
            &req[CM_OFF_AUTH..CM_OFF_AUTH + auth_len],
            crate::clientpin::PERM_CREDENTIAL_MGMT,
            Some(&scope),
        ) {
            return CmReply::Err(crate::clientpin::ERR_PIN_AUTH_INVALID);
        }
    }
    let mut cred_id = [0u8; 64];
    cred_id.copy_from_slice(&req[CM_OFF_CRED..CM_OFF_CRED + 64]);

    match sub {
        CM_GET_METADATA => {
            let (used, free) = crate::credstore::totals();
            let mut w = Writer::new(resp);
            w.raw(&[CTAP2_OK]);
            w.map(2);
            w.uint(1);
            w.uint(used as u64);
            w.uint(2);
            w.uint(free as u64);
            match w.finish() {
                Some(n) => CmReply::Bytes(n),
                None => CmReply::Err(CTAP2_ERR_INVALID_PARAMETER),
            }
        }
        CM_ENUM_RPS_BEGIN | CM_ENUM_RPS_NEXT => {
            // SAFETY: single-threaded; Secure-only cursor.
            let idx = unsafe {
                if sub == CM_ENUM_RPS_BEGIN {
                    CM_RP_CURSOR = 0;
                    CM_LIVE = CM_LIVE_RPS;
                } else {
                    CM_RP_CURSOR += 1;
                }
                CM_RP_CURSOR
            };
            let total = crate::credstore::rp_count();
            if total == 0 {
                cm_abandon();
                return CmReply::Err(CTAP2_ERR_NO_CREDENTIALS);
            }
            match crate::credstore::nth_rp(idx) {
                None => {
                    // Walked off the end: the enumeration is over, and a
                    // further Next must not be able to start it again.
                    cm_abandon();
                    CmReply::Err(CTAP2_ERR_NOT_ALLOWED)
                }
                Some(rec) => {
                    let t = if sub == CM_ENUM_RPS_BEGIN {
                        Some(total)
                    } else {
                        None
                    };
                    match cm_write_rp(&rec, t, resp) {
                        Some(n) => CmReply::Bytes(n),
                        None => CmReply::Err(CTAP2_ERR_INVALID_PARAMETER),
                    }
                }
            }
        }
        CM_ENUM_CREDS_BEGIN | CM_ENUM_CREDS_NEXT => {
            // SAFETY: single-threaded; Secure-only cursor.
            let idx = unsafe {
                if sub == CM_ENUM_CREDS_BEGIN {
                    CM_CRED_CURSOR = 0;
                    CM_CRED_RP = rp_hash;
                    CM_LIVE = CM_LIVE_CREDS;
                } else {
                    CM_CRED_CURSOR += 1;
                }
                CM_CRED_CURSOR
            };
            // SAFETY: as above.
            let rp = unsafe { CM_CRED_RP };
            let total = crate::credstore::count(&rp);
            if total == 0 {
                cm_abandon();
                return CmReply::Err(CTAP2_ERR_NO_CREDENTIALS);
            }
            match crate::credstore::get(&rp, idx) {
                None => {
                    cm_abandon();
                    CmReply::Err(CTAP2_ERR_NOT_ALLOWED)
                }
                Some(rec) => match lookup(&rp, &rec.cred_id, mldsa_scratch) {
                    None => CmReply::Err(CTAP2_ERR_NO_CREDENTIALS),
                    Some((x, y, pk_len)) => {
                        let t = if sub == CM_ENUM_CREDS_BEGIN {
                            Some(total)
                        } else {
                            None
                        };
                        match cm_write_cred(&rec, &x, &y, &mldsa_scratch[..pk_len], t, resp) {
                            Some(n) => CmReply::Bytes(n),
                            None => CmReply::Err(CTAP2_ERR_INVALID_PARAMETER),
                        }
                    }
                },
            }
        }
        CM_DELETE => {
            if req[CM_OFF_HAVE_CRED] == 0 {
                return CmReply::Err(CTAP2_ERR_INVALID_PARAMETER);
            }
            if crate::credstore::delete(&cred_id) {
                CmReply::Bytes(error(CTAP2_OK, resp))
            } else {
                CmReply::Err(CTAP2_ERR_NO_CREDENTIALS)
            }
        }
        CM_UPDATE_USER => {
            let ulen = (req[CM_OFF_USER_LEN] as usize).min(crate::credstore::MAX_USER_ID);
            let nlen = (req[CM_OFF_NAME_LEN] as usize).min(crate::credstore::MAX_NAME);
            let dlen = (req[CM_OFF_DISPLAY_LEN] as usize).min(crate::credstore::MAX_NAME);
            // CTAP2's updateUserInformation is a partial update of the
            // user entity, and in practice clients send only the names.
            // Requiring an id here rejected every real request.
            if req[CM_OFF_HAVE_CRED] == 0 || (ulen == 0 && nlen == 0 && dlen == 0) {
                return CmReply::Err(CTAP2_ERR_INVALID_PARAMETER);
            }
            if crate::credstore::update_user(
                &cred_id,
                &req[CM_OFF_USER..CM_OFF_USER + ulen],
                &req[CM_OFF_NAME..CM_OFF_NAME + nlen],
                &req[CM_OFF_DISPLAY..CM_OFF_DISPLAY + dlen],
            ) {
                CmReply::Bytes(error(CTAP2_OK, resp))
            } else {
                CmReply::Err(CTAP2_ERR_NO_CREDENTIALS)
            }
        }
        _ => CmReply::Err(CTAP2_ERR_INVALID_SUBCOMMAND),
    }
}
