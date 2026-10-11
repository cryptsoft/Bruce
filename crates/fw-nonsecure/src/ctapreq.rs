// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAP2 request parsing for the Non-secure world.
//!
//! Split out of `main.rs` so it can be tested. This is the code that
//! turns attacker-controlled CBOR into the fixed-layout byte arrays
//! handed across the TrustZone boundary, which makes it the most
//! valuable thing in the Non-secure image to get right and the hardest
//! to reach while it sits inside a `#[entry]` binary next to the veneer
//! declarations and the USB stack.
//!
//! Nothing here touches hardware or the gateway. `parse_make_credential`
//! needs to ask Secure whether a credential id is one of ours, for the
//! excludeList check, and takes that as an injected predicate rather
//! than calling the veneer directly -- which is what lets a test drive
//! the CTAP2 excludeList requirement in both directions.

use crate::cborr;

// CTAP2 command bytes (first byte of a CBOR request) we demux in NS.
pub const CTAP2_MAKE_CREDENTIAL: u8 = 0x01;
pub const CTAP2_GET_ASSERTION: u8 = 0x02;
pub const CTAP2_GET_INFO: u8 = 0x04;
pub const CTAP2_GET_NEXT_ASSERTION: u8 = 0x08;
pub const CTAP2_CLIENT_PIN: u8 = 0x06;
pub const CTAP2_SELECTION: u8 = 0x0b;
pub const CTAP2_CONFIG: u8 = 0x0d;
pub const CTAP2_CRED_MGMT: u8 = 0x0a;
/// Pre-2.1 alias some clients still send for CredentialManagement.
pub const CTAP2_CRED_MGMT_PRE: u8 = 0x41;

/// CredentialManagement request; mirrors `ctap::CM_REQ_LEN`.
pub const CM_REQ_LEN: usize = 585;
pub const CM_OFF_NAME_LEN: usize = 455;
pub const CM_OFF_NAME: usize = 456;
pub const CM_OFF_DISPLAY_LEN: usize = 520;
pub const CM_OFF_DISPLAY: usize = 521;
pub const CM_OFF_SUB: usize = 0;
pub const CM_OFF_AUTH_LEN: usize = 1;
pub const CM_OFF_AUTH: usize = 2;
pub const CM_OFF_PARAMS_LEN: usize = 34;
pub const CM_OFF_PARAMS: usize = 36;
pub const CM_OFF_RP_HASH: usize = 292;
pub const CM_OFF_HAVE_RP: usize = 324;
pub const CM_OFF_CRED: usize = 325;
pub const CM_OFF_HAVE_CRED: usize = 389;
pub const CM_OFF_USER_LEN: usize = 390;
pub const CM_OFF_USER: usize = 391;

/// authenticatorConfig request; mirrors `ctap::CONFIG_REQ_LEN`.
pub const CONFIG_REQ_LEN: usize = 295 + 4 * 129;
pub const CFG_OFF_SUB: usize = 0;
pub const CFG_OFF_AUTH_LEN: usize = 1;
pub const CFG_OFF_AUTH: usize = 2;
pub const CFG_OFF_PARAMS_LEN: usize = 34;
pub const CFG_OFF_PARAMS: usize = 36;
pub const CFG_OFF_NEW_LEN: usize = 292;
pub const CFG_OFF_FORCE: usize = 293;
pub const CFG_OFF_RP_COUNT: usize = 294;
pub const CFG_OFF_RPS: usize = 295;

/// Fixed-layout ClientPIN request; mirrors `clientpin::PIN_REQ_LEN`.
pub const PIN_REQ_LEN: usize = 344;
pub const PIN_OFF_PROTO: usize = 0;
pub const PIN_OFF_SUB: usize = 1;
pub const PIN_OFF_FLAGS: usize = 2;
pub const PIN_OFF_PERMS: usize = 3;
pub const PIN_OFF_KX: usize = 4;
pub const PIN_OFF_KY: usize = 36;
pub const PIN_OFF_AUTH_LEN: usize = 68;
pub const PIN_OFF_AUTH: usize = 69;
pub const PIN_OFF_HASH_LEN: usize = 101;
pub const PIN_OFF_HASH: usize = 102;
pub const PIN_OFF_NEW_LEN: usize = 134;
pub const PIN_OFF_NEW: usize = 135;
pub const PIN_OFF_RP_LEN: usize = 215;
pub const PIN_OFF_RP: usize = 216;
pub const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
pub const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
pub const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;

/// Fixed-layout request handed to the Secure CTAP2 gateways. Mirrors
/// `ctap::REQ_LEN` in fw-secure -- the two must agree byte for byte.
pub const REQ_LEN: usize = 717;
/// Second allowList candidate. The first is the first entry that is
/// ours; when that one is credProtect level 3 -- unusable in an allowList
/// without user verification -- this is the first entry that is ours AND
/// usable without it. Secure picks between them once it knows whether UV
/// happened. Without this the second pass stopped at the first of ours,
/// and a level-3 credential listed first made every later usable one
/// unreachable for a client with no PIN token.
pub const REQ_OFF_CRED2: usize = 652;
pub const REQ_OFF_HAVE_CRED2: usize = 716;
pub const REQ_OFF_CRED_PROTECT: usize = 617;
/// pinUvAuthParam, carried across the boundary for Secure to verify.
///
/// NS parses it and does not act on it. That split is the point: the
/// proof of user verification is checked where the token lives, so a
/// bug in this file cannot manufacture one. Bit 0 of the flags byte
/// says only that the client *asked* for uv -- which is a request, not
/// evidence, and used to be treated as both.
/// Flags-byte bits for the pinUvAuthParam's shape; see `take_puat`.
pub const FLAG_PUAT_PRESENT: u8 = 0x40;
pub const FLAG_PUAT_MALFORMED: u8 = 0x80;
pub const REQ_OFF_PUAT_LEN: usize = 618;
pub const REQ_OFF_PUAT: usize = 619;
pub const REQ_OFF_PUAT_PROTO: usize = 651;
pub const PUAT_MAX: usize = 32;
pub const REQ_OFF_HS_FLAG: usize = 454;
pub const REQ_OFF_HS_KX: usize = 455;
pub const REQ_OFF_HS_KY: usize = 487;
pub const REQ_OFF_HS_SALT_LEN: usize = 519;
pub const REQ_OFF_HS_SALT: usize = 520;
pub const REQ_OFF_HS_AUTH_LEN: usize = 584;
pub const REQ_OFF_HS_AUTH: usize = 585;
pub const MAX_NAME: usize = 64;
pub const MAX_CRED_BLOB: usize = 32;
pub const MAX_RP_ID: usize = 128;
pub const MAX_USER_ID: usize = 64;
pub const REQ_OFF_RP_LEN: usize = 0;
pub const REQ_OFF_RP: usize = 1;
pub const REQ_OFF_FLAGS: usize = 129;
pub const REQ_OFF_CDH: usize = 130;
pub const REQ_OFF_CRED: usize = 162;
pub const REQ_OFF_USER_LEN: usize = 226;
pub const REQ_OFF_USER: usize = 227;
pub const REQ_OFF_BLOB_LEN: usize = 291;
pub const REQ_OFF_BLOB: usize = 292;
pub const REQ_OFF_NAME_LEN: usize = 324;
pub const REQ_OFF_NAME: usize = 325;
pub const REQ_OFF_DISPLAY_LEN: usize = 389;
pub const REQ_OFF_DISPLAY: usize = 390;
pub const CTAP2_ERR_INVALID_COMMAND: u8 = 0x01;
/// A parameter present with the wrong CBOR major type. Distinct from
/// INVALID_CBOR (undecodable) because the client did send valid CBOR;
/// it sent the wrong thing.
pub const CTAP2_ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;

/// Copy a pinUvAuthParam into the request for Secure to verify.
///
/// Three shapes cross the boundary, and Secure answers each differently
/// (CTAP 2.1 sec. 6.1.2 step 1, sec. 6.5.5.7):
///
///   absent          -> no proof offered; uv decided by options.uv alone
///   present, empty  -> the PIN PROBE. Platforms send `pinUvAuthParam:
///                      h''` to ask whether a PIN is set, and the answer
///                      is PIN_NOT_SET or PIN_INVALID -- never a served
///                      request. Chrome does this on every registration.
///   present, sized  -> a claim of verification, to be checked
///
/// The first version of this function recorded only a length, so an
/// empty or over-long param looked exactly like an absent one and the
/// probe was answered with a credential. Two flag bits now carry what
/// the length byte cannot: PUAT_PRESENT for any key 0x08/0x06, and
/// PUAT_MALFORMED when it was present but longer than any protocol
/// produces, which Secure refuses as PIN_AUTH_INVALID.
///
/// A protocol byte is recorded but not judged. NS deciding which
/// protocols are acceptable would put a policy decision on the untrusted
/// side of the boundary.
fn take_puat(r: &mut cborr::Reader, req: &mut [u8; REQ_LEN]) -> Result<(), u8> {
    let v = r
        .str_bytes(cborr::MAJOR_BYTES)
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    req[REQ_OFF_FLAGS] |= FLAG_PUAT_PRESENT;
    if v.len() <= PUAT_MAX {
        req[REQ_OFF_PUAT_LEN] = v.len() as u8;
        req[REQ_OFF_PUAT..REQ_OFF_PUAT + v.len()].copy_from_slice(v);
    } else {
        req[REQ_OFF_FLAGS] |= FLAG_PUAT_MALFORMED;
    }
    Ok(())
}

pub fn parse_make_credential(
    msg: &[u8],
    hybrid_alg: Option<i64>,
    req: &mut [u8; REQ_LEN],
    // Asking Secure whether a credential id is ours, injected rather
    // than called through the veneer directly. The excludeList check is
    // a CTAP2 MUST and a test has to be able to drive it both ways.
    is_ours: &mut dyn FnMut(&[u8], &[u8; 64]) -> bool,
) -> Result<(), u8> {
    let mut r = cborr::Reader::new(&msg[1..]);
    let n = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut have_cdh = false;
    let mut have_rp = false;
    let mut es256 = false;
    let mut exclude_at: Option<usize> = None;

    for _ in 0..n {
        let key = match r.uint() {
            Some(k) => k,
            // Non-integer key: not something CTAP2 defines at this level.
            None => return Err(CTAP2_ERR_INVALID_CBOR),
        };
        match key {
            1 => {
                let b = r
                    .str_bytes(cborr::MAJOR_BYTES)
                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                if b.len() != 32 {
                    return Err(CTAP2_ERR_INVALID_CBOR);
                }
                req[REQ_OFF_CDH..REQ_OFF_CDH + 32].copy_from_slice(b);
                have_cdh = true;
            }
            2 => {
                // rp is a map; we want its "id".
                let m = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                for _ in 0..m {
                    let k = r
                        .str_bytes(cborr::MAJOR_TEXT)
                        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    if k == b"id" {
                        let v = r
                            .str_bytes(cborr::MAJOR_TEXT)
                            .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                        if v.is_empty() || v.len() > MAX_RP_ID {
                            return Err(CTAP2_ERR_INVALID_CBOR);
                        }
                        req[REQ_OFF_RP_LEN] = v.len() as u8;
                        req[REQ_OFF_RP..REQ_OFF_RP + v.len()].copy_from_slice(v);
                        have_rp = true;
                    } else {
                        r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    }
                }
            }
            3 => {
                // user is a map; we want its "id" -- the handle a
                // discoverable credential has to hand back later.
                let m = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                for _ in 0..m {
                    let k = r
                        .str_bytes(cborr::MAJOR_TEXT)
                        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    if k == b"id" {
                        let v = r
                            .str_bytes(cborr::MAJOR_BYTES)
                            .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                        if v.is_empty() || v.len() > MAX_USER_ID {
                            return Err(CTAP2_ERR_INVALID_CBOR);
                        }
                        req[REQ_OFF_USER_LEN] = v.len() as u8;
                        req[REQ_OFF_USER..REQ_OFF_USER + v.len()].copy_from_slice(v);
                    } else if k == b"name" || k == b"displayName" {
                        // Kept, not dropped: CredentialManagement
                        // enumerates these and updateUserInformation
                        // exists to change them.
                        let v = r
                            .str_bytes(cborr::MAJOR_TEXT)
                            .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                        let l = v.len().min(MAX_NAME);
                        let (lo, off) = if k == b"name" {
                            (REQ_OFF_NAME_LEN, REQ_OFF_NAME)
                        } else {
                            (REQ_OFF_DISPLAY_LEN, REQ_OFF_DISPLAY)
                        };
                        req[lo] = l as u8;
                        req[off..off + l].copy_from_slice(&v[..l]);
                    } else {
                        r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    }
                }
            }
            4 => {
                // pubKeyCredParams: array of {alg, type}. Accept the
                // request only if ES256 (-7) is among the offers.
                let count = r.array().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                for _ in 0..count {
                    let m = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    for _ in 0..m {
                        let k = r
                            .str_bytes(cborr::MAJOR_TEXT)
                            .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                        if k == b"alg" {
                            // Negative ints encode as -(n+1): ES256 (-7)
                            // is major type 1 with argument 6.
                            match r.header() {
                                Some((cborr::MAJOR_NINT, arg)) => {
                                    let alg = -1 - (arg as i64);
                                    if alg == -7 {
                                        es256 = true;
                                    } else if Some(alg) == hybrid_alg {
                                        // Prefer the composite algorithm
                                        // whenever the client offers it:
                                        // it is the whole point of this
                                        // project, and the client asked.
                                        req[REQ_OFF_FLAGS] |= 0x02;
                                    }
                                }
                                Some(_) => {}
                                None => return Err(CTAP2_ERR_INVALID_CBOR),
                            }
                        } else {
                            r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                        }
                    }
                }
            }
            5 => {
                // excludeList. Remembered and walked after the loop,
                // once rp.id is known -- rather than relying on CTAP2
                // canonical ordering putting rp (key 2) before this one.
                //
                // It used to be collected into a fixed array of eight
                // and silently truncated. A relying party where the user
                // has credentials on a phone, two laptops and a couple
                // of keys sends more than that routinely, and if this
                // token's id landed at index 8 or later it was never
                // asked about: the registration succeeded and the user
                // ended up enrolled twice. Re-reading from the recorded
                // offset caps the list at nothing.
                exclude_at = Some(r.position());
                let mut peek = cborr::Reader::new(&msg[1 + r.position()..]);
                match peek.header() {
                    Some((cborr::MAJOR_ARRAY, _)) => {}
                    Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
                    None => return Err(CTAP2_ERR_INVALID_CBOR),
                }
                r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?;
            }
            6 => parse_extensions(&mut r, req)?,
            // 0x08 pinUvAuthParam, 0x09 pinUvAuthProtocol (sec. 6.1.1).
            8 => take_puat(&mut r, req)?,
            9 => {
                req[REQ_OFF_PUAT_PROTO] =
                    u8::try_from(r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)?).unwrap_or(0xff);
            }
            7 => {
                let m = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                for _ in 0..m {
                    let k = r
                        .str_bytes(cborr::MAJOR_TEXT)
                        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    let (major, arg) = r.header().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    if major != cborr::MAJOR_SIMPLE {
                        return Err(CTAP2_ERR_INVALID_CBOR);
                    }
                    // 21 = true, 20 = false. This records that the client
                    // ASKED for user verification. It is not evidence that
                    // any happened -- Secure decides that from the
                    // pinUvAuthParam above.
                    if k == b"uv" && arg == 21 {
                        req[REQ_OFF_FLAGS] |= 0x01;
                    }
                    if k == b"rk" && arg == 21 {
                        req[REQ_OFF_FLAGS] |= 0x04;
                    }
                }
            }
            _ => r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?,
        }
    }

    if !have_cdh || !have_rp {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    // A discoverable credential needs a user handle to be discoverable
    // by; without one the client has asked for something incoherent.
    if req[REQ_OFF_FLAGS] & 0x04 != 0 && req[REQ_OFF_USER_LEN] == 0 {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    // Accept if either algorithm we support was offered.
    if !es256 && req[REQ_OFF_FLAGS] & 0x02 == 0 {
        return Err(CTAP2_ERR_UNSUPPORTED_ALGORITHM);
    }
    // CTAP2 MUST: refuse if the excludeList names a credential we hold.
    // Every entry, in order, however long the list.
    if let Some(at) = exclude_at {
        let rp_len = req[REQ_OFF_RP_LEN] as usize;
        let mut rp_copy = [0u8; MAX_RP_ID];
        rp_copy[..rp_len].copy_from_slice(&req[REQ_OFF_RP..REQ_OFF_RP + rp_len]);
        let rp = &rp_copy[..rp_len];

        let mut e = cborr::Reader::new(&msg[1 + at..]);
        let count = e.array().ok_or(CTAP2_ERR_INVALID_CBOR)?;
        for _ in 0..count {
            let m = e.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
            for _ in 0..m {
                let k = e
                    .str_bytes(cborr::MAJOR_TEXT)
                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                if k == b"id" {
                    let v = e
                        .str_bytes(cborr::MAJOR_BYTES)
                        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    // Only a 64-byte id can be one of ours.
                    if v.len() == 64 {
                        let mut id = [0u8; 64];
                        id.copy_from_slice(v);
                        if is_ours(rp, &id) {
                            return Err(CTAP2_ERR_CREDENTIAL_EXCLUDED);
                        }
                    }
                } else {
                    e.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                }
            }
        }
    }
    Ok(())
}

/// Parse an `authenticatorGetAssertion` request.
///
/// The allowList is walked AFTER the main loop, from a second reader
/// positioned at it, and every entry is put to `is_ours` until one is.
/// Two things about that are deliberate.
///
/// It used to take the first 64-byte id and stop. A relying party lists
/// a user's credentials in its own order, so if the first belonged to
/// another authenticator -- or was one this token minted before a reset
/// rotated its keys -- that was the only one tried, and a credential
/// listed second was unreachable. Both other ports loop until one
/// recovers.
///
/// And it is a second pass rather than a buffer because the rpId (key 1)
/// is needed to ask the question and canonical CBOR ordering is the only
/// thing putting it before the allowList (key 3). Re-reading from the
/// recorded offset needs no stack for the list and puts no cap on its
/// length, where a fixed array would have had to refuse a long list
/// this token has no reason to refuse.
pub fn parse_get_assertion(
    msg: &[u8],
    req: &mut [u8; REQ_LEN],
    // 0 = not ours; otherwise 1 + the credential's credProtect level.
    level_of: &mut dyn FnMut(&[u8], &[u8; 64]) -> u8,
) -> Result<(), u8> {
    let mut r = cborr::Reader::new(&msg[1..]);
    let n = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut have_cdh = false;
    let mut have_rp = false;
    let mut have_cred = false;
    let mut allow_at: Option<usize> = None;

    for _ in 0..n {
        let key = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)?;
        match key {
            1 => {
                let v = r
                    .str_bytes(cborr::MAJOR_TEXT)
                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                if v.is_empty() || v.len() > MAX_RP_ID {
                    return Err(CTAP2_ERR_INVALID_CBOR);
                }
                req[REQ_OFF_RP_LEN] = v.len() as u8;
                req[REQ_OFF_RP..REQ_OFF_RP + v.len()].copy_from_slice(v);
                have_rp = true;
            }
            2 => {
                let b = r
                    .str_bytes(cborr::MAJOR_BYTES)
                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                if b.len() != 32 {
                    return Err(CTAP2_ERR_INVALID_CBOR);
                }
                req[REQ_OFF_CDH..REQ_OFF_CDH + 32].copy_from_slice(b);
                have_cdh = true;
            }
            3 => {
                // Remember where it starts, check its type, skip it for
                // now. It is walked below once rpId is known.
                allow_at = Some(r.position());
                let mut peek = cborr::Reader::new(&msg[1 + r.position()..]);
                match peek.header() {
                    Some((cborr::MAJOR_ARRAY, _)) => {}
                    // Present but not an array is a malformed request,
                    // not an absent parameter. Treating it as absent sent
                    // the token into discovery and had it sign with
                    // whichever resident credential it held for the rpId.
                    Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
                    None => return Err(CTAP2_ERR_INVALID_CBOR),
                }
                r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?;
            }
            4 => parse_extensions(&mut r, req)?,
            // 0x06 pinUvAuthParam, 0x07 pinUvAuthProtocol -- note the
            // keys differ from MakeCredential's 0x08/0x09 (sec. 6.2.1).
            6 => take_puat(&mut r, req)?,
            7 => {
                req[REQ_OFF_PUAT_PROTO] =
                    u8::try_from(r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)?).unwrap_or(0xff);
            }
            5 => {
                let m = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                for _ in 0..m {
                    let k = r
                        .str_bytes(cborr::MAJOR_TEXT)
                        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    let (major, arg) = r.header().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    if major != cborr::MAJOR_SIMPLE {
                        return Err(CTAP2_ERR_INVALID_CBOR);
                    }
                    // As above: a request, not evidence.
                    if k == b"uv" && arg == 21 {
                        req[REQ_OFF_FLAGS] |= 0x01;
                    }
                }
            }
            _ => r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?,
        }
    }

    if !have_cdh || !have_rp {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }

    // Second pass over the allowList, now that rpId is known.
    if let Some(at) = allow_at {
        let rp_len = req[REQ_OFF_RP_LEN] as usize;
        let rp = &req[REQ_OFF_RP..REQ_OFF_RP + rp_len];
        // Borrow of `req` ends before the write below.
        let mut rp_copy = [0u8; MAX_RP_ID];
        rp_copy[..rp_len].copy_from_slice(rp);
        let rp = &rp_copy[..rp_len];

        let mut a = cborr::Reader::new(&msg[1 + at..]);
        let count = a.array().ok_or(CTAP2_ERR_INVALID_CBOR)?;
        if count > 0 {
            req[REQ_OFF_FLAGS] |= 0x08;
        }
        // The first of ours is the primary candidate. If it is level 3
        // (unusable without UV when named), keep looking for the first
        // of ours that IS usable without UV and carry it as the second
        // candidate; Secure chooses once it has resolved UV. Stop asking
        // as soon as both slots are settled.
        let mut first_is_level3 = false;
        let mut have_cred2 = false;
        for _ in 0..count {
            let m = a.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
            for _ in 0..m {
                let k = a
                    .str_bytes(cborr::MAJOR_TEXT)
                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                if k == b"id" {
                    let v = a
                        .str_bytes(cborr::MAJOR_BYTES)
                        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    let settled = have_cred && (!first_is_level3 || have_cred2);
                    // Entries of the wrong length cannot be ours and are
                    // not asked.
                    if !settled && v.len() == 64 {
                        let mut id = [0u8; 64];
                        id.copy_from_slice(v);
                        let lvl = level_of(rp, &id);
                        if lvl != 0 {
                            if !have_cred {
                                req[REQ_OFF_CRED..REQ_OFF_CRED + 64].copy_from_slice(&id);
                                have_cred = true;
                                first_is_level3 = lvl == 4; // 1 + level 3
                            } else if lvl != 4 {
                                req[REQ_OFF_CRED2..REQ_OFF_CRED2 + 64].copy_from_slice(&id);
                                req[REQ_OFF_HAVE_CRED2] = 1;
                                have_cred2 = true;
                            }
                        }
                    }
                } else {
                    a.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                }
            }
        }
    }

    // An absent or empty allowList is no longer an error: the Secure
    // side answers it from the resident store. Only a list that WAS
    // given but named nothing of ours is a miss.
    if req[REQ_OFF_FLAGS] & 0x08 != 0 && !have_cred {
        return Err(CTAP2_ERR_NO_CREDENTIALS);
    }
    Ok(())
}

/// Parse a CTAP2 extensions map, recording which we support.
///
/// Unknown extensions are skipped rather than refused: CTAP2 says an
/// authenticator ignores what it does not implement, and a client that
/// asks for one it does not get simply sees no output for it.
pub fn parse_extensions(r: &mut cborr::Reader, req: &mut [u8; REQ_LEN]) -> Result<(), u8> {
    let m = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
    for _ in 0..m {
        let k = r
            .str_bytes(cborr::MAJOR_TEXT)
            .ok_or(CTAP2_ERR_INVALID_CBOR)?;
        if k == b"minPinLength" {
            let (major, arg) = r.header().ok_or(CTAP2_ERR_INVALID_CBOR)?;
            if major == cborr::MAJOR_SIMPLE && arg == 21 {
                req[REQ_OFF_FLAGS] |= 0x10;
            }
        } else if k == b"hmac-secret" {
            // Two shapes again: `true` at registration, a map of
            // {1: keyAgreement, 2: saltEnc, 3: saltAuth} at assertion.
            match r.header().ok_or(CTAP2_ERR_INVALID_CBOR)? {
                (cborr::MAJOR_SIMPLE, 21) => req[REQ_OFF_HS_FLAG] = 1,
                (cborr::MAJOR_SIMPLE, _) => {}
                (cborr::MAJOR_MAP, n) => {
                    req[REQ_OFF_HS_FLAG] = 1;
                    for _ in 0..n {
                        let hk = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                        match hk {
                            1 => {
                                let m = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                for _ in 0..m {
                                    let (major, arg) = r.header().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                    let label = match major {
                                        cborr::MAJOR_UINT => arg as i64,
                                        cborr::MAJOR_NINT => -1 - (arg as i64),
                                        _ => return Err(CTAP2_ERR_INVALID_CBOR),
                                    };
                                    match label {
                                        -2 | -3 => {
                                            let v = r
                                                .str_bytes(cborr::MAJOR_BYTES)
                                                .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                            if v.len() != 32 {
                                                return Err(CTAP2_ERR_INVALID_CBOR);
                                            }
                                            let off = if label == -2 {
                                                REQ_OFF_HS_KX
                                            } else {
                                                REQ_OFF_HS_KY
                                            };
                                            req[off..off + 32].copy_from_slice(v);
                                        }
                                        _ => r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?,
                                    }
                                }
                            }
                            2 => {
                                let v = r
                                    .str_bytes(cborr::MAJOR_BYTES)
                                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                let l = v.len().min(64);
                                req[REQ_OFF_HS_SALT_LEN] = l as u8;
                                req[REQ_OFF_HS_SALT..REQ_OFF_HS_SALT + l].copy_from_slice(&v[..l]);
                            }
                            3 => {
                                let v = r
                                    .str_bytes(cborr::MAJOR_BYTES)
                                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                let l = v.len().min(32);
                                req[REQ_OFF_HS_AUTH_LEN] = l as u8;
                                req[REQ_OFF_HS_AUTH..REQ_OFF_HS_AUTH + l].copy_from_slice(&v[..l]);
                            }
                            _ => r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?,
                        }
                    }
                }
                _ => return Err(CTAP2_ERR_INVALID_CBOR),
            }
        } else if k == b"credProtect" {
            match r.header().ok_or(CTAP2_ERR_INVALID_CBOR)? {
                (cborr::MAJOR_UINT, v) if (1..=3).contains(&v) => {
                    req[REQ_OFF_CRED_PROTECT] = v as u8
                }
                (cborr::MAJOR_UINT, _) => {}
                _ => return Err(CTAP2_ERR_INVALID_CBOR),
            }
        } else if k == b"credBlob" {
            // MakeCredential sends the bytes to store; GetAssertion
            // sends `true` to ask for them back. Same key, two shapes.
            match r.header().ok_or(CTAP2_ERR_INVALID_CBOR)? {
                (cborr::MAJOR_SIMPLE, 21) => req[REQ_OFF_FLAGS] |= 0x20,
                (cborr::MAJOR_SIMPLE, _) => {}
                (cborr::MAJOR_BYTES, len) => {
                    let n = len as usize;
                    if n > MAX_CRED_BLOB {
                        // Too long to keep: CTAP2 wants the credential
                        // made anyway, with the extension reporting
                        // false, so skip the bytes and store nothing.
                        r.take(n).ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    } else {
                        let v = r.take(n).ok_or(CTAP2_ERR_INVALID_CBOR)?;
                        req[REQ_OFF_BLOB_LEN] = n as u8;
                        req[REQ_OFF_BLOB..REQ_OFF_BLOB + n].copy_from_slice(v);
                    }
                }
                _ => return Err(CTAP2_ERR_INVALID_CBOR),
            }
        } else {
            r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?;
        }
    }
    Ok(())
}

/// Parse an `authenticatorCredentialManagement` request.
///
/// As with authenticatorConfig, subCommandParams is captured verbatim
/// as well as parsed, because the pinUvAuthParam is a MAC over those
/// exact bytes.
pub fn parse_cred_mgmt(msg: &[u8], req: &mut [u8; CM_REQ_LEN]) -> Result<(), u8> {
    let body = &msg[1..];
    let mut r = cborr::Reader::new(body);
    let n = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
    for _ in 0..n {
        let key = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)?;
        match key {
            1 => req[CM_OFF_SUB] = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)? as u8,
            2 => {
                let start = r.position();
                let m = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                for _ in 0..m {
                    let k = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    match k {
                        1 => {
                            let v = r
                                .str_bytes(cborr::MAJOR_BYTES)
                                .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                            if v.len() == 32 {
                                req[CM_OFF_RP_HASH..CM_OFF_RP_HASH + 32].copy_from_slice(v);
                                req[CM_OFF_HAVE_RP] = 1;
                            }
                        }
                        2 => {
                            // credentialID descriptor: {id, type}
                            let cm = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                            for _ in 0..cm {
                                let ck = r
                                    .str_bytes(cborr::MAJOR_TEXT)
                                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                if ck == b"id" {
                                    let v = r
                                        .str_bytes(cborr::MAJOR_BYTES)
                                        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                    if v.len() == 64 {
                                        req[CM_OFF_CRED..CM_OFF_CRED + 64].copy_from_slice(v);
                                        req[CM_OFF_HAVE_CRED] = 1;
                                    }
                                } else {
                                    r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                }
                            }
                        }
                        3 => {
                            // user entity: {id, name, displayName}
                            let um = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                            for _ in 0..um {
                                let uk = r
                                    .str_bytes(cborr::MAJOR_TEXT)
                                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                if uk == b"id" {
                                    let v = r
                                        .str_bytes(cborr::MAJOR_BYTES)
                                        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                    let l = v.len().min(64);
                                    req[CM_OFF_USER_LEN] = l as u8;
                                    req[CM_OFF_USER..CM_OFF_USER + l].copy_from_slice(&v[..l]);
                                } else if uk == b"name" || uk == b"displayName" {
                                    let v = r
                                        .str_bytes(cborr::MAJOR_TEXT)
                                        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                    let l = v.len().min(MAX_NAME);
                                    let (lo, off) = if uk == b"name" {
                                        (CM_OFF_NAME_LEN, CM_OFF_NAME)
                                    } else {
                                        (CM_OFF_DISPLAY_LEN, CM_OFF_DISPLAY)
                                    };
                                    req[lo] = l as u8;
                                    req[off..off + l].copy_from_slice(&v[..l]);
                                } else {
                                    r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                }
                            }
                        }
                        _ => r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?,
                    }
                }
                let end = r.position();
                let len = (end - start).min(256);
                req[CM_OFF_PARAMS_LEN] = (len >> 8) as u8;
                req[CM_OFF_PARAMS_LEN + 1] = len as u8;
                req[CM_OFF_PARAMS..CM_OFF_PARAMS + len].copy_from_slice(&body[start..start + len]);
            }
            // Keys 3 and 4 carry pinUvAuthProtocol and pinUvAuthParam,
            // and clients disagree about which is which. Rather than
            // hard-code an order, dispatch on the TYPE: the param is a
            // byte string, the protocol an unsigned int. The protocol
            // value is ignored -- this image implements v1 only.
            3 | 4 => match r.header().ok_or(CTAP2_ERR_INVALID_CBOR)? {
                (cborr::MAJOR_BYTES, len) => {
                    let l = (len as usize).min(32);
                    let v = r.take(len as usize).ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    req[CM_OFF_AUTH_LEN] = l as u8;
                    req[CM_OFF_AUTH..CM_OFF_AUTH + l].copy_from_slice(&v[..l]);
                }
                (cborr::MAJOR_UINT, _) => {}
                _ => return Err(CTAP2_ERR_INVALID_CBOR),
            },
            _ => r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    if req[CM_OFF_SUB] == 0 {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok(())
}

/// Parse an `authenticatorConfig` request into the fixed layout.
///
/// subCommandParams is copied out **verbatim** as well as parsed: the
/// pinUvAuthParam is computed over those exact bytes, so re-encoding
/// them would break the MAC even if the meaning survived.
pub fn parse_config(msg: &[u8], req: &mut [u8; CONFIG_REQ_LEN]) -> Result<(), u8> {
    let body = &msg[1..];
    let mut r = cborr::Reader::new(body);
    let n = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
    for _ in 0..n {
        let key = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)?;
        match key {
            1 => req[CFG_OFF_SUB] = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)? as u8,
            2 => {
                let start = r.position();
                // Walk the params map, pulling out the fields we know
                // while remembering where the encoding began and ended.
                let m = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                for _ in 0..m {
                    let k = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    match k {
                        1 => req[CFG_OFF_NEW_LEN] = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)? as u8,
                        2 => {
                            let count = r.array().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                            let mut stored = 0usize;
                            for _ in 0..count {
                                let v = r
                                    .str_bytes(cborr::MAJOR_TEXT)
                                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                                if stored < 4 && !v.is_empty() && v.len() <= MAX_RP_ID {
                                    let base = CFG_OFF_RPS + stored * 129;
                                    req[base] = v.len() as u8;
                                    req[base + 1..base + 1 + v.len()].copy_from_slice(v);
                                    stored += 1;
                                }
                            }
                            req[CFG_OFF_RP_COUNT] = stored as u8;
                        }
                        3 => {
                            let (major, arg) = r.header().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                            if major != cborr::MAJOR_SIMPLE {
                                return Err(CTAP2_ERR_INVALID_CBOR);
                            }
                            req[CFG_OFF_FORCE] = if arg == 21 { 2 } else { 1 };
                        }
                        _ => r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?,
                    }
                }
                let end = r.position();
                let len = (end - start).min(256);
                req[CFG_OFF_PARAMS_LEN] = (len >> 8) as u8;
                req[CFG_OFF_PARAMS_LEN + 1] = len as u8;
                req[CFG_OFF_PARAMS..CFG_OFF_PARAMS + len]
                    .copy_from_slice(&body[start..start + len]);
            }
            // Keys 3 and 4 carry pinUvAuthProtocol and pinUvAuthParam,
            // and clients disagree about which is which. Rather than
            // hard-code an order, dispatch on the TYPE: the param is a
            // byte string, the protocol an unsigned int. The protocol
            // value is ignored -- this image implements v1 only.
            3 | 4 => match r.header().ok_or(CTAP2_ERR_INVALID_CBOR)? {
                (cborr::MAJOR_BYTES, len) => {
                    let l = (len as usize).min(32);
                    let v = r.take(len as usize).ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    req[CFG_OFF_AUTH_LEN] = l as u8;
                    req[CFG_OFF_AUTH..CFG_OFF_AUTH + l].copy_from_slice(&v[..l]);
                }
                (cborr::MAJOR_UINT, _) => {}
                _ => return Err(CTAP2_ERR_INVALID_CBOR),
            },
            _ => r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    Ok(())
}

/// Parse an `authenticatorClientPIN` request into the fixed layout.
///
/// The COSE key in `keyAgreement` (key 3) is a nested map with negative
/// integer labels; only x (-2) and y (-3) matter here, and everything
/// else in it is skipped rather than validated. The curve and algorithm
/// are Secure's business -- it rebuilds the point and will reject
/// anything that is not a valid P-256 affine.
pub fn parse_client_pin(msg: &[u8], req: &mut [u8; PIN_REQ_LEN]) -> Result<(), u8> {
    let mut r = cborr::Reader::new(&msg[1..]);
    let n = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
    for _ in 0..n {
        let key = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)?;
        match key {
            1 => req[PIN_OFF_PROTO] = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)? as u8,
            2 => req[PIN_OFF_SUB] = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)? as u8,
            3 => {
                let m = r.map().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                for _ in 0..m {
                    let (major, arg) = r.header().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                    let label = match major {
                        cborr::MAJOR_UINT => arg as i64,
                        cborr::MAJOR_NINT => -1 - (arg as i64),
                        _ => return Err(CTAP2_ERR_INVALID_CBOR),
                    };
                    match label {
                        -2 | -3 => {
                            let v = r
                                .str_bytes(cborr::MAJOR_BYTES)
                                .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                            if v.len() != 32 {
                                return Err(CTAP2_ERR_INVALID_CBOR);
                            }
                            let off = if label == -2 { PIN_OFF_KX } else { PIN_OFF_KY };
                            req[off..off + 32].copy_from_slice(v);
                            req[PIN_OFF_FLAGS] |= 0x01;
                        }
                        _ => r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?,
                    }
                }
            }
            4 => {
                let v = r
                    .str_bytes(cborr::MAJOR_BYTES)
                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                let l = v.len().min(32);
                req[PIN_OFF_AUTH_LEN] = l as u8;
                req[PIN_OFF_AUTH..PIN_OFF_AUTH + l].copy_from_slice(&v[..l]);
            }
            5 => {
                let v = r
                    .str_bytes(cborr::MAJOR_BYTES)
                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                if v.len() > 80 {
                    return Err(CTAP2_ERR_INVALID_CBOR);
                }
                req[PIN_OFF_NEW_LEN] = v.len() as u8;
                req[PIN_OFF_NEW..PIN_OFF_NEW + v.len()].copy_from_slice(v);
            }
            6 => {
                let v = r
                    .str_bytes(cborr::MAJOR_BYTES)
                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                let l = v.len().min(32);
                req[PIN_OFF_HASH_LEN] = l as u8;
                req[PIN_OFF_HASH..PIN_OFF_HASH + l].copy_from_slice(&v[..l]);
            }
            9 => req[PIN_OFF_PERMS] = r.uint().ok_or(CTAP2_ERR_INVALID_CBOR)? as u8,
            0x0a => {
                let v = r
                    .str_bytes(cborr::MAJOR_TEXT)
                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                if v.is_empty() || v.len() > MAX_RP_ID {
                    return Err(CTAP2_ERR_INVALID_CBOR);
                }
                req[PIN_OFF_RP_LEN] = v.len() as u8;
                req[PIN_OFF_RP..PIN_OFF_RP + v.len()].copy_from_slice(v);
                req[PIN_OFF_FLAGS] |= 0x02;
            }
            _ => r.skip().ok_or(CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    if req[PIN_OFF_SUB] == 0 {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok(())
}
