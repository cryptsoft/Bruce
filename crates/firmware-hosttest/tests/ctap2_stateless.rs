// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! getInfo, Selection and Reset -- phase 2 of the CTAP2 surface.
//!
//! getInfo is what every relying party and every browser reads before
//! deciding what this token can do. Every wrong answer in it is a
//! capability that goes unused or a ceremony that fails after the user
//! has already been prompted, and none of it was pinned: the conformance
//! suite reads getInfo but checks a handful of fields, not the map.
//!
//! Reset is the other side -- it destroys everything, and the failure
//! mode for an incomplete one is a token that looks factory-fresh while
//! still holding the previous owner's credentials.
//!
//! The signing is stubbed here; see `ctap2_dispatch.rs` for what that
//! costs. Nothing in this file touches a signature.

use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

use fw::client_pin::PinSession;
use fw::ctap2::{
    self, CredStore, HostOp, CTAP2_GET_INFO, CTAP2_LARGE_BLOBS, CTAP2_OK, CTAP2_RESET_CMD,
    CTAP2_SELECTION,
};
use fw::mldsa_alg::{COSE_ALG_MLDSA44_ES256, COSE_ALG_MLDSA65_ES256, COSE_ALG_MLDSA87_ES384};
use fw::trng::Trng;

struct Device {
    _guard: fw::testlock::Guard,
    trng: Trng,
    session: PinSession,
    store: CredStore,
}

impl Device {
    fn new() -> Self {
        let guard = fw::testlock::acquire();
        rp235x_hal::reset();
        rp235x_hal::reset_counts();
        fw::core1_signer::CORE1_SIGNER.reset_for_test();
        let mut trng = Trng::new_for_test();
        let store = CredStore::load(&mut trng);
        let session = PinSession::new(&mut trng);
        Self {
            _guard: guard,
            trng,
            session,
            store,
        }
    }

    fn send(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut host = |_op: HostOp| true;
        ctap2::handle_cbor(
            bytes,
            &mut self.trng,
            &mut self.session,
            &mut self.store,
            &mut host,
            0,
            [0, 0, 0, 1],
        )
        .to_vec()
    }

    /// getInfo, decoded into the CBOR map it carries.
    fn get_info(&mut self) -> Vec<(Value, Value)> {
        let r = self.send(&[CTAP2_GET_INFO]);
        assert_eq!(r[0], CTAP2_OK, "getInfo returned {:#04x}", r[0]);
        match pqf_cbor::decode(&r[1..]).expect("getInfo body is not decodable CBOR") {
            Value::Map(m) => m,
            other => panic!("getInfo body is {other:?}, not a map"),
        }
    }
}

/// One entry of the getInfo map, by its integer key.
fn key(map: &[(Value, Value)], k: u64) -> Option<&Value> {
    map.iter().find_map(|(kk, v)| match kk {
        Value::Uint(n) if *n == k => Some(v),
        _ => None,
    })
}

/// A named boolean out of getInfo's options map (key 0x04).
fn option(map: &[(Value, Value)], name: &str) -> Option<bool> {
    match key(map, 0x04)? {
        Value::Map(opts) => opts.iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(t), Value::Bool(b)) if t == name => Some(*b),
            _ => None,
        }),
        _ => None,
    }
}

fn text_array(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a
            .iter()
            .filter_map(|x| match x {
                Value::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

// ---- getInfo: the keys a client actually reads ------------------------

#[test]
fn get_info_advertises_ctap_2_1() {
    // A FIDO_2_0-only device gets Chrome's legacy security-key path
    // rather than the modern passkey path -- which is what made this
    // token "hijack" registrations before 2.1 was advertised.
    let mut d = Device::new();
    let m = d.get_info();
    let versions = text_array(key(&m, 0x01).expect("no versions key"));
    assert!(versions.iter().any(|v| v == "FIDO_2_0"), "FIDO_2_0 missing");
    assert!(
        versions.iter().any(|v| v == "FIDO_2_1"),
        "FIDO_2_1 missing -- browsers fall back to the legacy path without it"
    );
}

#[test]
fn get_info_advertises_the_extensions_it_implements() {
    let mut d = Device::new();
    let m = d.get_info();
    let ext = text_array(key(&m, 0x02).expect("no extensions key"));
    for want in [
        "credProtect",
        "hmac-secret",
        "credBlob",
        "largeBlobKey",
        "minPinLength",
    ] {
        assert!(
            ext.iter().any(|e| e == want),
            "extension {want} is implemented but not advertised: {ext:?}"
        );
    }
}

#[test]
fn the_aaguid_is_sixteen_bytes_and_not_all_zero() {
    // An all-zero AAGUID means "no identity", which is legal but is not
    // what this device intends; relying parties key attestation policy
    // off it.
    let mut d = Device::new();
    let m = d.get_info();
    match key(&m, 0x03).expect("no aaguid key") {
        Value::Bytes(b) => {
            assert_eq!(b.len(), 16, "an AAGUID is 16 bytes");
            assert_ne!(b[..], [0u8; 16][..], "the AAGUID is all zeroes");
        }
        other => panic!("aaguid is {other:?}, not a byte string"),
    }
}

#[test]
fn the_options_map_matches_what_the_firmware_implements() {
    // Each of these is a discovery signal a platform keys off. Claiming
    // one that is not implemented produces a ceremony that fails after
    // the user has been prompted; omitting one that is leaves a feature
    // permanently unused.
    let mut d = Device::new();
    let m = d.get_info();
    for (name, want) in [
        ("plat", false), // roaming, not platform-bound
        ("rk", true),    // discoverable credentials
        ("up", true),    // user presence
        ("makeCredUvNotRqd", true),
        ("credMgmt", true),
        ("authnrCfg", true),
        ("pinUvAuthToken", true),
        ("setMinPINLength", true),
        ("largeBlobs", true),
    ] {
        assert_eq!(
            option(&m, name),
            Some(want),
            "option {name} should be {want}"
        );
    }
}

#[test]
fn client_pin_tracks_whether_a_pin_is_actually_set() {
    // The one option here that is state, not capability, so it is the
    // one that can drift. Reporting true with no PIN sends a platform
    // down a PIN flow that cannot succeed; reporting false with a PIN
    // set makes it skip verification it should have demanded.
    let mut d = Device::new();
    assert_eq!(
        option(&d.get_info(), "clientPin"),
        Some(false),
        "a fresh device claims a PIN is set"
    );

    d.store.pin.pin_set = 1;
    d.store.persist();
    assert_eq!(
        option(&d.get_info(), "clientPin"),
        Some(true),
        "getInfo did not notice a PIN being set"
    );
}

#[test]
fn always_uv_is_advertised_false_by_default() {
    let mut d = Device::new();
    assert_eq!(option(&d.get_info(), "alwaysUv"), Some(false));
}

#[test]
fn the_advertised_max_message_size_matches_the_transport() {
    // 7609 is what CTAP HID can carry in one command: 57 + 128 * 59. A
    // larger claim means a response the transport truncates; a smaller
    // one means a client refuses a credential the device could make.
    let mut d = Device::new();
    let m = d.get_info();
    match key(&m, 0x05).expect("no maxMsgSize") {
        Value::Uint(n) => assert_eq!(*n, 7609, "maxMsgSize disagrees with the transport"),
        other => panic!("maxMsgSize is {other:?}"),
    }
    assert_eq!(57 + 128 * 59, 7609, "the transport arithmetic changed");
}

#[test]
fn both_pin_protocol_versions_are_advertised() {
    // v1 is what Chrome on macOS uses; v2 is required for L1
    // certification. Dropping either silently loses a platform.
    let mut d = Device::new();
    let m = d.get_info();
    match key(&m, 0x06).expect("no pinUvAuthProtocols") {
        Value::Array(a) => {
            let v: Vec<u64> = a
                .iter()
                .filter_map(|x| match x {
                    Value::Uint(n) => Some(*n),
                    _ => None,
                })
                .collect();
            assert!(v.contains(&1), "PIN protocol v1 not advertised: {v:?}");
            assert!(v.contains(&2), "PIN protocol v2 not advertised: {v:?}");
        }
        other => panic!("pinUvAuthProtocols is {other:?}"),
    }
}

#[test]
fn the_advertised_credential_id_length_matches_the_format() {
    // A client sizes its storage from this. The sealed id is 161 bytes.
    let mut d = Device::new();
    let m = d.get_info();
    match key(&m, 0x08).expect("no maxCredentialIdLength") {
        Value::Uint(n) => assert_eq!(
            *n as usize,
            fw::credential_id::CRED_ID_LEN,
            "the advertised id length disagrees with the format"
        ),
        other => panic!("maxCredentialIdLength is {other:?}"),
    }
}

#[test]
fn usb_is_the_only_transport_claimed() {
    let mut d = Device::new();
    let m = d.get_info();
    assert_eq!(
        text_array(key(&m, 0x09).expect("no transports")),
        vec!["usb"]
    );
}

/// The `alg` values out of getInfo's algorithms array (key 0x0a).
fn advertised_algs(map: &[(Value, Value)]) -> Vec<i64> {
    match key(map, 0x0a).expect("no algorithms key") {
        Value::Array(a) => a
            .iter()
            .map(|e| match e {
                Value::Map(mm) => mm
                    .iter()
                    .find_map(|(k, v)| match (k, v) {
                        (Value::Text(t), Value::Nint(n)) if t == "alg" => Some(*n),
                        (Value::Text(t), Value::Uint(n)) if t == "alg" => Some(*n as i64),
                        _ => None,
                    })
                    .expect("an algorithms entry has no alg field"),
                other => panic!("an algorithms entry is {other:?}"),
            })
            .collect(),
        other => panic!("algorithms is {other:?}"),
    }
}

#[test]
fn all_three_composites_are_advertised_strongest_first() {
    // Deliberately unconditional: every build advertises -56/-55/-54 so
    // a relying party's intersection check passes whatever it asked for,
    // and MakeCredential falls back to ES256 when the RP named a
    // composite this build cannot mint.
    //
    // So this list is what the token *offers*, not what it can produce,
    // and the gap is real -- it is what made the conformance suite's check
    // read a pass where a MakeCredential would have failed. Anything
    // asking "can this token mint X" has to try minting it.
    let mut d = Device::new();
    let algs = advertised_algs(&d.get_info());
    assert_eq!(
        &algs[..3],
        &[
            COSE_ALG_MLDSA87_ES384,
            COSE_ALG_MLDSA65_ES256,
            COSE_ALG_MLDSA44_ES256
        ],
        "the composites are not advertised strongest-first"
    );
}

#[test]
fn the_advertised_list_is_exactly_the_draft_04_ids_and_es256() {
    // The wire values, spelled out once as a tripwire: the named
    // constants above could all move together and the ordering test
    // would still pass. -54/-55/-56 are the ids draft-ietf-jose-pq-
    // composite-sigs-04 requests; a relabel has to update this line on
    // purpose. -51/-52/-53 (draft -02's request, since assigned by
    // RFC 9864 to ESP384 / ESP512 / Ed448) and the pure ML-DSA ids
    // -48/-49/-50 must not appear at all.
    let mut d = Device::new();
    let algs = advertised_algs(&d.get_info());
    let want: &[i64] = if cfg!(feature = "ed25519") {
        &[-56, -55, -54, -8, -7]
    } else {
        &[-56, -55, -54, -7]
    };
    assert_eq!(algs, want, "getInfo algorithms is not the draft -04 list");
    for old in [-48, -49, -50, -51, -52, -53] {
        assert!(
            !algs.contains(&old),
            "getInfo still advertises {old}: {algs:?}"
        );
    }
}

#[test]
fn es256_is_advertised_last_as_the_universal_floor() {
    // Order is preference. ES256 has to be present -- it is the only
    // algorithm every relying party accepts, and the fallback when a
    // requested composite is not mintable -- and it has to be last, or a
    // platform taking the head of the list would never see a composite.
    let mut d = Device::new();
    let algs = advertised_algs(&d.get_info());
    assert_eq!(*algs.last().unwrap(), -7, "ES256 is not the final fallback");
    assert!(algs[0] < -7, "a composite does not outrank ES256");
}

#[test]
fn this_builds_own_composite_is_among_those_advertised() {
    // The weaker half of the check above, but the one that would catch a
    // build configured for a level nobody can ask for.
    let mut d = Device::new();
    let algs = advertised_algs(&d.get_info());
    assert!(
        algs.contains(&fw::mldsa_alg::COSE_ALG_HYBRID_MLDSA),
        "this build mints {} but does not advertise it: {algs:?}",
        fw::mldsa_alg::COSE_ALG_HYBRID_MLDSA
    );
}

#[test]
fn the_large_blob_limit_matches_the_sector() {
    let mut d = Device::new();
    let m = d.get_info();
    match key(&m, 0x0b).expect("no maxSerializedLargeBlobArray") {
        Value::Uint(n) => assert_eq!(
            *n as usize,
            fw::flash_store::MAX_LARGE_BLOB_LEN,
            "the advertised largeBlob limit disagrees with the sector"
        ),
        other => panic!("maxSerializedLargeBlobArray is {other:?}"),
    }
}

#[test]
fn a_fresh_device_does_not_force_a_pin_change() {
    let mut d = Device::new();
    let m = d.get_info();
    assert_eq!(
        key(&m, 0x0c),
        Some(&Value::Bool(false)),
        "forcePINChange on a fresh device"
    );
}

#[test]
fn the_minimum_pin_length_is_the_ctap_default() {
    let mut d = Device::new();
    let m = d.get_info();
    match key(&m, 0x0d).expect("no minPINLength") {
        Value::Uint(n) => assert_eq!(*n, 4, "CTAP2 default minimum is 4 code points"),
        other => panic!("minPINLength is {other:?}"),
    }
}

#[test]
fn get_info_is_stable_across_calls() {
    // A client may read it more than once, and a device whose answer
    // moved would be reporting state it should not.
    let mut d = Device::new();
    let a = d.send(&[CTAP2_GET_INFO]);
    let b = d.send(&[CTAP2_GET_INFO]);
    assert_eq!(a, b, "two getInfo calls disagreed");
}

#[test]
fn get_info_ignores_trailing_parameters() {
    // getInfo takes none. A client that sends some should not change the
    // answer, and must not be able to make it fail.
    let mut d = Device::new();
    let plain = d.send(&[CTAP2_GET_INFO]);
    let with_junk = d.send(&[CTAP2_GET_INFO, 0xa1, 0x01, 0x02]);
    assert_eq!(with_junk[0], CTAP2_OK, "getInfo failed on trailing bytes");
    assert_eq!(
        plain, with_junk,
        "trailing bytes changed the getInfo answer"
    );
}

#[test]
fn the_response_fits_the_size_it_advertises() {
    // getInfo has grown with every feature. If it ever passed 7609 the
    // transport would truncate it and no client could read anything.
    let mut d = Device::new();
    let r = d.send(&[CTAP2_GET_INFO]);
    assert!(
        r.len() <= 7609,
        "getInfo is {} bytes, past the maxMsgSize it advertises",
        r.len()
    );
}

// ---- Selection --------------------------------------------------------

#[test]
fn selection_needs_a_gesture_and_says_so_when_it_does_not_get_one() {
    // Covered in dispatch too, repeated here because it is the whole of
    // what Selection does and the regression it guards was user-visible:
    // an instant OK wins every selection race, so the browser never
    // offers another authenticator and never prompts.
    let mut d = Device::new();
    assert_eq!(d.send(&[CTAP2_SELECTION])[0], CTAP2_OK);
    drop(d);

    let mut d = Device::new();
    let mut refuse = |_op: HostOp| false;
    let r = ctap2::handle_cbor(
        &[CTAP2_SELECTION],
        &mut d.trng,
        &mut d.session,
        &mut d.store,
        &mut refuse,
        0,
        [0, 0, 0, 1],
    );
    assert_ne!(r[0], CTAP2_OK, "selection succeeded with no gesture");
}

// ---- Reset ------------------------------------------------------------

#[test]
fn reset_succeeds_on_a_fresh_device() {
    let mut d = Device::new();
    assert_eq!(d.send(&[CTAP2_RESET_CMD])[0], CTAP2_OK);
}

#[test]
fn reset_clears_the_pin() {
    // CTAP 2.1 6.6: reset destroys all device data. A PIN surviving one
    // would leave a token the new owner cannot configure and the old
    // owner can still verify against.
    let mut d = Device::new();
    d.store.pin.pin_set = 1;
    d.store.pin.retries_left = 3;
    d.store.persist();

    assert_eq!(d.send(&[CTAP2_RESET_CMD])[0], CTAP2_OK);
    assert_eq!(d.store.pin.pin_set, 0, "the PIN survived a reset");
    assert_eq!(
        option(&d.get_info(), "clientPin"),
        Some(false),
        "getInfo still advertises a PIN after a reset"
    );
}

/// The CTAP 2.1 initial largeBlob array: `0x80` (CBOR empty array)
/// followed by the first 16 bytes of SHA-256 over that one byte.
fn initial_large_blob_array() -> Vec<u8> {
    let mut v = vec![0x80u8];
    v.extend_from_slice(&fw::bc_crypto::sha256(&[0x80u8])[..16]);
    v
}

#[test]
fn reset_clears_the_large_blob_array() {
    // It lives in its own sector, untouched by the credential wipe, so it
    // is the part most likely to be forgotten -- and a relying party can
    // put anything in it.
    let mut d = Device::new();
    fw::flash_store::write_large_blob_sector(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(fw::flash_store::read_large_blob_sector().is_some());

    assert_eq!(d.send(&[CTAP2_RESET_CMD])[0], CTAP2_OK);
    assert!(
        fw::flash_store::read_large_blob_sector().is_none(),
        "the largeBlob sector still held data after a reset"
    );
}

#[test]
fn a_reset_array_reads_back_as_the_spec_initial_value() {
    // Erasing the sector is only half of it. What a host sees is what
    // largeBlobs *serves*, and CTAP 2.1 6.10 says a reset device serves
    // the initial value -- an empty CBOR array plus its truncated hash --
    // not an empty response. A client validates that hash, so serving
    // nothing reads as a corrupt array rather than an empty one.
    //
    let mut d = Device::new();
    fw::flash_store::write_large_blob_sector(&[9; 64]);
    assert_eq!(d.send(&[CTAP2_RESET_CMD])[0], CTAP2_OK);

    let want = initial_large_blob_array();
    // {0x01: get, 0x03: offset} -- CTAP 2.1 sec. 6.10 numbering.
    let r = d.send(&[CTAP2_LARGE_BLOBS, 0xa2, 0x01, want.len() as u8, 0x03, 0x00]);
    assert_eq!(r[0], CTAP2_OK, "largeBlobs get failed after a reset");

    let got = match pqf_cbor::decode(&r[1..]).expect("largeBlobs body is not CBOR") {
        Value::Map(m) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Uint(1), Value::Bytes(b)) => Some(b.clone()),
                _ => None,
            })
            .expect("no config field in the largeBlobs response"),
        other => panic!("largeBlobs body is {other:?}"),
    };
    assert_eq!(got, want, "a reset device does not serve the initial array");
}

#[test]
fn a_spec_conformant_large_blob_get_is_understood() {
    // This used to be the record of a deviation. CTAP 2.1 sec. 6.10.2
    // numbers the parameters get=0x01, set=0x02, offset=0x03; both
    // firmware ports numbered them offset=0x01, get=0x02, set=0x03 --
    // the same three keys rotated -- and the in-house client was written
    // to match the firmware rather than the spec. Every in-house test
    // passed and no conformant platform could read the array at all.
    //
    // Kept as a test rather than deleted: it is the exact request a
    // browser sends, and it is the one that used to come back
    // CTAP2_ERR_MISSING_PARAMETER.
    let mut d = Device::new();
    // {0x01: 17, 0x03: 0} -- get 17 bytes at offset 0.
    let r = d.send(&[CTAP2_LARGE_BLOBS, 0xa2, 0x01, 0x11, 0x03, 0x00]);
    assert_eq!(
        r[0], CTAP2_OK,
        "a spec-conformant largeBlobs get was refused"
    );
    let got = match pqf_cbor::decode(&r[1..]).expect("largeBlobs body is not CBOR") {
        Value::Map(m) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Uint(1), Value::Bytes(b)) => Some(b.clone()),
                _ => None,
            })
            .expect("no config field in the largeBlobs response"),
        other => panic!("largeBlobs body is {other:?}"),
    };
    assert_eq!(got, initial_large_blob_array());
}

#[test]
fn reset_invalidates_the_pin_session() {
    // A live pinUvAuthToken across a reset would authorise operations on
    // a device that is meant to have forgotten the PIN it was minted
    // under.
    let mut d = Device::new();
    d.session.token_active = true;
    d.session.permissions = 0xff;

    assert_eq!(d.send(&[CTAP2_RESET_CMD])[0], CTAP2_OK);
    assert!(!d.session.token_active, "a pinUvAuthToken survived a reset");
    assert_eq!(d.session.permissions, 0, "permissions survived a reset");
}

#[test]
fn reset_leaves_a_device_that_still_answers() {
    // The failure to avoid is a reset that wipes something it needs. The
    // master keys live in their own sector, and a token that lost them
    // could never mint a credential again.
    let mut d = Device::new();
    assert_eq!(d.send(&[CTAP2_RESET_CMD])[0], CTAP2_OK);
    let m = d.get_info();
    assert!(key(&m, 0x01).is_some(), "getInfo broke after a reset");
    assert_eq!(d.store.active_count(), 0);
    assert!(
        fw::flash_store::read_key_sector().is_some(),
        "reset destroyed the master key sector"
    );
}

#[test]
fn reset_rotates_the_credential_master_keys() {
    // Wiping the slots is not enough. A credential id is a sealed blob
    // the *host* holds, so a host that cached one before the reset could
    // still present it afterwards; only rotating the keys it was sealed
    // under makes it undecryptable. Both keys, and on the die -- keeping
    // the old ones in flash would restore them at the next boot.
    let mut d = Device::new();
    let (aes_before, hmac_before) =
        fw::flash_store::read_key_sector().expect("no master keys before the reset");

    assert_eq!(d.send(&[CTAP2_RESET_CMD])[0], CTAP2_OK);

    let (aes_after, hmac_after) =
        fw::flash_store::read_key_sector().expect("the master key sector vanished on reset");
    assert_ne!(aes_before, aes_after, "the AES master key survived a reset");
    assert_ne!(
        hmac_before, hmac_after,
        "the HMAC master key survived a reset"
    );
    assert_eq!(
        d.store.key_handle_aes_key, aes_after,
        "flash and RAM disagree after a reset"
    );
}

#[test]
fn reset_returns_the_configuration_to_factory_defaults() {
    // AuthenticatorConfig state is a separate sector's worth of policy --
    // alwaysUv, a raised minimum PIN length, an RP allowlist. A reset
    // that left any of it would hand the next owner a token they cannot
    // configure back down.
    let mut d = Device::new();
    d.store.always_uv = true;
    d.store.min_pin_length = 8;
    d.store.persist();

    assert_eq!(d.send(&[CTAP2_RESET_CMD])[0], CTAP2_OK);
    assert!(!d.store.always_uv, "alwaysUv survived a reset");
    assert_eq!(
        d.store.min_pin_length, 0,
        "a raised minimum PIN length survived a reset"
    );

    let m = d.get_info();
    assert_eq!(option(&m, "alwaysUv"), Some(false));
    match key(&m, 0x0d).expect("no minPINLength") {
        Value::Uint(n) => assert_eq!(*n, 4, "getInfo still reports the old minimum"),
        other => panic!("minPINLength is {other:?}"),
    }
}

#[test]
fn reset_is_idempotent() {
    let mut d = Device::new();
    for i in 0..3 {
        assert_eq!(d.send(&[CTAP2_RESET_CMD])[0], CTAP2_OK, "reset {i} failed");
    }
    assert_eq!(d.store.active_count(), 0);
}
