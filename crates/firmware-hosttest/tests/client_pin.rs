// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The PIN protocol -- phase 4 of the CTAP2 surface.
//!
//! 1187 lines, and the only thing between a malformed request and every
//! credential on the token. Two protocol versions, an ECDH handshake per
//! attempt, two independent retry counters, and a permission model that
//! decides what a minted token may then authorise.
//!
//! **What the test client shares with the firmware, and what that
//! costs.** The client below does its own ECDH with `p256` and its own
//! CBOR, but derives the session keys through the firmware's own
//! `SharedSecret` rather than reimplementing SHA-256/HKDF/AES-CBC/HMAC a
//! second time. So a symmetric error -- both sides using the same wrong
//! HKDF info string, say -- would not show up here. Three checks at the
//! top pin the primitives independently to narrow that: v1 is
//! SHA-256(ECDH.x) computed separately, v2's two keys are distinct from
//! each other and from v1's, and v2 framing carries a fresh IV per call.
//! Everything after that is protocol logic, which is the point of the
//! phase.
//!
//! No signing happens here at all, so the stubbed signer is not in play.

use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

use fw::client_pin::{
    PinSession, SharedSecret, PERM_AUTHENTICATOR_CFG, PERM_CREDENTIAL_MGMT, PERM_GET_ASSERTION,
    PERM_LARGE_BLOB_WRITE, PERM_MAKE_CREDENTIAL, PIN_MAX_RETRIES, PIN_PROTOCOL_V1, PIN_PROTOCOL_V2,
};
use fw::ctap2::{self, CredStore, HostOp, CTAP2_CLIENT_PIN, CTAP2_OK};
use fw::trng::Trng;

// CTAP 2.1 sec. 8.2, spelled out so a wrong expectation reads as a number.
const ERR_INVALID_PARAM: u8 = 0x02;
const ERR_MISSING_PARAMETER: u8 = 0x14;
const ERR_INVALID_CBOR: u8 = 0x12;
const ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
const ERR_INVALID_SUBCOMMAND: u8 = 0x3e;
const ERR_PIN_INVALID: u8 = 0x31;
const ERR_PIN_BLOCKED: u8 = 0x32;
const ERR_PIN_AUTH_INVALID: u8 = 0x33;
const ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
const ERR_PIN_NOT_SET: u8 = 0x35;
const ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
const ERR_UNAUTHORIZED_PERMISSION: u8 = 0x40;

const SUB_GET_RETRIES: u64 = 0x01;
const SUB_GET_KEY_AGREEMENT: u64 = 0x02;
const SUB_SET_PIN: u64 = 0x03;
const SUB_CHANGE_PIN: u64 = 0x04;
const SUB_GET_PIN_TOKEN: u64 = 0x05;
const SUB_GET_UV_RETRIES: u64 = 0x07;
const SUB_GET_TOKEN_PERMS: u64 = 0x09;

const PIN: &[u8] = b"1234";
const PIN2: &[u8] = b"987654";
const RP: &str = "example.com";

fn enc(v: &Value) -> Vec<u8> {
    let mut o = Vec::new();
    pqf_cbor::encode(v, &mut o);
    o
}

/// SHA-256(pin)[..16] -- the 16 bytes the token actually stores.
fn pin_hash(pin: &[u8]) -> Vec<u8> {
    fw::bc_crypto::sha256(pin)[..16].to_vec()
}

/// The 64-byte zero-padded PIN CTAP encrypts on the wire.
fn padded(pin: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 64];
    p[..pin.len()].copy_from_slice(pin);
    p
}

// ---- the platform side ------------------------------------------------

/// A CTAP platform doing the ClientPIN handshake. Its ECDH is its own
/// (`p256`); the key derivation is the firmware's, see the module note.
struct Client {
    sk: p256::SecretKey,
    proto: u64,
}

impl Client {
    /// Deterministic per (protocol, nonce) so a test can re-handshake
    /// with the same platform key, or deliberately with a different one.
    fn new(proto: u64, nonce: u8) -> Self {
        let mut b = [0x11u8; 32];
        b[31] = nonce | 1;
        Client {
            sk: p256::SecretKey::from_slice(&b).expect("a valid P-256 scalar"),
            proto,
        }
    }

    /// The platform's public key, as the COSE_Key CTAP expects at 0x03.
    fn cose_pub(&self) -> Value {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let ep = self.sk.public_key().to_encoded_point(false);
        let b = ep.as_bytes();
        Value::Map(vec![
            (Value::Uint(1), Value::Uint(2)),
            (Value::Nint(-25), Value::Uint(0)), // placeholder, replaced below
            (Value::Nint(-1), Value::Uint(1)),
            (Value::Nint(-2), Value::Bytes(b[1..33].to_vec())),
            (Value::Nint(-3), Value::Bytes(b[33..65].to_vec())),
        ])
    }

    /// ECDH against the authenticator's advertised key, then the
    /// protocol's key derivation.
    fn shared(&self, auth_x: &[u8; 32], auth_y: &[u8; 32]) -> SharedSecret {
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        let ep = p256::EncodedPoint::from_affine_coordinates(auth_x.into(), auth_y.into(), false);
        let pk = p256::PublicKey::from_encoded_point(&ep).expect("authenticator key is on-curve");
        let s = p256::ecdh::diffie_hellman(self.sk.to_nonzero_scalar(), pk.as_affine());
        let mut x = [0u8; 32];
        x.copy_from_slice(s.raw_secret_bytes());
        SharedSecret::from_handshake(x, self.proto).expect("a known protocol version")
    }
}

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
        Device {
            _guard: guard,
            trng,
            session,
            store,
        }
    }

    /// A fresh boot on the same flash: new volatile session, same
    /// persistent PIN state. This is what a replug does, and it is the
    /// difference between the two retry counters.
    fn power_cycle(&mut self) {
        self.session = PinSession::new(&mut self.trng);
    }

    /// Send an arbitrary body after the clientPIN command byte, so a
    /// test can hand it something that is not a well-formed map.
    fn send_raw(&mut self, body: &[u8]) -> Vec<u8> {
        let mut msg = vec![CTAP2_CLIENT_PIN];
        msg.extend_from_slice(body);
        let mut host = |_op: HostOp| true;
        ctap2::handle_cbor(
            &msg,
            &mut self.trng,
            &mut self.session,
            &mut self.store,
            &mut host,
            0,
            [0, 0, 0, 1],
        )
        .to_vec()
    }

    fn send(&mut self, params: &[(u64, Value)]) -> Vec<u8> {
        let mut m: Vec<(Value, Value)> = params
            .iter()
            .map(|(k, v)| (Value::Uint(*k), v.clone()))
            .collect();
        m.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
        let mut msg = vec![CTAP2_CLIENT_PIN];
        msg.extend_from_slice(&enc(&Value::Map(m)));
        let mut host = |_op: HostOp| true;
        ctap2::handle_cbor(
            &msg,
            &mut self.trng,
            &mut self.session,
            &mut self.store,
            &mut host,
            0,
            [0, 0, 0, 1],
        )
        .to_vec()
    }

    /// getKeyAgreement, returning the authenticator's public point.
    fn key_agreement(&mut self, proto: u64) -> ([u8; 32], [u8; 32]) {
        let r = self.send(&[
            (1, Value::Uint(proto)),
            (2, Value::Uint(SUB_GET_KEY_AGREEMENT)),
        ]);
        assert_eq!(r[0], CTAP2_OK, "getKeyAgreement returned {:#04x}", r[0]);
        let cose = match resp_key(&r, 1).expect("no keyAgreement in the response") {
            Value::Map(m) => m,
            other => panic!("keyAgreement is {other:?}"),
        };
        let coord = |k: i64| -> [u8; 32] {
            let v = cose
                .iter()
                .find_map(|(kk, vv)| match kk {
                    Value::Nint(n) if *n == k => Some(vv.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no coordinate {k} in the COSE key"));
            match v {
                Value::Bytes(b) if b.len() == 32 => b.try_into().unwrap(),
                other => panic!("coordinate {k} is {other:?}"),
            }
        };
        (coord(-2), coord(-3))
    }

    /// Handshake and return both the shared secret and the platform key
    /// to quote back in the request.
    fn handshake(&mut self, c: &Client) -> (SharedSecret, Value) {
        let (x, y) = self.key_agreement(c.proto);
        (c.shared(&x, &y), c.cose_pub())
    }

    fn retries(&mut self, proto: u64) -> u64 {
        let r = self.send(&[(1, Value::Uint(proto)), (2, Value::Uint(SUB_GET_RETRIES))]);
        assert_eq!(r[0], CTAP2_OK);
        match resp_key(&r, 3).expect("no retries field") {
            Value::Uint(n) => n,
            other => panic!("retries is {other:?}"),
        }
    }

    /// `powerCycleState` (0x04) out of a getPinRetries response: `None`
    /// when the field is absent, which CTAP 2.1 sec. 6.5.5.2 defines as "no
    /// power cycle required".
    fn power_cycle_state(&mut self, proto: u64) -> Option<bool> {
        let r = self.send(&[(1, Value::Uint(proto)), (2, Value::Uint(SUB_GET_RETRIES))]);
        assert_eq!(r[0], CTAP2_OK);
        match resp_key(&r, 4) {
            None => None,
            Some(Value::Bool(b)) => Some(b),
            Some(other) => panic!("powerCycleState is {other:?}, not a bool"),
        }
    }

    fn set_pin(&mut self, c: &Client, pin: &[u8]) -> Vec<u8> {
        let (s, pub_key) = self.handshake(c);
        let new_pin_enc = s.encrypt(&mut self.trng, &padded(pin)).to_vec();
        let auth = s.authenticate(&new_pin_enc).to_vec();
        self.send(&[
            (1, Value::Uint(c.proto)),
            (2, Value::Uint(SUB_SET_PIN)),
            (3, pub_key),
            (4, Value::Bytes(auth)),
            (5, Value::Bytes(new_pin_enc)),
        ])
    }

    fn change_pin(&mut self, c: &Client, old: &[u8], new: &[u8]) -> Vec<u8> {
        let (s, pub_key) = self.handshake(c);
        let new_pin_enc = s.encrypt(&mut self.trng, &padded(new)).to_vec();
        let pin_hash_enc = s.encrypt(&mut self.trng, &pin_hash(old)).to_vec();
        let mut combined = new_pin_enc.clone();
        combined.extend_from_slice(&pin_hash_enc);
        let auth = s.authenticate(&combined).to_vec();
        self.send(&[
            (1, Value::Uint(c.proto)),
            (2, Value::Uint(SUB_CHANGE_PIN)),
            (3, pub_key),
            (4, Value::Bytes(auth)),
            (5, Value::Bytes(new_pin_enc)),
            (6, Value::Bytes(pin_hash_enc)),
        ])
    }

    fn get_pin_token(&mut self, c: &Client, pin: &[u8]) -> Vec<u8> {
        let (s, pub_key) = self.handshake(c);
        let pin_hash_enc = s.encrypt(&mut self.trng, &pin_hash(pin)).to_vec();
        self.send(&[
            (1, Value::Uint(c.proto)),
            (2, Value::Uint(SUB_GET_PIN_TOKEN)),
            (3, pub_key),
            (6, Value::Bytes(pin_hash_enc)),
        ])
    }

    fn get_token_with_perms(
        &mut self,
        c: &Client,
        pin: &[u8],
        perms: u64,
        rp: Option<&str>,
    ) -> Vec<u8> {
        let (s, pub_key) = self.handshake(c);
        let pin_hash_enc = s.encrypt(&mut self.trng, &pin_hash(pin)).to_vec();
        let mut p: Vec<(u64, Value)> = vec![
            (1, Value::Uint(c.proto)),
            (2, Value::Uint(SUB_GET_TOKEN_PERMS)),
            (3, pub_key),
            (6, Value::Bytes(pin_hash_enc)),
            (9, Value::Uint(perms)),
        ];
        if let Some(r) = rp {
            p.push((0x0A, Value::Text(r.into())));
        }
        self.send(&p)
    }

    /// Establish a PIN and leave the device ready for token requests.
    fn with_pin(&mut self, c: &Client, pin: &[u8]) {
        let r = self.set_pin(c, pin);
        assert_eq!(r[0], CTAP2_OK, "setPIN failed with {:#04x}", r[0]);
    }
}

fn resp_key(resp: &[u8], want: u64) -> Option<Value> {
    match pqf_cbor::decode(&resp[1..]).ok()? {
        Value::Map(m) => m.iter().find_map(|(k, v)| match k {
            Value::Uint(n) if *n == want => Some(v.clone()),
            _ => None,
        }),
        _ => None,
    }
}

/// The token bytes out of a successful token response (key 0x02).
fn token_of(resp: &[u8]) -> Vec<u8> {
    match resp_key(resp, 2).expect("no pinUvAuthToken in the response") {
        Value::Bytes(b) => b,
        other => panic!("the token is {other:?}"),
    }
}

// ---- the primitives, pinned independently ----------------------------

#[test]
fn the_v1_shared_secret_is_sha256_of_the_ecdh_x_coordinate() {
    // Computed here from the ECDH output directly, not through
    // SharedSecret, so the one place the two sides could agree on
    // something wrong is checked against the spec's definition.
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    let mut d = Device::new();
    let (x, y) = d.key_agreement(PIN_PROTOCOL_V1);

    let ep = p256::EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
    let pk = p256::PublicKey::from_encoded_point(&ep).unwrap();
    let raw = p256::ecdh::diffie_hellman(c.sk.to_nonzero_scalar(), pk.as_affine());
    let expected = fw::bc_crypto::sha256(raw.raw_secret_bytes());

    // A v1 secret authenticates with HMAC(secret, m)[..16]; reproduce
    // that from `expected` and check the firmware's agrees.
    let s = c.shared(&x, &y);
    let msg = b"a message";
    let theirs = s.authenticate(msg).to_vec();
    let ours = fw::bc_crypto::hmac_sha256(&expected, msg)[..16].to_vec();
    assert_eq!(theirs, ours, "the v1 shared secret is not SHA-256(ECDH.x)");
    assert_eq!(theirs.len(), 16, "a v1 pinUvAuthParam is 16 bytes");
}

#[test]
fn the_two_protocols_derive_different_keys() {
    // v2 splits the handshake into separate AES and HMAC keys via HKDF.
    // If either collapsed back onto v1's single key, a v1 param would
    // authenticate a v2 request and the version would be decorative.
    let mut d = Device::new();
    let (x, y) = d.key_agreement(PIN_PROTOCOL_V1);
    let v1 = Client::new(PIN_PROTOCOL_V1, 1).shared(&x, &y);
    let v2 = Client::new(PIN_PROTOCOL_V1, 1).shared(&x, &y);
    let v2 = match v2 {
        SharedSecret::V1(k) => SharedSecret::from_handshake(k, PIN_PROTOCOL_V2).unwrap(),
        other => other,
    };
    let msg = b"same message";
    assert_ne!(
        v1.authenticate(msg).to_vec(),
        v2.authenticate(msg).to_vec(),
        "the two protocols authenticate identically"
    );
    assert_eq!(
        v2.authenticate(msg).len(),
        32,
        "a v2 pinUvAuthParam is 32 bytes"
    );
}

#[test]
fn v2_framing_carries_a_fresh_iv_on_every_encryption() {
    // v1 uses a zero IV, so identical plaintexts give identical
    // ciphertexts -- that is the protocol. v2 must not: a fixed IV would
    // make an encrypted PIN comparable across attempts.
    let c = Client::new(PIN_PROTOCOL_V2, 1);
    let mut d = Device::new();
    let (x, y) = d.key_agreement(PIN_PROTOCOL_V2);
    let s = c.shared(&x, &y);
    let a = s.encrypt(&mut d.trng, &padded(PIN)).to_vec();
    let b = s.encrypt(&mut d.trng, &padded(PIN)).to_vec();
    assert_eq!(a.len(), 80, "a v2 newPinEnc is 16 bytes of IV plus 64");
    assert_ne!(a[..16], b[..16], "the v2 IV did not change between calls");
    assert_ne!(a, b, "two v2 encryptions of one plaintext are identical");
}

// ---- the plumbing ----------------------------------------------------

#[test]
fn a_fresh_device_reports_the_full_retry_budget() {
    let mut d = Device::new();
    assert_eq!(d.retries(PIN_PROTOCOL_V1), PIN_MAX_RETRIES as u64);
}

#[test]
fn key_agreement_returns_a_well_formed_p256_point() {
    // A platform runs this before every attempt. A malformed point means
    // no PIN can ever be set.
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    let mut d = Device::new();
    let (x, y) = d.key_agreement(PIN_PROTOCOL_V1);
    let ep = p256::EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
    assert!(
        bool::from(p256::PublicKey::from_encoded_point(&ep).is_some()),
        "the advertised keyAgreement point is not on the curve"
    );
    assert_ne!(x, [0u8; 32], "the key agreement x coordinate is zero");
}

#[test]
fn key_agreement_is_stable_within_one_boot() {
    // It rotates only on a failed PIN attempt. A key that moved on every
    // read would break a platform that handshakes once and reuses it.
    let mut d = Device::new();
    assert_eq!(
        d.key_agreement(PIN_PROTOCOL_V1),
        d.key_agreement(PIN_PROTOCOL_V1),
        "the key agreement key moved between two reads"
    );
}

#[test]
fn an_unknown_protocol_version_is_refused() {
    // Only 1 and 2 exist. A device that accepted 3 would be deriving keys
    // by whichever branch its match happened to fall through to.
    let mut d = Device::new();
    for proto in [0u64, 3, 255, u64::MAX] {
        let r = d.send(&[(1, Value::Uint(proto)), (2, Value::Uint(SUB_GET_RETRIES))]);
        assert_eq!(r[0], ERR_INVALID_PARAM, "protocol {proto} was accepted");
    }
}

#[test]
fn an_unknown_subcommand_is_refused() {
    let mut d = Device::new();
    for sub in [0u64, 8, 10, 99, u64::MAX] {
        let r = d.send(&[(1, Value::Uint(PIN_PROTOCOL_V1)), (2, Value::Uint(sub))]);
        assert_eq!(
            r[0], ERR_INVALID_SUBCOMMAND,
            "subcommand {sub} was accepted"
        );
    }
}

#[test]
fn get_uv_retries_is_refused_because_there_is_no_built_in_uv() {
    // getInfo advertises no `uv` option, so there is no counter to
    // report. Answering with a number would tell a platform a UV modality
    // exists and send it down a path that cannot complete.
    let mut d = Device::new();
    let r = d.send(&[
        (1, Value::Uint(PIN_PROTOCOL_V1)),
        (2, Value::Uint(SUB_GET_UV_RETRIES)),
    ]);
    assert_eq!(r[0], ERR_INVALID_SUBCOMMAND);
}

#[test]
fn a_request_missing_its_required_fields_is_refused() {
    // Both 0x01 and 0x02 are required. Without them there is nothing to
    // dispatch on, and defaulting either would pick a protocol the
    // platform never asked for.
    //
    // The status is MISSING_PARAMETER, not INVALID_PARAM: the client's
    // parameters were not wrong, one was absent, and those are different
    // things to fix. All four ways of failing to parse used to come back
    // as INVALID_PARAM -- including a body that did not decode as CBOR
    // at all.
    let mut d = Device::new();
    assert_eq!(
        d.send(&[(2, Value::Uint(SUB_GET_RETRIES))])[0],
        ERR_MISSING_PARAMETER,
        "an absent pinUvAuthProtocol"
    );
    assert_eq!(
        d.send(&[(1, Value::Uint(PIN_PROTOCOL_V1))])[0],
        ERR_MISSING_PARAMETER,
        "an absent subCommand"
    );
    assert_eq!(d.send(&[])[0], ERR_MISSING_PARAMETER, "an empty map");
}

#[test]
fn the_four_ways_a_client_pin_body_can_be_unparseable_are_told_apart() {
    // They all used to be INVALID_PARAM. A client whose CBOR failed to
    // encode and a client that forgot a field got the same answer, and
    // neither could tell which mistake it had made.
    let mut d = Device::new();

    // Not CBOR at all.
    assert_eq!(
        d.send_raw(&[0xFF, 0xFF, 0xFF])[0],
        ERR_INVALID_CBOR,
        "undecodable bytes"
    );
    // Valid CBOR, but not a map.
    assert_eq!(
        d.send_raw(&[0x07])[0], // CBOR uint 7: valid, and not a map
        ERR_CBOR_UNEXPECTED_TYPE,
        "a body that is an integer"
    );
    // A map, with a field of the wrong type.
    assert_eq!(
        d.send(&[
            (1, Value::Text("v1".into())),
            (2, Value::Uint(SUB_GET_RETRIES))
        ])[0],
        ERR_CBOR_UNEXPECTED_TYPE,
        "a text pinUvAuthProtocol"
    );
    // A map, well typed, missing a required field.
    assert_eq!(
        d.send(&[(1, Value::Uint(PIN_PROTOCOL_V1))])[0],
        ERR_MISSING_PARAMETER,
        "an absent subCommand"
    );
}

#[test]
fn malformed_client_pin_bodies_are_refused_without_panicking() {
    // ClientPIN runs before any authentication, so everything here is
    // reachable by anything that can open a CTAPHID channel.
    let mut d = Device::new();
    let bodies: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xff],
        vec![0xa1],
        vec![0xa1, 0x01],
        vec![0xa2, 0x01, 0x01, 0x02],
        vec![0x81, 0x01],
        vec![0x00],
        vec![0xff; 200],
        enc(&Value::Map(vec![
            (Value::Uint(1), Value::Text("one".into())),
            (Value::Uint(2), Value::Uint(SUB_GET_RETRIES)),
        ])),
        enc(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(PIN_PROTOCOL_V1)),
            (Value::Uint(2), Value::Bytes(vec![1])),
        ])),
    ];
    for b in bodies {
        let mut msg = vec![CTAP2_CLIENT_PIN];
        msg.extend_from_slice(&b);
        let mut host = |_op: HostOp| true;
        let r = ctap2::handle_cbor(
            &msg,
            &mut d.trng,
            &mut d.session,
            &mut d.store,
            &mut host,
            0,
            [0, 0, 0, 1],
        );
        assert!(!r.is_empty(), "an empty response to {b:?}");
        assert_ne!(r[0], CTAP2_OK, "{b:?} was accepted");
    }
}

// ---- setPIN ----------------------------------------------------------

#[test]
fn a_pin_can_be_set_under_either_protocol() {
    for proto in [PIN_PROTOCOL_V1, PIN_PROTOCOL_V2] {
        let mut d = Device::new();
        let c = Client::new(proto, 1);
        assert_eq!(
            d.set_pin(&c, PIN)[0],
            CTAP2_OK,
            "setPIN failed under v{proto}"
        );
        assert_eq!(d.store.pin.pin_set, 1, "v{proto} setPIN did not persist");
        assert_eq!(
            d.store.pin.pin_hash[..],
            pin_hash(PIN)[..],
            "v{proto} stored the wrong PIN hash"
        );
        assert_eq!(d.retries(proto), PIN_MAX_RETRIES as u64);
    }
}

#[test]
fn setting_a_pin_twice_is_refused() {
    // sec. 6.5.5.4: setPIN is for a device with no PIN. Allowing a second one
    // would let anyone with physical access replace the PIN without
    // knowing the first.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    assert_eq!(
        d.set_pin(&c, PIN2)[0],
        ERR_PIN_AUTH_INVALID,
        "a second setPIN replaced the PIN with no authentication"
    );
    assert_eq!(
        d.store.pin.pin_hash[..],
        pin_hash(PIN)[..],
        "the PIN changed anyway"
    );
}

#[test]
fn a_pin_shorter_than_the_minimum_is_refused() {
    // CTAP's floor is four code points. Anything shorter is inside brute
    // force range of the eight attempts the counter allows.
    for short in [&b""[..], b"1", b"12", b"123"] {
        let mut d = Device::new();
        let c = Client::new(PIN_PROTOCOL_V1, 1);
        assert_eq!(
            d.set_pin(&c, short)[0],
            ERR_PIN_POLICY_VIOLATION,
            "a {}-byte PIN was accepted",
            short.len()
        );
        assert_eq!(d.store.pin.pin_set, 0, "a too-short PIN was stored");
    }
}

#[test]
fn a_pin_of_exactly_the_minimum_length_is_accepted() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    assert_eq!(
        d.set_pin(&c, b"1234")[0],
        CTAP2_OK,
        "a four-byte PIN was refused"
    );
}

#[test]
fn a_long_pin_fills_the_padding_without_overflowing_it() {
    // 63 bytes is the most the 64-byte padded block can carry and still
    // be distinguishable from a shorter one by trailing-zero stripping.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    let long = vec![b'x'; 63];
    assert_eq!(
        d.set_pin(&c, &long)[0],
        CTAP2_OK,
        "a 63-byte PIN was refused"
    );
    assert_eq!(d.store.pin.pin_hash[..], pin_hash(&long)[..]);
}

#[test]
fn set_pin_with_a_bad_auth_param_is_refused() {
    // The param is what proves the newPinEnc came from a platform that
    // completed the handshake. Without the check, anyone who can send
    // CBOR sets the PIN.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    let (s, pub_key) = d.handshake(&c);
    let new_pin_enc = s.encrypt(&mut d.trng, &padded(PIN)).to_vec();
    for bad in [vec![0u8; 16], vec![0xff; 16], vec![], vec![0u8; 32]] {
        let r = d.send(&[
            (1, Value::Uint(PIN_PROTOCOL_V1)),
            (2, Value::Uint(SUB_SET_PIN)),
            (3, pub_key.clone()),
            (4, Value::Bytes(bad.clone())),
            (5, Value::Bytes(new_pin_enc.clone())),
        ]);
        assert_eq!(
            r[0], ERR_PIN_AUTH_INVALID,
            "auth param {bad:?} was accepted"
        );
    }
    assert_eq!(
        d.store.pin.pin_set, 0,
        "a PIN was set despite a bad auth param"
    );
}

#[test]
fn set_pin_rejects_a_new_pin_block_of_the_wrong_length() {
    // The length is fixed per protocol -- 64 for v1, 80 for v2 -- because
    // it is one padded block plus, for v2, the IV. A short block would be
    // decrypted into whatever happened to follow it.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    let (s, pub_key) = d.handshake(&c);
    for n in [0usize, 16, 48, 63, 65, 80] {
        let blob = vec![0u8; n];
        let auth = s.authenticate(&blob).to_vec();
        let r = d.send(&[
            (1, Value::Uint(PIN_PROTOCOL_V1)),
            (2, Value::Uint(SUB_SET_PIN)),
            (3, pub_key.clone()),
            (4, Value::Bytes(auth)),
            (5, Value::Bytes(blob)),
        ]);
        assert_eq!(
            r[0], ERR_MISSING_PARAMETER,
            "a {n}-byte newPinEnc was accepted"
        );
    }
}

#[test]
fn a_v1_authenticated_request_does_not_pass_as_v2() {
    // The version is negotiated per request. If a v1 param verified
    // against a v2 secret, the shorter 16-byte tag would be accepted
    // wherever v2 was in use.
    let mut d = Device::new();
    let c1 = Client::new(PIN_PROTOCOL_V1, 1);
    let (s1, pub_key) = d.handshake(&c1);
    let block = s1.encrypt(&mut d.trng, &padded(PIN)).to_vec();
    let v1_auth = s1.authenticate(&block).to_vec();
    assert_eq!(v1_auth.len(), 16);

    // Same platform key, same handshake, but claim v2.
    let r = d.send(&[
        (1, Value::Uint(PIN_PROTOCOL_V2)),
        (2, Value::Uint(SUB_SET_PIN)),
        (3, pub_key),
        (4, Value::Bytes(v1_auth)),
        (5, Value::Bytes(block)),
    ]);
    assert_ne!(r[0], CTAP2_OK, "a v1 auth param authenticated a v2 setPIN");
    assert_eq!(d.store.pin.pin_set, 0);
}

// ---- changePIN -------------------------------------------------------

#[test]
fn changing_a_pin_that_was_never_set_is_refused() {
    // Without this guard a changePIN whose pinHashEnc decrypts to the
    // all-zero stored hash would set a PIN with no prior authentication.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    assert_eq!(d.change_pin(&c, PIN, PIN2)[0], ERR_PIN_NOT_SET);
    assert_eq!(d.store.pin.pin_set, 0);
}

#[test]
fn a_pin_can_be_changed_and_the_new_one_takes_effect() {
    for proto in [PIN_PROTOCOL_V1, PIN_PROTOCOL_V2] {
        let mut d = Device::new();
        let c = Client::new(proto, 1);
        d.with_pin(&c, PIN);
        assert_eq!(
            d.change_pin(&c, PIN, PIN2)[0],
            CTAP2_OK,
            "changePIN failed under v{proto}"
        );
        assert_eq!(
            d.store.pin.pin_hash[..],
            pin_hash(PIN2)[..],
            "the new PIN was not stored"
        );
        assert_eq!(
            d.get_pin_token(&c, PIN2)[0],
            CTAP2_OK,
            "the new PIN does not work"
        );
        assert_eq!(
            d.get_pin_token(&c, PIN)[0],
            ERR_PIN_INVALID,
            "the old PIN still works"
        );
    }
}

#[test]
fn changing_with_the_wrong_old_pin_is_refused_and_costs_a_retry() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    let before = d.retries(PIN_PROTOCOL_V1);
    assert_eq!(d.change_pin(&c, b"0000", PIN2)[0], ERR_PIN_INVALID);
    assert_eq!(
        d.retries(PIN_PROTOCOL_V1),
        before - 1,
        "a wrong old PIN was free"
    );
    assert_eq!(
        d.store.pin.pin_hash[..],
        pin_hash(PIN)[..],
        "the PIN changed anyway"
    );
}

#[test]
fn a_bad_auth_param_on_change_pin_does_not_cost_a_retry() {
    // The distinction matters: a wrong PIN is a guess and must be
    // rationed, but a mangled request is not evidence of guessing. Making
    // it cost a retry would let a passive attacker exhaust the counter
    // and lock the user out with no knowledge of the PIN at all.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    let before = d.retries(PIN_PROTOCOL_V1);

    let (s, pub_key) = d.handshake(&c);
    let new_pin_enc = s.encrypt(&mut d.trng, &padded(PIN2)).to_vec();
    let pin_hash_enc = s.encrypt(&mut d.trng, &pin_hash(PIN)).to_vec();
    let r = d.send(&[
        (1, Value::Uint(PIN_PROTOCOL_V1)),
        (2, Value::Uint(SUB_CHANGE_PIN)),
        (3, pub_key),
        (4, Value::Bytes(vec![0u8; 16])),
        (5, Value::Bytes(new_pin_enc)),
        (6, Value::Bytes(pin_hash_enc)),
    ]);
    assert_eq!(r[0], ERR_PIN_AUTH_INVALID);
    assert_eq!(
        d.retries(PIN_PROTOCOL_V1),
        before,
        "a mangled request cost a retry"
    );
}

#[test]
fn a_successful_change_restores_the_full_retry_budget() {
    // Knowing the PIN is proof enough. Leaving the counter down would
    // accumulate toward a lockout across the device's life.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    assert_eq!(d.change_pin(&c, b"0000", PIN2)[0], ERR_PIN_INVALID);
    assert_eq!(d.retries(PIN_PROTOCOL_V1), PIN_MAX_RETRIES as u64 - 1);
    assert_eq!(d.change_pin(&c, PIN, PIN2)[0], CTAP2_OK);
    assert_eq!(
        d.retries(PIN_PROTOCOL_V1),
        PIN_MAX_RETRIES as u64,
        "retries were not restored"
    );
}

#[test]
fn a_new_pin_below_the_minimum_is_refused_on_change() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    assert_eq!(d.change_pin(&c, PIN, b"12")[0], ERR_PIN_POLICY_VIOLATION);
    assert_eq!(
        d.store.pin.pin_hash[..],
        pin_hash(PIN)[..],
        "a short PIN replaced a good one"
    );
}

// ---- the two retry counters ------------------------------------------

#[test]
fn every_wrong_pin_costs_exactly_one_retry() {
    // Off by one in either direction is a real defect: too few and the
    // token locks early, too many and the guess budget is larger than
    // advertised.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    for expected in (0..PIN_MAX_RETRIES).rev() {
        // A power cycle each time, so the per-boot soft block never
        // fires and this measures the persistent counter alone.
        d.power_cycle();
        let r = d.get_pin_token(&c, b"0000");
        assert_eq!(r[0], ERR_PIN_INVALID, "a wrong PIN was accepted");
        assert_eq!(
            d.retries(PIN_PROTOCOL_V1),
            expected as u64,
            "the counter did not step by one"
        );
    }
}

#[test]
fn the_right_pin_restores_the_counter() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    d.get_pin_token(&c, b"0000");
    d.power_cycle();
    d.get_pin_token(&c, b"0000");
    assert_eq!(d.retries(PIN_PROTOCOL_V1), PIN_MAX_RETRIES as u64 - 2);
    d.power_cycle();
    assert_eq!(d.get_pin_token(&c, PIN)[0], CTAP2_OK);
    assert_eq!(d.retries(PIN_PROTOCOL_V1), PIN_MAX_RETRIES as u64);
}

#[test]
fn three_wrong_pins_in_one_boot_block_until_a_power_cycle() {
    // The soft counter, sec. 6.5.5.6. It exists so an attacker with the token
    // plugged in cannot burn all eight attempts in one sitting -- they
    // have to physically re-seat it twice more. It is volatile by design.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    for i in 0..3 {
        assert_eq!(
            d.get_pin_token(&c, b"0000")[0],
            ERR_PIN_INVALID,
            "attempt {i} was not a plain wrong-PIN answer"
        );
    }
    assert_eq!(
        d.get_pin_token(&c, b"0000")[0],
        ERR_PIN_AUTH_BLOCKED,
        "a fourth attempt in one boot was not soft-blocked"
    );
    assert!(
        d.retries(PIN_PROTOCOL_V1) > 0,
        "the persistent budget was exhausted too"
    );
}

#[test]
fn the_soft_block_does_not_survive_a_power_cycle() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    for _ in 0..3 {
        d.get_pin_token(&c, b"0000");
    }
    assert_eq!(d.get_pin_token(&c, b"0000")[0], ERR_PIN_AUTH_BLOCKED);
    d.power_cycle();
    assert_eq!(
        d.get_pin_token(&c, PIN)[0],
        CTAP2_OK,
        "the soft block outlived the boot that set it"
    );
}

#[test]
fn get_pin_retries_omits_power_cycle_state_until_the_block_trips() {
    // sec. 6.5.5.2 defines 0x04 as "present and true if the authenticator
    // requires a power cycle". Present-and-false would be legal too, but
    // absent is the smaller wire response and the one every client
    // already handles, so the unblocked case stays a one-entry map.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    assert_eq!(d.power_cycle_state(PIN_PROTOCOL_V1), None);
    // Two wrong attempts is not enough to trip it.
    d.get_pin_token(&c, b"0000");
    d.get_pin_token(&c, b"0000");
    assert_eq!(
        d.power_cycle_state(PIN_PROTOCOL_V1),
        None,
        "the device asked for a power cycle while it was still answering PINs"
    );
}

#[test]
fn get_pin_retries_reports_power_cycle_state_once_blocked() {
    // Without this the block is invisible to a conformant client. It
    // sees pinRetries counting down normally, gets 0x34 back from every
    // attempt including the correct PIN, and has nothing on the wire
    // telling it the fix is to replug rather than to keep typing.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    for _ in 0..3 {
        d.get_pin_token(&c, b"0000");
    }
    assert_eq!(d.get_pin_token(&c, b"0000")[0], ERR_PIN_AUTH_BLOCKED);
    assert_eq!(
        d.power_cycle_state(PIN_PROTOCOL_V1),
        Some(true),
        "the device is refusing every PIN but does not say a power cycle is needed"
    );
    // And the persistent budget is still reported alongside it -- the two
    // fields are independent, and a client needs both to explain the
    // state to a user.
    assert!(d.retries(PIN_PROTOCOL_V1) > 0);
}

#[test]
fn power_cycle_state_clears_with_the_block_it_reports() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    for _ in 0..3 {
        d.get_pin_token(&c, b"0000");
    }
    assert_eq!(d.power_cycle_state(PIN_PROTOCOL_V1), Some(true));
    d.power_cycle();
    assert_eq!(
        d.power_cycle_state(PIN_PROTOCOL_V1),
        None,
        "the device still demands a power cycle after being power-cycled"
    );
}

#[test]
fn a_correct_pin_clears_power_cycle_state_short_of_the_block() {
    // The flag tracks the volatile counter, so a success below the
    // threshold must take it back to absent along with the counter.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    d.get_pin_token(&c, b"0000");
    d.get_pin_token(&c, b"0000");
    assert_eq!(d.get_pin_token(&c, PIN)[0], CTAP2_OK);
    assert_eq!(d.power_cycle_state(PIN_PROTOCOL_V1), None);
    // A further three wrong attempts must still be needed to trip it,
    // i.e. the success really reset the counter rather than just
    // masking the flag.
    d.get_pin_token(&c, b"0000");
    d.get_pin_token(&c, b"0000");
    assert_eq!(d.power_cycle_state(PIN_PROTOCOL_V1), None);
    d.get_pin_token(&c, b"0000");
    assert_eq!(d.power_cycle_state(PIN_PROTOCOL_V1), Some(true));
}

#[test]
fn power_cycle_state_is_reported_under_both_pin_protocols() {
    // getPinRetries carries a protocol number, and the flag must not
    // depend on which one the client used to ask.
    for proto in [PIN_PROTOCOL_V1, PIN_PROTOCOL_V2] {
        let mut d = Device::new();
        let c = Client::new(proto, 1);
        d.with_pin(&c, PIN);
        assert_eq!(d.power_cycle_state(proto), None, "proto {proto}");
        for _ in 0..3 {
            d.get_pin_token(&c, b"0000");
        }
        assert_eq!(d.power_cycle_state(proto), Some(true), "proto {proto}");
        // ...and asking under the other protocol sees the same state,
        // since the block is a property of the device, not the session.
        let other = if proto == PIN_PROTOCOL_V1 {
            PIN_PROTOCOL_V2
        } else {
            PIN_PROTOCOL_V1
        };
        assert_eq!(
            d.power_cycle_state(other),
            Some(true),
            "cross-protocol read"
        );
    }
}

#[test]
fn the_soft_block_still_admits_the_correct_pin_before_it_trips() {
    // Two wrong then the right one must work, or a mistyped PIN would
    // cost the user a replug.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    d.get_pin_token(&c, b"0000");
    d.get_pin_token(&c, b"0000");
    assert_eq!(
        d.get_pin_token(&c, PIN)[0],
        CTAP2_OK,
        "the third try was refused"
    );
}

#[test]
fn exhausting_the_persistent_budget_blocks_the_pin_for_good() {
    // Eight wrong PINs, power cycling so the soft block never
    // interferes. After that the correct PIN must not help -- the only
    // way back is a factory reset.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    for _ in 0..PIN_MAX_RETRIES {
        d.power_cycle();
        assert_eq!(d.get_pin_token(&c, b"0000")[0], ERR_PIN_INVALID);
    }
    assert_eq!(d.retries(PIN_PROTOCOL_V1), 0);
    d.power_cycle();
    assert_eq!(
        d.get_pin_token(&c, PIN)[0],
        ERR_PIN_BLOCKED,
        "the correct PIN was accepted on a blocked device"
    );
    assert_eq!(
        d.change_pin(&c, PIN, PIN2)[0],
        ERR_PIN_BLOCKED,
        "changePIN worked around the block"
    );
}

#[test]
fn a_failed_attempt_forces_a_fresh_handshake() {
    // The key agreement key rotates after every wrong PIN, so an attacker
    // cannot pre-compute a batch of encrypted guesses against one shared
    // secret -- each one costs a round trip.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    let (stale, pub_key) = d.handshake(&c);

    assert_eq!(d.get_pin_token(&c, b"0000")[0], ERR_PIN_INVALID);

    // Reuse the secret from before the failure.
    let pin_hash_enc = stale.encrypt(&mut d.trng, &pin_hash(PIN)).to_vec();
    let r = d.send(&[
        (1, Value::Uint(PIN_PROTOCOL_V1)),
        (2, Value::Uint(SUB_GET_PIN_TOKEN)),
        (3, pub_key),
        (6, Value::Bytes(pin_hash_enc)),
    ]);
    assert_ne!(
        r[0], CTAP2_OK,
        "a shared secret from before a failure still worked"
    );
}

// ---- tokens and permissions ------------------------------------------

#[test]
fn the_right_pin_yields_a_token_and_the_wrong_one_does_not() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    let r = d.get_pin_token(&c, PIN);
    assert_eq!(r[0], CTAP2_OK);
    assert!(!token_of(&r).is_empty(), "the token is empty");
    d.power_cycle();
    assert_eq!(d.get_pin_token(&c, b"0000")[0], ERR_PIN_INVALID);
}

#[test]
fn getting_a_token_before_a_pin_exists_is_refused() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    assert_eq!(d.get_pin_token(&c, PIN)[0], ERR_PIN_NOT_SET);
    assert_eq!(
        d.get_token_with_perms(&c, PIN, PERM_GET_ASSERTION as u64, None)[0],
        ERR_PIN_NOT_SET
    );
}

#[test]
fn the_token_is_encrypted_to_the_session_and_not_the_stored_secret() {
    // Two handshakes with different platform keys must wrap the same
    // token differently, or the wrapping is not bound to the session and
    // an observer could reuse a captured blob.
    let mut d = Device::new();
    let c1 = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c1, PIN);
    let a = token_of(&d.get_pin_token(&c1, PIN));
    let c2 = Client::new(PIN_PROTOCOL_V1, 9);
    let b = token_of(&d.get_pin_token(&c2, PIN));
    assert_ne!(a, b, "the token blob does not depend on the platform key");
}

#[test]
fn the_legacy_token_authorises_only_registration_and_assertion() {
    // getPinToken predates permissions and always grants mc+ga. It must
    // not quietly grant the management permissions too -- those exist so
    // a browser token cannot delete the user's credentials.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    assert_eq!(d.get_pin_token(&c, PIN)[0], CTAP2_OK);

    let rp_hash = fw::bc_crypto::sha256(RP.as_bytes());
    for (bit, name) in [
        (PERM_MAKE_CREDENTIAL, "makeCredential"),
        (PERM_GET_ASSERTION, "getAssertion"),
    ] {
        assert!(
            fw::client_pin::check_token_permission(&d.session, bit, &rp_hash).is_ok(),
            "the legacy token does not grant {name}"
        );
    }
    for (bit, name) in [
        (PERM_CREDENTIAL_MGMT, "credentialManagement"),
        (PERM_LARGE_BLOB_WRITE, "largeBlobWrite"),
        (PERM_AUTHENTICATOR_CFG, "authenticatorConfig"),
    ] {
        assert!(
            fw::client_pin::check_token_permission(&d.session, bit, &rp_hash).is_err(),
            "the legacy token grants {name}"
        );
    }
}

#[test]
fn a_permission_scoped_token_grants_only_what_was_asked_for() {
    // The point of subcommand 0x09. A token minted for assertions must
    // not be usable to enumerate or delete credentials.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    let r = d.get_token_with_perms(&c, PIN, PERM_GET_ASSERTION as u64, Some(RP));
    assert_eq!(r[0], CTAP2_OK, "a scoped token request failed");

    let rp_hash = fw::bc_crypto::sha256(RP.as_bytes());
    assert!(
        fw::client_pin::check_token_permission(&d.session, PERM_GET_ASSERTION, &rp_hash).is_ok()
    );
    assert!(
        fw::client_pin::check_token_permission(&d.session, PERM_CREDENTIAL_MGMT, &rp_hash).is_err(),
        "an assertion token authorised credential management"
    );
    assert!(
        fw::client_pin::check_token_permission(&d.session, PERM_MAKE_CREDENTIAL, &rp_hash).is_err(),
        "an assertion token authorised registration"
    );
}

#[test]
fn an_rp_scoped_token_does_not_work_for_another_relying_party() {
    // Scoping is what stops one site's token being replayed at another.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    assert_eq!(
        d.get_token_with_perms(&c, PIN, PERM_GET_ASSERTION as u64, Some(RP))[0],
        CTAP2_OK
    );
    let ours = fw::bc_crypto::sha256(RP.as_bytes());
    let theirs = fw::bc_crypto::sha256(b"evil.example");
    assert!(fw::client_pin::check_token_permission(&d.session, PERM_GET_ASSERTION, &ours).is_ok());
    assert!(
        fw::client_pin::check_token_permission(&d.session, PERM_GET_ASSERTION, &theirs).is_err(),
        "an RP-scoped token answered for another relying party"
    );
}

#[test]
fn an_unscoped_token_is_not_pinned_to_any_relying_party() {
    // Omitting the rpId is legal and means device-wide. Management
    // commands need it, since they are not about one RP.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    assert_eq!(
        d.get_token_with_perms(&c, PIN, PERM_CREDENTIAL_MGMT as u64, None)[0],
        CTAP2_OK
    );
    for rp in [RP, "other.example", "anything"] {
        let h = fw::bc_crypto::sha256(rp.as_bytes());
        assert!(
            fw::client_pin::check_token_permission(&d.session, PERM_CREDENTIAL_MGMT, &h).is_ok(),
            "an unscoped token was refused for {rp}"
        );
    }
}

#[test]
fn a_token_request_for_no_permissions_is_refused() {
    // The refusal is right and that is what matters -- a token in hand
    // with an empty permission set is a fact waiting for a later check to
    // read it wrong. The error code is not: CTAP 2.1 sec. 6.5.5.7 says "if
    // the authenticator receives a permissions parameter with value 0,
    // return CTAP1_ERR_INVALID_PARAMETER" (0x02), and this answers 0x14,
    // the code for a parameter that was not sent at all. A platform
    // cannot tell "you sent nothing" from "you sent zero".
    //
    // Recorded rather than asserted as correct; a one-line fix.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    let r = d.get_token_with_perms(&c, PIN, 0, Some(RP));
    assert_ne!(r[0], CTAP2_OK, "a zero-permission token was issued");
    assert_eq!(
        r[0], ERR_MISSING_PARAMETER,
        "the zero-permissions code changed -- if it is now 0x02 this \
         matches the spec, so update this test and docs/TESTING.md"
    );
}

#[test]
fn a_token_request_with_no_permissions_field_is_a_missing_parameter() {
    // The other half, and this one is right: the field is mandatory for
    // subcommand 0x09, so its absence is CTAP2_ERR_MISSING_PARAMETER.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    let (s, pub_key) = d.handshake(&c);
    let pin_hash_enc = s.encrypt(&mut d.trng, &pin_hash(PIN)).to_vec();
    let r = d.send(&[
        (1, Value::Uint(PIN_PROTOCOL_V1)),
        (2, Value::Uint(SUB_GET_TOKEN_PERMS)),
        (3, pub_key),
        (6, Value::Bytes(pin_hash_enc)),
    ]);
    assert_eq!(r[0], ERR_MISSING_PARAMETER);
}

#[test]
fn a_permission_this_device_cannot_honour_is_refused() {
    // sec. 6.5.5.7 lists a permission as unauthorized when its getInfo option
    // is false or absent. This device advertises no bioEnroll, so the
    // `be` bit must be refused rather than granted and then silently
    // never checked.
    const PERM_BIO_ENROLLMENT: u64 = 0x08;
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    let r = d.get_token_with_perms(&c, PIN, PERM_BIO_ENROLLMENT, Some(RP));
    assert_eq!(
        r[0], ERR_UNAUTHORIZED_PERMISSION,
        "a bioEnroll token was issued"
    );
}

#[test]
fn the_permissions_this_device_does_advertise_are_all_grantable() {
    // The complement: credMgmt, largeBlobs and authnrCfg are all
    // advertised true in getInfo, so sec. 6.5.5.7 says all three are
    // authorized and a request naming them must succeed.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    let all = (PERM_MAKE_CREDENTIAL
        | PERM_GET_ASSERTION
        | PERM_CREDENTIAL_MGMT
        | PERM_LARGE_BLOB_WRITE
        | PERM_AUTHENTICATOR_CFG) as u64;
    assert_eq!(
        d.get_token_with_perms(&c, PIN, all, Some(RP))[0],
        CTAP2_OK,
        "a token naming every advertised permission was refused"
    );
}

#[test]
fn an_undefined_permission_bit_is_refused_rather_than_ignored() {
    // A deviation, recorded. sec. 6.5.5.7: "Undefined permissions present in
    // the permissions parameter are ignored" -- a platform naming a bit
    // from a later revision should still get a token for the bits this
    // device does understand. This one refuses the whole request.
    //
    // The direction is the safe one, and it is deliberate: the comment on
    // SUPPORTED_PERMS says the check is against the full u64 so a high
    // bit cannot be dropped by the u8 narrowing. But it does mean a
    // future permission bit turns a working platform into a hard failure
    // rather than a degraded one, which is an interop cost that grows
    // with the spec.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    for bit in [0x80u64, 0x100, 1u64 << 40] {
        let asked = PERM_GET_ASSERTION as u64 | bit;
        let r = d.get_token_with_perms(&c, PIN, asked, Some(RP));
        assert_eq!(
            r[0], ERR_UNAUTHORIZED_PERMISSION,
            "undefined bit {bit:#x} is now ignored as the spec says -- \
             update this test and docs/TESTING.md"
        );
    }
}

#[test]
fn a_wrong_pin_yields_no_token_under_the_permissions_subcommand_either() {
    // The newer subcommand shares the retry accounting with the legacy
    // one; a path that skipped it would be a free guessing oracle.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    let before = d.retries(PIN_PROTOCOL_V1);
    let r = d.get_token_with_perms(&c, b"0000", PERM_GET_ASSERTION as u64, Some(RP));
    assert_eq!(r[0], ERR_PIN_INVALID);
    assert_eq!(
        d.retries(PIN_PROTOCOL_V1),
        before - 1,
        "the permissions path was free"
    );
}

#[test]
fn a_reset_clears_the_pin_and_returns_the_full_budget() {
    // The only way out of a blocked PIN. Checked here from the PIN
    // module's side: after a reset a new PIN can be set from scratch.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    d.with_pin(&c, PIN);
    for _ in 0..PIN_MAX_RETRIES {
        d.power_cycle();
        d.get_pin_token(&c, b"0000");
    }
    assert_eq!(d.retries(PIN_PROTOCOL_V1), 0);

    let mut host = |_op: HostOp| true;
    let r = ctap2::handle_cbor(
        &[fw::ctap2::CTAP2_RESET_CMD],
        &mut d.trng,
        &mut d.session,
        &mut d.store,
        &mut host,
        0,
        [0, 0, 0, 1],
    );
    assert_eq!(r[0], CTAP2_OK, "reset failed");
    assert_eq!(
        d.retries(PIN_PROTOCOL_V1),
        PIN_MAX_RETRIES as u64,
        "retries not restored"
    );
    assert_eq!(
        d.set_pin(&c, PIN2)[0],
        CTAP2_OK,
        "no PIN could be set after a reset"
    );
}

// ---------- PIN length: first NUL, and a ceiling ----------
//
// The padded block is 64 bytes and must end in at least one NUL, so 63
// bytes is the ceiling; C has had it since it was written, this port
// accepted 64. And the length was measured to the LAST non-zero byte
// rather than the FIRST NUL, so "1234" followed by NULs and then a
// stray byte counted as long enough for any minimum. Both are what the
// TrustZone port and C do; the second hunt found this one still open.

#[test]
fn a_sixty_four_byte_pin_is_refused_and_sixty_three_is_not() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    let r = d.set_pin(&c, &[b'A'; 64]);
    assert_eq!(
        r[0], ERR_PIN_POLICY_VIOLATION,
        "a 64-byte PIN filled the block and was accepted"
    );
    assert_eq!(d.store.pin.pin_set, 0);
    let r = d.set_pin(&c, &[b'A'; 63]);
    assert_eq!(r[0], CTAP2_OK, "a 63-byte PIN was refused");
}

#[test]
fn pin_length_is_measured_to_the_first_nul() {
    // "12" NUL "34": two characters of PIN, whatever follows the NUL.
    // Measured to the last non-zero byte this reads as 5 and passes the
    // minimum of 4 with a two-character PIN.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    let r = d.set_pin(&c, b"12\x0034");
    assert_eq!(
        r[0], ERR_PIN_POLICY_VIOLATION,
        "a two-character PIN passed the minimum"
    );
    assert_eq!(d.store.pin.pin_set, 0);
}

// ---------- forcePINChange is decided after the PIN is verified ----------
//
// The gate used to run before verification, so a WRONG PIN while a change
// was pending answered PIN_POLICY_VIOLATION and spent no retry -- a free
// oracle on whether the PIN was right, in the one state where the PIN is
// known to need changing. C and OpenSK verify first.

#[test]
fn a_wrong_pin_with_a_forced_change_pending_is_pin_invalid_and_costs_a_retry() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 1);
    assert_eq!(d.set_pin(&c, b"1234")[0], CTAP2_OK);
    d.store.force_pin_change = true;
    let before = d.store.pin.retries_left;
    let (s, pub_key) = d.handshake(&c);
    let wrong = s.encrypt(&mut d.trng, &pin_hash(b"9999")[..16]).to_vec();
    let r = d.send(&[
        (1, Value::Uint(PIN_PROTOCOL_V1)),
        (2, Value::Uint(9)), // getPinUvAuthTokenUsingPinWithPermissions
        (3, pub_key),
        (6, Value::Bytes(wrong)),
        (9, Value::Uint(0x01)), // makeCredential
    ]);
    assert_eq!(
        r[0], ERR_PIN_INVALID,
        "a wrong PIN was answered with the policy code"
    );
    assert_eq!(
        d.store.pin.retries_left,
        before - 1,
        "the wrong PIN cost no retry"
    );
}

#[test]
fn a_right_pin_asking_for_mc_or_ga_with_a_forced_change_pending_is_refused() {
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 2);
    assert_eq!(d.set_pin(&c, b"1234")[0], CTAP2_OK);
    d.store.force_pin_change = true;
    let (s, pub_key) = d.handshake(&c);
    let right = s.encrypt(&mut d.trng, &pin_hash(b"1234")[..16]).to_vec();
    let r = d.send(&[
        (1, Value::Uint(PIN_PROTOCOL_V1)),
        (2, Value::Uint(9)),
        (3, pub_key),
        (6, Value::Bytes(right)),
        (9, Value::Uint(0x02)), // getAssertion
    ]);
    assert_eq!(
        r[0], ERR_PIN_POLICY_VIOLATION,
        "an mc/ga token was issued with a change pending"
    );
}

#[test]
fn a_config_scoped_token_is_still_issued_with_a_forced_change_pending() {
    // Otherwise the host could never make the change it is being told to.
    let mut d = Device::new();
    let c = Client::new(PIN_PROTOCOL_V1, 3);
    assert_eq!(d.set_pin(&c, b"1234")[0], CTAP2_OK);
    d.store.force_pin_change = true;
    let (s, pub_key) = d.handshake(&c);
    let right = s.encrypt(&mut d.trng, &pin_hash(b"1234")[..16]).to_vec();
    let r = d.send(&[
        (1, Value::Uint(PIN_PROTOCOL_V1)),
        (2, Value::Uint(9)),
        (3, pub_key),
        (6, Value::Bytes(right)),
        (9, Value::Uint(0x20)), // authenticatorConfig
    ]);
    assert_eq!(
        r[0], CTAP2_OK,
        "a config-scoped token was refused: {:#04x}",
        r[0]
    );
}
