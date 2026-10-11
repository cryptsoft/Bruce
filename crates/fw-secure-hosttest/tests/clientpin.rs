// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The CTAP2 ClientPIN protocol, end to end against a simulated die.
//!
//! This is where a PIN is actually set, changed and verified: ECDH to a
//! shared secret, AES-256-CBC with a zero IV over it, and an HMAC that
//! authenticates the whole thing. Until now it had been exercised only by
//! the conformance suite driving a real token -- which proves the happy path works
//! and tells you nothing about what happens when a client gets the
//! authentication wrong, or keeps getting it wrong.
//!
//! The tests play the client's half honestly: real P-256 key agreement
//! against the token's public point, real AES, real HMAC. A test that
//! faked those would prove only that the token agrees with itself.

use pqf_fw_secure_hosttest as fws;
use std::sync::{Mutex, MutexGuard};

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use fws::clientpin::{self, PinReply, PinRequest};
use fws::pinstore::{self, MAX_RETRIES};
use hmac::{Mac, SimpleHmac};
use sha2::{Digest, Sha256};

static SERIAL: Mutex<()> = Mutex::new(());

fn fresh() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fws::fresh_die();
    pinstore::init();
    let mut trng = fws::trng::Trng::new_for_test();
    clientpin::init(&mut trng);
    g
}

// ---- the client's half, done properly -------------------------------

/// A client key pair and the shared secret it derives with the token.
struct Client {
    shared: [u8; 32],
    public: ([u8; 32], [u8; 32]),
}

impl Client {
    /// Agree with the token, exactly as a real client does: fetch the
    /// token's point, do ECDH, and SHA-256 the x coordinate.
    fn new(seed: u8) -> Self {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let sk = p256::SecretKey::from_slice(&[seed; 32]).expect("client key");
        let pk = sk.public_key();
        let ep = pk.to_encoded_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(ep.x().unwrap());
        y.copy_from_slice(ep.y().unwrap());

        // The token's point, and ECDH against it.
        let (tx, ty) = clientpin::key_agreement_public();
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&tx);
        sec1[33..].copy_from_slice(&ty);
        let token_point = p256::EncodedPoint::from_bytes(sec1).expect("token point");
        let token_pk = p256::PublicKey::from_sec1_bytes(token_point.as_bytes()).expect("token pk");

        let shared_pt = p256::elliptic_curve::ecdh::diffie_hellman(
            sk.to_nonzero_scalar(),
            token_pk.as_affine(),
        );
        let shared = Sha256::digest(shared_pt.raw_secret_bytes());

        Self {
            shared: shared.into(),
            public: (x, y),
        }
    }

    /// AES-256-CBC, zero IV, as PIN protocol v1 specifies.
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        assert_eq!(plaintext.len() % 16, 0, "CBC needs whole blocks");
        let cipher = <aes::Aes256 as AesKeyInit>::new_from_slice(&self.shared).unwrap();
        let mut prev = [0u8; 16];
        let mut out = Vec::with_capacity(plaintext.len());
        for chunk in plaintext.chunks(16) {
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = chunk[i] ^ prev[i];
            }
            let mut b = block.into();
            cipher.encrypt_block(&mut b);
            prev.copy_from_slice(&b);
            out.extend_from_slice(&b);
        }
        out
    }

    /// The left 16 bytes of HMAC-SHA-256, as protocol v1 specifies.
    fn auth(&self, message: &[u8]) -> Vec<u8> {
        let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(&self.shared).unwrap();
        mac.update(message);
        mac.finalize().into_bytes()[..16].to_vec()
    }

    /// A PIN padded to 64 bytes with zeroes, as the spec requires.
    fn padded_pin(pin: &str) -> [u8; 64] {
        let mut p = [0u8; 64];
        p[..pin.len()].copy_from_slice(pin.as_bytes());
        p
    }

    fn pin_hash_enc(&self, pin: &str) -> Vec<u8> {
        let full = Sha256::digest(pin.as_bytes());
        self.encrypt(&full[..16])
    }
}

fn req<'a>(
    c: &Client,
    subcommand: u64,
    auth_param: &'a [u8],
    new_pin_enc: &'a [u8],
    pin_hash_enc: &'a [u8],
) -> PinRequest<'a> {
    PinRequest {
        protocol: clientpin::PIN_PROTOCOL_V1,
        subcommand,
        key_agreement: Some(c.public),
        auth_param,
        new_pin_enc,
        pin_hash_enc,
        permissions: 0,
        rp_id_hash: None,
    }
}

/// Set `pin` on a token that has none.
fn set_pin(c: &Client, pin: &str) -> PinReply {
    let enc = c.encrypt(&Client::padded_pin(pin));
    let auth = c.auth(&enc);
    clientpin::handle(&req(c, clientpin::SUB_SET_PIN, &auth, &enc, &[]))
}

fn is_err(r: &PinReply, code: u8) -> bool {
    matches!(r, PinReply::Err(e) if *e == code)
}

// ---- setting a PIN ---------------------------------------------------

#[test]
fn a_pin_can_be_set_and_is_then_reported_as_set() {
    let _g = fresh();
    assert!(!clientpin::pin_is_set(), "a fresh token reported a PIN");
    let c = Client::new(0x11);
    assert!(
        matches!(set_pin(&c, "1234"), PinReply::Ok),
        "setPin was refused"
    );
    assert!(clientpin::pin_is_set(), "the PIN did not stick");
}

#[test]
fn setting_a_pin_twice_is_refused() {
    // setPin is for a token with no PIN. Allowing it on one that has a
    // PIN would let anyone with USB access replace it without knowing it.
    let _g = fresh();
    let c = Client::new(0x11);
    assert!(matches!(set_pin(&c, "1234"), PinReply::Ok));
    let again = set_pin(&c, "9999");
    assert!(
        !matches!(again, PinReply::Ok),
        "setPin overwrote an existing PIN without proving knowledge of it"
    );
}

#[test]
fn a_wrong_authenticator_hmac_is_refused() {
    // The HMAC proves the client holds the shared secret. Without this
    // check, anyone who can send USB packets can set the PIN.
    let _g = fresh();
    let c = Client::new(0x11);
    let enc = c.encrypt(&Client::padded_pin("1234"));
    let mut bad = c.auth(&enc);
    bad[0] ^= 0xff;
    let r = clientpin::handle(&req(&c, clientpin::SUB_SET_PIN, &bad, &enc, &[]));
    assert!(
        is_err(&r, clientpin::ERR_PIN_AUTH_INVALID),
        "a corrupt pinUvAuthParam was accepted: {:?}",
        matches!(r, PinReply::Ok)
    );
    assert!(
        !clientpin::pin_is_set(),
        "the PIN was set despite a bad HMAC"
    );
}

#[test]
fn a_pin_shorter_than_four_code_points_is_refused() {
    // CTAP2 6.5.5.5. Four is the floor, and a token that accepted "1"
    // would make the eight-attempt budget meaningless.
    let _g = fresh();
    let c = Client::new(0x11);
    for short in ["", "1", "12", "123"] {
        fws::fresh_die();
        pinstore::init();
        let r = set_pin(&c, short);
        assert!(
            is_err(&r, clientpin::ERR_PIN_POLICY_VIOLATION),
            "a {}-character PIN was accepted",
            short.len()
        );
    }
}

#[test]
fn a_pin_that_is_not_utf8_is_refused() {
    let _g = fresh();
    let c = Client::new(0x11);
    let mut padded = [0u8; 64];
    padded[..4].copy_from_slice(&[0xff, 0xfe, 0xfd, 0xfc]);
    let enc = c.encrypt(&padded);
    let auth = c.auth(&enc);
    let r = clientpin::handle(&req(&c, clientpin::SUB_SET_PIN, &auth, &enc, &[]));
    assert!(!matches!(r, PinReply::Ok), "a non-UTF-8 PIN was accepted");
}

#[test]
fn a_ciphertext_that_is_not_a_whole_number_of_blocks_is_refused() {
    // CBC has no partial blocks. A decryptor that tried would run off the
    // end of the buffer or produce garbage it then treated as a PIN.
    let _g = fresh();
    let c = Client::new(0x11);
    let mut enc = c.encrypt(&Client::padded_pin("1234"));
    enc.truncate(63); // not a multiple of 16
    let auth = c.auth(&enc);
    let r = clientpin::handle(&req(&c, clientpin::SUB_SET_PIN, &auth, &enc, &[]));
    assert!(
        !matches!(r, PinReply::Ok),
        "a ragged ciphertext was accepted"
    );
}

// ---- getting a token -------------------------------------------------

#[test]
fn the_right_pin_yields_a_token() {
    let _g = fresh();
    let c = Client::new(0x11);
    assert!(matches!(set_pin(&c, "1234"), PinReply::Ok));

    let hash_enc = c.pin_hash_enc("1234");
    let r = clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &hash_enc));
    match r {
        PinReply::Token(t) => assert!(!t.is_empty(), "an empty pinUvAuthToken"),
        _ => panic!("the correct PIN did not yield a token"),
    }
}

#[test]
fn the_wrong_pin_is_refused_and_costs_a_retry() {
    let _g = fresh();
    let c = Client::new(0x11);
    set_pin(&c, "1234");
    assert_eq!(pinstore::get().retries, MAX_RETRIES);

    let hash_enc = c.pin_hash_enc("9999");
    let r = clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &hash_enc));
    assert!(
        is_err(&r, clientpin::ERR_PIN_INVALID),
        "a wrong PIN was accepted"
    );
    assert_eq!(
        pinstore::get().retries,
        MAX_RETRIES - 1,
        "a wrong PIN did not cost an attempt"
    );
}

/// CTAP2 6.5.5.7: three consecutive failures inside one boot soft-block
/// the PIN until a power cycle. Separate from, and stricter than, the
/// eight-attempt lifetime budget.
const MAX_FAILURES_PER_BOOT: u8 = 3;

/// A power cycle: the session key and the per-boot failure count are
/// regenerated, which is what clears a soft block.
fn power_cycle() {
    let mut trng = fws::trng::Trng::new_for_test();
    clientpin::init(&mut trng);
}

#[test]
fn three_consecutive_failures_soft_block_until_a_power_cycle() {
    // The rate limit that makes eight lifetime attempts hard to spend
    // quickly: an attacker gets three tries per power cycle, not eight in
    // a row.
    let _g = fresh();
    let c = Client::new(0x11);
    set_pin(&c, "1234");
    let wrong = c.pin_hash_enc("9999");

    // The counter is incremented before it is tested, so the third
    // failure is both counted and refused -- there are two plain
    // invalid-PIN answers, not three.
    for i in 0..(MAX_FAILURES_PER_BOOT - 1) {
        let r = clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &wrong));
        assert!(
            is_err(&r, clientpin::ERR_PIN_INVALID),
            "failure {i} should be a plain invalid-PIN, before the soft block"
        );
    }

    let r = clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &wrong));
    assert!(
        is_err(&r, clientpin::ERR_PIN_AUTH_BLOCKED),
        "the third consecutive failure was not soft-blocked"
    );

    // A fourth is refused at the door, without the ciphertext being
    // looked at at all.
    let r = clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &wrong));
    assert!(
        is_err(&r, clientpin::ERR_PIN_AUTH_BLOCKED),
        "a fourth consecutive failure was not soft-blocked"
    );

    // And so is the *correct* PIN, until the token is power-cycled.
    let right = c.pin_hash_enc("1234");
    let r = clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &right));
    assert!(
        is_err(&r, clientpin::ERR_PIN_AUTH_BLOCKED),
        "the correct PIN was accepted while soft-blocked"
    );
}

#[test]
fn a_soft_block_costs_no_further_retries() {
    // The lifetime budget must not drain while the token is refusing to
    // look. Otherwise a host could spend all eight attempts in one boot
    // without ever making a real guess.
    let _g = fresh();
    let c = Client::new(0x11);
    set_pin(&c, "1234");
    let wrong = c.pin_hash_enc("9999");
    for _ in 0..MAX_FAILURES_PER_BOOT {
        clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &wrong));
    }
    let after_block = pinstore::get().retries;
    for _ in 0..20 {
        clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &wrong));
    }
    assert_eq!(
        pinstore::get().retries,
        after_block,
        "attempts refused by the soft block still cost lifetime retries"
    );
}

#[test]
fn a_power_cycle_clears_the_soft_block_but_not_the_lifetime_budget() {
    // The two limits are independent, and this is the interaction that
    // matters: rebooting buys three more tries, not a fresh eight.
    let _g = fresh();
    let c = Client::new(0x11);
    set_pin(&c, "1234");
    let wrong = c.pin_hash_enc("9999");
    for _ in 0..MAX_FAILURES_PER_BOOT {
        clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &wrong));
    }
    assert_eq!(pinstore::get().retries, MAX_RETRIES - MAX_FAILURES_PER_BOOT);

    power_cycle();
    // A new session means a new key agreement, so the client re-agrees.
    let c2 = Client::new(0x11);
    let r = clientpin::handle(&req(
        &c2,
        clientpin::SUB_GET_PIN_TOKEN,
        &[],
        &[],
        &c2.pin_hash_enc("1234"),
    ));
    assert!(
        matches!(r, PinReply::Token(_)),
        "a power cycle did not clear the soft block"
    );
    assert_eq!(
        pinstore::get().retries,
        MAX_RETRIES,
        "the correct PIN after a power cycle did not restore the budget"
    );
}

#[test]
fn the_right_pin_restores_the_retry_budget() {
    // Inside the soft-block allowance, so the correct PIN is still looked
    // at. Without this reset, a few lifetime typos would brick a token.
    let _g = fresh();
    let c = Client::new(0x11);
    set_pin(&c, "1234");
    let wrong = c.pin_hash_enc("9999");
    for _ in 0..(MAX_FAILURES_PER_BOOT - 1) {
        clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &wrong));
    }
    assert_eq!(
        pinstore::get().retries,
        MAX_RETRIES - (MAX_FAILURES_PER_BOOT - 1)
    );

    let right = c.pin_hash_enc("1234");
    let r = clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &right));
    assert!(
        matches!(r, PinReply::Token(_)),
        "the correct PIN was refused"
    );
    assert_eq!(
        pinstore::get().retries,
        MAX_RETRIES,
        "a correct PIN did not reset the budget"
    );
}

#[test]
fn the_lifetime_budget_runs_out_across_power_cycles_and_blocks_for_good() {
    // The attack the budget exists to stop: guess three, power-cycle,
    // repeat. Eight lifetime attempts is eight however they are spread,
    // and after that even the correct PIN is refused.
    let _g = fresh();
    let c0 = Client::new(0x11);
    set_pin(&c0, "1234");

    let mut spent = 0u8;
    while spent < MAX_RETRIES {
        power_cycle();
        let c = Client::new(0x11);
        let wrong = c.pin_hash_enc("9999");
        for _ in 0..MAX_FAILURES_PER_BOOT {
            if spent >= MAX_RETRIES {
                break;
            }
            clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &wrong));
            spent += 1;
        }
    }
    assert_eq!(
        pinstore::get().retries,
        0,
        "the lifetime budget did not run out"
    );

    power_cycle();
    let c = Client::new(0x11);
    let right = c.pin_hash_enc("1234");
    let r = clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &right));
    assert!(
        is_err(&r, clientpin::ERR_PIN_BLOCKED),
        "the correct PIN was accepted after the lifetime budget was spent"
    );
}

#[test]
fn asking_for_a_token_before_a_pin_exists_is_refused() {
    let _g = fresh();
    let c = Client::new(0x11);
    let hash_enc = c.pin_hash_enc("1234");
    let r = clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &hash_enc));
    assert!(
        is_err(&r, clientpin::ERR_PIN_NOT_SET),
        "a token was issued for a PIN that was never set"
    );
}

// ---- key agreement ---------------------------------------------------

#[test]
fn a_different_client_key_derives_a_different_secret_and_cannot_verify() {
    // The shared secret is per-session. If a second client could verify
    // against the first's ciphertext, key agreement would be doing
    // nothing.
    let _g = fresh();
    let a = Client::new(0x11);
    set_pin(&a, "1234");

    let b = Client::new(0x22);
    assert_ne!(
        a.shared, b.shared,
        "two client keys derived the same secret"
    );

    // B replays A's ciphertext under B's own agreement.
    let hash_enc = a.pin_hash_enc("1234");
    let r = clientpin::handle(&req(&b, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &hash_enc));
    assert!(
        !matches!(r, PinReply::Token(_)),
        "a replayed ciphertext verified under a different key agreement"
    );
}

#[test]
fn the_token_reports_a_point_on_the_curve() {
    let _g = fresh();
    let (x, y) = clientpin::key_agreement_public();
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..].copy_from_slice(&y);
    assert!(
        p256::PublicKey::from_sec1_bytes(&sec1).is_ok(),
        "the advertised key-agreement point is not on P-256"
    );
    assert_ne!(x, [0u8; 32], "the x coordinate is all zeroes");
}

#[test]
fn a_key_agreement_point_that_is_not_on_the_curve_is_refused() {
    // Invalid-curve attacks: feeding a point from a weaker curve can leak
    // the token's scalar if the implementation multiplies without
    // checking. p256's decoder rejects it, and this is the test that says
    // the rejection is actually reached.
    let _g = fresh();
    let c = Client::new(0x11);
    set_pin(&c, "1234");

    let bogus = ([0xAAu8; 32], [0xBBu8; 32]);
    let hash_enc = c.pin_hash_enc("1234");
    let mut r = req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &hash_enc);
    r.key_agreement = Some(bogus);
    let reply = clientpin::handle(&r);
    assert!(
        !matches!(reply, PinReply::Token(_)),
        "an off-curve key-agreement point was accepted"
    );
}

// ---- protocol plumbing -----------------------------------------------

#[test]
fn an_unknown_subcommand_is_refused() {
    let _g = fresh();
    let c = Client::new(0x11);
    let r = clientpin::handle(&req(&c, 0x7f, &[], &[], &[]));
    assert!(
        is_err(&r, clientpin::ERR_INVALID_SUBCOMMAND),
        "an unknown subcommand was not rejected"
    );
}

#[test]
fn get_retries_works_without_a_pin_and_without_key_agreement() {
    // A client asks this before it knows anything. Requiring a protocol
    // version or an agreement here would break the first thing every
    // client does.
    let _g = fresh();
    let c = Client::new(0x11);
    let mut r = req(&c, clientpin::SUB_GET_RETRIES, &[], &[], &[]);
    r.key_agreement = None;
    r.protocol = 99; // deliberately not v1
    match clientpin::handle(&r) {
        PinReply::Retries(n) => assert_eq!(n, MAX_RETRIES),
        other => panic!(
            "getRetries did not answer: {}",
            match other {
                PinReply::Err(e) => format!("error 0x{e:02x}"),
                _ => "unexpected reply".into(),
            }
        ),
    }
}

#[test]
fn an_unsupported_protocol_version_is_refused_for_everything_else() {
    let _g = fresh();
    let c = Client::new(0x11);
    let mut r = req(&c, clientpin::SUB_GET_KEY_AGREEMENT, &[], &[], &[]);
    r.protocol = 99;
    assert!(
        is_err(&clientpin::handle(&r), clientpin::ERR_INVALID_PARAM),
        "an unknown PIN protocol version was accepted"
    );
}

#[test]
fn key_agreement_is_offered_without_a_pin_being_set() {
    // The client needs the point before it can encrypt the PIN it is
    // about to set, so this cannot depend on a PIN existing.
    let _g = fresh();
    let c = Client::new(0x11);
    let r = clientpin::handle(&req(&c, clientpin::SUB_GET_KEY_AGREEMENT, &[], &[], &[]));
    assert!(
        matches!(r, PinReply::KeyAgreement(_, _)),
        "getKeyAgreement was refused on a token with no PIN"
    );
}

// ---- the token, once issued ------------------------------------------

#[test]
fn a_token_authenticates_a_message_and_a_tampered_one_does_not() {
    let _g = fresh();
    let c = Client::new(0x11);
    set_pin(&c, "1234");
    let hash_enc = c.pin_hash_enc("1234");
    let token = match clientpin::handle(&req(&c, clientpin::SUB_GET_PIN_TOKEN, &[], &[], &hash_enc))
    {
        PinReply::Token(t) => t,
        _ => panic!("no token issued"),
    };
    // The token comes back encrypted under the shared secret; the client
    // decrypts it. What matters here is that verify_token accepts a
    // signature made with the real token and not one made with junk.
    let message = b"authenticator data and a client data hash";
    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(&token).unwrap();
    mac.update(message);
    let sig_wrong_key = mac.finalize().into_bytes()[..16].to_vec();
    // Encrypted token bytes are not the token itself, so this must fail.
    assert!(
        !clientpin::verify_token(message, &sig_wrong_key, 0, None),
        "a signature made with the *encrypted* token verified"
    );
    assert!(
        !clientpin::verify_token(message, &[0u8; 16], 0, None),
        "an all-zero signature verified"
    );
}

// ================= the UV flag in signed authenticator data =============
//
// The TrustZone port set the authData UV bit from `options.uv` -- the
// client's own request -- and signed it. Non-secure wrote the bit into
// the flags byte, Secure read it back as `Request::uv`, and it went
// straight into the attestation. So any client could ask for the UV bit
// and get it, with no PIN configured and nothing verified, and a relying
// party that requires user verification would accept the result. The
// flag is how it is supposed to know.
//
// `ctap::resolve_uv` is the check that was missing. These tests drive it
// through the real PIN protocol -- a real token, a real HMAC -- because
// the interesting question is not whether the function returns what it
// was told, but whether a *forged* claim of verification is refused.

/// Decrypt the token the authenticator returns (AES-256-CBC, zero IV,
/// under the shared secret) so the client can sign with it, as a real
/// one does.
fn decrypt_token(c: &Client, enc: &[u8]) -> Vec<u8> {
    use aes::cipher::BlockDecrypt;
    let cipher = <aes::Aes256 as AesKeyInit>::new_from_slice(&c.shared).unwrap();
    let mut out = Vec::new();
    let mut prev = [0u8; 16];
    for chunk in enc.chunks(16) {
        let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut b);
        for (i, v) in b.iter().enumerate() {
            out.push(v ^ prev[i]);
        }
        prev.copy_from_slice(chunk);
    }
    out
}

/// Obtain a real pinUvAuthToken with `perms`.
fn token_with(c: &Client, pin: &str, perms: u8, rp: Option<[u8; 32]>) -> Vec<u8> {
    let hash_enc = c.pin_hash_enc(pin);
    let mut r = req(c, clientpin::SUB_GET_TOKEN_WITH_PERMS, &[], &[], &hash_enc);
    r.permissions = perms;
    r.rp_id_hash = rp;
    match clientpin::handle(&r) {
        PinReply::Token(t) => decrypt_token(c, &t),
        _ => panic!("no token issued"),
    }
}

const RP: &[u8] = b"example.com";

/// Build the fixed-layout request exactly as Non-secure lays it out.
/// Going through the byte array rather than constructing a `Request`
/// directly is deliberate: it checks the two sides still agree about
/// where the pinUvAuthParam lives, which is the sort of thing that
/// silently rots when one image is edited and the other is not.
fn req_bytes(uv_requested: bool, puat: &[u8], proto: u8) -> [u8; fws::ctap::REQ_LEN] {
    // Offsets come from the NON-SECURE side's constants. That is what
    // makes this an ABI check: Secure's parse() reads by its own OFF_*
    // values, so if the two ever drift the fields land in the wrong
    // place here and the assertions below fail. Hand-typed literals
    // would only prove that two copies of the same number agree.
    use fws::ctapreq::{
        REQ_OFF_CDH, REQ_OFF_FLAGS, REQ_OFF_PUAT, REQ_OFF_PUAT_LEN, REQ_OFF_PUAT_PROTO, REQ_OFF_RP,
        REQ_OFF_RP_LEN,
    };
    assert_eq!(
        fws::ctap::REQ_LEN,
        fws::ctapreq::REQ_LEN,
        "the two sides disagree on REQ_LEN"
    );
    let mut b = [0u8; fws::ctap::REQ_LEN];
    b[REQ_OFF_RP_LEN] = RP.len() as u8;
    b[REQ_OFF_RP..REQ_OFF_RP + RP.len()].copy_from_slice(RP);
    if uv_requested {
        b[REQ_OFF_FLAGS] |= 0x01;
    }
    for i in 0..32 {
        b[REQ_OFF_CDH + i] = i as u8; // client data hash
    }
    b[REQ_OFF_PUAT_LEN] = puat.len() as u8;
    b[REQ_OFF_PUAT..REQ_OFF_PUAT + puat.len()].copy_from_slice(puat);
    b[REQ_OFF_PUAT_PROTO] = proto;
    b
}

fn rp_hash() -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(&Sha256::digest(RP));
    h
}

/// The pinUvAuthParam a real client computes: HMAC over the client data
/// hash, left 16 bytes.
fn puat_over_cdh(token: &[u8], bytes: &[u8; fws::ctap::REQ_LEN]) -> Vec<u8> {
    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(token).unwrap();
    mac.update(&bytes[130..162]);
    mac.finalize().into_bytes()[..16].to_vec()
}

#[test]
fn asking_for_uv_without_proving_it_does_not_set_the_flag() {
    // The defect itself. A client sends options.uv = true, offers no
    // pinUvAuthParam, and must not get a signed assertion claiming a
    // user was verified. Before the fix this returned uv = true.
    let _g = fresh();
    let bytes = req_bytes(true, &[], 0);
    let mut r = fws::ctap::parse(&bytes).expect("request should parse");
    let verdict = fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL);
    assert!(
        verdict.is_err(),
        "options.uv alone was accepted as verification"
    );
    assert!(!r.uv, "the UV flag was set without any verification");
}

#[test]
fn uv_requested_with_no_pin_configured_is_unsupported_not_silently_downgraded() {
    // No PIN means no user-verification method exists at all on this
    // hardware -- there is no reader and no keypad. Serving the ceremony
    // with uv = false would look like success to a client that asked for
    // verification and did not get it.
    let _g = fresh();
    assert!(!clientpin::pin_is_set());
    let mut r = fws::ctap::parse(&req_bytes(true, &[], 0)).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Err(fws::ctap::CTAP2_ERR_UNSUPPORTED_OPTION)
    );
}

#[test]
fn uv_requested_with_a_pin_set_but_no_token_asks_for_one() {
    // A PIN exists, so the request is satisfiable -- the client just has
    // to get a token first. PUAT_REQUIRED is the retriable code that
    // tells it so; UNSUPPORTED_OPTION would make a platform give up.
    let _g = fresh();
    let c = Client::new(0x21);
    set_pin(&c, "1234");
    let mut r = fws::ctap::parse(&req_bytes(true, &[], 0)).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Err(fws::ctap::CTAP2_ERR_PUAT_REQUIRED)
    );
}

#[test]
fn a_genuine_pin_uv_auth_param_does_set_the_flag() {
    // The accept half. A guard that refused everything would pass every
    // test above and make PIN-protected registration impossible.
    let _g = fresh();
    let c = Client::new(0x22);
    set_pin(&c, "1234");
    let token = token_with(&c, "1234", clientpin::PERM_MAKE_CREDENTIAL, Some(rp_hash()));
    let bytes = req_bytes(true, &[], 1);
    let sig = puat_over_cdh(&token, &bytes);
    let mut bytes = bytes;
    bytes[618] = sig.len() as u8;
    bytes[619..619 + sig.len()].copy_from_slice(&sig);
    let mut r = fws::ctap::parse(&bytes).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Ok(())
    );
    assert!(r.uv, "a verified pinUvAuthParam did not set the UV flag");
}

#[test]
fn a_forged_pin_uv_auth_param_is_refused() {
    // The whole point. Sixteen bytes of anything must not pass for proof.
    let _g = fresh();
    let c = Client::new(0x23);
    set_pin(&c, "1234");
    let _ = token_with(&c, "1234", clientpin::PERM_MAKE_CREDENTIAL, Some(rp_hash()));
    for forged in [
        vec![0u8; 16],
        vec![0xFFu8; 16],
        (0..16u8).collect::<Vec<_>>(),
    ] {
        let mut r = fws::ctap::parse(&req_bytes(true, &forged, 1)).unwrap();
        assert_eq!(
            fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
            Err(clientpin::ERR_PIN_AUTH_INVALID),
            "a forged pinUvAuthParam was accepted"
        );
        assert!(!r.uv);
    }
}

#[test]
fn a_token_without_the_right_permission_cannot_authorise_the_command() {
    // A token minted for credential management must not sign a
    // registration. This is the permission bitmask doing its job, and
    // resolve_uv is where the two commands ask for their own bit.
    let _g = fresh();
    let c = Client::new(0x24);
    set_pin(&c, "1234");
    let token = token_with(&c, "1234", clientpin::PERM_CREDENTIAL_MGMT, Some(rp_hash()));
    let bytes = req_bytes(true, &[], 1);
    let sig = puat_over_cdh(&token, &bytes);
    let mut bytes = bytes;
    bytes[618] = sig.len() as u8;
    bytes[619..619 + sig.len()].copy_from_slice(&sig);
    let mut r = fws::ctap::parse(&bytes).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Err(clientpin::ERR_PIN_AUTH_INVALID),
        "a credMgmt token authorised a MakeCredential"
    );
}

#[test]
fn a_token_scoped_to_another_rp_is_refused() {
    // getPinToken can bind a token to one relying party. Without the
    // scope check a token minted for a phishing site would authenticate
    // a ceremony for a bank.
    let _g = fresh();
    let c = Client::new(0x25);
    set_pin(&c, "1234");
    let mut other = [0u8; 32];
    other.copy_from_slice(&Sha256::digest(b"attacker.example"));
    let token = token_with(&c, "1234", clientpin::PERM_MAKE_CREDENTIAL, Some(other));
    let bytes = req_bytes(true, &[], 1);
    let sig = puat_over_cdh(&token, &bytes);
    let mut bytes = bytes;
    bytes[618] = sig.len() as u8;
    bytes[619..619 + sig.len()].copy_from_slice(&sig);
    let mut r = fws::ctap::parse(&bytes).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Err(clientpin::ERR_PIN_AUTH_INVALID),
        "a token scoped to another RP authorised this one"
    );
}

#[test]
fn an_unsupported_pin_protocol_is_refused_rather_than_reinterpreted() {
    // getInfo advertises v1 only. A v2 param is also 32 bytes and would
    // verify under the wrong rules if the protocol byte went unchecked.
    let _g = fresh();
    let c = Client::new(0x26);
    set_pin(&c, "1234");
    let token = token_with(&c, "1234", clientpin::PERM_MAKE_CREDENTIAL, Some(rp_hash()));
    let bytes = req_bytes(true, &[], 2); // protocol 2
    let sig = puat_over_cdh(&token, &bytes);
    let mut bytes = bytes;
    bytes[618] = sig.len() as u8;
    bytes[619..619 + sig.len()].copy_from_slice(&sig);
    let mut r = fws::ctap::parse(&bytes).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Err(clientpin::ERR_PIN_AUTH_INVALID),
        "a param claiming protocol 2 was verified under v1 rules"
    );
}

#[test]
fn a_request_that_asks_for_nothing_gets_uv_false_and_no_error() {
    // The ordinary presence-only ceremony, which must keep working.
    let _g = fresh();
    let mut r = fws::ctap::parse(&req_bytes(false, &[], 0)).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Ok(())
    );
    assert!(!r.uv);
}

// ============ credentialManagement enumeration state ====================
//
// CTAP 2.1 sec. 6.8 exempts enumerateRPsGetNextRP (0x03) and
// enumerateCredentialsGetNextCredential (0x05) from carrying a
// pinUvAuthParam, because they continue an enumeration whose Begin was
// authenticated. That is only sound if a Begin actually ran and nothing
// has happened since -- the spec also requires the enumeration context
// to be abandoned as soon as any other command arrives.
//
// This image did neither. The cursors were bare statics with no notion
// of being live, so a cold token that had never seen a pinUvAuthToken
// would answer `{1: 3}` with its first stored relying party, and go on
// answering: the auth-exempt subcommands walked the whole store for a
// caller who had presented nothing. The tests that matter here are the
// ones that send a Next with no token at all.

const CM_ENUM_RPS_BEGIN: u8 = 0x02; // CTAP 2.1 sec. 6.8 subcommands
const CM_ENUM_RPS_NEXT: u8 = 0x03;
const CM_ENUM_CREDS_NEXT: u8 = 0x05;
const CM_GET_METADATA: u8 = 0x01;

/// Build the fixed-layout credentialManagement request Non-secure hands
/// over, using ctapreq's offsets so the two layouts are checked to still
/// agree -- the same reason the UV tests above go through the byte array.
fn cm_req(sub: u8, auth: &[u8]) -> [u8; fws::ctap::CM_REQ_LEN] {
    use fws::ctapreq::{CM_OFF_AUTH, CM_OFF_AUTH_LEN, CM_OFF_PARAMS_LEN, CM_OFF_SUB};
    let mut b = [0u8; fws::ctap::CM_REQ_LEN];
    b[CM_OFF_SUB] = sub;
    b[CM_OFF_AUTH_LEN] = auth.len() as u8;
    b[CM_OFF_AUTH..CM_OFF_AUTH + auth.len()].copy_from_slice(auth);
    b[CM_OFF_PARAMS_LEN] = 0;
    b[CM_OFF_PARAMS_LEN + 1] = 0;
    b
}

fn cm(sub: u8, auth: &[u8]) -> fws::ctap::CmReply {
    let mut resp = [0u8; 512];
    let mut scratch = [0u8; 64];
    fws::ctap::handle_cred_mgmt(
        &cm_req(sub, auth),
        &mut resp,
        &|_rp, _id, _scratch| Some(([1u8; 32], [2u8; 32], 0)),
        &mut scratch,
    )
}

fn cm_is_err(r: &fws::ctap::CmReply, code: u8) -> bool {
    matches!(r, fws::ctap::CmReply::Err(e) if *e == code)
}

/// pinUvAuthParam over a credentialManagement subcommand: HMAC of
/// `sub || subCommandParams`, left 16 bytes.
fn cm_auth(token: &[u8], sub: u8) -> Vec<u8> {
    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(token).unwrap();
    mac.update(&[sub]);
    mac.finalize().into_bytes()[..16].to_vec()
}

fn store_one(rp: u8, user: u8) {
    let mut h = [0u8; 32];
    h[0] = rp;
    h[31] = 0xa5;
    let mut id = [0u8; 64];
    id[0] = user;
    id[63] = 0x5a;
    assert!(
        fws::credstore::store(&h, &id, &[user], b"example.test", &[], b"n", b"d", 0),
        "store refused"
    );
}

#[test]
fn a_next_with_no_begin_enumerates_nothing() {
    // The defect. A cold token, no PIN ever set, no token ever minted:
    // subCommand 0x03 on its own must not be a way to read the store.
    let _g = fresh();
    store_one(1, 1);
    store_one(2, 2);
    assert!(
        cm_is_err(&cm(CM_ENUM_RPS_NEXT, &[]), fws::ctap::CTAP2_ERR_NOT_ALLOWED),
        "enumerateRPsGetNextRP answered with no Begin and no token"
    );
    assert!(
        cm_is_err(
            &cm(CM_ENUM_CREDS_NEXT, &[]),
            fws::ctap::CTAP2_ERR_NOT_ALLOWED
        ),
        "enumerateCredentialsGetNext answered with no Begin and no token"
    );
}

#[test]
fn repeating_the_unauthenticated_next_does_not_walk_the_store() {
    // The original could be called over and over, advancing its cursor
    // each time -- one command per relying party until the store was
    // read out. Refusing once is not enough; it has to keep refusing.
    let _g = fresh();
    for i in 1..=4u8 {
        store_one(i, i);
    }
    for round in 0..6 {
        assert!(
            cm_is_err(&cm(CM_ENUM_RPS_NEXT, &[]), fws::ctap::CTAP2_ERR_NOT_ALLOWED),
            "round {round}: the store was walked without authentication"
        );
    }
}

#[test]
fn an_authenticated_begin_arms_the_next() {
    // The accept half. Refusing every Next would pass both tests above
    // and make credential enumeration impossible for a legitimate
    // client, which is the feature.
    let _g = fresh();
    let c = Client::new(0x31);
    set_pin(&c, "1234");
    store_one(1, 1);
    store_one(2, 2);
    let token = token_with(&c, "1234", clientpin::PERM_CREDENTIAL_MGMT, None);

    let begin = cm(CM_ENUM_RPS_BEGIN, &cm_auth(&token, CM_ENUM_RPS_BEGIN));
    assert!(
        matches!(begin, fws::ctap::CmReply::Bytes(_)),
        "an authenticated enumerateRPsBegin was refused"
    );
    assert!(
        matches!(cm(CM_ENUM_RPS_NEXT, &[]), fws::ctap::CmReply::Bytes(_)),
        "the Next after a good Begin was refused"
    );
}

#[test]
fn an_unrelated_command_ends_the_enumeration() {
    // sec. 6.8: the context is abandoned as soon as any other command
    // arrives. Without this a Begin left one armed indefinitely, and
    // anyone reaching the token afterwards could resume it.
    let _g = fresh();
    let c = Client::new(0x32);
    set_pin(&c, "1234");
    store_one(1, 1);
    store_one(2, 2);
    let token = token_with(&c, "1234", clientpin::PERM_CREDENTIAL_MGMT, None);

    assert!(matches!(
        cm(CM_ENUM_RPS_BEGIN, &cm_auth(&token, CM_ENUM_RPS_BEGIN)),
        fws::ctap::CmReply::Bytes(_)
    ));
    // Another credentialManagement subcommand, properly authenticated.
    let _ = cm(CM_GET_METADATA, &cm_auth(&token, CM_GET_METADATA));
    assert!(
        cm_is_err(&cm(CM_ENUM_RPS_NEXT, &[]), fws::ctap::CTAP2_ERR_NOT_ALLOWED),
        "the enumeration survived an intervening command"
    );
}

#[test]
fn walking_off_the_end_disarms_rather_than_leaving_it_open() {
    // Terminal state. Two relying parties means Begin plus one Next;
    // the second Next is past the end, and after that the enumeration
    // must be over -- not merely erroring while still armed.
    let _g = fresh();
    let c = Client::new(0x33);
    set_pin(&c, "1234");
    store_one(1, 1);
    store_one(2, 2);
    let token = token_with(&c, "1234", clientpin::PERM_CREDENTIAL_MGMT, None);

    assert!(matches!(
        cm(CM_ENUM_RPS_BEGIN, &cm_auth(&token, CM_ENUM_RPS_BEGIN)),
        fws::ctap::CmReply::Bytes(_)
    ));
    assert!(matches!(
        cm(CM_ENUM_RPS_NEXT, &[]),
        fws::ctap::CmReply::Bytes(_)
    ));
    assert!(
        matches!(cm(CM_ENUM_RPS_NEXT, &[]), fws::ctap::CmReply::Err(_)),
        "a third Next over two RPs returned a relying party"
    );
    assert!(
        cm_is_err(&cm(CM_ENUM_RPS_NEXT, &[]), fws::ctap::CTAP2_ERR_NOT_ALLOWED),
        "after running off the end the enumeration was still armed"
    );
}

#[test]
fn a_begin_whose_auth_fails_does_not_arm_anything() {
    // A forged Begin is refused -- and must not leave the cursors in a
    // state a following Next can use.
    let _g = fresh();
    let c = Client::new(0x34);
    set_pin(&c, "1234");
    store_one(1, 1);
    let _ = token_with(&c, "1234", clientpin::PERM_CREDENTIAL_MGMT, None);

    assert!(
        cm_is_err(
            &cm(CM_ENUM_RPS_BEGIN, &[0u8; 16]),
            clientpin::ERR_PIN_AUTH_INVALID
        ),
        "a forged enumerateRPsBegin was accepted"
    );
    assert!(
        cm_is_err(&cm(CM_ENUM_RPS_NEXT, &[]), fws::ctap::CTAP2_ERR_NOT_ALLOWED),
        "a refused Begin still armed the Next"
    );
}

#[test]
fn an_rps_enumeration_does_not_arm_the_credentials_one() {
    // The two enumerations are separate contexts with separate cursors.
    // A single live flag shared between them would let a Begin for one
    // authorise Nexts for the other.
    let _g = fresh();
    let c = Client::new(0x35);
    set_pin(&c, "1234");
    store_one(1, 1);
    let token = token_with(&c, "1234", clientpin::PERM_CREDENTIAL_MGMT, None);

    assert!(matches!(
        cm(CM_ENUM_RPS_BEGIN, &cm_auth(&token, CM_ENUM_RPS_BEGIN)),
        fws::ctap::CmReply::Bytes(_)
    ));
    assert!(
        cm_is_err(
            &cm(CM_ENUM_CREDS_NEXT, &[]),
            fws::ctap::CTAP2_ERR_NOT_ALLOWED
        ),
        "an RP enumeration armed the credential enumeration"
    );
}

// ============ PIN policy: minPinLength and forceChangePin ==============
//
// Both were settable through authenticatorConfig, stored, and reported.
// Neither did anything. setMinPINLength was read in exactly two places
// -- the "may only increase" guard inside the setter, and the
// minPinLength extension output that tells a relying party the policy
// is in force -- and never by the code that accepts a new PIN. So an
// enterprise could set a minimum of 8, be told it applied, watch the
// token report 8 to its relying party, and have the user keep a 4-digit
// PIN. forceChangePin was a stored boolean with no reader at all.

/// Drive authenticatorConfig setMinPINLength the way the gateway does.
fn set_min_pin(len: Option<u8>, force: Option<bool>) -> u8 {
    fws::clientpin::set_min_pin_length(len, &[], force)
}

#[test]
fn a_raised_minimum_is_enforced_on_set_pin() {
    let _g = fresh();
    assert_eq!(
        set_min_pin(Some(8), None),
        0x00,
        "setMinPINLength was refused"
    );
    let c = Client::new(0x41);
    assert!(
        matches!(set_pin(&c, "1234"), PinReply::Err(_)),
        "a 4-character PIN was accepted under a minimum of 8"
    );
    assert!(!clientpin::pin_is_set(), "the short PIN was stored anyway");
    assert!(
        matches!(set_pin(&c, "12345678"), PinReply::Ok),
        "an 8-character PIN was refused under a minimum of 8"
    );
}

#[test]
fn a_raised_minimum_is_enforced_on_change_pin_too() {
    // Both paths take a new PIN, and enforcing one and not the other
    // would let the user set 4 by changing rather than setting.
    let _g = fresh();
    let c = Client::new(0x42);
    assert!(matches!(set_pin(&c, "123456"), PinReply::Ok));
    assert_eq!(set_min_pin(Some(8), None), 0x00);

    let hash_enc = c.pin_hash_enc("123456");
    let short = c.encrypt(&Client::padded_pin("4321"));
    let mut msg = Vec::new();
    msg.extend_from_slice(&short);
    msg.extend_from_slice(&hash_enc);
    let auth = c.auth(&msg);
    let r = clientpin::handle(&PinRequest {
        protocol: clientpin::PIN_PROTOCOL_V1,
        subcommand: clientpin::SUB_CHANGE_PIN,
        key_agreement: Some(c.public),
        auth_param: &auth,
        new_pin_enc: &short,
        pin_hash_enc: &hash_enc,
        permissions: 0,
        rp_id_hash: None,
    });
    assert!(
        matches!(r, PinReply::Err(_)),
        "changePIN accepted a PIN below the configured minimum"
    );
}

#[test]
fn the_default_minimum_still_accepts_a_four_character_pin() {
    // The accept half. A policy check that refused everything would pass
    // both tests above and make the token unusable out of the box.
    let _g = fresh();
    let c = Client::new(0x43);
    assert!(
        matches!(set_pin(&c, "1234"), PinReply::Ok),
        "the default minimum rejected 4"
    );
}

#[test]
fn a_pin_longer_than_the_padded_block_allows_is_refused() {
    // The padded block is 64 bytes and must end in at least one NUL, so
    // 63 bytes is the ceiling. Neither Rust port had one; C always did.
    let _g = fresh();
    let c = Client::new(0x44);
    let long = "A".repeat(64);
    assert!(
        matches!(set_pin(&c, &long), PinReply::Err(_)),
        "a 64-byte PIN filled the block with no terminator and was accepted"
    );
    let ok = "A".repeat(63);
    assert!(
        matches!(set_pin(&c, &ok), PinReply::Ok),
        "a 63-byte PIN was refused"
    );
}

#[test]
fn force_change_blocks_a_signing_token_but_not_a_config_one() {
    // sec. 6.5.5.7.2. Refusing every token would deadlock the device: the
    // host needs a credMgmt/authnrCfg-scoped one to drive the change it
    // is being told to make.
    let _g = fresh();
    let c = Client::new(0x45);
    assert!(matches!(set_pin(&c, "1234"), PinReply::Ok));
    assert_eq!(
        set_min_pin(None, Some(true)),
        0x00,
        "forceChangePin was refused"
    );

    let hash_enc = c.pin_hash_enc("1234");
    let ask = |perms: u8| {
        let mut r = req(&c, clientpin::SUB_GET_TOKEN_WITH_PERMS, &[], &[], &hash_enc);
        r.permissions = perms;
        clientpin::handle(&r)
    };
    for (perm, name) in [
        (clientpin::PERM_MAKE_CREDENTIAL, "makeCredential"),
        (clientpin::PERM_GET_ASSERTION, "getAssertion"),
    ] {
        assert!(
            matches!(
                ask(perm),
                PinReply::Err(clientpin::ERR_PIN_POLICY_VIOLATION)
            ),
            "a {name} token was issued with a PIN change pending"
        );
    }
    assert!(
        matches!(ask(clientpin::PERM_AUTHENTICATOR_CFG), PinReply::Token(_)),
        "an authnrCfg token was refused, so the change could never be made"
    );
}

#[test]
fn changing_the_pin_clears_the_forced_change() {
    // Otherwise the device stays locked out of signing forever.
    let _g = fresh();
    let c = Client::new(0x46);
    assert!(matches!(set_pin(&c, "1234"), PinReply::Ok));
    assert_eq!(set_min_pin(None, Some(true)), 0x00);

    let hash_enc = c.pin_hash_enc("1234");
    let new = c.encrypt(&Client::padded_pin("567890"));
    let mut msg = Vec::new();
    msg.extend_from_slice(&new);
    msg.extend_from_slice(&hash_enc);
    let auth = c.auth(&msg);
    assert!(
        matches!(
            clientpin::handle(&PinRequest {
                protocol: clientpin::PIN_PROTOCOL_V1,
                subcommand: clientpin::SUB_CHANGE_PIN,
                key_agreement: Some(c.public),
                auth_param: &auth,
                new_pin_enc: &new,
                pin_hash_enc: &hash_enc,
                permissions: 0,
                rp_id_hash: None,
            }),
            PinReply::Ok
        ),
        "changePIN was refused"
    );

    let new_hash = c.pin_hash_enc("567890");
    let mut r = req(&c, clientpin::SUB_GET_TOKEN_WITH_PERMS, &[], &[], &new_hash);
    r.permissions = clientpin::PERM_MAKE_CREDENTIAL;
    assert!(
        matches!(clientpin::handle(&r), PinReply::Token(_)),
        "the forced change survived the change that satisfied it"
    );
}

// ============ enumeration carrying a full composite key ==================
//
// The gateway returns the ES256 half for every enumerated credential,
// matching the C and Rust ports (see the lookup closure in fw-secure
// main.rs for why). But ctap.rs must still be able to CARRY a full
// composite key, because that is a one-line policy change away and it
// had never executed anywhere: the host stubs returned zero-length keys
// and the device never derived one. When the full key was tried on
// silicon (2026-09-02) it was well-formed here and the in-house client
// could not receive it -- a client buffer sized for the small reply.
// This keeps the firmware half of that path exercised.

#[test]
fn handle_cred_mgmt_can_carry_a_full_composite_public_key() {
    let _g = fresh();
    let c = Client::new(0x51);
    set_pin(&c, "1234");
    store_one(1, 1); // ES256-shaped
    store_one(1, 2); // will be reported as hybrid by the lookup
    let token = token_with(&c, "1234", clientpin::PERM_CREDENTIAL_MGMT, None);

    // A lookup that behaves like the real one: fills the scratch with a
    // full-size ML-DSA-65 public key for the second credential.
    const PK: usize = 1952;
    let lookup = |_rp: &[u8; 32], id: &[u8; 64], scratch: &mut [u8]| {
        if id[0] == 2 {
            assert!(
                scratch.len() >= PK,
                "scratch is {} bytes, the key is {PK}",
                scratch.len()
            );
            for (i, b) in scratch[..PK].iter_mut().enumerate() {
                *b = (i & 0xff) as u8;
            }
            Some(([1u8; 32], [2u8; 32], PK))
        } else {
            Some(([1u8; 32], [2u8; 32], 0))
        }
    };

    // Begin with the rpIdHash for rp 1, as NS would lay it out.
    use fws::ctapreq::{
        CM_OFF_AUTH, CM_OFF_AUTH_LEN, CM_OFF_HAVE_RP, CM_OFF_PARAMS_LEN, CM_OFF_RP_HASH, CM_OFF_SUB,
    };
    let mut h = [0u8; 32];
    h[0] = 1;
    h[31] = 0xa5;
    let mut req = [0u8; fws::ctap::CM_REQ_LEN];
    req[CM_OFF_SUB] = 0x04; // enumerateCredentialsBegin
    req[CM_OFF_RP_HASH..CM_OFF_RP_HASH + 32].copy_from_slice(&h);
    req[CM_OFF_HAVE_RP] = 1;
    // subCommandParams as encoded for the auth: the real parser keeps the
    // verbatim CBOR; the token signs sub || params. With params_len 0 the
    // message is just the subcommand byte, which is what cm_auth signs.
    req[CM_OFF_PARAMS_LEN] = 0;
    req[CM_OFF_PARAMS_LEN + 1] = 0;
    let auth = cm_auth(&token, 0x04);
    req[CM_OFF_AUTH_LEN] = auth.len() as u8;
    req[CM_OFF_AUTH..CM_OFF_AUTH + auth.len()].copy_from_slice(&auth);

    let mut resp = [0u8; fws::ctap::RESP_MAX];
    let mut scratch = [0u8; fws::ctap::MLDSA_PK_MAX];
    let begin = fws::ctap::handle_cred_mgmt(&req, &mut resp, &lookup, &mut scratch);
    assert!(
        matches!(begin, fws::ctap::CmReply::Bytes(_)),
        "enumerateCredentialsBegin failed: {:?}",
        match begin {
            fws::ctap::CmReply::Err(e) => format!("err {e:#04x}"),
            _ => "ok".into(),
        }
    );

    // Next: lands on the hybrid credential.
    let mut next_req = [0u8; fws::ctap::CM_REQ_LEN];
    next_req[CM_OFF_SUB] = 0x05;
    let next = fws::ctap::handle_cred_mgmt(&next_req, &mut resp, &lookup, &mut scratch);
    match next {
        fws::ctap::CmReply::Bytes(n) => {
            // The response must carry the full key: -4 label followed by
            // a 1952-byte string (0x59 0x07 0xA0).
            let body = &resp[..n];
            let needle = [0x23u8, 0x59, 0x07, 0xA0];
            assert!(
                body.windows(4).any(|w| w == needle),
                "the enumerated hybrid credential does not carry a 1952-byte ML-DSA key"
            );
            // And the whole reply is structurally valid CBOR: one map,
            // consumed exactly, nothing trailing. This is the check that
            // says the DEVICE side of the silicon failure is well-formed.
            assert_eq!(body[0], 0x00, "status byte");
            let mut r = fws::cborr::Reader::new(&body[1..]);
            r.skip()
                .expect("the hybrid enumeration reply is not well-formed CBOR");
            assert_eq!(
                r.position(),
                body.len() - 1,
                "the reply has {} trailing bytes after the map",
                body.len() - 1 - r.position()
            );
            println!(
                "hybrid enumeration reply: {} bytes, well-formed",
                body.len()
            );
        }
        fws::ctap::CmReply::Err(e) => panic!(
            "enumerateCredentialsGetNext on the hybrid credential failed with {e:#04x} \
             (0x2e NO_CREDENTIALS = lookup returned None; 0x02 INVALID_PARAMETER = \
             the response did not fit; 0x30 NOT_ALLOWED = enumeration not live)"
        ),
    }
}

// ============ the pinUvAuthParam PIN probe ==============================
//
// CTAP 2.1 sec. 6.1.2 step 1: a pinUvAuthParam that is present and EMPTY is
// how a platform asks whether a PIN is set. The answer is PIN_NOT_SET or
// PIN_INVALID -- a status, never a served request -- and Chrome sends it
// on every registration. When only a length crossed the boundary, an
// empty param looked identical to an absent one and the probe minted a
// credential. Found by the second hunt.

fn probe_req(present: bool, malformed: bool, uv: bool) -> [u8; fws::ctap::REQ_LEN] {
    let mut b = req_bytes(uv, &[], 1);
    if present {
        b[fws::ctapreq::REQ_OFF_FLAGS] |= fws::ctapreq::FLAG_PUAT_PRESENT;
    }
    if malformed {
        b[fws::ctapreq::REQ_OFF_FLAGS] |= fws::ctapreq::FLAG_PUAT_MALFORMED;
    }
    b
}

#[test]
fn an_empty_pin_uv_auth_param_with_no_pin_answers_pin_not_set() {
    let _g = fresh();
    let mut r = fws::ctap::parse(&probe_req(true, false, false)).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Err(clientpin::ERR_PIN_NOT_SET),
        "the PIN probe was served instead of answered"
    );
}

#[test]
fn an_empty_pin_uv_auth_param_with_a_pin_answers_pin_invalid() {
    let _g = fresh();
    let c = Client::new(0x61);
    set_pin(&c, "1234");
    let mut r = fws::ctap::parse(&probe_req(true, false, false)).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Err(clientpin::ERR_PIN_INVALID),
        "the PIN probe on a PIN-set token did not say PIN_INVALID"
    );
}

#[test]
fn the_probe_does_not_spend_a_pin_retry() {
    // PIN_INVALID here is a status about the probe, not a wrong guess.
    let _g = fresh();
    let c = Client::new(0x62);
    set_pin(&c, "1234");
    let before = pinstore::get().retries;
    let mut r = fws::ctap::parse(&probe_req(true, false, false)).unwrap();
    let _ = fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL);
    assert_eq!(
        pinstore::get().retries,
        before,
        "the PIN probe cost a retry"
    );
}

#[test]
fn an_over_long_pin_uv_auth_param_is_refused_not_ignored() {
    // Present but longer than either protocol produces. It used to fall
    // to the absent path and the request was served with uv=false.
    let _g = fresh();
    let mut r = fws::ctap::parse(&probe_req(true, true, false)).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Err(clientpin::ERR_PIN_AUTH_INVALID)
    );
}

#[test]
fn an_absent_pin_uv_auth_param_is_still_absent() {
    // The accept half: no flag, no param, ordinary presence-only request.
    let _g = fresh();
    let mut r = fws::ctap::parse(&probe_req(false, false, false)).unwrap();
    assert_eq!(
        fws::ctap::resolve_uv(&mut r, clientpin::PERM_MAKE_CREDENTIAL),
        Ok(())
    );
    assert!(!r.uv);
}

// ============ credentialManagement: token scope and the no-token case ===

fn cm_req_rp(sub: u8, auth: &[u8], rp: Option<&[u8; 32]>) -> [u8; fws::ctap::CM_REQ_LEN] {
    use fws::ctapreq::{CM_OFF_HAVE_RP, CM_OFF_RP_HASH};
    let mut b = cm_req(sub, auth);
    if let Some(h) = rp {
        b[CM_OFF_RP_HASH..CM_OFF_RP_HASH + 32].copy_from_slice(h);
        b[CM_OFF_HAVE_RP] = 1;
    }
    b
}

fn cm_run(req: &[u8; fws::ctap::CM_REQ_LEN]) -> fws::ctap::CmReply {
    let mut resp = [0u8; 512];
    let mut scratch = [0u8; 64];
    fws::ctap::handle_cred_mgmt(
        req,
        &mut resp,
        &|_, _, _| Some(([1u8; 32], [2u8; 32], 0)),
        &mut scratch,
    )
}

fn hash_of(rp: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = rp;
    h[31] = 0xa5;
    h
}

#[test]
fn cred_mgmt_with_no_token_asks_for_one_rather_than_calling_it_invalid() {
    // PUAT_REQUIRED is retriable -- "go and get a token". PIN_AUTH_INVALID
    // says the one you sent was wrong, and nothing was sent. The C port
    // got this correction yesterday; this port still said INVALID.
    let _g = fresh();
    store_one(1, 1);
    assert!(
        cm_is_err(
            &cm_run(&cm_req(CM_GET_METADATA, &[])),
            fws::ctap::CTAP2_ERR_PUAT_REQUIRED
        ),
        "getCredsMetadata with no token did not answer PUAT_REQUIRED"
    );
}

#[test]
fn a_token_scoped_to_one_rp_cannot_enumerate_another() {
    // verify_token was called with rp = None, which skips the scope check
    // entirely: a token scoped to one relying party managed every
    // credential on the device.
    let _g = fresh();
    let c = Client::new(0x71);
    set_pin(&c, "1234");
    store_one(1, 1);
    store_one(2, 2);
    let token = token_with(
        &c,
        "1234",
        clientpin::PERM_CREDENTIAL_MGMT,
        Some(hash_of(1)),
    );

    // Scoped to RP 1: may enumerate RP 1's credentials...
    let ok = cm_run(&cm_req_rp(0x04, &cm_auth(&token, 0x04), Some(&hash_of(1))));
    assert!(
        matches!(ok, fws::ctap::CmReply::Bytes(_)),
        "a token scoped to RP 1 could not enumerate RP 1"
    );
    // ...but not RP 2's,
    assert!(
        cm_is_err(
            &cm_run(&cm_req_rp(0x04, &cm_auth(&token, 0x04), Some(&hash_of(2)))),
            clientpin::ERR_PIN_AUTH_INVALID
        ),
        "a token scoped to RP 1 enumerated RP 2"
    );
    // ...nor the device-wide subcommands.
    assert!(
        cm_is_err(
            &cm_run(&cm_req(CM_GET_METADATA, &cm_auth(&token, CM_GET_METADATA))),
            clientpin::ERR_PIN_AUTH_INVALID
        ),
        "a scoped token read device-wide metadata"
    );
    assert!(
        cm_is_err(
            &cm_run(&cm_req(
                CM_ENUM_RPS_BEGIN,
                &cm_auth(&token, CM_ENUM_RPS_BEGIN)
            )),
            clientpin::ERR_PIN_AUTH_INVALID
        ),
        "a scoped token enumerated all relying parties"
    );
}

#[test]
fn an_unscoped_token_still_manages_everything() {
    // The accept half: the ordinary management token has no scope and
    // must keep working for every subcommand.
    let _g = fresh();
    let c = Client::new(0x72);
    set_pin(&c, "1234");
    store_one(1, 1);
    let token = token_with(&c, "1234", clientpin::PERM_CREDENTIAL_MGMT, None);
    assert!(matches!(
        cm_run(&cm_req(CM_GET_METADATA, &cm_auth(&token, CM_GET_METADATA))),
        fws::ctap::CmReply::Bytes(_)
    ));
    assert!(matches!(
        cm_run(&cm_req(
            CM_ENUM_RPS_BEGIN,
            &cm_auth(&token, CM_ENUM_RPS_BEGIN)
        )),
        fws::ctap::CmReply::Bytes(_)
    ));
    assert!(matches!(
        cm_run(&cm_req_rp(0x04, &cm_auth(&token, 0x04), Some(&hash_of(1)))),
        fws::ctap::CmReply::Bytes(_)
    ));
}

// ============ a PIN change ends the tokens issued under the old PIN =====

#[test]
fn changing_the_pin_invalidates_the_outstanding_token() {
    // The token was boot-constant and survived changePIN, so what the old
    // PIN authorised kept working after the user changed it -- and the
    // forceChangePin gate only ever governed tokens minted afterwards.
    let _g = fresh();
    let c = Client::new(0x73);
    set_pin(&c, "1234");
    store_one(1, 1);
    let token = token_with(&c, "1234", clientpin::PERM_CREDENTIAL_MGMT, None);
    assert!(
        matches!(
            cm_run(&cm_req(CM_GET_METADATA, &cm_auth(&token, CM_GET_METADATA))),
            fws::ctap::CmReply::Bytes(_)
        ),
        "token did not work before the change"
    );

    let hash_enc = c.pin_hash_enc("1234");
    let new = c.encrypt(&Client::padded_pin("567890"));
    let mut msg = Vec::new();
    msg.extend_from_slice(&new);
    msg.extend_from_slice(&hash_enc);
    let auth = c.auth(&msg);
    assert!(matches!(
        clientpin::handle(&PinRequest {
            protocol: clientpin::PIN_PROTOCOL_V1,
            subcommand: clientpin::SUB_CHANGE_PIN,
            key_agreement: Some(c.public),
            auth_param: &auth,
            new_pin_enc: &new,
            pin_hash_enc: &hash_enc,
            permissions: 0,
            rp_id_hash: None,
        }),
        PinReply::Ok
    ));
    assert!(
        cm_is_err(
            &cm_run(&cm_req(CM_GET_METADATA, &cm_auth(&token, CM_GET_METADATA))),
            clientpin::ERR_PIN_AUTH_INVALID
        ),
        "a token issued under the old PIN still worked after changePIN"
    );
}
