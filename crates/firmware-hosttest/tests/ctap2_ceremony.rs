// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! MakeCredential and GetAssertion -- phase 3 of the CTAP2 surface.
//!
//! The two ceremonies are the token. Everything else exists to
//! configure, enumerate or reset what these two produce, and between
//! them they are 1400 of `ctap2.rs`'s 2956 lines. Until now the only
//! thing exercising them was the conformance suite driving a real board.
//!
//! **What is faked.** The signing runs on core 1 behind a mailbox and is
//! stubbed here, so these tests cover what the token *decides* -- which
//! algorithm, which credential, whether to refuse, what shape comes back
//! -- and never whether a signature verifies. That stays a silicon claim:
//! `pqc_roundtrip` across all six port x ISA configurations, and the
//! conformance suite checking attestation against the credential's own key.
//!
//! Where a test names a byte offset inside authData it is asserting the
//! structure a relying party parses, not the cryptography.

use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

use fw::client_pin::PinSession;
use fw::ctap2::{
    self, CredStore, HostOp, CTAP2_GET_ASSERTION, CTAP2_GET_NEXT_ASSERTION, CTAP2_MAKE_CREDENTIAL,
    CTAP2_OK,
};
use fw::mldsa_alg::{COSE_ALG_HYBRID_MLDSA, COSE_ALG_MLDSA44_ES256, COSE_ALG_MLDSA87_ES384};
use fw::trng::Trng;

// CTAP 2.1 sec. 8.2 status codes, spelled out where the firmware does not
// export them, so a wrong expectation reads as a wrong number.
const ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
const ERR_MISSING_PARAMETER: u8 = 0x14;
const ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const ERR_UNSUPPORTED_OPTION: u8 = 0x2b;
const ERR_INVALID_OPTION: u8 = 0x2c;
const ERR_NO_CREDENTIALS: u8 = 0x2e;
const ERR_NOT_ALLOWED: u8 = 0x30;

const RP: &str = "example.com";
const ES256: i64 = -7;
/// A composite this build does not implement, whatever level it is
/// built at -- used to prove the fallback rather than any one level.
const UNMINTABLE_COMPOSITE: i64 = if COSE_ALG_HYBRID_MLDSA == COSE_ALG_MLDSA87_ES384 {
    COSE_ALG_MLDSA44_ES256
} else {
    COSE_ALG_MLDSA87_ES384
};
/// Labels this firmware used for its composites before draft -04:
/// -51/-52/-53 (draft -02's request, since assigned by RFC 9864 to
/// ESP384 / ESP512 / Ed448) and, before that, the pure ML-DSA ids
/// -48/-49/-50. None of them may select the hybrid construction now.
const OLD_LABELS: [i64; 6] = [-51, -52, -53, -48, -49, -50];

fn enc(v: &Value) -> Vec<u8> {
    let mut o = Vec::new();
    pqf_cbor::encode(v, &mut o);
    o
}
fn t(s: &str) -> Value {
    Value::Text(s.into())
}
fn alg_entry(alg: i64) -> Value {
    Value::Map(vec![
        (t("alg"), Value::Nint(alg)),
        (t("type"), t("public-key")),
    ])
}
fn cred_entry(id: &[u8]) -> Value {
    Value::Map(vec![
        (t("type"), t("public-key")),
        (t("id"), Value::Bytes(id.to_vec())),
    ])
}

/// A MakeCredential request, built up field by field.
#[derive(Clone)]
struct Mc {
    algs: Vec<i64>,
    opts: Vec<(String, Value)>,
    exts: Vec<(String, Value)>,
    exclude: Option<Vec<Vec<u8>>>,
    cdh_len: usize,
    drop: Option<u64>,
    user_id: Vec<u8>,
    user_name: Option<String>,
}

impl Mc {
    fn new() -> Self {
        Mc {
            algs: vec![ES256],
            opts: vec![],
            exts: vec![],
            exclude: None,
            cdh_len: 32,
            drop: None,
            user_id: vec![1, 2, 3, 4],
            user_name: None,
        }
    }
    /// A different user handle, so two resident registrations at the same
    /// RP are two credentials rather than one overwriting the other.
    fn user(mut self, id: &[u8]) -> Self {
        self.user_id = id.to_vec();
        self
    }
    /// A user name (sent as name and displayName), which GetAssertion
    /// releases only when UV happened or there are accounts to choose
    /// between.
    fn named(mut self, name: &str) -> Self {
        self.user_name = Some(name.into());
        self
    }
    fn algs(mut self, a: &[i64]) -> Self {
        self.algs = a.to_vec();
        self
    }
    fn opt(mut self, k: &str, v: Value) -> Self {
        self.opts.push((k.into(), v));
        self
    }
    fn rk(self) -> Self {
        self.opt("rk", Value::Bool(true))
    }
    fn ext(mut self, k: &str, v: Value) -> Self {
        self.exts.push((k.into(), v));
        self
    }
    fn exclude(mut self, ids: &[Vec<u8>]) -> Self {
        self.exclude = Some(ids.to_vec());
        self
    }
    fn without(mut self, key: u64) -> Self {
        self.drop = Some(key);
        self
    }
    fn cdh_len(mut self, n: usize) -> Self {
        self.cdh_len = n;
        self
    }
    fn build(&self) -> Value {
        let mut user = vec![(t("id"), Value::Bytes(self.user_id.clone()))];
        if let Some(n) = &self.user_name {
            user.push((t("name"), t(n)));
            user.push((t("displayName"), t(n)));
        }
        let mut e: Vec<(Value, Value)> = vec![
            (Value::Uint(1), Value::Bytes(vec![0x11; self.cdh_len])),
            (Value::Uint(2), Value::Map(vec![(t("id"), t(RP))])),
            (Value::Uint(3), Value::Map(user)),
            (
                Value::Uint(4),
                Value::Array(self.algs.iter().copied().map(alg_entry).collect()),
            ),
        ];
        if let Some(ids) = &self.exclude {
            e.push((
                Value::Uint(5),
                Value::Array(ids.iter().map(|i| cred_entry(i)).collect()),
            ));
        }
        if !self.exts.is_empty() {
            e.push((
                Value::Uint(6),
                Value::Map(self.exts.iter().map(|(k, v)| (t(k), v.clone())).collect()),
            ));
        }
        if !self.opts.is_empty() {
            e.push((
                Value::Uint(7),
                Value::Map(self.opts.iter().map(|(k, v)| (t(k), v.clone())).collect()),
            ));
        }
        if let Some(d) = self.drop {
            e.retain(|(k, _)| !matches!(k, Value::Uint(n) if *n == d));
        }
        e.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
        Value::Map(e)
    }
}

/// A GetAssertion request.
#[derive(Clone)]
struct Ga {
    rp: String,
    allow: Option<Vec<Vec<u8>>>,
    opts: Vec<(String, Value)>,
    drop: Option<u64>,
    pin_auth: Option<Vec<u8>>,
}

/// The clientDataHash every GetAssertion here signs over.
const GA_CDH: [u8; 32] = [0x22; 32];

impl Ga {
    fn new() -> Self {
        Ga {
            rp: RP.into(),
            allow: None,
            opts: vec![],
            drop: None,
            pin_auth: None,
        }
    }
    /// Authenticate the request with `token`: a v1 pinUvAuthParam over
    /// the clientDataHash, as a platform sends once the PIN is entered.
    fn pin_auth(mut self, token: &[u8]) -> Self {
        self.pin_auth = Some(fw::testclient::auth_param(token, &GA_CDH));
        self
    }
    fn rp(mut self, r: &str) -> Self {
        self.rp = r.into();
        self
    }
    fn allow(mut self, ids: &[Vec<u8>]) -> Self {
        self.allow = Some(ids.to_vec());
        self
    }
    fn opt(mut self, k: &str, v: Value) -> Self {
        self.opts.push((k.into(), v));
        self
    }
    fn without(mut self, key: u64) -> Self {
        self.drop = Some(key);
        self
    }
    fn build(&self) -> Value {
        let mut e: Vec<(Value, Value)> = vec![
            (Value::Uint(1), t(&self.rp)),
            (Value::Uint(2), Value::Bytes(GA_CDH.to_vec())),
        ];
        if let Some(ids) = &self.allow {
            e.push((
                Value::Uint(3),
                Value::Array(ids.iter().map(|i| cred_entry(i)).collect()),
            ));
        }
        if !self.opts.is_empty() {
            e.push((
                Value::Uint(5),
                Value::Map(self.opts.iter().map(|(k, v)| (t(k), v.clone())).collect()),
            ));
        }
        if let Some(p) = &self.pin_auth {
            e.push((Value::Uint(6), Value::Bytes(p.clone())));
            e.push((Value::Uint(7), Value::Uint(1)));
        }
        if let Some(d) = self.drop {
            e.retain(|(k, _)| !matches!(k, Value::Uint(n) if *n == d));
        }
        e.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
        Value::Map(e)
    }
}

/// The channel every request goes out on unless a test picks another.
const CID: [u8; 4] = [0, 0, 0, 1];

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

    fn send_with(&mut self, cmd: u8, v: &Value, present: bool) -> Vec<u8> {
        self.send_at(cmd, v, 0, CID, &mut |_op: HostOp| present)
    }

    /// `send_with`, with the clock, the channel and the whole host side
    /// chosen by the caller -- so presence and a CTAPHID_CANCEL during
    /// the sign (a `Pump` answered `false`) can be told apart.
    fn send_at(
        &mut self,
        cmd: u8,
        v: &Value,
        now_us: u64,
        cid: [u8; 4],
        host: &mut dyn FnMut(HostOp) -> bool,
    ) -> Vec<u8> {
        let mut msg = vec![cmd];
        msg.extend_from_slice(&enc(v));
        ctap2::handle_cbor(
            &msg,
            &mut self.trng,
            &mut self.session,
            &mut self.store,
            host,
            now_us,
            cid,
        )
        .to_vec()
    }

    /// GetNextAssertion on the default channel at time zero.
    fn next(&mut self) -> Vec<u8> {
        self.send_with(CTAP2_GET_NEXT_ASSERTION, &Value::Map(vec![]), true)
    }

    fn mc(&mut self, r: &Mc) -> Vec<u8> {
        self.send_with(CTAP2_MAKE_CREDENTIAL, &r.build(), true)
    }
    fn ga(&mut self, r: &Ga) -> Vec<u8> {
        self.send_with(CTAP2_GET_ASSERTION, &r.build(), true)
    }

    /// Register and return the credential id, failing loudly otherwise.
    fn register(&mut self, r: &Mc) -> Vec<u8> {
        let resp = self.mc(r);
        assert_eq!(resp[0], CTAP2_OK, "registration failed: {:#04x}", resp[0]);
        credential_id(&auth_data(&resp))
    }
}

/// The response's authData (MakeCredential key 0x02, GetAssertion 0x02).
fn auth_data(resp: &[u8]) -> Vec<u8> {
    assert_eq!(
        resp[0], CTAP2_OK,
        "no authData in a {:#04x} response",
        resp[0]
    );
    match pqf_cbor::decode(&resp[1..]).expect("response body is not CBOR") {
        Value::Map(m) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Uint(2), Value::Bytes(b)) => Some(b.clone()),
                _ => None,
            })
            .expect("no authData in the response"),
        other => panic!("response body is {other:?}"),
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

// authData: rpIdHash(32) | flags(1) | signCount(4) | [AAGUID(16) |
// credIdLen(2) | credId | COSE_Key] | [extensions]
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

fn flags(ad: &[u8]) -> u8 {
    ad[32]
}
fn sign_count(ad: &[u8]) -> u32 {
    u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]])
}
fn credential_id(ad: &[u8]) -> Vec<u8> {
    assert!(
        flags(ad) & FLAG_AT != 0,
        "authData carries no attested credential"
    );
    let len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    ad[55..55 + len].to_vec()
}
/// The extensions map at the tail of authData, if the ED flag is set.
fn extensions(ad: &[u8]) -> Option<Vec<(Value, Value)>> {
    if flags(ad) & FLAG_ED == 0 {
        return None;
    }
    let start = if flags(ad) & FLAG_AT != 0 {
        let len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        let after_id = 55 + len;
        // The COSE key is a CBOR map of unknown length; find where it
        // ends by decoding the tail at each offset until one parses.
        let rest = &ad[after_id..];
        (1..rest.len())
            .find(|&k| matches!(pqf_cbor::decode(&rest[k..]), Ok(Value::Map(_))))
            .map(|k| after_id + k)
            .expect("no extensions map found after the COSE key")
    } else {
        37
    };
    match pqf_cbor::decode(&ad[start..]).expect("the extensions block is not CBOR") {
        Value::Map(m) => Some(m),
        other => panic!("extensions is {other:?}, not a map"),
    }
}
fn ext_value(ad: &[u8], name: &str) -> Option<Value> {
    extensions(ad)?.iter().find_map(|(k, v)| match k {
        Value::Text(s) if s == name => Some(v.clone()),
        _ => None,
    })
}

/// The `alg` (label 3) of the COSE_Key in a MakeCredential authData
/// that carries no extensions -- the key runs to the end.
fn cose_alg(ad: &[u8]) -> i64 {
    assert!(
        flags(ad) & FLAG_ED == 0,
        "cose_alg() needs authData without extensions"
    );
    let len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    match pqf_cbor::decode(&ad[55 + len..]).expect("the COSE_Key is not CBOR") {
        Value::Map(m) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Uint(3), Value::Nint(n)) => Some(*n),
                _ => None,
            })
            .expect("the COSE_Key has no alg"),
        other => panic!("the COSE_Key is {other:?}"),
    }
}
/// The `alg` of a MakeCredential response's attestation statement.
fn att_stmt_alg(resp: &[u8]) -> i64 {
    match resp_key(resp, 3).expect("no attStmt") {
        Value::Map(m) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Text(t), Value::Nint(n)) if t == "alg" => Some(*n),
                _ => None,
            })
            .expect("attStmt has no alg"),
        other => panic!("attStmt is {other:?}"),
    }
}

// ---- MakeCredential: the required parameters ------------------------

#[test]
fn every_required_make_credential_parameter_is_required() {
    // Dropping any one of the four is what a half-implemented client
    // does, and each has to be refused rather than defaulted -- a
    // defaulted clientDataHash would sign over something the RP never
    // sent.
    for (name, k) in [
        ("clientDataHash", 1u64),
        ("rp", 2),
        ("user", 3),
        ("pubKeyCredParams", 4),
    ] {
        let mut d = Device::new();
        let r = d.mc(&Mc::new().without(k));
        assert_eq!(
            r[0], ERR_MISSING_PARAMETER,
            "MakeCredential without {name} was not refused"
        );
    }
}

#[test]
fn a_client_data_hash_that_is_not_thirty_two_bytes_is_refused() {
    // It is a SHA-256 hash and nothing else. Accepting a short one would
    // let a caller control how much of the signed message it fixes.
    for n in [0usize, 16, 31, 33, 64] {
        let mut d = Device::new();
        let r = d.mc(&Mc::new().cdh_len(n));
        assert_eq!(
            r[0], ERR_MISSING_PARAMETER,
            "a {n}-byte clientDataHash was accepted"
        );
    }
}

// ---- MakeCredential: choosing an algorithm ---------------------------

#[test]
fn a_list_with_no_supported_algorithm_is_refused() {
    let mut d = Device::new();
    assert_eq!(d.mc(&Mc::new().algs(&[-999]))[0], ERR_UNSUPPORTED_ALGORITHM);
}

#[test]
fn an_empty_algorithm_list_is_refused_as_unsupported_not_missing() {
    // The distinction CTAP 2.1 sec. 6.1 draws: no pubKeyCredParams at all is
    // a malformed request (0x14); a present-but-useless list is a
    // negotiation failure (0x26), and tells the RP to offer something
    // else rather than to fix its encoder.
    let mut d = Device::new();
    assert_eq!(d.mc(&Mc::new().algs(&[]))[0], ERR_UNSUPPORTED_ALGORITHM);
    drop(d);
    let mut d = Device::new();
    assert_eq!(d.mc(&Mc::new().without(4))[0], ERR_MISSING_PARAMETER);
}

#[test]
fn a_composite_this_build_cannot_mint_falls_through_to_es256() {
    // getInfo advertises all three composites on every build; only one
    // is mintable. An RP that asks for another one plus ES256 must get
    // ES256 rather than a refusal -- that fallback is the whole reason
    // the unconditional advertisement is safe.
    let mut d = Device::new();
    let r = d.mc(&Mc::new().algs(&[UNMINTABLE_COMPOSITE, ES256]));
    assert_eq!(r[0], CTAP2_OK, "the fallback to ES256 did not happen");
}

#[test]
fn a_composite_this_build_cannot_mint_alone_is_refused() {
    // The other half: with no ES256 to fall back to, the advertisement
    // is exposed for what it is. This is the advertised-versus-usable
    // gap, reproduced deliberately so it cannot be forgotten.
    let mut d = Device::new();
    let r = d.mc(&Mc::new().algs(&[UNMINTABLE_COMPOSITE]));
    assert_eq!(
        r[0], ERR_UNSUPPORTED_ALGORITHM,
        "a composite this build cannot mint was accepted"
    );
}

#[test]
fn an_old_composite_label_alone_is_refused_like_any_unsupported_alg() {
    // -52 now means ESP512 and -49 means pure ML-DSA-65: neither is the
    // hybrid construction, so a request offering only one of them must
    // be answered exactly as a request for -999 is.
    for old in OLD_LABELS {
        let mut d = Device::new();
        assert_eq!(
            d.mc(&Mc::new().algs(&[old]))[0],
            ERR_UNSUPPORTED_ALGORITHM,
            "{old} alone was accepted as if it were a composite"
        );
    }
    let mut d = Device::new();
    assert_eq!(
        d.mc(&Mc::new().algs(&[-51, -52, -53]))[0],
        ERR_UNSUPPORTED_ALGORITHM,
        "-51/-52/-53 together were accepted"
    );
}

#[test]
fn an_old_composite_label_before_es256_still_gets_es256() {
    // The PQC-first pass must not pick an old label: with ES256 also on
    // offer the result is an ES256 credential, labelled -7 in both the
    // COSE_Key and the attestation statement.
    for old in OLD_LABELS {
        let mut d = Device::new();
        let r = d.mc(&Mc::new().algs(&[old, ES256]));
        assert_eq!(r[0], CTAP2_OK, "[{old}, -7] was refused");
        assert_eq!(
            cose_alg(&auth_data(&r)),
            ES256,
            "[{old}, -7] minted a non-ES256 key"
        );
        assert_eq!(
            att_stmt_alg(&r),
            ES256,
            "[{old}, -7] attested with a non-ES256 alg"
        );
    }
}

#[test]
fn this_builds_composite_is_labelled_with_its_draft_04_id() {
    // Label 3 of the credential's COSE_Key is this build's composite
    // id, which is one of the draft -04 requests. The attestation is
    // signed with the credential key at 44 and 65, and with ES256 at
    // 87 (the CTAPHID message-size ceiling), so its alg follows suit.
    assert!(
        [-54, -55, -56].contains(&COSE_ALG_HYBRID_MLDSA),
        "this build's composite id {} is not a draft -04 id",
        COSE_ALG_HYBRID_MLDSA
    );
    let mut d = Device::new();
    let r = d.mc(&Mc::new().algs(&[COSE_ALG_HYBRID_MLDSA]));
    assert_eq!(r[0], CTAP2_OK);
    assert_eq!(cose_alg(&auth_data(&r)), COSE_ALG_HYBRID_MLDSA);
    let want_att = if COSE_ALG_HYBRID_MLDSA == COSE_ALG_MLDSA87_ES384 {
        ES256
    } else {
        COSE_ALG_HYBRID_MLDSA
    };
    assert_eq!(att_stmt_alg(&r), want_att);
}

#[test]
fn this_builds_composite_is_mintable_and_bigger_than_es256() {
    // Shape, not validity: a hybrid response carries an ML-DSA public
    // key and an ML-DSA signature, so it cannot be the same size as an
    // ES256 one. If they matched, the composite path would be silently
    // falling back.
    let mut d = Device::new();
    let hybrid = d.mc(&Mc::new().algs(&[fw::mldsa_alg::COSE_ALG_HYBRID_MLDSA]));
    assert_eq!(
        hybrid[0], CTAP2_OK,
        "this build cannot mint its own composite"
    );
    drop(d);

    let mut d = Device::new();
    let ec = d.mc(&Mc::new().algs(&[ES256]));
    assert_eq!(ec[0], CTAP2_OK);
    assert!(
        hybrid.len() > ec.len() * 2,
        "the composite response ({}) is not meaningfully larger than ES256 ({})",
        hybrid.len(),
        ec.len()
    );
}

#[test]
fn the_composite_wins_even_when_the_rp_lists_es256_first() {
    // A deliberate deviation, recorded as one.
    //
    // CTAP 2.1 sec. 6.1 says the authenticator "chooses the first occurrence
    // of an algorithm identifier supported by this authenticator", and
    // pubKeyCredParams is "ordered from most preferred to least
    // preferred". This device instead scans for its composite first
    // whatever position it is in, and only falls back to ES256 when no
    // composite is offered -- see the `is_pqc` pass in ctap2.rs.
    //
    // That is the point of the product, but it does override the RP's
    // stated preference, and an RP that lists [ES256, composite] meaning
    // "ES256 please, composite if you must" gets the composite. Worth
    // knowing before a conformance run reports it.
    let mut d = Device::new();
    let r = d.mc(&Mc::new().algs(&[ES256, fw::mldsa_alg::COSE_ALG_HYBRID_MLDSA]));
    assert_eq!(r[0], CTAP2_OK);
    drop(d);

    let mut d = Device::new();
    let es_only = d.mc(&Mc::new().algs(&[ES256]));
    assert!(
        r.len() > es_only.len(),
        "the RP's first choice won -- the PQC reordering is gone, and this \
         test and its note in docs/TESTING.md should go with it"
    );
}

// ---- MakeCredential: options ----------------------------------------

#[test]
fn user_presence_cannot_be_turned_off_for_a_registration() {
    // CTAP 2.1 sec. 6.1: "up" false on MakeCredential is invalid, not
    // merely unsupported. Silently registering without a gesture is how
    // a token becomes a background signing oracle.
    let mut d = Device::new();
    let r = d.mc(&Mc::new().opt("up", Value::Bool(false)));
    assert_eq!(
        r[0], ERR_INVALID_OPTION,
        "up=false was accepted on a registration"
    );
}

#[test]
fn user_verification_is_refused_when_no_pin_is_set() {
    // There is no built-in UV on this hardware, so uv=true with no PIN
    // has no way to succeed. Refusing it beats registering a credential
    // the RP believes is UV-protected and is not.
    let mut d = Device::new();
    let r = d.mc(&Mc::new().opt("uv", Value::Bool(true)));
    assert_eq!(r[0], ERR_UNSUPPORTED_OPTION);
}

#[test]
fn a_refused_gesture_leaves_no_credential_behind() {
    // The gate has to fail closed. A stored credential after a refusal
    // is both a leak of the ceremony and a slot lost forever.
    let mut d = Device::new();
    let before = d.store.active_count();
    let r = d.send_with(CTAP2_MAKE_CREDENTIAL, &Mc::new().rk().build(), false);
    assert_ne!(r[0], CTAP2_OK, "a registration succeeded without a gesture");
    assert_eq!(
        d.store.active_count(),
        before,
        "a refused registration stored a credential"
    );
}

#[test]
fn only_rk_true_consumes_a_slot() {
    // Non-discoverable credentials live entirely inside the credential
    // id the host keeps. Storing them anyway would fill 64 slots with
    // credentials nothing can enumerate.
    let mut d = Device::new();
    assert_eq!(d.mc(&Mc::new())[0], CTAP2_OK);
    assert_eq!(
        d.store.active_count(),
        0,
        "a non-resident credential took a slot"
    );
    assert_eq!(d.mc(&Mc::new().rk())[0], CTAP2_OK);
    assert_eq!(
        d.store.active_count(),
        1,
        "a resident credential took no slot"
    );
}

// ---- MakeCredential: excludeList -------------------------------------

#[test]
fn a_credential_this_token_minted_excludes_a_re_registration() {
    // WebAuthn's excludeCredentials guarantee: an RP passes what it
    // already holds, and the token must refuse rather than silently give
    // the user a second credential they will never be asked for.
    let mut d = Device::new();
    let id = d.register(&Mc::new().rk());
    let r = d.mc(&Mc::new().exclude(&[id]));
    assert_eq!(
        r[0], ERR_CREDENTIAL_EXCLUDED,
        "a re-registration was not excluded"
    );
}

#[test]
fn a_credential_from_another_token_does_not_exclude() {
    // The list is whatever the RP holds, across every authenticator the
    // user owns. Refusing on someone else's credential id would make a
    // second token impossible to enrol.
    let mut d = Device::new();
    let r = d.mc(&Mc::new().exclude(&[vec![0xAB; 161]]));
    assert_eq!(
        r[0], CTAP2_OK,
        "a foreign credential id blocked a registration"
    );
}

#[test]
fn a_malformed_exclude_list_does_not_stop_a_registration() {
    // Entries of the wrong length, wrong type, or empty arrive from real
    // clients. None of them is this token's credential, so none of them
    // is a match -- and none may be a panic.
    for entry in [
        Value::Bytes(vec![]),
        Value::Bytes(vec![0u8; 1]),
        Value::Bytes(vec![0u8; 4096]),
        Value::Text("not-a-credential".into()),
        Value::Uint(7),
        Value::Array(vec![]),
    ] {
        let mut d = Device::new();
        let mut req = Mc::new().build();
        if let Value::Map(m) = &mut req {
            m.push((Value::Uint(5), Value::Array(vec![entry.clone()])));
            m.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
        }
        let r = d.send_with(CTAP2_MAKE_CREDENTIAL, &req, true);
        assert_eq!(
            r[0], CTAP2_OK,
            "excludeList entry {entry:?} broke a registration"
        );
    }
}

// ---- MakeCredential: extensions --------------------------------------

#[test]
fn cred_protect_is_echoed_for_each_level_the_spec_defines() {
    // CTAP 2.1 sec. 12.1: the output value "MUST be the credProtect value
    // the authenticator set for the created credential". An RP reads it
    // to learn what protection it actually got.
    for level in 1u64..=3 {
        let mut d = Device::new();
        let r = d.mc(&Mc::new().ext("credProtect", Value::Uint(level)));
        assert_eq!(r[0], CTAP2_OK);
        let ad = auth_data(&r);
        assert_eq!(
            ext_value(&ad, "credProtect"),
            Some(Value::Uint(level)),
            "credProtect {level} was not echoed"
        );
    }
}

#[test]
fn no_extension_data_is_returned_when_none_was_asked_for() {
    // sec. 12.1: "The authenticator MUST NOT return an unsolicited
    // credProtect extension output." The ED flag governs whether a
    // relying party parses a tail at all, so an unsolicited one changes
    // how the whole structure is read.
    let mut d = Device::new();
    let r = d.mc(&Mc::new());
    let ad = auth_data(&r);
    assert_eq!(
        flags(&ad) & FLAG_ED,
        0,
        "authData carries unsolicited extension data"
    );
    assert!(extensions(&ad).is_none());
}

#[test]
fn an_out_of_range_cred_protect_is_ignored_rather_than_honoured() {
    // Recorded behaviour, not a spec requirement -- sec. 12.1 defines 1, 2
    // and 3 and says nothing about anything else. This device drops the
    // value and returns no credProtect output, so an RP sending a level
    // from a future revision learns it did not take. That is the safe
    // direction: the alternative is echoing a level nothing enforces.
    for level in [0u64, 4, 255] {
        let mut d = Device::new();
        let r = d.mc(&Mc::new().ext("credProtect", Value::Uint(level)));
        assert_eq!(r[0], CTAP2_OK, "credProtect {level} was rejected outright");
        let ad = auth_data(&r);
        assert_eq!(
            ext_value(&ad, "credProtect"),
            None,
            "credProtect {level} was echoed back as if honoured"
        );
    }
}

#[test]
fn a_cred_blob_within_the_advertised_limit_is_stored() {
    // getInfo advertises maxCredBlobLength. A blob at exactly that size
    // has to be accepted, or the advertised number is a lie.
    let max = fw::flash_store::MAX_CRED_BLOB_LEN;
    let mut d = Device::new();
    let r = d.mc(&Mc::new().rk().ext("credBlob", Value::Bytes(vec![7; max])));
    assert_eq!(r[0], CTAP2_OK);
    assert_eq!(
        ext_value(&auth_data(&r), "credBlob"),
        Some(Value::Bool(true)),
        "a maximum-size credBlob was not stored"
    );
}

#[test]
fn an_oversized_cred_blob_is_reported_as_not_stored() {
    // sec. 12.2: the output is a boolean saying whether it was kept. The
    // registration still succeeds -- what must not happen is a truncated
    // blob reported as stored, which an RP would read back as corrupt.
    let max = fw::flash_store::MAX_CRED_BLOB_LEN;
    for n in [max + 1, max * 2, 512] {
        let mut d = Device::new();
        let r = d.mc(&Mc::new().rk().ext("credBlob", Value::Bytes(vec![7; n])));
        assert_eq!(
            r[0], CTAP2_OK,
            "a {n}-byte credBlob failed the registration"
        );
        assert_eq!(
            ext_value(&auth_data(&r), "credBlob"),
            Some(Value::Bool(false)),
            "a {n}-byte credBlob was reported as stored"
        );
    }
}

// ---- MakeCredential: the response ------------------------------------

#[test]
fn the_attestation_response_has_the_three_fields_a_relying_party_reads() {
    let mut d = Device::new();
    let r = d.mc(&Mc::new());
    assert_eq!(r[0], CTAP2_OK);
    assert_eq!(resp_key(&r, 1), Some(t("packed")), "fmt is not \"packed\"");
    assert!(
        matches!(resp_key(&r, 2), Some(Value::Bytes(_))),
        "no authData"
    );
    assert!(matches!(resp_key(&r, 3), Some(Value::Map(_))), "no attStmt");
}

#[test]
fn registration_auth_data_is_shaped_the_way_webauthn_parses_it() {
    // A relying party walks these offsets literally. Getting the
    // credential-id length field wrong shifts everything after it, and
    // the failure surfaces as an unparseable COSE key.
    let mut d = Device::new();
    let r = d.mc(&Mc::new());
    let ad = auth_data(&r);
    assert!(
        ad.len() > 55,
        "authData is too short to hold an attested credential"
    );
    assert_eq!(
        &ad[..32],
        &fw::bc_crypto::sha256(RP.as_bytes())[..],
        "rpIdHash is not SHA-256(rpId)"
    );
    assert_ne!(
        flags(&ad) & FLAG_UP,
        0,
        "the UP flag is clear on a confirmed registration"
    );
    assert_ne!(
        flags(&ad) & FLAG_AT,
        0,
        "the AT flag is clear on a registration"
    );
    assert_eq!(
        u16::from_be_bytes([ad[53], ad[54]]) as usize,
        fw::credential_id::CRED_ID_LEN,
        "the credential-id length field disagrees with the format"
    );
    assert!(
        55 + fw::credential_id::CRED_ID_LEN < ad.len(),
        "authData ends before the COSE key"
    );
}

#[test]
fn two_registrations_for_one_rp_get_different_credential_ids() {
    // Sealed ids must not collide, or the second registration silently
    // replaces the first from the host's point of view.
    let mut d = Device::new();
    let a = d.register(&Mc::new());
    let b = d.register(&Mc::new());
    assert_ne!(a, b, "two registrations produced the same credential id");
}

// ---- GetAssertion ----------------------------------------------------

#[test]
fn every_required_get_assertion_parameter_is_required() {
    for (name, k) in [("rpId", 1u64), ("clientDataHash", 2)] {
        let mut d = Device::new();
        let r = d.ga(&Ga::new().without(k));
        assert_eq!(
            r[0], ERR_MISSING_PARAMETER,
            "GetAssertion without {name} was not refused"
        );
    }
}

#[test]
fn a_token_with_nothing_registered_has_no_credentials() {
    let mut d = Device::new();
    assert_eq!(d.ga(&Ga::new())[0], ERR_NO_CREDENTIALS);
}

#[test]
fn a_resident_credential_is_found_without_an_allow_list() {
    // The whole point of rk=true: a passkey the RP can ask for by name.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    assert_eq!(
        d.ga(&Ga::new())[0],
        CTAP2_OK,
        "a resident credential was not discovered"
    );
}

#[test]
fn a_non_resident_credential_is_found_only_through_the_allow_list() {
    // It exists nowhere but inside the id the host holds, so without
    // that id there is nothing to find -- and with it there must be.
    let mut d = Device::new();
    let id = d.register(&Mc::new());
    assert_eq!(
        d.ga(&Ga::new())[0],
        ERR_NO_CREDENTIALS,
        "a non-resident credential was discoverable"
    );
    assert_eq!(
        d.ga(&Ga::new().allow(&[id]))[0],
        CTAP2_OK,
        "the allowList did not find it"
    );
}

#[test]
fn a_credential_is_scoped_to_the_relying_party_that_made_it() {
    // The single most important boundary here. A credential usable under
    // another RP id is a cross-site authentication bypass, and the check
    // has to hold with the id in hand -- not merely when it is absent.
    let mut d = Device::new();
    let id = d.register(&Mc::new().rk());
    assert_eq!(d.ga(&Ga::new().rp("evil.example"))[0], ERR_NO_CREDENTIALS);
    assert_eq!(
        d.ga(&Ga::new().rp("evil.example").allow(&[id]))[0],
        ERR_NO_CREDENTIALS,
        "a credential answered for the wrong relying party when its id was supplied"
    );
}

#[test]
fn a_credential_id_this_token_did_not_mint_is_not_honoured() {
    // The id is sealed under the device master keys. Anything else is
    // either another token's or a forgery, and both must miss.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    for forged in [vec![0xCD; 161], vec![0u8; 161], vec![0xFF; 161]] {
        assert_eq!(
            d.ga(&Ga::new().allow(&[forged.clone()]))[0],
            ERR_NO_CREDENTIALS,
            "a forged credential id was honoured"
        );
    }
}

#[test]
fn a_tampered_credential_id_is_rejected() {
    // Flip one byte of a genuine sealed id. The authentication tag over
    // it is the only thing standing between the host and a credential
    // handle it can steer.
    let mut d = Device::new();
    let id = d.register(&Mc::new());
    assert_eq!(d.ga(&Ga::new().allow(&[id.clone()]))[0], CTAP2_OK);
    for pos in [0usize, 1, id.len() / 2, id.len() - 1] {
        let mut bad = id.clone();
        bad[pos] ^= 0x01;
        assert_eq!(
            d.ga(&Ga::new().allow(&[bad]))[0],
            ERR_NO_CREDENTIALS,
            "a credential id with byte {pos} flipped was accepted"
        );
    }
}

/// Entries a client can send that are not a `{id, type}` descriptor.
const MALFORMED_ENTRIES: [&str; 5] = [
    "empty bytes",
    "short bytes",
    "huge bytes",
    "text",
    "integer",
];
fn malformed_entry(which: usize) -> Value {
    match which {
        0 => Value::Bytes(vec![]),
        1 => Value::Bytes(vec![0u8; 1]),
        2 => Value::Bytes(vec![0u8; 4096]),
        3 => Value::Text("nope".into()),
        _ => Value::Uint(7),
    }
}
fn ga_with_raw_allow_list(d: &mut Device, entries: Vec<Value>) -> Vec<u8> {
    let mut req = Ga::new().build();
    if let Value::Map(m) = &mut req {
        m.push((Value::Uint(3), Value::Array(entries)));
        m.sort_by_key(|(k, _)| if let Value::Uint(n) = k { *n } else { 0 });
    }
    d.send_with(CTAP2_GET_ASSERTION, &req, true)
}

#[test]
fn a_malformed_allow_list_finds_nothing_when_nothing_is_discoverable() {
    // The safe half, and the one that holds. With no resident credential
    // there is nothing to fall back to, so an unparseable allowList
    // correctly finds nothing -- and, importantly, does not panic on any
    // of these shapes.
    for (i, name) in MALFORMED_ENTRIES.iter().enumerate() {
        let mut d = Device::new();
        d.register(&Mc::new()); // non-resident: takes no slot
        let r = ga_with_raw_allow_list(&mut d, vec![malformed_entry(i)]);
        assert_eq!(
            r[0], ERR_NO_CREDENTIALS,
            "a {name} allowList entry did not miss"
        );
    }
}

#[test]
fn a_malformed_allow_list_does_not_fall_back_to_a_discoverable_credential() {
    // This used to be a fail-open, recorded as a test. CTAP 2.1 sec. 6.2
    // branches on the parameter -- "present and non-empty" means locate
    // the *denoted* credentials -- but the Rust port branched on the
    // parsed list, so an allowList whose entries it could not read was
    // treated as absent and the token answered with whichever
    // discoverable credential it held for that rpId.
    //
    // A relying party naming one credential got a different one. On a
    // token holding passkeys for two accounts at one site that silently
    // switched which account authenticated. The C port was already
    // correct and was the reference for the fix.
    for (i, name) in MALFORMED_ENTRIES.iter().enumerate() {
        let mut d = Device::new();
        d.register(&Mc::new().rk());
        let r = ga_with_raw_allow_list(&mut d, vec![malformed_entry(i)]);
        assert_eq!(
            r[0], ERR_NO_CREDENTIALS,
            "a {name} allowList entry fell back to a discoverable credential"
        );
    }
}

#[test]
fn an_allow_list_that_is_present_but_empty_still_finds_discoverables() {
    // The one case that must NOT change. sec. 6.2's two branches are
    // "present and non-empty" and "not present"; a zero-length array
    // falls in neither, and every platform treats it as absent -- it is
    // what a browser sends for a passwordless login. Reading it as
    // "present" would make discoverable credentials unreachable.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    let r = ga_with_raw_allow_list(&mut d, vec![]);
    assert_eq!(
        r[0], CTAP2_OK,
        "an empty allowList stopped a discoverable credential being found"
    );
}

#[test]
fn a_refused_gesture_produces_no_assertion() {
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    let r = d.send_with(CTAP2_GET_ASSERTION, &Ga::new().build(), false);
    assert_ne!(
        r[0], CTAP2_OK,
        "an assertion was produced without a gesture"
    );
}

#[test]
fn the_assertion_response_carries_credential_auth_data_and_signature() {
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    let r = d.ga(&Ga::new());
    assert_eq!(r[0], CTAP2_OK);
    assert!(
        matches!(resp_key(&r, 1), Some(Value::Map(_))),
        "no credential descriptor"
    );
    assert!(
        matches!(resp_key(&r, 2), Some(Value::Bytes(_))),
        "no authData"
    );
    assert!(
        matches!(resp_key(&r, 3), Some(Value::Bytes(_))),
        "no signature"
    );
    assert!(
        matches!(resp_key(&r, 4), Some(Value::Map(_))),
        "no user handle"
    );
}

#[test]
fn assertion_auth_data_omits_the_attested_credential() {
    // An assertion is 37 bytes of authData: hash, flags, counter. The AT
    // block belongs to registration only, and including it would make
    // every assertion carry the public key again.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    let ad = auth_data(&d.ga(&Ga::new()));
    assert_eq!(
        ad.len(),
        37,
        "assertion authData is {} bytes, not 37",
        ad.len()
    );
    assert_eq!(
        flags(&ad) & FLAG_AT,
        0,
        "an assertion carried attested credential data"
    );
    assert_ne!(
        flags(&ad) & FLAG_UP,
        0,
        "the UP flag is clear on a confirmed assertion"
    );
    assert_eq!(&ad[..32], &fw::bc_crypto::sha256(RP.as_bytes())[..]);
}

#[test]
fn the_signature_counter_advances_with_every_assertion() {
    // A relying party watching this counter go backwards concludes the
    // token has been cloned. It must be strictly increasing.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    let mut last = 0u32;
    for i in 0..4 {
        let ad = auth_data(&d.ga(&Ga::new()));
        let c = sign_count(&ad);
        assert!(c > last, "assertion {i}: counter went {last} -> {c}");
        last = c;
    }
}

#[test]
fn a_discoverable_credential_counts_up_from_its_registration() {
    // The slot starts at the counter the registration reported, so the
    // first assertion must already be ahead of it.
    let mut d = Device::new();
    let reg = auth_data(&d.mc(&Mc::new().rk()));
    let first = auth_data(&d.ga(&Ga::new()));
    assert!(
        sign_count(&first) > sign_count(&reg),
        "registration reported {} and the first assertion {}",
        sign_count(&reg),
        sign_count(&first)
    );
}

#[test]
fn a_non_discoverable_credential_keeps_no_counter_from_registration_on() {
    // Without a flash slot there is nothing to count with, so every
    // assertion signs with 0. Registration must report 0 as well: a 1 at
    // registration followed by 0 at login looks, to a relying party, like
    // a counter going backwards -- the WebAuthn cloned-key signal -- and a
    // strict RP refuses the login (the project's relying party does).
    let mut d = Device::new();
    let reg = auth_data(&d.mc(&Mc::new()));
    assert_eq!(
        sign_count(&reg),
        0,
        "registration reported counter {}",
        sign_count(&reg)
    );
    let id = credential_id(&reg);
    for i in 0..3 {
        let ad = auth_data(&d.ga(&Ga::new().allow(&[id.clone()])));
        assert_eq!(
            sign_count(&ad),
            0,
            "assertion {i}: counter {}",
            sign_count(&ad)
        );
    }
}

#[test]
fn user_verification_flag_is_clear_when_no_pin_was_presented() {
    // An RP trusting the UV bit skips its own second factor. Setting it
    // on a touch alone would be a silent downgrade.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    let ad = auth_data(&d.ga(&Ga::new()));
    assert_eq!(flags(&ad) & FLAG_UV, 0, "the UV flag was set without a PIN");
}

#[test]
fn get_next_assertion_without_a_preceding_one_is_refused() {
    // It reads an iterator the previous GetAssertion left behind. With
    // no iterator there is nothing to advance, and CTAP 2.1 sec. 6.3 says
    // so explicitly.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    let r = d.send_with(CTAP2_GET_NEXT_ASSERTION, &Value::Map(vec![]), true);
    assert_eq!(r[0], ERR_NOT_ALLOWED);
}

#[test]
fn get_next_assertion_is_refused_after_a_single_credential_assertion() {
    // One match means the iterator is exhausted by the first response.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    assert_eq!(d.ga(&Ga::new())[0], CTAP2_OK);
    let r = d.send_with(CTAP2_GET_NEXT_ASSERTION, &Value::Map(vec![]), true);
    assert_eq!(
        r[0], ERR_NOT_ALLOWED,
        "GetNextAssertion answered with only one credential"
    );
}

// ---- credProtect, enforced -------------------------------------------

#[test]
fn a_uv_required_credential_is_not_discoverable_without_uv() {
    // credProtect 3 is the level an RP picks when the credential alone
    // must not be usable. With no PIN set there is no way to satisfy it,
    // so the credential has to stay invisible rather than answer.
    let mut d = Device::new();
    d.register(&Mc::new().rk().ext("credProtect", Value::Uint(3)));
    assert_eq!(
        d.ga(&Ga::new())[0],
        ERR_NO_CREDENTIALS,
        "a userVerificationRequired credential answered without UV"
    );
}

#[test]
fn a_list_protected_credential_needs_its_id_supplied() {
    // credProtect 2: discoverable only when the platform names it, or
    // after UV. Answering a bare rpId query would leak that an account
    // exists at this RP to anything that can reach the token.
    let mut d = Device::new();
    let id = d.register(&Mc::new().rk().ext("credProtect", Value::Uint(2)));
    assert_eq!(
        d.ga(&Ga::new())[0],
        ERR_NO_CREDENTIALS,
        "a list-protected credential answered a bare rpId query"
    );
    assert_eq!(
        d.ga(&Ga::new().allow(&[id]))[0],
        CTAP2_OK,
        "a list-protected credential did not answer when named"
    );
}

#[test]
fn the_default_protection_level_stays_discoverable() {
    // The complement of the two above: without the extension, a passkey
    // has to be found by rpId alone or no browser can use it.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    assert_eq!(d.ga(&Ga::new())[0], CTAP2_OK);
}

// ---- register then assert --------------------------------------------

#[test]
fn a_registration_and_its_assertion_agree_on_the_credential() {
    // The end-to-end shape: what MakeCredential handed out is what
    // GetAssertion names in its credential descriptor. A mismatch means
    // the RP cannot tie the assertion to the key it stored.
    let mut d = Device::new();
    let id = d.register(&Mc::new().rk());
    let r = d.ga(&Ga::new());
    assert_eq!(r[0], CTAP2_OK);
    let named = match resp_key(&r, 1).expect("no credential descriptor") {
        Value::Map(m) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Text(s), Value::Bytes(b)) if s == "id" => Some(b.clone()),
                _ => None,
            })
            .expect("the credential descriptor has no id"),
        other => panic!("credential descriptor is {other:?}"),
    };
    assert_eq!(named, id, "the assertion named a different credential");
}

#[test]
fn a_composite_registration_can_be_asserted() {
    // Shape only -- the signature is stubbed. What this proves is that
    // the hybrid path stores enough to come back for, which is where the
    // ML-DSA seed handling would break first.
    let mut d = Device::new();
    let id = d.register(&Mc::new().rk().algs(&[fw::mldsa_alg::COSE_ALG_HYBRID_MLDSA]));
    let r = d.ga(&Ga::new().allow(&[id]));
    assert_eq!(
        r[0], CTAP2_OK,
        "a composite credential could not be asserted"
    );
    match resp_key(&r, 3) {
        Some(Value::Bytes(sig)) => assert!(
            sig.len() > 128,
            "the composite assertion signature is {} bytes -- too short to be hybrid",
            sig.len()
        ),
        other => panic!("no signature in the assertion: {other:?}"),
    }
}

// ---------- allowList: present, but not an array ----------
//
// b38a558 made `allow_list_present` track the parameter rather than the
// entries that survived parsing, which closed the array-of-garbage case.
// It left this one open: a key 0x03 that is not an array at all still
// read as absent, and the request still fell into discoverable-credential
// selection. Same wrong-account substitution the commit describes, one
// CBOR major type over -- on a token holding passkeys for two accounts
// at one site, it silently switched which account authenticated.
//
// The C port had the identical hole; both are fixed.

const ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;

/// A GetAssertion whose allowList is `v`, whatever `v` is.
fn ga_allow_raw(v: Value) -> Value {
    Value::Map(vec![
        (Value::Uint(1), t(RP)),
        (Value::Uint(2), Value::Bytes(vec![0x22; 32])),
        (Value::Uint(3), v),
    ])
}

#[test]
fn an_allow_list_that_is_not_an_array_is_refused_rather_than_ignored() {
    let mut d = Device::new();
    // A discoverable credential exists, so "read as absent" has
    // something to wrongly hand back -- without this the test would
    // pass on NO_CREDENTIALS and prove nothing.
    d.register(&Mc::new().rk());

    for (name, v) in [
        ("a text string", t("x")),
        ("a byte string", Value::Bytes(vec![1, 2, 3])),
        ("an integer", Value::Uint(4)),
        (
            "a map",
            Value::Map(vec![(t("id"), Value::Bytes(vec![7; 64]))]),
        ),
    ] {
        let resp = d.send_with(CTAP2_GET_ASSERTION, &ga_allow_raw(v), true);
        assert_eq!(
            resp[0], ERR_CBOR_UNEXPECTED_TYPE,
            "an allowList that is {name} gave {:#04x}",
            resp[0]
        );
    }
}

#[test]
fn a_malformed_allow_list_does_not_sign_with_a_discoverable_credential() {
    // The consequence, stated as itself. The relying party named a
    // credential; if the token cannot read the list it must not answer
    // with a different account.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    let resp = d.send_with(CTAP2_GET_ASSERTION, &ga_allow_raw(t("not-a-list")), true);
    assert_ne!(
        resp[0], CTAP2_OK,
        "the token signed despite an unreadable allowList"
    );
    assert!(
        auth_data_opt(&resp).is_none(),
        "an assertion was returned for a request whose allowList was unreadable"
    );
}

#[test]
fn an_empty_allow_list_still_reaches_discovery() {
    // The accept half: `[]` is the one non-absent value that means
    // discovery, and refusing it would break clients that send it.
    let mut d = Device::new();
    d.register(&Mc::new().rk());
    let resp = d.send_with(
        CTAP2_GET_ASSERTION,
        &ga_allow_raw(Value::Array(vec![])),
        true,
    );
    assert_eq!(
        resp[0], CTAP2_OK,
        "an empty allowList was refused instead of falling through to discovery"
    );
}

#[test]
fn a_well_formed_allow_list_is_unaffected() {
    let mut d = Device::new();
    let id = d.register(&Mc::new().rk());
    let resp = d.ga(&Ga::new().allow(&[id]));
    assert_eq!(resp[0], CTAP2_OK, "a good allowList stopped working");
}

/// `auth_data` but tolerant of an error response.
fn auth_data_opt(resp: &[u8]) -> Option<Vec<u8>> {
    if resp.first() != Some(&CTAP2_OK) {
        return None;
    }
    Some(auth_data(resp))
}

// ---------- a COSE alg that does not fit i64 ----------

#[test]
fn a_pub_key_cred_param_alg_above_i64_max_is_not_an_algorithm() {
    // `*u as i64` wrapped: 2^64 - 7 came out as -7 and minted ES256 for an
    // algorithm the relying party never named. The mirror of the C port's
    // `(int)` cast. A Uint outside i64 is nobody's algorithm and the list
    // must read as "nothing we support".
    let mut d = Device::new();
    for bad in [u64::MAX - 6, u64::MAX, (i64::MAX as u64) + 1] {
        let req = Value::Map(vec![
            (Value::Uint(1), Value::Bytes(vec![0x11; 32])),
            (Value::Uint(2), Value::Map(vec![(t("id"), t(RP))])),
            (
                Value::Uint(3),
                Value::Map(vec![(t("id"), Value::Bytes(vec![1, 2, 3, 4]))]),
            ),
            (
                Value::Uint(4),
                Value::Array(vec![Value::Map(vec![
                    (t("alg"), Value::Uint(bad)),
                    (t("type"), t("public-key")),
                ])]),
            ),
        ]);
        let resp = d.send_with(CTAP2_MAKE_CREDENTIAL, &req, true);
        assert_eq!(
            resp[0], ERR_UNSUPPORTED_ALGORITHM,
            "alg {bad} was accepted as an algorithm (status {:#04x})",
            resp[0]
        );
    }
}

// ---------- GetNextAssertion inherits the originating UP flag ----------

#[test]
fn get_next_assertion_after_a_silent_get_assertion_does_not_claim_presence() {
    // A silent GetAssertion (`up: false`, CTAP 2.1 sec. 6.2) clears the UP
    // flag in its own authData. The GetNextAssertions that continue it
    // sign the same ceremony and must say the same thing. This port
    // hard-coded UP on every GetNextAssertion, so with two resident
    // credentials the second one's assertion claimed a presence test that
    // never happened. The C port has carried the flag all along.
    let mut d = Device::new();
    d.register(&Mc::new().rk().user(&[1]));
    d.register(&Mc::new().rk().user(&[2]));

    let first = d.ga(&Ga::new().opt("up", Value::Bool(false)));
    assert_eq!(
        first[0], CTAP2_OK,
        "silent GetAssertion refused: {:#04x}",
        first[0]
    );
    assert_eq!(
        flags(&auth_data(&first)) & FLAG_UP,
        0,
        "the silent GetAssertion set UP"
    );

    let next = d.send_with(CTAP2_GET_NEXT_ASSERTION, &Value::Map(vec![]), true);
    assert_eq!(
        next[0], CTAP2_OK,
        "GetNextAssertion refused: {:#04x}",
        next[0]
    );
    assert_eq!(
        flags(&auth_data(&next)) & FLAG_UP,
        0,
        "GetNextAssertion claimed user presence after a silent GetAssertion"
    );
}

#[test]
fn get_next_assertion_after_a_normal_get_assertion_still_claims_presence() {
    // The accept half: an ordinary ceremony asserted presence, and so do
    // its continuations.
    let mut d = Device::new();
    d.register(&Mc::new().rk().user(&[1]));
    d.register(&Mc::new().rk().user(&[2]));
    let first = d.ga(&Ga::new());
    assert_eq!(first[0], CTAP2_OK);
    assert_ne!(flags(&auth_data(&first)) & FLAG_UP, 0);
    let next = d.send_with(CTAP2_GET_NEXT_ASSERTION, &Value::Map(vec![]), true);
    assert_eq!(next[0], CTAP2_OK);
    assert_ne!(
        flags(&auth_data(&next)) & FLAG_UP,
        0,
        "GetNextAssertion dropped UP"
    );
}

// ---------- authenticatorReset needs a touch ----------

#[test]
fn reset_without_user_presence_is_refused_and_wipes_nothing() {
    // CTAP 2.1 sec. 6.6. Reset takes no PIN and no token; the touch is the
    // only thing standing between a plugged-in authenticator and an empty
    // one, and this port wiped on request from any software.
    let mut d = Device::new();
    let id = d.register(&Mc::new().rk());
    let r = d.send_with(fw::ctap2::CTAP2_RESET_CMD, &Value::Map(vec![]), false);
    assert_ne!(r[0], CTAP2_OK, "reset succeeded with no user presence");
    // The credential must still be there and still assert.
    let resp = d.ga(&Ga::new().allow(&[id]));
    assert_eq!(
        resp[0], CTAP2_OK,
        "a refused reset still wiped the credential"
    );
}

#[test]
fn reset_with_user_presence_still_wipes() {
    // The accept half, so the gate cannot pass by refusing everything.
    let mut d = Device::new();
    let id = d.register(&Mc::new().rk());
    let r = d.send_with(fw::ctap2::CTAP2_RESET_CMD, &Value::Map(vec![]), true);
    assert_eq!(
        r[0], CTAP2_OK,
        "reset with presence was refused: {:#04x}",
        r[0]
    );
    let resp = d.ga(&Ga::new().allow(&[id]));
    assert_ne!(
        resp[0], CTAP2_OK,
        "the credential survived a completed reset"
    );
}

// ---------- the assertion iterator does not survive other commands ----------

#[test]
fn get_next_assertion_is_refused_after_an_intervening_command() {
    // sec. 6.3: the iterator is the immediate successor of its GetAssertion.
    // It used to survive anything that was not itself a GetAssertion, so
    // a credential deleted between the two left the iterator pointing at
    // a store that had changed underneath it.
    let mut d = Device::new();
    d.register(&Mc::new().rk().user(&[1]));
    d.register(&Mc::new().rk().user(&[2]));
    assert_eq!(d.ga(&Ga::new())[0], CTAP2_OK);
    // Any other command -- getInfo is the most innocent one there is.
    let _ = d.send_with(fw::ctap2::CTAP2_GET_INFO, &Value::Map(vec![]), true);
    let r = d.send_with(CTAP2_GET_NEXT_ASSERTION, &Value::Map(vec![]), true);
    assert_eq!(
        r[0], ERR_NOT_ALLOWED,
        "the iterator survived an intervening command"
    );
}

#[test]
fn get_next_assertion_directly_after_get_assertion_still_works() {
    let mut d = Device::new();
    d.register(&Mc::new().rk().user(&[1]));
    d.register(&Mc::new().rk().user(&[2]));
    assert_eq!(d.ga(&Ga::new())[0], CTAP2_OK);
    let r = d.send_with(CTAP2_GET_NEXT_ASSERTION, &Value::Map(vec![]), true);
    assert_eq!(r[0], CTAP2_OK, "the immediate GetNextAssertion was refused");
}

// ---------- a GetAssertion that fails arms no continuation ----------
//
// GetAssertion armed the GetNextAssertion iterator at discovery -- before
// the presence gate and before the signature -- with UP copied from the
// request. A touch that timed out answered OPERATION_DENIED and left the
// iterator behind, and the dispatcher clears it only for a command that
// is not GetNextAssertion. So a GetNextAssertion sent straight after, on
// the same channel, signed the next credential with UP set (and UV, if
// the request carried a verified PIN) although nobody touched the token.
// The C port had the same shape; see c/firmware/test/test_ctap2.c.

/// The credential a GetAssertion or GetNextAssertion response names.
fn named_credential(resp: &[u8]) -> Vec<u8> {
    match resp_key(resp, 1).expect("no credential descriptor") {
        Value::Map(m) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Text(s), Value::Bytes(b)) if s == "id" => Some(b.clone()),
                _ => None,
            })
            .expect("the credential descriptor has no id"),
        other => panic!("credential descriptor is {other:?}"),
    }
}

/// The user name a response releases in its user entity (0x04), if any.
fn released_name(resp: &[u8]) -> Option<String> {
    match resp_key(resp, 4)? {
        Value::Map(m) => m.iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(key), Value::Text(s)) if key == "name" => Some(s.clone()),
            _ => None,
        }),
        _ => None,
    }
}

/// Two discoverable credentials at `RP`, one per user.
fn two_accounts(d: &mut Device, alg: i64) {
    d.register(&Mc::new().rk().user(&[1]).algs(&[alg]));
    d.register(&Mc::new().rk().user(&[2]).algs(&[alg]));
}

/// Set the PIN and mint a getAssertion token scoped to `RP`. Called
/// after registering: with a PIN set, a discoverable registration would
/// need a token of its own.
fn pin_token(d: &mut Device) -> Vec<u8> {
    fw::testclient::authenticate(
        &mut d.trng,
        &mut d.session,
        &mut d.store,
        fw::testclient::TEST_PIN,
        fw::client_pin::PERM_GET_ASSERTION as u64,
        Some(RP),
    )
}

/// "Refused, and nothing was signed", with the flags of whatever was
/// signed in the message when it was not.
fn assert_refused(resp: &[u8], what: &str) {
    assert_eq!(
        resp[0],
        ERR_NOT_ALLOWED,
        "{what}: GetNextAssertion answered {:#04x}, authData flags {:?}",
        resp[0],
        auth_data_opt(resp).map(|ad| flags(&ad))
    );
}

#[test]
fn get_next_assertion_is_refused_after_a_refused_gesture() {
    let mut d = Device::new();
    two_accounts(&mut d, ES256);
    let r = d.send_with(CTAP2_GET_ASSERTION, &Ga::new().build(), false);
    assert_eq!(
        r[0],
        ctap2::CTAP2_ERR_OPERATION_DENIED,
        "no touch answered {:#04x}",
        r[0]
    );
    assert_refused(&d.next(), "after a GetAssertion nobody touched for");
}

#[test]
fn a_verified_pin_does_not_stand_in_for_a_refused_gesture() {
    // The worst case: several accounts, the PIN verified, the touch not
    // given. UV is a check that completed and UP is one that did not; a
    // continuation carrying either signs an assertion the user never
    // approved.
    let mut d = Device::new();
    two_accounts(&mut d, ES256);
    let token = pin_token(&mut d);
    let req = Ga::new().pin_auth(&token).build();
    let r = d.send_with(CTAP2_GET_ASSERTION, &req, false);
    assert_eq!(
        r[0],
        ctap2::CTAP2_ERR_OPERATION_DENIED,
        "no touch answered {:#04x}",
        r[0]
    );
    assert_refused(
        &d.next(),
        "after a PIN-verified GetAssertion nobody touched for",
    );
}

#[test]
fn get_next_assertion_is_refused_after_a_cancelled_sign() {
    // The touch was given, then the platform sent CTAPHID_CANCEL during
    // the hybrid sign. KEEPALIVE_CANCEL says no assertion was produced,
    // so there is nothing to continue.
    let mut d = Device::new();
    two_accounts(&mut d, fw::mldsa_alg::COSE_ALG_HYBRID_MLDSA);
    // Keep the sign busy for one poll, so the wait loop pumps the host
    // once -- and the host answers that pump with the cancel.
    fw::core1_signer::CORE1_SIGNER.hold_next_result(1);
    let mut cancel_during_sign = |op: HostOp| !matches!(op, HostOp::Pump);
    let r = d.send_at(
        CTAP2_GET_ASSERTION,
        &Ga::new().build(),
        0,
        CID,
        &mut cancel_during_sign,
    );
    assert_eq!(
        r[0],
        ctap2::CTAP2_ERR_KEEPALIVE_CANCEL,
        "the cancel answered {:#04x}",
        r[0]
    );
    assert_refused(&d.next(), "after a cancelled GetAssertion");

    // Not sticky: the ceremony simply runs again.
    assert_eq!(
        d.ga(&Ga::new())[0],
        CTAP2_OK,
        "a GetAssertion after the cancel failed"
    );
    assert_eq!(d.next()[0], CTAP2_OK, "and its continuation was refused");
}

#[test]
fn get_next_assertion_is_refused_after_a_failed_sign() {
    // Core 1 failing the sign (a panic, the shared heap running out)
    // still answers OK, with an empty signature the relying party will
    // reject -- see `opensk_hybrid_sign`. That reply must neither promise
    // a second account nor leave a continuation that would sign one.
    let mut d = Device::new();
    two_accounts(&mut d, fw::mldsa_alg::COSE_ALG_HYBRID_MLDSA);
    fw::core1_signer::CORE1_SIGNER.fail_next_submit();
    let r = d.ga(&Ga::new());
    let next = d.next();
    assert!(
        resp_key(&r, 3).map_or(true, |s| s == Value::Bytes(vec![])),
        "a failed sign still produced a signature"
    );
    assert_refused(&next, "after a GetAssertion whose sign failed");
    assert_eq!(
        resp_key(&r, 5),
        None,
        "a failed assertion advertised numberOfCredentials"
    );
}

#[test]
fn a_confirmed_assertion_still_continues_through_every_account() {
    // The accept half of all of the above, end to end: the count, the
    // names a chooser shows, UP on every assertion, newest first
    // (CTAP 2.1 sec. 6.2.2), and a clean end.
    let mut d = Device::new();
    let ids: Vec<Vec<u8>> = (1..=3u8)
        .map(|u| d.register(&Mc::new().rk().user(&[u]).named(&format!("user-{u}"))))
        .collect();
    let first = d.ga(&Ga::new());
    assert_eq!(
        first[0], CTAP2_OK,
        "GetAssertion refused: {:#04x}",
        first[0]
    );
    assert_eq!(
        resp_key(&first, 5),
        Some(Value::Uint(3)),
        "numberOfCredentials is not 3"
    );
    assert_ne!(
        flags(&auth_data(&first)) & FLAG_UP,
        0,
        "the first assertion lacks UP"
    );
    assert_eq!(
        released_name(&first).as_deref(),
        Some("user-3"),
        "the first of three accounts came back without its name"
    );
    let mut seen = vec![named_credential(&first)];
    for i in 1..3 {
        let next = d.next();
        assert_eq!(
            next[0], CTAP2_OK,
            "GetNextAssertion {i} refused: {:#04x}",
            next[0]
        );
        assert_ne!(
            flags(&auth_data(&next)) & FLAG_UP,
            0,
            "GetNextAssertion {i} dropped UP"
        );
        assert_eq!(
            resp_key(&next, 5),
            None,
            "GetNextAssertion {i} repeated numberOfCredentials"
        );
        assert!(
            released_name(&next).is_some(),
            "GetNextAssertion {i} withheld the name"
        );
        seen.push(named_credential(&next));
    }
    let newest_first: Vec<Vec<u8>> = ids.iter().rev().cloned().collect();
    assert_eq!(
        seen, newest_first,
        "the accounts came back out of order or repeated"
    );
    assert_refused(&d.next(), "past the last account");
}

#[test]
fn a_continuation_reports_the_user_verification_that_happened() {
    // UV on a GetNextAssertion is inherited, so it has to be the value
    // the GetAssertion verified: set after a checked PIN, clear without.
    let mut d = Device::new();
    two_accounts(&mut d, ES256);
    let token = pin_token(&mut d);
    let both = FLAG_UP | FLAG_UV;

    let first = d.ga(&Ga::new().pin_auth(&token));
    assert_eq!(
        first[0], CTAP2_OK,
        "PIN-verified GetAssertion refused: {:#04x}",
        first[0]
    );
    assert_eq!(
        flags(&auth_data(&first)) & both,
        both,
        "the PIN-verified assertion lacks UP|UV"
    );
    let next = d.next();
    assert_eq!(
        next[0], CTAP2_OK,
        "its GetNextAssertion refused: {:#04x}",
        next[0]
    );
    assert_eq!(
        flags(&auth_data(&next)) & both,
        both,
        "the continuation lost UP or UV"
    );

    let first = d.ga(&Ga::new());
    assert_eq!(first[0], CTAP2_OK);
    let next = d.next();
    assert_eq!(next[0], CTAP2_OK);
    assert_eq!(
        flags(&auth_data(&next)) & FLAG_UV,
        0,
        "a continuation claimed a PIN the GetAssertion never presented"
    );
}

#[test]
fn a_silent_assertion_never_asks_for_presence_and_its_continuation_says_so() {
    // up=false: the gate does not run, so no presence was established and
    // none may be reported -- whatever the host would have answered had it
    // been asked. This one refuses, and counts how often it is asked.
    let mut d = Device::new();
    two_accounts(&mut d, ES256);
    let mut asked = 0u32;
    let mut refusing = |op: HostOp| match op {
        HostOp::WaitForUp { .. } => {
            asked += 1;
            false
        }
        HostOp::Pump => true,
    };
    let silent = Ga::new().opt("up", Value::Bool(false)).build();
    let first = d.send_at(CTAP2_GET_ASSERTION, &silent, 0, CID, &mut refusing);
    assert_eq!(
        first[0], CTAP2_OK,
        "silent GetAssertion refused: {:#04x}",
        first[0]
    );
    assert_eq!(
        flags(&auth_data(&first)) & FLAG_UP,
        0,
        "the silent GetAssertion set UP"
    );
    let next = d.send_at(
        CTAP2_GET_NEXT_ASSERTION,
        &Value::Map(vec![]),
        0,
        CID,
        &mut refusing,
    );
    assert_eq!(
        next[0], CTAP2_OK,
        "its GetNextAssertion refused: {:#04x}",
        next[0]
    );
    assert_eq!(
        flags(&auth_data(&next)) & FLAG_UP,
        0,
        "the continuation claimed presence"
    );
    assert_eq!(asked, 0, "a silent ceremony asked for a touch");
}

#[test]
fn get_next_assertion_from_another_channel_is_refused_and_ends_the_ceremony() {
    // The iterator belongs to the channel that ran the GetAssertion: a
    // second host process must not drive, or read, another one's account
    // picker. A foreign attempt drops the ceremony, as in the C port.
    let other = [0, 0, 0, 2];
    let mut d = Device::new();
    two_accounts(&mut d, ES256);
    assert_eq!(d.ga(&Ga::new())[0], CTAP2_OK);
    let empty = Value::Map(vec![]);
    let foreign = d.send_at(
        CTAP2_GET_NEXT_ASSERTION,
        &empty,
        0,
        other,
        &mut |_op: HostOp| true,
    );
    assert_refused(&foreign, "from another channel");
    assert_refused(&d.next(), "on the owning channel after a foreign attempt");

    assert_eq!(d.ga(&Ga::new())[0], CTAP2_OK);
    assert_eq!(
        d.next()[0],
        CTAP2_OK,
        "the owning channel could not continue its own ceremony"
    );
}

#[test]
fn get_next_assertion_expires_thirty_seconds_after_the_last_reply() {
    // CTAP 2.1 sec. 6.3's stateful-command window, counted as OpenSK does:
    // 30 s, restarted by every reply.
    let mut d = Device::new();
    for u in 1..=3u8 {
        d.register(&Mc::new().rk().user(&[u]));
    }
    let (ga, empty) = (Ga::new().build(), Value::Map(vec![]));
    let mut yes = |_op: HostOp| true;
    let s = 1_000_000u64;

    // 45 s is past the GetAssertion's own deadline, but inside the one
    // the reply at 20 s set.
    assert_eq!(
        d.send_at(CTAP2_GET_ASSERTION, &ga, 0, CID, &mut yes)[0],
        CTAP2_OK
    );
    let r = d.send_at(CTAP2_GET_NEXT_ASSERTION, &empty, 20 * s, CID, &mut yes);
    assert_eq!(r[0], CTAP2_OK, "refused 20 s in: {:#04x}", r[0]);
    let r = d.send_at(CTAP2_GET_NEXT_ASSERTION, &empty, 45 * s, CID, &mut yes);
    assert_eq!(
        r[0], CTAP2_OK,
        "the reply at 20 s did not restart the window: {:#04x}",
        r[0]
    );

    // And 30 s with no reply ends it.
    assert_eq!(
        d.send_at(CTAP2_GET_ASSERTION, &ga, 100 * s, CID, &mut yes)[0],
        CTAP2_OK
    );
    let late = d.send_at(CTAP2_GET_NEXT_ASSERTION, &empty, 130 * s, CID, &mut yes);
    assert_refused(&late, "30 s after the GetAssertion");
}
