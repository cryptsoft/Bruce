// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 (-8), the one algorithm path verifiable on the host.
//!
//! Everywhere else in this harness the signing is stubbed and the tests
//! can only assert *shape* -- a signature of the right length, in the
//! right place. Here `ed25519_dalek` is the real implementation, so a
//! signature made in this file can actually be checked. That makes this
//! the only suite that says anything about correctness rather than
//! plumbing, and it is worth using that for what it is good for:
//! verification, determinism, and the exact bytes a relying party will
//! parse.
//!
//! Off by default, like the firmware feature. ~30 KiB of flash from the
//! curve25519-dalek backend is why.

#![cfg(feature = "ed25519")]

use pqf_cbor::Value;
use pqf_firmware_hosttest as fw;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use fw::ed25519_alg as ed;
use fw::trng::Trng;

fn seed_of(byte: u8) -> [u8; 32] {
    [byte; 32]
}

// ---- the part only this suite can do: actually verify ----------------

#[test]
fn a_signature_verifies_under_the_derived_public_key() {
    // The whole chain in one check: derive a public key from a seed,
    // sign with the same seed, and verify with a *separately
    // constructed* verifier. If the derivation and the signing ever
    // disagreed about which key they were using, every credential this
    // algorithm mints would be unverifiable by the relying party -- and
    // nothing else in this harness could tell you.
    let seed = seed_of(0x42);
    let public = ed::derive_public_bytes(&seed);
    let msg = b"authenticatorData || clientDataHash";
    let sig = ed::sign_with_seed(&seed, msg);

    let vk = VerifyingKey::from_bytes(&public).expect("the derived key is a valid point");
    let signature = Signature::from_bytes(&sig);
    vk.verify(msg, &signature)
        .expect("a signature did not verify under the key derived from the same seed");
}

#[test]
fn a_signature_does_not_verify_under_another_key() {
    // The complement. A verifier that accepts anything is not a
    // verifier, and a test that only ever checks the happy path cannot
    // tell the difference.
    let msg = b"message";
    let sig = ed::sign_with_seed(&seed_of(1), msg);
    let other = ed::derive_public_bytes(&seed_of(2));

    let vk = VerifyingKey::from_bytes(&other).unwrap();
    assert!(
        vk.verify(msg, &Signature::from_bytes(&sig)).is_err(),
        "a signature verified under a key it was not made with"
    );
}

#[test]
fn a_tampered_message_does_not_verify() {
    let seed = seed_of(7);
    let public = ed::derive_public_bytes(&seed);
    let vk = VerifyingKey::from_bytes(&public).unwrap();
    let msg = b"the original message";
    let sig = Signature::from_bytes(&ed::sign_with_seed(&seed, msg));

    assert!(
        vk.verify(msg, &sig).is_ok(),
        "setup: the untampered message verifies"
    );
    for flip in [0usize, 5, msg.len() - 1] {
        let mut bad = msg.to_vec();
        bad[flip] ^= 0x01;
        assert!(
            vk.verify(&bad, &sig).is_err(),
            "a message with byte {flip} flipped still verified"
        );
    }
}

#[test]
fn a_tampered_signature_does_not_verify() {
    // Both halves matter: R (the first 32 bytes) and s (the last 32).
    let seed = seed_of(9);
    let vk = VerifyingKey::from_bytes(&ed::derive_public_bytes(&seed)).unwrap();
    let msg = b"message";
    let good = ed::sign_with_seed(&seed, msg);

    for flip in [0usize, 31, 32, 63] {
        let mut bad = good;
        bad[flip] ^= 0x01;
        assert!(
            vk.verify(msg, &Signature::from_bytes(&bad)).is_err(),
            "a signature with byte {flip} flipped still verified"
        );
    }
}

// ---- determinism, which is the property RFC 8032 promises ------------

#[test]
fn signing_is_deterministic() {
    // RFC 8032 sec. 5.1.6: Ed25519 derives its nonce from the private key
    // and the message, with no randomness. Two signatures over the same
    // pair must be identical -- and that is not a curiosity, it is why
    // this algorithm needs no TRNG at signing time and cannot leak a key
    // through a repeated nonce the way ECDSA can.
    let seed = seed_of(0x5a);
    let msg = b"sign me twice";
    assert_eq!(
        ed::sign_with_seed(&seed, msg),
        ed::sign_with_seed(&seed, msg),
        "two signatures over one message differed -- the nonce is not deterministic"
    );
}

#[test]
fn different_messages_give_different_signatures() {
    let seed = seed_of(0x5a);
    assert_ne!(
        ed::sign_with_seed(&seed, b"message one"),
        ed::sign_with_seed(&seed, b"message two"),
        "two different messages produced the same signature"
    );
}

#[test]
fn different_seeds_give_different_keys_and_signatures() {
    let msg = b"same message";
    assert_ne!(
        ed::derive_public_bytes(&seed_of(1)),
        ed::derive_public_bytes(&seed_of(2)),
        "two seeds derived the same public key"
    );
    assert_ne!(
        ed::sign_with_seed(&seed_of(1), msg),
        ed::sign_with_seed(&seed_of(2), msg),
        "two seeds produced the same signature"
    );
}

#[test]
fn public_derivation_is_pure() {
    // No randomness, no state: the same seed must give the same key
    // every time, including across a fresh call sequence. A credential
    // id stores the seed and rebuilds the key on demand, so a
    // derivation that drifted would orphan every credential.
    let seed = seed_of(0x33);
    let first = ed::derive_public_bytes(&seed);
    for _ in 0..8 {
        assert_eq!(
            ed::derive_public_bytes(&seed),
            first,
            "the derivation drifted"
        );
    }
}

#[test]
fn an_all_zero_seed_still_produces_a_usable_key() {
    // Not a realistic seed, but it is the one a zeroed buffer produces,
    // and "the TRNG failed and gave us zeros" must not become "the
    // signature silently does not verify".
    let seed = [0u8; 32];
    let public = ed::derive_public_bytes(&seed);
    assert_ne!(
        public, [0u8; 32],
        "an all-zero seed derived an all-zero key"
    );
    let msg = b"m";
    let vk = VerifyingKey::from_bytes(&public).expect("the key is a valid point");
    vk.verify(msg, &Signature::from_bytes(&ed::sign_with_seed(&seed, msg)))
        .expect("a zero-seed signature did not verify");
}

#[test]
fn an_empty_message_can_be_signed_and_verified() {
    let seed = seed_of(0x11);
    let vk = VerifyingKey::from_bytes(&ed::derive_public_bytes(&seed)).unwrap();
    let sig = ed::sign_with_seed(&seed, b"");
    vk.verify(b"", &Signature::from_bytes(&sig))
        .expect("an empty message did not verify");
}

#[test]
fn a_long_message_can_be_signed_and_verified() {
    // authenticatorData plus a clientDataHash is small, but nothing in
    // the signing path bounds the input and a relying party controls
    // part of it.
    let seed = seed_of(0x22);
    let vk = VerifyingKey::from_bytes(&ed::derive_public_bytes(&seed)).unwrap();
    let msg: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
    let sig = ed::sign_with_seed(&seed, &msg);
    vk.verify(&msg, &Signature::from_bytes(&sig))
        .expect("an 8 KiB message did not verify");
}

// ---- the seed comes from the TRNG ------------------------------------

#[test]
fn generated_seeds_are_not_constant() {
    // The stub TRNG is not the hardware one, so this says nothing about
    // entropy quality. What it does check is that gen_seed actually
    // consumes from the TRNG rather than returning a fixed buffer --
    // which is the failure that would make every token mint the same
    // key.
    let mut trng = Trng::new_for_test();
    let a = ed::gen_seed(&mut trng);
    let b = ed::gen_seed(&mut trng);
    assert_ne!(a, b, "two generated seeds were identical");
    assert_ne!(a, [0u8; 32], "a generated seed was all zeroes");
}

#[test]
fn a_generated_seed_works_end_to_end() {
    let mut trng = Trng::new_for_test();
    let seed = ed::gen_seed(&mut trng);
    let vk = VerifyingKey::from_bytes(&ed::derive_public_bytes(&seed))
        .expect("a generated seed derived an invalid key");
    let msg = b"end to end";
    vk.verify(msg, &Signature::from_bytes(&ed::sign_with_seed(&seed, msg)))
        .expect("a generated seed did not round trip");
}

// ---- the COSE key a relying party parses -----------------------------

/// One entry of the COSE map, by integer label.
fn label(map: &[(Value, Value)], want: i64) -> Option<Value> {
    map.iter().find_map(|(k, v)| match k {
        Value::Uint(n) if *n as i64 == want => Some(v.clone()),
        Value::Nint(n) if *n == want => Some(v.clone()),
        _ => None,
    })
}

#[test]
fn the_cose_key_carries_the_labels_rfc_8152_defines() {
    // A relying party reads these four and nothing else. Every one of
    // them wrong in a different way: the wrong kty sends it to an EC2
    // parser, the wrong alg makes it reject the algorithm outright, the
    // wrong crv makes it verify against the wrong curve, and the wrong
    // x makes every signature fail.
    let public = ed::derive_public_bytes(&seed_of(0x77));
    let key = match ed::cose_key(&public) {
        Value::Map(m) => m,
        other => panic!("cose_key returned {other:?}, not a map"),
    };

    assert_eq!(label(&key, 1), Some(Value::Uint(1)), "kty is not OKP (1)");
    assert_eq!(
        label(&key, 3),
        Some(Value::Nint(-8)),
        "alg is not EdDSA (-8)"
    );
    assert_eq!(
        label(&key, -1),
        Some(Value::Uint(6)),
        "crv is not Ed25519 (6)"
    );
    match label(&key, -2) {
        Some(Value::Bytes(x)) => {
            assert_eq!(x.len(), 32, "x is {} bytes, not 32", x.len());
            assert_eq!(x, public, "x is not the public key it was built from");
        }
        other => panic!("x is {other:?}, not a 32-byte string"),
    }
    assert_eq!(
        key.len(),
        4,
        "the COSE key carries {} entries, not 4",
        key.len()
    );
}

#[test]
fn the_cose_key_round_trips_through_cbor() {
    // It is embedded in authenticatorData and parsed by someone else's
    // decoder, so encoding then decoding must give back what went in.
    let public = ed::derive_public_bytes(&seed_of(0x88));
    let mut buf = Vec::new();
    pqf_cbor::encode(&ed::cose_key(&public), &mut buf);
    assert!(!buf.is_empty(), "the COSE key encoded to nothing");

    let back = pqf_cbor::decode(&buf).expect("the encoded COSE key is not decodable CBOR");
    let m = match back {
        Value::Map(m) => m,
        other => panic!("decoded to {other:?}"),
    };
    match label(&m, -2) {
        Some(Value::Bytes(x)) => assert_eq!(x, public, "x changed across a CBOR round trip"),
        other => panic!("x came back as {other:?}"),
    }
}

#[test]
fn a_verifier_can_be_rebuilt_from_the_cose_key_alone() {
    // The end-to-end shape of what a relying party does: take the COSE
    // key out of authenticatorData, pull x, and verify a later
    // assertion with it. Nothing else in this harness closes that loop.
    let seed = seed_of(0x99);
    let public = ed::derive_public_bytes(&seed);
    let key = match ed::cose_key(&public) {
        Value::Map(m) => m,
        _ => unreachable!(),
    };
    let x = match label(&key, -2) {
        Some(Value::Bytes(b)) => b,
        other => panic!("x is {other:?}"),
    };
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&x);

    let vk = VerifyingKey::from_bytes(&arr).expect("x is not a valid Ed25519 point");
    let msg = b"a later assertion";
    vk.verify(msg, &Signature::from_bytes(&ed::sign_with_seed(&seed, msg)))
        .expect("an assertion did not verify under the key from the COSE blob");
}
