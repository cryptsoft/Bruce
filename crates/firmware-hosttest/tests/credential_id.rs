// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The sealed credential id.
//!
//! Every credential this token mints lives inside its own id, encrypted
//! under a device-wide key: the ECDSA scalar, the ML-DSA seed, the rpId
//! hash, the credProtect policy. The relying party stores that blob and
//! hands it back on every login. So the id is simultaneously the key
//! store, the access-control record, and the only thing an attacker with
//! a stolen credential list has to work with.
//!
//! The C port has proved the tamper property since Phase C-11
//! (`test_domain.c`): *every* single-byte flip of the sealed blob is
//! rejected, not merely one. The Rust port has made no such claim until
//! now, and these two implementations are meant to be at parity.

use pqf_firmware_hosttest as fw;

use fw::credential_id::{
    decrypt_credential_id, derive_cred_random, derive_large_blob_key, encrypt_to_credential_id,
    CredentialSource, DecryptError, COSE_ALG_ES256, COSE_ALG_HYBRID_MLDSA65, CRED_ID_LEN,
};
use fw::trng::Trng;

const AES_KEY: [u8; 32] = [0x11; 32];
const HMAC_KEY: [u8; 32] = [0x22; 32];

fn rp_hash(n: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = n;
    h[31] = 0xa5;
    h
}

fn source(alg: i64, rp: u8) -> CredentialSource {
    CredentialSource {
        alg,
        ecdsa_scalar: core::array::from_fn(|i| (i as u8) ^ 0x3c),
        mldsa_seed: if alg == COSE_ALG_ES256 {
            [0u8; 32]
        } else {
            core::array::from_fn(|i| (i as u8).wrapping_mul(7))
        },
        rp_id_hash: rp_hash(rp),
        cred_protect: 2,
        large_blob_key: true,
    }
}

fn mint(alg: i64, rp: u8) -> [u8; CRED_ID_LEN] {
    let mut trng = Trng::new_for_test();
    encrypt_to_credential_id(&AES_KEY, &HMAC_KEY, &mut trng, &source(alg, rp))
}

// ---- the round trip --------------------------------------------------

#[test]
fn a_credential_survives_the_round_trip_intact() {
    for alg in [COSE_ALG_ES256, COSE_ALG_HYBRID_MLDSA65] {
        let src = source(alg, 1);
        let mut trng = Trng::new_for_test();
        let id = encrypt_to_credential_id(&AES_KEY, &HMAC_KEY, &mut trng, &src);
        let out = decrypt_credential_id(&AES_KEY, &HMAC_KEY, &id, &rp_hash(1))
            .expect("a credential this device minted did not decrypt");
        assert_eq!(out.alg, src.alg, "algorithm changed in transit");
        assert_eq!(
            out.ecdsa_scalar, src.ecdsa_scalar,
            "the ECDSA scalar changed"
        );
        assert_eq!(out.rp_id_hash, src.rp_id_hash);
        assert_eq!(
            out.cred_protect, src.cred_protect,
            "credProtect policy changed"
        );
        assert_eq!(out.large_blob_key, src.large_blob_key);
        if alg != COSE_ALG_ES256 {
            assert_eq!(out.mldsa_seed, src.mldsa_seed, "the ML-DSA seed changed");
        }
    }
}

#[test]
fn the_id_is_the_documented_length_and_version() {
    // 161 bytes is not arbitrary: base64url(161) is 215 characters, and
    // relying parties with a VARCHAR(255) credential_id column exist.
    // Growing this silently breaks them.
    let id = mint(COSE_ALG_HYBRID_MLDSA65, 1);
    assert_eq!(id.len(), 161);
    assert_eq!(CRED_ID_LEN, 161);
    assert_eq!(id[0], 0x01, "version byte");
    let b64_len = 4 * ((CRED_ID_LEN + 2) / 3);
    assert!(
        b64_len <= 255,
        "base64url of a credential id is {b64_len} characters, past the \
         255 an RP database column may allow"
    );
}

// ---- the tamper property, which is the point -------------------------

#[test]
fn every_single_byte_flip_is_rejected() {
    // The claim the C port makes and this one did not. Not "a corrupt id
    // is rejected" -- *every* corruption of *every* byte, which is the
    // difference between a tag that is checked and a tag that is checked
    // over everything.
    let id = mint(COSE_ALG_HYBRID_MLDSA65, 1);
    let rp = rp_hash(1);
    assert!(decrypt_credential_id(&AES_KEY, &HMAC_KEY, &id, &rp).is_ok());

    for byte in 0..CRED_ID_LEN {
        for bit in 0..8u8 {
            let mut bad = id;
            bad[byte] ^= 1 << bit;
            let r = decrypt_credential_id(&AES_KEY, &HMAC_KEY, &bad, &rp);
            assert!(
                r.is_err(),
                "flipping bit {bit} of byte {byte} produced a credential the \
                 device accepted"
            );
        }
    }
}

#[test]
fn truncation_and_extension_are_rejected() {
    let id = mint(COSE_ALG_ES256, 1);
    let rp = rp_hash(1);
    for len in [0usize, 1, 32, CRED_ID_LEN - 1] {
        assert!(
            matches!(
                decrypt_credential_id(&AES_KEY, &HMAC_KEY, &id[..len], &rp),
                Err(DecryptError::BadFormat)
            ),
            "a {len}-byte credential id was not rejected as malformed"
        );
    }
    let mut longer = id.to_vec();
    longer.push(0);
    assert!(
        matches!(
            decrypt_credential_id(&AES_KEY, &HMAC_KEY, &longer, &rp),
            Err(DecryptError::BadFormat)
        ),
        "an over-long credential id was accepted"
    );
}

#[test]
fn a_credential_from_another_device_is_rejected() {
    // Different master keys: the whole point of sealing under a
    // device-wide key is that one token's credentials are useless to
    // another.
    let id = mint(COSE_ALG_HYBRID_MLDSA65, 1);
    let rp = rp_hash(1);
    let other_aes = [0x99u8; 32];
    let other_hmac = [0x88u8; 32];

    assert!(
        matches!(
            decrypt_credential_id(&other_aes, &HMAC_KEY, &id, &rp),
            Err(DecryptError::RpMismatch) | Err(DecryptError::BadFormat)
        ) || decrypt_credential_id(&other_aes, &HMAC_KEY, &id, &rp).is_err(),
        "a different AES key still yielded a usable credential"
    );
    assert!(
        matches!(
            decrypt_credential_id(&AES_KEY, &other_hmac, &id, &rp),
            Err(DecryptError::BadHmac)
        ),
        "a different HMAC key did not fail the integrity check"
    );
}

// ---- cross-RP replay -------------------------------------------------

#[test]
fn a_credential_is_refused_at_a_different_relying_party() {
    // Even with a perfectly valid HMAC. This is the guard that stops
    // evil.example replaying a credential it was handed for
    // bank.example -- and the rpId hash lives *inside* the sealed
    // plaintext precisely so it cannot be edited.
    let id = mint(COSE_ALG_HYBRID_MLDSA65, 1);
    assert!(decrypt_credential_id(&AES_KEY, &HMAC_KEY, &id, &rp_hash(1)).is_ok());
    assert!(
        matches!(
            decrypt_credential_id(&AES_KEY, &HMAC_KEY, &id, &rp_hash(2)),
            Err(DecryptError::RpMismatch)
        ),
        "a credential minted for one RP was accepted at another"
    );
}

#[test]
fn the_rp_hash_cannot_be_edited_without_failing_the_tag() {
    // Belt and braces on the above: an attacker who knows the format
    // cannot simply overwrite the rpId hash region, because the HMAC
    // covers the ciphertext and the plaintext is encrypted.
    let id = mint(COSE_ALG_ES256, 1);
    for off in 17..129 {
        let mut bad = id;
        bad[off] ^= 0xff;
        assert!(
            decrypt_credential_id(&AES_KEY, &HMAC_KEY, &bad, &rp_hash(1)).is_err(),
            "editing ciphertext byte {off} produced an accepted credential"
        );
    }
}

// ---- what distinguishes two credentials ------------------------------

#[test]
fn two_credentials_for_the_same_rp_differ() {
    // Same inputs, different IVs. If two mints produced the same bytes,
    // a relying party could tell that two registrations came from one
    // token, and the id would leak a linkable identifier.
    let mut t1 = Trng::new_for_test();
    let mut t2 = Trng::stuck(0xAB);
    let src = source(COSE_ALG_HYBRID_MLDSA65, 1);
    let a = encrypt_to_credential_id(&AES_KEY, &HMAC_KEY, &mut t1, &src);
    let b = encrypt_to_credential_id(&AES_KEY, &HMAC_KEY, &mut t2, &src);
    assert_ne!(
        a, b,
        "two credentials with different IVs came out identical"
    );
    assert_ne!(&a[1..17], &b[1..17], "the IV is not where the format says");
}

#[test]
fn a_stuck_rng_does_not_stop_a_credential_working() {
    // Not an endorsement of a stuck RNG -- it is a real weakness, and CBC
    // with a repeated IV leaks equality of plaintext prefixes. What this
    // pins is that the *format* does not additionally break: the failure
    // should be confined to what CBC leaks, not a credential that cannot
    // be decrypted at all.
    let mut t = Trng::stuck(0x5A);
    let src = source(COSE_ALG_ES256, 1);
    let id = encrypt_to_credential_id(&AES_KEY, &HMAC_KEY, &mut t, &src);
    let out = decrypt_credential_id(&AES_KEY, &HMAC_KEY, &id, &rp_hash(1))
        .expect("a credential minted with a stuck RNG did not decrypt");
    assert_eq!(out.ecdsa_scalar, src.ecdsa_scalar);
}

#[test]
fn the_es256_case_carries_a_zero_ml_dsa_seed() {
    // The format documents "all-zero iff alg == ES256". A non-zero seed
    // on an ES256 credential would be 32 bytes of something in a field
    // nothing reads.
    let mut t = Trng::new_for_test();
    let src = source(COSE_ALG_ES256, 1);
    let id = encrypt_to_credential_id(&AES_KEY, &HMAC_KEY, &mut t, &src);
    let out = decrypt_credential_id(&AES_KEY, &HMAC_KEY, &id, &rp_hash(1)).unwrap();
    assert_eq!(out.alg, COSE_ALG_ES256);
    assert_eq!(
        out.mldsa_seed, [0u8; 32],
        "an ES256 credential carried a seed"
    );
}

// ---- the derived secrets ---------------------------------------------

#[test]
fn cred_random_is_bound_to_the_credential_and_to_uv() {
    // hmac-secret. Two credentials must not derive the same secret, or
    // one relying party's hmac-secret output would be another's. And the
    // UV and non-UV variants must differ, because CTAP2 treats them as
    // separate secrets.
    let a = mint(COSE_ALG_HYBRID_MLDSA65, 1);
    let b = mint(COSE_ALG_HYBRID_MLDSA65, 2);

    let a_uv = derive_cred_random(&HMAC_KEY, &a, true);
    let a_no = derive_cred_random(&HMAC_KEY, &a, false);
    let b_uv = derive_cred_random(&HMAC_KEY, &b, true);

    assert_ne!(a_uv, a_no, "the UV and non-UV secrets are the same");
    assert_ne!(a_uv, b_uv, "two credentials derive the same cred_random");
    assert_eq!(
        a_uv,
        derive_cred_random(&HMAC_KEY, &a, true),
        "cred_random is not deterministic"
    );
}

#[test]
fn the_large_blob_key_is_separate_from_cred_random() {
    // Both are HMACs under the same key over the same credential id, so
    // the only thing keeping them apart is domain separation. If it were
    // ever dropped, the largeBlobKey would equal a secret the relying
    // party can already obtain through hmac-secret.
    let id = mint(COSE_ALG_HYBRID_MLDSA65, 1);
    let lbk = derive_large_blob_key(&HMAC_KEY, &id);
    assert_ne!(
        lbk,
        derive_cred_random(&HMAC_KEY, &id, true),
        "largeBlobKey equals the UV cred_random -- domain separation is gone"
    );
    assert_ne!(
        lbk,
        derive_cred_random(&HMAC_KEY, &id, false),
        "largeBlobKey equals the non-UV cred_random"
    );
    assert_eq!(
        lbk,
        derive_large_blob_key(&HMAC_KEY, &id),
        "not deterministic"
    );
}

#[test]
fn the_derived_secrets_change_with_the_device_key() {
    // They are device secrets. Two tokens must not derive the same
    // largeBlobKey for the same credential id.
    let id = mint(COSE_ALG_HYBRID_MLDSA65, 1);
    let other = [0x77u8; 32];
    assert_ne!(
        derive_large_blob_key(&HMAC_KEY, &id),
        derive_large_blob_key(&other, &id)
    );
    assert_ne!(
        derive_cred_random(&HMAC_KEY, &id, true),
        derive_cred_random(&other, &id, true)
    );
}

#[test]
fn a_one_bit_change_in_the_id_changes_every_derived_secret() {
    // The derivations take the whole id, so a credential that differed
    // in one bit must not share secrets with the original.
    let id = mint(COSE_ALG_HYBRID_MLDSA65, 1);
    let mut near = id;
    near[100] ^= 0x01;
    assert_ne!(
        derive_cred_random(&HMAC_KEY, &id, true),
        derive_cred_random(&HMAC_KEY, &near, true)
    );
    assert_ne!(
        derive_large_blob_key(&HMAC_KEY, &id),
        derive_large_blob_key(&HMAC_KEY, &near)
    );
}
