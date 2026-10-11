/* hybrid.c -- hybrid ECDSA-P256 + ML-DSA signing.
 *
 * See hybrid.h for the construction. The signed message format (the
 * 32-byte LABEL prefix, the ECDSA-over-SHA-256(LABEL||msg) half, and
 * the ML-DSA-over-(LABEL||msg||ecdsaDER) half) is fixed, so a
 * signature this code produces verifies against the same relying
 * party as one produced by the Rust firmware.
 *
 * The two ports are NOT byte-identical, however. This C port signs the
 * ECDSA half with a HEDGED nonce k -- not a plain random one and not
 * RFC 6979. Signing goes through ECDSA_do_sign() with a non-NULL digest
 * and nonce_type == 0, which selects ossl_bn_gen_dsa_nonce_fixed_top()
 * (ecdsa_ossl.c): a SHA-512 chain over the padded private key, 64 fresh
 * TRNG bytes and the message digest. The ML-DSA half uses rnd = 0^32,
 * the FIPS 204 sec. 5.2 deterministic variant (rho' = SHAKE256(K || 0^32 ||
 * mu)) -- see pqf_mldsa_sign(). The Rust firmware now uses the SAME
 * rnd = 0^32, but still the RFC 6979 deterministic ECDSA nonce.
 *
 * So the two ports STILL emit different signature bytes for the same
 * message, and converging rnd did not change that: mu covers ecdsaDER,
 * so a different ECDSA half changes mu, which changes rho', which
 * changes the ML-DSA half too. Converging k as well is what would make
 * them byte-identical, and that is still open -- it is a real security
 * trade (reproducibility versus fault-attack resistance) rather than
 * the free standardisation win converging rnd was.
 *
 * Neither divergence affects verification: rnd is a signer-only input,
 * not recoverable from and not checked by ML-DSA.Verify, and ECDSA
 * verify never sees k, so either port's signature verifies under the
 * same public key. docs/PROTOCOL.md has the detail.
 *
 * Security note: k varies per CALL rather than per (key, message),
 * because fresh TRNG bytes go into that chain. Hedging means an RNG
 * that is merely weak does not immediately leak the private scalar --
 * the private key and the digest are also in the input -- but an RNG
 * that repeats and a repeated message together still give k reuse, so
 * pqf_rand.c / get_rand_64 is still required to be CSPRNG-grade.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "hybrid.h"
#include "pqf_crypto.h"

/* ---------- Attribution ----------
 * These 32 bytes are reproduced verbatim from the OpenSK PQC fork
 * (`OpenSK/libraries/crypto/src/hybrid.rs::LABEL`), Copyright (c)
 * 2019-2023 Google LLC, licensed under the Apache License, Version
 * 2.0. Full licence text in `LICENSE-APACHE-OPENSK` at the repository
 * root. The Rust firmware carries the identical constant in
 * `crates/firmware/src/core1_signer.rs`; both must match for hybrid
 * signatures to interoperate. */
const uint8_t PQF_HYBRID_LABEL[32] = {
    43, 253, 32, 250, 19, 51, 24, 237, 138, 49, 47, 182, 4, 194, 133, 183,
    177, 218, 115, 58, 92, 117, 45, 172, 156, 5, 214, 176, 248, 103, 55, 216,
};

/* Build LABEL || msg [|| der] into `buf`; returns the total length.
 * Caller sizes buf >= 32 + msg_len + der_len. */
static size_t build_labelled(uint8_t *buf, const uint8_t *msg, size_t msg_len,
                             const uint8_t *der, size_t der_len)
{
    size_t off = 0;
    memcpy(buf + off, PQF_HYBRID_LABEL, 32); off += 32;
    memcpy(buf + off, msg, msg_len);         off += msg_len;
    if (der != NULL && der_len) {
        memcpy(buf + off, der, der_len);     off += der_len;
    }
    return off;
}

int hybrid_public(const uint8_t ecdsa_scalar[32], const uint8_t mldsa_seed[32],
                  uint8_t ec_x[32], uint8_t ec_y[32],
                  uint8_t *mldsa_pub, size_t *mldsa_pub_len)
{
    if (pqf_p256_derive_public(ecdsa_scalar, ec_x, ec_y) != 0)
        return -1;
    if (pqf_mldsa_pub_from_seed(PQF_HYBRID_MLDSA, mldsa_seed,
                                mldsa_pub, mldsa_pub_len) != 0)
        return -1;
    return 0;
}

int hybrid_sign(const uint8_t ecdsa_scalar[32], const uint8_t mldsa_seed[32],
                const uint8_t *msg, size_t msg_len,
                uint8_t *out, size_t *out_len)
{
    /* Buffer for LABEL || msg [|| der]. For a MakeCredential attestation
     * `msg` is authData || clientDataHash, and authData embeds the full
     * ML-DSA public key (~2 KB), so this must be sized for the worst
     * case -- see PQF_HYBRID_LABELLED_MAX in hybrid.h. (.bss, not stack.) */
    static uint8_t labelled[PQF_HYBRID_LABELLED_MAX];
    if (32 + msg_len + PQF_P256_MAX_SIG_DER > sizeof labelled)
        return -1;

    /* --- ECDSA half: sign SHA-256(LABEL || msg). --- */
    size_t lm_len = build_labelled(labelled, msg, msg_len, NULL, 0);
    uint8_t prehash[32];
    pqf_sha256(labelled, lm_len, prehash);

    uint8_t der[PQF_P256_MAX_SIG_DER];
    size_t  der_len = 0;
    if (pqf_ecdsa_p256_sign(ecdsa_scalar, prehash, der, &der_len) != 0)
        return -1;

    /* --- ML-DSA half: pure-sign LABEL || msg || ecdsaDER. --- */
    size_t lmd_len = build_labelled(labelled, msg, msg_len, der, der_len);
    uint8_t *mldsa_sig = out + der_len;
    size_t   mldsa_len = 0;
    if (pqf_mldsa_sign(PQF_HYBRID_MLDSA, mldsa_seed, labelled, lmd_len,
                       mldsa_sig, &mldsa_len) != 0)
        return -1;

    /* hybridSig = ecdsaDER || mldsaSig (DER first, in place). */
    memmove(out, der, der_len);
    *out_len = der_len + mldsa_len;
    return 0;
}

/* Parse the length of a DER SEQUENCE at `der` (ECDSA sigs use the
 * short-form length, always < 128). Returns total bytes, or 0. */
static size_t der_seq_len(const uint8_t *der, size_t avail)
{
    if (avail < 2 || der[0] != 0x30) return 0;
    if (der[1] & 0x80) return 0;          /* long form not expected */
    size_t total = 2 + (size_t)der[1];
    return (total <= avail) ? total : 0;
}

int hybrid_verify(const uint8_t ec_x[32], const uint8_t ec_y[32],
                  const uint8_t *mldsa_pub, size_t mldsa_pub_len,
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len)
{
    /* Split sig into the DER ECDSA prefix + ML-DSA remainder. */
    size_t der_len = der_seq_len(sig, sig_len);
    if (der_len == 0 || der_len >= sig_len) return -1;
    const uint8_t *mldsa_sig = sig + der_len;
    size_t mldsa_len = sig_len - der_len;

    static uint8_t labelled[PQF_HYBRID_LABELLED_MAX];
    if (32 + msg_len + der_len > sizeof labelled) return -1;

    /* ECDSA half over SHA-256(LABEL || msg). */
    size_t lm_len = build_labelled(labelled, msg, msg_len, NULL, 0);
    uint8_t prehash[32];
    pqf_sha256(labelled, lm_len, prehash);
    int ev = pqf_ecdsa_p256_verify(ec_x, ec_y, prehash, sig, der_len);
    if (ev != 1) return 0;

    /* ML-DSA half over LABEL || msg || ecdsaDER. */
    size_t lmd_len = build_labelled(labelled, msg, msg_len, sig, der_len);
    int mv = pqf_mldsa_verify(PQF_HYBRID_MLDSA, mldsa_pub, mldsa_pub_len,
                              labelled, lmd_len, mldsa_sig, mldsa_len);
    return (mv == 1) ? 1 : 0;
}
