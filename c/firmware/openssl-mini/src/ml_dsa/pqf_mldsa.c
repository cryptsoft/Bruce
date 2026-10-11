/* pqf_mldsa.c -- pqf_* ML-DSA wrapper over the vendored OpenSSL
 * crypto/ml_dsa core.
 *
 * Exposes deterministic seed-based key derivation + sign / verify in
 * terms of raw byte buffers, keeping the ML_DSA_KEY lifecycle and the
 * ossl_ml_dsa_* spellings contained here. FIDO stores only the
 * 32-byte seed (in the credentialID); the key is re-derived on demand.
 *
 * Pure ML-DSA (FIPS 204 sec. 5, no pre-hash), empty context string,
 * deterministic signing so a given (seed, message) maps to a stable
 * signature. FIPS 204 sec. 5.2 spells the deterministic variant as rnd set
 * to 32 zero bytes, which is what pqf_mldsa_sign() passes; that is the
 * form the published ACVP / RFC 9881 vectors use.
 *
 * This file is project-original on top of the
 * Apache-2.0 vendored ML-DSA core.
 *
 * Copyright 2026 Cryptsoft Pty Ltd
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "pqf_crypto.h"
#include "openssl/evp.h"        /* EVP_PKEY_ML_DSA_44 / 65 / 87 */
#include "crypto/ml_dsa.h"
#include "pqf_yield.h"

static int variant_evp_type(int variant)
{
    switch (variant) {
    case PQF_MLDSA_44: return EVP_PKEY_ML_DSA_44;
    case PQF_MLDSA_65: return EVP_PKEY_ML_DSA_65;
    case PQF_MLDSA_87: return EVP_PKEY_ML_DSA_87;
    default:           return 0;
    }
}

/* Build an ML_DSA_KEY and deterministically derive it from `seed`.
 *
 * `for_sign` derives only the values ML-DSA.Sign() reads, leaving out the
 * encoded public and private keys and t1. Those are 15,680 bytes at
 * ML-DSA-87 that would otherwise stay resident for the whole signature. */
/* Stage the seed as the key's prekey (prefer_seed = 1) without generating
 * anything yet. The caller picks which generator to run. */
static ML_DSA_KEY *key_stage_seed(int variant, const uint8_t seed[32])
{
    int evp_type = variant_evp_type(variant);
    if (evp_type == 0) return NULL;

    ML_DSA_KEY *key = ossl_ml_dsa_key_new(NULL, NULL, evp_type);
    if (key == NULL) return NULL;

    if (ossl_ml_dsa_set_prekey(key, 1, 0, seed, 32, NULL, 0) != 1) {
        ossl_ml_dsa_key_free(key);
        return NULL;
    }
    return key;
}

static ML_DSA_KEY *key_from_seed(int variant, const uint8_t seed[32],
                                 int for_sign)
{
    ML_DSA_KEY *key = key_stage_seed(variant, seed);
    if (key == NULL) return NULL;

    /* Key generation expands the seed per FIPS 204. */
    if ((for_sign ? ossl_ml_dsa_generate_key_for_sign(key)
                  : ossl_ml_dsa_generate_key(key)) != 1) {
        ossl_ml_dsa_key_free(key);
        return NULL;
    }
    return key;
}

int pqf_mldsa_pub_from_seed(int variant, const uint8_t seed[32],
                            uint8_t *pub, size_t *pub_len)
{
    /*
     * Staged, not generated: ossl_ml_dsa_generate_key_pubkey() runs the
     * generator itself and writes t1 straight into |pub| as Power2Round
     * produces it. Going through ossl_ml_dsa_generate_key() would build the
     * whole key pair - 47 polynomials at ML-DSA-87 - to hand back 2,592
     * bytes and then throw the rest away.
     */
    ML_DSA_KEY *key = key_stage_seed(variant, seed);
    size_t pk_len;
    int rc = -1;

    if (key == NULL)
        return -1;

    pk_len = ossl_ml_dsa_key_get_pub_len(key);
    if (pk_len > 0 && ossl_ml_dsa_generate_key_pubkey(key, pub, pk_len) == 1) {
        *pub_len = pk_len;
        rc = 0;
    }
    ossl_ml_dsa_key_free(key);
    return rc;
}

int pqf_mldsa_sign(int variant, const uint8_t seed[32],
                   const uint8_t *msg, size_t msg_len,
                   uint8_t *sig, size_t *sig_len)
{
    /* FIPS 204 Algorithm 2 step 6: the deterministic variant sets
     * rnd = 0^32, so rho_prime = SHAKE256(K || 0^32 || mu). Passing
     * rand = NULL instead would absorb nothing and give
     * SHAKE256(K || mu) -- still a valid signature, but one no other
     * implementation reproduces. */
    static const uint8_t rnd[32] = { 0 };

    ML_DSA_KEY *key = key_from_seed(variant, seed, 1);
    if (key == NULL) return -1;

    size_t sigsize = ossl_ml_dsa_key_get_sig_len(key);
    int rc = ossl_ml_dsa_sign(key, 0 /*msg_is_mu*/, msg, msg_len,
                              NULL, 0 /*context*/, rnd, sizeof rnd,
                              1 /*encode*/, sig, sig_len, sigsize);
    ossl_ml_dsa_key_free(key);
    return rc == 1 ? 0 : -1;
}

int pqf_mldsa_verify(int variant, const uint8_t *pub, size_t pub_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig, size_t sig_len)
{
    int evp_type = variant_evp_type(variant);
    if (evp_type == 0) return -1;

    ML_DSA_KEY *key = ossl_ml_dsa_key_new(NULL, NULL, evp_type);
    if (key == NULL) return -1;

    int rc = -1;
    if (ossl_ml_dsa_pk_decode(key, pub, pub_len) == 1) {
        int v = ossl_ml_dsa_verify(key, 0, msg, msg_len, NULL, 0,
                                   1 /*encode*/, sig, sig_len);
        rc = (v == 1) ? 1 : 0;
    }
    ossl_ml_dsa_key_free(key);
    return rc;
}

/* ---- pqf_yield ---------------------------------------------------- *
 * The cooperative yield point the ML-DSA loops call (pqf_yield.h). Weak
 * no-op default; the single-core firmware defines the real one. The EC
 * directory carries an identical weak default -- see ec/pqf_ec_stubs.c
 * for why there are two. */
void __attribute__((weak)) pqf_yield(void) { }
