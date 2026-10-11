/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Modified by Cryptsoft Pty Ltd for Bruce (2026). This file is not the
 * OpenSSL 3.5 original: the low-memory ML-DSA changes it carries are
 * listed, with their reasons, in ../../ML-DSA-LOWMEM.md.
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include "ml_dsa_key.h"
#include "ml_dsa_matrix.h"
#include "ml_dsa_hash.h"
#include "internal/encoder.h"

const ML_DSA_PARAMS *ossl_ml_dsa_key_params(const ML_DSA_KEY *key)
{
    return key->params;
}

/* Returns the seed data or NULL if there is no seed */
const uint8_t *ossl_ml_dsa_key_get_seed(const ML_DSA_KEY *key)
{
    return key->seed;
}

int ossl_ml_dsa_key_prefer_seed(const ML_DSA_KEY *key)
{
    return key->prefer_seed;
}

int ossl_ml_dsa_key_retain_seed(const ML_DSA_KEY *key)
{
    return key->retain_seed;
}

int ossl_ml_dsa_set_prekey(ML_DSA_KEY *key, int prefer_seed, int retain_seed,
                           const uint8_t *seed, size_t seed_len,
                           const uint8_t *sk, size_t sk_len)
{
    int ret = 0;

    if (key == NULL
        || key->pub_encoding != NULL
        || key->priv_encoding != NULL
        || (sk != NULL && sk_len != key->params->sk_len)
        || (seed != NULL && seed_len != ML_DSA_SEED_BYTES)
        || key->seed != NULL)
        return 0;

    if (sk != NULL
        && (key->priv_encoding = OPENSSL_memdup(sk, sk_len)) == NULL)
        goto end;
    if (seed != NULL
        && (key->seed = OPENSSL_memdup(seed, seed_len)) == NULL)
        goto end;
    if (prefer_seed >= 0)
        key->prefer_seed = prefer_seed;
    if (retain_seed >= 0)
        key->retain_seed = retain_seed;
    ret = 1;

  end:
    if (!ret) {
        OPENSSL_free(key->priv_encoding);
        OPENSSL_free(key->seed);
        key->priv_encoding = key->seed = NULL;
    }
    return ret;
}

/**
 * @brief Create a new ML_DSA_KEY object
 *
 * @param libctx A OSSL_LIB_CTX object used for fetching algorithms.
 * @param propq The property query used for fetching algorithms
 * @param alg The algorithm name associated with the key type
 * @returns The new ML_DSA_KEY object on success, or NULL on malloc failure
 */
ML_DSA_KEY *ossl_ml_dsa_key_new(OSSL_LIB_CTX *libctx, const char *propq,
                                int evp_type)
{
    ML_DSA_KEY *ret;
    const ML_DSA_PARAMS *params = ossl_ml_dsa_params_get(evp_type);

    if (params == NULL)
        return NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret != NULL) {
        ret->libctx = libctx;
        ret->params = params;
        ret->prefer_seed = 1;
        ret->retain_seed = 1;
        ret->shake128_md = EVP_MD_fetch(libctx, "SHAKE-128", propq);
        ret->shake256_md = EVP_MD_fetch(libctx, "SHAKE-256", propq);
        if (ret->shake128_md == NULL || ret->shake256_md == NULL)
            goto err;
    }
    return ret;
err:
    ossl_ml_dsa_key_free(ret);
    return NULL;
}

int ossl_ml_dsa_key_pub_alloc(ML_DSA_KEY *key)
{
    if (key->t1.poly != NULL)
        return 0;
    return vector_alloc(&key->t1, key->params->k);
}

int ossl_ml_dsa_key_priv_alloc(ML_DSA_KEY *key)
{
    size_t k = key->params->k, l = key->params->l;
    POLY *poly;

    if (key->s1.poly != NULL)
        return 0;
    if (!vector_alloc(&key->s1, l + 2 * k))
        return 0;

    poly = key->s1.poly;
    key->s1.num_poly = l;
    vector_init(&key->s2, poly + l, k);
    vector_init(&key->t0, poly + l + k, k);
    return 1;
}

/*
 * @brief Release s1, s2 and t0.
 *
 * They share one allocation owned by s1, so all three views have to be
 * dropped together.
 */
static void priv_vectors_free(ML_DSA_KEY *key)
{
    vector_zero(&key->s2);
    vector_zero(&key->t0);
    vector_zero(&key->s1);
    vector_free(&key->s1);
    vector_init(&key->s2, NULL, 0);
    vector_init(&key->t0, NULL, 0);
}

/**
 * @brief Destroy an ML_DSA_KEY object
 */
void ossl_ml_dsa_key_free(ML_DSA_KEY *key)
{
    if (key == NULL)
        return;

    EVP_MD_free(key->shake128_md);
    EVP_MD_free(key->shake256_md);
    ossl_ml_dsa_key_reset(key);
    OPENSSL_free(key);
}

/**
 * @brief Factory reset an ML_DSA_KEY object
 */
void ossl_ml_dsa_key_reset(ML_DSA_KEY *key)
{
    priv_vectors_free(key);
    vector_free(&key->t1);
    if (key->s_packed != NULL)
        OPENSSL_clear_free(key->s_packed,
                           ossl_ml_dsa_priv_packed_len(key->params));
    key->s_packed = NULL;
    OPENSSL_cleanse(key->K, sizeof(key->K));
    OPENSSL_free(key->pub_encoding);
    key->pub_encoding = NULL;
    if (key->priv_encoding != NULL)
        OPENSSL_clear_free(key->priv_encoding, key->params->sk_len);
    key->priv_encoding = NULL;
    if (key->seed != NULL)
        OPENSSL_clear_free(key->seed, ML_DSA_SEED_BYTES);
    key->seed = NULL;
}

/**
 * @brief Duplicate a key
 *
 * @param src A ML_DSA_KEY object to copy
 * @param selection to select public and/or private components. Selecting the
 *                  private key will also select the public key
 * @returns The duplicated key, or NULL on failure.
 */
ML_DSA_KEY *ossl_ml_dsa_key_dup(const ML_DSA_KEY *src, int selection)
{
    ML_DSA_KEY *ret = NULL;

    if (src == NULL)
        return NULL;

    /* Prekeys with just a seed or private key are not dupable */
    if (src->pub_encoding == NULL
        && (src->priv_encoding != NULL || src->seed != NULL))
        return NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret != NULL) {
        ret->libctx = src->libctx;
        ret->params = src->params;
        ret->retain_seed = src->retain_seed;
        ret->prefer_seed = src->prefer_seed;
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
            if (src->pub_encoding != NULL) {
                /* The public components are present if the private key is present */
                memcpy(ret->rho, src->rho, sizeof(src->rho));
                memcpy(ret->tr, src->tr, sizeof(src->tr));
                if (src->t1.poly != NULL) {
                    if (!ossl_ml_dsa_key_pub_alloc(ret))
                        goto err;
                    vector_copy(&ret->t1, &src->t1);
                }
                if ((ret->pub_encoding = OPENSSL_memdup(src->pub_encoding,
                                                        src->params->pk_len)) == NULL)
                    goto err;
            }
            if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
                if (src->priv_encoding != NULL) {
                    memcpy(ret->K, src->K, sizeof(src->K));
                    if (src->s1.poly != NULL) {
                        if (!ossl_ml_dsa_key_priv_alloc(ret))
                            goto err;
                        vector_copy(&ret->s1, &src->s1);
                        vector_copy(&ret->s2, &src->s2);
                        vector_copy(&ret->t0, &src->t0);
                    }
                    if ((ret->priv_encoding =
                            OPENSSL_memdup(src->priv_encoding,
                                           src->params->sk_len)) == NULL)
                        goto err;
                }
                if (src->seed != NULL
                    && (ret->seed = OPENSSL_memdup(src->seed,
                                                   ML_DSA_SEED_BYTES)) == NULL)
                    goto err;
            }
        }
        EVP_MD_up_ref(src->shake128_md);
        EVP_MD_up_ref(src->shake256_md);
        ret->shake128_md = src->shake128_md;
        ret->shake256_md = src->shake256_md;
    }
    return ret;
 err:
    ossl_ml_dsa_key_free(ret);
    return NULL;
}

/**
 * @brief Are 2 keys equal?
 *
 * To be equal the keys must have matching public or private key data and
 * contain the same parameters.
 * (Note that in OpenSSL that the private key always has a public key component).
 *
 * @param key1 A ML_DSA_KEY object
 * @param key2 A ML_DSA_KEY object
 * @param selection to select public and/or private component comparison.
 * @returns 1 if the keys are equal otherwise it returns 0.
 */
int ossl_ml_dsa_key_equal(const ML_DSA_KEY *key1, const ML_DSA_KEY *key2,
                          int selection)
{
    int key_checked = 0;

    if (key1->params != key2->params)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            if (key1->pub_encoding != NULL && key2->pub_encoding != NULL) {
                if (memcmp(key1->pub_encoding, key2->pub_encoding,
                                  key1->params->pk_len) != 0)
                    return 0;
                key_checked = 1;
            }
        }
        if (!key_checked
                && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            if (key1->priv_encoding != NULL && key2->priv_encoding != NULL) {
                if (memcmp(key1->priv_encoding, key2->priv_encoding,
                           key1->params->sk_len) != 0)
                    return 0;
                key_checked = 1;
            }
        }
        return key_checked;
    }
    return 1;
}

int ossl_ml_dsa_key_has(const ML_DSA_KEY *key, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        /* Note that the public key always exists if there is a private key */
        if (ossl_ml_dsa_key_get_pub(key) == NULL)
            return 0; /* No public key */
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
                && ossl_ml_dsa_key_get_priv(key) == NULL)
            return 0; /* No private key */
        return 1;
    }
    return 0;
}

/*
 * @brief Given a key containing private key values for rho, s1 & s2
 * generate the public value t and return the compressed values t1, t0.
 *
 * @param key A private key containing params, rh0, s1 & s2.
 * @param md_ctx A EVP_MD_CTX used for sampling.
 * @param t1 The returned polynomial encoding of the 10 MSB of each coefficient
 *        of the uncompressed public key polynomial t.
 * @param t0 The returned polynomial encoding of the 13 LSB of each coefficient
 *        of the uncompressed public key polynomial t.
 * @returns 1 on success, or 0 on failure.
 */
static int public_from_private(const ML_DSA_KEY *key, EVP_MD_CTX *md_ctx,
                               VECTOR *t1, VECTOR *t0)
{
    const ML_DSA_PARAMS *params = key->params;
    uint32_t k = params->k, l = params->l;
    int ret = 0;
    POLY *polys;
    MATRIX a_ntt;
    VECTOR s1_ntt;
    VECTOR t;

    /*
     * A is consumed by a single matrix multiply here, so it is expanded a
     * row at a time and only a one polynomial scratch block is reserved for
     * it rather than k * l blocks.
     */
    polys = OPENSSL_malloc(sizeof(*polys) * (k + l + 1));
    if (polys == NULL)
        return 0;

    vector_init(&t, polys, k);
    vector_init(&s1_ntt, t.poly + k, l);
    /* Using rho generate A' = A in NTT form, one element at a time */
    matrix_init_stream(&a_ntt, s1_ntt.poly + l, k, l, md_ctx,
                       key->shake128_md, key->rho);

    /* t = NTT_inv(A' * NTT(s1)) + s2 */
    vector_copy(&s1_ntt, &key->s1);
    vector_ntt(&s1_ntt);

    if (!matrix_mult_vector(&a_ntt, &s1_ntt, &t))
        goto err;
    vector_ntt_inverse(&t);
    vector_add(&t, &key->s2, &t);

    /* Compress t */
    vector_power2_round(&t, t1, t0);
    ret = 1;
err:
    /*
     * Zeroize secrets. |polys| carries NTT(s1) and t, and t0 is recoverable
     * from t because t = t1 * 2^d + t0, so the whole block is cleansed
     * rather than just NTT(s1). Upstream frees it uncleansed.
     */
    OPENSSL_clear_free(polys, sizeof(*polys) * (k + l + 1));
    return ret;
}

int ossl_ml_dsa_key_public_from_private(ML_DSA_KEY *key)
{
    int ret = 0;
    VECTOR t0;
    EVP_MD_CTX *md_ctx = NULL;

    if (!vector_alloc(&t0, key->params->k)) /* t0 is already in the private key */
        return 0;
    ret = ((md_ctx = EVP_MD_CTX_new())!= NULL)
        && ossl_ml_dsa_key_pub_alloc(key)  /* allocate space for t1 */
        && public_from_private(key, md_ctx, &key->t1, &t0)
        && vector_equal(&t0, &key->t0) /* compare the generated t0 to the expected */
        && ossl_ml_dsa_pk_encode(key)
        && shake_xof(md_ctx, key->shake256_md,
                     key->pub_encoding, key->params->pk_len,
                     key->tr, sizeof(key->tr));
    vector_zero(&t0); /* t0 is a private key component */
    vector_free(&t0);
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

int ossl_ml_dsa_key_pairwise_check(const ML_DSA_KEY *key)
{
    int ret = 0;
    VECTOR t1, t0;
    POLY *polys = NULL;
    uint32_t k = key->params->k;
    EVP_MD_CTX *md_ctx = NULL;

    if (key->pub_encoding == NULL || key->priv_encoding == 0)
        return 0;

    polys = OPENSSL_malloc(sizeof(*polys) * (2 * k));
    if (polys == NULL)
        return 0;
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        goto err;

    vector_init(&t1, polys, k);
    vector_init(&t0, polys + k, k);
    if (!public_from_private(key, md_ctx, &t1, &t0))
        goto err;

    ret = vector_equal(&t1, &key->t1) && vector_equal(&t0, &key->t0);
err:
    EVP_MD_CTX_free(md_ctx);
    /* t0 is a private key component, so |polys| goes back cleansed */
    OPENSSL_clear_free(polys, sizeof(*polys) * (2 * k));
    return ret;
}

/*
 * @brief Generate a full public-private key pair from an expanded seed.
 * See FIPS 204, Algorithm 6 ML-DSA.KeyGen_internal().
 *
 * This is the unmodified upstream shape: s1, s2, t1 and t0 are materialised
 * in the key and then encoded. Its heap cost is the (l + 2k) polynomial
 * private block plus k for t1 - 31744 bytes at ML-DSA-87 - which only a key
 * that has to be exported needs to pay.
 *
 * @param out The key to generate into, with rho and K already set.
 * @param md_ctx A EVP_MD_CTX used for sampling and hashing.
 * @param priv_seed The 64 byte p' the private vectors are sampled from.
 * @returns 1 on success or 0 on failure.
 */
static int keygen_full(ML_DSA_KEY *out, EVP_MD_CTX *md_ctx,
                       const uint8_t *priv_seed)
{
    if (!ossl_ml_dsa_key_pub_alloc(out)
        || !ossl_ml_dsa_key_priv_alloc(out))
        return 0;
    return vector_expand_S(md_ctx, out->shake256_md, out->params->eta,
                           priv_seed, &out->s1, &out->s2)
        && public_from_private(out, md_ctx, &out->t1, &out->t0)
        && ossl_ml_dsa_pk_encode(out)
        && shake_xof(md_ctx, out->shake256_md, out->pub_encoding,
                     out->params->pk_len, out->tr, sizeof(out->tr))
        && ossl_ml_dsa_sk_encode(out);
}

/*
 * @brief Generate only the key values ML-DSA.Sign() consumes, keeping s1, s2
 * and t0 bit-packed throughout.
 *
 * Signing reads rho, tr, K, s1, s2 and t0, and reads the last three one
 * polynomial at a time out of |s_packed| (see ossl_ml_dsa_priv_unpack_poly()).
 * So this walks Algorithm 6 producing one polynomial at a time and packs each
 * as it appears, rather than filling the (l + 2k) polynomial unpacked block
 * and packing it afterwards. Three things follow from that:
 *
 * - ExpandS samples each polynomial of s1 || s2 independently, so each is
 *   packed straight from the scratch block it is sampled into.
 * - t = A * NTT(s1) + s2 is accumulated column by column, unpacking and
 *   transforming one column of s1 at a time, which is the same
 *   column-outer/row-inner order the signing loop uses. A is streamed an
 *   element at a time as usual. t stays as k polynomials: it is the one
 *   value here that is live across a whole pass.
 * - Power2Round is applied a row at a time, packing that row of t0 and
 *   absorbing that row of t1 into tr. t1 only feeds the public key encoding,
 *   so nothing keeps it.
 *
 * The unpacked storage is therefore k + 2 polynomials rather than the
 * 2l + 4k + 1 that were live at once before - the (l + 2k) private block,
 * t1 (k), and public_from_private()'s own (k + l + 1) - and the largest
 * single allocation is k rather than l + 2k: 8192 bytes instead of 23552 at
 * ML-DSA-87. The resulting key cannot be exported, duplicated or used to
 * verify.
 *
 * @param out The key to generate into, with rho and K already set.
 * @param md_ctx A EVP_MD_CTX used for sampling and hashing.
 * @param priv_seed The 64 byte p' the private vectors are sampled from.
 * @returns 1 on success or 0 on failure.
 */
static int keygen_sign_only(ML_DSA_KEY *out, EVP_MD_CTX *md_ctx,
                            const uint8_t *priv_seed)
{
    const ML_DSA_PARAMS *params = out->params;
    size_t k = params->k, l = params->l, i, j;
    int ret = 0;
    POLY *t_poly = NULL, *scratch = NULL, *s, *a;
    VECTOR t;
    MATRIX a_ntt;

    /*
     * Nothing here allocates the unpacked vectors, so refuse a key that
     * already carries them rather than leaving a stale copy beside the packed
     * form. ossl_ml_dsa_priv_pack_alloc() makes the same refusal for a key
     * that has already been generated.
     */
    if (out->t1.poly != NULL || out->s1.poly != NULL
            || !ossl_ml_dsa_priv_pack_alloc(out))
        return 0;
    /*
     * |s| holds whichever private polynomial is in flight, |a| the matrix
     * element being consumed - and, once the multiply is done, the row of t0
     * being packed. They are a separate allocation from |t| so that the
     * largest block asked for stays at k polynomials.
     */
    t_poly = OPENSSL_malloc(sizeof(*t_poly) * k);
    scratch = OPENSSL_malloc(sizeof(*scratch) * 2);
    if (t_poly == NULL || scratch == NULL)
        goto err;
    vector_init(&t, t_poly, k);
    s = scratch;
    a = scratch + 1;

    /* ExpandS, bit-packing each polynomial as it is sampled */
    for (i = 0; i < l + k; i++) {
        if (!ossl_ml_dsa_expand_S_poly(md_ctx, out->shake256_md, params->eta,
                                       priv_seed, i, s))
            goto err;
        if (i < l) {
            if (!ossl_ml_dsa_priv_pack_poly(out, ML_DSA_PRIV_S1, i, s))
                goto err;
        } else {
            if (!ossl_ml_dsa_priv_pack_poly(out, ML_DSA_PRIV_S2, i - l, s))
                goto err;
        }
    }

    /* Using rho generate A' = A in NTT form, one element at a time */
    matrix_init_stream(&a_ntt, a, k, l, md_ctx, out->shake128_md, out->rho);

    /* t = NTT_inv(A' * NTT(s1)), accumulated a column of s1 at a time */
    vector_zero(&t);
    for (j = 0; j < l; j++) {
        if (!ossl_ml_dsa_priv_unpack_poly(out, ML_DSA_PRIV_S1, j, s))
            goto err;
        ossl_ml_dsa_poly_ntt(s);
        for (i = 0; i < k; i++) {
            const POLY *a_elem = matrix_get_elem(&a_ntt, i, j);

            if (a_elem == NULL)
                goto err;
            ossl_ml_dsa_poly_ntt_mult_add(a_elem, s, t.poly + i);
        }
    }
    vector_ntt_inverse(&t);

    /*
     * t += s2, then (t1, t0) = Power2Round(t) a row at a time: t0 goes to its
     * slot in the packed private block and t1 into tr = H(pkEncode(rho, t1)).
     */
    if (!ossl_ml_dsa_pk_hash_init(out, md_ctx))
        goto err;
    for (i = 0; i < k; i++) {
        if (!ossl_ml_dsa_priv_unpack_poly(out, ML_DSA_PRIV_S2, i, s))
            goto err;
        poly_add(t.poly + i, s, t.poly + i);
        poly_power2_round(t.poly + i, s, a);
        if (!ossl_ml_dsa_pk_hash_poly(md_ctx, s)
            || !ossl_ml_dsa_priv_pack_poly(out, ML_DSA_PRIV_T0, i, a))
            goto err;
    }
    ret = EVP_DigestSqueeze(md_ctx, out->tr, sizeof(out->tr));
err:
    /*
     * Zeroize secrets. This is the success path as well as the error path:
     * |scratch| holds whichever private polynomial was last in flight, and
     * t0 is recoverable from |t| because t = t1 * 2^d + t0, so both have to
     * go back to the allocator cleansed.
     */
    OPENSSL_clear_free(scratch, sizeof(*scratch) * 2);
    OPENSSL_clear_free(t_poly, sizeof(*t_poly) * k);
    return ret;
}

/*
 * @brief Produce only the encoded public key, into the caller's buffer.
 *
 * A public key needs t1, and t1 needs t = A*s1 + s2. Nothing else survives:
 * t0 is discarded, and s1/s2 are wanted only while the multiply is running.
 * So this walks the same column-outer/row-inner shape keygen_sign_only()
 * uses, re-deriving each private polynomial from ExpandS at the point of use
 * rather than packing it (there is no signing to keep it for), and encodes
 * each row of t1 straight into the caller's buffer as Power2Round yields it.
 *
 * Live at the peak: t (k polynomials) plus two scratch. 10 polynomials at
 * ML-DSA-87 against the 47 that going through keygen_full() costs.
 *
 * @param out A key with its seed staged; rho and K are filled by the caller.
 * @param md_ctx The digest context, already used for the seed expansion.
 * @param priv_seed rho', the private half of the expanded seed.
 * @param pk Caller's buffer, exactly params->pk_len bytes.
 * @returns 1 on success, 0 on failure.
 */
static int keygen_pub_only(ML_DSA_KEY *out, EVP_MD_CTX *md_ctx,
                           const uint8_t *priv_seed, uint8_t *pk,
                           size_t pk_len)
{
    const ML_DSA_PARAMS *params = out->params;
    size_t k = params->k, l = params->l, i, j;
    int ret = 0;
    POLY *t_poly = NULL, *scratch = NULL, *s, *a;
    VECTOR t;
    MATRIX a_ntt;
    WPACKET pkt;
    int pkt_open = 0;

    if (out->t1.poly != NULL || out->s1.poly != NULL)
        return 0;

    /*
     * |t| is the accumulator; |s| holds whichever private polynomial is in
     * flight and |a| the matrix element, then the t0 half of Power2Round that
     * this path throws away. Separate allocations so the largest single
     * request stays at k polynomials.
     */
    t_poly = OPENSSL_malloc(sizeof(*t_poly) * k);
    scratch = OPENSSL_malloc(sizeof(*scratch) * 2);
    if (t_poly == NULL || scratch == NULL)
        goto err;
    vector_init(&t, t_poly, k);
    s = scratch;
    a = scratch + 1;

    if (!ossl_ml_dsa_pk_encode_begin(out, &pkt, pk, pk_len))
        goto err;
    pkt_open = 1;

    matrix_init_stream(&a_ntt, a, k, l, md_ctx, out->shake128_md, out->rho);

    /*
     * t = NTT_inv(A' * NTT(s1)), a column of s1 at a time. ExpandS is
     * deterministic in (rho', index), so s1[j] is re-derived here rather than
     * kept.
     */
    vector_zero(&t);
    for (j = 0; j < l; j++) {
        if (!ossl_ml_dsa_expand_S_poly(md_ctx, out->shake256_md, params->eta,
                                       priv_seed, j, s))
            goto err;
        ossl_ml_dsa_poly_ntt(s);
        for (i = 0; i < k; i++) {
            const POLY *a_elem = matrix_get_elem(&a_ntt, i, j);

            if (a_elem == NULL)
                goto err;
            ossl_ml_dsa_poly_ntt_mult_add(a_elem, s, t.poly + i);
        }
    }
    vector_ntt_inverse(&t);

    /* t += s2, Power2Round a row at a time, t1 straight out to the caller. */
    for (i = 0; i < k; i++) {
        if (!ossl_ml_dsa_expand_S_poly(md_ctx, out->shake256_md, params->eta,
                                       priv_seed, l + i, s))
            goto err;
        poly_add(t.poly + i, s, t.poly + i);
        poly_power2_round(t.poly + i, s, a);  /* t1 -> s, t0 -> a (dropped) */
        if (!ossl_ml_dsa_pk_encode_poly(&pkt, s))
            goto err;
    }
    ret = ossl_ml_dsa_pk_encode_done(out, &pkt);
err:
    if (pkt_open)
        WPACKET_finish(&pkt);
    /*
     * |scratch| last held a private polynomial, and t0 is recoverable from |t|
     * because t = t1 * 2^d + t0. Both go back to the allocator cleansed.
     */
    OPENSSL_clear_free(scratch, sizeof(*scratch) * 2);
    OPENSSL_clear_free(t_poly, sizeof(*t_poly) * k);
    return ret;
}

/*
 * @brief Generate a public-private key pair from a seed.
 * See FIPS 204, Algorithm 6 ML-DSA.KeyGen_internal().
 *
 * @param out The generated key (which contains params on input)
 * @param mode ML_DSA_KEYGEN_FULL builds the whole key pair.
 *        ML_DSA_KEYGEN_SIGN_ONLY retains only the values ML-DSA.Sign consumes
 *        (rho, tr, K and the bit-packed s1, s2, t0) and skips the encoded
 *        public and private keys. tr is still derived from the public key
 *        encoding, but by hashing it as it is produced rather than storing
 *        it. See keygen_sign_only().
 *        ML_DSA_KEYGEN_PUB_ONLY writes just the encoded public key into |pk|
 *        and retains nothing. See keygen_pub_only().
 * @param pk Caller's buffer, used by ML_DSA_KEYGEN_PUB_ONLY only.
 *
 * @returns 1 on success or 0 on failure.
 */
static int keygen_internal(ML_DSA_KEY *out, int mode,
                           uint8_t *pk, size_t pk_len)
{
    int ret = 0;
    uint8_t augmented_seed[ML_DSA_SEED_BYTES + 2];
    uint8_t expanded_seed[ML_DSA_RHO_BYTES + ML_DSA_PRIV_SEED_BYTES + ML_DSA_K_BYTES];
    const uint8_t *const rho = expanded_seed; /* p = Public Random Seed */
    const uint8_t *const priv_seed = expanded_seed + ML_DSA_RHO_BYTES;
    const uint8_t *const K = priv_seed + ML_DSA_PRIV_SEED_BYTES;
    const ML_DSA_PARAMS *params = out->params;
    EVP_MD_CTX *md_ctx = NULL;

    if (out->seed == NULL
        || (md_ctx = EVP_MD_CTX_new()) == NULL)
        goto err;

    /* augmented_seed = seed || k || l */
    memcpy(augmented_seed, out->seed, ML_DSA_SEED_BYTES);
    augmented_seed[ML_DSA_SEED_BYTES] = (uint8_t)params->k;
    augmented_seed[ML_DSA_SEED_BYTES + 1] = (uint8_t)params->l;
    /* Expand the seed into p[32], p'[64], K[32] */
    if (!shake_xof(md_ctx, out->shake256_md, augmented_seed, sizeof(augmented_seed),
                   expanded_seed, sizeof(expanded_seed)))
        goto err;

    memcpy(out->rho, rho, sizeof(out->rho));
    memcpy(out->K, K, sizeof(out->K));

    switch (mode) {
    case ML_DSA_KEYGEN_SIGN_ONLY:
        ret = keygen_sign_only(out, md_ctx, priv_seed);
        break;
    case ML_DSA_KEYGEN_PUB_ONLY:
        ret = keygen_pub_only(out, md_ctx, priv_seed, pk, pk_len);
        break;
    default:
        ret = keygen_full(out, md_ctx, priv_seed);
        break;
    }

err:
    if (out->seed != NULL && !out->retain_seed) {
        OPENSSL_clear_free(out->seed, ML_DSA_SEED_BYTES);
        out->seed = NULL;
    }
    EVP_MD_CTX_free(md_ctx);
    OPENSSL_cleanse(augmented_seed, sizeof(augmented_seed));
    OPENSSL_cleanse(expanded_seed, sizeof(expanded_seed));
    return ret;
}

static int generate_key(ML_DSA_KEY *out, int mode)
{
    size_t seed_len = ML_DSA_SEED_BYTES;

    if (out->seed == NULL) {
        if ((out->seed = OPENSSL_malloc(seed_len)) == NULL)
            return 0;
        if (RAND_priv_bytes_ex(out->libctx, out->seed, seed_len, 0) <= 0) {
            OPENSSL_free(out->seed);
            out->seed = NULL;
            return 0;
        }
    }
    /* We're generating from a seed, drop private prekey encoding */
    OPENSSL_free(out->priv_encoding);
    out->priv_encoding = NULL;
    return keygen_internal(out, mode, NULL, 0);
}

int ossl_ml_dsa_generate_key(ML_DSA_KEY *out)
{
    return generate_key(out, ML_DSA_KEYGEN_FULL);
}

/*
 * @brief Generate only the key values that ML-DSA.Sign() consumes.
 *
 * The resulting key can sign, but has no encoded public or private key and
 * no t1, so it cannot be exported, duplicated or used to verify. Callers
 * that hold a seed and want a signature - which on this firmware is every
 * signature, the credential ID carries the seed - should use this in place
 * of ossl_ml_dsa_generate_key().
 *
 * @returns 1 on success or 0 on failure.
 */
int ossl_ml_dsa_generate_key_for_sign(ML_DSA_KEY *out)
{
    return generate_key(out, ML_DSA_KEYGEN_SIGN_ONLY);
}

/*
 * @brief Produce only the encoded public key, into the caller's buffer.
 *
 * See keygen_pub_only(): 10 polynomials are live at ML-DSA-87 rather than
 * 47, because nothing but t1 is wanted and t1 is written out as it appears.
 * The key itself retains nothing and is not usable afterwards.
 *
 * @returns 1 on success or 0 on failure.
 */
int ossl_ml_dsa_generate_key_pubkey(ML_DSA_KEY *out, uint8_t *pk,
                                    size_t pk_len)
{
    if (out == NULL || pk == NULL || out->params == NULL
            || pk_len != out->params->pk_len || out->seed == NULL)
        return 0;
    return keygen_internal(out, ML_DSA_KEYGEN_PUB_ONLY, pk, pk_len);
}

/**
 * @brief This is used when a ML DSA key is used for an operation.
 * This checks that the algorithm is the same (i.e. uses the same parameters)
 *
 * @param key A ML_DSA key to use for an operation.
 * @param evp_type The algorithm nid associated with an operation
 *
 * @returns 1 if the algorithm matches, or 0 otherwise.
 */

int ossl_ml_dsa_key_matches(const ML_DSA_KEY *key, int evp_type)
{
    return (key->params->evp_type == evp_type);
}

/* Returns the public key data or NULL if there is no public key */
const uint8_t *ossl_ml_dsa_key_get_pub(const ML_DSA_KEY *key)
{
    return key->pub_encoding;
}

/* Returns the encoded public key size */
size_t ossl_ml_dsa_key_get_pub_len(const ML_DSA_KEY *key)
{
    return key->params->pk_len;
}

size_t ossl_ml_dsa_key_get_collision_strength_bits(const ML_DSA_KEY *key)
{
    return key->params->bit_strength;
}

/* Returns the private key data or NULL if there is no private key */
const uint8_t *ossl_ml_dsa_key_get_priv(const ML_DSA_KEY *key)
{
    return key->priv_encoding;
}

size_t ossl_ml_dsa_key_get_priv_len(const ML_DSA_KEY *key)
{
    return key->params->sk_len;
}

size_t ossl_ml_dsa_key_get_sig_len(const ML_DSA_KEY *key)
{
    return key->params->sig_len;
}

OSSL_LIB_CTX *ossl_ml_dsa_key_get0_libctx(const ML_DSA_KEY *key)
{
    return key != NULL ? key->libctx : NULL;
}

const char *ossl_ml_dsa_key_get_name(const ML_DSA_KEY *key)
{
    return key->params->alg;
}
