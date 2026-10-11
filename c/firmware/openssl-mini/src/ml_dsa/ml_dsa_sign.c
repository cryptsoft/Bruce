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
#include <openssl/rand.h>
#include "ml_dsa_local.h"
#include "ml_dsa_key.h"
#include "ml_dsa_matrix.h"
#include "ml_dsa_hash.h"
#include "pqf_yield.h"

#define ML_DSA_MAX_LAMBDA 256 /* bit strength for ML-DSA-87 */

/*
 * Whether the signing loop expands A a row at a time instead of holding all
 * k * l polynomials.
 *
 * Key generation and verification each multiply by A exactly once, so they
 * always stream - it costs them nothing. Signing multiplies once per
 * rejection iteration (4-5 expected), so streaming there re-runs ExpandA per
 * iteration. What it buys is (k * l - 1) polynomials of heap: 15K at
 * ML-DSA-44, 29K at ML-DSA-65, 55K at ML-DSA-87.
 *
 * PQF_MLDSA_LOWMEM selects the policy:
 *   0  never stream - materialise A for the whole loop (fastest signing)
 *   1  always stream (smallest heap, the default)
 *   2  stream only for parameter sets whose A is at least
 *      ML_DSA_STREAM_A_MIN_POLYS polynomials
 *
 * The default is 1: this is a low-memory library, so it streams everywhere
 * and the memory cost rises monotonically with the parameter set.
 *
 * Policy 2 exists because that is not what a fixed-arena firmware wants. When
 * one arena is sized for the worst case, only the largest set matters, and
 * holding A at the smaller ones is free. It was the default here until the
 * threshold's effect on a general-purpose build was measured: at
 * ML_DSA_STREAM_A_MIN_POLYS=32 it streams at ML-DSA-87 only, because
 * ML-DSA-65's A is 30 polynomials and misses the cutoff by two. That made
 * ML-DSA-65 signing the largest heap figure in the whole library - larger
 * than ML-DSA-87 - with a 46K largest single request against 87's 20K.
 */
#ifndef PQF_MLDSA_LOWMEM
# define PQF_MLDSA_LOWMEM 1
#endif
#ifndef ML_DSA_STREAM_A_MIN_POLYS
# define ML_DSA_STREAM_A_MIN_POLYS 32
#endif

static ossl_inline ossl_unused int
ml_dsa_sign_stream_a(const ML_DSA_PARAMS *params)
{
#if PQF_MLDSA_LOWMEM == 0
    (void)params;
    return 0;
#elif PQF_MLDSA_LOWMEM == 1
    (void)params;
    return 1;
#else
    return params->k * params->l >= ML_DSA_STREAM_A_MIN_POLYS;
#endif
}

/**
 * @brief Compute mu = H(tr || M', 64) without assembling M'.
 *
 * M' is the pure signature encoding 00 || ctx_len || ctx || msg, see FIPS
 * 204 Algorithm 2 Step 10 (and Algorithm 3 Step 5). Its only consumer is
 * this hash, so the pieces are absorbed in order rather than concatenated
 * into a buffer first. On this firmware that buffer was a 1.6 to 2.9 KiB
 * heap allocation, because authenticatorData carries an ML-DSA public key.
 *
 * @param md_ctx A EVP_MD_CTX to hash with
 * @param md A pre-fetched SHAKE256 object
 * @param tr The hash of the encoded public key
 * @param tr_len The size of |tr|
 * @param msg The message to sign or verify
 * @param msg_len The size of |msg|
 * @param ctx An optional context string, at most 255 bytes
 * @param ctx_len The size of |ctx|
 * @param encode Use the pure signature encoding if 1, hash |msg| raw if 0
 * @param mu The returned message representative
 * @param mu_len The size of |mu|
 * @returns 1 on success or 0 on failure.
 */
static int msg_hash(EVP_MD_CTX *md_ctx, const EVP_MD *md,
                    const uint8_t *tr, size_t tr_len,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *ctx, size_t ctx_len, int encode,
                    uint8_t *mu, size_t mu_len)
{
    uint8_t prefix[2];

    if (!EVP_DigestInit_ex2(md_ctx, md, NULL)
            || !EVP_DigestUpdate(md_ctx, tr, tr_len))
        return 0;
    if (encode != 0) {
        prefix[0] = 0;
        prefix[1] = (uint8_t)ctx_len;
        if (!EVP_DigestUpdate(md_ctx, prefix, sizeof(prefix)))
            return 0;
        if (ctx_len != 0 && !EVP_DigestUpdate(md_ctx, ctx, ctx_len))
            return 0;
    }
    return EVP_DigestUpdate(md_ctx, msg, msg_len)
        && EVP_DigestSqueeze(md_ctx, mu, mu_len);
}

/**
 * @brief Fetch one polynomial of s1, s2 or t0 in NTT form.
 *
 * A key made by ossl_ml_dsa_generate_key_for_sign() holds the three private
 * vectors bit-packed, so the polynomial is decoded straight out of that; a
 * key carrying them unpacked is copied from. Either way only the polynomial
 * being consumed is ever in NTT form, so none of the three has to be held as
 * a vector across the rejection loop.
 *
 * @param priv The private key
 * @param which ML_DSA_PRIV_S1, ML_DSA_PRIV_S2 or ML_DSA_PRIV_T0
 * @param idx The index of the polynomial within that vector
 * @param out The returned polynomial, in NTT form
 * @returns 1 on success or 0 on failure.
 */
static int sign_priv_poly_ntt(const ML_DSA_KEY *priv, int which, size_t idx,
                              POLY *out)
{
    if (priv->s_packed != NULL) {
        if (!ossl_ml_dsa_priv_unpack_poly(priv, which, idx, out))
            return 0;
    } else {
        const VECTOR *v;

        switch (which) {
        case ML_DSA_PRIV_S1:
            v = &priv->s1;
            break;
        case ML_DSA_PRIV_S2:
            v = &priv->s2;
            break;
        default:
            v = &priv->t0;
            break;
        }
        if (v->poly == NULL || idx >= v->num_poly)
            return 0;
        memcpy(out, v->poly + idx, sizeof(*out));
    }
    ossl_ml_dsa_poly_ntt(out);
    return 1;
}

/*
 * FIPS 204, Algorithm 7, ML-DSA.Sign_internal()
 * @returns 1 on success and 0 on failure.
 */
static int ml_dsa_sign_internal(const ML_DSA_KEY *priv, int msg_is_mu,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *ctx, size_t ctx_len, int encode,
                                const uint8_t *rnd, size_t rnd_len,
                                uint8_t *out_sig)
{
    int ret = 0;
    const ML_DSA_PARAMS *params = priv->params;
    EVP_MD_CTX *md_ctx = NULL;
    uint32_t k = params->k, l = params->l;
    uint32_t gamma1 = params->gamma1, gamma2 = params->gamma2;
    uint8_t *alloc = NULL, *w1_encoded, *sig_hint;
    size_t alloc_len, w1_encoded_len;
    int stream_a = ml_dsa_sign_stream_a(params);
    size_t num_polys_a = stream_a ? 1 : (size_t)k * l;
    POLY *polys = NULL, *p, *c_ntt, *tmp1, *tmp2;
    VECTOR w, y;
    MATRIX a_ntt;
    uint8_t mu[ML_DSA_MU_BYTES], *mu_ptr = mu;
    const size_t mu_len = sizeof(mu);
    uint8_t rho_prime[ML_DSA_RHO_PRIME_BYTES];
    size_t c_tilde_len = params->bit_strength >> 2;
    size_t kappa;

    /*
     * Allocate a single blob for most of the variable size temporary variables.
     * Mostly used for VECTOR POLYNOMIALS (every POLY is 1K).
     *
     * The rejection loop runs a polynomial at a time, so only y (l) and w (k)
     * are vectors; s1, s2, t0, cs1, cs2, NTT(y), ct0 and the high/low bits of
     * w are all derived at the point of use into c_ntt plus two scratch
     * blocks. That is l + k + 3 polynomials where upstream needs 3l + 4k + 2.
     *
     * c_tilde, z and the hint are not here at all: each is bit-packed into
     * |out_sig| as it is produced, at the offset sigEncode() gives it.
     */
    w1_encoded_len = k * (gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV88 ? 192 : 128);
    alloc_len = w1_encoded_len + sizeof(*polys) * (3 + k + l + num_polys_a);
    alloc = OPENSSL_malloc(alloc_len);
    if (alloc == NULL)
        return 0;
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        goto err;

    w1_encoded = alloc;
    /* c_tilde || z || hint, so the hint follows the l packed z polynomials */
    sig_hint = out_sig + c_tilde_len
        + l * ossl_ml_dsa_sig_z_packed_len(params);
    /* Init the temp vectors to point to the allocated polys blob */
    p = (POLY *)(w1_encoded + w1_encoded_len);
    c_ntt = p++;
    /*
     * Two scratch polynomials. |tmp1| holds NTT(y[col]), then HighBits(w),
     * then c * s1[col] and c * s2[row]; |tmp2| holds LowBits(w - c * s2) and
     * then ct0. None of those is ever needed as a whole vector.
     */
    tmp1 = p++;
    tmp2 = p++;
    if (stream_a)
        matrix_init_stream(&a_ntt, p, k, l, md_ctx, priv->shake128_md,
                           priv->rho);
    else
        matrix_init(&a_ntt, p, k, l);
    p += num_polys_a;
    vector_init(&w, p, k);
    vector_init(&y, p + k, l);
    /* End of the allocated blob setup */

    if (!stream_a
        && !matrix_expand_A(md_ctx, priv->shake128_md, priv->rho, &a_ntt))
        goto err;
    if (msg_is_mu) {
        if (msg_len != mu_len)
            goto err;
        mu_ptr = (uint8_t *)msg;
    } else {
        if (!msg_hash(md_ctx, priv->shake256_md, priv->tr, sizeof(priv->tr),
                      msg, msg_len, ctx, ctx_len, encode, mu_ptr, mu_len))
            goto err;
    }
    if (!shake_xof_3(md_ctx, priv->shake256_md, priv->K, sizeof(priv->K),
                     rnd, rnd_len, mu_ptr, mu_len,
                     rho_prime, sizeof(rho_prime)))
        goto err;

    /*
     * kappa must not exceed 2^16. But the probability of it
     * exceeding even 1000 iterations is vanishingly small.
     */
    for (kappa = 0; ; kappa += l) {
        uint32_t z_max = 0, r0_max = 0, ct0_max = 0;
        size_t col, row, h_ones = 0;

        pqf_yield();                /* one rejection-sampling attempt */

        /*
         * The attempt writes c_tilde, z and the hint into |out_sig| in place,
         * so clear it first: a rejected attempt must not leave any of its
         * bytes behind for the next one, whose hint in particular only writes
         * the index slots it fills.
         */
        memset(out_sig, 0, params->sig_len);

        vector_expand_mask(&y, rho_prime, sizeof(rho_prime), kappa,
                           gamma1, md_ctx, priv->shake256_md);

        /*
         * w = NTT_inverse(A * NTT(y)), accumulated a column at a time. Each
         * column of y is transformed once into |tmp1| and multiplied into
         * every row of w, so NTT(y) is never a whole vector. This runs the
         * same l transforms and k * l matrix elements as the row-outer order
         * does; ExpandA() samples elements independently, so a streaming A
         * is free to be walked in column order.
         */
        vector_zero(&w);
        for (col = 0; col < l; col++) {
            memcpy(tmp1, y.poly + col, sizeof(*tmp1));
            ossl_ml_dsa_poly_ntt(tmp1);
            for (row = 0; row < k; row++) {
                const POLY *a = matrix_get_elem(&a_ntt, row, col);

                if (a == NULL)
                    goto err;
                ossl_ml_dsa_poly_ntt_mult_add(a, tmp1, w.poly + row);
            }
        }
        vector_ntt_inverse(&w);

        if (!ossl_ml_dsa_w1_encode_high_bits(&w, gamma2, tmp1,
                                             w1_encoded, w1_encoded_len))
            goto err;

        /* c_tilde is the first field of the signature, so squeeze it there */
        if (!shake_xof_2(md_ctx, priv->shake256_md, mu_ptr, mu_len,
                         w1_encoded, w1_encoded_len, out_sig, c_tilde_len))
            goto err;

        if (!poly_sample_in_ball_ntt(c_ntt, out_sig, c_tilde_len,
                                     md_ctx, priv->shake256_md, params->tau))
            goto err;
        pqf_yield();                /* after H(mu || w1) and SampleInBall */

        /*
         * z = y + c * s1, a column at a time, formed over the column of y it
         * consumes and bit-packed into its slot in the signature. The next
         * rejection iteration re-expands the whole of y from scratch.
         */
        for (col = 0; col < l; col++) {
            if (!sign_priv_poly_ntt(priv, ML_DSA_PRIV_S1, col, tmp1))
                goto err;
            ossl_ml_dsa_poly_ntt_mult(tmp1, c_ntt, tmp1);
            ossl_ml_dsa_poly_ntt_inverse(tmp1);
            poly_add(y.poly + col, tmp1, y.poly + col);
            poly_max(y.poly + col, &z_max);
            if (!ossl_ml_dsa_sig_encode_z(y.poly + col, params, col, out_sig))
                goto err;
        }

        /*
         * r0 = LowBits(w - c * s2) and the hint both read w[row] and
         * c * s2[row], so they share one row loop and c * s2 stays scratch.
         */
        for (row = 0; row < k; row++) {
            if (!sign_priv_poly_ntt(priv, ML_DSA_PRIV_S2, row, tmp1))
                goto err;
            ossl_ml_dsa_poly_ntt_mult(tmp1, c_ntt, tmp1);
            ossl_ml_dsa_poly_ntt_inverse(tmp1);

            poly_sub(w.poly + row, tmp1, tmp2);
            poly_low_bits(tmp2, gamma2, tmp2);
            poly_max_signed(tmp2, &r0_max);

            if (!sign_priv_poly_ntt(priv, ML_DSA_PRIV_T0, row, tmp2))
                goto err;
            ossl_ml_dsa_poly_ntt_mult(tmp2, c_ntt, tmp2);
            ossl_ml_dsa_poly_ntt_inverse(tmp2);
            ossl_ml_dsa_sig_make_hint(tmp2, tmp1, w.poly + row, gamma2,
                                      params->omega, row, sig_hint, &h_ones);
            poly_max(tmp2, &ct0_max);
        }

        /*
         * Leaking that the signature is rejected is fine as the next attempt at a
         * signature will be (indistinguishable from) independent of this one.
         * Which of the four bounds failed is not leaked: every one of them is
         * accumulated over a whole vector and they are weighed together.
         */
        if (value_barrier_32(constant_time_ge(z_max, gamma1 - params->beta)
                             | constant_time_ge(r0_max, gamma2 - params->beta)
                             | constant_time_ge(ct0_max, gamma2)
                             | constant_time_lt(params->omega,
                                                (uint32_t)h_ones)))
            continue;
        ret = 1;
        break;
    }
err:
    /*
     * The attempts write through |out_sig|, so a failure must not leave a
     * rejected attempt's z behind in the caller's buffer.
     */
    if (ret == 0)
        OPENSSL_cleanse(out_sig, params->sig_len);
    EVP_MD_CTX_free(md_ctx);
    OPENSSL_clear_free(alloc, alloc_len);
    OPENSSL_cleanse(rho_prime, sizeof(rho_prime));
    return ret;
}

/*
 * See FIPS 204, Algorithm 8, ML-DSA.Verify_internal().
 */
static int ml_dsa_verify_internal(const ML_DSA_KEY *pub, int msg_is_mu,
                                  const uint8_t *msg, size_t msg_len,
                                  const uint8_t *ctx, size_t ctx_len,
                                  int encode,
                                  const uint8_t *sig_enc, size_t sig_enc_len)
{
    int ret = 0;
    uint8_t *alloc = NULL, *w1_encoded;
    POLY *polys = NULL, *p, *c_ntt, *tmp;
    MATRIX a_ntt;
    VECTOR w_approx;
    const ML_DSA_PARAMS *params = pub->params;
    uint32_t k = pub->params->k;
    uint32_t l = pub->params->l;
    uint32_t gamma2 = params->gamma2;
    size_t w1_encoded_len;
    /*
     * A is consumed by a single matrix multiply, so it is expanded an element
     * at a time into one scratch block instead of being materialised.
     */
    size_t num_polys_a = 1;
    uint8_t mu[ML_DSA_MU_BYTES], *mu_ptr = mu;
    const size_t mu_len = sizeof(mu);
    uint8_t c_tilde[ML_DSA_MAX_LAMBDA / 4];
    uint8_t hint[ML_DSA_HINT_POLY_BYTES];
    EVP_MD_CTX *md_ctx = NULL;
    size_t c_tilde_len = params->bit_strength >> 2;
    size_t col, row;
    uint32_t z_max = 0;

    /*
     * Allocate space for all the POLYNOMIALS used by temporary VECTORS.
     *
     * Only w_approx (k) is a vector: z and the hint are decoded out of
     * |sig_enc| a row at a time as they are consumed, and c * t1 * 2^d is
     * formed per row in |tmp|. That is k + 3 polynomials where upstream needs
     * 3k + l + 1 and a k * 32 byte hint bitmap.
     */
    w1_encoded_len = k * (gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV88 ? 192 : 128);
    alloc = OPENSSL_malloc(w1_encoded_len
                           + sizeof(*polys) * (2 + k + num_polys_a));
    if (alloc == NULL)
        return 0;
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        goto err;

    w1_encoded = alloc;
    /* Init the temp vectors to point to the allocated polys blob */
    p = (POLY *)(w1_encoded + w1_encoded_len);
    c_ntt = p++;
    tmp = p++;
    matrix_init_stream(&a_ntt, p, k, l, md_ctx, pub->shake128_md, pub->rho);
    p += num_polys_a;
    vector_init(&w_approx, p, k);

    /*
     * sigDecode() consumed the whole encoding and required it to end exactly,
     * so the length is checked here instead.
     */
    if (sig_enc_len != params->sig_len)
        goto err;
    if (msg_is_mu) {
        if (msg_len != mu_len)
            goto err;
        mu_ptr = (uint8_t *)msg;
    } else {
        if (!msg_hash(md_ctx, pub->shake256_md, pub->tr, sizeof(pub->tr),
                      msg, msg_len, ctx, ctx_len, encode, mu_ptr, mu_len))
            goto err;
    }
    /* Compute verifiers challenge c_ntt = NTT(SampleInBall(c_tilde) */
    if (!poly_sample_in_ball_ntt(c_ntt, sig_enc, c_tilde_len,
                                 md_ctx, pub->shake256_md, params->tau))
        goto err;

    /*
     * A * NTT(z), accumulated a column at a time so that z is only ever one
     * polynomial: each column is decoded into |tmp|, weighed into the
     * ||z||inf bound, transformed and multiplied into every row.
     */
    vector_zero(&w_approx);
    for (col = 0; col < l; col++) {
        if (!ossl_ml_dsa_sig_decode_z(tmp, params, col, sig_enc))
            goto err;
        poly_max(tmp, &z_max);
        ossl_ml_dsa_poly_ntt(tmp);
        for (row = 0; row < k; row++) {
            const POLY *a = matrix_get_elem(&a_ntt, row, col);

            if (a == NULL)
                goto err;
            ossl_ml_dsa_poly_ntt_mult_add(a, tmp, w_approx.poly + row);
        }
    }

    /*
     * w1 = UseHint(h, NTT_inverse(A * NTT(z) - NTT(c) * NTT(t1 * 2^d))), a
     * row at a time over w_approx, encoding each row as it is finished.
     */
    for (row = 0; row < k; row++) {
        poly_scale_power2_round(pub->t1.poly + row, tmp);
        ossl_ml_dsa_poly_ntt(tmp);
        ossl_ml_dsa_poly_ntt_mult(tmp, c_ntt, tmp);
        poly_sub(w_approx.poly + row, tmp, w_approx.poly + row);
        ossl_ml_dsa_poly_ntt_inverse(w_approx.poly + row);

        if (!ossl_ml_dsa_sig_decode_h_row(hint, params, row, sig_enc))
            goto err;
        poly_use_hint(hint, w_approx.poly + row, gamma2, w_approx.poly + row);
        if (!ossl_ml_dsa_w1_encode_poly(w_approx.poly + row, gamma2, row,
                                        w1_encoded, w1_encoded_len))
            goto err;
    }

    if (!shake_xof_3(md_ctx, pub->shake256_md, mu_ptr, mu_len,
                     w1_encoded, w1_encoded_len, NULL, 0, c_tilde, c_tilde_len))
        goto err;

    ret = (z_max < (uint32_t)(params->gamma1 - params->beta))
        && memcmp(c_tilde, sig_enc, c_tilde_len) == 0;
err:
    OPENSSL_free(alloc);
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

/**
 * See FIPS 204 Section 5.2 Algorithm 2 ML-DSA.Sign()
 *
 * @returns 1 on success, or 0 on error.
 */
int ossl_ml_dsa_sign(const ML_DSA_KEY *priv, int msg_is_mu,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *context, size_t context_len,
                     const uint8_t *rand, size_t rand_len, int encode,
                     unsigned char *sig, size_t *sig_len, size_t sig_size)
{
    int ret = 1;

    /*
     * Signing consumes the private vectors, not the encoded private key, so
     * test for what it actually reads: either the unpacked s1 or the packed
     * form a key generated by ossl_ml_dsa_generate_key_for_sign() carries.
     * A prekey holding only an encoding has neither.
     */
    if (priv->s1.poly == NULL && priv->s_packed == NULL)
        return 0;
    if (sig != NULL) {
        if (sig_size < priv->params->sig_len)
            return 0;
        if (!msg_is_mu && encode != 0
                && context_len > ML_DSA_MAX_CONTEXT_STRING_LEN)
            return 0;
        ret = ml_dsa_sign_internal(priv, msg_is_mu, msg, msg_len,
                                   context, context_len, encode,
                                   rand, rand_len, sig);
    }
    if (sig_len != NULL)
        *sig_len = priv->params->sig_len;
    return ret;
}

/**
 * See FIPS 203 Section 5.3 Algorithm 3 ML-DSA.Verify()
 * @returns 1 on success, or 0 on error.
 */
int ossl_ml_dsa_verify(const ML_DSA_KEY *pub, int msg_is_mu,
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t *context, size_t context_len, int encode,
                       const uint8_t *sig, size_t sig_len)
{
    if (ossl_ml_dsa_key_get_pub(pub) == NULL)
        return 0;
    if (!msg_is_mu && encode != 0
            && context_len > ML_DSA_MAX_CONTEXT_STRING_LEN)
        return 0;

    return ml_dsa_verify_internal(pub, msg_is_mu, msg, msg_len,
                                  context, context_len, encode, sig, sig_len);
}
