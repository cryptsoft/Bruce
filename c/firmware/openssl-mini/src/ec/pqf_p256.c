/* pqf_p256.c -- pqf_* P-256 wrapper (ECDSA + ECDH) over the vendored
 * OpenSSL EC stack.
 *
 * Exposes the four operations the FIDO firmware needs in terms of
 * raw byte buffers (32-byte scalars / coordinates, DER signatures),
 * keeping the EC_KEY / EC_GROUP / BIGNUM spellings contained here.
 * The heavy lifting (curve arithmetic, ECDSA, ECDH) is the vendored
 * Apache-2.0 OpenSSL code in this directory; this file is the
 * project-original Apache-2.0 adapter.
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

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "ec_local.h"

/* ECDSA_do_sign / ECDSA_do_verify operate on ECDSA_SIG objects; the
 * vendored ecdsa_ossl.c implements them via the EC_KEY method. We
 * declare them here (they're in ec.h under the deprecation-gated
 * block, which is visible in our build). */

/* ---- Helpers --------------------------------------------------- */

/* Build a fresh P-256 EC_GROUP. Cached would be nice, but the
 * firmware does few EC ops and a static cache complicates the
 * single-core/dual-core story; build per call for now. */
static EC_GROUP *p256_group(void)
{
    return EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
}

/* Write a BIGNUM into a fixed 32-byte big-endian buffer, left-
 * padding with zeros. Returns 0 on success, <0 if it doesn't fit. */
static int bn_to_32(const BIGNUM *v, uint8_t out[32])
{
    int n = BN_num_bytes(v);
    if (n < 0 || n > 32)
        return -1;
    memset(out, 0, 32);
    BN_bn2bin(v, out + (32 - n));
    return 0;
}

/* ---- Key generation / public derivation ----------------------- */

int pqf_p256_keygen(uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32])
{
    int rc = -1;
    EC_GROUP *group = NULL;
    EC_KEY   *key   = NULL;
    BIGNUM   *x = NULL, *y = NULL;

    group = p256_group();
    if (group == NULL) goto out;
    key = EC_KEY_new();
    if (key == NULL || EC_KEY_set_group(key, group) != 1) goto out;
    if (EC_KEY_generate_key(key) != 1) goto out;

    x = BN_new(); y = BN_new();
    if (x == NULL || y == NULL) goto out;
    if (EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(key),
                                        x, y, NULL) != 1)
        goto out;
    if (bn_to_32(EC_KEY_get0_private_key(key), priv) != 0) goto out;
    if (bn_to_32(x, pub_x) != 0 || bn_to_32(y, pub_y) != 0) goto out;
    rc = 0;

out:
    BN_free(x); BN_free(y);
    EC_KEY_free(key);
    EC_GROUP_free(group);
    return rc;
}

int pqf_p256_derive_public(const uint8_t priv[32],
                           uint8_t pub_x[32], uint8_t pub_y[32])
{
    int rc = -1;
    EC_GROUP *group = NULL;
    EC_POINT *pub   = NULL;
    BIGNUM   *d = NULL, *x = NULL, *y = NULL;

    group = p256_group();
    if (group == NULL) goto out;
    d = BN_bin2bn(priv, 32, NULL);
    if (d == NULL) goto out;
    pub = EC_POINT_new(group);
    if (pub == NULL) goto out;
    /* pub = d * G */
    if (EC_POINT_mul(group, pub, d, NULL, NULL, NULL) != 1) goto out;
    x = BN_new(); y = BN_new();
    if (x == NULL || y == NULL) goto out;
    if (EC_POINT_get_affine_coordinates(group, pub, x, y, NULL) != 1)
        goto out;
    if (bn_to_32(x, pub_x) != 0 || bn_to_32(y, pub_y) != 0) goto out;
    rc = 0;

out:
    BN_clear_free(d);
    BN_free(x); BN_free(y);
    EC_POINT_free(pub);
    EC_GROUP_free(group);
    return rc;
}

/* Build an EC_KEY from a raw private scalar (public point derived). */
static EC_KEY *key_from_priv(const uint8_t priv[32])
{
    EC_GROUP *group = p256_group();
    EC_KEY   *key   = NULL;
    BIGNUM   *d     = NULL;
    EC_POINT *pub   = NULL;

    if (group == NULL) goto fail;
    key = EC_KEY_new();
    if (key == NULL || EC_KEY_set_group(key, group) != 1) goto fail;
    d = BN_bin2bn(priv, 32, NULL);
    if (d == NULL || EC_KEY_set_private_key(key, d) != 1) goto fail;
    pub = EC_POINT_new(group);
    if (pub == NULL || EC_POINT_mul(group, pub, d, NULL, NULL, NULL) != 1)
        goto fail;
    if (EC_KEY_set_public_key(key, pub) != 1) goto fail;

    BN_clear_free(d);
    EC_POINT_free(pub);
    EC_GROUP_free(group);
    return key;

fail:
    BN_clear_free(d);
    EC_POINT_free(pub);
    EC_KEY_free(key);
    EC_GROUP_free(group);
    return NULL;
}

/* Build a public-only EC_KEY from affine coordinates. */
static EC_KEY *key_from_pub(const uint8_t pub_x[32], const uint8_t pub_y[32])
{
    EC_GROUP *group = p256_group();
    EC_KEY   *key   = NULL;
    BIGNUM   *x = NULL, *y = NULL;
    EC_POINT *pub = NULL;

    if (group == NULL) goto fail;
    key = EC_KEY_new();
    if (key == NULL || EC_KEY_set_group(key, group) != 1) goto fail;
    x = BN_bin2bn(pub_x, 32, NULL);
    y = BN_bin2bn(pub_y, 32, NULL);
    if (x == NULL || y == NULL) goto fail;
    pub = EC_POINT_new(group);
    if (pub == NULL) goto fail;
    if (EC_POINT_set_affine_coordinates(group, pub, x, y, NULL) != 1)
        goto fail;
    if (EC_KEY_set_public_key(key, pub) != 1) goto fail;

    BN_free(x); BN_free(y);
    EC_POINT_free(pub);
    EC_GROUP_free(group);
    return key;

fail:
    BN_free(x); BN_free(y);
    EC_POINT_free(pub);
    EC_KEY_free(key);
    EC_GROUP_free(group);
    return NULL;
}

/* ---- ECDSA ----------------------------------------------------- */

int pqf_ecdsa_p256_sign(const uint8_t priv[32], const uint8_t hash[32],
                        uint8_t *sig_der, size_t *sig_len)
{
    int rc = -1;
    EC_KEY *key = key_from_priv(priv);
    if (key == NULL) return -1;

    /* Hedged nonce, not a plain random one: a non-NULL digest with
     * nonce_type == 0 sends ecdsa_ossl.c down
     * ossl_bn_gen_dsa_nonce_fixed_top(), a SHA-512 chain over the padded
     * private key, 64 fresh RAND_priv_bytes and this digest. k still
     * varies per call; the RNG is hedged, not removed. */
    ECDSA_SIG *sig = ECDSA_do_sign(hash, 32, key);
    if (sig == NULL) goto out;

    unsigned char *p = sig_der;
    int n = i2d_ECDSA_SIG(sig, &p);
    if (n <= 0) goto out;
    *sig_len = (size_t)n;
    rc = 0;

out:
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    return rc;
}

int pqf_ecdsa_p256_verify(const uint8_t pub_x[32], const uint8_t pub_y[32],
                          const uint8_t hash[32],
                          const uint8_t *sig_der, size_t sig_len)
{
    EC_KEY *key = key_from_pub(pub_x, pub_y);
    if (key == NULL) return -1;

    const unsigned char *p = sig_der;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)sig_len);
    int rc;
    if (sig == NULL) {
        rc = -1;
    } else {
        /* ECDSA_do_verify -> 1 valid, 0 invalid, -1 error. */
        rc = ECDSA_do_verify(hash, 32, sig, key);
    }
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    return rc;
}

/* ---- ECDH ------------------------------------------------------ */

int pqf_ecdh_p256(const uint8_t priv[32],
                  const uint8_t peer_x[32], const uint8_t peer_y[32],
                  uint8_t shared_x[32])
{
    int rc = -1;
    EC_GROUP *group = NULL;
    BIGNUM   *d = NULL, *x = NULL, *y = NULL, *sx = NULL;
    EC_POINT *peer = NULL, *shared = NULL;

    group = p256_group();
    if (group == NULL) goto out;
    d = BN_bin2bn(priv, 32, NULL);
    x = BN_bin2bn(peer_x, 32, NULL);
    y = BN_bin2bn(peer_y, 32, NULL);
    if (d == NULL || x == NULL || y == NULL) goto out;

    peer = EC_POINT_new(group);
    shared = EC_POINT_new(group);
    if (peer == NULL || shared == NULL) goto out;
    if (EC_POINT_set_affine_coordinates(group, peer, x, y, NULL) != 1)
        goto out;
    /* shared = d * peer */
    if (EC_POINT_mul(group, shared, NULL, peer, d, NULL) != 1) goto out;

    sx = BN_new();
    if (sx == NULL) goto out;
    if (EC_POINT_get_affine_coordinates(group, shared, sx, NULL, NULL) != 1)
        goto out;
    if (bn_to_32(sx, shared_x) != 0) goto out;
    rc = 0;

out:
    BN_clear_free(d);
    BN_free(x); BN_free(y); BN_clear_free(sx);
    EC_POINT_free(peer);
    EC_POINT_free(shared);
    EC_GROUP_free(group);
    return rc;
}
