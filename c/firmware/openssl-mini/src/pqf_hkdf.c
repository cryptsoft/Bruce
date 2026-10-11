/* pqf_hkdf.c -- HKDF-SHA-256 (RFC 5869) on top of pqf HMAC-SHA-256.
 *
 * CTAP 2.1 PIN/UV protocol v2 (sec. 6.5.6) derives two independent keys
 * from the ECDH shared X-coordinate:
 *
 *     PRK     = HKDF-Extract(salt = 32 zero bytes, IKM = Z)
 *     AESkey  = HKDF-Expand(PRK, "CTAP2 AES key",  32)
 *     HMACkey = HKDF-Expand(PRK, "CTAP2 HMAC key", 32)
 *
 * Project-original C derived from RFC 5869 sec. 2; the HMAC underneath is
 * the vendored / pqf SHA-256 HMAC.
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

#define HASH_LEN  32

void pqf_hkdf_extract(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len,
                      uint8_t prk[32])
{
    static const uint8_t zero_salt[HASH_LEN] = { 0 };
    if (salt == NULL || salt_len == 0) {
        salt = zero_salt;
        salt_len = HASH_LEN;
    }
    /* PRK = HMAC(salt, IKM). */
    pqf_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int pqf_hkdf_expand(const uint8_t prk[32],
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len)
{
    if (out_len > 255u * HASH_LEN)
        return -1;

    uint8_t t[HASH_LEN];
    size_t  t_len = 0;        /* 0 for the first round (T(0) is empty) */
    uint8_t counter = 1;
    size_t  done = 0;

    while (done < out_len) {
        /* T(i) = HMAC(PRK, T(i-1) || info || i). */
        pqf_hmac_sha256_ctx_t hc;
        pqf_hmac_sha256_init(&hc, prk, HASH_LEN);
        if (t_len)
            pqf_hmac_sha256_update(&hc, t, t_len);
        if (info_len)
            pqf_hmac_sha256_update(&hc, info, info_len);
        pqf_hmac_sha256_update(&hc, &counter, 1);
        pqf_hmac_sha256_final(&hc, t);
        t_len = HASH_LEN;

        size_t take = out_len - done;
        if (take > HASH_LEN) take = HASH_LEN;
        memcpy(out + done, t, take);
        done += take;
        counter++;
    }

    memset(t, 0, sizeof t);
    return 0;
}
