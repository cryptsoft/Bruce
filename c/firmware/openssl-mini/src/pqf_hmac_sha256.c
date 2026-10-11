/* pqf_hmac_sha256.c -- HMAC-SHA-256 per RFC 2104, on top of the
 * vendored SHA-256.
 *
 * Reference: RFC 2104 sec. 2 "Definition of HMAC".
 *
 *   HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
 *
 * where:
 *   - H = SHA-256, block size B = 64, output size L = 32.
 *   - K' = K, padded with zeros to B, if |K| <= B; or H(K) padded
 *          with zeros to B, if |K| > B.
 *   - ipad = 0x36 repeated B times.
 *   - opad = 0x5c repeated B times.
 *
 * The implementation is project-original C, derived from RFC 2104
 * alone -- no code copied from OpenSSL's `crypto/hmac/hmac.c` (which
 * is heavily EVP-wrapped and pulls a wider dependency surface than
 * we want for the firmware).
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
#include <openssl/crypto.h>   /* OPENSSL_cleanse */

#define BLOCK_SIZE  PQF_SHA256_BLOCK_LEN    /* 64 */
#define DIGEST_SIZE PQF_SHA256_DIGEST_LEN   /* 32 */

/* Reduce an arbitrary-length key to a B-byte buffer per RFC 2104:
 *   - keys longer than B are hashed first
 *   - shorter keys are zero-padded on the right
 * Result is written into `out` which the caller sized to B bytes. */
static void normalise_key(const uint8_t *key, size_t key_len,
                          uint8_t out[BLOCK_SIZE])
{
    memset(out, 0, BLOCK_SIZE);
    if (key_len > BLOCK_SIZE) {
        pqf_sha256(key, key_len, out);
        /* H output is 32 bytes; remaining 32 bytes are already 0. */
    } else if (key_len > 0) {
        memcpy(out, key, key_len);
    }
}

void pqf_hmac_sha256_init(pqf_hmac_sha256_ctx_t *ctx,
                           const uint8_t *key, size_t key_len)
{
    uint8_t k_prime[BLOCK_SIZE];
    uint8_t i_key_pad[BLOCK_SIZE];

    normalise_key(key, key_len, k_prime);

    /* Build i_key_pad = K' XOR ipad (0x36...) and o_key_pad =
     * K' XOR opad (0x5c...). The constants are bit-disjoint
     * (0x36 ^ 0x5c = 0x6a) so they buy us domain separation
     * between the inner and outer hash invocations. */
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        i_key_pad[i]      = k_prime[i] ^ 0x36;
        ctx->o_key_pad[i] = k_prime[i] ^ 0x5c;
    }

    /* Start the inner hash with i_key_pad already absorbed; the
     * message bytes follow on update(). */
    pqf_sha256_init(&ctx->inner);
    pqf_sha256_update(&ctx->inner, i_key_pad, BLOCK_SIZE);

    /* Wipe the intermediate buffers. K' is the most sensitive -- a
     * leaked K' is equivalent to the key itself. */
    OPENSSL_cleanse(k_prime,   sizeof k_prime);
    OPENSSL_cleanse(i_key_pad, sizeof i_key_pad);
}

void pqf_hmac_sha256_update(pqf_hmac_sha256_ctx_t *ctx,
                             const uint8_t *data, size_t len)
{
    pqf_sha256_update(&ctx->inner, data, len);
}

void pqf_hmac_sha256_final(pqf_hmac_sha256_ctx_t *ctx, uint8_t out[32])
{
    uint8_t inner_digest[DIGEST_SIZE];
    pqf_sha256_ctx_t outer;

    /* Inner hash -> H((K' XOR ipad) || m). */
    pqf_sha256_final(&ctx->inner, inner_digest);

    /* Outer hash -> H((K' XOR opad) || inner_digest). */
    pqf_sha256_init(&outer);
    pqf_sha256_update(&outer, ctx->o_key_pad, BLOCK_SIZE);
    pqf_sha256_update(&outer, inner_digest, DIGEST_SIZE);
    pqf_sha256_final(&outer, out);

    /* Wipe everything that could leak key material. */
    OPENSSL_cleanse(ctx->o_key_pad, sizeof ctx->o_key_pad);
    OPENSSL_cleanse(inner_digest,   sizeof inner_digest);
    OPENSSL_cleanse(&outer,         sizeof outer);
}

void pqf_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t out[32])
{
    pqf_hmac_sha256_ctx_t ctx;
    pqf_hmac_sha256_init  (&ctx, key, key_len);
    pqf_hmac_sha256_update(&ctx, msg, msg_len);
    pqf_hmac_sha256_final (&ctx, out);
}
