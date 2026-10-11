/* test_hmac_sha256.c -- host-side unit tests for pqf_hmac_sha256.
 *
 * Test vectors are RFC 4231 sec. 4, the canonical HMAC-SHA-256 known
 * answer set every implementation since 2005 has used. The vectors
 * exercise:
 *
 *   - short key + short message (TC 1)
 *   - key shorter than block, longer message (TC 2)
 *   - all-byte-value-0xdd 50-byte message (TC 3)
 *   - 25-byte key, 50-byte message (TC 4)
 *   - keys longer than the SHA-256 block size, requiring rehash (TC 6, 7)
 *
 * Plus streaming-consistency checks: one-shot, byte-by-byte, and
 * mid-message chunks should all produce the same MAC.
 *
 * Copyright 2026 Cryptsoft Pty Ltd
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "pqf_crypto.h"

static int fails = 0;

static int hex_eq(const uint8_t *got, const char *expect_hex,
                  size_t bytes)
{
    char buf[128];
    for (size_t i = 0; i < bytes; i++) {
        snprintf(&buf[i * 2], sizeof buf - i * 2, "%02x", got[i]);
    }
    return strcmp(buf, expect_hex) == 0;
}

static void check(const char *label,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *msg, size_t msg_len,
                   const char *expect_hex)
{
    uint8_t out[32];
    pqf_hmac_sha256(key, key_len, msg, msg_len, out);
    if (!hex_eq(out, expect_hex, 32)) {
        char hex[65];
        for (int i = 0; i < 32; i++) {
            snprintf(&hex[i * 2], sizeof hex - i * 2, "%02x", out[i]);
        }
        fprintf(stderr,
                "FAIL %s\n  expected %s\n  got      %s\n",
                label, expect_hex, hex);
        fails++;
        return;
    }
    printf("  ok: %s\n", label);
}

/* Streaming check: hash the message in chunks of `chunk`, ensure
 * the result matches one-shot. */
static void check_streaming(const char *label,
                             const uint8_t *key, size_t key_len,
                             const uint8_t *msg, size_t msg_len,
                             size_t chunk,
                             const char *expect_hex)
{
    pqf_hmac_sha256_ctx_t ctx;
    uint8_t out[32];
    pqf_hmac_sha256_init(&ctx, key, key_len);
    for (size_t off = 0; off < msg_len; off += chunk) {
        size_t take = (msg_len - off < chunk) ? (msg_len - off) : chunk;
        pqf_hmac_sha256_update(&ctx, &msg[off], take);
    }
    pqf_hmac_sha256_final(&ctx, out);
    if (!hex_eq(out, expect_hex, 32)) {
        char hex[65];
        for (int i = 0; i < 32; i++) {
            snprintf(&hex[i * 2], sizeof hex - i * 2, "%02x", out[i]);
        }
        fprintf(stderr,
                "FAIL %s (chunk=%zu)\n  expected %s\n  got      %s\n",
                label, chunk, expect_hex, hex);
        fails++;
        return;
    }
    printf("  ok: %s (chunk=%zu)\n", label, chunk);
}

int main(void)
{
    printf("pqf_hmac_sha256 host tests (RFC 4231)\n");

    /* TC 1: K = 0x0b * 20, M = "Hi There" */
    {
        uint8_t key[20]; memset(key, 0x0b, 20);
        const char *msg = "Hi There";
        const char *expect =
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7";
        check("TC1",
              key, 20, (const uint8_t *)msg, strlen(msg), expect);
        check_streaming("TC1 stream c=1",
                        key, 20, (const uint8_t *)msg, strlen(msg),
                        1, expect);
    }

    /* TC 2: K = "Jefe", M = "what do ya want for nothing?" */
    {
        const char *key = "Jefe";
        const char *msg = "what do ya want for nothing?";
        const char *expect =
            "5bdcc146bf60754e6a042426089575c7"
            "5a003f089d2739839dec58b964ec3843";
        check("TC2",
              (const uint8_t *)key, strlen(key),
              (const uint8_t *)msg, strlen(msg), expect);
        check_streaming("TC2 stream c=3",
                        (const uint8_t *)key, strlen(key),
                        (const uint8_t *)msg, strlen(msg),
                        3, expect);
    }

    /* TC 3: K = 0xaa * 20, M = 0xdd * 50 */
    {
        uint8_t key[20]; memset(key, 0xaa, 20);
        uint8_t msg[50]; memset(msg, 0xdd, 50);
        const char *expect =
            "773ea91e36800e46854db8ebd09181a7"
            "2959098b3ef8c122d9635514ced565fe";
        check("TC3", key, 20, msg, 50, expect);
    }

    /* TC 4: K = 0x01..0x19 (25 bytes), M = 0xcd * 50 */
    {
        uint8_t key[25];
        for (int i = 0; i < 25; i++) key[i] = (uint8_t)(i + 1);
        uint8_t msg[50]; memset(msg, 0xcd, 50);
        const char *expect =
            "82558a389a443c0ea4cc819899f2083a"
            "85f0faa3e578f8077a2e3ff46729665b";
        check("TC4", key, 25, msg, 50, expect);
    }

    /* TC 6: K = 0xaa * 131 (> block), M = "Test Using Larger Than Block-Size Key - Hash Key First" */
    {
        uint8_t key[131]; memset(key, 0xaa, 131);
        const char *msg =
            "Test Using Larger Than Block-Size Key - Hash Key First";
        const char *expect =
            "60e431591ee0b67f0d8a26aacbf5b77f"
            "8e0bc6213728c5140546040f0ee37f54";
        check("TC6 (key>block)",
              key, 131, (const uint8_t *)msg, strlen(msg), expect);
    }

    /* TC 7: K = 0xaa * 131, long message */
    {
        uint8_t key[131]; memset(key, 0xaa, 131);
        const char *msg =
            "This is a test using a larger than block-size key and a "
            "larger than block-size data. The key needs to be hashed "
            "before being used by the HMAC algorithm.";
        const char *expect =
            "9b09ffa71b942fcb27635fbcd5b0e944"
            "bfdc63644f0713938a7f51535c3a35e2";
        check("TC7 (key>block, long msg)",
              key, 131, (const uint8_t *)msg, strlen(msg), expect);
    }

    /* Streaming consistency: random-looking 1 KiB message, one-shot vs
     * byte-by-byte vs chunks of 17 -- all three MACs must agree. */
    {
        uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        uint8_t msg[1024];
        for (size_t i = 0; i < sizeof msg; i++) {
            msg[i] = (uint8_t)(i * 31 + 7);
        }
        uint8_t a[32], b[32], c[32];

        pqf_hmac_sha256(key, sizeof key, msg, sizeof msg, a);

        pqf_hmac_sha256_ctx_t ctx;
        pqf_hmac_sha256_init(&ctx, key, sizeof key);
        for (size_t i = 0; i < sizeof msg; i++) {
            pqf_hmac_sha256_update(&ctx, &msg[i], 1);
        }
        pqf_hmac_sha256_final(&ctx, b);

        pqf_hmac_sha256_init(&ctx, key, sizeof key);
        for (size_t off = 0; off < sizeof msg; off += 17) {
            size_t take = (sizeof msg - off < 17)
                            ? (sizeof msg - off) : 17;
            pqf_hmac_sha256_update(&ctx, &msg[off], take);
        }
        pqf_hmac_sha256_final(&ctx, c);

        if (memcmp(a, b, 32) != 0 || memcmp(a, c, 32) != 0) {
            fprintf(stderr,
                    "FAIL streaming consistency: 1 KiB MAC differs "
                    "across one-shot / byte / 17-chunk paths\n");
            fails++;
        } else {
            printf("  ok: streaming consistency (1 KiB)\n");
        }
    }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
