/* test_sha256.c -- host-side unit tests for pqf_sha256.
 *
 * Test vectors are FIPS 180-2 Appendix A (the canonical SHA-256
 * reference vectors that every implementation since 2002 has used)
 * plus a few edge cases that exercise the streaming API:
 *
 *   1. ""                       -- empty input
 *   2. "abc"                    -- 3 bytes
 *   3. "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 *                                -- 56-byte string straddling the
 *                                  block boundary
 *   4. one million 'a' bytes    -- exercises multi-block updates
 *
 * Build via the Makefile in this directory; the test program is
 * standalone host C and doesn't pull in any pico-sdk dependencies.
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

static void check_oneshot(const char *label,
                          const uint8_t *data, size_t len,
                          const char *expect_hex)
{
    uint8_t out[32];
    pqf_sha256(data, len, out);
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

static void check_streaming(const char *label,
                            const uint8_t *data, size_t len,
                            size_t chunk,
                            const char *expect_hex)
{
    pqf_sha256_ctx_t ctx;
    uint8_t out[32];
    pqf_sha256_init(&ctx);
    for (size_t off = 0; off < len; off += chunk) {
        size_t take = (len - off < chunk) ? (len - off) : chunk;
        pqf_sha256_update(&ctx, &data[off], take);
    }
    pqf_sha256_final(&ctx, out);
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
    printf("pqf_sha256 host tests\n");

    /* Vector 1: empty input. */
    {
        const char *expect =
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855";
        check_oneshot("empty",
                      (const uint8_t *)"", 0, expect);
        check_streaming("empty stream",
                        (const uint8_t *)"", 0, 1, expect);
    }

    /* Vector 2: "abc". */
    {
        const char *expect =
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad";
        check_oneshot("abc",
                      (const uint8_t *)"abc", 3, expect);
        check_streaming("abc stream 1",
                        (const uint8_t *)"abc", 3, 1, expect);
        check_streaming("abc stream 2",
                        (const uint8_t *)"abc", 3, 2, expect);
    }

    /* Vector 3: 56-byte FIPS string (the alphabet straddling block
     * boundary). */
    {
        const char *msg =
            "abcdbcdecdefdefgefghfghighijhijk"
            "ijkljklmklmnlmnomnopnopq";
        const char *expect =
            "248d6a61d20638b8e5c026930c3e6039"
            "a33ce45964ff2167f6ecedd419db06c1";
        check_oneshot("FIPS-56-byte",
                      (const uint8_t *)msg, 56, expect);
        check_streaming("FIPS-56-byte chunk 7",
                        (const uint8_t *)msg, 56, 7, expect);
        check_streaming("FIPS-56-byte chunk 63",
                        (const uint8_t *)msg, 56, 63, expect);
    }

    /* Vector 4: one million 'a' bytes. */
    {
        static uint8_t aaa[1000000];
        memset(aaa, 'a', sizeof aaa);
        const char *expect =
            "cdc76e5c9914fb9281a1c7e284d73e67"
            "f1809a48a497200e046d39ccc7112cd0";
        check_oneshot("1M-a", aaa, sizeof aaa, expect);
        check_streaming("1M-a chunk 64", aaa, sizeof aaa, 64, expect);
        check_streaming("1M-a chunk 1023", aaa, sizeof aaa, 1023, expect);
        check_streaming("1M-a chunk 65537",
                        aaa, sizeof aaa, 65537, expect);
    }

    /* Vector 5: byte-by-byte streaming consistency. Hash 1024 random-
     * looking bytes one byte at a time, then in chunks of 17, then
     * all-at-once, and ensure all three agree. */
    {
        uint8_t buf[1024];
        for (size_t i = 0; i < sizeof buf; i++) {
            buf[i] = (uint8_t)(i * 31 + 7);
        }
        uint8_t a[32], b[32], c[32];
        pqf_sha256(buf, sizeof buf, a);

        pqf_sha256_ctx_t ctx;
        pqf_sha256_init(&ctx);
        for (size_t i = 0; i < sizeof buf; i++) {
            pqf_sha256_update(&ctx, &buf[i], 1);
        }
        pqf_sha256_final(&ctx, b);

        pqf_sha256_init(&ctx);
        for (size_t off = 0; off < sizeof buf; off += 17) {
            size_t take = (sizeof buf - off < 17)
                            ? (sizeof buf - off) : 17;
            pqf_sha256_update(&ctx, &buf[off], take);
        }
        pqf_sha256_final(&ctx, c);

        if (memcmp(a, b, 32) != 0 || memcmp(a, c, 32) != 0) {
            fprintf(stderr,
                    "FAIL streaming-consistency: "
                    "one-shot vs byte-by-byte vs 17-byte chunks differ\n");
            fails++;
        } else {
            printf("  ok: streaming consistency (1KB)\n");
        }
    }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
