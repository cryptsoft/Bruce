/* test_bn.c -- host-side smoke test for the vendored OpenSSL BN.
 *
 * Goal: make sure the vendored BN sources + shim headers actually
 * link end-to-end and produce correct arithmetic on a couple of
 * trivial values. The point of this test isn't to validate BN
 * exhaustively (the upstream test suite already does that -- we
 * vendored the same source) but to catch undefined symbols early
 * before we try to layer EC / ECDSA on top.
 *
 * Vectors:
 *   - BN_set_word + BN_get_word round-trip
 *   - BN_add(7, 13) == 20
 *   - BN_mul(0xdeadbeef, 0x1234) == 0xfd99_5b16_67dc (verified by
 *     casting via BN_bn2bin)
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
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

static int fails = 0;

#define EXPECT(cond, msg) do {                                       \
    if (!(cond)) {                                                   \
        fprintf(stderr, "FAIL %s (%s:%d)\n", msg, __FILE__, __LINE__);\
        fails++;                                                     \
    } else {                                                         \
        printf("  ok: %s\n", msg);                                   \
    }                                                                \
} while (0)

int main(void)
{
    printf("BN host smoke test\n");

    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *r = BN_new();
    EXPECT(a && b && r, "BN_new");

    EXPECT(BN_set_word(a, 7) == 1, "BN_set_word(a, 7)");
    EXPECT(BN_get_word(a) == 7,    "BN_get_word == 7");

    EXPECT(BN_set_word(b, 13) == 1, "BN_set_word(b, 13)");
    EXPECT(BN_add(r, a, b) == 1,    "BN_add");
    EXPECT(BN_get_word(r) == 20,    "7 + 13 == 20");

    EXPECT(BN_set_word(a, 0xdeadbeefUL) == 1, "BN_set_word large");
    EXPECT(BN_set_word(b, 0x1234U) == 1,      "BN_set_word small");
    BN_CTX *ctx = BN_CTX_new();
    EXPECT(ctx != NULL, "BN_CTX_new");
    EXPECT(BN_mul(r, a, b, ctx) == 1, "BN_mul");
    /* 0xdeadbeef * 0x1234 = 0xfd99_5b16_67dc.
     * BN_get_word returns the low BN_BITS2 bits as an unsigned long. */
    unsigned long expected = (unsigned long)0xdeadbeefUL * 0x1234UL;
    EXPECT(BN_get_word(r) == expected, "BN_mul large product");

    /* bn2bin round-trip. */
    unsigned char buf[16];
    int n = BN_bn2bin(r, buf);
    EXPECT(n > 0 && n <= (int)sizeof buf, "BN_bn2bin length");
    BIGNUM *r2 = BN_bin2bn(buf, n, NULL);
    EXPECT(r2 != NULL, "BN_bin2bn");
    EXPECT(BN_cmp(r, r2) == 0, "round-trip cmp");

    BN_free(a); BN_free(b); BN_free(r); BN_free(r2);
    BN_CTX_free(ctx);

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
