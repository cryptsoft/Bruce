/* host_rand_stub.c -- host-side stub for RAND_* used by the smoke
 * tests.
 *
 * The vendored BN sources reference RAND_bytes / RAND_priv_bytes /
 * RAND_priv_bytes_ex / RAND_bytes_ex for nonce generation. On the
 * embedded firmware these route through the RP2350 TRNG via
 * `src/pqf_rand.c` (added in Phase C-5). On the host test rig we
 * use `arc4random_buf` which is good enough for KAT-vector tests
 * (the BN tests in test_bn.c don't actually consume random bytes,
 * but bn_rand.c references the symbols so they need to link).
 *
 * Copyright 2026 Cryptsoft Pty Ltd
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#if defined(__APPLE__) || defined(__BSD__) || defined(__linux__)
#include <stdint.h>
extern void arc4random_buf(void *, size_t);
#endif

static void fill_random(unsigned char *buf, size_t n)
{
#if defined(__APPLE__) || defined(__BSD__) || defined(__linux__)
    arc4random_buf(buf, n);
#else
    /* Last-resort fallback. Good enough for tests; never used in
     * the firmware build. */
    for (size_t i = 0; i < n; i++) buf[i] = (unsigned char)rand();
#endif
}

int RAND_bytes(unsigned char *buf, int num)
{
    if (num <= 0) return 0;
    fill_random(buf, (size_t)num);
    return 1;
}

int RAND_priv_bytes(unsigned char *buf, int num)
{
    return RAND_bytes(buf, num);
}

int RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                  unsigned int strength)
{
    (void)ctx; (void)strength;
    fill_random(buf, num);
    return 1;
}

int RAND_priv_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                       unsigned int strength)
{
    return RAND_bytes_ex(ctx, buf, num, strength);
}

int RAND_status(void) { return 1; }
