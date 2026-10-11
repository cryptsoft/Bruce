/* refcount.h -- reference-counting shim.
 *
 * Upstream `internal/refcount.h` picks an atomic backend (C11
 * atomics, GCC __atomic builtins, or a lock fallback) for the
 * CRYPTO_REF_COUNT used by EC_KEY / EC_GROUP. The firmware's CTAP
 * dispatch is single-threaded, and the core-1 PQC worker shares
 * state through an explicit hand-off (not concurrent libcrypto
 * calls), so a plain non-atomic int is correct here.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/internal/refcount.h`,
 *   Copyright 2016-2020 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OSSL_INTERNAL_REFCOUNT_H
#define OSSL_INTERNAL_REFCOUNT_H

#include <openssl/crypto.h>

/* The upstream CRYPTO_REF_COUNT is a struct carrying the counter +
 * (on the lock fallback) a lock pointer. We keep it a struct so the
 * `.val` field accesses in the EC sources compile unchanged. */
typedef struct {
    int val;
} CRYPTO_REF_COUNT;

static inline int CRYPTO_UP_REF(CRYPTO_REF_COUNT *r, int *ret)
{
    r->val++;
    if (ret) *ret = r->val;
    return 1;
}

static inline int CRYPTO_DOWN_REF(CRYPTO_REF_COUNT *r, int *ret)
{
    r->val--;
    if (ret) *ret = r->val;
    return 1;
}

static inline int CRYPTO_GET_REF(CRYPTO_REF_COUNT *r, int *ret)
{
    *ret = r->val;
    return 1;
}

static inline int CRYPTO_NEW_REF(CRYPTO_REF_COUNT *r, int n)
{
    r->val = n;
    return 1;
}

static inline void CRYPTO_FREE_REF(CRYPTO_REF_COUNT *r) { (void)r; }

/* REF_PRINT_COUNT -- a debug-only trace hook upstream compiles in
 * when REF_PRINT is defined (it dumps each up/down-ref to stderr).
 * We never enable REF_PRINT, so make it a no-op. The EC sources
 * call it unconditionally inside `#ifndef OPENSSL_NO_...` blocks,
 * so it needs to exist as a macro. */
#ifndef REF_PRINT_COUNT
/* Variadic -- call sites pass 2 or 3 args across the BN/EC sources. */
#define REF_PRINT_COUNT(...)           ((void)0)
#define REF_PRINT_EX(...)              ((void)0)
#endif
#ifndef REF_ASSERT_ISNT
#define REF_ASSERT_ISNT(test)          ((void)0)
#endif

#endif /* OSSL_INTERNAL_REFCOUNT_H */
