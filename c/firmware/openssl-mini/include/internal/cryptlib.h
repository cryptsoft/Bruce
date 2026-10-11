/* cryptlib.h -- internal library glue shim.
 *
 * The upstream `internal/cryptlib.h` declares OPENSSL_malloc /
 * OPENSSL_free / OPENSSL_realloc plus the error-stack and BIO glue
 * used across libcrypto. We only need the allocator and the
 * "ERR_raise" macro family -- every BN error path expands to one of
 * those -- and we stub the rest because the firmware doesn't ship
 * libcrypto's error machinery.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/internal/cryptlib.h`,
 *   Copyright 1995-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OSSL_INTERNAL_CRYPTLIB_H
#define OSSL_INTERNAL_CRYPTLIB_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

/* Memory allocators. The firmware ships an `embedded-alloc`-backed
 * heap; for now we route through plain malloc/free/realloc + a
 * memset on alloc to mimic OPENSSL_zalloc's zero-fill semantics. */
/* OPENSSL_malloc family + OPENSSL_cleanse come from <openssl/crypto.h>
 * (the header every BN/EC source pulls via types.h). Don't redefine
 * them here. */

/* Error-stack stubs (ERR_raise etc.) + ERR_LIB_* live in
 * <openssl/err.h>. Pull it here so every file that includes
 * internal/cryptlib.h for OPENSSL_malloc also gets the no-op
 * ERR_raise macro -- which swallows its arguments, so the BN_R_* /
 * EC_R_* reason codes never need defining. */
#include <openssl/err.h>
#include <internal/nelem.h>   /* OSSL_NELEM -- bn_nist.c + EC tables use it */

/* Common library version-info string (never inspected by BN). */
#define OPENSSL_VERSION_STR     "OpenSSL 3.5.0 (Bruce C port)"
#define OPENSSL_FULL_VERSION_STR OPENSSL_VERSION_STR

/* ossl_assert: returns the truth of its argument, like an assert
 * macro that lets the caller branch on the result. */
#ifndef ossl_assert
#define ossl_assert(x)          ((x) ? 1 : 0)
#endif

/* CRYPTO_THREAD_ID -- used by BN_BLINDING to remember which thread
 * owns the blinding state. Single-threaded firmware -> constant 0. */
typedef unsigned long CRYPTO_THREAD_ID;
static inline CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void)
    { return 0; }
static inline int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a,
                                            CRYPTO_THREAD_ID b)
    { return a == b; }

#endif /* OSSL_INTERNAL_CRYPTLIB_H */
