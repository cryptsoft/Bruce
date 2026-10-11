/* self_test.h -- FIPS self-test hook shim.
 *
 * ec_key.c runs an OSSL_SELF_TEST pairwise-consistency check during
 * key generation when a FIPS self-test callback is installed. The
 * firmware installs none (OSSL_SELF_TEST_get_callback returns NULL),
 * so the self-test block is skipped at runtime -- but the symbols
 * must resolve to compile + link. All stubs are inert.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from upstream include/openssl/self_test.h,
 *   Copyright The OpenSSL Project Authors. Apache-2.0.
 */
#ifndef OPENSSL_SELF_TEST_H
#define OPENSSL_SELF_TEST_H
#include <openssl/types.h>
#include <openssl/core.h>    /* OSSL_CALLBACK is typedef'd here */
typedef struct ossl_self_test_st OSSL_SELF_TEST;

/* Self-test type / description strings -- passed to OSSL_SELF_TEST_onbegin
 * (a no-op stub), never inspected. */
#define OSSL_SELF_TEST_TYPE_PCT       "PCT"
#define OSSL_SELF_TEST_TYPE_PCT_KAT   "PCT_KAT"
#define OSSL_SELF_TEST_DESC_PCT_ECDSA "ECDSA"

static inline OSSL_SELF_TEST *OSSL_SELF_TEST_new(OSSL_CALLBACK *cb, void *arg)
{ (void)cb; (void)arg; return (OSSL_SELF_TEST *)0; }
static inline void OSSL_SELF_TEST_free(OSSL_SELF_TEST *st) { (void)st; }
static inline void OSSL_SELF_TEST_onbegin(OSSL_SELF_TEST *st, const char *type,
                                          const char *desc)
{ (void)st; (void)type; (void)desc; }
static inline int  OSSL_SELF_TEST_oncorrupt_byte(OSSL_SELF_TEST *st,
                                                 unsigned char *b)
{ (void)st; (void)b; return 0; }
static inline void OSSL_SELF_TEST_onend(OSSL_SELF_TEST *st, int ret)
{ (void)st; (void)ret; }
static inline void OSSL_SELF_TEST_get_callback(void *libctx, OSSL_CALLBACK **cb,
                                               void **arg)
{ (void)libctx; if (cb) *cb = (OSSL_CALLBACK *)0; if (arg) *arg = (void *)0; }
#endif
