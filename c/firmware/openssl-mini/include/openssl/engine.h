/* engine.h -- ENGINE API shim.
 *
 * The EC_KEY method machinery (ec_key.c / ec_kmeth.c) consults an
 * ENGINE to allow hardware-backed key operations. The firmware never
 * configures an ENGINE, so every lookup returns NULL and the code
 * falls through to the built-in software method. These stubs make
 * that path compile + link; they are never meaningfully exercised.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from upstream include/openssl/engine.h.in,
 *   Copyright The OpenSSL Project Authors. Apache-2.0.
 */
#ifndef OPENSSL_ENGINE_H
#define OPENSSL_ENGINE_H
#include <openssl/types.h>
typedef struct engine_st ENGINE;
static inline int     ENGINE_init(ENGINE *e)    { (void)e; return 0; }
static inline int     ENGINE_finish(ENGINE *e)  { (void)e; return 1; }
static inline ENGINE *ENGINE_get_default_EC(void)        { return (ENGINE *)0; }
static inline const void *ENGINE_get_EC(const ENGINE *e) { (void)e; return (void *)0; }
#endif
