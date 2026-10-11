/* crypto/rand.h -- internal randomness API shim.
 *
 * Vendored bn_rand.c, ecdsa_*.c, ecdh_*.c call RAND_priv_bytes_ex /
 * RAND_bytes_ex / RAND_bytes for nonce generation and ephemeral key
 * material. In the firmware we don't have a libcrypto RAND provider
 * -- randomness comes from the RP2350 ring-oscillator TRNG exposed
 * by the Rust path's `trng.rs` (and which the C port will expose
 * via `pqf_rand_bytes` once that wrapper lands in Phase C-5).
 *
 * For now we declare the prototypes as `int` functions that the
 * pqf glue layer (`src/pqf_rand.c`) implements by routing through
 * the TRNG. Implementations that need to call these BEFORE the
 * TRNG is initialised will fail with a non-zero return.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/crypto/rand.h`,
 *   Copyright 2018-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OSSL_CRYPTO_RAND_H
#define OSSL_CRYPTO_RAND_H

#include <openssl/crypto.h>
#include <openssl/types.h>

typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

int RAND_bytes(unsigned char *buf, int num);
int RAND_priv_bytes(unsigned char *buf, int num);
int RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                  unsigned int strength);
int RAND_priv_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                       unsigned int strength);
int RAND_set_DRBG_type(OSSL_LIB_CTX *ctx, const char *drbg,
                       const char *propq, const char *cipher,
                       const char *digest);

/* Status accessor -- the BN-rand path tests this before calling. We
 * report ready once `pqf_rand_init()` has been called (which Phase
 * C-5 wires in from src/main.c during bring-up). */
int RAND_status(void);

#endif
