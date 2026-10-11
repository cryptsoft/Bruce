/* aes.h -- minimal AES public API shim for the vendored OpenSSL
 * primitives in `openssl-mini/`.
 *
 * The upstream `openssl/aes.h` declares the AES block cipher plus
 * helpers for AES_wrap_key / AES_unwrap_key / AES_bi_ige_encrypt /
 * AES_cmac_resume / etc., and pulls `openssl/macros.h`,
 * `openssl/e_os2.h`, `openssl/opensslconf.h`. We need only the core
 * block cipher (key setup + single-block encrypt / decrypt) -- the
 * pqf_aes wrapper layers CBC mode on top in `src/pqf_aes.c`.
 *
 * The compile-time layout of AES_KEY is byte-for-byte identical to
 * the upstream type so the vendored aes_core.c source compiles
 * unmodified.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/aes.h`,
 *   Copyright 2002-2020 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_AES_H
#define OPENSSL_AES_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE      16
#define AES_ENCRYPT         1
#define AES_DECRYPT         0
#define AES_MAXNR           14

/* Round-key schedule. The upstream type uses `unsigned long` if
 * AES_LONG is defined, else `unsigned int`. We use the latter to
 * match the vendored aes_core.c default. */
struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int          rounds;
};
typedef struct aes_key_st AES_KEY;

int  AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                         AES_KEY *key);
int  AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                         AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_AES_H */
