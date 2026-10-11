/* sha.h -- minimal SHA public API shim for the vendored OpenSSL
 * primitives in `openssl-mini/`.
 *
 * The upstream `openssl/sha.h` declares the full SHA family (SHA-1,
 * SHA-2, SHA-3) and pulls a stack of `openssl/macros.h`,
 * `openssl/e_os2.h`, etc. transitively. The Bruce firmware uses
 * only SHA-256, so this shim exposes just SHA-256's types + function
 * prototypes -- exactly the surface `crypto/sha/sha256.c` references
 * from upstream -- and skips the rest of the OpenSSL header machinery.
 *
 * The compile-time layout of SHA256_CTX is byte-for-byte identical to
 * the upstream type so the vendored sha256.c source compiles
 * unmodified.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/sha.h`,
 *   Copyright 1995-2023 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_SHA_H
#define OPENSSL_SHA_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA_LONG must be at least 32 bits wide. unsigned int matches the
 * upstream choice on every platform we target. */
#ifndef SHA_LONG
#define SHA_LONG unsigned int
#endif

#define SHA_LBLOCK              16
#define SHA_CBLOCK              (SHA_LBLOCK * 4)
#define SHA256_CBLOCK           (SHA_LBLOCK * 4)
#define SHA224_DIGEST_LENGTH    28
#define SHA256_DIGEST_LENGTH    32
#define SHA256_192_DIGEST_LENGTH 24
#define SHA384_DIGEST_LENGTH    48
#define SHA512_DIGEST_LENGTH    64

typedef struct SHA256state_st {
    SHA_LONG       h[8];
    SHA_LONG       Nl, Nh;
    SHA_LONG       data[SHA_LBLOCK];
    unsigned int   num, md_len;
} SHA256_CTX;

int  SHA224_Init  (SHA256_CTX *c);
int  SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
int  SHA224_Final (unsigned char *md, SHA256_CTX *c);

int  SHA256_Init  (SHA256_CTX *c);
int  SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int  SHA256_Final (unsigned char *md, SHA256_CTX *c);
void SHA256_Transform(SHA256_CTX *c, const unsigned char *data);

/* SHA-512 (+ SHA-384, same state) -- needed by the ECDSA hedged-nonce
 * generator (ossl_bn_gen_dsa_nonce hashes with SHA-512). Layout is
 * byte-for-byte identical to upstream so the vendored sha512.c
 * compiles unmodified. */
#define SHA512_CBLOCK   (SHA_LBLOCK * 8)
#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#  define SHA_LONG64 unsigned __int64
#elif defined(__arch64__)
#  define SHA_LONG64 unsigned long
#else
#  define SHA_LONG64 unsigned long long
#endif

typedef struct SHA512state_st {
    SHA_LONG64 h[8];
    SHA_LONG64 Nl, Nh;
    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;

int  SHA384_Init  (SHA512_CTX *c);
int  SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int  SHA384_Final (unsigned char *md, SHA512_CTX *c);
int  SHA512_Init  (SHA512_CTX *c);
int  SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
int  SHA512_Final (unsigned char *md, SHA512_CTX *c);
void SHA512_Transform(SHA512_CTX *c, const unsigned char *data);

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_SHA_H */
