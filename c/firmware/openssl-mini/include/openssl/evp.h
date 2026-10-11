/* evp.h -- EVP envelope-cipher API shim.
 *
 * Upstream `openssl/evp.h` is the high-level cipher / digest /
 * signature API and pulls a huge dep surface. The vendored BN code
 * only references the EVP_MD typedef + EVP_MD_CTX_* helpers for
 * the deterministic-nonce sign-hashing path inside bn_rand.c. We
 * shim those as opaque types + non-functioning stubs -- the only
 * real caller (ECDSA deterministic-k) is rerouted in the pqf
 * wrapper to use our SHA-256 directly.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/evp.h`,
 *   Copyright 1995-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_EVP_H
#define OPENSSL_EVP_H

#include <openssl/types.h>
#include <openssl/params.h>

/* OSSL_KEYMGMT_SELECT_* -- key-component selection bit flags. ec_key.c
 * passes these to its check/dup helpers to choose which parts of a
 * key to operate on. Same numeric values as upstream
 * core_dispatch.h. */
#include <openssl/obj_mac.h>
#define EVP_PKEY_ML_DSA_44 NID_ML_DSA_44
#define EVP_PKEY_ML_DSA_65 NID_ML_DSA_65
#define EVP_PKEY_ML_DSA_87 NID_ML_DSA_87

#define OSSL_KEYMGMT_SELECT_PRIVATE_KEY         0x01
#define OSSL_KEYMGMT_SELECT_PUBLIC_KEY          0x02
#define OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS   0x04
#define OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS    0x80
#define OSSL_KEYMGMT_SELECT_ALL_PARAMETERS      \
    (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS      \
     | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)
#define OSSL_KEYMGMT_SELECT_KEYPAIR             \
    (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
#define OSSL_KEYMGMT_SELECT_ALL                 \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

/* Real (not stubbed) EVP_MD digest API -- implemented in src/pqf_evp.c
 * over the vendored SHA-256/384/512. The ECDSA hedged-nonce path
 * (ossl_bn_gen_dsa_nonce, SHA-512) needs a working digest, so these
 * are genuine, not no-ops. ENGINE* is accepted (and ignored) on
 * DigestInit_ex to match the upstream signature. */
#include <openssl/engine.h>      /* ENGINE typedef for DigestInit_ex */

const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
const EVP_MD *EVP_shake128(void);
const EVP_MD *EVP_shake256(void);
int           EVP_MD_get_size(const EVP_MD *md);

EVP_MD     *EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
                         const char *properties);
void        EVP_MD_free(EVP_MD *md);
int         EVP_MD_up_ref(EVP_MD *md);

EVP_MD_CTX *EVP_MD_CTX_new(void);
void        EVP_MD_CTX_free(EVP_MD_CTX *ctx);
const EVP_MD *EVP_MD_CTX_get0_md(const EVP_MD_CTX *ctx);

int  EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int  EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *type,
                        const OSSL_PARAM params[]);
int  EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int  EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t n);
int  EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int  EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int  EVP_DigestSqueeze(EVP_MD_CTX *ctx, unsigned char *out, size_t len);

#endif
