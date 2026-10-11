/* pqf_evp.c -- minimal EVP_MD digest layer.
 *
 * The vendored ECDSA signer reaches for the EVP digest API to build
 * its hedged per-signature nonce (`ossl_bn_gen_dsa_nonce_fixed_top`
 * hashes priv-key || message || random with SHA-512, FIPS 186-4
 * Appendix B style -- so a weak RNG can't leak the private key). We
 * therefore need a *working* EVP_MD layer, not stubs.
 *
 * Rather than vendor OpenSSL's provider-backed EVP (which pulls the
 * whole OSSL_PARAM / fetch / provider machinery), this is a tiny
 * hand-written EVP_MD that dispatches to the vendored low-level
 * SHA-256 / SHA-384 / SHA-512 implementations. It implements exactly
 * the surface the vendored code calls:
 *
 *   EVP_sha256 / EVP_sha384 / EVP_sha512   -- static method descriptors
 *   EVP_MD_fetch("SHA256"|"SHA384"|"SHA512") / EVP_MD_free
 *   EVP_MD_CTX_new / EVP_MD_CTX_free
 *   EVP_DigestInit_ex / EVP_DigestUpdate / EVP_DigestFinal[_ex]
 *   EVP_MD_get_size / EVP_MD_CTX_get0_md (used incidentally)
 *
 * This is project-original C implementing the
 * upstream prototypes; the actual hashing is the Apache-2.0 vendored
 * SHA code.
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

#include <openssl/evp.h>
#include <openssl/sha.h>
#include "internal/sha3.h"

/* ---- EVP_MD descriptor ---------------------------------------- */

/* Function-pointer set over an opaque context, one per digest. For
 * fixed-output hashes `final` produces the digest; for XOFs (SHAKE)
 * `squeeze` is non-NULL and emits an arbitrary-length stream. */
struct evp_md_st {
    int   nid_size;                         /* digest length (0 = XOF) */
    int   block_size;
    size_t ctx_size;                        /* sizeof the backing ctx */
    int  (*init)  (void *c);
    int  (*update)(void *c, const void *d, size_t n);
    int  (*final) (unsigned char *md, void *c);
    int  (*squeeze)(void *c, unsigned char *out, size_t n);  /* XOF only */
    const char *name;
};

/* Adapter casts: the SHA*_CTX functions take typed contexts; we
 * store them behind void* so one descriptor shape fits all three. */
static int s256_init(void *c)                         { return SHA256_Init(c); }
static int s256_upd (void *c, const void *d, size_t n){ return SHA256_Update(c, d, n); }
static int s256_fin (unsigned char *m, void *c)       { return SHA256_Final(m, c); }
static int s384_init(void *c)                         { return SHA384_Init(c); }
static int s384_upd (void *c, const void *d, size_t n){ return SHA384_Update(c, d, n); }
static int s384_fin (unsigned char *m, void *c)       { return SHA384_Final(m, c); }
static int s512_init(void *c)                         { return SHA512_Init(c); }
static int s512_upd (void *c, const void *d, size_t n){ return SHA512_Update(c, d, n); }
static int s512_fin (unsigned char *m, void *c)       { return SHA512_Final(m, c); }

/* SHAKE-128 / SHAKE-256 (FIPS 202 XOFs) over the vendored KECCAK1600
 * core. ossl_sha3_init(pad=0x1f, bitlen) sets up the SHAKE sponge;
 * update absorbs, squeeze emits the output stream. */
static int sk128_init(void *c) { return ossl_sha3_init((KECCAK1600_CTX *)c, 0x1f, 128); }
static int sk256_init(void *c) { return ossl_sha3_init((KECCAK1600_CTX *)c, 0x1f, 256); }
static int sk_upd (void *c, const void *d, size_t n)
    { return ossl_sha3_update((KECCAK1600_CTX *)c, d, n); }
static int sk_sqz (void *c, unsigned char *o, size_t n)
    { return ossl_sha3_squeeze((KECCAK1600_CTX *)c, o, n); }

static const EVP_MD k_sha256 = {
    SHA256_DIGEST_LENGTH, SHA256_CBLOCK, sizeof(SHA256_CTX),
    s256_init, s256_upd, s256_fin, NULL, "SHA256"
};
static const EVP_MD k_sha384 = {
    SHA384_DIGEST_LENGTH, SHA512_CBLOCK, sizeof(SHA512_CTX),
    s384_init, s384_upd, s384_fin, NULL, "SHA384"
};
static const EVP_MD k_sha512 = {
    SHA512_DIGEST_LENGTH, SHA512_CBLOCK, sizeof(SHA512_CTX),
    s512_init, s512_upd, s512_fin, NULL, "SHA512"
};
/* block_size = rate = (1600 - 2*bitlen)/8 : 168 for SHAKE128, 136 for 256. */
static const EVP_MD k_shake128 = {
    0, 168, sizeof(KECCAK1600_CTX),
    sk128_init, sk_upd, NULL, sk_sqz, "SHAKE-128"
};
static const EVP_MD k_shake256 = {
    0, 136, sizeof(KECCAK1600_CTX),
    sk256_init, sk_upd, NULL, sk_sqz, "SHAKE-256"
};

const EVP_MD *EVP_sha256(void)  { return &k_sha256; }
const EVP_MD *EVP_sha384(void)  { return &k_sha384; }
const EVP_MD *EVP_sha512(void)  { return &k_sha512; }
const EVP_MD *EVP_shake128(void){ return &k_shake128; }
const EVP_MD *EVP_shake256(void){ return &k_shake256; }

int EVP_MD_get_size(const EVP_MD *md) { return md ? md->nid_size : 0; }

/* EVP_MD_fetch: map an algorithm name to one of the static
 * descriptors. libctx / propq are ignored (no provider system).
 * The returned pointer is static, so EVP_MD_free is a no-op. */
EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
                     const char *properties)
{
    (void)libctx; (void)properties;
    if (algorithm == NULL) return NULL;
    if (strcmp(algorithm, "SHA256") == 0 || strcmp(algorithm, "SHA2-256") == 0)
        return (EVP_MD *)&k_sha256;
    if (strcmp(algorithm, "SHA384") == 0 || strcmp(algorithm, "SHA2-384") == 0)
        return (EVP_MD *)&k_sha384;
    if (strcmp(algorithm, "SHA512") == 0 || strcmp(algorithm, "SHA2-512") == 0)
        return (EVP_MD *)&k_sha512;
    if (strcmp(algorithm, "SHAKE-128") == 0 || strcmp(algorithm, "SHAKE128") == 0)
        return (EVP_MD *)&k_shake128;
    if (strcmp(algorithm, "SHAKE-256") == 0 || strcmp(algorithm, "SHAKE256") == 0)
        return (EVP_MD *)&k_shake256;
    return NULL;
}

void EVP_MD_free(EVP_MD *md) { (void)md; }   /* descriptors are static */
int  EVP_MD_up_ref(EVP_MD *md) { (void)md; return 1; }  /* static -> no refcount */

/* ---- EVP_MD_CTX ----------------------------------------------- */

struct evp_md_ctx_st {
    const EVP_MD *md;
    void         *cctx;      /* heap SHA*_CTX, cctx_size bytes */
    size_t        cctx_size; /* what was allocated, >= md->ctx_size */
};

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    return calloc(1, sizeof(EVP_MD_CTX));
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    if (ctx == NULL) return;
    if (ctx->cctx != NULL) {
        /* wipe digest state before releasing it */
        memset(ctx->cctx, 0, ctx->cctx_size);
        free(ctx->cctx);
    }
    free(ctx);
}

const EVP_MD *EVP_MD_CTX_get0_md(const EVP_MD_CTX *ctx)
{
    return ctx ? ctx->md : NULL;
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    (void)impl;
    if (ctx == NULL || type == NULL) return 0;
    /* The state buffer is kept when it is already big enough: init()
     * overwrites all of it, so switching algorithm needs no reallocation.
     * ML-DSA alternates SHAKE-128 and SHAKE-256 several times per signature
     * and both want a 400-byte KECCAK1600_CTX, so this holds the context at
     * one allocation for the whole operation instead of one per switch --
     * which matters on the blob's arena, where small chunks are bump
     * allocated and not reclaimed until the arena is reset. */
    if (ctx->cctx == NULL || ctx->cctx_size < type->ctx_size) {
        free(ctx->cctx);
        ctx->cctx = malloc(type->ctx_size);
        if (ctx->cctx == NULL) {
            ctx->md = NULL;
            ctx->cctx_size = 0;
            return 0;
        }
        ctx->cctx_size = type->ctx_size;
    }
    ctx->md = type;
    return type->init(ctx->cctx);
}

int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
{
    return EVP_DigestInit_ex(ctx, type, NULL);
}

/* OpenSSL 3.x init variant taking an OSSL_PARAM array (ML-DSA's
 * shake_xof uses it). We don't honour params -- SHAKE here has no
 * tunable parameters -- so it's a plain init. */
int EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *type,
                       const OSSL_PARAM params[])
{
    (void)params;
    return EVP_DigestInit_ex(ctx, type, NULL);
}

/* XOF squeeze: emit `len` bytes of output stream. Valid only for an
 * XOF MD (SHAKE); fixed-output digests return failure. Multiple
 * squeeze calls continue the stream (ossl_sha3_squeeze keeps state). */
int EVP_DigestSqueeze(EVP_MD_CTX *ctx, unsigned char *out, size_t len)
{
    if (ctx == NULL || ctx->md == NULL || ctx->cctx == NULL
        || ctx->md->squeeze == NULL)
        return 0;
    return ctx->md->squeeze(ctx->cctx, out, len);
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
    if (ctx == NULL || ctx->md == NULL || ctx->cctx == NULL) return 0;
    return ctx->md->update(ctx->cctx, d, cnt);
}

int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
    if (ctx == NULL || ctx->md == NULL || ctx->cctx == NULL) return 0;
    int rc = ctx->md->final(md, ctx->cctx);
    if (rc && s != NULL) *s = (unsigned int)ctx->md->nid_size;
    return rc;
}

int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
    return EVP_DigestFinal_ex(ctx, md, s);
}
