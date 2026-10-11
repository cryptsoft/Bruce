/* pqf_sha256.c -- pqf_* API wrappers around the vendored OpenSSL
 * SHA-256 implementation.
 *
 * The actual hashing lives in `sha256.c` (copied verbatim from
 * upstream `crypto/sha/sha256.c`, Apache-2.0, see
 * `LICENSE-APACHE-OPENSSL`). This file is the thin pqf_* adapter
 * that keeps firmware code free of upstream symbol names.
 *
 * Copyright 2026 Cryptsoft Pty Ltd
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "pqf_crypto.h"
#include "openssl/sha.h"

/* Compile-time assertion that the opaque pqf_sha256_ctx_t and the
 * upstream SHA256_CTX have the same layout. If this fires, the
 * struct in pqf_crypto.h drifted from sha.h's SHA256state_st. */
typedef char pqf_sha256_ctx_layout_check[
    sizeof(pqf_sha256_ctx_t) == sizeof(SHA256_CTX) ? 1 : -1];

/* ---- Incremental API ------------------------------------------ */

void pqf_sha256_init(pqf_sha256_ctx_t *ctx)
{
    SHA256_Init((SHA256_CTX *)ctx);
}

void pqf_sha256_update(pqf_sha256_ctx_t *ctx,
                        const uint8_t *data, size_t len)
{
    SHA256_Update((SHA256_CTX *)ctx, data, len);
}

void pqf_sha256_final(pqf_sha256_ctx_t *ctx, uint8_t out[32])
{
    SHA256_Final(out, (SHA256_CTX *)ctx);
}

/* ---- One-shot --------------------------------------------------- */

void pqf_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, len);
    SHA256_Final(out, &c);
}
