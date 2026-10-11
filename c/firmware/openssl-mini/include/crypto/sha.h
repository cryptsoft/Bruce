/* crypto/sha.h -- internal SHA helper prototypes.
 *
 * Upstream uses this internal header to declare the
 * `ossl_sha256_192_init` entry point implemented inside sha256.c.
 * We don't call it from the firmware, but the source file defines
 * it and gcc warns about a missing prototype unless we forward-
 * declare it. Hence this two-line shim.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/crypto/sha.h`,
 *   Copyright 2018-2023 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OSSL_CRYPTO_SHA_H
#define OSSL_CRYPTO_SHA_H

#include <openssl/sha.h>

int ossl_sha256_192_init(SHA256_CTX *c);

#endif
