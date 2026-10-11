/* opensslv.h -- version macros shim.
 *
 * sha256.c only includes this header; nothing inside the SHA-256
 * implementation references the macros it defines. We keep the file
 * present so the include resolves cleanly.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/opensslv.h.in`,
 *   Copyright 1999-2023 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_OPENSSLV_H
#define OPENSSL_OPENSSLV_H

#define OPENSSL_VERSION_NUMBER   0x30500000L
#define OPENSSL_VERSION_TEXT     "OpenSSL 3.5.0-vendored (Bruce C port)"

#endif /* OPENSSL_OPENSSLV_H */
