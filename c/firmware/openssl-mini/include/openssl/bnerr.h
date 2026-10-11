/* bnerr.h -- BN error-reason codes shim.
 *
 * Upstream `openssl/bnerr.h` declares the BN error reasons that
 * `ERR_raise(ERR_LIB_BN, BN_R_*)` uses. We already define these
 * in `internal/cryptlib.h` (the shim), so this file just exists
 * as an include-resolution target -- the codes are numerically
 * stable from the cryptlib shim.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/bnerr.h`,
 *   Copyright 1995-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_BNERR_H
#define OPENSSL_BNERR_H

/* BN_R_* defines live in `internal/cryptlib.h`. Including this
 * header is a no-op; the cryptlib include chain already pulled the
 * names in. */

#endif
