/* deprecated.h -- internal flag shim.
 *
 * Upstream uses this to enable use of public-API entry points marked
 * deprecated. For a private vendored snapshot, there is no
 * deprecation gate to bypass -- every reference to a deprecated symbol
 * is intentional. We make the include a no-op.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/internal/deprecated.h`,
 *   Copyright 2016-2021 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OSSL_INTERNAL_DEPRECATED_H
#define OSSL_INTERNAL_DEPRECATED_H
/* intentionally empty */
#endif
