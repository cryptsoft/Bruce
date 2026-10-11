/* macros.h -- deprecation and compatibility-marker shim.
 *
 * Upstream `openssl/macros.h` carries the OSSL_DEPRECATED markers
 * plus the OPENSSL_API_COMPAT version logic. For a private vendored
 * snapshot, deprecation gates are inactive and the API-compat
 * machinery isn't needed -- every reference to a deprecated symbol
 * inside the vendored sources is intentional. We expand the markers
 * to empty.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/macros.h`,
 *   Copyright 2019-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_MACROS_H
#define OPENSSL_MACROS_H

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

#define OPENSSL_MSTR_HELPER(x) #x
#define OPENSSL_MSTR(x)        OPENSSL_MSTR_HELPER(x)

#define NON_EMPTY_TRANSLATION_UNIT static void *dummy = &dummy;

/* Deprecation markers -- no-ops for the embedded build. */
#define OSSL_DEPRECATED(since)
#define OSSL_DEPRECATED_FOR(since, msg)

/* The OPENSSL_NO_DEPRECATED_<X_Y> macros are intentionally LEFT
 * UNDEFINED. Upstream public headers gate deprecated declarations
 * with `#ifndef OPENSSL_NO_DEPRECATED_3_0` -- i.e. "declare the
 * deprecated API unless deprecation is disabled". The vendored EC
 * code uses several of those deprecated entry points internally
 * (e.g. EC_POINT_set_Jprojective_coordinates_GFp). Defining the
 * macro -- even to 0 -- makes the `#ifndef` false and HIDES those
 * declarations, breaking the build. Leaving them undefined keeps
 * the deprecated surface visible, which is what we want. */

#define DECLARE_DEPRECATED(f) f

/* OSSL_DEPRECATEDIN_<MAJ>_<MIN> -- empty markers. */
#define OSSL_DEPRECATEDIN_0_9_8
#define OSSL_DEPRECATEDIN_1_0_0
#define OSSL_DEPRECATEDIN_1_0_1
#define OSSL_DEPRECATEDIN_1_0_2
#define OSSL_DEPRECATEDIN_1_1_0
#define OSSL_DEPRECATEDIN_1_1_1
#define OSSL_DEPRECATEDIN_3_0
#define OSSL_DEPRECATEDIN_3_1
#define OSSL_DEPRECATEDIN_3_2
#define OSSL_DEPRECATEDIN_3_3
#define OSSL_DEPRECATEDIN_3_4
#define OSSL_DEPRECATEDIN_3_5

/* Equivalent _FOR variants (deprecated since X.Y, use Y). */
#define OSSL_DEPRECATEDIN_0_9_8_FOR(msg)
#define OSSL_DEPRECATEDIN_1_0_0_FOR(msg)
#define OSSL_DEPRECATEDIN_1_0_1_FOR(msg)
#define OSSL_DEPRECATEDIN_1_0_2_FOR(msg)
#define OSSL_DEPRECATEDIN_1_1_0_FOR(msg)
#define OSSL_DEPRECATEDIN_1_1_1_FOR(msg)
#define OSSL_DEPRECATEDIN_3_0_FOR(msg)
#define OSSL_DEPRECATEDIN_3_1_FOR(msg)
#define OSSL_DEPRECATEDIN_3_2_FOR(msg)
#define OSSL_DEPRECATEDIN_3_3_FOR(msg)
#define OSSL_DEPRECATEDIN_3_4_FOR(msg)
#define OSSL_DEPRECATEDIN_3_5_FOR(msg)

#endif /* OPENSSL_MACROS_H */
