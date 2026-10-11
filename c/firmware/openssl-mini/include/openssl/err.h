/* err.h -- error-stack shim.
 *
 * The upstream `openssl/err.h` declares the ERR_* error-stack API
 * + the ERR_LIB_* / ERR_R_* code namespaces. None of the BN / EC
 * sources we vendor inspect the error stack -- they call ERR_raise
 * (already stubbed in `internal/cryptlib.h`) and surface failure
 * via their normal return value. We make this header a no-op so
 * the `#include <openssl/err.h>` directives the vendored .c files
 * carry resolve cleanly.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/err.h.in`,
 *   Copyright 1995-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_ERR_H
#define OPENSSL_ERR_H

#include <openssl/crypto.h>
#include <openssl/bio.h>     /* BIO_snprintf etc. used from err.h path */

/* Error-stack stubs.
 *
 * ERR_raise / ERR_raise_data swallow their arguments entirely (the
 * macro body never references them), so the ERR_LIB_* library tags
 * and the per-library reason codes (BN_R_*, EC_R_*, ERR_R_*) that
 * appear ONLY as arguments to these calls never need to be defined.
 * That saves vendoring ~hundreds of reason-code constants.
 *
 * Defined here (the public header every BN/EC source includes,
 * directly or via internal/cryptlib.h) so both subsystems pick them
 * up uniformly. */
#ifndef ERR_raise
#define ERR_raise(lib, reason)              ((void)0)
#endif
#ifndef ERR_raise_data
#define ERR_raise_data(lib, reason, ...)     ((void)0)
#endif
#define ERR_set_mark()                       (1)
#define ERR_pop_to_mark()                    (1)
#define ERR_clear_last_mark()                (1)
#define ERR_clear_error()                    ((void)0)
#define ERR_peek_last_error()                (0)
#define ERR_get_error()                      (0)

/* Error-code field extractors. ecp_oct.c does
 * `if (ERR_GET_LIB(e) == ERR_LIB_EC && ERR_GET_REASON(e) == ...)`
 * to decide whether a BN failure was a specific EC reason. With our
 * no-op error stack, ERR_get_error() always returns 0, so these
 * extractors return 0 and the special-case branch is never taken --
 * which is correct: the generic error path handles it. */
#define ERR_GET_LIB(e)                       (0)
#define ERR_GET_REASON(e)                    (0)
#define ERR_GET_FUNC(e)                      (0)

/* The ONE reason code that the vendored sources COMPARE against
 * (rather than just pass to ERR_raise): ecp_oct.c checks
 * `ERR_GET_REASON(err) == BN_R_NOT_A_SQUARE` to map a BN failure to
 * EC_R_INVALID_COMPRESSED_POINT. Since ERR_GET_REASON is always 0
 * here, that branch is never taken -- but the identifier still needs
 * to exist for the comparison to compile. Value matches upstream. */
#ifndef BN_R_NOT_A_SQUARE
#define BN_R_NOT_A_SQUARE   111
#endif

/* Library tags -- only ever passed to ERR_raise (swallowed), so the
 * exact values don't matter; provide a few the sources name. */
#ifndef ERR_LIB_BN
#define ERR_LIB_BN      3
#endif
#ifndef ERR_LIB_EC
#define ERR_LIB_EC      16
#endif
#ifndef ERR_LIB_CRYPTO
#define ERR_LIB_CRYPTO  15
#endif

#endif
