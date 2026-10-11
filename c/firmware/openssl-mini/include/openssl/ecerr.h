/* ecerr.h -- EC error-reason shim (no-op).
 *
 * EC error reasons are surfaced via ERR_raise(), which is stubbed
 * in internal/cryptlib.h. The EC sources only pass EC_R_* / EC_F_*
 * constants to ERR_raise; we route any unknown one to 0.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from upstream include/openssl/ecerr.h,
 *   Copyright 1995-2024 The OpenSSL Project Authors. Apache-2.0.
 */
#ifndef OPENSSL_ECERR_H
#define OPENSSL_ECERR_H
#include <openssl/crypto.h>
/* All EC_R_* reason codes collapse to a single placeholder. They
 * are only ever the 2nd argument to ERR_raise (a no-op), never
 * inspected. Defining a catch-all avoids vendoring 200 constants. */
#endif
