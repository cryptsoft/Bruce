/* prov/providercommon.h -- provider-common shim (empty).
 *
 * ec_key.c includes this for provider-side helpers (ossl_prov_is_running
 * etc.). None of those symbols are referenced on the raw-EC ECDSA/ECDH
 * paths the firmware uses, so the header is empty. If a future change
 * actually calls ossl_prov_is_running, add a `return 1` stub here.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from upstream providers/common/include/prov/providercommon.h,
 *   Copyright The OpenSSL Project Authors. Apache-2.0.
 */
#ifndef OSSL_PROV_PROVIDERCOMMON_H
#define OSSL_PROV_PROVIDERCOMMON_H
static inline int ossl_prov_is_running(void) { return 1; }
/* ossl_set_error_state -- FIPS module error latch. No FIPS module
 * here, so it is a no-op. */
static inline void ossl_set_error_state(const char *type) { (void)type; }
#endif
