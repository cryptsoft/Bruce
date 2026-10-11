/* prov/ecx.h -- X25519/X448 + DHKEM provider header shim.
 *
 * The firmware does only P-256 ECDSA/ECDH, never the Edwards/
 * Montgomery curves or RFC 9180 DHKEM. ec_key.c references
 * ossl_ec_dhkem_derive_private() on its seed-based keygen path
 * (EC_KEY generated from input key material), which our random
 * EC_KEY_generate_key() never takes. Declare it so ec_key.c
 * compiles; the impl is a failing stub in src/ec/pqf_ecdsa_sig.c.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from upstream providers/.../include/prov/ecx.h,
 *   Copyright The OpenSSL Project Authors. Apache-2.0.
 */
#ifndef OSSL_PROV_ECX_H
#define OSSL_PROV_ECX_H
#include <openssl/ec.h>
int ossl_ec_dhkem_derive_private(EC_KEY *ec, BIGNUM *privout,
                                 const unsigned char *ikm, size_t ikmlen);
#endif
