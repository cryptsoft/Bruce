/* rsa.h -- shim (empty / opaque).
 *
 * ec_key.c / ec_kmeth.c include <openssl/rsa.h> for integration
 * points (ENGINE bridge, FIPS self-test hooks, RSA cross-refs) that
 * the firmware's raw-EC ECDSA/ECDH paths never exercise. Empty.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from upstream include/openssl/rsa.h(.in),
 *   Copyright The OpenSSL Project Authors. Apache-2.0.
 */
#ifndef OPENSSL_SHIM_RSA_H
#define OPENSSL_SHIM_RSA_H
#endif
