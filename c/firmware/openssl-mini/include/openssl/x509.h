/* x509.h -- X.509 shim (empty).
 *
 * ec_key.c / ec_kmeth.c include <openssl/x509.h> for the
 * X509_PUBKEY / X509_ALGOR bridges used when an EC key is embedded
 * in a certificate. The firmware never does that -- it works with
 * raw EC keys for ECDSA / ECDH -- so the include resolves to nothing.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from upstream include/openssl/x509.h.in,
 *   Copyright 1995-2024 The OpenSSL Project Authors. Apache-2.0.
 */
#ifndef OPENSSL_X509_H
#define OPENSSL_X509_H
#endif
