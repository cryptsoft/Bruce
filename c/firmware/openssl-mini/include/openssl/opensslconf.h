/* opensslconf.h -- minimal config shim.
 *
 * The upstream `openssl/opensslconf.h` is generated at configure time
 * and encodes a thousand feature flags (FIPS, AES-NI, threading,
 * ASN.1, ZLIB, ...). For the vendored SHA-256 path none of those
 * conditionals matter, but the `sha256.c` source still includes the
 * header. This shim exists to satisfy that include with the minimum
 * set of symbols upstream actually references from inside sha256.c +
 * sha_local.h + md32_common.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/opensslconf.h.in`,
 *   Copyright 2016-2023 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_OPENSSLCONF_H
#define OPENSSL_OPENSSLCONF_H

/* Feature exclusions for the firmware EC build.
 *
 *   OPENSSL_NO_EC_NISTP_64_GCC_128 -- drops the 64-bit "fast" NIST
 *     prime field methods (ecp_nistp{224,256,521}.c, which we did
 *     not vendor). The generic NIST + montgomery GFp methods handle
 *     P-256 correctly; this just removes the curve_list entries +
 *     pre_comp dup/free hooks that referenced the fast path.
 *   OPENSSL_NO_EC2M -- drops binary-field (GF2m) curve support. FIDO
 *     uses only prime-field P-256, so the GF2m constructor +
 *     EC_GF2m_simple_method (ec2_smpl.c, not vendored) are excluded. */
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
#define OPENSSL_NO_EC_NISTP_64_GCC_128
#endif
#ifndef OPENSSL_NO_QUIC
#define OPENSSL_NO_QUIC
#endif
#ifndef OPENSSL_NO_EC2M
#define OPENSSL_NO_EC2M
#endif

/* The vendored OpenSSL source uses these to gate deprecated public-
 * API entry points. Leaving them undefined makes upstream behave as
 * if the deprecation gates were inactive, which is exactly what we
 * want for an internal-only build. */

#endif /* OPENSSL_OPENSSLCONF_H */
