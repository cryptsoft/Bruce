/* bn_conf.h -- BN word-size configuration shim.
 *
 * Upstream `include/crypto/bn_conf.h` is generated at configure time
 * with exactly one of:
 *   - SIXTY_FOUR_BIT_LONG  (LP64: long is 64 bits)
 *   - SIXTY_FOUR_BIT       (LLP64: long long is 64 bits, long is 32)
 *   - THIRTY_TWO_BIT       (32-bit limbs)
 *
 * Set here based on the compile-time architecture. The firmware
 * target is 32-bit ARM Cortex-M33 (THIRTY_TWO_BIT). Host builds on
 * macOS / Linux x86-64 use SIXTY_FOUR_BIT_LONG (LP64), Windows x64
 * uses SIXTY_FOUR_BIT (LLP64).
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/crypto/bn_conf.h.in`,
 *   Copyright 2016-2021 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OSSL_CRYPTO_BN_CONF_H
#define OSSL_CRYPTO_BN_CONF_H

#if defined(__LP64__) || defined(_LP64)
/* LP64: macOS, Linux, BSD on x86-64 / arm64. */
#  define SIXTY_FOUR_BIT_LONG
#elif defined(_WIN64)
/* LLP64: Windows x64. long is 32-bit, long long is 64-bit. */
#  define SIXTY_FOUR_BIT
#else
/* 32-bit targets -- including the RP2350 Cortex-M33 firmware. */
#  define THIRTY_TWO_BIT
#endif

#endif /* OSSL_CRYPTO_BN_CONF_H */
