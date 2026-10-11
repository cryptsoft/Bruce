/* dh.h -- Diffie-Hellman shim.
 *
 * `crypto/bn/bn_dh.c` references this header, but the only DH-side
 * symbols its code touches come through `crypto/bn_dh.h` (which we
 * vendor). The full upstream `openssl/dh.h` pulls the ASN.1
 * generic-stack machinery via `openssl/types.h`'s safestack chain
 * -- we don't need any of it.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/dh.h.in`,
 *   Copyright 1995-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_DH_H
#define OPENSSL_DH_H
/* intentionally empty -- see comment above */
#endif
