/* rand.h -- public RAND API shim.
 *
 * Same prototype shape as upstream -- `crypto/rand.h` (our shim) and
 * this header declare the same functions. The actual entropy source
 * is the firmware's TRNG, wired in via `src/pqf_rand.c` once that
 * lands in Phase C-5.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/rand.h.in`,
 *   Copyright 1995-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_RAND_H
#define OPENSSL_RAND_H

#include <openssl/crypto.h>
#include <openssl/types.h>
#include <crypto/rand.h>

/* The upstream header also declares RAND_load_file / RAND_write_file
 * / RAND_egd / RAND_seed / RAND_add -- none of which the BN paths we
 * vendor reach for. We leave them undeclared so a future addition
 * that actually needs them surfaces the dep here. */

#endif
