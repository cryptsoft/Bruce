/* bio.h -- BIO I/O abstraction shim.
 *
 * Upstream `openssl/bio.h` is huge: BIO chains, filter BIOs, memory
 * BIOs, network BIOs, etc. The vendored sources only reach for
 * BIO_printf inside bn_ctx.c's tracing path -- which we don't
 * exercise. Stub the type as opaque and `#define BIO_printf` to a
 * no-op that returns a positive count so debug-only callers don't
 * branch on a failure.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/bio.h.in`,
 *   Copyright 1995-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_BIO_H
#define OPENSSL_BIO_H

#include <stddef.h>

typedef struct bio_st BIO;

#define BIO_printf(bio, ...)            (1)
#define BIO_write(bio, buf, n)          ((int)(n))
#define BIO_flush(bio)                  (1)
#define BIO_free(bio)                   ((void)0)
#define BIO_new_mem_buf(buf, len)       ((BIO *)0)
#define BIO_snprintf snprintf

#endif
