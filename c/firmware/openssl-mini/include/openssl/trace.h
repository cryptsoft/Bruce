/* trace.h -- runtime-trace shim.
 *
 * Upstream `openssl/trace.h` provides the `OSSL_TRACE_*` family used
 * to instrument libcrypto for debugging. The vendored sources only
 * call OSSL_TRACE_* macros, which expand to nothing when tracing is
 * disabled. We stub them to nothing here.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/trace.h`,
 *   Copyright 2019-2023 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_TRACE_H
#define OPENSSL_TRACE_H

/* Some vendored .c files (bn_ctx.c) reference BIO_printf inside
 * trace blocks without including bio.h themselves; pull our BIO
 * shim here so the dprintf calls resolve. */
#include <openssl/bio.h>

#define OSSL_TRACE_BEGIN(category)            do { if (0) {
#define OSSL_TRACE_END(category)              } } while (0);
#define OSSL_TRACE(category, ...)             ((void)0)
#define OSSL_TRACE1(category, fmt, a)         ((void)0)
#define OSSL_TRACE2(category, fmt, a, b)      ((void)0)
#define OSSL_TRACE3(category, fmt, a, b, c)   ((void)0)
#define OSSL_TRACE4(category, fmt, a, b, c, d) ((void)0)
#define OSSL_TRACE5(category, fmt, a, b, c, d, e) ((void)0)
#define OSSL_TRACE6(category, fmt, a, b, c, d, e, f) ((void)0)
#define OSSL_TRACE_ENABLED(category)          0
#define OSSL_TRACE_CTX(category, c, fmt, ...) ((void)0)
#define OSSL_TRACE_STRING(category, text, len) ((void)0)
#define OSSL_TRACE_CANCEL(category)           ((void)0)
#define OSSL_TRACE_BEGIN_EX(...)              do { if (0) {
#define OSSL_TRACE_END_EX(...)                } } while (0);

/* The TRACE-category enum tag is referenced by `internal/trace.h`
 * if the BN code ever expands a category constant. None of our
 * code paths use it; the literal is never inspected. */
#define OSSL_TRACE_CATEGORY_BN                0

/* bn_ctx.c references `trc_out` directly inside an OSSL_TRACE_BEGIN
 * block -- the upstream macro declares it as a local BIO* via
 * `OSSL_TRACE_BEGIN`. Our stub version of the macro elides the
 * declaration but leaves the body of the block in scope; provide a
 * `trc_out` global the no-op block can read. */
extern BIO *trc_out;

#endif
