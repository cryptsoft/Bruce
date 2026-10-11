/* safestack.h -- STACK_OF() type-generic-stack shim (empty).
 *
 * Upstream `openssl/safestack.h` generates a family of type-safe
 * wrappers around `OPENSSL_STACK` (`STACK_OF(X)`, `sk_X_new()`,
 * `sk_X_push()`, ...) for every aggregate type libcrypto uses. None
 * of the BN / EC / ECDSA code paths we actually call into reference
 * those generics, but `openssl/types.h` includes safestack.h
 * unconditionally so the source files that need types.h transitively
 * pull this header. We make it a no-op.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/safestack.h.in`,
 *   Copyright 1999-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_SAFESTACK_H
#define OPENSSL_SAFESTACK_H

/* Minimal STACK_OF(X) -- forwards to an opaque struct so types.h's
 * forward declarations (`STACK_OF(BIGNUM);`, etc.) parse. None of
 * our call sites instantiate stacks, so the type stays opaque. */
#define STACK_OF(X) struct stack_st_##X

#endif
