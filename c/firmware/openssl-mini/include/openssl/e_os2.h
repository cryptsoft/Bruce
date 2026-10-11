/* e_os2.h -- OS-detection shim.
 *
 * The upstream `openssl/e_os2.h` defines a thicket of OPENSSL_SYS_*
 * macros for every supported OS (Windows / VMS / DOS / Unix / ...) and
 * pulls `openssl/macros.h` + `openssl/opensslconf.h`. The vendored
 * aes_local.h includes this header, but the AES code itself doesn't
 * reference any of the OS macros -- they only affect the surrounding
 * library plumbing we don't ship.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/e_os2.h`,
 *   Copyright 1995-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_E_OS2_H
#define OPENSSL_E_OS2_H

/* aes_local.h does `typedef uint64_t u64;` without including
 * <stdint.h> first, and only happens to compile on hosts where one
 * of the other system headers (stdio.h on macOS, ...) has already
 * pulled stdint in. Cross-compiling with newlib for ARM is stricter
 * -- newlib's stdio.h does NOT transitively expose uint64_t. Pull
 * <stdint.h> here so the typedef resolves on every toolchain we
 * support. */
#include <stdint.h>

/* `ossl_inline` and `ossl_unused` come from the upstream
 * `openssl/e_os2.h`. We provide the minimum the vendored sources
 * actually reference. */
#define ossl_inline inline
#if defined(__GNUC__)
#  define ossl_unused __attribute__((unused))
#  define ossl_noreturn __attribute__((noreturn))
#else
#  define ossl_unused
#  define ossl_noreturn
#endif

/* Largest portable integer types -- vendored BN code uses these
 * names for some local helpers. */
typedef int64_t  ossl_intmax_t;
typedef uint64_t ossl_uintmax_t;
typedef intptr_t ossl_ssize_t;

/* OPENSSL_EXPORT -- the symbol-visibility marker upstream uses to
 * export the provider entry point. The EC param/provider headers
 * (core.h) reference it. On our static build it's just `extern`. */
#ifndef OPENSSL_EXPORT
#  define OPENSSL_EXPORT extern
#endif

/* __owur ("warn unused result") -- a function attribute the EC
 * headers tag return-checked functions with. Map to the GCC/Clang
 * attribute, or nothing on other toolchains. */
#ifndef __owur
#  if defined(__GNUC__)
#    define __owur __attribute__((__warn_unused_result__))
#  else
#    define __owur
#  endif
#endif

#endif
