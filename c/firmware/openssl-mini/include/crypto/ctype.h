/* crypto/ctype.h -- locale-independent ctype helpers shim.
 *
 * Upstream `crypto/ctype.h` provides ossl_isdigit / ossl_isspace /
 * ossl_tolower that are locale-aware in the same way upstream
 * libcrypto expects. The BN-conv path uses these for parsing hex /
 * decimal strings. The standard ctype.h equivalents are good enough
 * for our use because the firmware doesn't honour locales.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/crypto/ctype.h`,
 *   Copyright 2017-2021 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OSSL_CRYPTO_CTYPE_H
#define OSSL_CRYPTO_CTYPE_H

#include <ctype.h>

#define ossl_isascii(c)       isascii((unsigned char)(c))
#define ossl_isalnum(c)       isalnum((unsigned char)(c))
#define ossl_isalpha(c)       isalpha((unsigned char)(c))
#define ossl_isdigit(c)       isdigit((unsigned char)(c))
#define ossl_isxdigit(c)      isxdigit((unsigned char)(c))
#define ossl_isspace(c)       isspace((unsigned char)(c))
#define ossl_isupper(c)       isupper((unsigned char)(c))
#define ossl_islower(c)       islower((unsigned char)(c))
#define ossl_isprint(c)       isprint((unsigned char)(c))
#define ossl_iscntrl(c)       iscntrl((unsigned char)(c))
#define ossl_ispunct(c)       ispunct((unsigned char)(c))
#define ossl_tolower(c)       tolower((unsigned char)(c))
#define ossl_toupper(c)       toupper((unsigned char)(c))
#define ossl_isspace_or_eol(c) (isspace((unsigned char)(c)) || (c) == '\n' || (c) == '\r')

/* ossl_to_hex / ossl_from_hex -- pair-wise hex <-> nibble helpers
 * the BN conversion path uses. Upstream lives in `crypto/ctype.c`;
 * we inline here so we don't have to vendor that source file. */
static inline int ossl_to_hex(unsigned char *out, unsigned char nibble)
{
    if (nibble < 10) out[0] = (unsigned char)('0' + nibble);
    else if (nibble < 16) out[0] = (unsigned char)('A' + nibble - 10);
    else return 0;
    return 1;
}
static inline int ossl_from_hex(unsigned char c, unsigned char *out)
{
    if (c >= '0' && c <= '9') { *out = (unsigned char)(c - '0'); return 1; }
    if (c >= 'a' && c <= 'f') { *out = (unsigned char)(c - 'a' + 10); return 1; }
    if (c >= 'A' && c <= 'F') { *out = (unsigned char)(c - 'A' + 10); return 1; }
    return 0;
}

#endif
