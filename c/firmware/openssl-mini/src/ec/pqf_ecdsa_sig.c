/* pqf_ecdsa_sig.c -- ECDSA_SIG lifecycle + DER codec.
 *
 * OpenSSL's `ecdsa_ossl.c` produces / consumes signatures through
 * the ECDSA_SIG object and the `i2d_ECDSA_SIG` / `d2i_ECDSA_SIG`
 * DER (de)serialisers. Upstream backs those with the ASN.1 template
 * engine (`crypto/ec/ec_asn1.c` + the whole `crypto/asn1/` tree),
 * which is a large dependency surface we deliberately don't vendor.
 *
 * The DER form of an ECDSA signature is tiny and fixed-shape:
 *
 *     SEQUENCE {
 *         INTEGER r,
 *         INTEGER s
 *     }
 *
 * with each INTEGER in DER big-endian two's-complement (a leading
 * 0x00 byte is prepended when the high bit of the magnitude is set,
 * so the value stays positive). We hand-roll exactly that here,
 * which is both smaller and easier to audit than the template
 * engine for this one structure.
 *
 * This file is project-original C written from X.690 (DER) + the
 * ECDSA-Sig-Value definition in RFC 3279 sec. 2.2.3 -- no ASN.1-codec
 * code copied from OpenSSL. It links against the vendored BN
 * (Apache-2.0) for the bignum <-> bytes conversions.
 *
 * Copyright 2026 Cryptsoft Pty Ltd
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include "ec_local.h"     /* struct ECDSA_SIG_st { BIGNUM *r, *s; } */
#include "internal/deterministic_nonce.h"

/* ---- Deterministic-nonce stub --------------------------------- *
 *
 * `ecdsa_ossl.c` references ossl_gen_deterministic_nonce_rfc6979 for
 * the RFC 6979 deterministic-k path, reached only when the caller
 * passes nonce_type == 1. The FIDO firmware always signs with
 * nonce_type == 0, so this function is never called at runtime. Note
 * that nonce_type == 0 with a non-NULL digest does NOT mean a bare
 * random k: ecdsa_ossl.c routes it to
 * ossl_bn_gen_dsa_nonce_fixed_top(), which hedges the RP2350 TRNG
 * bytes with the private key and the message digest (see
 * docs/PROTOCOL.md). We provide a failing stub so
 * the symbol resolves without dragging in the HMAC-DRBG subsystem
 * RFC 6979 would require. If it is ever invoked, it returns 0
 * (failure), which the caller surfaces as a sign error rather than
 * silently producing a bad signature. */
int ossl_gen_deterministic_nonce_rfc6979(BIGNUM *out, const BIGNUM *q,
                                         const BIGNUM *priv,
                                         const unsigned char *message,
                                         size_t message_len,
                                         const char *digestname,
                                         OSSL_LIB_CTX *libctx,
                                         const char *propq)
{
    (void)out; (void)q; (void)priv; (void)message; (void)message_len;
    (void)digestname; (void)libctx; (void)propq;
    return 0;
}

/* ---- DHKEM stub ----------------------------------------------- *
 *
 * ec_key.c calls ossl_ec_dhkem_derive_private on its seed-based
 * keygen path (deriving a private key deterministically from input
 * key material per RFC 9180). The firmware only ever calls
 * EC_KEY_generate_key (random k from the TRNG), which never takes
 * that path, so this is dead code. Stub returns 0 (failure) so an
 * accidental call surfaces loudly rather than silently deriving a
 * predictable key. */
int ossl_ec_dhkem_derive_private(EC_KEY *ec, BIGNUM *privout,
                                 const unsigned char *ikm, size_t ikmlen)
{
    (void)ec; (void)privout; (void)ikm; (void)ikmlen;
    return 0;
}

/* ---- Lifecycle ------------------------------------------------ */

ECDSA_SIG *ECDSA_SIG_new(void)
{
    ECDSA_SIG *s = OPENSSL_zalloc(sizeof(*s));
    /* r and s start NULL; ECDSA_SIG_set0 / d2i fill them. */
    return s;
}

void ECDSA_SIG_free(ECDSA_SIG *sig)
{
    if (sig == NULL)
        return;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    OPENSSL_free(sig);
}

void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL) *pr = sig->r;
    if (ps != NULL) *ps = sig->s;
}

const BIGNUM *ECDSA_SIG_get0_r(const ECDSA_SIG *sig) { return sig->r; }
const BIGNUM *ECDSA_SIG_get0_s(const ECDSA_SIG *sig) { return sig->s; }

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

/* ECDSA_size -- maximum DER length of a signature over this key's
 * group. Upstream (ec_asn1.c) computes it by encoding a signature
 * whose r and s both equal the group order (the largest they can
 * be) and measuring the result. We reproduce that exactly, using
 * our own i2d_ECDSA_SIG in its sizing mode (pp == NULL). Defined
 * here so we don't have to vendor ec_asn1.c (which would pull the
 * whole ASN.1 template engine). */
int ECDSA_size(const EC_KEY *ec)
{
    if (ec == NULL)
        return 0;
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    if (group == NULL)
        return 0;
    const BIGNUM *order = EC_GROUP_get0_order(group);
    if (order == NULL)
        return 0;

    ECDSA_SIG sig;
    sig.r = sig.s = (BIGNUM *)order;
    int ret = i2d_ECDSA_SIG(&sig, NULL);
    return ret < 0 ? 0 : ret;
}

/* ---- DER length helpers --------------------------------------- */

/* Number of bytes needed to DER-encode a definite length `len`.
 *   len < 0x80          -> 1 byte  (short form)
 *   len <= 0xff         -> 2 bytes (0x81, len)
 *   len <= 0xffff       -> 3 bytes (0x82, hi, lo)
 * ECDSA sig components never exceed a few hundred bytes, so we cap
 * at the 2-byte long form. */
static size_t der_len_size(size_t len)
{
    if (len < 0x80)   return 1;
    if (len <= 0xff)  return 2;
    return 3;
}

static unsigned char *der_put_len(unsigned char *p, size_t len)
{
    if (len < 0x80) {
        *p++ = (unsigned char)len;
    } else if (len <= 0xff) {
        *p++ = 0x81;
        *p++ = (unsigned char)len;
    } else {
        *p++ = 0x82;
        *p++ = (unsigned char)(len >> 8);
        *p++ = (unsigned char)(len & 0xff);
    }
    return p;
}

/* Encoded size of one INTEGER holding the non-negative bignum `v`:
 * tag(1) + lenbytes + content, where content = magnitude bytes plus
 * an optional leading 0x00 when the top bit is set. A zero value
 * encodes as a single 0x00 content byte. */
static size_t der_int_size(const BIGNUM *v)
{
    int    bytes = BN_num_bytes(v);
    size_t content;

    if (bytes == 0) {
        content = 1;                 /* the value 0 -> one 0x00 byte */
    } else {
        content = (size_t)bytes;
        if (BN_is_bit_set(v, bytes * 8 - 1))
            content += 1;            /* pad to keep sign positive */
    }
    return 1 + der_len_size(content) + content;
}

static unsigned char *der_put_int(unsigned char *p, const BIGNUM *v)
{
    int    bytes = BN_num_bytes(v);
    int    pad   = 0;
    size_t content;

    if (bytes == 0) {
        *p++ = 0x02;                 /* INTEGER tag */
        *p++ = 0x01;                 /* length 1    */
        *p++ = 0x00;                 /* value 0     */
        return p;
    }

    if (BN_is_bit_set(v, bytes * 8 - 1))
        pad = 1;
    content = (size_t)bytes + pad;

    *p++ = 0x02;                     /* INTEGER tag */
    p = der_put_len(p, content);
    if (pad)
        *p++ = 0x00;
    BN_bn2bin(v, p);                 /* big-endian magnitude */
    p += bytes;
    return p;
}

/* ---- i2d / d2i ------------------------------------------------ */

/* Encode `sig` to DER. Follows the OpenSSL i2d convention:
 *   - returns the encoded length (or < 0 on error)
 *   - if pp != NULL and *pp != NULL, writes into *pp and advances it
 *   - if pp != NULL and *pp == NULL, allocates a buffer, sets *pp
 *   - if pp == NULL, just returns the length (sizing pass) */
int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp)
{
    if (sig == NULL || sig->r == NULL || sig->s == NULL)
        return -1;

    size_t rlen = der_int_size(sig->r);
    size_t slen = der_int_size(sig->s);
    size_t body = rlen + slen;
    size_t total = 1 + der_len_size(body) + body;   /* SEQUENCE wrap */

    if (pp == NULL)
        return (int)total;

    unsigned char *buf;
    unsigned char *owned = NULL;
    if (*pp == NULL) {
        owned = OPENSSL_malloc(total);
        if (owned == NULL)
            return -1;
        buf = owned;
    } else {
        buf = *pp;
    }

    unsigned char *p = buf;
    *p++ = 0x30;                                     /* SEQUENCE tag */
    p = der_put_len(p, body);
    p = der_put_int(p, sig->r);
    p = der_put_int(p, sig->s);

    if (owned != NULL) {
        *pp = owned;                  /* caller now owns the buffer */
    } else {
        *pp = p;                      /* advance caller's pointer  */
    }
    return (int)total;
}

/* Parse one DER INTEGER at *p (with `end` as the hard limit) into a
 * freshly-allocated BIGNUM. Advances *p past the integer. Returns
 * NULL on malformed input. Rejects negative integers (high bit set
 * with no leading 0x00) since ECDSA r/s are always non-negative. */
static BIGNUM *der_get_int(const unsigned char **p, const unsigned char *end)
{
    const unsigned char *q = *p;
    if (q >= end || *q != 0x02)              /* INTEGER tag */
        return NULL;
    q++;
    if (q >= end)
        return NULL;

    size_t len;
    if (*q < 0x80) {
        len = *q++;
    } else if (*q == 0x81) {
        q++;
        if (q >= end) return NULL;
        len = *q++;
    } else if (*q == 0x82) {
        q++;
        if (q + 1 >= end) return NULL;
        len = ((size_t)q[0] << 8) | q[1];
        q += 2;
    } else {
        return NULL;                         /* >2-byte lengths n/a */
    }

    if (len == 0 || (size_t)(end - q) < len)
        return NULL;
    /* A leading 0x00 is only legal as sign padding; a 0x80+ first
     * byte without it would be a negative integer (illegal here). */
    if ((q[0] & 0x80) != 0)
        return NULL;

    BIGNUM *v = BN_bin2bn(q, (int)len, NULL);
    if (v == NULL)
        return NULL;
    q += len;
    *p = q;
    return v;
}

ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **psig, const unsigned char **pp, long len)
{
    if (pp == NULL || *pp == NULL || len <= 0)
        return NULL;

    const unsigned char *p   = *pp;
    const unsigned char *end = p + len;

    if (*p != 0x30)                          /* SEQUENCE tag */
        return NULL;
    p++;

    size_t body;
    if (p >= end) return NULL;
    if (*p < 0x80) {
        body = *p++;
    } else if (*p == 0x81) {
        p++;
        if (p >= end) return NULL;
        body = *p++;
    } else if (*p == 0x82) {
        p++;
        if (p + 1 >= end) return NULL;
        body = ((size_t)p[0] << 8) | p[1];
        p += 2;
    } else {
        return NULL;
    }
    if ((size_t)(end - p) < body)
        return NULL;
    end = p + body;                          /* tighten to body end */

    BIGNUM *r = der_get_int(&p, end);
    if (r == NULL)
        return NULL;
    BIGNUM *s = der_get_int(&p, end);
    if (s == NULL) {
        BN_free(r);
        return NULL;
    }

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (sig == NULL) {
        BN_free(r);
        BN_free(s);
        return NULL;
    }
    sig->r = r;
    sig->s = s;

    if (psig != NULL) {
        ECDSA_SIG_free(*psig);
        *psig = sig;
    }
    *pp = p;
    return sig;
}
