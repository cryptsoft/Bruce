/* cbor_read.h -- small helpers over the pqcbor decoder.
 *
 * Shared by the CTAP2 command handlers (ctap2.c, client_pin.c, ...) for
 * looking up values in a decoded request map by integer or text key,
 * and for reading a COSE EC2 public key out of a keyAgreement map.
 *
 * Header-only (static inline) so each translation unit gets its own
 * copies without a separate .c -- these are tiny and hot.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CBOR_READ_H
#define PQF_CBOR_READ_H

#include <string.h>
#include <stdbool.h>
#include "pqcbor.h"

/* Value for an unsigned-integer key in a map, or NULL. */
static inline const pqfido_cbor_item_t *
cbor_map_get_uint(const pqfido_cbor_item_t *map, uint64_t key)
{
    if (!pqfido_cbor_is_map(map)) return NULL;
    size_t n = pqfido_cbor_map_size(map);
    const pqfido_cbor_pair_t *p = pqfido_cbor_map_pairs(map);
    for (size_t i = 0; i < n; i++)
        if (pqfido_cbor_is_uint(p[i].key)
            && pqfido_cbor_uint(p[i].key) == key)
            return p[i].value;
    return NULL;
}

/* Value for a text-string key in a map, or NULL. */
static inline const pqfido_cbor_item_t *
cbor_map_get_text(const pqfido_cbor_item_t *map, const char *key)
{
    if (!pqfido_cbor_is_map(map)) return NULL;
    size_t klen = strlen(key);
    size_t n = pqfido_cbor_map_size(map);
    const pqfido_cbor_pair_t *p = pqfido_cbor_map_pairs(map);
    for (size_t i = 0; i < n; i++)
        if (pqfido_cbor_is_string(p[i].key)
            && pqfido_cbor_string_len(p[i].key) == klen
            && memcmp(pqfido_cbor_string(p[i].key), key, klen) == 0)
            return p[i].value;
    return NULL;
}

/* Read the x / y affine coordinates (32 bytes each) out of a COSE
 * EC2 key map. COSE uses negative-integer keys: -2 = x, -3 = y,
 * which the decoder represents as negints with arg 1 and 2. Returns
 * true on success. */
static inline bool
cbor_cose_ec2_xy(const pqfido_cbor_item_t *cose,
                 uint8_t x[32], uint8_t y[32])
{
    if (!pqfido_cbor_is_map(cose)) return false;
    size_t n = pqfido_cbor_map_size(cose);
    const pqfido_cbor_pair_t *p = pqfido_cbor_map_pairs(cose);
    const uint8_t *px = NULL, *py = NULL;
    for (size_t i = 0; i < n; i++) {
        if (!pqfido_cbor_is_negint(p[i].key)) continue;
        uint64_t arg = pqfido_cbor_negint_arg(p[i].key);
        if (arg == 1 && pqfido_cbor_is_bytes(p[i].value)
            && pqfido_cbor_bytes_len(p[i].value) == 32)
            px = pqfido_cbor_bytes(p[i].value);
        else if (arg == 2 && pqfido_cbor_is_bytes(p[i].value)
            && pqfido_cbor_bytes_len(p[i].value) == 32)
            py = pqfido_cbor_bytes(p[i].value);
    }
    if (px == NULL || py == NULL) return false;
    memcpy(x, px, 32);
    memcpy(y, py, 32);
    return true;
}

/* ---- Raw-slice locator (for pinUvAuthParam over sub-command params) ----
 *
 * Several CTAP 2.1 commands -- authenticatorConfig (sec. 6.11),
 * credentialManagement (sec. 6.8), largeBlobs (sec. 6.10) -- compute their
 * pinUvAuthParam over a byte sequence that embeds the *verbatim* CBOR
 * encoding of a sub-parameters map exactly as the platform sent it.
 * Re-encoding a decoded tree would risk diverging from the host's
 * byte layout (key order, integer width, indefinite vs definite), so
 * instead we locate the exact source bytes of a value inside the
 * already-decoded request buffer and MAC over that zero-copy view. */

/* Read one CBOR head (initial byte + argument) from *p, advancing it.
 * Sets *major (0..7) and *arg. Rejects the indefinite/reserved
 * additional-info codes (28..31) that CTAP request maps never use.
 * Returns 0 on success, -1 on truncation/malformed. */
static inline int
cbor_read_head(const uint8_t **p, const uint8_t *end,
               int *major, uint64_t *arg)
{
    if (*p >= end) return -1;
    uint8_t ib = *(*p)++;
    *major = ib >> 5;
    uint8_t ai = ib & 0x1f;
    if (ai < 24) { *arg = ai; return 0; }
    int n;
    switch (ai) {
        case 24: n = 1; break;
        case 25: n = 2; break;
        case 26: n = 4; break;
        case 27: n = 8; break;
        default: return -1;   /* 28..31: not produced by CTAP encoders */
    }
    if (*p + n > end) return -1;
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v = (v << 8) | *(*p)++;
    *arg = v;
    return 0;
}

/* Locate the verbatim encoded bytes of the value stored under the
 * unsigned-integer key `key` in the CBOR map encoded at buf[0..len).
 * On a match, sets *out_ptr / *out_len to a slice of `buf` (no copy)
 * and returns true. Returns false if `buf` is not a definite-length
 * map, the key is absent, or the encoding is malformed/truncated. */
static inline bool
cbor_raw_map_value(const uint8_t *buf, size_t len, uint64_t key,
                   const uint8_t **out_ptr, size_t *out_len)
{
    const uint8_t *p = buf, *end = buf + len;
    int major; uint64_t n;
    if (cbor_read_head(&p, end, &major, &n) != 0 || major != 5)
        return false;                       /* not a map */
    for (uint64_t i = 0; i < n; i++) {
        int kmaj; uint64_t karg;
        if (cbor_read_head(&p, end, &kmaj, &karg) != 0) return false;
        /* A bytes/text key carries a payload after its head; uint and
         * negint keys are fully described by the head alone. */
        if (kmaj == 2 || kmaj == 3) {
            if ((size_t)(end - p) < karg) return false;
            p += karg;
        }
        size_t vlen = 0;
        if (pqfido_cbor_item_length(p, (size_t)(end - p), &vlen) != PQFIDO_OK)
            return false;
        if ((size_t)(end - p) < vlen) return false;
        if (kmaj == 0 && karg == key) {     /* unsigned-int key match */
            *out_ptr = p;
            *out_len = vlen;
            return true;
        }
        p += vlen;
    }
    return false;
}

#endif /* PQF_CBOR_READ_H */
