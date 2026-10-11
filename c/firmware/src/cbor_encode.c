/* cbor_encode.c -- minimal CBOR encoder.
 *
 * Implements the subset of RFC 8949 that the CTAP 2.1 device-side
 * response set uses: definite-length items only, shortest-form
 * integer encoding throughout (RFC 8949 sec. 4.2.1 canonical), no
 * floats, no tags, no indefinite-length items.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "cbor_encode.h"

void cbor_w_init(cbor_writer_t *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->off = 0;
    w->err = false;
}

/* Internal: bounded write of N bytes. Latches the overflow flag and
 * makes all subsequent writes a no-op. */
static void put_n(cbor_writer_t *w, const uint8_t *src, size_t n)
{
    if (w->err) return;
    if (n > w->cap - w->off) {
        w->err = true;
        return;
    }
    memcpy(&w->buf[w->off], src, n);
    w->off += n;
}

static void put1(cbor_writer_t *w, uint8_t b)
{
    put_n(w, &b, 1);
}

/* Emit one CBOR head: (major << 5) | additional info.
 *
 * RFC 8949 sec. 3:
 *   info 0..23   -> value encoded directly in the head byte
 *   info 24      -> 1-byte argument follows
 *   info 25      -> 2-byte big-endian argument
 *   info 26      -> 4-byte big-endian argument
 *   info 27      -> 8-byte big-endian argument
 *
 * Shortest-form per canonical sec. 4.2.1: pick the smallest form that
 * fits `n`. */
static void emit_head(cbor_writer_t *w, uint8_t major, uint64_t n)
{
    uint8_t mt = (uint8_t)(major << 5);

    if (n < 24) {
        put1(w, mt | (uint8_t)n);
    } else if (n <= 0xff) {
        put1(w, mt | 24);
        put1(w, (uint8_t)n);
    } else if (n <= 0xffff) {
        put1(w, mt | 25);
        put1(w, (uint8_t)(n >> 8));
        put1(w, (uint8_t)n);
    } else if (n <= 0xffffffffu) {
        put1(w, mt | 26);
        put1(w, (uint8_t)(n >> 24));
        put1(w, (uint8_t)(n >> 16));
        put1(w, (uint8_t)(n >>  8));
        put1(w, (uint8_t)n);
    } else {
        put1(w, mt | 27);
        put1(w, (uint8_t)(n >> 56));
        put1(w, (uint8_t)(n >> 48));
        put1(w, (uint8_t)(n >> 40));
        put1(w, (uint8_t)(n >> 32));
        put1(w, (uint8_t)(n >> 24));
        put1(w, (uint8_t)(n >> 16));
        put1(w, (uint8_t)(n >>  8));
        put1(w, (uint8_t)n);
    }
}

/* ---- Public emitters ------------------------------------------- */

void cbor_w_uint(cbor_writer_t *w, uint64_t n)
{
    emit_head(w, 0, n);
}

void cbor_w_negint(cbor_writer_t *w, uint64_t arg)
{
    emit_head(w, 1, arg);
}

void cbor_w_int(cbor_writer_t *w, int64_t n)
{
    if (n >= 0) {
        cbor_w_uint(w, (uint64_t)n);
    } else {
        /* -1 - arg = n  ->  arg = -1 - n  ->  arg = -(n + 1).
         * For n == INT64_MIN this overflows the signed range; the
         * cast through uint64_t makes the arithmetic defined and
         * correct mod 2^64. */
        uint64_t arg = (uint64_t)(-(n + 1));
        cbor_w_negint(w, arg);
    }
}

void cbor_w_bytes(cbor_writer_t *w, const uint8_t *data, size_t len)
{
    emit_head(w, 2, (uint64_t)len);
    if (len) put_n(w, data, len);
}

void cbor_w_text_n(cbor_writer_t *w, const char *str, size_t len)
{
    emit_head(w, 3, (uint64_t)len);
    if (len) put_n(w, (const uint8_t *)str, len);
}

void cbor_w_text(cbor_writer_t *w, const char *str)
{
    cbor_w_text_n(w, str, strlen(str));
}

void cbor_w_array_header(cbor_writer_t *w, size_t count)
{
    emit_head(w, 4, (uint64_t)count);
}

void cbor_w_map_header(cbor_writer_t *w, size_t count)
{
    emit_head(w, 5, (uint64_t)count);
}

void cbor_w_bool(cbor_writer_t *w, bool b)
{
    /* Major type 7, value 20 (false) / 21 (true). Encoded directly
     * in the head byte (additional info = value). */
    put1(w, (uint8_t)(0xe0 | (b ? 21 : 20)));
}

void cbor_w_raw(cbor_writer_t *w, const uint8_t *data, size_t len)
{
    /* Splice an already-encoded CBOR item in verbatim. The caller is
     * responsible for `data` being a single well-formed CBOR item, so
     * the surrounding structure (map/array headers + counts) stays
     * consistent. Used to embed a sub-parameters map whose exact bytes
     * must also be authenticated by a pinUvAuthParam MAC. */
    if (len) put_n(w, data, len);
}
