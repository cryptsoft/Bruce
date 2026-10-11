/* cbor_encode.h -- minimal CBOR encoder (RFC 8949).
 *
 * Covers the subset CTAP 2.1 responses need:
 *   - unsigned integers (major type 0)
 *   - negative integers (major type 1) -- for COSE alg ids
 *   - byte strings (major type 2)
 *   - text strings (major type 3)
 *   - arrays  (major type 4) -- header only; caller appends items
 *   - maps    (major type 5) -- header only; caller appends pairs
 *   - the simple values false / true (major type 7, values 20 / 21)
 *
 * Shortest-form integer encoding throughout -- canonical CBOR sec. 4.2.1.
 * Caller is responsible for emitting map keys in canonical order;
 * for the small-integer keys we use (1..N) that's just numeric order.
 *
 * No allocations. The writer wraps a caller-supplied buffer; if a
 * write would overflow, an internal error flag latches and all
 * subsequent writes become no-ops. Inspect via cbor_w_ok() / cbor_w_off()
 * after the last emit to decide whether to ship the buffer.
 *
 * Companion to the vendored decoder at `c/cbor/pqcbor.{c,h}` -- same
 * codec on the device, two roles split across two source files.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CBOR_ENCODE_H
#define PQF_CBOR_ENCODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    uint8_t *buf;       /* caller-owned output buffer        */
    size_t   cap;       /* total writable bytes              */
    size_t   off;       /* bytes written so far              */
    bool     err;       /* set on overflow; sticky           */
} cbor_writer_t;

void cbor_w_init(cbor_writer_t *w, uint8_t *buf, size_t cap);

/* Inspectors. After emission, ship `buf[0..off)` if ok() is true. */
static inline bool   cbor_w_ok (const cbor_writer_t *w) { return !w->err; }
static inline size_t cbor_w_off(const cbor_writer_t *w) { return w->off;   }

/* Major type 0 -- unsigned integer, shortest form. */
void cbor_w_uint(cbor_writer_t *w, uint64_t n);

/* Major type 1 -- negative integer. `arg` is the raw argument N, so
 * the encoded value is -1 - N (per RFC 8949 sec. 3). For example, to
 * emit COSE alg -7 (ES256), pass arg = 6. */
void cbor_w_negint(cbor_writer_t *w, uint64_t arg);

/* Convenience: signed integer. Dispatches to uint / negint. */
void cbor_w_int(cbor_writer_t *w, int64_t n);

/* Major type 2 -- byte string. */
void cbor_w_bytes(cbor_writer_t *w, const uint8_t *data, size_t len);

/* Major type 3 -- text string. cbor_w_text() takes a NUL-terminated
 * C string; cbor_w_text_n() takes an explicit length so callers can
 * pass non-NUL-terminated buffers. */
void cbor_w_text  (cbor_writer_t *w, const char *str);
void cbor_w_text_n(cbor_writer_t *w, const char *str, size_t len);

/* Major types 4 / 5 -- write only the header (major + count). The
 * caller must emit exactly `count` items for arrays, or `count`
 * key-value pairs (2*count items) for maps. */
void cbor_w_array_header(cbor_writer_t *w, size_t count);
void cbor_w_map_header  (cbor_writer_t *w, size_t count);

/* Major type 7 -- simple values false (20) and true (21). */
void cbor_w_bool(cbor_writer_t *w, bool b);

/* Splice a pre-encoded CBOR item in verbatim. `data` must be exactly
 * one well-formed CBOR item so the enclosing structure's item/pair
 * counts stay correct. */
void cbor_w_raw(cbor_writer_t *w, const uint8_t *data, size_t len);

#endif /* PQF_CBOR_ENCODE_H */
