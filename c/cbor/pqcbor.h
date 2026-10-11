/* pqcbor.h
 *
 * Minimal CBOR decoder for Bruce's C tools.
 *
 * Implements the subset of RFC 8949 needed to parse FIDO2/WebAuthn
 * attestation objects, authenticator data, COSE keys, and packed
 * attestation statements:
 *
 *   - All eight major types (0..7) for definite-length items.
 *   - Indefinite-length items (additional info 31) are rejected, since
 *     FIDO2/CTAP2 encoders never produce them.
 *   - Reserved additional-info codes (28..30) are rejected.
 *   - Recursion depth is bounded to defeat hostile input.
 *   - Byte and text strings are zero-copy: their `bytes` pointers point
 *     into the caller-supplied source buffer, which must outlive any
 *     parsed tree that references it.
 *
 * The implementation is written from RFC 8949 alone -- no code is copied
 * from any third-party CBOR library.
 *
 * SDK conventions:
 *   - all public symbols use the pqfido_cbor_ / PQFIDO_CBOR_ prefix
 *   - every function returns PQFIDO_OK or a negative PQFIDO_ERR_* value
 *     (defined in this header -- see the "Result codes" section below)
 *
 * The codec is self-contained: this header declares its own minimal
 * set of PQFIDO_OK / PQFIDO_ERR_* / version macros, so nothing else
 * has to be linked to use it.
 *
 * Copyright (C) 2010-2026 Cryptsoft Pty Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQFIDO_PQCBOR_H
#define PQFIDO_PQCBOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Result codes ----
 *
 * Declared here so this codec is standalone. The numeric values are
 * shared with pqhid.h so a caller that links both can pass codes
 * between the two unchanged. */

#ifndef PQFIDO_OK
#define PQFIDO_OK                        0
#endif
#ifndef PQFIDO_ERR_INVAL
#define PQFIDO_ERR_INVAL                -1   /* invalid argument */
#endif
#ifndef PQFIDO_ERR_NOMEM
#define PQFIDO_ERR_NOMEM                -2   /* memory allocation failed */
#endif
#ifndef PQFIDO_ERR_CBOR
#define PQFIDO_ERR_CBOR                 -4   /* CBOR decode error */
#endif

/* ---- Version ----
 *
 * These macros and the corresponding pqfido_cbor_version() function
 * report the codec's own version. */

#ifndef PQFIDO_VERSION_MAJOR
#define PQFIDO_VERSION_MAJOR    0
#endif
#ifndef PQFIDO_VERSION_MINOR
#define PQFIDO_VERSION_MINOR    5
#endif
#ifndef PQFIDO_VERSION_PATCH
#define PQFIDO_VERSION_PATCH    0
#endif
#ifndef PQFIDO_VERSION_STRING
#define PQFIDO_VERSION_STRING   "0.5.0"
#endif

#define PQFIDO_CBOR_VERSION_MAJOR   PQFIDO_VERSION_MAJOR
#define PQFIDO_CBOR_VERSION_MINOR   PQFIDO_VERSION_MINOR
#define PQFIDO_CBOR_VERSION_PATCH   PQFIDO_VERSION_PATCH
#define PQFIDO_CBOR_VERSION_STRING  PQFIDO_VERSION_STRING

/* Return the pqcbor version as a NUL-terminated "MAJOR.MINOR.PATCH" string. */
const char *pqfido_cbor_version(void);

/* ---- Types ---- */

typedef enum {
	PQFIDO_CBOR_UINT    = 0,
	PQFIDO_CBOR_NEGINT  = 1,
	PQFIDO_CBOR_BYTES   = 2,
	PQFIDO_CBOR_STRING  = 3,
	PQFIDO_CBOR_ARRAY   = 4,
	PQFIDO_CBOR_MAP     = 5,
	PQFIDO_CBOR_TAG     = 6,
	PQFIDO_CBOR_SIMPLE  = 7
} pqfido_cbor_type_t;

typedef struct pqfido_cbor_item  pqfido_cbor_item_t;

typedef struct pqfido_cbor_pair {
	pqfido_cbor_item_t *key;
	pqfido_cbor_item_t *value;
} pqfido_cbor_pair_t;

/* Maximum nesting depth honoured by the decoder. FIDO2 attestation trees
 * are at most ~4 levels deep; this is a defensive cap on hostile input. */
#define PQFIDO_CBOR_MAX_DEPTH   32

/* ---- Decode / free ----
 *
 * Decode one top-level CBOR item from buf[0..len). The source buffer
 * must remain alive while the returned tree is in use, because BYTES
 * and STRING items hold pointers into it. Trailing bytes after the
 * top-level item are ignored.
 *
 * On success: *out is set to the parsed tree and PQFIDO_OK is returned.
 * On failure: *out is set to NULL and the return value is one of:
 *   PQFIDO_ERR_INVAL    NULL buffer or zero length
 *   PQFIDO_ERR_NOMEM    out-of-memory during tree allocation
 *   PQFIDO_ERR_CBOR     malformed input, indefinite-length, reserved
 *                       additional-info, or recursion depth exceeded
 */
int pqfido_cbor_decode(const unsigned char *buf, size_t len,
  pqfido_cbor_item_t **out);

/* Recursively free a decoded tree. Safe to call with NULL. */
void pqfido_cbor_free(pqfido_cbor_item_t *item);

/* ---- Type predicates (NULL-safe -- return 0 on NULL) ---- */

int pqfido_cbor_is_uint  (const pqfido_cbor_item_t *it);
int pqfido_cbor_is_negint(const pqfido_cbor_item_t *it);
int pqfido_cbor_is_bytes (const pqfido_cbor_item_t *it);
int pqfido_cbor_is_string(const pqfido_cbor_item_t *it);
int pqfido_cbor_is_array (const pqfido_cbor_item_t *it);
int pqfido_cbor_is_map   (const pqfido_cbor_item_t *it);
/* True only for the boolean simple values (RFC 8949 section 3: simple
 * value 20 = false, 21 = true); other simple values return 0. */
int pqfido_cbor_is_bool  (const pqfido_cbor_item_t *it);

/* ---- Accessors ----
 * Callers must check the type first; results on a mismatched type are
 * undefined (the decoder never produces such a structure). */

/* For PQFIDO_CBOR_UINT: the unsigned value. */
uint64_t pqfido_cbor_uint(const pqfido_cbor_item_t *it);

/* For PQFIDO_CBOR_NEGINT: the raw argument N. The mathematical value
 * of the integer is -1 - N (per RFC 8949 section 3). */
uint64_t pqfido_cbor_negint_arg(const pqfido_cbor_item_t *it);

/* For a boolean simple value (check pqfido_cbor_is_bool first): 1 for
 * true (simple value 21), 0 for false (simple value 20). */
int pqfido_cbor_bool(const pqfido_cbor_item_t *it);

/* For PQFIDO_CBOR_BYTES / PQFIDO_CBOR_STRING: pointer into the source
 * buffer and length in bytes. Text strings are NOT NUL-terminated. */
const unsigned char *pqfido_cbor_bytes     (const pqfido_cbor_item_t *it);
size_t               pqfido_cbor_bytes_len (const pqfido_cbor_item_t *it);
const unsigned char *pqfido_cbor_string    (const pqfido_cbor_item_t *it);
size_t               pqfido_cbor_string_len(const pqfido_cbor_item_t *it);

/* For PQFIDO_CBOR_ARRAY: element count and per-index access. */
size_t              pqfido_cbor_array_size(const pqfido_cbor_item_t *it);
pqfido_cbor_item_t *pqfido_cbor_array_get (const pqfido_cbor_item_t *it,
  size_t idx);

/* For PQFIDO_CBOR_MAP: pair count and pointer to the contiguous pair
 * array (key0,val0,key1,val1,...). Pairs preserve insertion order. */
size_t                    pqfido_cbor_map_size (const pqfido_cbor_item_t *it);
const pqfido_cbor_pair_t *pqfido_cbor_map_pairs(const pqfido_cbor_item_t *it);

/* ---- Tree-free length scanner ----
 *
 * Scan one CBOR item without building a tree and report its encoded
 * byte length via *outLen. Used to locate where an embedded item ends
 * inside a larger byte stream (for example, the COSE key nested inside
 * authData).
 *
 * Returns PQFIDO_OK on success (with *outLen set), or one of:
 *   PQFIDO_ERR_INVAL  NULL buffer / zero length / NULL outLen
 *   PQFIDO_ERR_CBOR   malformed input, indefinite-length, reserved
 *                     additional-info, or recursion depth exceeded
 */
int pqfido_cbor_item_length(const unsigned char *buf, size_t len,
  size_t *outLen);

#ifdef __cplusplus
}
#endif

#endif /* PQFIDO_PQCBOR_H */
