/* pqcbor.c
 *
 * Minimal CBOR decoder for Bruce's C tools. Written from RFC 8949 only
 * (specifically section 3, "Specification of the CBOR Encoding").
 *
 * Encoding refresher (RFC 8949 sec. 3):
 *
 *   Every CBOR data item starts with a one-byte head whose top three
 *   bits encode the major type (0..7) and whose bottom five bits hold
 *   the "additional information" (ai). The ai determines whether the
 *   item's argument is encoded inline (ai 0..23) or in the following
 *   1, 2, 4, or 8 bytes (ai 24, 25, 26, 27 respectively). ai 28..30
 *   are reserved and ai 31 indicates an indefinite-length item.
 *
 *   Major type semantics:
 *     0  argument is an unsigned integer
 *     1  argument is N; the integer's value is -1 - N
 *     2  argument is the length of a byte string; that many bytes follow
 *     3  argument is the length of a text string; that many UTF-8 bytes follow
 *     4  argument is the number of items in an array; that many items follow
 *     5  argument is the number of (k,v) pairs in a map; 2N items follow
 *     6  argument is a tag value; one tagged item follows
 *     7  simple value (ai 0..23, 24) or float (ai 25/26/27); "break" (ai 31)
 *
 * This decoder accepts only definite-length items. Indefinite-length
 * encoding (ai 31) is rejected, as FIDO2/CTAP2 never emits it.
 * Reserved additional-info codes (28..30) are also rejected. Major-7
 * floats (ai 25/26/27) are rejected too -- CTAP2 never sends a float,
 * and accepting one would store a raw bit pattern that a later reader
 * could misread as a number; only true simple values are decoded.
 *
 * Every function returns PQFIDO_OK or a negative PQFIDO_ERR_* value
 * (see pqcbor.h). The library never writes to stderr and never exits.
 *
 * Byte and text strings are zero-copy: `it->bytes` points into the
 * caller-supplied source buffer. Other items own heap memory which is
 * released by pqfido_cbor_free().
 *
 * Copyright (C) 2010-2026 Cryptsoft Pty Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pqcbor.h"

/* Internal item representation. Field usage by type:
 *
 *   UINT / NEGINT / SIMPLE : arg
 *   BYTES  / STRING        : arg = length, bytes = data (zero-copy)
 *   ARRAY                  : arg = count,  children = arg items
 *   MAP                    : arg = count,  pairs    = arg pairs
 *   TAG                    : arg = tag,    children = 1 nested item
 */
struct pqfido_cbor_item {
	pqfido_cbor_type_t    type;
	uint64_t              arg;
	const unsigned char  *bytes;
	pqfido_cbor_item_t  **children;
	pqfido_cbor_pair_t   *pairs;
};

/* ---- Version ---------------------------------------------------- */

const char *pqfido_cbor_version(void)
{
	return PQFIDO_CBOR_VERSION_STRING;
}

/* ---- Head parsing ----------------------------------------------- */

/* Decode the head at buf[*pos]: major type and uint64 argument.
 * On success advances *pos past the head and returns 0; on malformed
 * or truncated input returns -1. Distinguishing "malformed" from
 * "truncated" at this layer is not useful -- both surface as
 * PQFIDO_ERR_CBOR. */
static int pqcbor_read_head(const unsigned char *buf, size_t len,
                            size_t *pos,
                            int *majorOut, uint64_t *argOut)
{
	unsigned char ib;
	unsigned int ai;
	size_t nbytes;
	uint64_t v;
	size_t i;

	if(*pos >= len)
		return -1;

	ib = buf[*pos];
	*pos += 1;
	*majorOut = ib >> 5;
	ai = ib & 0x1f;

	if(ai < 24){
		*argOut = ai;
		return 0;
	}

	/* Major type 7 carries simple values (ai 0..23, 24) and floats
	 * (ai 25/26/27). FIDO2/CTAP2 never sends a float, and decoding one
	 * into the same SIMPLE slot as a small integer-like simple value
	 * would let a host smuggle a 16/32/64-bit bit pattern that a later
	 * reader could misread as a number (RFC 8949 sec. 3.3). Reject all
	 * major-7 floats up front; only definite simple values survive. */
	if(*majorOut == 7 && (ai == 25 || ai == 26 || ai == 27))
		return -1;

	switch(ai){
	case 24: nbytes = 1; break;
	case 25: nbytes = 2; break;
	case 26: nbytes = 4; break;
	case 27: nbytes = 8; break;
	default:
		/* ai 28..30 reserved; ai 31 indefinite-length (rejected) */
		return -1;
	}

	if(nbytes > len - *pos)
		return -1;

	v = 0;
	for(i = 0; i < nbytes; i++)
		v = (v << 8) | buf[*pos + i];

	*pos += nbytes;
	*argOut = v;
	return 0;
}

/* ---- Allocation helpers ----------------------------------------- */

static pqfido_cbor_item_t *pqcbor_alloc(pqfido_cbor_type_t type, uint64_t arg)
{
	pqfido_cbor_item_t *it;

	it = (pqfido_cbor_item_t *)calloc(1, sizeof(*it));
	if(it == NULL)
		return NULL;
	it->type = type;
	it->arg = arg;
	return it;
}

/* ---- Recursive decode -------------------------------------------- */

/* Compare two decoded map keys for equality (RFC 8949 sec. 5.6 duplicate
 * detection). CTAP map keys are only small uints, negints, or short
 * text/byte strings; that's all this needs to cover.
 *
 * For UINT / NEGINT / SIMPLE the scalar `arg` fully identifies the key,
 * so equal type + equal arg means equal key. For BYTES / STRING `arg`
 * is the payload length and `bytes` the payload, so the content is
 * compared as well.
 *
 * For the COMPOUND types (ARRAY / MAP / TAG) `arg` is the element /
 * pair COUNT, NOT a value -- two structurally distinct compound keys
 * that merely share the same count (e.g. [1,2] vs [3,4], both arg==2)
 * are NOT equal. Comparing them by `arg` alone would falsely reject a
 * well-formed, key-distinct map (the element bytes are never consulted
 * here). Such keys never appear in CTAP, so rather than recurse we
 * conservatively report not-equal and let the input through. */
static int pqcbor_key_equal(const pqfido_cbor_item_t *a,
                            const pqfido_cbor_item_t *b)
{
	if(a == NULL || b == NULL) return 0;
	if(a->type != b->type || a->arg != b->arg) return 0;
	switch(a->type){
	case PQFIDO_CBOR_BYTES:
	case PQFIDO_CBOR_STRING:
		return a->arg == 0
		    || memcmp(a->bytes, b->bytes, (size_t)a->arg) == 0;
	case PQFIDO_CBOR_UINT:
	case PQFIDO_CBOR_NEGINT:
	case PQFIDO_CBOR_SIMPLE:
		return 1;  /* scalar arg fully identifies the key */
	default:
		/* ARRAY / MAP / TAG: arg is a count, not a value -- equal
		 * count does not imply an equal compound key. */
		return 0;
	}
}

/* Parse one CBOR item. On success returns PQFIDO_OK with *out set; on
 * failure returns PQFIDO_ERR_CBOR / PQFIDO_ERR_NOMEM with *out cleared. */
static int pqcbor_parse_one(const unsigned char *buf, size_t len,
                            size_t *pos, int depth,
                            pqfido_cbor_item_t **out)
{
	int major;
	uint64_t arg;
	pqfido_cbor_item_t *it;
	size_t i;
	size_t n;
	int rc;

	*out = NULL;

	if(depth <= 0)
		return PQFIDO_ERR_CBOR;

	if(pqcbor_read_head(buf, len, pos, &major, &arg) != 0)
		return PQFIDO_ERR_CBOR;

	switch(major){
	case 0: /* unsigned integer */
		it = pqcbor_alloc(PQFIDO_CBOR_UINT, arg);
		if(it == NULL) return PQFIDO_ERR_NOMEM;
		*out = it;
		return PQFIDO_OK;

	case 1: /* negative integer; value == -1 - arg */
		it = pqcbor_alloc(PQFIDO_CBOR_NEGINT, arg);
		if(it == NULL) return PQFIDO_ERR_NOMEM;
		*out = it;
		return PQFIDO_OK;

	case 2: /* byte string */
	case 3: /* text string */
		if(arg > (uint64_t)(len - *pos))
			return PQFIDO_ERR_CBOR;
		if(arg > (uint64_t)SIZE_MAX)
			return PQFIDO_ERR_CBOR;
		it = pqcbor_alloc((pqfido_cbor_type_t)major, arg);
		if(it == NULL) return PQFIDO_ERR_NOMEM;
		it->bytes = buf + *pos;
		*pos += (size_t)arg;
		*out = it;
		return PQFIDO_OK;

	case 4: /* array of arg items */
		/* Each item is at least one byte, so an arg larger than the
		 * remaining buffer cannot be honest; also guard the allocation
		 * size against multiplicative overflow. */
		if(arg > (uint64_t)(len - *pos))
			return PQFIDO_ERR_CBOR;
		if(arg > SIZE_MAX / sizeof(pqfido_cbor_item_t *))
			return PQFIDO_ERR_CBOR;
		it = pqcbor_alloc(PQFIDO_CBOR_ARRAY, arg);
		if(it == NULL) return PQFIDO_ERR_NOMEM;
		n = (size_t)arg;
		if(n > 0){
			it->children = (pqfido_cbor_item_t **)
			  calloc(n, sizeof(pqfido_cbor_item_t *));
			if(it->children == NULL){
				pqfido_cbor_free(it);
				return PQFIDO_ERR_NOMEM;
			}
			for(i = 0; i < n; i++){
				rc = pqcbor_parse_one(buf, len, pos,
				  depth - 1, &it->children[i]);
				if(rc != PQFIDO_OK){
					pqfido_cbor_free(it);
					return rc;
				}
			}
		}
		*out = it;
		return PQFIDO_OK;

	case 5: /* map of arg pairs */
		/* Each pair is at least two bytes. */
		if(arg > (uint64_t)((len - *pos) / 2))
			return PQFIDO_ERR_CBOR;
		if(arg > SIZE_MAX / sizeof(pqfido_cbor_pair_t))
			return PQFIDO_ERR_CBOR;
		it = pqcbor_alloc(PQFIDO_CBOR_MAP, arg);
		if(it == NULL) return PQFIDO_ERR_NOMEM;
		n = (size_t)arg;
		if(n > 0){
			it->pairs = (pqfido_cbor_pair_t *)
			  calloc(n, sizeof(pqfido_cbor_pair_t));
			if(it->pairs == NULL){
				pqfido_cbor_free(it);
				return PQFIDO_ERR_NOMEM;
			}
			for(i = 0; i < n; i++){
				rc = pqcbor_parse_one(buf, len, pos,
				  depth - 1, &it->pairs[i].key);
				if(rc != PQFIDO_OK){
					pqfido_cbor_free(it);
					return rc;
				}
				/* Reject duplicate keys (RFC 8949 sec. 5.6 /
				 * CTAP 2.1 sec. 6): silent first-match would let
				 * a peer smuggle a second value past the
				 * reader. */
				{
					size_t j;
					for(j = 0; j < i; j++)
						if(pqcbor_key_equal(
						     it->pairs[j].key,
						     it->pairs[i].key)){
							pqfido_cbor_free(it);
							return PQFIDO_ERR_CBOR;
						}
				}
				rc = pqcbor_parse_one(buf, len, pos,
				  depth - 1, &it->pairs[i].value);
				if(rc != PQFIDO_OK){
					pqfido_cbor_free(it);
					return rc;
				}
			}
		}
		*out = it;
		return PQFIDO_OK;

	case 6: /* tagged item: tag value `arg`, then one nested item */
		it = pqcbor_alloc(PQFIDO_CBOR_TAG, arg);
		if(it == NULL) return PQFIDO_ERR_NOMEM;
		it->children = (pqfido_cbor_item_t **)
		  calloc(1, sizeof(pqfido_cbor_item_t *));
		if(it->children == NULL){
			pqfido_cbor_free(it);
			return PQFIDO_ERR_NOMEM;
		}
		rc = pqcbor_parse_one(buf, len, pos,
		  depth - 1, &it->children[0]);
		if(rc != PQFIDO_OK){
			pqfido_cbor_free(it);
			return rc;
		}
		*out = it;
		return PQFIDO_OK;

	case 7: /* simple values (false/true/null/undefined and ai-24
	         * simple values); floats are rejected in read_head */
		it = pqcbor_alloc(PQFIDO_CBOR_SIMPLE, arg);
		if(it == NULL) return PQFIDO_ERR_NOMEM;
		*out = it;
		return PQFIDO_OK;
	}

	return PQFIDO_ERR_CBOR;
}

/* ---- Public decode + free ---------------------------------------- */

int pqfido_cbor_decode(const unsigned char *buf, size_t len,
  pqfido_cbor_item_t **out)
{
	size_t pos = 0;

	if(out == NULL)
		return PQFIDO_ERR_INVAL;
	*out = NULL;

	if(buf == NULL || len == 0)
		return PQFIDO_ERR_INVAL;

	return pqcbor_parse_one(buf, len, &pos,
	  PQFIDO_CBOR_MAX_DEPTH, out);
}

void pqfido_cbor_free(pqfido_cbor_item_t *it)
{
	size_t i;
	size_t n;

	if(it == NULL)
		return;

	switch(it->type){
	case PQFIDO_CBOR_ARRAY:
		if(it->children != NULL){
			n = (size_t)it->arg;
			for(i = 0; i < n; i++)
				pqfido_cbor_free(it->children[i]);
			free(it->children);
		}
		break;

	case PQFIDO_CBOR_MAP:
		if(it->pairs != NULL){
			n = (size_t)it->arg;
			for(i = 0; i < n; i++){
				pqfido_cbor_free(it->pairs[i].key);
				pqfido_cbor_free(it->pairs[i].value);
			}
			free(it->pairs);
		}
		break;

	case PQFIDO_CBOR_TAG:
		if(it->children != NULL){
			pqfido_cbor_free(it->children[0]);
			free(it->children);
		}
		break;

	default:
		/* UINT, NEGINT, BYTES, STRING, SIMPLE: no owned heap */
		break;
	}
	free(it);
}

/* ---- Predicates -------------------------------------------------- */

int pqfido_cbor_is_uint(const pqfido_cbor_item_t *it)
  { return it != NULL && it->type == PQFIDO_CBOR_UINT; }
int pqfido_cbor_is_negint(const pqfido_cbor_item_t *it)
  { return it != NULL && it->type == PQFIDO_CBOR_NEGINT; }
int pqfido_cbor_is_bytes(const pqfido_cbor_item_t *it)
  { return it != NULL && it->type == PQFIDO_CBOR_BYTES; }
int pqfido_cbor_is_string(const pqfido_cbor_item_t *it)
  { return it != NULL && it->type == PQFIDO_CBOR_STRING; }
int pqfido_cbor_is_array(const pqfido_cbor_item_t *it)
  { return it != NULL && it->type == PQFIDO_CBOR_ARRAY; }
int pqfido_cbor_is_map(const pqfido_cbor_item_t *it)
  { return it != NULL && it->type == PQFIDO_CBOR_MAP; }
/* RFC 8949 section 3: simple value 20 = false, 21 = true. */
int pqfido_cbor_is_bool(const pqfido_cbor_item_t *it)
  { return it != NULL && it->type == PQFIDO_CBOR_SIMPLE
           && (it->arg == 20 || it->arg == 21); }

/* ---- Accessors --------------------------------------------------- */

int pqfido_cbor_bool(const pqfido_cbor_item_t *it)
  { return it->arg == 21; }

uint64_t pqfido_cbor_uint(const pqfido_cbor_item_t *it)
  { return it->arg; }
uint64_t pqfido_cbor_negint_arg(const pqfido_cbor_item_t *it)
  { return it->arg; }

const unsigned char *pqfido_cbor_bytes(const pqfido_cbor_item_t *it)
  { return it->bytes; }
size_t pqfido_cbor_bytes_len(const pqfido_cbor_item_t *it)
  { return (size_t)it->arg; }
const unsigned char *pqfido_cbor_string(const pqfido_cbor_item_t *it)
  { return it->bytes; }
size_t pqfido_cbor_string_len(const pqfido_cbor_item_t *it)
  { return (size_t)it->arg; }

size_t pqfido_cbor_array_size(const pqfido_cbor_item_t *it)
  { return (size_t)it->arg; }

pqfido_cbor_item_t *pqfido_cbor_array_get(const pqfido_cbor_item_t *it,
  size_t idx)
{
	if(it == NULL || it->type != PQFIDO_CBOR_ARRAY)
		return NULL;
	if(idx >= (size_t)it->arg)
		return NULL;
	return it->children[idx];
}

size_t pqfido_cbor_map_size(const pqfido_cbor_item_t *it)
  { return (size_t)it->arg; }

const pqfido_cbor_pair_t *pqfido_cbor_map_pairs(const pqfido_cbor_item_t *it)
{
	if(it == NULL || it->type != PQFIDO_CBOR_MAP)
		return NULL;
	return it->pairs;
}

/* ---- Length scanner (no tree allocation) ------------------------- */

/* Tree-free pass over one CBOR item. Mirrors the parse logic but only
 * advances `*pos` without allocating. Returns PQFIDO_OK or
 * PQFIDO_ERR_CBOR. */
static int pqcbor_walk(const unsigned char *buf, size_t len, size_t *pos,
                       int depth)
{
	int major;
	uint64_t arg;
	uint64_t i;
	uint64_t n;
	int rc;

	if(depth <= 0)
		return PQFIDO_ERR_CBOR;

	if(pqcbor_read_head(buf, len, pos, &major, &arg) != 0)
		return PQFIDO_ERR_CBOR;

	switch(major){
	case 0:
	case 1:
	case 7:
		return PQFIDO_OK;

	case 2:
	case 3:
		if(arg > (uint64_t)(len - *pos))
			return PQFIDO_ERR_CBOR;
		*pos += (size_t)arg;
		return PQFIDO_OK;

	case 4:
		/* Each item is at least one byte, so an arg larger than the
		 * remaining buffer cannot be honest (mirrors the bound in
		 * pqcbor_parse_one). */
		if(arg > (uint64_t)(len - *pos))
			return PQFIDO_ERR_CBOR;
		n = arg;
		for(i = 0; i < n; i++){
			rc = pqcbor_walk(buf, len, pos, depth - 1);
			if(rc != PQFIDO_OK) return rc;
		}
		return PQFIDO_OK;

	case 5:
		/* Each pair is at least two bytes (mirrors pqcbor_parse_one). */
		if(arg > (uint64_t)((len - *pos) / 2))
			return PQFIDO_ERR_CBOR;
		n = arg;
		for(i = 0; i < n; i++){
			rc = pqcbor_walk(buf, len, pos, depth - 1);
			if(rc != PQFIDO_OK) return rc;
			rc = pqcbor_walk(buf, len, pos, depth - 1);
			if(rc != PQFIDO_OK) return rc;
		}
		return PQFIDO_OK;

	case 6:
		return pqcbor_walk(buf, len, pos, depth - 1);
	}
	return PQFIDO_ERR_CBOR;
}

int pqfido_cbor_item_length(const unsigned char *buf, size_t len,
  size_t *outLen)
{
	size_t pos = 0;
	int rc;

	if(outLen == NULL)
		return PQFIDO_ERR_INVAL;
	*outLen = 0;

	if(buf == NULL || len == 0)
		return PQFIDO_ERR_INVAL;

	rc = pqcbor_walk(buf, len, &pos, PQFIDO_CBOR_MAX_DEPTH);
	if(rc != PQFIDO_OK)
		return rc;

	*outLen = pos;
	return PQFIDO_OK;
}
