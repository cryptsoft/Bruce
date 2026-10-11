/* smoke.c -- sanity-check program for the vendored pqcbor codec.
 *
 * Decodes three small fixtures that exercise the major-type
 * coverage and prints a one-line summary. Exit 0 on success.
 *
 * Build via `make smoke` or `make test` in this directory.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "pqcbor.h"

static int
fail(const char *msg)
{
	fprintf(stderr, "smoke: FAIL: %s\n", msg);
	return 1;
}

int
main(void)
{
	printf("pqcbor version: %s\n", pqfido_cbor_version());

	/* Fixture 1: unsigned int 23 (CBOR 0x17). */
	{
		const unsigned char wire[] = { 0x17 };
		pqfido_cbor_item_t *it = NULL;
		int rc = pqfido_cbor_decode(wire, sizeof(wire), &it);
		if(rc != PQFIDO_OK || !pqfido_cbor_is_uint(it)) {
			pqfido_cbor_free(it);
			return fail("decode uint 23");
		}
		if(pqfido_cbor_uint(it) != 23) {
			pqfido_cbor_free(it);
			return fail("uint 23 value");
		}
		pqfido_cbor_free(it);
		printf("  uint 23: ok\n");
	}

	/* Fixture 2: negative int -7 (CBOR 0x26 = mt=1, arg=6, value=-1-6=-7).
	 *            Used as the ES256 COSE alg id. */
	{
		const unsigned char wire[] = { 0x26 };
		pqfido_cbor_item_t *it = NULL;
		int rc = pqfido_cbor_decode(wire, sizeof(wire), &it);
		if(rc != PQFIDO_OK || !pqfido_cbor_is_negint(it)) {
			pqfido_cbor_free(it);
			return fail("decode negint -7");
		}
		if(pqfido_cbor_negint_arg(it) != 6) {
			pqfido_cbor_free(it);
			return fail("negint arg 6");
		}
		pqfido_cbor_free(it);
		printf("  negint -7 (arg=6): ok\n");
	}

	/* Fixture 3: tiny map {1: "a"} = 0xA1 0x01 0x61 'a'. */
	{
		const unsigned char wire[] = { 0xa1, 0x01, 0x61, 'a' };
		pqfido_cbor_item_t *it = NULL;
		int rc = pqfido_cbor_decode(wire, sizeof(wire), &it);
		if(rc != PQFIDO_OK || !pqfido_cbor_is_map(it)) {
			pqfido_cbor_free(it);
			return fail("decode map");
		}
		if(pqfido_cbor_map_size(it) != 1) {
			pqfido_cbor_free(it);
			return fail("map size 1");
		}
		const pqfido_cbor_pair_t *pairs = pqfido_cbor_map_pairs(it);
		if(!pqfido_cbor_is_uint(pairs[0].key)
		   || pqfido_cbor_uint(pairs[0].key) != 1) {
			pqfido_cbor_free(it);
			return fail("map key");
		}
		if(!pqfido_cbor_is_string(pairs[0].value)
		   || pqfido_cbor_string_len(pairs[0].value) != 1
		   || pqfido_cbor_string(pairs[0].value)[0] != 'a') {
			pqfido_cbor_free(it);
			return fail("map value");
		}
		pqfido_cbor_free(it);
		printf("  map {1: \"a\"}: ok\n");
	}

	/* Fixture 4: tree-free length scan over the same map. */
	{
		const unsigned char wire[] = { 0xa1, 0x01, 0x61, 'a', 0xff, 0xff };
		size_t consumed = 0;
		int rc = pqfido_cbor_item_length(wire, sizeof(wire), &consumed);
		if(rc != PQFIDO_OK) return fail("length scan");
		if(consumed != 4) return fail("length scan byte count");
		printf("  length scan: 4 bytes ok\n");
	}

	/* Fixture 5: indefinite-length array (0x9f) is rejected. */
	{
		const unsigned char wire[] = { 0x9f, 0x01, 0xff };
		pqfido_cbor_item_t *it = NULL;
		int rc = pqfido_cbor_decode(wire, sizeof(wire), &it);
		if(rc != PQFIDO_ERR_CBOR || it != NULL) {
			pqfido_cbor_free(it);
			return fail("indefinite-length not rejected");
		}
		printf("  indefinite-length rejected: ok\n");
	}

	printf("all fixtures pass\n");
	return 0;
}
