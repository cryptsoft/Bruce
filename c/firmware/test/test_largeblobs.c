/* test_largeblobs.c -- host test of authenticatorLargeBlobs (0x0C) and
 * the largeBlobKey extension.
 *
 * No PIN is set, so large-blob writes need no pinUvAuthParam -- the
 * test focuses on the offset/length read/write protocol, the SHA-256
 * trailer validation, and the deterministic per-credential
 * largeBlobKey returned by MakeCredential (0x05) / GetAssertion (0x07).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "ctap2.h"
#include "credential.h"
#include "large_blobs.h"
#include "flash_store.h"
#include "cbor_encode.h"
#include "cbor_read.h"
#include "pqcbor.h"
#include "pqf_crypto.h"

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("  ok: %s\n", m); \
    else { fprintf(stderr, "FAIL: %s\n", m); fails++; } } while (0)

static const uint8_t CDH[32] = {
    0xaa,1,2,3,4,5,6,7, 8,9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23, 24,25,26,27,28,29,30,0xbb,
};

/* authenticatorLargeBlobs read (offset, length). Copies out the 0x01
 * config slice. Returns the status byte. */
static uint8_t lb_read(uint32_t offset, uint32_t len,
                       uint8_t *out, size_t *out_len)
{
    uint8_t msg[64]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, len);        /* get */
    cbor_w_uint(&w, 0x03); cbor_w_uint(&w, offset);
    msg[0] = CTAP2_CMD_LARGE_BLOBS;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return resp[0];
    *out_len = 0;
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *cfg = cbor_map_get_uint(m, 0x01);
    if (cfg && pqfido_cbor_is_bytes(cfg)) {
        *out_len = pqfido_cbor_bytes_len(cfg);
        memcpy(out, pqfido_cbor_bytes(cfg), *out_len);
    }
    pqfido_cbor_free(m);
    return CTAP2_OK;
}

/* authenticatorLargeBlobs single-shot write at offset 0. */
static uint8_t lb_write(const uint8_t *arr, size_t len)
{
    uint8_t msg[2200]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 3);
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, arr, len);  /* set */
    cbor_w_uint(&w, 0x03); cbor_w_uint(&w, 0);          /* offset */
    cbor_w_uint(&w, 0x04); cbor_w_uint(&w, len);        /* length */
    msg[0] = CTAP2_CMD_LARGE_BLOBS;
    uint8_t resp[64]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    return resp[0];
}

/* Assemble a valid large-blob array: body || SHA-256(body)[..16]. */
static size_t make_array(const uint8_t *body, size_t body_len, uint8_t *out)
{
    memcpy(out, body, body_len);
    uint8_t h[32]; pqf_sha256(body, body_len, h);
    memcpy(out + body_len, h, 16);
    return body_len + 16;
}

/* MakeCredential requesting largeBlobKey; copies out the credentialID
 * (from authData) and the returned 0x05 largeBlobKey. */
static uint8_t mc_lbk(const char *rp, uint8_t *key_out)
{
    uint8_t uid[4] = {1,2,3,4};
    uint8_t msg[700]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 6);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_bytes(&w, uid, 4);
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x06); cbor_w_map_header(&w, 1);   /* extensions */
    cbor_w_text(&w, "largeBlobKey"); cbor_w_bool(&w, true);
    cbor_w_uint(&w, 0x07); cbor_w_map_header(&w, 1);   /* options */
    cbor_w_text(&w, "rk"); cbor_w_bool(&w, true);      /* discoverable */
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return resp[0];
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *k = cbor_map_get_uint(m, 0x05);
    int ok = k && pqfido_cbor_is_bytes(k) && pqfido_cbor_bytes_len(k) == 32;
    if (ok) memcpy(key_out, pqfido_cbor_bytes(k), 32);
    pqfido_cbor_free(m);
    return ok ? CTAP2_OK : CTAP2_ERR_OTHER;
}

/* MakeCredential WITHOUT the largeBlobKey extension (rk=true so it is
 * discoverable). Used to check that GetAssertion then withholds the
 * largeBlobKey output (L11). Returns the CTAP status byte. */
static uint8_t mc_no_lbk(const char *rp)
{
    uint8_t uid[4] = {5,6,7,8};
    uint8_t msg[700]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_bytes(&w, uid, 4);
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x07); cbor_w_map_header(&w, 1);   /* options */
    cbor_w_text(&w, "rk"); cbor_w_bool(&w, true);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    return resp[0];
}

/* GetAssertion (no allowList) requesting largeBlobKey; copies out the
 * returned 0x07 key. */
static uint8_t ga_lbk(const char *rp, uint8_t *key_out)
{
    uint8_t msg[200]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 3);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x04); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "largeBlobKey"); cbor_w_bool(&w, true);
    msg[0] = CTAP2_CMD_GET_ASSERTION;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return resp[0];
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *k = cbor_map_get_uint(m, 0x07);
    int ok = k && pqfido_cbor_is_bytes(k) && pqfido_cbor_bytes_len(k) == 32;
    if (ok) memcpy(key_out, pqfido_cbor_bytes(k), 32);
    pqfido_cbor_free(m);
    return ok ? CTAP2_OK : CTAP2_ERR_OTHER;
}

int main(void)
{
    printf("authenticatorLargeBlobs host test\n");
    ctap2_init();

    /* 1. Initial value: 0x80 || SHA-256("\x80")[..16] (17 bytes). */
    uint8_t rd[2200]; size_t rd_len = 0;
    CHECK(lb_read(0, 1000, rd, &rd_len) == CTAP2_OK, "read initial array OK");
    CHECK(rd_len == 17 && rd[0] == 0x80, "initial array is 17 B starting 0x80");

    /* 2. Write a valid array (body + SHA-256 trailer), read it back. */
    const uint8_t body[] = {
        0x83, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    };
    uint8_t arr[2200];
    size_t arr_len = make_array(body, sizeof body, arr);
    CHECK(lb_write(arr, arr_len) == CTAP2_OK, "write valid array OK");
    CHECK(lb_read(0, 1000, rd, &rd_len) == CTAP2_OK, "read-back OK");
    CHECK(rd_len == arr_len && memcmp(rd, arr, arr_len) == 0,
          "array round-trips byte-for-byte");

    /* 3. Offset read returns the tail slice. */
    CHECK(lb_read(4, 4, rd, &rd_len) == CTAP2_OK && rd_len == 4
          && memcmp(rd, arr + 4, 4) == 0, "offset read returns the right slice");

    /* 4. Bad SHA-256 trailer -> INVALID_PARAMETER (0x02). */
    uint8_t bad[64]; memcpy(bad, arr, arr_len); bad[arr_len - 1] ^= 0xFF;
    CHECK(lb_write(bad, arr_len) == CTAP2_ERR_INVALID_PARAMETER,
          "bad trailer rejected (0x02)");

    /* 5. First fragment longer than the declared total length ->
     *    INVALID_LENGTH (0x03). With fragmented writes (CTAP 2.1 sec. 11.5)
     *    a first fragment SHORTER than `length` is a legal partial write
     *    (see test 5b); only a fragment that overruns the declared total
     *    is a length error. */
    {
        uint8_t msg[64]; cbor_writer_t w;
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 3);
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, arr, arr_len);
        cbor_w_uint(&w, 0x03); cbor_w_uint(&w, 0);
        cbor_w_uint(&w, 0x04); cbor_w_uint(&w, arr_len - 5);   /* < payload */
        msg[0] = CTAP2_CMD_LARGE_BLOBS;
        uint8_t resp[64]; size_t rl = 0;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        CHECK(resp[0] == 0x03, "first fragment over declared length -> 0x03");
    }

    /* 5b. Fragmented write (F5): write the same array in two fragments
     *     and read it back. The first fragment (offset 0) carries the
     *     total length; the second carries the running offset and no
     *     length. Each fragment alone is incomplete (CTAP2_OK), and the
     *     array only changes once the final fragment completes it. */
    {
        const uint8_t body2[] = {
            0x84, 50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,
            69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,
        };
        uint8_t arr2[2200];
        size_t arr2_len = make_array(body2, sizeof body2, arr2);
        size_t split = 16;   /* first fragment: 16 B, then the remainder */

        /* Fragment 1: offset 0, total length, first `split` bytes. */
        uint8_t msg[2200]; cbor_writer_t w;
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 3);
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, arr2, split);
        cbor_w_uint(&w, 0x03); cbor_w_uint(&w, 0);
        cbor_w_uint(&w, 0x04); cbor_w_uint(&w, arr2_len);
        msg[0] = CTAP2_CMD_LARGE_BLOBS;
        uint8_t resp[64]; size_t rl = 0;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_OK, "fragment 1 accepted");

        /* The array must NOT change until the write completes. */
        CHECK(lb_read(0, 2000, rd, &rd_len) == CTAP2_OK
              && rd_len == arr_len && memcmp(rd, arr, arr_len) == 0,
              "array unchanged mid-fragmented-write");

        /* Fragment 2: offset == split, remainder, no length. */
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 2);
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, arr2 + split, arr2_len - split);
        cbor_w_uint(&w, 0x03); cbor_w_uint(&w, split);
        msg[0] = CTAP2_CMD_LARGE_BLOBS;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_OK, "fragment 2 completes the write");
        CHECK(lb_read(0, 2000, rd, &rd_len) == CTAP2_OK
              && rd_len == arr2_len && memcmp(rd, arr2, arr2_len) == 0,
              "fragmented array round-trips byte-for-byte");

        /* A non-contiguous continuation fragment is rejected. */
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 3);
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, arr2, split);
        cbor_w_uint(&w, 0x03); cbor_w_uint(&w, 0);
        cbor_w_uint(&w, 0x04); cbor_w_uint(&w, arr2_len);
        msg[0] = CTAP2_CMD_LARGE_BLOBS;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_OK, "restart fragmented write");
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 2);
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, arr2 + split, arr2_len - split);
        cbor_w_uint(&w, 0x03); cbor_w_uint(&w, split + 1);   /* wrong offset */
        msg[0] = CTAP2_CMD_LARGE_BLOBS;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_ERR_INVALID_PARAMETER,
              "non-contiguous fragment offset rejected");

        /* Restore the single-shot array for the remaining tests. */
        CHECK(lb_write(arr, arr_len) == CTAP2_OK, "restore single-shot array");
    }

    /* 6. Read past the end -> INVALID_LENGTH (0x03). */
    CHECK(lb_read(9999, 4, rd, &rd_len) == 0x03, "out-of-range read -> 0x03");

    /* 6b. A declared length too big to ever store is STORAGE_FULL
     * (0x18), not INVALID_LENGTH -- a client can act on the difference
     * by writing less. A length below the 17-byte minimum array stays
     * INVALID_LENGTH (0x03). Both used to be 0x29, which is NOT_BUSY
     * and answers neither question. The C suite had no test for the
     * over-ceiling case at all. */
    {
        uint8_t frag[64]; memset(frag, 0xAB, sizeof frag);
        struct { uint64_t declared; uint8_t want; const char *what; } cases[] = {
            { (uint64_t)MAX_LARGE_BLOB_LEN + 1, 0x18,
              "declared length over the ceiling -> 0x18 STORAGE_FULL" },
            { 65535,                            0x18,
              "a wildly over-ceiling length -> 0x18" },
            { 16,                               0x03,
              "declared length below the minimum array -> 0x03" },
            { 0,                                0x03,
              "a declared length of zero -> 0x03" },
        };
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            uint8_t msg[128]; cbor_writer_t w;
            cbor_w_init(&w, msg + 1, sizeof msg - 1);
            cbor_w_map_header(&w, 3);
            cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, frag, sizeof frag);
            cbor_w_uint(&w, 0x03); cbor_w_uint(&w, 0);
            cbor_w_uint(&w, 0x04); cbor_w_uint(&w, cases[i].declared);
            msg[0] = CTAP2_CMD_LARGE_BLOBS;
            uint8_t resp[64]; size_t rl = 0;
            ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
            CHECK(resp[0] == cases[i].want, cases[i].what);
        }
    }

    /* 7. largeBlobKey: deterministic, identical across MakeCred (0x05)
     *    and GetAssertion (0x07) for the same credential. */
    uint8_t k_mc[32], k_ga[32];
    CHECK(mc_lbk("lbk.example", k_mc) == CTAP2_OK,
          "MakeCredential returns largeBlobKey (0x05)");
    CHECK(ga_lbk("lbk.example", k_ga) == CTAP2_OK,
          "GetAssertion returns largeBlobKey (0x07)");
    CHECK(memcmp(k_mc, k_ga, 32) == 0,
          "largeBlobKey is stable across MakeCred + GetAssertion");

    /* 8. L11 gating: a credential registered WITHOUT the largeBlobKey
     *    extension must NOT have the 0x07 key returned on GetAssertion,
     *    even when the RP asks for it. The assertion itself still
     *    succeeds; only the per-credential key is withheld. */
    CHECK(mc_no_lbk("nolbk.example") == CTAP2_OK,
          "MakeCredential without largeBlobKey OK");
    {
        uint8_t msg[200]; cbor_writer_t w;
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 3);
        cbor_w_uint(&w, 0x01); cbor_w_text(&w, "nolbk.example");
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
        cbor_w_uint(&w, 0x04); cbor_w_map_header(&w, 1);
        cbor_w_text(&w, "largeBlobKey"); cbor_w_bool(&w, true);
        msg[0] = CTAP2_CMD_GET_ASSERTION;
        uint8_t resp[4096]; size_t rl = 0;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        bool ok = resp[0] == CTAP2_OK;
        bool no_key = true;
        if (ok) {
            pqfido_cbor_item_t *m = NULL;
            pqfido_cbor_decode(resp + 1, rl - 1, &m);
            no_key = (cbor_map_get_uint(m, 0x07) == NULL);
            pqfido_cbor_free(m);
        }
        CHECK(ok && no_key,
              "GetAssertion withholds largeBlobKey for a cred minted without it");
    }

    /* 9. alwaysUv gate (#18 / L24): on a no-PIN device, a write with no
     *    pinUvAuthParam normally succeeds (auth not required). Once the
     *    device-wide alwaysUv policy is on, the same write MUST be
     *    refused -- on this hardware no UV method exists without a PIN,
     *    so the write cannot be authenticated and returns
     *    CTAP2_ERR_PUAT_REQUIRED (0x36) rather than slipping through. */
    {
        flash_store_set_always_uv(true);
        const uint8_t body9[] = { 0x82, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        uint8_t arr9[64];
        size_t arr9_len = make_array(body9, sizeof body9, arr9);
        CHECK(lb_write(arr9, arr9_len) == CTAP2_ERR_PUAT_REQUIRED,
              "alwaysUv write with no token/PIN -> 0x36 (PUAT_REQUIRED)");
        flash_store_set_always_uv(false);
        /* With the policy off again, the unauthenticated write proceeds. */
        CHECK(lb_write(arr9, arr9_len) == CTAP2_OK,
              "write proceeds once alwaysUv is cleared");
    }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
