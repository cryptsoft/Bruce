/* test_resident.c -- host test of discoverable (resident) credentials.
 *
 * Exercises the C-10r-1 foundation: MakeCredential indexes every
 * credential; GetAssertion with NO allowList discovers a resident
 * credential by rp_id_hash, returns the user handle (response 0x04),
 * and reports a per-credential signature counter that advances on each
 * assertion. Also checks RP isolation (rp A's cred isn't returned for
 * rp B) and that authenticatorReset clears the resident store.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "ctap2.h"
#include "credential.h"
#include "resident_store.h"
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

/* MakeCredential (ES256, rk) for `rp` with the given user.id. On
 * success copies the issued credentialID out of the attestation
 * authData. Returns the CTAP status byte. */
static uint8_t make_cred(const char *rp, const uint8_t *uid, size_t uid_len,
                         uint8_t *cred_id_out, size_t *cred_id_len_out)
{
    uint8_t msg[700]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_bytes(&w, uid, uid_len);
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x07); cbor_w_map_header(&w, 1);    /* options */
    cbor_w_text(&w, "rk"); cbor_w_bool(&w, true);       /* discoverable */
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return resp[0];

    /* Pull credentialID out of authData (0x02): rpIdHash(32) flags(1)
     * counter(4) aaguid(16) credIdLen(2) credId(L). */
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
    if (ad && pqfido_cbor_is_bytes(ad)) {
        const uint8_t *a = pqfido_cbor_bytes(ad);
        size_t l = (size_t)a[53] << 8 | a[54];
        if (l <= CRED_ID_LEN) {
            memcpy(cred_id_out, a + 55, l);
            *cred_id_len_out = l;
        }
    }
    pqfido_cbor_free(m);
    return CTAP2_OK;
}

/* MakeCredential with explicit options: rk / up / uv each carried only
 * when the matching has_* is true. Returns the CTAP status byte. */
static uint8_t make_cred_opt(const char *rp, const uint8_t *uid, size_t uid_len,
                             bool has_rk, bool rk, bool has_up, bool up,
                             bool has_uv, bool uv)
{
    unsigned no = (has_rk ? 1u : 0u) + (has_up ? 1u : 0u) + (has_uv ? 1u : 0u);
    uint8_t msg[700]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, no ? 5 : 4);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_bytes(&w, uid, uid_len);
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    if (no) {
        /* options map, canonical key order: rk(2) < up(2) < uv(2)
         * (same length, lexicographic). */
        cbor_w_uint(&w, 0x07); cbor_w_map_header(&w, no);
        if (has_rk) { cbor_w_text(&w, "rk"); cbor_w_bool(&w, rk); }
        if (has_up) { cbor_w_text(&w, "up"); cbor_w_bool(&w, up); }
        if (has_uv) { cbor_w_text(&w, "uv"); cbor_w_bool(&w, uv); }
    }
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    return resp[0];
}

/* GetAssertion with NO allowList for `rp`. On success copies out the
 * returned credentialID, user.id and the authData counter. Returns the
 * status byte. */
static uint8_t get_assert_discoverable(const char *rp,
                                       uint8_t *cred_id_out, size_t *cred_id_len,
                                       uint8_t *user_id_out, size_t *user_id_len,
                                       uint32_t *counter_out)
{
    uint8_t msg[200]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
    msg[0] = CTAP2_CMD_GET_ASSERTION;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return resp[0];

    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *cred = cbor_map_get_uint(m, 0x01);
    const pqfido_cbor_item_t *ad   = cbor_map_get_uint(m, 0x02);
    const pqfido_cbor_item_t *usr  = cbor_map_get_uint(m, 0x04);
    if (cred) {
        const pqfido_cbor_item_t *id = cbor_map_get_text(cred, "id");
        if (id && pqfido_cbor_is_bytes(id)) {
            *cred_id_len = pqfido_cbor_bytes_len(id);
            memcpy(cred_id_out, pqfido_cbor_bytes(id), *cred_id_len);
        }
    }
    if (ad && pqfido_cbor_is_bytes(ad)) {
        const uint8_t *a = pqfido_cbor_bytes(ad);
        *counter_out = (uint32_t)a[33] << 24 | (uint32_t)a[34] << 16
                     | (uint32_t)a[35] << 8 | a[36];
    }
    *user_id_len = 0;
    if (usr) {
        const pqfido_cbor_item_t *uid = cbor_map_get_text(usr, "id");
        if (uid && pqfido_cbor_is_bytes(uid)) {
            *user_id_len = pqfido_cbor_bytes_len(uid);
            memcpy(user_id_out, pqfido_cbor_bytes(uid), *user_id_len);
        }
    }
    pqfido_cbor_free(m);
    return CTAP2_OK;
}

/* GetAssertion (no allowList) returning the credentialID + the
 * numberOfCredentials field (0x05, 0 if absent). Status byte. */
static uint8_t get_assert_count(const char *rp, uint8_t *cred_out,
                                size_t *cred_len, uint32_t *ncred)
{
    uint8_t msg[200]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
    msg[0] = CTAP2_CMD_GET_ASSERTION;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return resp[0];
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *cred = cbor_map_get_uint(m, 0x01);
    const pqfido_cbor_item_t *nc   = cbor_map_get_uint(m, 0x05);
    const pqfido_cbor_item_t *id = cred ? cbor_map_get_text(cred, "id") : NULL;
    if (id && pqfido_cbor_is_bytes(id)) {
        *cred_len = pqfido_cbor_bytes_len(id);
        memcpy(cred_out, pqfido_cbor_bytes(id), *cred_len);
    }
    *ncred = (nc && pqfido_cbor_is_uint(nc)) ? (uint32_t)pqfido_cbor_uint(nc) : 0;
    pqfido_cbor_free(m);
    return CTAP2_OK;
}

/* authenticatorGetNextAssertion (0x08) -> credentialID. Status byte. */
static uint8_t get_next(uint8_t *cred_out, size_t *cred_len)
{
    uint8_t msg[1] = { CTAP2_CMD_GET_NEXT_ASSERTION };
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1, resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return resp[0];
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *cred = cbor_map_get_uint(m, 0x01);
    const pqfido_cbor_item_t *id = cred ? cbor_map_get_text(cred, "id") : NULL;
    if (id && pqfido_cbor_is_bytes(id)) {
        *cred_len = pqfido_cbor_bytes_len(id);
        memcpy(cred_out, pqfido_cbor_bytes(id), *cred_len);
    }
    pqfido_cbor_free(m);
    return CTAP2_OK;
}

/* MakeCredential (ES256, rk) for `rp` carrying a credBlob extension. */
static uint8_t make_cred_blob(const char *rp, const uint8_t *uid, size_t uid_len,
                              const uint8_t *blob, size_t blob_len)
{
    uint8_t msg[700]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 6);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_bytes(&w, uid, uid_len);
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x06); cbor_w_map_header(&w, 1);   /* extensions */
    cbor_w_text(&w, "credBlob"); cbor_w_bytes(&w, blob, blob_len);
    cbor_w_uint(&w, 0x07); cbor_w_map_header(&w, 1);   /* options */
    cbor_w_text(&w, "rk"); cbor_w_bool(&w, true);      /* discoverable */
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    return resp[0];
}

/* GetAssertion (no allowList) requesting credBlob; pulls the returned
 * blob out of the authData extensions map (offset 37, after rpIdHash +
 * flags + counter). */
static uint8_t get_assert_blob(const char *rp, uint8_t *blob_out, size_t *blob_len)
{
    uint8_t msg[200]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 3);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x04); cbor_w_map_header(&w, 1);   /* extensions */
    cbor_w_text(&w, "credBlob"); cbor_w_bool(&w, true);
    msg[0] = CTAP2_CMD_GET_ASSERTION;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return resp[0];
    *blob_len = 0;
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
    if (ad && pqfido_cbor_is_bytes(ad)) {
        const uint8_t *a = pqfido_cbor_bytes(ad);
        size_t al = pqfido_cbor_bytes_len(ad);
        if ((a[32] & 0x80) && al > 37) {   /* ED flag -> extensions map */
            pqfido_cbor_item_t *ex = NULL;
            if (pqfido_cbor_decode(a + 37, al - 37, &ex) == PQFIDO_OK) {
                const pqfido_cbor_item_t *cb = cbor_map_get_text(ex, "credBlob");
                if (cb && pqfido_cbor_is_bytes(cb)) {
                    *blob_len = pqfido_cbor_bytes_len(cb);
                    memcpy(blob_out, pqfido_cbor_bytes(cb), *blob_len);
                }
                pqfido_cbor_free(ex);
            }
        }
    }
    pqfido_cbor_free(m);
    return CTAP2_OK;
}

int main(void)
{
    printf("resident-credential host test\n");
    ctap2_init();   /* fresh device */

    const uint8_t uidA[] = { 'a','l','i','c','e' };
    const uint8_t uidB[] = { 'b','o','b' };
    const uint8_t uidC[] = { 'c','a','r','o','l' };
    uint8_t mc_cred[CRED_ID_LEN]; size_t mc_len = 0;

    /* 1. Register a discoverable credential for example.com. */
    CHECK(make_cred("example.com", uidA, sizeof uidA, mc_cred, &mc_len)
              == CTAP2_OK, "MakeCredential(rk) OK");
    CHECK(mc_len == CRED_ID_LEN, "issued credentialID is 161 B");

    /* 2. GetAssertion with no allowList discovers it + returns the
     *    user handle. */
    uint8_t ga_cred[CRED_ID_LEN]; size_t ga_len = 0;
    uint8_t ga_uid[64]; size_t ga_uid_len = 0;
    uint32_t ctr1 = 0;
    CHECK(get_assert_discoverable("example.com", ga_cred, &ga_len,
                                  ga_uid, &ga_uid_len, &ctr1) == CTAP2_OK,
          "discoverable GetAssertion OK (no allowList)");
    CHECK(ga_len == mc_len && memcmp(ga_cred, mc_cred, ga_len) == 0,
          "returned credentialID matches the registered one");
    CHECK(ga_uid_len == sizeof uidA && memcmp(ga_uid, uidA, ga_uid_len) == 0,
          "returned user.id matches");

    /* 3. Counter advances on the next assertion. */
    uint32_t ctr2 = 0;
    get_assert_discoverable("example.com", ga_cred, &ga_len,
                            ga_uid, &ga_uid_len, &ctr2);
    CHECK(ctr2 > ctr1, "per-credential counter increments across assertions");

    /* 4. RP isolation: a credential for another RP isn't discovered. */
    CHECK(get_assert_discoverable("other.example", ga_cred, &ga_len,
                                  ga_uid, &ga_uid_len, &ctr1)
              == CTAP2_ERR_NO_CREDENTIALS,
          "no resident credential for a different RP -> 0x2e");

    /* 5. A second RP's credential is independent. */
    CHECK(make_cred("other.example", uidB, sizeof uidB, mc_cred, &mc_len)
              == CTAP2_OK, "MakeCredential(rk) for second RP OK");
    CHECK(get_assert_discoverable("other.example", ga_cred, &ga_len,
                                  ga_uid, &ga_uid_len, &ctr1) == CTAP2_OK,
          "discoverable GetAssertion for second RP OK");
    CHECK(ga_uid_len == sizeof uidB && memcmp(ga_uid, uidB, ga_uid_len) == 0,
          "second RP returns its own user.id");

    /* 6. Reset clears the resident store. */
    {
        uint8_t rst[1] = { CTAP2_CMD_RESET };
        uint8_t resp[64]; size_t rl = 0;
        ctap2_dispatch(rst, 1, resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_OK, "Reset OK");
    }
    CHECK(get_assert_discoverable("example.com", ga_cred, &ga_len,
                                  ga_uid, &ga_uid_len, &ctr1)
              == CTAP2_ERR_NO_CREDENTIALS,
          "no discoverable credentials after Reset -> 0x2e");

    /* 7. GetNextAssertion: three discoverable creds for one RP, walked
     *    newest-first via GetAssertion + GetNextAssertion. Distinct
     *    user.ids -- per CTAP 2.1 sec. 6.1 a new discoverable credential for
     *    an already-registered (rpId, userId) overwrites the existing
     *    slot rather than adding a second, so three separate users are
     *    needed to populate three slots. */
    uint8_t c1[CRED_ID_LEN], c2[CRED_ID_LEN], c3[CRED_ID_LEN];
    size_t l1 = 0, l2 = 0, l3 = 0;
    make_cred("multi.example", uidA, sizeof uidA, c1, &l1);
    make_cred("multi.example", uidB, sizeof uidB, c2, &l2);
    make_cred("multi.example", uidC, sizeof uidC, c3, &l3);

    uint8_t g1[CRED_ID_LEN], g2[CRED_ID_LEN], g3[CRED_ID_LEN];
    size_t gl1 = 0, gl2 = 0, gl3 = 0; uint32_t ncred = 0;
    CHECK(get_assert_count("multi.example", g1, &gl1, &ncred) == CTAP2_OK,
          "GetAssertion (3 resident creds) OK");
    CHECK(ncred == 3, "numberOfCredentials == 3");
    CHECK(get_next(g2, &gl2) == CTAP2_OK, "GetNextAssertion #1 OK");
    CHECK(get_next(g3, &gl3) == CTAP2_OK, "GetNextAssertion #2 OK");
    CHECK(gl1 == CRED_ID_LEN && gl2 == CRED_ID_LEN && gl3 == CRED_ID_LEN
          && memcmp(g1, g2, CRED_ID_LEN) != 0
          && memcmp(g1, g3, CRED_ID_LEN) != 0
          && memcmp(g2, g3, CRED_ID_LEN) != 0,
          "the three assertions return distinct credentials");
    CHECK(get_next(g3, &gl3) == CTAP2_ERR_NOT_ALLOWED,
          "GetNextAssertion past the end -> 0x30");

    /* 8. A fresh GetAssertion re-arms the iterator. */
    get_assert_count("multi.example", g1, &gl1, &ncred);
    CHECK(get_next(g2, &gl2) == CTAP2_OK,
          "a new GetAssertion re-arms GetNextAssertion");

    /* 9. Any intervening non-GetNext command cancels the sequence. */
    make_cred("multi.example", uidA, sizeof uidA, c1, &l1);
    CHECK(get_next(g2, &gl2) == CTAP2_ERR_NOT_ALLOWED,
          "intervening MakeCredential cancels GetNextAssertion (0x30)");

    /* 10. credBlob: stored at MakeCredential, returned at GetAssertion. */
    ctap2_init();
    const uint8_t blob[] = { 0xDE,0xAD,0xBE,0xEF, 1,2,3,4,5,6,7,8,9,10 };
    CHECK(make_cred_blob("blob.example", uidA, sizeof uidA, blob, sizeof blob)
              == CTAP2_OK, "MakeCredential(credBlob) OK");
    uint8_t rb[64]; size_t rb_len = 0;
    CHECK(get_assert_blob("blob.example", rb, &rb_len) == CTAP2_OK,
          "GetAssertion(credBlob) OK");
    CHECK(rb_len == sizeof blob && memcmp(rb, blob, rb_len) == 0,
          "credBlob round-trips through the resident credential");

    /* 11. rk semantics (M15/L1): a fresh device, then a non-resident
     *     (rk absent / rk=false) MakeCredential must NOT consume a slot,
     *     and must not be discoverable. */
    ctap2_init();
    const uint8_t uidX[] = { 'x' };
    CHECK(make_cred_opt("rk.example", uidX, sizeof uidX,
                        false, false, false, false, false, false) == CTAP2_OK,
          "MakeCredential with no options (rk default false) OK");
    CHECK(resident_store_count() == 0,
          "rk-absent credential did not consume a resident slot");
    {
        uint8_t g[CRED_ID_LEN]; size_t gl = 0; uint8_t u[64]; size_t ul = 0;
        uint32_t c = 0;
        CHECK(get_assert_discoverable("rk.example", g, &gl, u, &ul, &c)
                  == CTAP2_ERR_NO_CREDENTIALS,
              "rk-absent credential is not discoverable");
    }
    CHECK(make_cred_opt("rk.example", uidX, sizeof uidX,
                        true, false, false, false, false, false) == CTAP2_OK,
          "explicit rk=false does not consume a slot");
    CHECK(resident_store_count() == 0, "rk=false stored nothing");

    /* 12. up=false on MakeCredential -> INVALID_OPTION (0x2c). */
    CHECK(make_cred_opt("rk.example", uidX, sizeof uidX,
                        true, true, true, false, false, false) == 0x2c,
          "MakeCredential up=false rejected (0x2c)");

    /* 13. uv=true with no PIN set: there is no user-verification method
     *     on this hardware at all, so the request can never be
     *     satisfied -- UNSUPPORTED_OPTION (0x2b). This asserted
     *     INVALID_OPTION (0x2c), which tells a platform the request was
     *     malformed rather than unsupported. With a PIN set the answer
     *     is PUAT_REQUIRED (0x36); see test_ctap2.c. */
    CHECK(make_cred_opt("rk.example", uidX, sizeof uidX,
                        true, true, false, false, true, true) == 0x2b,
          "MakeCredential uv=true with no UV rejected (0x2b)");

    /* 14. KEY_STORE_FULL (M15): fill all RESIDENT_MAX_SLOTS with rk
     *     credentials (distinct users), then one more rk=true on a new
     *     user must return CTAP2_ERR_KEY_STORE_FULL (0x28). */
    ctap2_init();
    for (size_t i = 0; i < RESIDENT_MAX_SLOTS; i++) {
        uint8_t u[2] = { 'u', (uint8_t)('0' + i) };
        CHECK(make_cred_opt("full.example", u, sizeof u,
                            true, true, false, false, false, false) == CTAP2_OK,
              "fill resident slot");
    }
    CHECK(resident_store_count() == RESIDENT_MAX_SLOTS, "store is full");
    {
        uint8_t u[2] = { 'u', 'X' };
        CHECK(make_cred_opt("full.example", u, sizeof u,
                            true, true, false, false, false, false)
                  == CTAP2_ERR_KEY_STORE_FULL,
              "rk=true on a full store -> KEY_STORE_FULL (0x28)");
    }
    {
        /* Re-registering an existing (rp, user.id) overwrites in place,
         * so it succeeds even on a full store (no new slot consumed). */
        uint8_t u[2] = { 'u', '0' };
        CHECK(make_cred_opt("full.example", u, sizeof u,
                            true, true, false, false, false, false) == CTAP2_OK,
              "re-register existing user overwrites (no KEY_STORE_FULL)");
        CHECK(resident_store_count() == RESIDENT_MAX_SLOTS,
              "store still full after in-place overwrite");
    }

    /* 15. GetAssertion options.up=false (L7): a silent assertion still
     *     succeeds but clears the UP flag (bit0) in authData. up=true
     *     (the default) keeps it set. */
    ctap2_init();
    {
        uint8_t uidU[] = { 'u' };
        CHECK(make_cred_opt("up.example", uidU, sizeof uidU,
                            true, true, false, false, false, false) == CTAP2_OK,
              "register discoverable cred for up test");
        /* up=false silent assertion. */
        uint8_t msg[200]; cbor_writer_t w;
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 3);
        cbor_w_uint(&w, 0x01); cbor_w_text(&w, "up.example");
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
        cbor_w_uint(&w, 0x05); cbor_w_map_header(&w, 1);    /* options */
        cbor_w_text(&w, "up"); cbor_w_bool(&w, false);
        msg[0] = CTAP2_CMD_GET_ASSERTION;
        uint8_t resp[4096]; size_t rl = 0;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        bool up_clear = false;
        if (resp[0] == CTAP2_OK) {
            pqfido_cbor_item_t *m = NULL;
            pqfido_cbor_decode(resp + 1, rl - 1, &m);
            const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
            if (ad && pqfido_cbor_is_bytes(ad)) {
                const uint8_t *a = pqfido_cbor_bytes(ad);
                up_clear = (a[32] & 0x01) == 0;   /* UP flag must be clear */
            }
            pqfido_cbor_free(m);
        }
        CHECK(resp[0] == CTAP2_OK && up_clear,
              "GetAssertion up=false succeeds with UP flag cleared");

        /* Default (up omitted) keeps UP set. */
        uint8_t g[CRED_ID_LEN]; size_t gl = 0; uint8_t u[64]; size_t ul = 0;
        uint32_t c = 0; bool up_set = false;
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 2);
        cbor_w_uint(&w, 0x01); cbor_w_text(&w, "up.example");
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
        msg[0] = CTAP2_CMD_GET_ASSERTION;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        if (resp[0] == CTAP2_OK) {
            pqfido_cbor_item_t *m = NULL;
            pqfido_cbor_decode(resp + 1, rl - 1, &m);
            const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
            if (ad && pqfido_cbor_is_bytes(ad))
                up_set = (pqfido_cbor_bytes(ad)[32] & 0x01) != 0;
            pqfido_cbor_free(m);
        }
        CHECK(up_set, "GetAssertion default keeps UP flag set");
        (void)g; (void)gl; (void)u; (void)ul; (void)c;
    }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
