/* test_credmgmt.c -- host test of authenticatorCredentialManagement
 * (0x0A): all seven subcommands driven against ctap2_dispatch().
 *
 * Registers resident credentials (before a PIN is set, so MakeCred
 * needs no token), then sets a PIN, obtains a credMgmt-permission
 * token (ClientPIN subcommand 0x09), and exercises getCredsMetadata,
 * enumerateRPs(Begin/GetNext), enumerateCredentials(Begin/GetNext),
 * deleteCredential, and updateUserInformation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "ctap2.h"
#include "client_pin.h"
#include "credential.h"
#include "pin_protocol.h"
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

static void emit_cose(cbor_writer_t *w, const uint8_t x[32], const uint8_t y[32])
{
    cbor_w_map_header(w, 5);
    cbor_w_uint(w, 1); cbor_w_uint(w, 2);
    cbor_w_uint(w, 3); cbor_w_int(w, -25);
    cbor_w_int(w, -1); cbor_w_uint(w, 1);
    cbor_w_int(w, -2); cbor_w_bytes(w, x, 32);
    cbor_w_int(w, -3); cbor_w_bytes(w, y, 32);
}

/* No-token MakeCredential (used before a PIN is set). Captures the
 * issued credentialID from the attestation authData. */
static uint8_t make_cred(const char *rp, const uint8_t *uid, size_t uid_len,
                         const char *name,
                         uint8_t *cred_out, size_t *cred_len)
{
    uint8_t msg[700]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "id"); cbor_w_bytes(&w, uid, uid_len);
    cbor_w_text(&w, "name"); cbor_w_text(&w, name);
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
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
    if (ad && pqfido_cbor_is_bytes(ad)) {
        const uint8_t *a = pqfido_cbor_bytes(ad);
        size_t l = (size_t)a[53] << 8 | a[54];
        memcpy(cred_out, a + 55, l);
        *cred_len = l;
    }
    pqfido_cbor_free(m);
    return CTAP2_OK;
}

/* Set PIN "1234" and return a token carrying `perms` (unscoped). The
 * caller must have already ctap2_init()'d (and optionally registered
 * credentials before the PIN was set). Returns 0 on success. */
static int set_pin_get_token(uint8_t proto, uint32_t perms, uint8_t token[32])
{
    uint8_t resp[2048]; size_t rl = 0; uint8_t msg[700]; cbor_writer_t w;

    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x02);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;
    uint8_t ax[32], ay[32];
    {
        pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *ka = cbor_map_get_uint(m, 0x01);
        int ok = ka && cbor_cose_ec2_xy(ka, ax, ay);
        pqfido_cbor_free(m); if (!ok) return -1;
    }
    uint8_t pp[32], px[32], py[32]; pqf_p256_keygen(pp, px, py);
    pin_shared_secret_t ss;
    if (pin_shared_secret(proto, pp, ax, ay, &ss) != 0) return -1;

    uint8_t padded[64]; memset(padded, 0, sizeof padded); memcpy(padded, "1234", 4);
    uint8_t npe[80]; size_t npl = 0; pin_encrypt(&ss, padded, 64, npe, &npl);
    uint8_t puap[32]; size_t pul = 0;
    pin_authenticate(proto, ss.hmac_key, 32, npe, npl, puap, &pul);
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x03);
    cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);
    cbor_w_uint(&w, 0x04); cbor_w_bytes(&w, puap, pul);
    cbor_w_uint(&w, 0x05); cbor_w_bytes(&w, npe, npl);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;

    uint8_t pinhash[32]; pqf_sha256((const uint8_t *)"1234", 4, pinhash);
    uint8_t phe[48]; size_t pel = 0; pin_encrypt(&ss, pinhash, 16, phe, &pel);
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x09);
    cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);
    cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, phe, pel);
    cbor_w_uint(&w, 0x09); cbor_w_uint(&w, perms);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;
    {
        pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *t = cbor_map_get_uint(m, 0x02);
        int ok = 0;
        if (t && pqfido_cbor_is_bytes(t)) {
            size_t tl = 0;
            if (pin_decrypt(&ss, pqfido_cbor_bytes(t), pqfido_cbor_bytes_len(t),
                            token, 32, &tl) == 0 && tl == 32) ok = 1;
        }
        pqfido_cbor_free(m); if (!ok) return -1;
    }
    return 0;
}

/* Build + dispatch a CredentialManagement request. `sp` is the
 * verbatim subCommandParams (NULL if none). With `auth`, attaches a
 * pinUvAuthParam over (subCommand || subCommandParams). */
static uint8_t cm(uint8_t sub, const uint8_t *sp, size_t sp_len,
                  const uint8_t *token, uint8_t proto, int auth,
                  uint8_t *resp, size_t *rl)
{
    uint8_t mac[1 + 512]; size_t ml = 0;
    mac[ml++] = sub;
    if (sp_len) { memcpy(mac + ml, sp, sp_len); ml += sp_len; }
    uint8_t puap[32]; size_t pul = 0;
    if (auth) pin_authenticate(proto, token, 32, mac, ml, puap, &pul);

    uint8_t msg[700]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    size_t n = 1u + (sp_len ? 1u : 0u) + (auth ? 2u : 0u);
    cbor_w_map_header(&w, n);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, sub);
    if (sp_len) { cbor_w_uint(&w, 0x02); cbor_w_raw(&w, sp, sp_len); }
    if (auth) {
        cbor_w_uint(&w, 0x03); cbor_w_uint(&w, proto);
        cbor_w_uint(&w, 0x04); cbor_w_bytes(&w, puap, pul);
    }
    msg[0] = CTAP2_CMD_CREDENTIAL_MANAGEMENT;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, 4096, rl);
    return resp[0];
}

int main(void)
{
    printf("authenticatorCredentialManagement host test\n");
    ctap2_init();

    const uint8_t uidA[] = {'a'}, uidB[] = {'b','b'}, uidC[] = {'c','c','c'};
    uint8_t cA[CRED_ID_LEN], cB[CRED_ID_LEN], cC[CRED_ID_LEN];
    size_t lA = 0, lB = 0, lC = 0;

    /* Register 2 creds for site-a + 1 for site-b (no PIN yet). */
    make_cred("site-a.example", uidA, sizeof uidA, "Alice", cA, &lA);
    make_cred("site-a.example", uidB, sizeof uidB, "Bob",   cB, &lB);
    make_cred("site-b.example", uidC, sizeof uidC, "Carol", cC, &lC);

    uint8_t token[32];
    CHECK(set_pin_get_token(PIN_PROTOCOL_V2, PIN_PERM_CRED_MGMT, token) == 0,
          "obtained credMgmt token");

    uint8_t proto = PIN_PROTOCOL_V2;
    uint8_t resp[4096]; size_t rl = 0;

    /* getCredsMetadata -> existing=3. */
    CHECK(cm(0x01, NULL, 0, token, proto, 1, resp, &rl) == CTAP2_OK,
          "getCredsMetadata OK");
    {
        pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *ex = cbor_map_get_uint(m, 0x01);
        CHECK(ex && pqfido_cbor_uint(ex) == 3, "existingResidentCredentials == 3");
        pqfido_cbor_free(m);
    }

    /* enumerateRPs: Begin -> total 2, GetNext -> 2nd, GetNext -> 0x30. */
    CHECK(cm(0x02, NULL, 0, token, proto, 1, resp, &rl) == CTAP2_OK,
          "enumerateRPsBegin OK");
    {
        pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *tot = cbor_map_get_uint(m, 0x05);
        const pqfido_cbor_item_t *h = cbor_map_get_uint(m, 0x04);
        const pqfido_cbor_item_t *rp = cbor_map_get_uint(m, 0x03);
        CHECK(tot && pqfido_cbor_uint(tot) == 2, "totalRPs == 2");
        CHECK(h && pqfido_cbor_is_bytes(h) && pqfido_cbor_bytes_len(h) == 32,
              "RP entry carries a 32-byte rpIDHash");
        /* F4: the RP entity must carry the real UTF-8 rp.id, not "". */
        const pqfido_cbor_item_t *rpid = rp ? cbor_map_get_text(rp, "id") : NULL;
        size_t idl = rpid ? pqfido_cbor_string_len(rpid) : 0;
        CHECK(rpid && pqfido_cbor_is_string(rpid) && idl == 14
              && memcmp(pqfido_cbor_string(rpid), "site-", 5) == 0,
              "RP entry carries the persisted rp.id string");
        pqfido_cbor_free(m);
    }
    CHECK(cm(0x03, NULL, 0, NULL, 0, 0, resp, &rl) == CTAP2_OK,
          "enumerateRPsGetNext OK (no reauth)");
    CHECK(cm(0x03, NULL, 0, NULL, 0, 0, resp, &rl) == CTAP2_ERR_NOT_ALLOWED,
          "enumerateRPsGetNext past end -> 0x30");

    /* enumerateCredentials for site-a -> total 2. */
    uint8_t rpa[32]; pqf_sha256((const uint8_t *)"site-a.example", 14, rpa);
    uint8_t sp[256]; cbor_writer_t spw;
    cbor_w_init(&spw, sp, sizeof sp);
    cbor_w_map_header(&spw, 1);
    cbor_w_uint(&spw, 0x01); cbor_w_bytes(&spw, rpa, 32);
    size_t spl = cbor_w_off(&spw);
    CHECK(cm(0x04, sp, spl, token, proto, 1, resp, &rl) == CTAP2_OK,
          "enumerateCredentialsBegin(site-a) OK");
    {
        pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *tot = cbor_map_get_uint(m, 0x09);
        const pqfido_cbor_item_t *cred = cbor_map_get_uint(m, 0x07);
        const pqfido_cbor_item_t *usr = cbor_map_get_uint(m, 0x06);
        CHECK(tot && pqfido_cbor_uint(tot) == 2, "site-a totalCredentials == 2");
        CHECK(cred && cbor_map_get_text(cred, "id"), "credential entry has id");
        CHECK(usr && cbor_map_get_text(usr, "id"), "credential entry has user.id");
        pqfido_cbor_free(m);
    }
    CHECK(cm(0x05, NULL, 0, NULL, 0, 0, resp, &rl) == CTAP2_OK,
          "enumerateCredentialsGetNext OK");
    CHECK(cm(0x05, NULL, 0, NULL, 0, 0, resp, &rl) == CTAP2_ERR_NOT_ALLOWED,
          "enumerateCredentialsGetNext past end -> 0x30");

    /* deleteCredential(cA) -> existing drops to 2. */
    cbor_w_init(&spw, sp, sizeof sp);
    cbor_w_map_header(&spw, 1);
    cbor_w_uint(&spw, 0x02); cbor_w_map_header(&spw, 2);
    cbor_w_text(&spw, "id"); cbor_w_bytes(&spw, cA, lA);
    cbor_w_text(&spw, "type"); cbor_w_text(&spw, "public-key");
    spl = cbor_w_off(&spw);
    CHECK(cm(0x06, sp, spl, token, proto, 1, resp, &rl) == CTAP2_OK,
          "deleteCredential OK");
    CHECK(cm(0x01, NULL, 0, token, proto, 1, resp, &rl) == CTAP2_OK, "metadata OK");
    {
        pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *ex = cbor_map_get_uint(m, 0x01);
        CHECK(ex && pqfido_cbor_uint(ex) == 2, "existing == 2 after delete");
        pqfido_cbor_free(m);
    }
    /* Deleting the same credential again -> no credentials (0x2e). */
    CHECK(cm(0x06, sp, spl, token, proto, 1, resp, &rl) == CTAP2_ERR_NO_CREDENTIALS,
          "deleteCredential(absent) -> 0x2e");

    /* updateUserInformation(cC, name="Caroline"). */
    uint8_t up[256];
    cbor_w_init(&spw, up, sizeof up);
    cbor_w_map_header(&spw, 2);
    cbor_w_uint(&spw, 0x02); cbor_w_map_header(&spw, 2);
    cbor_w_text(&spw, "id"); cbor_w_bytes(&spw, cC, lC);
    cbor_w_text(&spw, "type"); cbor_w_text(&spw, "public-key");
    cbor_w_uint(&spw, 0x03); cbor_w_map_header(&spw, 1);
    cbor_w_text(&spw, "name"); cbor_w_text(&spw, "Caroline");
    size_t upl = cbor_w_off(&spw);
    CHECK(cm(0x07, up, upl, token, proto, 1, resp, &rl) == CTAP2_OK,
          "updateUserInformation OK");
    /* Verify via enumerateCredentials(site-b). */
    uint8_t rpb[32]; pqf_sha256((const uint8_t *)"site-b.example", 14, rpb);
    cbor_w_init(&spw, sp, sizeof sp);
    cbor_w_map_header(&spw, 1);
    cbor_w_uint(&spw, 0x01); cbor_w_bytes(&spw, rpb, 32);
    spl = cbor_w_off(&spw);
    cm(0x04, sp, spl, token, proto, 1, resp, &rl);
    {
        pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *usr = cbor_map_get_uint(m, 0x06);
        const pqfido_cbor_item_t *nm = usr ? cbor_map_get_text(usr, "name") : NULL;
        int ok = nm && pqfido_cbor_is_string(nm)
                 && pqfido_cbor_string_len(nm) == 8
                 && memcmp(pqfido_cbor_string(nm), "Caroline", 8) == 0;
        CHECK(ok, "updated user.name reads back as \"Caroline\"");
        pqfido_cbor_free(m);
    }

    /* Bad token -> 0x33; missing pinUvAuthParam -> 0x36 PUAT_REQUIRED,
     * which is retriable and tells the platform to fetch one. This
     * asserted 0x14 MISSING_PARAMETER, which reads as a malformed
     * request; the Rust port has answered 0x36 since M16. */
    uint8_t bad[32]; memset(bad, 0x99, 32);
    CHECK(cm(0x01, NULL, 0, bad, proto, 1, resp, &rl) == CTAP2_ERR_PIN_AUTH_INVALID,
          "bad credMgmt token -> 0x33");
    CHECK(cm(0x01, NULL, 0, NULL, 0, 0, resp, &rl) == CTAP2_ERR_PUAT_REQUIRED,
          "getCredsMetadata without token -> 0x36 PUAT_REQUIRED");

    /* #19: a credential deleted mid-enumeration must be SKIPPED by
     *      enumerateCredentialsGetNext, not abort the whole listing.
     *      Register three creds for one RP, Begin (returns #1, total 3),
     *      delete the 2nd, then GetNext must skip the tombstoned slot
     *      and return the 3rd (CTAP2_OK) -- never CTAP2_ERR_NO_CREDENTIALS
     *      (the old buggy abort). A final GetNext ends cleanly with
     *      0x30. */
    {
        ctap2_init();
        const uint8_t u1[] = {'1'}, u2[] = {'2'}, u3[] = {'3'};
        uint8_t c1[CRED_ID_LEN], c2[CRED_ID_LEN], c3[CRED_ID_LEN];
        size_t l1 = 0, l2 = 0, l3 = 0;
        make_cred("skip.example", u1, sizeof u1, "One",   c1, &l1);
        make_cred("skip.example", u2, sizeof u2, "Two",   c2, &l2);
        make_cred("skip.example", u3, sizeof u3, "Three", c3, &l3);

        uint8_t tok2[32];
        CHECK(set_pin_get_token(PIN_PROTOCOL_V2, PIN_PERM_CRED_MGMT, tok2) == 0,
              "obtained credMgmt token (skip test)");
        uint8_t p2 = PIN_PROTOCOL_V2;

        uint8_t rph[32]; pqf_sha256((const uint8_t *)"skip.example", 12, rph);
        uint8_t spx[64]; cbor_writer_t spxw;
        cbor_w_init(&spxw, spx, sizeof spx);
        cbor_w_map_header(&spxw, 1);
        cbor_w_uint(&spxw, 0x01); cbor_w_bytes(&spxw, rph, 32);
        size_t spxl = cbor_w_off(&spxw);

        CHECK(cm(0x04, spx, spxl, tok2, p2, 1, resp, &rl) == CTAP2_OK,
              "enumerateCredentialsBegin(skip) OK");

        /* Delete the 2nd credential (a still-pending iterator slot). */
        uint8_t del[256]; cbor_writer_t delw;
        cbor_w_init(&delw, del, sizeof del);
        cbor_w_map_header(&delw, 1);
        cbor_w_uint(&delw, 0x02); cbor_w_map_header(&delw, 2);
        cbor_w_text(&delw, "id"); cbor_w_bytes(&delw, c2, l2);
        cbor_w_text(&delw, "type"); cbor_w_text(&delw, "public-key");
        size_t dell = cbor_w_off(&delw);
        CHECK(cm(0x06, del, dell, tok2, p2, 1, resp, &rl) == CTAP2_OK,
              "deleteCredential(#2) mid-enumeration OK");

        /* GetNext skips the tombstoned #2 and returns #3 -- NOT 0x2e. */
        uint8_t st = cm(0x05, NULL, 0, NULL, 0, 0, resp, &rl);
        CHECK(st == CTAP2_OK,
              "GetNext skips deleted slot and returns next cred (not 0x2e)");
        /* Following GetNext reaches the end cleanly. */
        CHECK(cm(0x05, NULL, 0, NULL, 0, 0, resp, &rl) == CTAP2_ERR_NOT_ALLOWED,
              "GetNext past end after skip -> 0x30");
    }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
