/* test_extensions.c -- host-side test of the hmac-secret extension.
 *
 * Plays the platform through a full ceremony:
 *   1. MakeCredential with {extensions:{hmac-secret:true}} -> expect the
 *      authData extension output to echo {hmac-secret:true} (ED flag).
 *   2. getKeyAgreement (ClientPIN 0x02) for the authenticator's ECDH key.
 *   3. GetAssertion with the hmac-secret input map (keyAgreement,
 *      saltEnc, saltAuth) -> decrypt the output and check it equals
 *      HMAC(cred_random, salt), where cred_random is what the device
 *      derives. Since cred_random is internal, we instead verify
 *      self-consistency: the same salt yields the same output across
 *      two GetAssertions (determinism), and two different salts yield
 *      different outputs.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "ctap2.h"
#include "client_pin.h"
#include "pin_protocol.h"
#include "cbor_encode.h"
#include "cbor_read.h"
#include "pqcbor.h"
#include "pqf_crypto.h"
#include "openssl/rand.h"

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("  ok: %s\n", m); \
    else { fprintf(stderr, "FAIL: %s\n", m); fails++; } } while (0)

static const uint8_t CDH[32] = {
    9,8,7,6,5,4,3,2, 1,0,1,2,3,4,5,6, 7,8,9,10,11,12,13,14, 15,16,17,18,19,20,21,22,
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

/* Pull bytes for an integer-key entry of the response map. */
static const uint8_t *resp_bytes(const pqfido_cbor_item_t *m, uint64_t key,
                                 size_t *len)
{
    const pqfido_cbor_item_t *v = cbor_map_get_uint(m, key);
    if (v && pqfido_cbor_is_bytes(v)) { *len = pqfido_cbor_bytes_len(v); return pqfido_cbor_bytes(v); }
    return NULL;
}

int main(void)
{
    printf("hmac-secret extension host test\n");
    ctap2_init();

    uint8_t msg[512], resp[2048]; size_t rl = 0; cbor_writer_t w;

    /* 1. MakeCredential with hmac-secret:true. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u[4]={1,2,3,4}; cbor_w_bytes(&w, u, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x06); cbor_w_map_header(&w, 1);    /* extensions */
    cbor_w_text(&w, "hmac-secret"); cbor_w_bool(&w, true);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "MakeCredential(hmac-secret) OK");

    uint8_t cred_id[256]; size_t cred_id_len = 0;
    {
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, rl - 1, &m);
        size_t adl = 0;
        const uint8_t *ad = resp_bytes(m, 2, &adl);
        /* authData: ...[37] then attestedCredentialData: aaguid(16)
         * credIdLen(2) at [53..55], credId at [55]. ED flag (0x80)
         * must be set since we emitted an extension. */
        CHECK(ad && (ad[32] & 0x80), "MakeCredential authData has ED flag");
        if (ad) {
            uint16_t cl = (ad[53] << 8) | ad[54];
            cred_id_len = cl; memcpy(cred_id, ad + 55, cl);
        }
        pqfido_cbor_free(m);
    }

    /* 2. getKeyAgreement. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, 1);   /* proto v1 */
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x02);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    uint8_t ax[32], ay[32];
    {
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *ka = cbor_map_get_uint(m, 0x01);
        CHECK(ka && cbor_cose_ec2_xy(ka, ax, ay), "keyAgreement obtained");
        pqfido_cbor_free(m);
    }

    /* 3. Platform shared secret + a GetAssertion with hmac-secret. */
    uint8_t pp[32], px[32], py[32];
    pqf_p256_keygen(pp, px, py);
    pin_shared_secret_t ss;
    pin_shared_secret(PIN_PROTOCOL_V1, pp, ax, ay, &ss);

    uint8_t salt[32];
    for (int i = 0; i < 32; i++) salt[i] = (uint8_t)(i + 0x40);
    uint8_t saltenc[48]; size_t se_len = 0;
    pin_encrypt(&ss, salt, 32, saltenc, &se_len);
    uint8_t saltauth[32]; size_t sa_len = 0;
    pin_authenticate(PIN_PROTOCOL_V1, ss.hmac_key, 32, saltenc, se_len,
                     saltauth, &sa_len);

    /* Helper to run one GetAssertion + return the decrypted hmac output. */
    uint8_t out1[64]; size_t out1_len = 0;
    for (int pass = 0; pass < 2; pass++) {
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 4);
        cbor_w_uint(&w, 0x01); cbor_w_text(&w, "example.com");
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
        cbor_w_uint(&w, 0x03); cbor_w_array_header(&w, 1);
        cbor_w_map_header(&w, 2);
        cbor_w_text(&w, "id");   cbor_w_bytes(&w, cred_id, cred_id_len);
        cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
        cbor_w_uint(&w, 0x04); cbor_w_map_header(&w, 1);   /* extensions */
        cbor_w_text(&w, "hmac-secret"); cbor_w_map_header(&w, 3);
        cbor_w_uint(&w, 1); emit_cose(&w, px, py);
        cbor_w_uint(&w, 2); cbor_w_bytes(&w, saltenc, se_len);
        cbor_w_uint(&w, 3); cbor_w_bytes(&w, saltauth, sa_len);
        msg[0] = CTAP2_CMD_GET_ASSERTION;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        if (pass == 0) CHECK(resp[0] == CTAP2_OK, "GetAssertion(hmac-secret) OK");

        /* authData (key 2) carries the ED flag + the extension map at
         * its tail; decode authData as bytes, then the extension CBOR
         * map starts at byte 37 (no attestedCredentialData). */
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, rl - 1, &m);
        size_t adl = 0; const uint8_t *ad = resp_bytes(m, 2, &adl);
        uint8_t got[64]; size_t got_len = 0; bool ok = false;
        if (ad && (ad[32] & 0x80) && adl > 37) {
            pqfido_cbor_item_t *em = NULL;
            if (pqfido_cbor_decode(ad + 37, adl - 37, &em) == PQFIDO_OK) {
                const pqfido_cbor_item_t *hv = cbor_map_get_text(em, "hmac-secret");
                if (hv && pqfido_cbor_is_bytes(hv)) {
                    /* decrypt the output under the shared secret */
                    if (pin_decrypt(&ss, pqfido_cbor_bytes(hv),
                                    pqfido_cbor_bytes_len(hv), got, sizeof got,
                                    &got_len) == 0)
                        ok = true;
                }
                pqfido_cbor_free(em);
            }
        }
        if (pass == 0) {
            CHECK(ok && got_len == 32, "hmac-secret output present + 32 B");
            memcpy(out1, got, got_len); out1_len = got_len;
        } else {
            CHECK(ok && got_len == out1_len && memcmp(got, out1, got_len) == 0,
                  "hmac-secret output is stable for the same salt");
        }
        pqfido_cbor_free(m);
    }

    /* The decrypted output must equal HMAC(cred_random, salt). We can't
     * see cred_random, but we can confirm it's a 32-byte HMAC-shaped
     * value that changes with the salt: flip the salt, expect a
     * different output. */
    {
        uint8_t salt2[32]; memcpy(salt2, salt, 32); salt2[0] ^= 0xff;
        uint8_t se2[48]; size_t se2l = 0; pin_encrypt(&ss, salt2, 32, se2, &se2l);
        uint8_t sa2[32]; size_t sa2l = 0;
        pin_authenticate(PIN_PROTOCOL_V1, ss.hmac_key, 32, se2, se2l, sa2, &sa2l);
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 4);
        cbor_w_uint(&w, 0x01); cbor_w_text(&w, "example.com");
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
        cbor_w_uint(&w, 0x03); cbor_w_array_header(&w, 1);
        cbor_w_map_header(&w, 2);
        cbor_w_text(&w, "id"); cbor_w_bytes(&w, cred_id, cred_id_len);
        cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
        cbor_w_uint(&w, 0x04); cbor_w_map_header(&w, 1);
        cbor_w_text(&w, "hmac-secret"); cbor_w_map_header(&w, 3);
        cbor_w_uint(&w, 1); emit_cose(&w, px, py);
        cbor_w_uint(&w, 2); cbor_w_bytes(&w, se2, se2l);
        cbor_w_uint(&w, 3); cbor_w_bytes(&w, sa2, sa2l);
        msg[0] = CTAP2_CMD_GET_ASSERTION;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
        size_t adl = 0; const uint8_t *ad = resp_bytes(m, 2, &adl);
        uint8_t got[64]; size_t gl = 0; bool diff = false;
        if (ad && adl > 37) {
            pqfido_cbor_item_t *em = NULL;
            if (pqfido_cbor_decode(ad + 37, adl - 37, &em) == PQFIDO_OK) {
                const pqfido_cbor_item_t *hv = cbor_map_get_text(em, "hmac-secret");
                if (hv && pqfido_cbor_is_bytes(hv)
                    && pin_decrypt(&ss, pqfido_cbor_bytes(hv),
                                   pqfido_cbor_bytes_len(hv), got, sizeof got,
                                   &gl) == 0)
                    diff = (gl == out1_len && memcmp(got, out1, gl) != 0);
                pqfido_cbor_free(em);
            }
        }
        CHECK(diff, "a different salt yields a different hmac-secret output");
        pqfido_cbor_free(m);
    }

    /* C2 regression: an over-length saltEnc must be rejected before
     * decryption. Pre-fix this 256-byte, block-aligned blob decrypted
     * straight into the fixed salts[64] stack buffer (unauthenticated
     * overflow). Now the hmac-secret block is skipped: GetAssertion
     * still succeeds, but with no hmac-secret output and no crash. */
    {
        /* 96 B is block-aligned and > sizeof(salts)=64, so pre-fix the v1
         * decrypt wrote 32 B past the buffer; it's also not a legal
         * saltEnc length, so se_ok rejects it up front. */
        uint8_t big_se[96]; memset(big_se, 0x5a, sizeof big_se);
        uint8_t big_sa[32]; size_t big_sal = 0;
        pin_authenticate(PIN_PROTOCOL_V1, ss.hmac_key, 32,
                         big_se, sizeof big_se, big_sa, &big_sal);
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 4);
        cbor_w_uint(&w, 0x01); cbor_w_text(&w, "example.com");
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
        cbor_w_uint(&w, 0x03); cbor_w_array_header(&w, 1);
        cbor_w_map_header(&w, 2);
        cbor_w_text(&w, "id"); cbor_w_bytes(&w, cred_id, cred_id_len);
        cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
        cbor_w_uint(&w, 0x04); cbor_w_map_header(&w, 1);
        cbor_w_text(&w, "hmac-secret"); cbor_w_map_header(&w, 3);
        cbor_w_uint(&w, 1); emit_cose(&w, px, py);
        cbor_w_uint(&w, 2); cbor_w_bytes(&w, big_se, sizeof big_se);
        cbor_w_uint(&w, 3); cbor_w_bytes(&w, big_sa, big_sal);
        msg[0] = CTAP2_CMD_GET_ASSERTION;
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        bool no_hmac = false;
        if (resp[0] == CTAP2_OK) {
            pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
            size_t adl = 0; const uint8_t *ad = resp_bytes(m, 2, &adl);
            if (ad) {
                if (!(ad[32] & 0x80)) {
                    no_hmac = true;                 /* ED flag clear: no ext map */
                } else if (adl > 37) {
                    pqfido_cbor_item_t *em = NULL;
                    if (pqfido_cbor_decode(ad + 37, adl - 37, &em) == PQFIDO_OK) {
                        no_hmac = (cbor_map_get_text(em, "hmac-secret") == NULL);
                        pqfido_cbor_free(em);
                    }
                }
            }
            pqfido_cbor_free(m);
        }
        CHECK(no_hmac,
              "over-length saltEnc rejected, no overflow + no hmac output");
    }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
