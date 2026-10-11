/* test_pin.c -- host-side test of the ClientPIN flow.
 *
 * Plays the platform against ctap2_dispatch(): for each PIN protocol
 * (v1 and v2) it runs
 *
 *   getKeyAgreement -> setPIN -> getPinToken -> PIN-gated MakeCredential
 *
 * and checks: the PIN is accepted, a token comes back, a
 * MakeCredential carrying pinUvAuthParam = MAC(token, clientDataHash)
 * succeeds with the UV flag set in authData, a wrong-token request is
 * rejected with 0x33, and a no-token request once a PIN is set is
 * rejected with 0x36.
 *
 * Uses the firmware's own pin_protocol.c for the platform-side
 * crypto (ECDH is symmetric, so the same shared-secret derivation
 * works from either side).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "ctap2.h"
#include "client_pin.h"
#include "flash_store.h"
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
    0xaa,1,2,3,4,5,6,7, 8,9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23, 24,25,26,27,28,29,30,0xbb,
};

/* Emit a COSE EC2 public key (P-256) for the platform's keyAgreement. */
static void emit_cose(cbor_writer_t *w, const uint8_t x[32], const uint8_t y[32])
{
    cbor_w_map_header(w, 5);
    cbor_w_uint(w, 1); cbor_w_uint(w, 2);
    cbor_w_uint(w, 3); cbor_w_int(w, -25);
    cbor_w_int(w, -1); cbor_w_uint(w, 1);
    cbor_w_int(w, -2); cbor_w_bytes(w, x, 32);
    cbor_w_int(w, -3); cbor_w_bytes(w, y, 32);
}

/* Dispatch a ClientPIN request, return status; on success leaves the
 * decoded response map in *out (caller frees). */
static uint8_t do_dispatch(const uint8_t *msg, size_t msg_len,
                           uint8_t *resp, size_t *resp_len)
{
    ctap2_dispatch(msg, msg_len, resp, 2048, resp_len);
    return resp[0];
}

/* Query the device's current PIN retry counter (getPinRetries, 0x01).
 * Returns the count, or -1 on any error. */
static int query_pin_retries(uint8_t proto)
{
    uint8_t msg[64], resp[256]; size_t rl = 0; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x01);   /* getPinRetries */
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;
    pqfido_cbor_item_t *m = NULL;
    if (pqfido_cbor_decode(resp + 1, rl - 1, &m) != PQFIDO_OK) return -1;
    const pqfido_cbor_item_t *rv = cbor_map_get_uint(m, 0x03);
    int n = (rv && pqfido_cbor_is_uint(rv)) ? (int)pqfido_cbor_uint(rv) : -1;
    pqfido_cbor_free(m);
    return n;
}

/* Query powerCycleState (0x04) out of getPinRetries. CTAP 2.1 sec. 6.5.5.2
 * defines it as "present and true if the authenticator requires a power
 * cycle before any future PIN operation", so absence means no. Returns
 * 1 for present-and-true, 0 for absent, -1 on any error (including
 * present-but-not-a-bool, which would be a malformed response). */
static int query_power_cycle_state(uint8_t proto)
{
    uint8_t msg[64], resp[256]; size_t rl = 0; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x01);   /* getPinRetries */
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;
    pqfido_cbor_item_t *m = NULL;
    if (pqfido_cbor_decode(resp + 1, rl - 1, &m) != PQFIDO_OK) return -1;
    const pqfido_cbor_item_t *pcs = cbor_map_get_uint(m, 0x04);
    int r;
    if (!pcs)                        r = 0;
    else if (pqfido_cbor_is_bool(pcs)) r = pqfido_cbor_bool(pcs) ? 1 : 0;
    else                             r = -1;
    pqfido_cbor_free(m);
    return r;
}

static int test_pin(uint8_t proto)
{
    char label[64];
    printf("-- PIN protocol v%u --\n", proto);
    ctap2_init();   /* fresh device (host flash stub regenerates) */

    uint8_t resp[2048]; size_t rl = 0;
    uint8_t msg[600]; cbor_writer_t w;

    /* 1. getKeyAgreement -> authenticator public key. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x02);   /* getKeyAgreement */
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    uint8_t auth_x[32], auth_y[32];
    {
        do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
        snprintf(label, sizeof label, "getKeyAgreement OK (v%u)", proto);
        CHECK(resp[0] == CTAP2_OK, label);
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *ka = cbor_map_get_uint(m, 0x01);
        CHECK(ka && cbor_cose_ec2_xy(ka, auth_x, auth_y), "keyAgreement key parsed");
        pqfido_cbor_free(m);
    }

    /* 2. Platform ephemeral key + shared secret. */
    uint8_t plat_priv[32], plat_x[32], plat_y[32];
    pqf_p256_keygen(plat_priv, plat_x, plat_y);
    pin_shared_secret_t ss;
    CHECK(pin_shared_secret(proto, plat_priv, auth_x, auth_y, &ss) == 0,
          "platform derives shared secret");

    /* 3. setPIN with PIN "1234". Padded to 64 bytes. */
    const char *pin = "1234";
    uint8_t padded[64]; memset(padded, 0, sizeof padded);
    memcpy(padded, pin, strlen(pin));
    uint8_t newpinenc[80]; size_t npe_len = 0;
    pin_encrypt(&ss, padded, 64, newpinenc, &npe_len);
    uint8_t puap[32]; size_t puap_len = 0;
    pin_authenticate(proto, ss.hmac_key, 32, newpinenc, npe_len, puap, &puap_len);

    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x03);          /* setPIN */
    cbor_w_uint(&w, 0x03); emit_cose(&w, plat_x, plat_y);
    cbor_w_uint(&w, 0x04); cbor_w_bytes(&w, puap, puap_len);
    cbor_w_uint(&w, 0x05); cbor_w_bytes(&w, newpinenc, npe_len);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    snprintf(label, sizeof label, "setPIN OK (v%u)", proto);
    CHECK(resp[0] == CTAP2_OK, label);
    CHECK(client_pin_is_set(), "PIN now reported as set");

    /* 4. getPinToken (0x05): pinHashEnc = enc(SHA256(pin)[:16]). */
    uint8_t pinhash[32]; pqf_sha256((const uint8_t *)pin, strlen(pin), pinhash);
    uint8_t phe[48]; size_t phe_len = 0;
    pin_encrypt(&ss, pinhash, 16, phe, &phe_len);
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 4);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x05);          /* getPinToken */
    cbor_w_uint(&w, 0x03); emit_cose(&w, plat_x, plat_y);
    cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, phe, phe_len);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    snprintf(label, sizeof label, "getPinToken OK (v%u)", proto);
    CHECK(resp[0] == CTAP2_OK, label);

    uint8_t token[32]; bool got_token = false;
    {
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *t = cbor_map_get_uint(m, 0x02);
        if (t && pqfido_cbor_is_bytes(t)) {
            size_t tl = 0;
            if (pin_decrypt(&ss, pqfido_cbor_bytes(t), pqfido_cbor_bytes_len(t),
                            token, sizeof token, &tl) == 0 && tl == 32)
                got_token = true;
        }
        pqfido_cbor_free(m);
    }
    CHECK(got_token, "decrypted 32-byte PIN token");

    /* 5. PIN-gated MakeCredential: pinUvAuthParam = MAC(token, CDH). */
    uint8_t mc_puap[32]; size_t mc_puap_len = 0;
    pin_authenticate(proto, token, 32, CDH, 32, mc_puap, &mc_puap_len);
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 6);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u[4]={1,2,3,4}; cbor_w_bytes(&w, u, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x08); cbor_w_bytes(&w, mc_puap, mc_puap_len);
    cbor_w_uint(&w, 0x09); cbor_w_uint(&w, proto);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    snprintf(label, sizeof label, "PIN-gated MakeCredential OK (v%u)", proto);
    CHECK(resp[0] == CTAP2_OK, label);
    /* Check UV flag (0x04) set in authData (key 2, byte 32 = flags). */
    {
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
        bool uv = ad && pqfido_cbor_is_bytes(ad)
                  && (pqfido_cbor_bytes(ad)[32] & 0x04);
        CHECK(uv, "authData UV flag set");
        pqfido_cbor_free(m);
    }

    /* 5a. options.uv = true with a PIN set but NO pinUvAuthParam: the
     * request is satisfiable once the platform fetches a token, so the
     * answer is the retriable PUAT_REQUIRED (0x36), not UNSUPPORTED_OPTION
     * (that is the no-PIN answer, tested in test_ctap2.c) and not the old
     * INVALID_OPTION. This is the arm a one-iteration loop in test_ctap2.c
     * claimed to cover and did not. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u[4]={9,9,9,9}; cbor_w_bytes(&w, u, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x07); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "uv"); cbor_w_bool(&w, true);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    snprintf(label, sizeof label, "hunt: uv=true, PIN set, no token -> 0x36 PUAT_REQUIRED (v%u)", proto);
    CHECK(resp[0] == CTAP2_ERR_PUAT_REQUIRED, label);

    /* An unknown ClientPIN subCommand is INVALID_SUBCOMMAND (0x3E). This
     * module answered INVALID_PARAMETER (0x02) via a literal, so the
     * 0x16 -> 0x3E sweep that fixed the other five declarations missed
     * it; the second hunt caught the C/Rust disagreement. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x0f);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    snprintf(label, sizeof label, "hunt: unknown ClientPIN subCommand -> 0x3e (v%u)", proto);
    CHECK(resp[0] == CTAP2_ERR_INVALID_SUBCOMMAND, label);

    /* 5b. L5 regression: a getPinUvAuthTokenUsingPinWithPermissions
     *     (0x09) that verifies the PIN but omits the required
     *     permissions parameter must return MISSING_PARAMETER WITHOUT
     *     destroying the token minted in step 4/5. We send a valid
     *     pinHashEnc but no 0x09 permissions key, expect 0x14, then
     *     re-run the gated MakeCredential with the OLD token and
     *     confirm it still succeeds. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 4);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x09);   /* ...WithPermissions */
    cbor_w_uint(&w, 0x03); emit_cose(&w, plat_x, plat_y);
    cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, phe, phe_len);  /* no 0x09 perms */
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_MISSING_PARAMETER,
          "get-token-with-permissions missing perms -> 0x14");

    /* Old token must still gate MakeCredential. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 6);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u[4]={1,2,3,4}; cbor_w_bytes(&w, u, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x08); cbor_w_bytes(&w, mc_puap, mc_puap_len);
    cbor_w_uint(&w, 0x09); cbor_w_uint(&w, proto);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    CHECK(resp[0] == CTAP2_OK,
          "prior token survives a malformed get-token-with-permissions");

    /* 6. Wrong token -> 0x33. */
    uint8_t bad[32]; memset(bad, 0x99, 32);
    uint8_t bad_mac[32]; size_t bad_len = 0;
    pin_authenticate(proto, bad, 32, CDH, 32, bad_mac, &bad_len);
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 6);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u[4]={1,2,3,4}; cbor_w_bytes(&w, u, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x08); cbor_w_bytes(&w, bad_mac, bad_len);
    cbor_w_uint(&w, 0x09); cbor_w_uint(&w, proto);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_PIN_AUTH_INVALID, "bad token rejected (0x33)");

    /* 7. No pinUvAuthParam while a PIN is set, for a NON-discoverable
     *    credential with no uv option -> makeCredUvNotRqd lets it through
     *    on user-presence alone (host stub auto-confirms UP), so it
     *    SUCCEEDS (0x00). It used to be refused with 0x36; forcing UV on
     *    every registration once a PIN existed is what made Chrome drive
     *    the token differently from a YubiKey (the "hijacking" symptom).
     *    The UV-required cases are still refused -- covered by test_config
     *    (alwaysUv), the uv=true check below, and the rk gate (test 7b). */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 4);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u[4]={1,2,3,4}; cbor_w_bytes(&w, u, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    CHECK(resp[0] == CTAP2_OK,
          "PIN set + no token, non-discoverable -> succeeds (makeCredUvNotRqd)");

    /* 7b. Same, but rk=true (discoverable / passkey): makeCredUvNotRqd
     *     does NOT exempt discoverable credentials -- they still require
     *     UV, so a tokenless request is refused with 0x36. */
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
    cbor_w_uint(&w, 0x07); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "rk"); cbor_w_bool(&w, true);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_PUAT_REQUIRED,
          "PIN set + no token, discoverable (rk) -> 0x36 (UV still required)");

    /* 8. GetAssertion with a PIN set + no token no longer refuses with
     *    0x36 -- a PIN being set does not force UV on assertion. It
     *    proceeds past the PIN gate to credential lookup; with no
     *    matching credential registered it returns NO_CREDENTIALS
     *    (0x2e), NOT PUAT_REQUIRED. (alwaysUv / uv=true / credProtect
     *    still force UV where required -- checked elsewhere.) */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, "no-such-rp.example");
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
    msg[0] = CTAP2_CMD_GET_ASSERTION;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_NO_CREDENTIALS,
          "PIN set + tokenless GetAssertion -> proceeds (0x2e, not 0x36)");

    /* 9. Chrome's silent probe: pinUvAuthParam = h'' (present but
     *    empty) + protocol 1 -> MUST be 0x33, never 0x36. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 6);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u[4]={1,2,3,4}; cbor_w_bytes(&w, u, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x08); cbor_w_bytes(&w, NULL, 0);   /* empty param */
    cbor_w_uint(&w, 0x09); cbor_w_uint(&w, 1);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_PIN_AUTH_INVALID,
          "empty-param probe with PIN set -> 0x33");

    /* 10. C1 regression: a getPinToken whose pinHashEnc is far longer
     *     than one block must be rejected on length BEFORE decryption.
     *     Pre-fix this 256-byte, block-aligned blob decrypted straight
     *     into the fixed got[] stack buffer (unauthenticated overflow);
     *     now it returns 0x14 and the device stays up. */
    {
        uint8_t big_phe[256]; memset(big_phe, 0x41, sizeof big_phe);
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 4);
        cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
        cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x05);   /* getPinToken */
        cbor_w_uint(&w, 0x03); emit_cose(&w, plat_x, plat_y);
        cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, big_phe, sizeof big_phe);
        msg[0] = CTAP2_CMD_CLIENT_PIN;
        do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
        snprintf(label, sizeof label,
                 "over-length pinHashEnc rejected, no overflow (v%u)", proto);
        CHECK(resp[0] == CTAP2_ERR_MISSING_PARAMETER, label);
    }

    /* 11. M7 regression: a wrong PIN must decrement + persist the retry
     *     counter BEFORE the compare (so a power glitch can't refund the
     *     guess). The counter was reset to max by step 4's success. */
    {
        snprintf(label, sizeof label, "retries at max before wrong PIN (v%u)", proto);
        CHECK(query_pin_retries(proto) == PIN_MAX_RETRIES, label);

        uint8_t wrong_hash[16]; memset(wrong_hash, 0x55, sizeof wrong_hash);
        uint8_t wphe[48]; size_t wphe_len = 0;
        pin_encrypt(&ss, wrong_hash, 16, wphe, &wphe_len);
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 4);
        cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
        cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x05);   /* getPinToken */
        cbor_w_uint(&w, 0x03); emit_cose(&w, plat_x, plat_y);
        cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, wphe, wphe_len);
        msg[0] = CTAP2_CMD_CLIENT_PIN;
        do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
        snprintf(label, sizeof label, "wrong PIN -> 0x31 (v%u)", proto);
        CHECK(resp[0] == CTAP2_ERR_PIN_INVALID, label);
        snprintf(label, sizeof label,
                 "retry counter decremented after wrong PIN (v%u)", proto);
        CHECK(query_pin_retries(proto) == PIN_MAX_RETRIES - 1, label);
    }

    return 0;
}

/* With NO PIN set, a present pinUvAuthParam (Chrome probes PIN-less
 * devices too) must be IGNORED -- the ceremony proceeds UP-only,
 * matching the Rust base, instead of failing 0x33. */
static void test_no_pin_param_ignored(void)
{
    printf("-- no PIN: pinUvAuthParam ignored --\n");
    ctap2_init();   /* fresh device, no PIN */

    uint8_t resp[4096]; size_t rl = 0;
    uint8_t msg[600]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 6);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u[4]={1,2,3,4}; cbor_w_bytes(&w, u, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x08); cbor_w_bytes(&w, NULL, 0);   /* empty param */
    cbor_w_uint(&w, 0x09); cbor_w_uint(&w, 1);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK,
          "no PIN: empty pinUvAuthParam ignored, MakeCredential OK");
    /* UV must NOT be claimed (flags bit 0x04 clear). */
    {
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
        bool uv = ad && pqfido_cbor_is_bytes(ad)
                  && (pqfido_cbor_bytes(ad)[32] & 0x04);
        CHECK(!uv, "no PIN: authData UV flag stays clear");
        pqfido_cbor_free(m);
    }
}

/* #5 (= #25): per-power-cycle consecutive-failure lockout. After
 * MAX_CONSECUTIVE_PIN_FAILURES (3) wrong PINs in one power cycle the PIN
 * paths must refuse with CTAP2_ERR_PIN_AUTH_BLOCKED (0x34), even though
 * the persistent 8-retry counter is far from exhausted. A fresh boot
 * (ctap2_init) clears the volatile counter. */
static void test_consecutive_failure_lockout(uint8_t proto)
{
    printf("-- consecutive-failure lockout (PIN protocol v%u) --\n", proto);
    ctap2_init();   /* fresh device clears the volatile lockout counter */

    uint8_t resp[2048]; size_t rl = 0;
    uint8_t msg[600]; cbor_writer_t w;
    char label[80];

    /* getKeyAgreement + shared secret + setPIN "1234". */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x02);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    uint8_t ax[32], ay[32];
    {
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *ka = cbor_map_get_uint(m, 0x01);
        cbor_cose_ec2_xy(ka, ax, ay);
        pqfido_cbor_free(m);
    }
    uint8_t pp[32], px[32], py[32];
    pqf_p256_keygen(pp, px, py);
    pin_shared_secret_t ss;
    pin_shared_secret(proto, pp, ax, ay, &ss);
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
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "setPIN OK (lockout test)");

    /* Wrong-PIN guess: getPinToken (0x05) with a bogus pinHashEnc. The
     * key-agreement key rotates on each failure, so re-fetch it + derive
     * a fresh shared secret per attempt (as a real platform would). */
    #define WRONG_GUESS(expect_status, lbl)                                  \
    do {                                                                     \
        cbor_w_init(&w, msg + 1, sizeof msg - 1);                            \
        cbor_w_map_header(&w, 2);                                            \
        cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);                       \
        cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x02);                        \
        msg[0] = CTAP2_CMD_CLIENT_PIN;                                       \
        do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);                     \
        { pqfido_cbor_item_t *m = NULL;                                      \
          pqfido_cbor_decode(resp + 1, rl - 1, &m);                          \
          const pqfido_cbor_item_t *ka = cbor_map_get_uint(m, 0x01);         \
          cbor_cose_ec2_xy(ka, ax, ay); pqfido_cbor_free(m); }               \
        pqf_p256_keygen(pp, px, py);                                         \
        pin_shared_secret(proto, pp, ax, ay, &ss);                           \
        uint8_t wh[16]; memset(wh, 0x77, sizeof wh);                         \
        uint8_t wphe[48]; size_t wpl = 0;                                    \
        pin_encrypt(&ss, wh, 16, wphe, &wpl);                                \
        cbor_w_init(&w, msg + 1, sizeof msg - 1);                            \
        cbor_w_map_header(&w, 4);                                            \
        cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);                       \
        cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x05);                        \
        cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);                        \
        cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, wphe, wpl);                  \
        msg[0] = CTAP2_CMD_CLIENT_PIN;                                       \
        do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);                     \
        snprintf(label, sizeof label, lbl " (v%u)", proto);                  \
        CHECK(resp[0] == (expect_status), label);                           \
    } while (0)

    /* Three wrong PINs each return 0x31 (PIN invalid) while consuming a
     * persistent retry; the fourth must be blocked with 0x34 BEFORE a
     * retry is spent. */
    /* While the device is still answering, getPinRetries must not be
     * asking for a power cycle. */
    snprintf(label, sizeof label, "powerCycleState absent before lockout (v%u)", proto);
    CHECK(query_power_cycle_state(proto) == 0, label);

    WRONG_GUESS(CTAP2_ERR_PIN_INVALID, "wrong PIN #1 -> 0x31");
    WRONG_GUESS(CTAP2_ERR_PIN_INVALID, "wrong PIN #2 -> 0x31");

    snprintf(label, sizeof label, "powerCycleState absent at 2 failures (v%u)", proto);
    CHECK(query_power_cycle_state(proto) == 0, label);

    WRONG_GUESS(CTAP2_ERR_PIN_INVALID, "wrong PIN #3 -> 0x31");
    WRONG_GUESS(CTAP2_ERR_PIN_AUTH_BLOCKED, "wrong PIN #4 blocked -> 0x34");

    /* Persistent retries should be 8 - 3 = 5 (the 4th never spent one). */
    snprintf(label, sizeof label, "retries == MAX-3 after lockout (v%u)", proto);
    CHECK(query_pin_retries(proto) == PIN_MAX_RETRIES - 3, label);

    /* ...and the device must now say so on the wire. Without this the
     * lockout is invisible to a conformant client: pinRetries still reads
     * 5, every attempt comes back 0x34 including the correct PIN, and
     * nothing tells the client the fix is a replug rather than another
     * guess. */
    snprintf(label, sizeof label, "powerCycleState true once blocked (v%u)", proto);
    CHECK(query_power_cycle_state(proto) == 1, label);

    /* Reading it must not itself disturb the state. */
    snprintf(label, sizeof label, "retries unchanged by a getPinRetries read (v%u)", proto);
    CHECK(query_pin_retries(proto) == PIN_MAX_RETRIES - 3, label);

    /* A reboot clears the volatile lockout (persistent retries persist in
     * the real device; the host stub resets them, which is fine -- we only
     * assert the lockout itself lifts). */
    ctap2_init();

    snprintf(label, sizeof label, "powerCycleState clears on reboot (v%u)", proto);
    CHECK(query_power_cycle_state(proto) == 0, label);
    #undef WRONG_GUESS
}

/* #13: with forcePINChange pending, getPinUvAuthTokenUsingPinWithPermissions
 * (0x09) must refuse a token carrying makeCredential/getAssertion with
 * CTAP2_ERR_PIN_POLICY_VIOLATION (0x37), even with the correct PIN. */
static void test_force_pin_change_enforced(uint8_t proto)
{
    printf("-- forcePINChange enforcement (PIN protocol v%u) --\n", proto);
    ctap2_init();

    uint8_t resp[2048]; size_t rl = 0;
    uint8_t msg[600]; cbor_writer_t w;
    char label[80];

    /* getKeyAgreement + setPIN "1234". */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x02);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    uint8_t ax[32], ay[32];
    {
        pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
        cbor_cose_ec2_xy(cbor_map_get_uint(m, 0x01), ax, ay);
        pqfido_cbor_free(m);
    }
    uint8_t pp[32], px[32], py[32]; pqf_p256_keygen(pp, px, py);
    pin_shared_secret_t ss; pin_shared_secret(proto, pp, ax, ay, &ss);
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
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "setPIN OK (forcePINChange test)");

    /* Correct pinHashEnc for the WithPermissions request. */
    uint8_t pinhash[32]; pqf_sha256((const uint8_t *)"1234", 4, pinhash);
    uint8_t phe[48]; size_t pel = 0; pin_encrypt(&ss, pinhash, 16, phe, &pel);

    /* Permissions this device does not implement are refused, not
     * stored. This used to take the requested bitmask verbatim, so a
     * token could carry bioEnrollment (0x08) -- which nothing here ever
     * checks -- and a bit above 32 would vanish in the narrowing cast.
     * The Rust port refuses with UNAUTHORIZED_PERMISSION (0x40). */
    for (int i = 0; i < 3; i++) {
        static const uint64_t bad[3] = { PIN_PERM_BIO_ENROLL, 0x40, 0x100000000ULL };
        cbor_w_init(&w, msg + 1, sizeof msg - 1);
        cbor_w_map_header(&w, 5);
        cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
        cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x09);
        cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);
        cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, phe, pel);
        cbor_w_uint(&w, 0x09); cbor_w_uint(&w, bad[i]);
        msg[0] = CTAP2_CMD_CLIENT_PIN;
        do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
        snprintf(label, sizeof label,
                 "hunt: permissions 0x%llx refused with 0x40 (v%u)",
                 (unsigned long long)bad[i], proto);
        CHECK(resp[0] == CTAP2_ERR_UNAUTHORIZED_PERMISSION, label);
    }
    /* A supported bit mixed with an unsupported one is still refused:
     * granting the subset would be a silent downgrade. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x09);
    cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);
    cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, phe, pel);
    cbor_w_uint(&w, 0x09); cbor_w_uint(&w, PIN_PERM_MAKE_CREDENTIAL | PIN_PERM_BIO_ENROLL);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    snprintf(label, sizeof label, "hunt: mc|bioEnroll refused whole (v%u)", proto);
    CHECK(resp[0] == CTAP2_ERR_UNAUTHORIZED_PERMISSION, label);

    /* Simulate an admin setting the force-change flag (the
     * authenticatorConfig setMinPINLength path is exercised in
     * test_config.c). */
    flash_store_set_force_pin_change(true);

    /* Requesting makeCredential (0x01) while force-change is pending -> 0x37. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x09);
    cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);
    cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, phe, pel);
    cbor_w_uint(&w, 0x09); cbor_w_uint(&w, PIN_PERM_MAKE_CREDENTIAL);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    snprintf(label, sizeof label, "mc-token w/ forcePINChange -> 0x37 (v%u)", proto);
    CHECK(resp[0] == CTAP2_ERR_PIN_POLICY_VIOLATION, label);

    /* Legacy getPinToken (0x05) grants mc+ga, so it's also blocked. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 4);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x05);
    cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);
    cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, phe, pel);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    snprintf(label, sizeof label, "legacy getPinToken w/ forcePINChange -> 0x37 (v%u)", proto);
    CHECK(resp[0] == CTAP2_ERR_PIN_POLICY_VIOLATION, label);

    /* A token scoped only to authnrCfg (0x20) is still issued so the host
     * can drive the change. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x09);
    cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);
    cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, phe, pel);
    cbor_w_uint(&w, 0x09); cbor_w_uint(&w, PIN_PERM_AUTH_CONFIG);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    do_dispatch(msg, 1 + cbor_w_off(&w), resp, &rl);
    snprintf(label, sizeof label, "authnrCfg-only token still issued (v%u)", proto);
    CHECK(resp[0] == CTAP2_OK, label);
}

int main(void)
{
    printf("ClientPIN host test\n");
    test_pin(PIN_PROTOCOL_V1);
    test_pin(PIN_PROTOCOL_V2);
    test_no_pin_param_ignored();
    test_consecutive_failure_lockout(PIN_PROTOCOL_V1);
    test_consecutive_failure_lockout(PIN_PROTOCOL_V2);
    test_force_pin_change_enforced(PIN_PROTOCOL_V1);
    test_force_pin_change_enforced(PIN_PROTOCOL_V2);
    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
