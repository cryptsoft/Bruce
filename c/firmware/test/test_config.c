/* test_config.c -- host-side test of authenticatorConfig (0x0D),
 * authenticatorSelection (0x0B), authenticatorReset (0x07), and the
 * alwaysUv / minPinLength behaviours they drive.
 *
 * Drives ctap2_dispatch() as the platform would:
 *   - getInfo advertises the new options + minPINLength;
 *   - toggleAlwaysUv with no token bootstraps a fresh device, and
 *     alwaysUv then forces UV on MakeCredential;
 *   - setMinPINLength / enableEnterpriseAttestation require a token
 *     carrying the authnrCfg permission (subcommand 0x09), raise the
 *     min PIN length (raise-only), and gate the minPinLength
 *     MakeCredential extension on the RP allowlist;
 *   - Selection ACKs, vendorPrototype is rejected, Reset clears state.
 *
 * The pinUvAuthParam for a config request authenticates
 *   0xFFx32 || 0x0D || subCommand || subCommandParams
 * under the token; cbor_w_raw splices the verbatim subCommandParams so
 * the bytes the firmware extracts (cbor_raw_map_value) match the MAC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "ctap2.h"
#include "client_pin.h"
#include "flash_store.h"
#include "resident_store.h"   /* RESIDENT_MAX_SLOTS */
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

/* COSE EC2 P-256 keyAgreement key (alg -25). */
static void emit_cose(cbor_writer_t *w, const uint8_t x[32], const uint8_t y[32])
{
    cbor_w_map_header(w, 5);
    cbor_w_uint(w, 1); cbor_w_uint(w, 2);
    cbor_w_uint(w, 3); cbor_w_int(w, -25);
    cbor_w_int(w, -1); cbor_w_uint(w, 1);
    cbor_w_int(w, -2); cbor_w_bytes(w, x, 32);
    cbor_w_int(w, -3); cbor_w_bytes(w, y, 32);
}

/* Set up a fresh device with PIN "1234" and return a PIN/UV-auth token
 * carrying `perms` (unscoped). Returns 0 on success. */
static int setup_token(uint8_t proto, uint32_t perms, uint8_t token[32])
{
    uint8_t resp[2048]; size_t rl = 0;
    uint8_t msg[700]; cbor_writer_t w;

    /* getKeyAgreement -> authenticator public key. */
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x02);
    msg[0] = CTAP2_CMD_CLIENT_PIN;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;
    uint8_t ax[32], ay[32];
    {
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *ka = cbor_map_get_uint(m, 0x01);
        int ok = ka && cbor_cose_ec2_xy(ka, ax, ay);
        pqfido_cbor_free(m);
        if (!ok) return -1;
    }

    uint8_t pp[32], px[32], py[32];
    pqf_p256_keygen(pp, px, py);
    pin_shared_secret_t ss;
    if (pin_shared_secret(proto, pp, ax, ay, &ss) != 0) return -1;

    /* setPIN "1234". */
    uint8_t padded[64]; memset(padded, 0, sizeof padded); memcpy(padded, "1234", 4);
    uint8_t npe[80]; size_t npl = 0;
    pin_encrypt(&ss, padded, 64, npe, &npl);
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

    /* getPinUvAuthTokenUsingPinWithPermissions (0x09). */
    uint8_t pinhash[32]; pqf_sha256((const uint8_t *)"1234", 4, pinhash);
    uint8_t phe[48]; size_t pel = 0;
    pin_encrypt(&ss, pinhash, 16, phe, &pel);
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
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, rl - 1, &m);
        const pqfido_cbor_item_t *t = cbor_map_get_uint(m, 0x02);
        int ok = 0;
        if (t && pqfido_cbor_is_bytes(t)) {
            size_t tl = 0;
            if (pin_decrypt(&ss, pqfido_cbor_bytes(t), pqfido_cbor_bytes_len(t),
                            token, 32, &tl) == 0 && tl == 32)
                ok = 1;
        }
        pqfido_cbor_free(m);
        if (!ok) return -1;
    }
    return 0;
}

/* Encode a setMinPINLength subCommandParams map { 0x01: newmin?,
 * 0x02: rpids? } into `sp`. Returns its length. */
static size_t enc_minpin(uint8_t *sp, size_t cap, int newmin,
                         const char **rpids, size_t nr)
{
    cbor_writer_t w; cbor_w_init(&w, sp, cap);
    size_t nf = (newmin > 0 ? 1u : 0u) + (nr > 0 ? 1u : 0u);
    cbor_w_map_header(&w, nf);
    if (newmin > 0) { cbor_w_uint(&w, 0x01); cbor_w_uint(&w, (uint64_t)newmin); }
    if (nr > 0) {
        cbor_w_uint(&w, 0x02);
        cbor_w_array_header(&w, nr);
        for (size_t i = 0; i < nr; i++) cbor_w_text(&w, rpids[i]);
    }
    return cbor_w_off(&w);
}

/* Build a full authenticatorConfig request into `msg` (msg[0] = cmd).
 * `sp`/`sp_len` is the verbatim subCommandParams (NULL/0 if none).
 * When `with_token`, attaches pinUvAuthProtocol (0x03) + param (0x04)
 * computed over the canonical config auth message. Returns msg length. */
static size_t build_config(uint8_t *msg, size_t cap, uint8_t sub,
                           const uint8_t *sp, size_t sp_len,
                           const uint8_t *token, uint8_t proto, int with_token)
{
    uint8_t mm[34 + 512]; size_t ml = 0;
    memset(mm, 0xFF, 32); ml = 32;
    mm[ml++] = CTAP2_CMD_CONFIG;
    mm[ml++] = sub;
    if (sp_len) { memcpy(mm + ml, sp, sp_len); ml += sp_len; }
    uint8_t puap[32]; size_t pul = 0;
    if (with_token) pin_authenticate(proto, token, 32, mm, ml, puap, &pul);

    cbor_writer_t w; cbor_w_init(&w, msg + 1, cap - 1);
    size_t n = 1u + (sp_len ? 1u : 0u) + (with_token ? 2u : 0u);
    cbor_w_map_header(&w, n);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, sub);
    if (sp_len) { cbor_w_uint(&w, 0x02); cbor_w_raw(&w, sp, sp_len); }
    if (with_token) {
        cbor_w_uint(&w, 0x03); cbor_w_uint(&w, proto);
        cbor_w_uint(&w, 0x04); cbor_w_bytes(&w, puap, pul);
    }
    msg[0] = CTAP2_CMD_CONFIG;
    return 1 + cbor_w_off(&w);
}

/* getInfo helpers. */
static int info_minpin(void)
{
    uint8_t msg[1] = { CTAP2_CMD_GET_INFO };
    uint8_t resp[2048]; size_t rl = 0;
    ctap2_dispatch(msg, 1, resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *mp = cbor_map_get_uint(m, 0x0d);
    int v = (mp && pqfido_cbor_is_uint(mp)) ? (int)pqfido_cbor_uint(mp) : -1;
    pqfido_cbor_free(m);
    return v;
}
static int info_has_option(const char *name)
{
    uint8_t msg[1] = { CTAP2_CMD_GET_INFO };
    uint8_t resp[2048]; size_t rl = 0;
    ctap2_dispatch(msg, 1, resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return 0;
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *opts = cbor_map_get_uint(m, 0x04);
    int present = opts && cbor_map_get_text(opts, name) != NULL;
    pqfido_cbor_free(m);
    return present;
}

/* getInfo: uint value at top-level `key` (-1 if absent/not-uint). */
static long info_uint(uint64_t key)
{
    uint8_t msg[1] = { CTAP2_CMD_GET_INFO };
    uint8_t resp[2048]; size_t rl = 0;
    ctap2_dispatch(msg, 1, resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *v = cbor_map_get_uint(m, key);
    long out = (v && pqfido_cbor_is_uint(v)) ? (long)pqfido_cbor_uint(v) : -1;
    pqfido_cbor_free(m);
    return out;
}

/* getInfo: array element count at top-level `key` (-1 if absent). */
static long info_array_size(uint64_t key)
{
    uint8_t msg[1] = { CTAP2_CMD_GET_INFO };
    uint8_t resp[2048]; size_t rl = 0;
    ctap2_dispatch(msg, 1, resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *v = cbor_map_get_uint(m, key);
    long out = (v && pqfido_cbor_is_array(v))
               ? (long)pqfido_cbor_array_size(v) : -1;
    pqfido_cbor_free(m);
    return out;
}

/* ES256 MakeCredential for `rp` with no token. Returns status byte. */
static uint8_t makecred_plain(const char *rp)
{
    uint8_t msg[700]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 4);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u[4] = {1,2,3,4}; cbor_w_bytes(&w, u, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    return resp[0];
}

/* Token-gated ES256 MakeCredential for `rp` requesting the
 * minPinLength extension. Returns the authData flags byte, or -1. */
static int makecred_minpin_ext(const char *rp, const uint8_t *token, uint8_t proto)
{
    uint8_t mp[32]; size_t mpl = 0;
    pin_authenticate(proto, token, 32, CDH, 32, mp, &mpl);
    uint8_t msg[700]; cbor_writer_t w;
    cbor_w_init(&w, msg + 1, sizeof msg - 1);
    cbor_w_map_header(&w, 7);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u[4] = {1,2,3,4}; cbor_w_bytes(&w, u, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x06); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "minPinLength"); cbor_w_bool(&w, true);
    cbor_w_uint(&w, 0x08); cbor_w_bytes(&w, mp, mpl);
    cbor_w_uint(&w, 0x09); cbor_w_uint(&w, proto);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    uint8_t resp[4096]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
    int flags = (ad && pqfido_cbor_is_bytes(ad)) ? pqfido_cbor_bytes(ad)[32] : -1;
    pqfido_cbor_free(m);
    return flags;
}

/* ---- Test groups ---------------------------------------------- */

static void test_defaults_selection_reset(void)
{
    printf("-- getInfo defaults / Selection / Reset / vendorPrototype --\n");
    ctap2_init();
    uint8_t resp[2048]; size_t rl = 0;

    CHECK(info_has_option("authnrCfg"), "getInfo advertises authnrCfg");
    CHECK(info_has_option("alwaysUv"),  "getInfo advertises alwaysUv");
    /* #29: enterprise attestation is NOT advertised (self-attestation
     * only -- we never emit epAtt). */
    CHECK(!info_has_option("ep"),       "getInfo does NOT advertise ep (#29)");
    CHECK(info_has_option("rk"),        "getInfo advertises rk");
    CHECK(info_has_option("credMgmt"),  "getInfo advertises credMgmt");
    CHECK(info_has_option("largeBlobs"), "getInfo advertises largeBlobs");
    /* #30 / #31: discovery signals for the permission-scoped token flow
     * (ClientPIN 0x09) and setMinPINLength (authnrConfig 0x03). */
    CHECK(info_has_option("pinUvAuthToken"), "getInfo advertises pinUvAuthToken (#30)");
    CHECK(info_has_option("setMinPINLength"), "getInfo advertises setMinPINLength (#31)");
    CHECK(info_minpin() == PIN_MIN_LENGTH, "getInfo minPINLength == default (4)");
    /* #35: remainingDiscoverableCredentials present; fresh device = full
     * resident capacity (RESIDENT_MAX_SLOTS, now 7 after the rp_id->128
     * slot-size bump in #15, plus 7 per PQF_RESIDENT_EXTRA_SECTORS). */
    CHECK(info_uint(0x14) == RESIDENT_MAX_SLOTS,
          "getInfo remainingDiscoverableCredentials == capacity (#35)");
    CHECK(PQF_RESIDENT_EXTRA_SECTORS != 0 || info_uint(0x14) == 7,
          "the default capacity is 7");

    /* Rust-base parity surface. */
    CHECK(info_array_size(0x01) == 2, "versions == [FIDO_2_0, FIDO_2_1]");
    CHECK(info_uint(0x07) == 8, "maxCredentialCountInList == 8");
    CHECK(info_uint(0x08) == 161, "maxCredentialIdLength == 161");
    CHECK(info_array_size(0x0a) == 4, "algorithms list has 4 entries (-56/-55/-54/-7)");
    CHECK(info_uint(0x0b) == 2048, "maxSerializedLargeBlobArray == 2048");
    CHECK(info_uint(0x0e) == 1, "firmwareVersion == 1");
    CHECK(info_uint(0x0f) == 32, "maxCredBlobLength == 32");

    /* Selection (0x0B) -> CTAP2_OK. */
    uint8_t sel[1] = { CTAP2_CMD_SELECTION };
    ctap2_dispatch(sel, 1, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "Selection ACKs with CTAP2_OK");

    /* vendorPrototype (0xFF) -> ERR_INVALID_SUBCOMMAND (0x3e; 0x16 is
     * UNSUPPORTED_EXTENSION, which is what this used to send). */
    uint8_t msg[64];
    size_t n = build_config(msg, sizeof msg, 0xFF, NULL, 0, NULL, 0, 0);
    ctap2_dispatch(msg, n, resp, sizeof resp, &rl);
    CHECK(resp[0] == 0x3e, "vendorPrototype rejected (0x3e INVALID_SUBCOMMAND)");

    /* Reset (0x07) -> CTAP2_OK. */
    uint8_t rst[1] = { CTAP2_CMD_RESET };
    ctap2_dispatch(rst, 1, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "Reset returns CTAP2_OK");
}

static void test_always_uv_bootstrap(void)
{
    printf("-- toggleAlwaysUv bootstrap + enforcement --\n");
    ctap2_init();
    uint8_t resp[2048]; size_t rl = 0;
    uint8_t msg[64];

    /* Fresh device, no PIN: toggleAlwaysUv without a token is allowed. */
    size_t n = build_config(msg, sizeof msg, 0x02, NULL, 0, NULL, 0, 0);
    ctap2_dispatch(msg, n, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "toggleAlwaysUv (no PIN, no token) OK");

    /* alwaysUv now forces UV: a plain MakeCredential -> 0x36. */
    CHECK(makecred_plain("example.com") == CTAP2_ERR_PUAT_REQUIRED,
          "alwaysUv forces UV on MakeCredential (0x36)");

    /* getInfo minPINLength is unaffected. */
    CHECK(info_minpin() == PIN_MIN_LENGTH, "minPINLength still default");

    /* A second toggle now needs a token (alwaysUv on) -> missing param. */
    n = build_config(msg, sizeof msg, 0x02, NULL, 0, NULL, 0, 0);
    ctap2_dispatch(msg, n, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_PUAT_REQUIRED,
          "second toggleAlwaysUv without token -> 0x36 PUAT_REQUIRED");
}

static void test_config_with_token(uint8_t proto)
{
    printf("-- token-authed config (PIN protocol v%u) --\n", proto);
    ctap2_init();
    uint8_t token[32];
    CHECK(setup_token(proto, PIN_PERM_AUTH_CONFIG, token) == 0,
          "obtained authnrCfg PIN token");

    uint8_t resp[2048]; size_t rl = 0;
    uint8_t msg[700];

    /* enableEnterpriseAttestation (no subParams). */
    size_t n = build_config(msg, sizeof msg, 0x01, NULL, 0, token, proto, 1);
    ctap2_dispatch(msg, n, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "enableEnterpriseAttestation OK");

    /* setMinPINLength -> 8. */
    uint8_t sp[64];
    size_t spl = enc_minpin(sp, sizeof sp, 8, NULL, 0);
    n = build_config(msg, sizeof msg, 0x03, sp, spl, token, proto, 1);
    ctap2_dispatch(msg, n, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "setMinPINLength(8) OK");
    CHECK(info_minpin() == 8, "getInfo minPINLength now 8");

    /* Raise-only: lowering to 6 is rejected. */
    spl = enc_minpin(sp, sizeof sp, 6, NULL, 0);
    n = build_config(msg, sizeof msg, 0x03, sp, spl, token, proto, 1);
    ctap2_dispatch(msg, n, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_PIN_POLICY_VIOLATION,
          "setMinPINLength(6 < 8) rejected (0x37)");

    /* Wrong token (bad MAC) -> 0x33. */
    uint8_t bad[32]; memset(bad, 0x99, 32);
    spl = enc_minpin(sp, sizeof sp, 10, NULL, 0);
    n = build_config(msg, sizeof msg, 0x03, sp, spl, bad, proto, 1);
    ctap2_dispatch(msg, n, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_PIN_AUTH_INVALID, "bad config token -> 0x33");

    /* toggleAlwaysUv now works via the token. */
    n = build_config(msg, sizeof msg, 0x02, NULL, 0, token, proto, 1);
    ctap2_dispatch(msg, n, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "token-authed toggleAlwaysUv OK");
}

static void test_min_pin_length_extension(uint8_t proto)
{
    printf("-- minPinLength extension allowlist (PIN protocol v%u) --\n", proto);
    ctap2_init();
    uint8_t token[32];
    /* Need both authnrCfg (for setMinPINLength) and makeCredential. */
    CHECK(setup_token(proto, PIN_PERM_AUTH_CONFIG | PIN_PERM_MAKE_CREDENTIAL,
                      token) == 0, "obtained authnrCfg+mc token");

    uint8_t resp[2048]; size_t rl = 0;
    uint8_t msg[700];

    /* setMinPINLength(6) with example.com in the allowlist. */
    const char *rpids[1] = { "example.com" };
    uint8_t sp[96];
    size_t spl = enc_minpin(sp, sizeof sp, 6, rpids, 1);
    size_t n = build_config(msg, sizeof msg, 0x03, sp, spl, token, proto, 1);
    ctap2_dispatch(msg, n, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "setMinPINLength(6, [example.com]) OK");
    CHECK(info_minpin() == 6, "getInfo minPINLength now 6");

    /* Allowlisted RP -> minPinLength extension emitted (ED flag set). */
    int f_allow = makecred_minpin_ext("example.com", token, proto);
    CHECK(f_allow >= 0 && (f_allow & 0x80), "minPinLength ext emitted (ED set) for allowlisted RP");

    /* Non-allowlisted RP -> no extension emitted (ED flag clear). */
    int f_deny = makecred_minpin_ext("other.example", token, proto);
    CHECK(f_deny >= 0 && !(f_deny & 0x80), "no minPinLength ext (ED clear) for non-allowlisted RP");
}

/* getInfo: boolean value at top-level `key` (-1 if absent/not-bool). */
static int info_bool(uint64_t key)
{
    uint8_t msg[1] = { CTAP2_CMD_GET_INFO };
    uint8_t resp[2048]; size_t rl = 0;
    ctap2_dispatch(msg, 1, resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return -1;
    pqfido_cbor_item_t *m = NULL;
    pqfido_cbor_decode(resp + 1, rl - 1, &m);
    const pqfido_cbor_item_t *v = cbor_map_get_uint(m, key);
    int out = (v && pqfido_cbor_is_bool(v)) ? pqfido_cbor_bool(v) : -1;
    pqfido_cbor_free(m);
    return out;
}

/* #26 / #34 / #13: setMinPINLength forceChangePin must persist a flag,
 * surface it as getInfo 0x0C forcePINChange, block mc/ga token issuance,
 * and be cleared by a successful changePIN. Drives the whole lifecycle
 * through the real authenticatorConfig + ClientPIN paths. */
static void test_force_pin_change_lifecycle(uint8_t proto)
{
    printf("-- forcePINChange lifecycle (PIN protocol v%u) --\n", proto);
    ctap2_init();

    uint8_t resp[2048]; size_t rl = 0;
    uint8_t msg[700];

    /* Need authnrCfg (to set the flag) + makeCredential (to test the
     * gate later). Establish the shared secret too so we can changePIN. */
    /* Reproduce setup_token's handshake but keep the shared secret. */
    uint8_t token[32];
    {
        uint8_t m2[700]; cbor_writer_t w;
        cbor_w_init(&w, m2 + 1, sizeof m2 - 1);
        cbor_w_map_header(&w, 2);
        cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
        cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x02);
        m2[0] = CTAP2_CMD_CLIENT_PIN;
        ctap2_dispatch(m2, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        uint8_t ax[32], ay[32];
        { pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
          cbor_cose_ec2_xy(cbor_map_get_uint(m, 0x01), ax, ay); pqfido_cbor_free(m); }
        uint8_t pp[32], px[32], py[32]; pqf_p256_keygen(pp, px, py);
        pin_shared_secret_t ss; pin_shared_secret(proto, pp, ax, ay, &ss);
        uint8_t padded[64]; memset(padded, 0, sizeof padded); memcpy(padded, "1234", 4);
        uint8_t npe[80]; size_t npl = 0; pin_encrypt(&ss, padded, 64, npe, &npl);
        uint8_t pa[32]; size_t pal = 0;
        pin_authenticate(proto, ss.hmac_key, 32, npe, npl, pa, &pal);
        cbor_w_init(&w, m2 + 1, sizeof m2 - 1);
        cbor_w_map_header(&w, 5);
        cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
        cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x03);
        cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);
        cbor_w_uint(&w, 0x04); cbor_w_bytes(&w, pa, pal);
        cbor_w_uint(&w, 0x05); cbor_w_bytes(&w, npe, npl);
        m2[0] = CTAP2_CMD_CLIENT_PIN;
        ctap2_dispatch(m2, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_OK, "setPIN OK (forcePINChange lifecycle)");

        /* getPinUvAuthTokenUsingPinWithPermissions(authnrCfg) -- allowed
         * (no force-change pending yet). */
        uint8_t pinhash[32]; pqf_sha256((const uint8_t *)"1234", 4, pinhash);
        uint8_t phe[48]; size_t pel = 0; pin_encrypt(&ss, pinhash, 16, phe, &pel);
        cbor_w_init(&w, m2 + 1, sizeof m2 - 1);
        cbor_w_map_header(&w, 5);
        cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
        cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x09);
        cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);
        cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, phe, pel);
        cbor_w_uint(&w, 0x09); cbor_w_uint(&w, PIN_PERM_AUTH_CONFIG);
        m2[0] = CTAP2_CMD_CLIENT_PIN;
        ctap2_dispatch(m2, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_OK, "authnrCfg token obtained");
        { pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
          const pqfido_cbor_item_t *t = cbor_map_get_uint(m, 0x02);
          size_t tl = 0;
          pin_decrypt(&ss, pqfido_cbor_bytes(t), pqfido_cbor_bytes_len(t),
                      token, 32, &tl);
          pqfido_cbor_free(m); }
    }

    CHECK(info_bool(0x0c) == 0, "forcePINChange starts false");

    /* setMinPINLength { newMin: 8, forceChangePin: true } via the real
     * config path. */
    uint8_t sp[64]; cbor_writer_t spw; cbor_w_init(&spw, sp, sizeof sp);
    cbor_w_map_header(&spw, 2);
    cbor_w_uint(&spw, 0x01); cbor_w_uint(&spw, 8);
    cbor_w_uint(&spw, 0x03); cbor_w_bool(&spw, true);   /* forceChangePin */
    size_t spl = cbor_w_off(&spw);
    size_t n = build_config(msg, sizeof msg, 0x03, sp, spl, token, proto, 1);
    ctap2_dispatch(msg, n, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "setMinPINLength{forceChangePin:true} OK");
    CHECK(info_bool(0x0c) == 1, "getInfo forcePINChange now true (#34)");

    /* A successful changePIN (1234 -> 56789012) clears the flag (#26).
     * The new PIN must be >= the just-raised min length (8). */
    {
        uint8_t m2[700]; cbor_writer_t w;
        cbor_w_init(&w, m2 + 1, sizeof m2 - 1);
        cbor_w_map_header(&w, 2);
        cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
        cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x02);
        m2[0] = CTAP2_CMD_CLIENT_PIN;
        ctap2_dispatch(m2, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        uint8_t ax[32], ay[32];
        { pqfido_cbor_item_t *m = NULL; pqfido_cbor_decode(resp + 1, rl - 1, &m);
          cbor_cose_ec2_xy(cbor_map_get_uint(m, 0x01), ax, ay); pqfido_cbor_free(m); }
        uint8_t pp[32], px[32], py[32]; pqf_p256_keygen(pp, px, py);
        pin_shared_secret_t ss; pin_shared_secret(proto, pp, ax, ay, &ss);

        uint8_t newpad[64]; memset(newpad, 0, sizeof newpad);
        memcpy(newpad, "56789012", 8);   /* >= raised min length (8) */
        uint8_t npe[80]; size_t npl = 0; pin_encrypt(&ss, newpad, 64, npe, &npl);
        uint8_t oldhash[32]; pqf_sha256((const uint8_t *)"1234", 4, oldhash);
        uint8_t phe[48]; size_t pel = 0; pin_encrypt(&ss, oldhash, 16, phe, &pel);
        /* pinUvAuthParam = MAC(ss, newPinEnc || pinHashEnc). */
        uint8_t mac_in[160]; memcpy(mac_in, npe, npl); memcpy(mac_in + npl, phe, pel);
        uint8_t pa[32]; size_t pal = 0;
        pin_authenticate(proto, ss.hmac_key, 32, mac_in, npl + pel, pa, &pal);
        cbor_w_init(&w, m2 + 1, sizeof m2 - 1);
        cbor_w_map_header(&w, 6);
        cbor_w_uint(&w, 0x01); cbor_w_uint(&w, proto);
        cbor_w_uint(&w, 0x02); cbor_w_uint(&w, 0x04);   /* changePIN */
        cbor_w_uint(&w, 0x03); emit_cose(&w, px, py);
        cbor_w_uint(&w, 0x04); cbor_w_bytes(&w, pa, pal);
        cbor_w_uint(&w, 0x05); cbor_w_bytes(&w, npe, npl);
        cbor_w_uint(&w, 0x06); cbor_w_bytes(&w, phe, pel);
        m2[0] = CTAP2_CMD_CLIENT_PIN;
        ctap2_dispatch(m2, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_OK, "changePIN OK");
    }
    CHECK(info_bool(0x0c) == 0, "getInfo forcePINChange cleared by changePIN (#26)");
}

int main(void)
{
    printf("authenticatorConfig host test\n");
    test_defaults_selection_reset();
    test_always_uv_bootstrap();
    test_config_with_token(PIN_PROTOCOL_V1);
    test_config_with_token(PIN_PROTOCOL_V2);
    test_min_pin_length_extension(PIN_PROTOCOL_V1);
    test_force_pin_change_lifecycle(PIN_PROTOCOL_V1);
    test_force_pin_change_lifecycle(PIN_PROTOCOL_V2);
    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
