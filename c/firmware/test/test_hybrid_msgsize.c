/* test_hybrid_msgsize.c -- hybrid responses must fit CTAP HID.
 *
 * The CTAPHID transport caps a message at 7609 bytes structurally
 * (57 + 128/59: initialization frame + at most 128 continuation
 * frames, the 7-bit sequence number's range). A hybrid ML-DSA-87
 * MakeCredential that carried BOTH the 2592-byte ML-DSA public key
 * (authData) and a full ~4.6 KB hybrid attestation signature
 * (attStmt) measured 7617 bytes on silicon -- 8 over the ceiling and
 * unfixable by buffer sizing. The fix is ECDSA-only self-attestation
 * at registration (OpenSK's technique): attStmt carries alg ES256 +
 * a ~72 B ECDSA sig, the ML-DSA public key stays in authData, and
 * ML-DSA still signs every GetAssertion (no public key in that
 * response, so it fits at every level).
 *
 * That fallback is scoped to level 87 ALONE. At 44 and 65 the dual
 * attStmt fits comfortably, so emitting ES256 there would be a PQC
 * downgrade with no size justification -- and conformant verifiers
 * reject it: the conformance suite answers a 44/65 ES256 attStmt with
 * a flag-policy error and refuses the registration outright. So this
 * test asserts a DIFFERENT attestation shape per level -- full hybrid
 * at 44/65, ES256 at 87 -- which is what keeps the fallback honest and
 * stops it from silently spreading back to the levels that don't need
 * it.
 *
 * This test registers a hybrid credential and asserts with it,
 * checking at each step that the full CTAP response (status byte +
 * CBOR) is within CTAPHID_MAX_MSG_BYTES, that the registration
 * attStmt has the shape that level requires and verifies against the
 * right key material, and that the assertion is a full hybrid
 * signature that verifies against both halves. Build it at each level
 * to probe that level's sizes:
 *
 *     make build/test_hybrid_msgsize CC="cc -DPQF_HYBRID_VARIANT=87"
 *     ./build/test_hybrid_msgsize
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "ctap2.h"
#include "ctaphid.h"
#include "cbor_encode.h"
#include "cbor_read.h"
#include "hybrid.h"
#include "pqcbor.h"
#include "pqf_crypto.h"

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("  ok: %s\n", m); \
    else { fprintf(stderr, "FAIL: %s\n", m); fails++; } } while (0)

static const uint8_t CDH[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18, 0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
};

/* Extract the hybrid COSE key halves from a COSE_Key map embedded at
 * `cose`: EC x/y at labels -2/-3, raw ML-DSA public key at -4. */
static int cose_hybrid_pub(const uint8_t *cose, size_t len,
                           uint8_t x[32], uint8_t y[32],
                           uint8_t *mldsa, size_t *mldsa_len)
{
    pqfido_cbor_item_t *m = NULL;
    if (pqfido_cbor_decode(cose, len, &m) != PQFIDO_OK) return -1;
    int rc = -1;
    if (!pqfido_cbor_is_map(m)) goto out;
    size_t n = pqfido_cbor_map_size(m);
    const pqfido_cbor_pair_t *p = pqfido_cbor_map_pairs(m);
    const uint8_t *px = NULL, *py = NULL, *pm = NULL;
    size_t pm_len = 0;
    for (size_t i = 0; i < n; i++) {
        if (!pqfido_cbor_is_negint(p[i].key) || !pqfido_cbor_is_bytes(p[i].value))
            continue;
        uint64_t arg = pqfido_cbor_negint_arg(p[i].key);   /* -2->1, -3->2, -4->3 */
        if (arg == 1) px = pqfido_cbor_bytes(p[i].value);
        if (arg == 2) py = pqfido_cbor_bytes(p[i].value);
        if (arg == 3) { pm = pqfido_cbor_bytes(p[i].value);
                        pm_len = pqfido_cbor_bytes_len(p[i].value); }
    }
    if (px && py && pm && pm_len == PQF_HYBRID_PK_LEN) {
        memcpy(x, px, 32); memcpy(y, py, 32);
        memcpy(mldsa, pm, pm_len); *mldsa_len = pm_len;
        rc = 0;
    }
out:
    pqfido_cbor_free(m);
    return rc;
}

int main(void)
{
    printf("hybrid CTAP HID message-size test (ML-DSA-%d, COSE %d)\n",
           PQF_HYBRID_VARIANT, PQF_HYBRID_COSE_ALG);
    ctap2_init();

    /* ---- 1. MakeCredential offering ONLY the hybrid alg ---- */
    uint8_t req[512];
    cbor_writer_t w;
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 4);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);          /* clientDataHash */
    cbor_w_uint(&w, 0x02);                                     /* rp */
    cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03);                                     /* user */
    cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t uid[4] = {1,2,3,4}; cbor_w_bytes(&w, uid, 4); }
    cbor_w_uint(&w, 0x04);                                     /* pubKeyCredParams */
    cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, PQF_HYBRID_COSE_ALG);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    CHECK(cbor_w_ok(&w), "build hybrid MakeCredential request");

    uint8_t msg[600];
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, req, cbor_w_off(&w));
    size_t msg_len = 1 + cbor_w_off(&w);

    /* 16 KiB response buffer: big enough that the transport ceiling --
     * not the buffer -- is what the size CHECK below exercises. */
    static uint8_t resp[16384];
    size_t resp_len = 0;
    ctap2_dispatch(msg, msg_len, resp, sizeof resp, &resp_len);
    CHECK(resp_len > 1 && resp[0] == CTAP2_OK, "MakeCredential status OK");

    printf("  MakeCredential response: %zu bytes (CTAPHID ceiling %d)\n",
           resp_len, CTAPHID_MAX_MSG_BYTES);
    CHECK(resp_len <= CTAPHID_MAX_MSG_BYTES,
          "MakeCredential response fits CTAP HID");

    /* ---- 2. Parse: attStmt must be ES256 self-attestation ---- */
    uint8_t cred_id[256]; size_t cred_id_len = 0;
    uint8_t pub_x[32], pub_y[32];
    static uint8_t mldsa_pub[PQF_HYBRID_PK_LEN]; size_t mldsa_pub_len = 0;
    static uint8_t mc_authdata[PQF_HYBRID_PK_LEN + 512]; size_t mc_ad_len = 0;
    /* Big enough for BOTH attestation shapes: a lone ECDSA DER sig
     * (level 87, ~72 B) and the full hybrid pair (44/65, ECDSA DER +
     * ML-DSA). Sized at 80 it silently dropped the hybrid signature via
     * the `<= sizeof mc_sig` guard below, which reads as "no signature"
     * rather than "buffer too small". */
    static uint8_t mc_sig[PQF_HYBRID_MAX_SIG]; size_t mc_sig_len = 0;
    int64_t att_alg = 0;
    {
        pqfido_cbor_item_t *m = NULL;
        int dr = pqfido_cbor_decode(resp + 1, resp_len - 1, &m);
        CHECK(dr == PQFIDO_OK && pqfido_cbor_is_map(m),
              "MakeCredential response is a map");

        const pqfido_cbor_item_t *ad = NULL, *att = NULL;
        size_t n = pqfido_cbor_is_map(m) ? pqfido_cbor_map_size(m) : 0;
        const pqfido_cbor_pair_t *pr = n ? pqfido_cbor_map_pairs(m) : NULL;
        for (size_t i = 0; i < n; i++) {
            if (pqfido_cbor_is_uint(pr[i].key)) {
                uint64_t k = pqfido_cbor_uint(pr[i].key);
                if (k == 2) ad = pr[i].value;
                if (k == 3) att = pr[i].value;
            }
        }
        CHECK(ad && pqfido_cbor_is_bytes(ad), "authData present");
        CHECK(att && pqfido_cbor_is_map(att), "attStmt present");

        if (ad && pqfido_cbor_is_bytes(ad)) {
            mc_ad_len = pqfido_cbor_bytes_len(ad);
            CHECK(mc_ad_len <= sizeof mc_authdata, "authData fits staging");
            memcpy(mc_authdata, pqfido_cbor_bytes(ad), mc_ad_len);
            /* rpIdHash(32) flags(1) signCount(4) aaguid(16)
             * credIdLen(2) credId(L) COSE_Key(rest) */
            const uint8_t *a = mc_authdata;
            uint16_t cidl = (uint16_t)((a[53] << 8) | a[54]);
            cred_id_len = cidl;
            memcpy(cred_id, a + 55, cidl);
            size_t cose_off = 55 + cidl;
            CHECK(cose_hybrid_pub(a + cose_off, mc_ad_len - cose_off,
                                  pub_x, pub_y, mldsa_pub, &mldsa_pub_len) == 0,
                  "authData COSE key carries EC point + full ML-DSA pubkey");
        }
        if (att && pqfido_cbor_is_map(att)) {
            size_t an = pqfido_cbor_map_size(att);
            const pqfido_cbor_pair_t *ap = pqfido_cbor_map_pairs(att);
            for (size_t i = 0; i < an; i++) {
                if (!pqfido_cbor_is_string(ap[i].key)) continue;
                size_t kl = pqfido_cbor_string_len(ap[i].key);
                const char *ks = pqfido_cbor_string(ap[i].key);
                if (kl == 3 && memcmp(ks, "alg", 3) == 0
                    && pqfido_cbor_is_negint(ap[i].value))
                    att_alg = -1 - (int64_t)pqfido_cbor_negint_arg(ap[i].value);
                if (kl == 3 && memcmp(ks, "sig", 3) == 0
                    && pqfido_cbor_is_bytes(ap[i].value)
                    && pqfido_cbor_bytes_len(ap[i].value) <= sizeof mc_sig) {
                    mc_sig_len = pqfido_cbor_bytes_len(ap[i].value);
                    memcpy(mc_sig, pqfido_cbor_bytes(ap[i].value), mc_sig_len);
                }
            }
        }
        pqfido_cbor_free(m);
    }
    /* ---- 3. The attestation shape is LEVEL-DEPENDENT ----------------
     *
     * 44/65: the full dual signature fits, so attStmt.alg must equal the
     *        credential's hybrid alg. Sending ES256 here would be an
     *        unjustified PQC downgrade, and conformant verifiers reject
     *        it (the conformance suite answers with a flag-policy error).
     * 87:    the dual attStmt measures 7617 B against the 7609 B CTAPHID
     *        ceiling, so ES256-only self-attestation is the documented
     *        and only viable fallback.
     */
#if PQF_HYBRID_VARIANT == 87
    CHECK(att_alg == -7,
          "level 87: attStmt alg is ES256 (size-capped fallback)");
    CHECK(mc_sig_len > 0 && mc_sig_len <= 72,
          "level 87: attStmt sig is a lone ECDSA DER signature");
    {
        /* Plain SHA-256 over authData || clientDataHash, no hybrid
         * label -- packed ES256 is not the hybrid construction. */
        uint8_t h[32];
        pqf_sha256_ctx_t sc; pqf_sha256_init(&sc);
        pqf_sha256_update(&sc, mc_authdata, mc_ad_len);
        pqf_sha256_update(&sc, CDH, 32);
        pqf_sha256_final(&sc, h);
        CHECK(pqf_ecdsa_p256_verify(pub_x, pub_y, h, mc_sig, mc_sig_len) == 1,
              "level 87: ES256 self-attestation verifies");
    }
#else
    CHECK(att_alg == PQF_HYBRID_COSE_ALG,
          "attStmt alg equals the credential's hybrid alg (no PQC downgrade)");
    CHECK(mc_sig_len > PQF_HYBRID_SIG_LEN,
          "attStmt sig is the full hybrid pair (ECDSA \xe2\x80\x96 ML-DSA)");
    {
        /* Same construction as an assertion: hybrid_verify applies the
         * LABEL over authData || clientDataHash internally. */
        static uint8_t signed_msg[8192];
        size_t sm_len = mc_ad_len + 32;
        CHECK(sm_len <= sizeof signed_msg, "attestation signed-message fits");
        memcpy(signed_msg, mc_authdata, mc_ad_len);
        memcpy(signed_msg + mc_ad_len, CDH, 32);
        CHECK(hybrid_verify(pub_x, pub_y, mldsa_pub, mldsa_pub_len,
                            signed_msg, sm_len, mc_sig, mc_sig_len) == 1,
              "full hybrid attestation signature verifies");
    }
#endif

    /* ---- 4. GetAssertion: full hybrid signature, must also fit ---- */
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 3);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, "example.com");     /* rpId */
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);          /* clientDataHash */
    cbor_w_uint(&w, 0x03);                                     /* allowList */
    cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "id");   cbor_w_bytes(&w, cred_id, cred_id_len);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    CHECK(cbor_w_ok(&w), "build GetAssertion request");

    msg[0] = CTAP2_CMD_GET_ASSERTION;
    memcpy(msg + 1, req, cbor_w_off(&w));
    msg_len = 1 + cbor_w_off(&w);
    ctap2_dispatch(msg, msg_len, resp, sizeof resp, &resp_len);
    CHECK(resp_len > 1 && resp[0] == CTAP2_OK, "GetAssertion status OK");

    printf("  GetAssertion response: %zu bytes (CTAPHID ceiling %d)\n",
           resp_len, CTAPHID_MAX_MSG_BYTES);
    CHECK(resp_len <= CTAPHID_MAX_MSG_BYTES,
          "GetAssertion response fits CTAP HID");

    /* ---- 5. The assertion is a FULL hybrid signature ---- */
    {
        pqfido_cbor_item_t *m = NULL;
        pqfido_cbor_decode(resp + 1, resp_len - 1, &m);
        const pqfido_cbor_item_t *ad = NULL, *sig = NULL;
        size_t n = pqfido_cbor_is_map(m) ? pqfido_cbor_map_size(m) : 0;
        const pqfido_cbor_pair_t *pr = n ? pqfido_cbor_map_pairs(m) : NULL;
        for (size_t i = 0; i < n; i++) {
            if (pqfido_cbor_is_uint(pr[i].key)) {
                uint64_t k = pqfido_cbor_uint(pr[i].key);
                if (k == 2) ad = pr[i].value;
                if (k == 3) sig = pr[i].value;
            }
        }
        CHECK(ad && pqfido_cbor_is_bytes(ad) && sig && pqfido_cbor_is_bytes(sig),
              "assertion has authData + signature");
        if (ad && sig && pqfido_cbor_is_bytes(ad) && pqfido_cbor_is_bytes(sig)) {
            size_t sl = pqfido_cbor_bytes_len(sig);
            CHECK(sl > PQF_HYBRID_SIG_LEN,
                  "assertion signature is hybrid (ECDSA || ML-DSA)");
            /* hybrid_sign covers authData || clientDataHash. */
            static uint8_t hm[PQF_HYBRID_PK_LEN + 600 + 32];
            size_t adl = pqfido_cbor_bytes_len(ad);
            memcpy(hm, pqfido_cbor_bytes(ad), adl);
            memcpy(hm + adl, CDH, 32);
            CHECK(hybrid_verify(pub_x, pub_y, mldsa_pub, mldsa_pub_len,
                                hm, adl + 32,
                                pqfido_cbor_bytes(sig), sl) == 1,
                  "full hybrid assertion signature verifies");
        }
        pqfido_cbor_free(m);
    }

    /* ---- credProtect is echoed on a HYBRID registration ----
     * It used to be suppressed for hybrid credentials on a size claim
     * this very test now measures to be ~1950 bytes wide of the mark.
     * The echo is what tells a relying party using
     * enforceCredentialProtectionPolicy that the policy applied. */
    {
        uint8_t req2[512]; cbor_writer_t w2;
        cbor_w_init(&w2, req2, sizeof req2);
        cbor_w_map_header(&w2, 5);
        cbor_w_uint(&w2, 0x01); cbor_w_bytes(&w2, CDH, 32);
        cbor_w_uint(&w2, 0x02); cbor_w_map_header(&w2, 1);
        cbor_w_text(&w2, "id"); cbor_w_text(&w2, "example.com");
        cbor_w_uint(&w2, 0x03); cbor_w_map_header(&w2, 1);
        cbor_w_text(&w2, "id"); { uint8_t uid[4] = {5,6,7,8}; cbor_w_bytes(&w2, uid, 4); }
        cbor_w_uint(&w2, 0x04); cbor_w_array_header(&w2, 1);
        cbor_w_map_header(&w2, 2);
        cbor_w_text(&w2, "alg"); cbor_w_int(&w2, PQF_HYBRID_COSE_ALG);
        cbor_w_text(&w2, "type"); cbor_w_text(&w2, "public-key");
        cbor_w_uint(&w2, 0x06); cbor_w_map_header(&w2, 1);
        cbor_w_text(&w2, "credProtect"); cbor_w_uint(&w2, 2);
        uint8_t msg2[600]; msg2[0] = CTAP2_CMD_MAKE_CREDENTIAL;
        memcpy(msg2 + 1, req2, cbor_w_off(&w2));
        static uint8_t resp2[16384]; size_t rl2 = 0;
        ctap2_dispatch(msg2, 1 + cbor_w_off(&w2), resp2, sizeof resp2, &rl2);
        CHECK(resp2[0] == CTAP2_OK, "hybrid MakeCredential with credProtect OK");
        pqfido_cbor_item_t *m2 = NULL; const pqfido_cbor_item_t *ad2 = NULL;
        if (resp2[0] == CTAP2_OK && pqfido_cbor_decode(resp2 + 1, rl2 - 1, &m2) == PQFIDO_OK)
            ad2 = cbor_map_get_uint(m2, 0x02);
        bool ed = ad2 && pqfido_cbor_is_bytes(ad2) && (pqfido_cbor_bytes(ad2)[32] & 0x80);
        CHECK(ed, "hybrid authData carries the ED (extensions) flag");
        bool echoed = false;
        if (ad2 && pqfido_cbor_is_bytes(ad2)) {
            const uint8_t *a2 = pqfido_cbor_bytes(ad2); size_t n2 = pqfido_cbor_bytes_len(ad2);
            for (size_t i = 0; i + 11 <= n2; i++)
                if (memcmp(a2 + i, "credProtect", 11) == 0) { echoed = true; break; }
        }
        CHECK(echoed, "hybrid authData echoes credProtect (was suppressed on hybrid)");
        CHECK(rl2 <= 7609, "hybrid MakeCredential with credProtect still fits CTAP HID");
        pqfido_cbor_free(m2);
    }

    printf(fails ? "RESULT: %d FAILURE(S)\n" : "RESULT: all passed\n", fails);
    return fails ? 1 : 0;
}
