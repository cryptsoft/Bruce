/* test_ctap2.c -- host-side end-to-end test of the CTAP2 layer.
 *
 * Drives ctap2_dispatch() exactly as the CTAPHID transport would on
 * the device, but on the host so we can validate the full
 * MakeCredential -> GetAssertion round-trip without flashing:
 *
 *   1. Build a MakeCredential request (clientDataHash, rp.id,
 *      user, pubKeyCredParams=[ES256]) and dispatch it.
 *   2. Parse the response: status, fmt="packed", authData, attStmt.
 *   3. Pull the credentialId + COSE public key out of authData.
 *   4. Verify the packed self-attestation signature over
 *      authData||clientDataHash with that public key.
 *   5. Build a GetAssertion request whose allowList holds the new
 *      credentialId; dispatch it.
 *   6. Verify the assertion signature over authData2||clientDataHash
 *      with the same public key.
 *
 * This catches CBOR wire-format + authData layout + signing bugs
 * that would otherwise only show up against a live RP.
 *
 * The firmware's RAND_* is TRNG-backed (pqf_rand.c, pico-sdk only);
 * on the host we link host_rand_stub.c from openssl-mini/test.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "ctap2.h"
#include "cbor_encode.h"
#include "cbor_read.h"
#include "hybrid.h"
#include "resident_store.h"
#include "pqcbor.h"
#include "pqf_crypto.h"

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("  ok: %s\n", m); \
    else { fprintf(stderr, "FAIL: %s\n", m); fails++; } } while (0)

/* A fixed 32-byte clientDataHash used for both ceremonies. */
static const uint8_t CDH[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18, 0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
};

/* Pull the EC2 public key (x,y) out of a COSE_Key map embedded at
 * `cose` (decode one CBOR item). Returns 0 on success. */
static int cose_pub(const uint8_t *cose, size_t len, uint8_t x[32], uint8_t y[32])
{
    pqfido_cbor_item_t *m = NULL;
    if (pqfido_cbor_decode(cose, len, &m) != PQFIDO_OK) return -1;
    int rc = -1;
    if (!pqfido_cbor_is_map(m)) goto out;
    size_t n = pqfido_cbor_map_size(m);
    const pqfido_cbor_pair_t *p = pqfido_cbor_map_pairs(m);
    const uint8_t *px = NULL, *py = NULL;
    for (size_t i = 0; i < n; i++) {
        if (pqfido_cbor_is_negint(p[i].key)) {
            uint64_t arg = pqfido_cbor_negint_arg(p[i].key);  /* -2->1, -3->2 */
            if (arg == 1 && pqfido_cbor_is_bytes(p[i].value)) px = pqfido_cbor_bytes(p[i].value);
            if (arg == 2 && pqfido_cbor_is_bytes(p[i].value)) py = pqfido_cbor_bytes(p[i].value);
        }
    }
    if (px && py) { memcpy(x, px, 32); memcpy(y, py, 32); rc = 0; }
out:
    pqfido_cbor_free(m);
    return rc;
}

/* Signed value of a CBOR integer item, or 0 (never a valid COSE alg
 * id here) if the item is not an integer at all. */
static long cbor_int_val(const pqfido_cbor_item_t *it)
{
    if (it == NULL) return 0;
    if (pqfido_cbor_is_negint(it)) return -(long)pqfido_cbor_negint_arg(it) - 1;
    if (pqfido_cbor_is_uint(it))   return (long)pqfido_cbor_uint(it);
    return 0;
}

/* getInfo 0x0a `algorithms`.
 *
 * The advertised list must be exactly the composite ids the
 * MakeCredential picker accepts, and it must contain *this* build's
 * PQF_HYBRID_COSE_ALG -- that second property is the one whose
 * violation broke the PQC path: 0x0a went on publishing the RFC 9964
 * pure ML-DSA ids (-50/-49/-48) after pick_alg() had moved to the
 * composite ones, so a host that trusted getInfo asked for an id the
 * device then refused, and every registration silently degraded to
 * ES256. Runs at all three PQF_HYBRID_VARIANT values. */
static void test_getinfo_algorithms(void)
{
    /* MLDSA87-ES384, MLDSA65-ES256, MLDSA44-ES256 (hybrid.h), then -7
     * ES256; all three composite variants are advertised regardless of
     * which one this build mints (see ctap2.c's 0x0a block). */
    static const long want[] = { COSE_ALG_MLDSA87_ES384,
                                 COSE_ALG_MLDSA65_ES256,
                                 COSE_ALG_MLDSA44_ES256, -7 };
    /* The wire values, spelled out once as a tripwire: the named
     * constants could all move together and the checks below would
     * still pass. -56/-55/-54 are the draft-ietf-jose-pq-composite-
     * sigs-04 requests; a relabel has to update this line on purpose. */
    static const long want_wire[] = { -56, -55, -54, -7 };
    const size_t n_want = sizeof want / sizeof want[0];

    printf("-- getInfo 0x0a algorithms (PQF_HYBRID_VARIANT=%d, "
           "PQF_HYBRID_COSE_ALG=%d) --\n",
           PQF_HYBRID_VARIANT, PQF_HYBRID_COSE_ALG);

    uint8_t msg[1] = { CTAP2_CMD_GET_INFO };
    uint8_t resp[2048]; size_t rl = 0;
    ctap2_dispatch(msg, 1, resp, sizeof resp, &rl);
    CHECK(rl > 1 && resp[0] == CTAP2_OK, "getInfo status OK");

    pqfido_cbor_item_t *m = NULL;
    CHECK(pqfido_cbor_decode(resp + 1, rl - 1, &m) == PQFIDO_OK
          && pqfido_cbor_is_map(m), "getInfo response is a map");

    const pqfido_cbor_item_t *algs = cbor_map_get_uint(m, 0x0a);
    CHECK(algs != NULL && pqfido_cbor_is_array(algs),
          "getInfo key 0x0a present and an array");

    long got[8]; size_t n_got = 0;
    if (algs != NULL && pqfido_cbor_is_array(algs)) {
        size_t n = pqfido_cbor_array_size(algs);
        CHECK(n == n_want, "0x0a holds exactly 4 entries");
        for (size_t i = 0; i < n && n_got < sizeof got / sizeof got[0]; i++) {
            const pqfido_cbor_item_t *e = pqfido_cbor_array_get(algs, i);
            char msgbuf[64];
            snprintf(msgbuf, sizeof msgbuf,
                     "entry %zu is a 2-entry map with alg + type", i);
            const pqfido_cbor_item_t *a = cbor_map_get_text(e, "alg");
            const pqfido_cbor_item_t *t = cbor_map_get_text(e, "type");
            CHECK(e != NULL && pqfido_cbor_is_map(e)
                  && pqfido_cbor_map_size(e) == 2
                  && a != NULL && (pqfido_cbor_is_negint(a) || pqfido_cbor_is_uint(a))
                  && t != NULL, msgbuf);
            snprintf(msgbuf, sizeof msgbuf, "entry %zu type is \"public-key\"", i);
            CHECK(t != NULL && pqfido_cbor_is_string(t)
                  && pqfido_cbor_string_len(t) == 10
                  && memcmp(pqfido_cbor_string(t), "public-key", 10) == 0, msgbuf);
            got[n_got++] = cbor_int_val(a);
        }
    }

    /* Set equality, both directions, so neither a missing nor a
     * left-over identifier can slip through. */
    for (size_t i = 0; i < n_want; i++) {
        size_t hits = 0;
        for (size_t j = 0; j < n_got; j++) if (got[j] == want[i]) hits++;
        char msgbuf[64];
        snprintf(msgbuf, sizeof msgbuf, "alg %ld advertised exactly once", want[i]);
        CHECK(hits == 1, msgbuf);
    }
    for (size_t j = 0; j < n_got; j++) {
        int expected = 0;
        for (size_t i = 0; i < n_want; i++) if (got[j] == want[i]) expected = 1;
        char msgbuf[64];
        snprintf(msgbuf, sizeof msgbuf, "advertised alg %ld is one we mint", got[j]);
        CHECK(expected, msgbuf);
    }

    /* Order and wire values, exactly. */
    CHECK(n_got == n_want, "0x0a decoded to 4 alg values");
    for (size_t i = 0; i < n_got && i < n_want; i++) {
        char msgbuf[64];
        snprintf(msgbuf, sizeof msgbuf, "entry %zu is alg %ld", i,
                 want_wire[i]);
        CHECK(got[i] == want[i] && got[i] == want_wire[i], msgbuf);
    }

    /* The property the bug violated: whatever this build actually
     * mints has to be in the list the host is told about. */
    int mintable_advertised = 0;
    for (size_t j = 0; j < n_got; j++)
        if (got[j] == (long)PQF_HYBRID_COSE_ALG) mintable_advertised = 1;
    CHECK(mintable_advertised,
          "this build's PQF_HYBRID_COSE_ALG is in the advertised list");

    pqfido_cbor_free(m);
}


/* MakeCredential offering exactly the `n` algs in `algs`; returns the
 * status byte. On CTAP2_OK also reports the COSE_Key alg (label 3) and
 * the attStmt alg through `cose_alg` / `att_alg`. */
static uint8_t mc_algs(const long *algs, size_t n, long *cose_alg,
                       long *att_alg)
{
    static uint8_t resp[8192];
    uint8_t req[512], msg[600]; cbor_writer_t w;
    size_t rl = 0;
    *cose_alg = 0; *att_alg = 0;
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 4);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "relabel.example");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u = 0x5a; cbor_w_bytes(&w, &u, 1); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, n);
    for (size_t i = 0; i < n; i++) {
        cbor_w_map_header(&w, 2);
        cbor_w_text(&w, "alg"); cbor_w_int(&w, algs[i]);
        cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    }
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, req, cbor_w_off(&w));
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (rl < 1 || resp[0] != CTAP2_OK) return rl ? resp[0] : 0xff;

    pqfido_cbor_item_t *m = NULL;
    if (pqfido_cbor_decode(resp + 1, rl - 1, &m) != PQFIDO_OK) return 0xfe;
    const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
    const pqfido_cbor_item_t *att = cbor_map_get_uint(m, 0x03);
    if (ad && pqfido_cbor_is_bytes(ad) && pqfido_cbor_bytes_len(ad) > 55) {
        /* No extensions were asked for, so the COSE_Key runs to the
         * end of authData. */
        const uint8_t *a = pqfido_cbor_bytes(ad);
        size_t adl = pqfido_cbor_bytes_len(ad);
        size_t off = 55 + (((size_t)a[53] << 8) | a[54]);
        pqfido_cbor_item_t *k = NULL;
        if (off < adl
            && pqfido_cbor_decode(a + off, adl - off, &k) == PQFIDO_OK) {
            *cose_alg = cbor_int_val(cbor_map_get_uint(k, 3));
            pqfido_cbor_free(k);
        }
    }
    if (att && pqfido_cbor_is_map(att))
        *att_alg = cbor_int_val(cbor_map_get_text(att, "alg"));
    pqfido_cbor_free(m);
    return CTAP2_OK;
}

/* The composite relabel to draft-ietf-jose-pq-composite-sigs-04.
 *
 * -51/-52/-53 were this firmware's composite ids until RFC 9864 gave
 * them to ESP384 / ESP512 / Ed448, and -48/-49/-50 are the pure ML-DSA
 * ids it emitted before that. None of them may select the hybrid
 * construction now: alone they are refused like any unsupported alg,
 * and in front of ES256 they lose to it. This build's own composite is
 * labelled with its draft -04 id in the COSE_Key and, at 44 and 65, in
 * the attestation statement (87 attests with ES256, the CTAPHID
 * message-size ceiling). */
static void test_old_composite_labels(void)
{
    static const long old_ids[] = { -51, -52, -53, -48, -49, -50 };
    const size_t n_old = sizeof old_ids / sizeof old_ids[0];
    long ca = 0, aa = 0;
    char msgbuf[96];

    printf("-- old composite labels are not picked --\n");
    for (size_t i = 0; i < n_old; i++) {
        long one[1];
        long two[2];
        one[0] = old_ids[i];
        snprintf(msgbuf, sizeof msgbuf,
                 "[%ld] alone -> 0x26 UNSUPPORTED_ALGORITHM", old_ids[i]);
        CHECK(mc_algs(one, 1, &ca, &aa) == CTAP2_ERR_UNSUPPORTED_ALGORITHM,
              msgbuf);
        two[0] = old_ids[i]; two[1] = COSE_ALG_ES256;
        snprintf(msgbuf, sizeof msgbuf,
                 "[%ld, -7] -> an ES256 credential, attested -7", old_ids[i]);
        CHECK(mc_algs(two, 2, &ca, &aa) == CTAP2_OK
              && ca == COSE_ALG_ES256 && aa == COSE_ALG_ES256, msgbuf);
    }
    {
        static const long all3[] = { -51, -52, -53 };
        CHECK(mc_algs(all3, 3, &ca, &aa) == CTAP2_ERR_UNSUPPORTED_ALGORITHM,
              "[-51, -52, -53] -> 0x26 UNSUPPORTED_ALGORITHM");
    }
    {
        long mine[1];
        long want_att = PQF_HYBRID_COSE_ALG;
        mine[0] = PQF_HYBRID_COSE_ALG;
        if (PQF_HYBRID_COSE_ALG == COSE_ALG_MLDSA87_ES384)
            want_att = COSE_ALG_ES256;
        CHECK(PQF_HYBRID_COSE_ALG == -54 || PQF_HYBRID_COSE_ALG == -55
              || PQF_HYBRID_COSE_ALG == -56,
              "this build's composite id is a draft -04 id");
        CHECK(mc_algs(mine, 1, &ca, &aa) == CTAP2_OK
              && ca == PQF_HYBRID_COSE_ALG,
              "own composite mints, COSE_Key alg is PQF_HYBRID_COSE_ALG");
        CHECK(aa == want_att, "own composite attStmt alg as expected");
    }
}


/* ---- Fixes from the 2026-09 defect hunt, each pinned at its boundary.
 *
 * Every one of these was a divergence from the Rust port, and in every
 * case the Rust port was right. The tests drive ctap2_dispatch the way
 * ctaphid.c does, including ctap2_set_cid(), which the transport calls
 * before each CBOR dispatch and which host tests never had to before. */

static bool up_refuse(uint32_t timeout_us) { (void)timeout_us; return false; }

static size_t mc_rk(const char *rp, uint8_t user_byte, uint8_t *msg,
                    size_t cap, uint8_t *cred_id_out)
{
    /* rk=true MakeCredential at `rp` for one-byte user `user_byte`;
     * returns the credentialId length (read from authData -- it is 161
     * bytes in this build, not the 64 the Rust port uses) or 0. */
    uint8_t req[512]; cbor_writer_t w;
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, rp);
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_bytes(&w, &user_byte, 1);
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x07); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "rk"); cbor_w_bool(&w, true);
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, req, cbor_w_off(&w));
    uint8_t resp[2048]; size_t rl = 0;
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    if (resp[0] != CTAP2_OK) return 0;
    /* credentialId sits in authData at 37 + 16 + 2 (aaguid, len). */
    pqfido_cbor_item_t *m = NULL;
    if (pqfido_cbor_decode(resp + 1, rl - 1, &m) != PQFIDO_OK) return 0;
    const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
    size_t got = 0;
    if (ad && pqfido_cbor_is_bytes(ad) && pqfido_cbor_bytes_len(ad) > 55) {
        const uint8_t *a = pqfido_cbor_bytes(ad);
        size_t l = ((size_t)a[53] << 8) | a[54];
        if (l > 0 && l <= 256 && pqfido_cbor_bytes_len(ad) >= 55 + l) {
            memcpy(cred_id_out, a + 55, l); got = l;
        }
    }
    pqfido_cbor_free(m);
    (void)cap;
    return got;
}

static void test_defect_hunt_fixes(void)
{
    uint8_t msg[700], resp[2048]; size_t rl = 0;
    uint8_t req[512]; cbor_writer_t w;
    uint8_t cred_a[256], cred_b[256];

    ctap2_set_cid(0x1111);
    size_t cred_a_len = mc_rk("hard.example", 0xA1, msg, sizeof msg, cred_a);
    size_t cred_b_len = mc_rk("hard.example", 0xB2, msg, sizeof msg, cred_b);
    CHECK(cred_a_len > 0, "hunt: rk credential A minted");
    CHECK(cred_b_len > 0, "hunt: rk credential B minted");

    /* -- excludeList answers only after the gesture (sec. 6.1.2 step 11).
     * With presence refused, a matching excludeList must come back as
     * the presence failure, not as CREDENTIAL_EXCLUDED: otherwise the
     * excludeList is a zero-touch "is this credential yours?" oracle. */
    ctap2_user_presence_hook = up_refuse;
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "hard.example");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u = 0xC3; cbor_w_bytes(&w, &u, 1); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x05); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "id"); cbor_w_bytes(&w, cred_a, cred_a_len);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, req, cbor_w_off(&w));
    size_t excl_len = 1 + cbor_w_off(&w);
    ctap2_dispatch(msg, excl_len, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_OPERATION_DENIED,
          "hunt: excludeList match with NO touch -> 0x27, not 0x19");
    CHECK(resp[0] != CTAP2_ERR_CREDENTIAL_EXCLUDED,
          "hunt: excludeList did not answer before the gesture");
    ctap2_user_presence_hook = NULL;                 /* auto-confirm again */
    ctap2_dispatch(msg, excl_len, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_CREDENTIAL_EXCLUDED,
          "hunt: ...and WITH the touch -> 0x19");

    /* -- GetNextAssertion is bound to the channel that began it. */
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, "hard.example");
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
    msg[0] = CTAP2_CMD_GET_ASSERTION;
    memcpy(msg + 1, req, cbor_w_off(&w));
    size_t ga_len = 1 + cbor_w_off(&w);
    uint8_t gna[1] = { CTAP2_CMD_GET_NEXT_ASSERTION };

    ctap2_set_cid(0x1111);
    ctap2_dispatch(msg, ga_len, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "hunt: GA with two resident creds OK");
    ctap2_set_cid(0x2222);                           /* a different host */
    ctap2_dispatch(gna, 1, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_NOT_ALLOWED,
          "hunt: GetNextAssertion from ANOTHER channel -> 0x30");
    ctap2_set_cid(0x1111);
    ctap2_dispatch(gna, 1, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_NOT_ALLOWED,
          "hunt: ...and the foreign attempt tore the ceremony down");

    ctap2_dispatch(msg, ga_len, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK, "hunt: GA again on channel 0x1111");
    ctap2_dispatch(gna, 1, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_OK,
          "hunt: GetNextAssertion on the SAME channel -> OK");

    /* -- a 64-bit alg must not wrap into ES256. 4294967289 = 2^32 - 7. */
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 4);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "hard.example");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t u = 0xD4; cbor_w_bytes(&w, &u, 1); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_uint(&w, 4294967289ULL);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, req, cbor_w_off(&w));
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_UNSUPPORTED_ALGORITHM,
          "hunt: alg 4294967289 is not ES256 -> 0x26");

    /* -- user (0x03) is required, and user.id is refused rather than
     * clamped. */
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 3);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "hard.example");
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, req, cbor_w_off(&w));
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_MISSING_PARAMETER,
          "hunt: MakeCredential with no user -> 0x14");

    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 4);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "hard.example");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t big[65]; memset(big, 0xEE, 65); cbor_w_bytes(&w, big, 65); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, req, cbor_w_off(&w));
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_MISSING_PARAMETER,
          "hunt: a 65-byte user.id is refused, not truncated to 64");

    /* -- authenticatorReset needs a touch. Without one it must refuse
     * AND leave the store intact: this is the command that empties the
     * device, and it takes no PIN and no token. It used to wipe on
     * request from any software. */
    ctap2_user_presence_hook = up_refuse;
    {
        uint8_t rst[1] = { CTAP2_CMD_RESET };
        ctap2_dispatch(rst, 1, resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_ERR_OPERATION_DENIED,
              "hunt: Reset with NO touch -> 0x27");
        CHECK(resident_store_count() == 2,
              "hunt: ...and the two resident credentials survived it");
    }
    ctap2_user_presence_hook = NULL;

    /* -- options.uv = true the device cannot satisfy. Two answers, and
     * the client acts on the difference: with no PIN there is no UV
     * method at all, so UNSUPPORTED_OPTION (0x2b) says give up; with a
     * PIN the platform should fetch a token, which PUAT_REQUIRED (0x36)
     * says. This port answered INVALID_OPTION (0x2c) for both, telling
     * a platform to give up in the case where it should have prompted.
     * The Rust port has had the split for longer. */
    /* Only the no-PIN arm can run here: this suite has no PIN machinery.
     * The PIN-set arm (-> 0x36 PUAT_REQUIRED) lives in test_pin.c. An
     * earlier version of this block was a one-iteration for-loop whose
     * comment promised both arms; the second hunt caught it. */
    {
        cbor_w_init(&w, req, sizeof req);
        cbor_w_map_header(&w, 5);
        cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
        cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
        cbor_w_text(&w, "id"); cbor_w_text(&w, "hard.example");
        cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
        cbor_w_text(&w, "id"); { uint8_t u = 0xE5; cbor_w_bytes(&w, &u, 1); }
        cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
        cbor_w_map_header(&w, 2);
        cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
        cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
        cbor_w_uint(&w, 0x07); cbor_w_map_header(&w, 1);
        cbor_w_text(&w, "uv"); cbor_w_bool(&w, true);
        msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
        memcpy(msg + 1, req, cbor_w_off(&w));
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_ERR_UNSUPPORTED_OPTION,
              "hunt: uv=true with no PIN set -> 0x2b UNSUPPORTED_OPTION");
        CHECK(resp[0] != CTAP2_ERR_INVALID_OPTION,
              "hunt: ...and not 0x2c, which tells the platform to give up");

        /* Same on GetAssertion. */
        cbor_w_init(&w, req, sizeof req);
        cbor_w_map_header(&w, 3);
        cbor_w_uint(&w, 0x01); cbor_w_text(&w, "hard.example");
        cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
        cbor_w_uint(&w, 0x05); cbor_w_map_header(&w, 1);
        cbor_w_text(&w, "uv"); cbor_w_bool(&w, true);
        msg[0] = CTAP2_CMD_GET_ASSERTION;
        memcpy(msg + 1, req, cbor_w_off(&w));
        ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
        CHECK(resp[0] == CTAP2_ERR_UNSUPPORTED_OPTION,
              "hunt: GetAssertion uv=true with no PIN -> 0x2b");
    }

    /* -- an allowList that is present but not an array is malformed,
     * not absent. Absent would fall into discovery and sign with a
     * resident credential the relying party never named. */
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 3);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, "hard.example");
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x03); cbor_w_text(&w, "x");
    msg[0] = CTAP2_CMD_GET_ASSERTION;
    memcpy(msg + 1, req, cbor_w_off(&w));
    ctap2_dispatch(msg, 1 + cbor_w_off(&w), resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
          "hunt: allowList that is a text string -> 0x11, not discovery");
    CHECK(resp[0] != CTAP2_OK,
          "hunt: ...and it did NOT sign with a resident credential");
}

/* ---- A GetAssertion that fails arms no GetNextAssertion.
 *
 * The iterator used to be armed at discovery -- before the presence
 * gate and before the signature -- with UP copied from the request. A
 * touch that never came answered 0x27 and left it armed, and the
 * dispatcher resets it only for a command that is NOT GetNextAssertion,
 * so the GetNextAssertion that followed on the same channel signed the
 * next credential with UP set although nobody had touched the token.
 * The Rust port had the same shape and is fixed the same way. */

extern int host_core1_fail_next_sign;             /* host_core1_stub.c */

/* authData's flags byte and numberOfCredentials (0 if absent) from an
 * OK GetAssertion / GetNextAssertion response; flags is -1 otherwise. */
static void assertion_facts(const uint8_t *resp, size_t rl,
                            int *flags, unsigned *ncred)
{
    *flags = -1;
    *ncred = 0;
    if (rl < 2 || resp[0] != CTAP2_OK) return;
    pqfido_cbor_item_t *m = NULL;
    if (pqfido_cbor_decode(resp + 1, rl - 1, &m) != PQFIDO_OK) return;
    const pqfido_cbor_item_t *ad = cbor_map_get_uint(m, 0x02);
    const pqfido_cbor_item_t *nc = cbor_map_get_uint(m, 0x05);
    if (ad && pqfido_cbor_is_bytes(ad) && pqfido_cbor_bytes_len(ad) >= 37)
        *flags = pqfido_cbor_bytes(ad)[32];
    if (nc && pqfido_cbor_is_uint(nc))
        *ncred = (unsigned)pqfido_cbor_uint(nc);
    pqfido_cbor_free(m);
}

static void test_failed_assertion_arms_no_continuation(void)
{
    uint8_t msg[700], resp[2048], cred[256]; size_t rl = 0;
    uint8_t ga[128], silent[128]; cbor_writer_t w;
    uint8_t gna[1] = { CTAP2_CMD_GET_NEXT_ASSERTION };
    int flags; unsigned ncred;

    ctap2_set_cid(0x3333);
    CHECK(mc_rk("cont.example", 0x01, msg, sizeof msg, cred) > 0
          && mc_rk("cont.example", 0x02, msg, sizeof msg, cred) > 0,
          "cont: two rk credentials minted");

    /* No allowList, so both are discovered; `silent` adds up=false. */
    cbor_w_init(&w, ga + 1, sizeof ga - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, "cont.example");
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
    ga[0] = CTAP2_CMD_GET_ASSERTION;
    size_t ga_len = 1 + cbor_w_off(&w);
    cbor_w_init(&w, silent + 1, sizeof silent - 1);
    cbor_w_map_header(&w, 3);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, "cont.example");
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x05); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "up"); cbor_w_bool(&w, false);
    silent[0] = CTAP2_CMD_GET_ASSERTION;
    size_t silent_len = 1 + cbor_w_off(&w);

    /* No touch: refused, and nothing may continue from it. */
    ctap2_user_presence_hook = up_refuse;
    ctap2_dispatch(ga, ga_len, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_OPERATION_DENIED,
          "cont: GA with NO touch -> 0x27");
    ctap2_user_presence_hook = NULL;
    ctap2_dispatch(gna, 1, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_NOT_ALLOWED,
          "cont: ...then GetNextAssertion -> 0x30, not a signature with UP");

    /* A sign that fails: the same. */
    host_core1_fail_next_sign = 1;
    ctap2_dispatch(ga, ga_len, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_OTHER, "cont: GA whose sign fails -> 0x7f");
    ctap2_dispatch(gna, 1, resp, sizeof resp, &rl);
    CHECK(resp[0] == CTAP2_ERR_NOT_ALLOWED,
          "cont: ...then GetNextAssertion -> 0x30");

    /* The accept half: a confirmed GA counts both and continues with UP. */
    ctap2_dispatch(ga, ga_len, resp, sizeof resp, &rl);
    assertion_facts(resp, rl, &flags, &ncred);
    CHECK(flags >= 0 && (flags & 0x01) && ncred == 2,
          "cont: confirmed GA -> OK, UP set, numberOfCredentials 2");
    ctap2_dispatch(gna, 1, resp, sizeof resp, &rl);
    assertion_facts(resp, rl, &flags, &ncred);
    CHECK(flags >= 0 && (flags & 0x01) && ncred == 0,
          "cont: ...and its GetNextAssertion signs with UP set");

    /* up=false: the gate never runs, so neither assertion may report
     * presence -- with a host that would have refused, had it been
     * asked. */
    ctap2_user_presence_hook = up_refuse;
    ctap2_dispatch(silent, silent_len, resp, sizeof resp, &rl);
    assertion_facts(resp, rl, &flags, &ncred);
    CHECK(flags >= 0 && !(flags & 0x01) && ncred == 2,
          "cont: silent GA -> OK with UP clear, no touch asked for");
    ctap2_dispatch(gna, 1, resp, sizeof resp, &rl);
    assertion_facts(resp, rl, &flags, &ncred);
    CHECK(flags >= 0 && !(flags & 0x01),
          "cont: ...and its GetNextAssertion has UP clear too");
    ctap2_user_presence_hook = NULL;
}

int main(void)
{
    printf("CTAP2 host end-to-end test\n");
    ctap2_init();

    test_getinfo_algorithms();
    test_old_composite_labels();
    test_defect_hunt_fixes();
    test_failed_assertion_arms_no_continuation();

    /* ---- 1. Build MakeCredential request ---- */
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
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    CHECK(cbor_w_ok(&w), "build MakeCredential request");

    uint8_t msg[600];
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, req, cbor_w_off(&w));
    size_t msg_len = 1 + cbor_w_off(&w);

    uint8_t resp[2048]; size_t resp_len = 0;
    ctap2_dispatch(msg, msg_len, resp, sizeof resp, &resp_len);
    CHECK(resp_len > 1 && resp[0] == CTAP2_OK, "MakeCredential status OK");

    /* ---- 2/3. Parse response, extract authData + sig ---- */
    uint8_t cred_id[256]; size_t cred_id_len = 0;
    uint8_t pub_x[32], pub_y[32];
    uint8_t mc_authdata[512]; size_t mc_ad_len = 0;
    uint8_t mc_sig[80]; size_t mc_sig_len = 0;
    {
        pqfido_cbor_item_t *m = NULL;
        int dr = pqfido_cbor_decode(resp + 1, resp_len - 1, &m);
        CHECK(dr == PQFIDO_OK && pqfido_cbor_is_map(m), "MakeCredential response is a map");

        /* key 2 = authData, key 3 = attStmt */
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
            memcpy(mc_authdata, pqfido_cbor_bytes(ad), mc_ad_len);
            /* authData: rpIdHash(32) flags(1) signCount(4) aaguid(16)
             * credIdLen(2) credId(L) COSE_Key(rest) */
            const uint8_t *a = mc_authdata;
            uint16_t cidl = (a[53] << 8) | a[54];
            cred_id_len = cidl;
            memcpy(cred_id, a + 55, cidl);
            size_t cose_off = 55 + cidl;
            CHECK(cose_pub(a + cose_off, mc_ad_len - cose_off, pub_x, pub_y) == 0,
                  "extract COSE public key from authData");
        }
        /* attStmt sig (key "sig") */
        if (att && pqfido_cbor_is_map(att)) {
            size_t an = pqfido_cbor_map_size(att);
            const pqfido_cbor_pair_t *ap = pqfido_cbor_map_pairs(att);
            for (size_t i = 0; i < an; i++) {
                if (pqfido_cbor_is_string(ap[i].key)
                    && pqfido_cbor_string_len(ap[i].key) == 3
                    && memcmp(pqfido_cbor_string(ap[i].key), "sig", 3) == 0
                    && pqfido_cbor_is_bytes(ap[i].value)) {
                    mc_sig_len = pqfido_cbor_bytes_len(ap[i].value);
                    memcpy(mc_sig, pqfido_cbor_bytes(ap[i].value), mc_sig_len);
                }
            }
        }
        pqfido_cbor_free(m);
    }
    CHECK(cred_id_len == 161, "credentialId is 161 bytes");

    /* ---- 4. Verify the self-attestation signature ---- */
    {
        uint8_t h[32];
        pqf_sha256_ctx_t sc; pqf_sha256_init(&sc);
        pqf_sha256_update(&sc, mc_authdata, mc_ad_len);
        pqf_sha256_update(&sc, CDH, 32);
        pqf_sha256_final(&sc, h);
        int v = pqf_ecdsa_p256_verify(pub_x, pub_y, h, mc_sig, mc_sig_len);
        CHECK(v == 1, "packed self-attestation signature verifies");
    }

    /* ---- 5. GetAssertion with the new credential ---- */
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

    /* ---- 6. Verify the assertion signature ---- */
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
            uint8_t h[32];
            pqf_sha256_ctx_t sc; pqf_sha256_init(&sc);
            pqf_sha256_update(&sc, pqfido_cbor_bytes(ad), pqfido_cbor_bytes_len(ad));
            pqf_sha256_update(&sc, CDH, 32);
            pqf_sha256_final(&sc, h);
            int v = pqf_ecdsa_p256_verify(pub_x, pub_y, h,
                                          pqfido_cbor_bytes(sig),
                                          pqfido_cbor_bytes_len(sig));
            CHECK(v == 1, "assertion signature verifies");
        }
        pqfido_cbor_free(m);
    }

    /* ---- 7. Negative: GetAssertion at the WRONG rp must fail ---- */
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 3);
    cbor_w_uint(&w, 0x01); cbor_w_text(&w, "evil.example");
    cbor_w_uint(&w, 0x02); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x03);
    cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "id");   cbor_w_bytes(&w, cred_id, cred_id_len);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    msg[0] = CTAP2_CMD_GET_ASSERTION;
    memcpy(msg + 1, req, cbor_w_off(&w));
    msg_len = 1 + cbor_w_off(&w);
    ctap2_dispatch(msg, msg_len, resp, sizeof resp, &resp_len);
    CHECK(resp[0] == CTAP2_ERR_NO_CREDENTIALS,
          "credential rejected at a different RP");

    /* ---- excludeList (M4/F1): a MakeCredential listing an existing
     * credential for this RP must be refused with CREDENTIAL_EXCLUDED. */
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t uid[4] = {1,2,3,4}; cbor_w_bytes(&w, uid, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x05);                                     /* excludeList */
    cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "id");   cbor_w_bytes(&w, cred_id, cred_id_len);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, req, cbor_w_off(&w));
    msg_len = 1 + cbor_w_off(&w);
    ctap2_dispatch(msg, msg_len, resp, sizeof resp, &resp_len);
    CHECK(resp[0] == CTAP2_ERR_CREDENTIAL_EXCLUDED,
          "excludeList match rejected (0x19)");

    /* A credentialID that this device didn't mint must NOT block it. */
    cbor_w_init(&w, req, sizeof req);
    cbor_w_map_header(&w, 5);
    cbor_w_uint(&w, 0x01); cbor_w_bytes(&w, CDH, 32);
    cbor_w_uint(&w, 0x02); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text(&w, "example.com");
    cbor_w_uint(&w, 0x03); cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); { uint8_t uid[4] = {1,2,3,4}; cbor_w_bytes(&w, uid, 4); }
    cbor_w_uint(&w, 0x04); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg"); cbor_w_int(&w, -7);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x05); cbor_w_array_header(&w, 1);
    cbor_w_map_header(&w, 2);
    { uint8_t bogus[161]; memset(bogus, 0xAB, sizeof bogus);
      cbor_w_text(&w, "id"); cbor_w_bytes(&w, bogus, sizeof bogus); }
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    msg[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    memcpy(msg + 1, req, cbor_w_off(&w));
    msg_len = 1 + cbor_w_off(&w);
    ctap2_dispatch(msg, msg_len, resp, sizeof resp, &resp_len);
    CHECK(resp[0] == CTAP2_OK,
          "foreign credentialId in excludeList does not block registration");

    /* ---- CBOR decoder hardening regressions (X7 / X9) ---- */
    {
        pqfido_cbor_item_t *it = NULL;

        /* Major-7 floats (ai 25 half, 26 single, 27 double) must be
         * rejected, not decoded into an opaque SIMPLE integer. */
        const uint8_t f16[] = { 0xf9, 0x3c, 0x00 };          /* 1.0 half  */
        CHECK(pqfido_cbor_decode(f16, sizeof f16, &it) != PQFIDO_OK,
              "CBOR half-float (0xf9) rejected");
        pqfido_cbor_free(it); it = NULL;
        const uint8_t f32[] = { 0xfa, 0x3f, 0x80, 0x00, 0x00 };
        CHECK(pqfido_cbor_decode(f32, sizeof f32, &it) != PQFIDO_OK,
              "CBOR single-float (0xfa) rejected");
        pqfido_cbor_free(it); it = NULL;
        const uint8_t f64[] = { 0xfb, 0,0,0,0,0,0,0,0 };
        CHECK(pqfido_cbor_decode(f64, sizeof f64, &it) != PQFIDO_OK,
              "CBOR double-float (0xfb) rejected");
        pqfido_cbor_free(it); it = NULL;

        /* Genuine simple values (false/true/null) still decode. */
        const uint8_t strue[] = { 0xf5 };
        CHECK(pqfido_cbor_decode(strue, sizeof strue, &it) == PQFIDO_OK,
              "CBOR simple value true (0xf5) still accepted");
        pqfido_cbor_free(it); it = NULL;

        /* An array/map count larger than the remaining bytes can hold
         * is rejected by both the tree decoder and the length scanner
         * (the scanner gained the pre-bound check). 0x98 0xff = array
         * of 255 items with no elements following. */
        const uint8_t bigarr[] = { 0x98, 0xff };
        size_t scanned = 0;
        CHECK(pqfido_cbor_decode(bigarr, sizeof bigarr, &it) != PQFIDO_OK,
              "CBOR over-long array count rejected (decode)");
        pqfido_cbor_free(it); it = NULL;
        CHECK(pqfido_cbor_item_length(bigarr, sizeof bigarr, &scanned) != PQFIDO_OK,
              "CBOR over-long array count rejected (length scan)");
    }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
