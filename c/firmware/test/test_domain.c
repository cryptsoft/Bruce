/* test_domain.c -- host-side test of finding X11 (HMAC domain
 * separation) in the credential layer.
 *
 * Covers, per the X11 spec sec. Tests (C):
 *   - encrypt -> decrypt round-trip recovers the credential_source_t for
 *     BOTH ES256 and hybrid, including the cred_protect + large_blob_key
 *     fields and the recovered alg.
 *   - domain distinctness: for a fixed (masterMacKey, credentialID) the
 *     integrity tag, cred_random(uv=0), cred_random(uv=1), and
 *     largeBlobKey are all pairwise distinct -- the three HMAC
 *     derivations keyed on the single master MAC key cannot collide.
 *   - flipping any single byte of the blob => credential_recover fails
 *     the integrity check (the domain-prefixed tag stays symmetric
 *     across seal/verify, so an untampered blob still verifies).
 *   - the rp_id_hash binding rejects a cross-RP credentialID.
 *
 * The integrity tag is internal to the credential layer, so the test
 * recomputes it the same way credential.c does (DOMAIN_CRED_ID ||
 * version || IV || ciphertext over bytes [0 .. TAG_OFF)) using the
 * master MAC key exposed for host tests via flash_store_keys().
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "credential.h"
#include "hybrid.h"
#include "flash_store.h"
#include "pqf_crypto.h"

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("  ok: %s\n", m); \
    else { fprintf(stderr, "FAIL: %s\n", m); fails++; } } while (0)

/* Must match the TAG_OFF / DOMAIN_CRED_ID in credential.c. */
#define TAG_OFF 129
#define DOMAIN_CRED_ID "pqf-cred-id"

/* Recompute the credentialID integrity tag the way credential.c does:
 * HMAC(macKey, "pqf-cred-id" || cred_id[0 .. TAG_OFF)). */
static void integrity_tag(const uint8_t mac_key[32],
                          const uint8_t *cred_id, uint8_t out[32])
{
    static const char domain[] = DOMAIN_CRED_ID;
    pqf_hmac_sha256_ctx_t hc;
    pqf_hmac_sha256_init(&hc, mac_key, 32);
    pqf_hmac_sha256_update(&hc, (const uint8_t *)domain, sizeof domain - 1);
    pqf_hmac_sha256_update(&hc, cred_id, TAG_OFF);
    pqf_hmac_sha256_final(&hc, out);
}

static int differ(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) != 0;
}

/* Round-trip an alg through make -> recover, asserting all fields. */
static void roundtrip(int alg, uint8_t cred_protect, bool large_blob_key,
                      const char *label)
{
    uint8_t rp[32];
    for (int i = 0; i < 32; i++) rp[i] = (uint8_t)(0xA0 ^ (i * 7));

    uint8_t cred_id[CRED_ID_LEN];
    credential_source_t made;
    uint8_t mk_x[32], mk_y[32];
    CHECK(credential_make(rp, alg, cred_protect, large_blob_key,
                          cred_id, &made, mk_x, mk_y) == 0, label);

    credential_source_t rec;
    CHECK(credential_recover(cred_id, sizeof cred_id, rp, &rec) == 0,
          "  recover succeeds");
    CHECK(rec.alg == alg, "  recovered alg matches");
    CHECK(!differ(rec.ecdsa_scalar, made.ecdsa_scalar, 32),
          "  recovered ecdsa scalar matches");
    CHECK(!differ(rec.mldsa_seed, made.mldsa_seed, 32),
          "  recovered mldsa seed matches");
    CHECK(rec.cred_protect == cred_protect, "  recovered cred_protect matches");
    CHECK(rec.large_blob_key == large_blob_key,
          "  recovered large_blob_key flag matches");

    /* Cross-RP credentialID must be rejected by the binding check. */
    uint8_t other_rp[32];
    memcpy(other_rp, rp, 32);
    other_rp[0] ^= 0x01;
    credential_source_t bad;
    CHECK(credential_recover(cred_id, sizeof cred_id, other_rp, &bad) != 0,
          "  cross-RP credentialID rejected");

    /* Flipping any single byte of the blob breaks the integrity tag. */
    int tamper_ok = 1;
    for (size_t i = 0; i < CRED_ID_LEN; i++) {
        uint8_t t[CRED_ID_LEN];
        memcpy(t, cred_id, CRED_ID_LEN);
        t[i] ^= 0x01;
        credential_source_t junk;
        if (credential_recover(t, sizeof t, rp, &junk) == 0)
            tamper_ok = 0;   /* a tampered blob must never verify */
    }
    CHECK(tamper_ok, "  every single-byte flip is rejected");
}

int main(void)
{
    printf("X11 HMAC domain-separation host test\n");

    flash_store_init();   /* seed the host master keys */
    credential_init();    /* loads s_aes_key / s_mac_key from the store */

    /* (a) round-trips: ES256 and hybrid, exercising cred_protect +
     *     large_blob_key. */
    roundtrip(COSE_ALG_ES256, 1, false, "ES256 round-trip (cp=1, lbk=0)");
    roundtrip(COSE_ALG_ES256, 3, true,  "ES256 round-trip (cp=3, lbk=1)");
    roundtrip(PQF_HYBRID_COSE_ALG, 2, false,
              "hybrid round-trip (cp=2, lbk=0)");
    roundtrip(PQF_HYBRID_COSE_ALG, 3, true,
              "hybrid round-trip (cp=3, lbk=1)");

    /* (b) domain distinctness. Fix a single (macKey, credentialID) and
     *     show the four master-MAC-keyed derivations are pairwise
     *     distinct: integrity tag, cred_random(uv=0), cred_random(uv=1),
     *     largeBlobKey. */
    uint8_t rp[32];
    for (int i = 0; i < 32; i++) rp[i] = (uint8_t)(i + 1);
    uint8_t cred_id[CRED_ID_LEN];
    credential_source_t src;
    uint8_t mk_x[32], mk_y[32];
    CHECK(credential_make(rp, PQF_HYBRID_COSE_ALG, 1, true,
                          cred_id, &src, mk_x, mk_y) == 0,
          "mint credential for distinctness check");

    uint8_t aes_key[32], mac_key[32];
    flash_store_keys(aes_key, mac_key);   /* same master key the layer uses */

    uint8_t tag[32], cr0[32], cr1[32], lbk[32];
    integrity_tag(mac_key, cred_id, tag);
    credential_cred_random(cred_id, sizeof cred_id, false, cr0);
    credential_cred_random(cred_id, sizeof cred_id, true,  cr1);
    credential_large_blob_key(cred_id, sizeof cred_id, lbk);

    CHECK(differ(tag, cr0, 32), "integrity tag != cred_random(uv=0)");
    CHECK(differ(tag, cr1, 32), "integrity tag != cred_random(uv=1)");
    CHECK(differ(tag, lbk, 32), "integrity tag != largeBlobKey");
    CHECK(differ(cr0, cr1, 32), "cred_random(uv=0) != cred_random(uv=1)");
    CHECK(differ(cr0, lbk, 32), "cred_random(uv=0) != largeBlobKey");
    CHECK(differ(cr1, lbk, 32), "cred_random(uv=1) != largeBlobKey");

    /* The recomputed integrity tag must equal the one stored in the
     * credentialID -- confirms the test mirrors the layer's derivation
     * (and that the domain prefix is applied as specified). */
    CHECK(!differ(tag, cred_id + TAG_OFF, 32),
          "recomputed domain-prefixed tag matches stored tag");

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
