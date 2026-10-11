/* test_hybrid.c -- host-side test of the hybrid ECDSA+ML-DSA signer.
 *
 * Derives a hybrid key pair from (ecdsaScalar, mldsaSeed), signs a
 * message, and verifies -- checking the concatenated ecdsaDER||mldsaSig
 * round-trips and that tampering either the message or either half
 * is rejected.
 *
 * Also pins the ML-DSA half of the public key for a fixed seed to a
 * known-answer vector, so the hybrid layer can't quietly mangle the
 * seed on its way into ML-DSA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "hybrid.h"
#include "pqf_crypto.h"
#include "openssl/rand.h"

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("  ok: %s\n", m); \
    else { fprintf(stderr, "FAIL: %s\n", m); fails++; } } while (0)

/* sha256() of the ML-DSA public key BouncyCastle derives from the seed
 * 000102..1f -- the RFC 9881 keygen vector. The full expected bytes for
 * the same seed are in openssl-mini/test/test_mldsa.c; only the digest
 * is repeated here to keep this file small. The signature half can't be
 * pinned: the ECDSA nonce is hedged-random, and the ML-DSA half signs
 * over the resulting DER. */
#if   PQF_HYBRID_VARIANT == 44
#define KAT_MLDSA_PK_SHA256 \
    "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46"
#elif PQF_HYBRID_VARIANT == 65
#define KAT_MLDSA_PK_SHA256 \
    "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9"
#else
#define KAT_MLDSA_PK_SHA256 \
    "91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd"
#endif

static void test_seed_kat(void)
{
    uint8_t seed[32], scalar[32];
    for (int i = 0; i < 32; i++) {
        seed[i] = (uint8_t)i;
        scalar[i] = 0x11;
    }

    uint8_t ec_x[32], ec_y[32];
    uint8_t pub[PQF_HYBRID_PK_LEN]; size_t pub_len = 0;
    CHECK(hybrid_public(scalar, seed, ec_x, ec_y, pub, &pub_len) == 0,
          "KAT: derive hybrid public key from a fixed seed");

    uint8_t dg[32], want[32];
    pqf_sha256(pub, pub_len, dg);
    for (int i = 0; i < 32; i++) {
        unsigned v; sscanf(KAT_MLDSA_PK_SHA256 + 2 * i, "%2x", &v);
        want[i] = (uint8_t)v;
    }
    CHECK(pub_len == PQF_HYBRID_PK_LEN && memcmp(dg, want, 32) == 0,
          "KAT: ML-DSA public key half matches the BouncyCastle vector");
}

int main(void)
{
    printf("hybrid ECDSA+ML-DSA host test (variant ML-DSA-%d, COSE %d)\n",
           PQF_HYBRID_VARIANT, PQF_HYBRID_COSE_ALG);

    test_seed_kat();

    uint8_t ec_scalar[32], mldsa_seed[32];
    RAND_bytes(ec_scalar, 32);
    RAND_bytes(mldsa_seed, 32);

    uint8_t ec_x[32], ec_y[32];
    uint8_t mldsa_pub[2600]; size_t mldsa_pub_len = 0;
    CHECK(hybrid_public(ec_scalar, mldsa_seed, ec_x, ec_y,
                        mldsa_pub, &mldsa_pub_len) == 0, "derive hybrid public");
    CHECK(mldsa_pub_len == PQF_HYBRID_PK_LEN, "ML-DSA public key length");

    /* A representative FIDO signed-data blob (authData || cdh). */
    uint8_t msg[101];
    for (size_t i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 5 + 1);

    uint8_t sig[PQF_HYBRID_MAX_SIG]; size_t sig_len = 0;
    CHECK(hybrid_sign(ec_scalar, mldsa_seed, msg, sizeof msg,
                      sig, &sig_len) == 0, "hybrid sign");
    /* DER ECDSA prefix is 70-72 bytes; total ~ that + ML-DSA sig. */
    CHECK(sig_len > PQF_HYBRID_SIG_LEN && sig_len <= PQF_HYBRID_MAX_SIG,
          "hybrid signature length sane");

    CHECK(hybrid_verify(ec_x, ec_y, mldsa_pub, mldsa_pub_len,
                        msg, sizeof msg, sig, sig_len) == 1,
          "hybrid verify accepts");

    /* A second, independent signature must also verify. (Unlike the
     * ML-DSA half, the ECDSA half uses a hedged-random nonce -- more
     * side-channel resistant than RFC 6979 -- so two signatures over
     * the same message differ in their ECDSA prefix yet both verify.
     * Verification, not byte-equality, is the interop requirement.) */
    uint8_t sig2[PQF_HYBRID_MAX_SIG]; size_t sig2_len = 0;
    hybrid_sign(ec_scalar, mldsa_seed, msg, sizeof msg, sig2, &sig2_len);
    CHECK(hybrid_verify(ec_x, ec_y, mldsa_pub, mldsa_pub_len,
                        msg, sizeof msg, sig2, sig2_len) == 1,
          "a second independent hybrid signature also verifies");

    /* Tamper message -> reject. */
    uint8_t bad[101]; memcpy(bad, msg, sizeof msg); bad[0] ^= 1;
    CHECK(hybrid_verify(ec_x, ec_y, mldsa_pub, mldsa_pub_len,
                        bad, sizeof bad, sig, sig_len) == 0,
          "hybrid verify rejects altered message");

    /* Tamper ML-DSA half -> reject. */
    uint8_t t1[PQF_HYBRID_MAX_SIG]; memcpy(t1, sig, sig_len);
    t1[sig_len - 1] ^= 0x80;
    CHECK(hybrid_verify(ec_x, ec_y, mldsa_pub, mldsa_pub_len,
                        msg, sizeof msg, t1, sig_len) == 0,
          "hybrid verify rejects altered ML-DSA half");

    /* Tamper ECDSA half (a byte inside the DER prefix) -> reject. */
    uint8_t t2[PQF_HYBRID_MAX_SIG]; memcpy(t2, sig, sig_len);
    t2[10] ^= 0x40;
    CHECK(hybrid_verify(ec_x, ec_y, mldsa_pub, mldsa_pub_len,
                        msg, sizeof msg, t2, sig_len) == 0,
          "hybrid verify rejects altered ECDSA half");

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
