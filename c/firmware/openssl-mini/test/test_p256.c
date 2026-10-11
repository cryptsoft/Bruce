/* test_p256.c -- host-side tests for pqf P-256 ECDSA + ECDH.
 *
 * Mixes a NIST known-answer vector (FIPS 186-4 ECDSA P-256/SHA-256,
 * from the CAVP "SigVer" set -- a fixed key + message + signature
 * that MUST verify) with round-trip self-consistency tests:
 *
 *   1. KAT verify -- a canonical (Qx,Qy,hash,r,s) that must verify.
 *   2. KAT negative -- flip one hash byte; the same sig must NOT
 *      verify.
 *   3. keygen -> sign -> verify round-trip.
 *   4. cross-key -- a signature from key A must not verify under
 *      key B.
 *   5. ECDH -- two fresh keypairs agree on the same shared X
 *      (g^ab == g^ba).
 *
 * Copyright 2026 Cryptsoft Pty Ltd
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "pqf_crypto.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok: %s\n", msg); } \
    else { fprintf(stderr, "FAIL: %s\n", msg); fails++; } \
} while (0)

static void from_hex(const char *h, uint8_t *o, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v; sscanf(h + 2 * i, "%2x", &v); o[i] = (uint8_t)v;
    }
}

/* Build a DER SEQUENCE{INTEGER r, INTEGER s} from raw 32-byte r,s so
 * we can feed the KAT signature to the verifier (which takes DER).
 * Mirrors the encoder in pqf_ecdsa_sig.c; kept independent here so
 * the test doesn't lean on the code under test for its input. */
static size_t der_int(uint8_t *out, const uint8_t v[32])
{
    int lead = 0;
    while (lead < 31 && v[lead] == 0) lead++;      /* strip leading 0s */
    const uint8_t *mag = v + lead;
    int mlen = 32 - lead;
    int pad = (mag[0] & 0x80) ? 1 : 0;
    size_t i = 0;
    out[i++] = 0x02;
    out[i++] = (uint8_t)(mlen + pad);
    if (pad) out[i++] = 0x00;
    memcpy(out + i, mag, mlen);
    return i + mlen;
}
static size_t der_sig(uint8_t *out, const uint8_t r[32], const uint8_t s[32])
{
    uint8_t body[160];
    size_t bl = der_int(body, r);
    size_t bs = der_int(body + bl, s);
    size_t total = bl + bs;
    size_t i = 0;
    out[i++] = 0x30;
    out[i++] = (uint8_t)total;
    memcpy(out + i, body, total);
    return i + total;
}

int main(void)
{
    printf("pqf P-256 host tests\n");

    /* ---- 1. NIST CAVP KAT (FIPS 186-4, P-256, SHA-256) ---- *
     * One vector from the NIST ECDSA FIPS 186-4 SigVer set whose
     * expected result is "pass". Qx/Qy = public key, the 32-byte
     * SHA-256 message digest, and r/s the signature. */
    {
        uint8_t qx[32], qy[32], h[32], r[32], s[32], der[80];
        from_hex("e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c", qx, 32);
        from_hex("970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927", qy, 32);
        from_hex("d1b8ef21eb4182ee270638061063a3f3c16c114e33937f69fb232cc833965a94", h, 32);
        from_hex("bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f", r, 32);
        from_hex("17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c", s, 32);
        size_t dl = der_sig(der, r, s);
        int v = pqf_ecdsa_p256_verify(qx, qy, h, der, dl);
        CHECK(v == 1, "CAVP KAT signature verifies");

        /* 2. Flip a digest byte -> must fail. */
        uint8_t h2[32]; memcpy(h2, h, 32); h2[0] ^= 0x01;
        int v2 = pqf_ecdsa_p256_verify(qx, qy, h2, der, dl);
        CHECK(v2 == 0, "CAVP KAT rejects altered digest");
    }

    /* ---- 3. keygen -> sign -> verify round-trip ---- */
    uint8_t priv[32], px[32], py[32];
    CHECK(pqf_p256_keygen(priv, px, py) == 0, "keygen");
    {
        uint8_t hash[32];
        for (int i = 0; i < 32; i++) hash[i] = (uint8_t)(i * 7 + 1);
        uint8_t sig[80]; size_t sl = 0;
        CHECK(pqf_ecdsa_p256_sign(priv, hash, sig, &sl) == 0, "sign");
        CHECK(sl > 8 && sl <= PQF_P256_MAX_SIG_DER, "sig DER length sane");
        CHECK(pqf_ecdsa_p256_verify(px, py, hash, sig, sl) == 1,
              "self sign/verify round-trip");

        /* 4. cross-key: a different key must not verify this sig. */
        uint8_t p2[32], x2[32], y2[32];
        pqf_p256_keygen(p2, x2, y2);
        CHECK(pqf_ecdsa_p256_verify(x2, y2, hash, sig, sl) == 0,
              "cross-key signature rejected");

        /* derive_public must reproduce the keygen public point. */
        uint8_t dx[32], dy[32];
        CHECK(pqf_p256_derive_public(priv, dx, dy) == 0, "derive_public");
        CHECK(memcmp(dx, px, 32) == 0 && memcmp(dy, py, 32) == 0,
              "derived public matches keygen");
    }

    /* ---- 5. ECDH agreement ---- */
    {
        uint8_t a[32], ax[32], ay[32];
        uint8_t b[32], bx[32], by[32];
        CHECK(pqf_p256_keygen(a, ax, ay) == 0, "ECDH keygen A");
        CHECK(pqf_p256_keygen(b, bx, by) == 0, "ECDH keygen B");
        uint8_t sab[32], sba[32];
        CHECK(pqf_ecdh_p256(a, bx, by, sab) == 0, "ECDH a*B");
        CHECK(pqf_ecdh_p256(b, ax, ay, sba) == 0, "ECDH b*A");
        CHECK(memcmp(sab, sba, 32) == 0, "ECDH shared secrets agree");
    }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
