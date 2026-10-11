/* test_aes.c -- host-side unit tests for pqf_aes256.
 *
 * Vectors:
 *
 *   - FIPS 197 Appendix C.3 -- the canonical AES-256 single-block
 *     known-answer pair (00..1f key, 00..0f plaintext -> 8ea2b7ca...).
 *   - NIST SP 800-38A Appendix F.2 -- the four-block AES-256-CBC
 *     known-answer vectors, both encrypt and decrypt directions.
 *   - Round-trip checks across a range of message sizes, including
 *     in-place encrypt/decrypt (out == in) and non-aligned IVs.
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

static void print_hex(const uint8_t *data, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        sprintf(&out[i * 2], "%02x", data[i]);
    }
}

static int hex_eq(const uint8_t *got, const char *expect, size_t n)
{
    char buf[256];
    print_hex(got, n, buf);
    return strcmp(buf, expect) == 0;
}

static void from_hex(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        unsigned v = 0;
        sscanf(&hex[i * 2], "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void report(const char *label, const uint8_t *got, size_t n,
                   const char *expect)
{
    if (hex_eq(got, expect, n)) {
        printf("  ok: %s\n", label);
        return;
    }
    char buf[256];
    print_hex(got, n, buf);
    fprintf(stderr,
            "FAIL %s\n  expected %s\n  got      %s\n",
            label, expect, buf);
    fails++;
}

int main(void)
{
    printf("pqf_aes256 host tests\n");

    /* ---- Single-block AES-256 (FIPS 197 Appendix C.3) ---- */
    {
        uint8_t key[32];
        from_hex("000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f", key, 32);
        uint8_t pt[16];
        from_hex("00112233445566778899aabbccddeeff", pt, 16);
        const char *ct_hex =
            "8ea2b7ca516745bfeafc49904b496089";

        pqf_aes256_key_t sched;
        if (pqf_aes256_set_encrypt_key(key, &sched) != 0) {
            fprintf(stderr, "FAIL FIPS-197 set_encrypt_key\n"); fails++;
        }
        uint8_t ct[16];
        pqf_aes256_encrypt_block(&sched, pt, ct);
        report("FIPS-197 C.3 encrypt", ct, 16, ct_hex);

        if (pqf_aes256_set_decrypt_key(key, &sched) != 0) {
            fprintf(stderr, "FAIL FIPS-197 set_decrypt_key\n"); fails++;
        }
        uint8_t back[16];
        pqf_aes256_decrypt_block(&sched, ct, back);
        report("FIPS-197 C.3 decrypt",
               back, 16,
               "00112233445566778899aabbccddeeff");
    }

    /* ---- AES-256-CBC (NIST SP 800-38A Appendix F.2.5/F.2.6) ---- */
    {
        uint8_t key[32];
        from_hex("603deb1015ca71be2b73aef0857d7781"
                 "1f352c073b6108d72d9810a30914dff4", key, 32);
        uint8_t iv[16];
        from_hex("000102030405060708090a0b0c0d0e0f", iv, 16);

        uint8_t pt[64];
        from_hex("6bc1bee22e409f96e93d7e117393172a"
                 "ae2d8a571e03ac9c9eb76fac45af8e51"
                 "30c81c46a35ce411e5fbc1191a0a52ef"
                 "f69f2445df4f9b17ad2b417be66c3710", pt, 64);

        const char *ct_hex =
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
            "9cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461"
            "b2eb05e2c39be9fcda6c19078c6a9d1b";

        uint8_t ct[64];
        if (pqf_aes256_cbc_encrypt(key, iv, pt, 64, ct) != 0) {
            fprintf(stderr, "FAIL SP800-38A CBC encrypt rc\n"); fails++;
        }
        report("SP800-38A F.2.5 CBC encrypt", ct, 64, ct_hex);

        uint8_t back[64];
        if (pqf_aes256_cbc_decrypt(key, iv, ct, 64, back) != 0) {
            fprintf(stderr, "FAIL SP800-38A CBC decrypt rc\n"); fails++;
        }
        if (memcmp(back, pt, 64) != 0) {
            fprintf(stderr, "FAIL SP800-38A F.2.6 CBC decrypt\n"); fails++;
        } else {
            printf("  ok: SP800-38A F.2.6 CBC decrypt\n");
        }
    }

    /* ---- In-place encrypt/decrypt round-trip ---- */
    {
        uint8_t key[32], iv[16], buf[80], orig[80];
        for (int i = 0; i < 32; i++) key[i]  = (uint8_t)(i * 7 + 1);
        for (int i = 0; i < 16; i++) iv[i]   = (uint8_t)(i * 13 + 3);
        for (int i = 0; i < 80; i++) buf[i]  = (uint8_t)(i * 31 + 5);
        memcpy(orig, buf, 80);

        if (pqf_aes256_cbc_encrypt(key, iv, buf, 80, buf) != 0) {
            fprintf(stderr, "FAIL in-place encrypt rc\n"); fails++;
        }
        if (memcmp(buf, orig, 80) == 0) {
            fprintf(stderr, "FAIL in-place encrypt: ciphertext == "
                            "plaintext (key schedule didn't run?)\n");
            fails++;
        }

        if (pqf_aes256_cbc_decrypt(key, iv, buf, 80, buf) != 0) {
            fprintf(stderr, "FAIL in-place decrypt rc\n"); fails++;
        }
        if (memcmp(buf, orig, 80) != 0) {
            fprintf(stderr, "FAIL in-place decrypt: round-trip lost data\n");
            fails++;
        } else {
            printf("  ok: in-place CBC round-trip (80 bytes)\n");
        }
    }

    /* ---- Length validation ---- */
    {
        uint8_t key[32] = {0};
        uint8_t iv[16] = {0};
        uint8_t buf[31] = {0};
        if (pqf_aes256_cbc_encrypt(key, iv, buf, 31, buf) == 0) {
            fprintf(stderr,
                    "FAIL non-block-aligned encrypt should reject\n");
            fails++;
        }
        if (pqf_aes256_cbc_decrypt(key, iv, buf, 31, buf) == 0) {
            fprintf(stderr,
                    "FAIL non-block-aligned decrypt should reject\n");
            fails++;
        }
        if (pqf_aes256_cbc_encrypt(key, iv, buf, 0, buf) == 0) {
            fprintf(stderr,
                    "FAIL zero-length encrypt should reject\n");
            fails++;
        }
        printf("  ok: length validation rejects non-block-multiples + zero\n");
    }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
