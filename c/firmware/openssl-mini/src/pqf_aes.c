/* pqf_aes.c -- pqf_* wrapper around the vendored OpenSSL AES core
 * plus a CBC mode implementation per NIST SP 800-38A sec. 6.2.
 *
 * The block cipher itself (key schedule + single-block encrypt /
 * decrypt) is the OpenSSL `crypto/aes/aes_core.c` source vendored
 * verbatim in `src/aes_core.c`. The CBC chaining is project-original
 * C, written from SP 800-38A -- short enough that vendoring
 * `crypto/modes/cbc128.c` (which pulls `crypto/modes.h` and threads
 * the block cipher through `block128_f` typedefs) is more friction
 * than payoff for an embedded build that uses only AES-256-CBC.
 *
 * Copyright 2026 Cryptsoft Pty Ltd
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "pqf_crypto.h"
#include "openssl/aes.h"

/* Compile-time assertion: the opaque pqf_aes256_key_t matches the
 * upstream AES_KEY layout, so the vendored aes_core.c sees the same
 * bytes through either name. If aes_core.c is updated upstream and
 * grows the struct, this fires at build time. */
typedef char pqf_aes256_key_layout_check[
    sizeof(pqf_aes256_key_t) == sizeof(AES_KEY) ? 1 : -1];

/* ---- Key setup ------------------------------------------------ */

int pqf_aes256_set_encrypt_key(const uint8_t key[32],
                                pqf_aes256_key_t *out)
{
    return AES_set_encrypt_key(key, 256, (AES_KEY *)out);
}

int pqf_aes256_set_decrypt_key(const uint8_t key[32],
                                pqf_aes256_key_t *out)
{
    return AES_set_decrypt_key(key, 256, (AES_KEY *)out);
}

/* ---- Single-block primitives ---------------------------------- */

void pqf_aes256_encrypt_block(const pqf_aes256_key_t *key,
                                const uint8_t in[16], uint8_t out[16])
{
    AES_encrypt(in, out, (const AES_KEY *)key);
}

void pqf_aes256_decrypt_block(const pqf_aes256_key_t *key,
                                const uint8_t in[16], uint8_t out[16])
{
    AES_decrypt(in, out, (const AES_KEY *)key);
}

/* ---- CBC mode (NIST SP 800-38A sec. 6.2) -------------------------- */

/* Encryption (sec. 6.2.1):
 *   C_0     = IV
 *   C_j     = CIPH_K(P_j XOR C_{j-1})    for j = 1..n
 *
 * Decryption (sec. 6.2.2):
 *   P_j     = CIPH_K^{-1}(C_j) XOR C_{j-1}   for j = 1..n
 *
 * Both directions tolerate `out == in` (output may overwrite input
 * in place). The decrypt path snapshots each ciphertext block before
 * the AES_decrypt overwrites it, so a single buffer holds the input
 * and output at the same time. */

int pqf_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                            const uint8_t *in, size_t len,
                            uint8_t *out)
{
    if (len == 0 || (len % PQF_AES_BLOCK_LEN) != 0) return -1;

    pqf_aes256_key_t schedule;
    if (pqf_aes256_set_encrypt_key(key, &schedule) < 0) return -1;

    uint8_t chain[PQF_AES_BLOCK_LEN];
    memcpy(chain, iv, PQF_AES_BLOCK_LEN);

    for (size_t off = 0; off < len; off += PQF_AES_BLOCK_LEN) {
        uint8_t xored[PQF_AES_BLOCK_LEN];
        for (int i = 0; i < PQF_AES_BLOCK_LEN; i++) {
            xored[i] = in[off + i] ^ chain[i];
        }
        pqf_aes256_encrypt_block(&schedule, xored, &out[off]);
        memcpy(chain, &out[off], PQF_AES_BLOCK_LEN);
    }

    /* Wipe the key schedule. The chain block is just ciphertext, no
     * key material -- leaving it on the stack is fine. */
    memset(&schedule, 0, sizeof schedule);
    return 0;
}

int pqf_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                            const uint8_t *in, size_t len,
                            uint8_t *out)
{
    if (len == 0 || (len % PQF_AES_BLOCK_LEN) != 0) return -1;

    pqf_aes256_key_t schedule;
    if (pqf_aes256_set_decrypt_key(key, &schedule) < 0) return -1;

    uint8_t chain[PQF_AES_BLOCK_LEN];
    memcpy(chain, iv, PQF_AES_BLOCK_LEN);

    for (size_t off = 0; off < len; off += PQF_AES_BLOCK_LEN) {
        /* Snapshot the ciphertext block BEFORE the decrypt
         * overwrites it (in case out == in). */
        uint8_t cipher_block[PQF_AES_BLOCK_LEN];
        memcpy(cipher_block, &in[off], PQF_AES_BLOCK_LEN);

        uint8_t plain[PQF_AES_BLOCK_LEN];
        pqf_aes256_decrypt_block(&schedule, cipher_block, plain);

        for (int i = 0; i < PQF_AES_BLOCK_LEN; i++) {
            out[off + i] = plain[i] ^ chain[i];
        }
        memcpy(chain, cipher_block, PQF_AES_BLOCK_LEN);
    }

    memset(&schedule, 0, sizeof schedule);
    return 0;
}
