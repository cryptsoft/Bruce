/* pin_protocol.c -- PIN/UV-auth protocol v1 + v2 primitives.
 *
 * See pin_protocol.h for the protocol differences. The crypto below
 * (ECDH, SHA-256, HKDF, AES-256-CBC, HMAC-SHA-256) all comes from the
 * pqf_crypto layer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "pin_protocol.h"
#include "pqf_crypto.h"
#include "pqf_cleanse.h"
#include "openssl/rand.h"

int pin_shared_secret(uint8_t protocol,
                      const uint8_t auth_priv[32],
                      const uint8_t plat_x[32], const uint8_t plat_y[32],
                      pin_shared_secret_t *out)
{
    /* (The 2026-07-10 bring-up CDC markers that bracketed this ECDH
     * call are gone: the vendored EC code was exonerated on riscv32 by
     * a QEMU differential test, and a hang/trap anywhere in it now
     * shows up in the RISC-V trap record instead -- see
     * isr_riscv_machine_exception in core1_signer.c.) */
    uint8_t z[32];
    if (pqf_ecdh_p256(auth_priv, plat_x, plat_y, z) != 0)
        return -1;

    out->protocol = protocol;

    if (protocol == PIN_PROTOCOL_V1) {
        /* sharedSecret = SHA-256(Z); one key used for both AES + MAC. */
        pqf_sha256(z, 32, out->aes_key);
        memcpy(out->hmac_key, out->aes_key, 32);
    } else if (protocol == PIN_PROTOCOL_V2) {
        uint8_t prk[32];
        pqf_hkdf_extract(NULL, 0, z, 32, prk);
        int he = pqf_hkdf_expand(prk, (const uint8_t *)"CTAP2 HMAC key", 14,
                                 out->hmac_key, 32);
        int ae = pqf_hkdf_expand(prk, (const uint8_t *)"CTAP2 AES key", 13,
                                 out->aes_key, 32);
        pqf_cleanse(prk, sizeof prk);
        if (he != 0 || ae != 0) {
            pqf_cleanse(z, sizeof z);
            return -1;
        }
    } else {
        pqf_cleanse(z, sizeof z);
        return -1;
    }

    pqf_cleanse(z, sizeof z);
    return 0;
}

int pin_decrypt(const pin_shared_secret_t *ss,
                const uint8_t *in, size_t in_len,
                uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ss->protocol == PIN_PROTOCOL_V1) {
        if (in_len == 0 || (in_len % 16) != 0) return -1;
        /* AES-CBC yields exactly in_len plaintext bytes; refuse to write
         * past the caller's buffer before touching the cipher. */
        if (in_len > out_cap) return -1;
        static const uint8_t zero_iv[16] = { 0 };
        if (pqf_aes256_cbc_decrypt(ss->aes_key, zero_iv, in, in_len, out) != 0)
            return -1;
        *out_len = in_len;
        return 0;
    }
    /* v2: [16-byte IV][ciphertext]. */
    if (in_len < 16 + 16 || ((in_len - 16) % 16) != 0) return -1;
    size_t ct_len = in_len - 16;
    if (ct_len > out_cap) return -1;
    const uint8_t *iv = in;
    const uint8_t *ct = in + 16;
    if (pqf_aes256_cbc_decrypt(ss->aes_key, iv, ct, ct_len, out) != 0)
        return -1;
    *out_len = ct_len;
    return 0;
}

int pin_encrypt(const pin_shared_secret_t *ss,
                const uint8_t *in, size_t in_len,
                uint8_t *out, size_t *out_len)
{
    if (in_len == 0 || (in_len % 16) != 0) return -1;

    if (ss->protocol == PIN_PROTOCOL_V1) {
        static const uint8_t zero_iv[16] = { 0 };
        if (pqf_aes256_cbc_encrypt(ss->aes_key, zero_iv, in, in_len, out) != 0)
            return -1;
        *out_len = in_len;
        return 0;
    }
    /* v2: prepend a fresh random IV. */
    uint8_t iv[16];
    RAND_bytes(iv, 16);
    memcpy(out, iv, 16);
    if (pqf_aes256_cbc_encrypt(ss->aes_key, iv, in, in_len, out + 16) != 0)
        return -1;
    *out_len = in_len + 16;
    return 0;
}

void pin_authenticate(uint8_t protocol, const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t *mac, size_t *mac_len)
{
    uint8_t full[32];
    pqf_hmac_sha256(key, key_len, data, data_len, full);
    if (protocol == PIN_PROTOCOL_V1) {
        memcpy(mac, full, 16);
        *mac_len = 16;
    } else {
        memcpy(mac, full, 32);
        *mac_len = 32;
    }
}

bool pin_verify(const pin_shared_secret_t *ss,
                const uint8_t *data, size_t data_len,
                const uint8_t *mac, size_t mac_len)
{
    uint8_t expect[32];
    size_t  expect_len = 0;
    pin_authenticate(ss->protocol, ss->hmac_key, 32,
                     data, data_len, expect, &expect_len);
    if (mac_len != expect_len)
        return false;
    /* constant-time compare */
    uint8_t diff = 0;
    for (size_t i = 0; i < expect_len; i++)
        diff |= (uint8_t)(expect[i] ^ mac[i]);
    return diff == 0;
}
