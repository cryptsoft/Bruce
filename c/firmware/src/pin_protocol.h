/* pin_protocol.h -- CTAP 2.1 PIN/UV-auth protocols v1 and v2.
 *
 * Both protocols establish a shared secret via ECDH(P-256) between
 * the platform and the authenticator, then use it to encrypt PIN
 * material and authenticate (MAC) blobs. They differ only in key
 * derivation + the encrypt/MAC details:
 *
 *   v1 (sec. 6.5.7):  sharedSecret = SHA-256(Z)
 *                 encrypt = AES-256-CBC, zero IV, no IV on the wire
 *                 authenticate = left 16 bytes of HMAC-SHA-256
 *
 *   v2 (sec. 6.5.7):  PRK = HKDF-Extract(0, Z)
 *                 aesKey  = HKDF-Expand(PRK, "CTAP2 AES key",  32)
 *                 hmacKey = HKDF-Expand(PRK, "CTAP2 HMAC key", 32)
 *                 encrypt = AES-256-CBC, random 16-byte IV prepended
 *                 authenticate = full 32-byte HMAC-SHA-256
 *
 * `Z` is the X-coordinate of platformPublic / authenticatorPrivate.
 *
 * This module hides those differences behind one shared_secret_t so
 * the ClientPIN subcommand handlers stay protocol-agnostic.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_PIN_PROTOCOL_H
#define PQF_PIN_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PIN_PROTOCOL_V1     1
#define PIN_PROTOCOL_V2     2

/* Derived shared secret, tagged with the protocol it was made for. */
typedef struct {
    uint8_t protocol;       /* PIN_PROTOCOL_V1 / _V2          */
    uint8_t aes_key[32];    /* v1: SHA-256(Z); v2: HKDF AES   */
    uint8_t hmac_key[32];   /* v1: == aes_key; v2: HKDF HMAC  */
} pin_shared_secret_t;

/* Derive the shared secret from our (authenticator) private scalar and
 * the platform's public point. Returns 0 on success, < 0 on error. */
int pin_shared_secret(uint8_t protocol,
                      const uint8_t auth_priv[32],
                      const uint8_t plat_x[32], const uint8_t plat_y[32],
                      pin_shared_secret_t *out);

/* Decrypt `in_len` bytes of `in` into `out` (same length minus the IV
 * for v2). For v1 `in_len` must be a multiple of 16 and the IV is
 * implicit (zero); for v2 the first 16 bytes of `in` are the IV and
 * the remainder (multiple of 16) is the ciphertext. `out_cap` is the
 * capacity of `out`; the call fails (returns < 0) without writing if
 * the plaintext would not fit, so an attacker-supplied over-length
 * ciphertext can never overrun the caller's buffer. `*out_len`
 * receives the plaintext length. Returns 0 / < 0. */
int pin_decrypt(const pin_shared_secret_t *ss,
                const uint8_t *in, size_t in_len,
                uint8_t *out, size_t out_cap, size_t *out_len);

/* Encrypt `in_len` bytes (a multiple of 16) into `out`. For v2 a
 * random IV is generated and prepended, so `*out_len` is in_len for
 * v1 and in_len+16 for v2. Returns 0 / < 0. */
int pin_encrypt(const pin_shared_secret_t *ss,
                const uint8_t *in, size_t in_len,
                uint8_t *out, size_t *out_len);

/* Verify a pinUvAuthParam: recompute the MAC over `data` and compare.
 * v1 compares the left 16 bytes; v2 the full 32. Returns true if the
 * provided `mac` (of length `mac_len`) matches. */
bool pin_verify(const pin_shared_secret_t *ss,
                const uint8_t *data, size_t data_len,
                const uint8_t *mac, size_t mac_len);

/* Compute a MAC with a raw key (used for pinToken-based
 * pinUvAuthParam, where the key is the pinToken not the shared
 * secret). v1 -> 16-byte output, v2 -> 32-byte. *mac_len receives the
 * length. */
void pin_authenticate(uint8_t protocol, const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t *mac, size_t *mac_len);

#endif /* PQF_PIN_PROTOCOL_H */
