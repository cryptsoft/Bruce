/* pqf_crypto.h -- public API for the crypto primitives the Bruce
 * C firmware needs, sitting on top of the vendored OpenSSL source in
 * `openssl-mini/src/`.
 *
 * The intent is to keep firmware code (`src/ctap2.c`, `src/u2f.c`,
 * `src/client_pin.c`, ...) free of the upstream OpenSSL spellings -- no
 * `SHA256_CTX`, no `OPENSSL_cleanse`, no `EVP_*`. Everything funnels
 * through `pqf_*` names so a future switch of the underlying
 * implementation (a hardware accelerator, a smaller in-house codec)
 * doesn't touch the call sites.
 *
 * Phases C-4a..C-4e populate this header incrementally:
 *
 *   C-4a -- SHA-256        (this commit)
 *   C-4b -- HMAC-SHA-256   (RFC 2104 on top of SHA-256)
 *   C-4c -- AES-256-CBC    (block cipher + CBC chaining)
 *   C-4d -- P-256 ECDSA    (sign + verify on NIST P-256)
 *   C-4e -- P-256 ECDH     (shared secret derivation)
 *
 * Copyright 2026 Cryptsoft Pty Ltd
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CRYPTO_H
#define PQF_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================ */
/* SHA-256 -- FIPS 180-4                                         */
/* ============================================================ */

/* Output size in bytes. */
#define PQF_SHA256_DIGEST_LEN   32
#define PQF_SHA256_BLOCK_LEN    64

/* Opaque incremental hashing context. Wraps the vendored OpenSSL
 * SHA256_CTX. */
typedef struct {
    /* Layout-compatible with SHA256_CTX from sha.h. We keep the
     * type opaque at the API boundary so callers don't take a
     * dependency on the upstream struct layout. */
    uint32_t      h[8];
    uint32_t      Nl, Nh;
    uint32_t      data[16];
    unsigned int  num, md_len;
} pqf_sha256_ctx_t;

/* One-shot hash. `out` MUST point at >= PQF_SHA256_DIGEST_LEN bytes. */
void pqf_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* Incremental API. The classic init / update* / final triplet. */
void pqf_sha256_init  (pqf_sha256_ctx_t *ctx);
void pqf_sha256_update(pqf_sha256_ctx_t *ctx,
                        const uint8_t *data, size_t len);
void pqf_sha256_final (pqf_sha256_ctx_t *ctx, uint8_t out[32]);

/* ============================================================ */
/* HMAC-SHA-256 -- RFC 2104                                       */
/* ============================================================ */

/* Output size is the same as the underlying hash. */
#define PQF_HMAC_SHA256_LEN     32

/* HMAC context. Holds the inner hash mid-stream plus the outer key
 * material for finalisation. */
typedef struct {
    pqf_sha256_ctx_t  inner;            /* H((K' XOR ipad) || m) so far */
    uint8_t           o_key_pad[64];    /* K' XOR opad, kept for final  */
} pqf_hmac_sha256_ctx_t;

/* One-shot HMAC. */
void pqf_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t out[32]);

/* ============================================================ */
/* HKDF-SHA-256 -- RFC 5869                                       */
/* ============================================================ */

/* HKDF-Extract: PRK = HMAC-SHA-256(salt, ikm). A NULL/zero-length
 * salt is treated as 32 zero bytes per the RFC. */
void pqf_hkdf_extract(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len,
                      uint8_t prk[32]);

/* HKDF-Expand: OKM = T(1) | T(2) | ... truncated to out_len bytes.
 * out_len must be <= 255*32. Returns 0 on success, < 0 on bad length. */
int pqf_hkdf_expand(const uint8_t prk[32],
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len);

/* Incremental API. Init absorbs the key; update / update* / final
 * absorb the message in pieces. Final wipes the o_key_pad. */
void pqf_hmac_sha256_init  (pqf_hmac_sha256_ctx_t *ctx,
                             const uint8_t *key, size_t key_len);
void pqf_hmac_sha256_update(pqf_hmac_sha256_ctx_t *ctx,
                             const uint8_t *data, size_t len);
void pqf_hmac_sha256_final (pqf_hmac_sha256_ctx_t *ctx, uint8_t out[32]);

/* ============================================================ */
/* AES-256 -- FIPS 197 + NIST SP 800-38A CBC mode                 */
/* ============================================================ */

/* AES block size (the same 128-bit value for all key sizes). */
#define PQF_AES_BLOCK_LEN       16

/* AES-256 key + IV sizes. */
#define PQF_AES256_KEY_LEN      32
#define PQF_AES256_IV_LEN       16

/* Opaque round-key schedule. Layout-compatible with the upstream
 * AES_KEY struct so the vendored aes_core.c sees the same memory. */
typedef struct {
    uint32_t rd_key[60];   /* 4 * (14+1) = 60 words for AES-256     */
    int      rounds;
} pqf_aes256_key_t;

/* Key setup. AES-256 takes a 32-byte (256-bit) key. The encrypt
 * schedule is suitable for both forward encryption and inverse-
 * key construction. The decrypt schedule lets AES_decrypt run a
 * single-pass inverse cipher; we keep two separate schedules so
 * code that only encrypts pays no setup cost for the inverse.
 *
 * Returns 0 on success, < 0 on a bad-input error. */
int pqf_aes256_set_encrypt_key(const uint8_t key[32],
                                pqf_aes256_key_t *out);
int pqf_aes256_set_decrypt_key(const uint8_t key[32],
                                pqf_aes256_key_t *out);

/* Single-block primitives. `in` and `out` may alias. */
void pqf_aes256_encrypt_block(const pqf_aes256_key_t *key,
                                const uint8_t in[16], uint8_t out[16]);
void pqf_aes256_decrypt_block(const pqf_aes256_key_t *key,
                                const uint8_t in[16], uint8_t out[16]);

/* CBC mode (NIST SP 800-38A sec. 6.2). The plaintext / ciphertext length
 * MUST be a positive multiple of 16; this matches the FIDO CTAP 2.1
 * PIN protocols that already pre-pad to the block size. No PKCS#7
 * padding is applied. The IV must be 16 bytes; for PIN protocol v1
 * it's all zeros, for v2 it's a fresh random value prepended to the
 * ciphertext on the wire.
 *
 * `out` may alias `in`. Returns 0 on success, < 0 on length error. */
int pqf_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                            const uint8_t *in, size_t len,
                            uint8_t *out);
int pqf_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                            const uint8_t *in, size_t len,
                            uint8_t *out);

/* ============================================================ */
/* NIST P-256 -- ECDSA (FIPS 186-5) + ECDH (SP 800-56A)          */
/* ============================================================ */

/* Field / scalar sizes for P-256. */
#define PQF_P256_SCALAR_LEN     32   /* private key / coordinate    */
#define PQF_P256_POINT_LEN      65   /* uncompressed 0x04||X||Y      */
#define PQF_P256_MAX_SIG_DER    72   /* max DER ECDSA sig (2x33+pad) */

/* Generate a P-256 key pair. The 32-byte big-endian private scalar
 * is written to `priv`; the public point's affine X / Y (32 bytes
 * each, big-endian) to `pub_x` / `pub_y`. Randomness comes from the
 * RAND_* surface (firmware: RP2350 TRNG; host tests: arc4random).
 * Returns 0 on success, < 0 on error. */
int pqf_p256_keygen(uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32]);

/* Compute the public point for a given private scalar (used when
 * re-deriving a key from stored private material). Returns 0 / <0. */
int pqf_p256_derive_public(const uint8_t priv[32],
                            uint8_t pub_x[32], uint8_t pub_y[32]);

/* ECDSA sign. `hash` is the 32-byte message digest (e.g. SHA-256 of
 * the signed data). Produces a DER-encoded SEQUENCE{INTEGER r,
 * INTEGER s} into `sig_der` (caller provides >= PQF_P256_MAX_SIG_DER
 * bytes); the actual length lands in *sig_len. A fresh random k is
 * used per signature. Returns 0 on success, < 0 on error. */
int pqf_ecdsa_p256_sign(const uint8_t priv[32], const uint8_t hash[32],
                        uint8_t *sig_der, size_t *sig_len);

/* ECDSA verify. `pub_x`/`pub_y` are the signer's affine public
 * coordinates; `sig_der`/`sig_len` the DER signature. Returns 1 if
 * the signature is valid, 0 if invalid, < 0 on error. */
int pqf_ecdsa_p256_verify(const uint8_t pub_x[32], const uint8_t pub_y[32],
                          const uint8_t hash[32],
                          const uint8_t *sig_der, size_t sig_len);

/* ECDH. Multiplies the peer's public point by our private scalar and
 * returns the shared point's X coordinate (32 bytes big-endian) --
 * the standard P-256 ECDH shared secret. Returns 0 / <0. */
int pqf_ecdh_p256(const uint8_t priv[32],
                  const uint8_t peer_x[32], const uint8_t peer_y[32],
                  uint8_t shared_x[32]);

/* ============================================================ */
/* ML-DSA -- FIPS 204 (ML-DSA-44 / 65 / 87)                       */
/* ============================================================ */

/* Variant selector -- the numeric suffix. */
#define PQF_MLDSA_44    44
#define PQF_MLDSA_65    65
#define PQF_MLDSA_87    87

/* Public-key + signature sizes per variant (FIPS 204). */
#define PQF_MLDSA44_PK_LEN   1312
#define PQF_MLDSA44_SIG_LEN  2420
#define PQF_MLDSA65_PK_LEN   1952
#define PQF_MLDSA65_SIG_LEN  3309
#define PQF_MLDSA87_PK_LEN   2592
#define PQF_MLDSA87_SIG_LEN  4627

/* Deterministic key derivation: an ML-DSA key pair is generated from
 * a 32-byte seed (FIPS 204 xi). The firmware stores only the seed (in
 * the credentialID) and re-derives the key on demand. `pub` receives
 * the encoded public key; `*pub_len` its length. Returns 0 / < 0. */
int pqf_mldsa_pub_from_seed(int variant, const uint8_t seed[32],
                            uint8_t *pub, size_t *pub_len);

/* Sign `msg` with the key derived from `seed`. Pure ML-DSA (no
 * pre-hash), empty context, deterministic. `sig` must hold the
 * variant's signature size; `*sig_len` receives the actual length.
 * Returns 0 / < 0. */
int pqf_mldsa_sign(int variant, const uint8_t seed[32],
                   const uint8_t *msg, size_t msg_len,
                   uint8_t *sig, size_t *sig_len);

/* Verify an ML-DSA signature against an encoded public key.
 * Returns 1 valid, 0 invalid, < 0 error. */
int pqf_mldsa_verify(int variant, const uint8_t *pub, size_t pub_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig, size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* PQF_CRYPTO_H */
