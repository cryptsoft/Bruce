/* credential.h -- credential key management (ES256 + hybrid PQC).
 *
 * Stateless credential model: the per-credential secrets are
 * encrypted into the credentialID under the device master key, so
 * the device stores no per-credential state. The 161-byte
 * credentialID layout:
 *
 *     [0]          version (0x01 = ES256 / hybrid)
 *     [1   .. 17)  IV (16)
 *     [17  .. 129) ciphertext (112) = AES-256-CBC of the 112-byte plaintext
 *     [129 .. 161) HMAC-SHA-256("pqf-cred-id" || version || IV ||
 *                  ciphertext) left 32 (domain-separated integrity tag)
 *
 *   plaintext (112 bytes):
 *     [0  .. 32)  ecdsaScalar  -- P-256 private scalar
 *     [32 .. 64)  mldsaSeed    -- ML-DSA seed (all-zero => ES256-only)
 *     [64 .. 96)  rpIdHash     -- SHA-256(rp.id) this cred is bound to
 *     [96]        credProtect  -- policy 1/2/3 (0 => default level 1)
 *     [97]        flags        -- bit0: largeBlobKey extension enabled
 *     [98 .. 112) reserved (zero)
 *
 * The algorithm is recovered at decrypt time by zero-checking the
 * mldsaSeed slot: all-zero => ES256, otherwise the build's hybrid
 * variant. credProtect rides in the plaintext so the policy is known
 * at GetAssertion without any per-credential storage -- the price is
 * a 161-byte credentialID (base64url 215 chars, still < 255). A
 * credentialID is only ever decryptable under the master key of the
 * device that minted it, so it never needs to interoperate with -- or
 * match the layout of -- any other implementation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CREDENTIAL_H
#define PQF_CREDENTIAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CRED_ID_LEN         161
#define CRED_VERSION        0x01

/* COSE algorithm ids the credential layer understands. */
#define COSE_ALG_ES256      (-7)
/* The hybrid id comes from hybrid.h (PQF_HYBRID_COSE_ALG): one of the
 * composite PQ/T code points -54 (MLDSA44-ES256), -55 (MLDSA65-ES256)
 * or -56 (MLDSA87-ES384), selected by PQF_HYBRID_VARIANT. Not the
 * RFC 9964 pure ML-DSA ids -48/-49/-50, and not -51/-52/-53 (RFC 9864's
 * ESP384 / ESP512 / Ed448), neither of which this firmware implements.
 * The id is never stored in a credential; it is derived on decrypt. */

/* The secrets recovered from / generated for a credential. */
typedef struct {
    int     alg;                 /* COSE_ALG_ES256 or hybrid id      */
    uint8_t ecdsa_scalar[32];
    uint8_t mldsa_seed[32];      /* all-zero when alg == ES256       */
    uint8_t cred_protect;        /* credProtect policy 1/2/3 (0=lvl1)*/
    bool    large_blob_key;      /* minted with the largeBlobKey ext */
} credential_source_t;

void credential_init(void);

/* Mint a new credential bound to `rp_id_hash` using algorithm `alg`
 * (COSE_ALG_ES256 or the hybrid id). `large_blob_key` records whether
 * the largeBlobKey extension was requested at registration; the bit is
 * baked into the credentialID so GetAssertion can gate the extension
 * output without per-credential storage (CTAP 2.1 sec. 6.2.5). Writes the
 * 161-byte credentialID, returns the generated secrets in `*src` (so
 * the caller can sign the attestation without a second decrypt), and
 * the P-256 public point in pub_x/pub_y (computed by the keygen anyway;
 * re-deriving it costs another scalar multiplication -- ~2.4 s from XIP
 * flash in the mixed build). Returns 0 / < 0. */
int credential_make(const uint8_t rp_id_hash[32], int alg,
                    uint8_t cred_protect, bool large_blob_key,
                    uint8_t cred_id[CRED_ID_LEN],
                    credential_source_t *src,
                    uint8_t pub_x[32], uint8_t pub_y[32]);

/* Recover a credential's secrets from its credentialID, verifying the
 * HMAC tag and the RP binding. On success fills `*src` (including the
 * recovered `alg`) and returns 0; returns < 0 if the tag is invalid,
 * the length/version is wrong, or the RP doesn't match. */
int credential_recover(const uint8_t *cred_id, size_t cred_id_len,
                       const uint8_t rp_id_hash[32],
                       credential_source_t *src);

/* Sign `to_sign` with a recovered/just-made credential, dispatching
 * on src->alg: ES256 -> ECDSA over SHA-256(to_sign); hybrid ->
 * hybrid_sign (LABEL-prefixed ECDSA || ML-DSA). `sig` must hold the
 * worst-case hybrid length. Returns 0 / < 0. */
int credential_sign(const credential_source_t *src,
                    const uint8_t *to_sign, size_t to_sign_len,
                    uint8_t *sig, size_t *sig_len);

/* Derive the per-credential `cred_random` secret used by the
 * hmac-secret extension: HMAC(masterMacKey, domain || credentialID ||
 * uv-byte). Deterministic -- no per-credential storage -- so it works
 * for stateless (non-resident) credentials and survives reboots
 * (the master key is persisted). `uv` selects a distinct secret for
 * the user-verified vs non-verified case, per CTAP 2.1 sec. 11.2. */
void credential_cred_random(const uint8_t *cred_id, size_t cred_id_len,
                            bool uv, uint8_t out[32]);

/* Derive the per-credential `largeBlobKey` (CTAP 2.1 sec. 6.10, sec. 11.4):
 * HMAC(masterMacKey, "pqf-large-blob-key" || credentialID). Returned to the RP (when
 * the largeBlobKey extension is requested) for use as an AEAD key over
 * the data it stores via authenticatorLargeBlobs. Deterministic -- no
 * per-credential storage. */
void credential_large_blob_key(const uint8_t *cred_id, size_t cred_id_len,
                               uint8_t out[32]);

#endif /* PQF_CREDENTIAL_H */
