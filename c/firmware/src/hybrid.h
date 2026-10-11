/* hybrid.h -- hybrid ECDSA-P256 + ML-DSA signing (the PQC path).
 *
 * Wire-compatible with the Rust firmware (and the OpenSK PQC fork it
 * mirrors), so credentials and assertions verify under the same
 * relying party. The construction (see hybrid.c):
 *
 *   ecdsaPrehash = SHA-256(LABEL || msg)
 *   ecdsaDER     = ECDSA-P256(ecdsaScalar, ecdsaPrehash)        // DER
 *   mldsaSig     = ML-DSA(mldsaSeed, LABEL || msg || ecdsaDER)  // pure
 *   hybridSig    = ecdsaDER || mldsaSig                         // concat
 *
 * where `msg` is the FIDO signed data (authenticatorData ||
 * clientDataHash) and LABEL is the 32-byte domain separator.
 *
 * The hybrid ML-DSA variant is fixed at build time (default ML-DSA-65
 * -> COSE_ALG_MLDSA65_ES256), mirroring the Rust firmware's mldsa65
 * default.
 *
 * COSE algorithm identifiers are the composite PQ/T code points
 * requested in draft-ietf-jose-pq-composite-sigs-04 (MLDSA44-ES256 =
 * -54, MLDSA65-ES256 = -55, MLDSA87-ES384 = -56), defined once below.
 * Draft -02 requested -51/-52/-53, but RFC 9864 assigned those to
 * ESP384 / ESP512 / Ed448, so they must never be read as a composite;
 * before that this firmware emitted the pure ML-DSA ids -48/-49/-50.
 * Only the identifier integers changed; the signing construction above
 * is unchanged.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_HYBRID_H
#define PQF_HYBRID_H

#include <stdint.h>
#include <stddef.h>

#include "pqf_crypto.h"

/* The composite PQ/T COSE algorithm ids, one per ML-DSA level. Still
 * provisional (the draft reads "TBD, request -54" and so on), so each
 * is defined exactly once, here: a relabel is a one-line change per
 * level. ctap2.c advertises all three in getInfo; the Rust firmware's
 * copy is in crates/signer-core/src/mldsa_alg.rs and must agree. */
#define COSE_ALG_MLDSA44_ES256  (-54)   /* ML-DSA-44 + ECDSA P-256 */
#define COSE_ALG_MLDSA65_ES256  (-55)   /* ML-DSA-65 + ECDSA P-256 */
#define COSE_ALG_MLDSA87_ES384  (-56)   /* ML-DSA-87 + ECDSA; P-256 here */

/* Build-time ML-DSA variant for the hybrid scheme. Override with
 * -DPQF_HYBRID_VARIANT=44 / 87 to match a differently-configured
 * Rust build. Default 65 (COSE_ALG_MLDSA65_ES256), the Rust default. */
#ifndef PQF_HYBRID_VARIANT
#define PQF_HYBRID_VARIANT      65
#endif

#if   PQF_HYBRID_VARIANT == 44
#  define PQF_HYBRID_COSE_ALG   COSE_ALG_MLDSA44_ES256
#  define PQF_HYBRID_MLDSA      PQF_MLDSA_44
#  define PQF_HYBRID_PK_LEN     PQF_MLDSA44_PK_LEN
#  define PQF_HYBRID_SIG_LEN    PQF_MLDSA44_SIG_LEN
#elif PQF_HYBRID_VARIANT == 65
#  define PQF_HYBRID_COSE_ALG   COSE_ALG_MLDSA65_ES256
#  define PQF_HYBRID_MLDSA      PQF_MLDSA_65
#  define PQF_HYBRID_PK_LEN     PQF_MLDSA65_PK_LEN
#  define PQF_HYBRID_SIG_LEN    PQF_MLDSA65_SIG_LEN
#elif PQF_HYBRID_VARIANT == 87
#  define PQF_HYBRID_COSE_ALG   COSE_ALG_MLDSA87_ES384
#  define PQF_HYBRID_MLDSA      PQF_MLDSA_87
#  define PQF_HYBRID_PK_LEN     PQF_MLDSA87_PK_LEN
#  define PQF_HYBRID_SIG_LEN    PQF_MLDSA87_SIG_LEN
#else
#  error "PQF_HYBRID_VARIANT must be 44, 65, or 87"
#endif

/* Maximum hybrid signature length: a DER ECDSA sig (<= 72) + the
 * ML-DSA sig. */
#define PQF_HYBRID_MAX_SIG  (PQF_P256_MAX_SIG_DER + PQF_HYBRID_SIG_LEN)

/* Worst-case staging buffer for LABEL || msg [|| ecdsaDER]. `msg` is
 * authData || clientDataHash; for a hybrid MakeCredential the authData
 * embeds the full ML-DSA public key (up to 2592 B for ML-DSA-87), so
 * the signed message reaches ~3 KB -- far past the old 640 B guess.
 * PQF_HYBRID_MSG_MAX = 4096 matches the Rust signer's message cap; the
 * label (32 B) and the appended ECDSA DER round out the worst case. */
#define PQF_HYBRID_MSG_MAX       4096
#define PQF_HYBRID_LABELLED_MAX  (32 + PQF_HYBRID_MSG_MAX + PQF_P256_MAX_SIG_DER)

/* The 32-byte domain-separation label. Defined in hybrid.c. */
extern const uint8_t PQF_HYBRID_LABEL[32];

/* Derive the hybrid public key components from the stored secrets.
 * `ec_x`/`ec_y` get the ECDSA-P256 affine public coordinates;
 * `mldsa_pub` (>= PQF_HYBRID_PK_LEN) gets the ML-DSA public key, its
 * length in `*mldsa_pub_len`. Returns 0 / < 0. */
int hybrid_public(const uint8_t ecdsa_scalar[32], const uint8_t mldsa_seed[32],
                  uint8_t ec_x[32], uint8_t ec_y[32],
                  uint8_t *mldsa_pub, size_t *mldsa_pub_len);

/* Produce a hybrid signature over `msg` (= authData || clientDataHash).
 * `out` must hold >= PQF_HYBRID_MAX_SIG bytes; `*out_len` receives the
 * actual length (ecdsaDER_len + ML-DSA sig len). Returns 0 / < 0. */
int hybrid_sign(const uint8_t ecdsa_scalar[32], const uint8_t mldsa_seed[32],
                const uint8_t *msg, size_t msg_len,
                uint8_t *out, size_t *out_len);

/* Verify a hybrid signature (host-side test helper). Returns 1 valid,
 * 0 invalid, < 0 error. Splits `sig` into the DER ECDSA prefix + the
 * ML-DSA remainder and checks both halves. */
int hybrid_verify(const uint8_t ec_x[32], const uint8_t ec_y[32],
                  const uint8_t *mldsa_pub, size_t mldsa_pub_len,
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len);

#endif /* PQF_HYBRID_H */
