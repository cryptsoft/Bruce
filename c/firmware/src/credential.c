/* credential.c -- stateless credential key management (ES256 + hybrid).
 *
 * See credential.h for the 161-byte credentialID layout + the
 * 112-byte plaintext (ecdsaScalar || mldsaSeed || rpIdHash ||
 * credProtect || flags || reserved).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "credential.h"
#include "hybrid.h"
#include "core1_signer.h"
#include "pqf_crypto.h"
#include "pqf_cleanse.h"
#include "flash_store.h"
#include "openssl/rand.h"
#include "xip_stats.h"          /* no-op unless -DPQF_XIP_STATS=ON */

#define PT_LEN      112         /* plaintext bytes (7 AES blocks) */
#define CT_OFF      17          /* ciphertext offset in cred_id   */
#define TAG_OFF     (CT_OFF + PT_LEN)   /* HMAC tag offset = 129   */

/* plaintext[97] flag bits. */
#define CRED_FLAG_LARGE_BLOB_KEY  0x01

/* HMAC domain-separation tags (finding X11).
 *
 * Three independent secrets are derived by HMAC-SHA-256 keyed on the
 * single device master MAC key (s_mac_key): the credentialID integrity
 * tag, the hmac-secret cred_random, and the largeBlobKey. To guarantee
 * those three derivations can never collide -- regardless of
 * credentialID length or content -- each HMAC message begins with a
 * distinct ASCII domain label as its first bytes (no NUL terminator).
 *
 * The three labels differ within their first five bytes (the 'c' / 'h'
 * / 'l' at index 4) and none is a prefix of another, so no two HMAC
 * inputs can ever be equal: rigorous, length-independent separation.
 * The byte strings are shared verbatim with the Rust port so the two
 * derivations are byte-for-byte mirrors. */
#define DOMAIN_CRED_ID         "pqf-cred-id"          /* integrity tag  (11) */
#define DOMAIN_CRED_RANDOM     "pqf-hmac-secret"      /* cred_random    (15) */
#define DOMAIN_LARGE_BLOB_KEY  "pqf-large-blob-key"   /* largeBlobKey   (18) */

static uint8_t s_aes_key[32];
static uint8_t s_mac_key[32];
static bool    s_inited = false;

void credential_init(void)
{
    flash_store_keys(s_aes_key, s_mac_key);
    s_inited = true;
}

static int is_zero32(const uint8_t *p)
{
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= p[i];
    return acc == 0;
}

static int tag_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* Integrity tag: HMAC(masterMacKey, DOMAIN_CRED_ID || version(1) ||
 * IV(16) || ciphertext), i.e. the DOMAIN_CRED_ID label prepended to the
 * signed credentialID region (bytes [0 .. TAG_OFF), TAG_OFF = 129). The
 * domain prefix keeps this tag independent of cred_random and
 * largeBlobKey (which HMAC the same key over inputs carrying distinct
 * prefixes). Called identically by seal() and credential_recover(), so
 * the prefix stays symmetric -- the round-trip holds. */
static void cred_tag(const uint8_t *cred_id, uint8_t out[32])
{
    static const char domain[] = DOMAIN_CRED_ID;
    pqf_hmac_sha256_ctx_t hc;
    pqf_hmac_sha256_init(&hc, s_mac_key, 32);
    pqf_hmac_sha256_update(&hc, (const uint8_t *)domain, sizeof domain - 1);
    pqf_hmac_sha256_update(&hc, cred_id, TAG_OFF);
    pqf_hmac_sha256_final(&hc, out);
}

/* Encrypt a plaintext (ecdsaScalar||mldsaSeed||rpIdHash) into cred_id. */
static int seal(const uint8_t plain[PT_LEN], uint8_t cred_id[CRED_ID_LEN])
{
    cred_id[0] = CRED_VERSION;
    uint8_t *iv = cred_id + 1;
    RAND_bytes(iv, 16);
    if (pqf_aes256_cbc_encrypt(s_aes_key, iv, plain, PT_LEN,
                               cred_id + CT_OFF) != 0)
        return -1;
    uint8_t tag[32];
    cred_tag(cred_id, tag);
    memcpy(cred_id + TAG_OFF, tag, 32);
    return 0;
}

int credential_make(const uint8_t rp_id_hash[32], int alg,
                    uint8_t cred_protect, bool large_blob_key,
                    uint8_t cred_id[CRED_ID_LEN],
                    credential_source_t *src,
                    uint8_t pub_x[32], uint8_t pub_y[32])
{
    if (!s_inited) return -1;

    memset(src, 0, sizeof *src);
    src->alg = alg;
    src->cred_protect = cred_protect;
    src->large_blob_key = large_blob_key;

    /* ECDSA scalar: generate a P-256 key, keep the private scalar.
     * Routed through the signing core: in the mixed build core 0's
     * bn/ec runs from XIP flash where this one scalar mult costs ~5 s
     * under cache thrash; the RISC-V blob does it from SRAM in ms.
     * Single-ISA builds run it inline (copy_to_ram, already fast).
     * The public point is returned to the caller -- deriving it again
     * later costs another scalar mult (the caller's COSE key needs it,
     * so hand it out instead of making MakeCredential re-derive). */
    if (core1_p256_keygen(src->ecdsa_scalar, pub_x, pub_y) != 0)
        return -1;

    if (alg == PQF_HYBRID_COSE_ALG) {
        /* Hybrid: also draw a random ML-DSA seed (non-zero w.h.p.;
         * the zero-check below makes the alg recoverable). */
        RAND_bytes(src->mldsa_seed, 32);
        if (is_zero32(src->mldsa_seed))     /* astronomically unlikely */
            src->mldsa_seed[0] = 1;
        /* alg-discriminator invariant: the algorithm is recovered on
         * decrypt by zero-checking the mldsaSeed slot (all-zero => ES256,
         * otherwise hybrid). This discriminator is internal and is
         * authenticated by the credentialID integrity tag -- it is not a
         * wire guarantee. A hybrid credential minted with an all-zero
         * seed would be mis-decoded as ES256, so guard against it: the
         * forced-non-zero above must hold here. */
        if (is_zero32(src->mldsa_seed))
            return -1;
    }
    /* else ES256: mldsa_seed stays all-zero. */

    uint8_t plain[PT_LEN];
    memset(plain, 0, sizeof plain);
    memcpy(plain,      src->ecdsa_scalar, 32);
    memcpy(plain + 32, src->mldsa_seed,   32);
    memcpy(plain + 64, rp_id_hash,        32);
    plain[96] = cred_protect;
    plain[97] = large_blob_key ? CRED_FLAG_LARGE_BLOB_KEY : 0;
    /* plain[98..112) stays reserved zero. */

    int rc = seal(plain, cred_id);
    pqf_cleanse(plain, sizeof plain);
    return rc;
}

int credential_recover(const uint8_t *cred_id, size_t cred_id_len,
                       const uint8_t rp_id_hash[32],
                       credential_source_t *src)
{
    if (!s_inited || cred_id == NULL || cred_id_len != CRED_ID_LEN)
        return -1;
    if (cred_id[0] != CRED_VERSION)
        return -1;

    /* Verify the tag before decrypting (encrypt-then-MAC). */
    uint8_t tag[32];
    cred_tag(cred_id, tag);
    if (!tag_equal(cred_id + TAG_OFF, tag, 32))
        return -1;

    uint8_t plain[PT_LEN];
    if (pqf_aes256_cbc_decrypt(s_aes_key, cred_id + 1, cred_id + CT_OFF,
                               PT_LEN, plain) != 0)
        return -1;

    /* RP binding. */
    if (memcmp(plain + 64, rp_id_hash, 32) != 0) {
        pqf_cleanse(plain, sizeof plain);
        return -1;
    }

    memset(src, 0, sizeof *src);
    memcpy(src->ecdsa_scalar, plain,      32);
    memcpy(src->mldsa_seed,   plain + 32, 32);
    src->cred_protect = plain[96];
    src->large_blob_key = (plain[97] & CRED_FLAG_LARGE_BLOB_KEY) != 0;
    /* alg-discriminator: all-zero mldsaSeed => ES256, otherwise hybrid.
     * This is an internal mapping authenticated by the integrity tag
     * verified above (so an attacker cannot flip the discriminator) -- it
     * is not a wire-format guarantee. credential_make() guards against
     * ever sealing a hybrid credential with an all-zero seed. */
    src->alg = is_zero32(src->mldsa_seed) ? COSE_ALG_ES256
                                          : PQF_HYBRID_COSE_ALG;
    pqf_cleanse(plain, sizeof plain);
    return 0;
}

void credential_cred_random(const uint8_t *cred_id, size_t cred_id_len,
                            bool uv, uint8_t out[32])
{
    /* HMAC(masterMacKey, DOMAIN_CRED_RANDOM || credentialID || uv).
     * The domain prefix keeps this independent of the credentialID
     * integrity tag and the largeBlobKey, which HMAC the same key under
     * distinct domain prefixes. */
    static const char domain[] = DOMAIN_CRED_RANDOM;
    pqf_hmac_sha256_ctx_t hc;
    pqf_hmac_sha256_init(&hc, s_mac_key, 32);
    pqf_hmac_sha256_update(&hc, (const uint8_t *)domain, sizeof domain - 1);
    pqf_hmac_sha256_update(&hc, cred_id, cred_id_len);
    uint8_t b = uv ? 0x01 : 0x00;
    pqf_hmac_sha256_update(&hc, &b, 1);
    pqf_hmac_sha256_final(&hc, out);
}

void credential_large_blob_key(const uint8_t *cred_id, size_t cred_id_len,
                               uint8_t out[32])
{
    /* HMAC(masterMacKey, DOMAIN_LARGE_BLOB_KEY || credentialID).
     * Deterministic -- no per-credential storage -- so the same key is
     * recoverable on every MakeCredential / GetAssertion for this
     * credential. The domain prefix keeps it independent of cred_random
     * and of the credentialID integrity tag (each under a distinct
     * prefix). */
    static const char domain[] = DOMAIN_LARGE_BLOB_KEY;
    pqf_hmac_sha256_ctx_t hc;
    pqf_hmac_sha256_init(&hc, s_mac_key, 32);
    pqf_hmac_sha256_update(&hc, (const uint8_t *)domain, sizeof domain - 1);
    pqf_hmac_sha256_update(&hc, cred_id, cred_id_len);
    pqf_hmac_sha256_final(&hc, out);
}

int credential_sign(const credential_source_t *src,
                    const uint8_t *to_sign, size_t to_sign_len,
                    uint8_t *sig, size_t *sig_len)
{
    if (src->alg == PQF_HYBRID_COSE_ALG) {
        /* Offloaded to core 1 (with KEEPALIVE pumping on core 0) on
         * the firmware; a host stub runs it inline.
         *
         * This call is also the XIP-cache sample window on
         * PQF_XIP_STATS builds: it brackets the whole ML-DSA sign, the
         * one operation whose wall time the cache decides. Both hooks
         * compile to nothing without the option. */
        xip_stats_begin();
        int rc = core1_hybrid_sign(src->ecdsa_scalar, src->mldsa_seed,
                                   to_sign, to_sign_len, sig, sig_len);
        xip_stats_end();
        return rc;
    }
    /* ES256: ECDSA over SHA-256(to_sign). Routed through the signing
     * core for the same XIP reason as the keygen above. */
    uint8_t h[32];
    pqf_sha256(to_sign, to_sign_len, h);
    return core1_p256_sign(src->ecdsa_scalar, h, sig, sig_len);
}
