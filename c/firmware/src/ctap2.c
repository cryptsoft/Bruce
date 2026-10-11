/* ctap2.c -- CTAP 2.1 command dispatcher (device side).
 *
 * Phase C-5 scope:
 *   - authenticatorGetInfo            (0x04)
 *   - authenticatorMakeCredential     (0x01)  ES256, packed self-attestation
 *   - authenticatorGetAssertion       (0x02)  ES256
 *
 * Credentials are stateless: the per-credential private key is
 * encrypted into the credentialID (see credential.c), so GetAssertion
 * recovers the key from the allowList entry rather than from a stored
 * table. UP is asserted unconditionally for now (real button gating
 * is a later phase, mirroring the Rust port's phase order).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "ctap2.h"
#include "cbor_encode.h"
#include "cbor_read.h"     /* cbor_cose_ec2_xy (hmac-secret keyAgreement) */
#include "credential.h"
#include "flash_store.h"
#include "resident_store.h"
#include "client_pin.h"
#include "authenticator_config.h"
#include "credential_management.h"
#include "large_blobs.h"
#include "hybrid.h"
#include "core1_signer.h"  /* core1_p256_sign (hybrid registration attStmt) */
#include "pqf_crypto.h"
#include "pqcbor.h"

/* ---- Constants ------------------------------------------------- */

/* Bruce (C port) AAGUID: 35d31127-7725-4b9b-85ab-73049d569636, a
 * random version-4 UUID allocated for this port. Distinct from the Rust
 * firmware's and the TrustZone image's, so a relying party can tell the
 * three apart. */
static const uint8_t k_aaguid[16] = {
    0x35, 0xd3, 0x11, 0x27, 0x77, 0x25, 0x4b, 0x9b,
    0x85, 0xab, 0x73, 0x04, 0x9d, 0x56, 0x96, 0x36
};

#define COSE_ALG_ES256          (-7)
#define COSE_KTY_EC2            2
#define COSE_CRV_P256           1

/* The three composite PQ/T code points, COSE_ALG_MLDSA44_ES256 /
 * _MLDSA65_ES256 / _MLDSA87_ES384, are defined once in hybrid.h (the
 * draft-ietf-jose-pq-composite-sigs-04 requests -54/-55/-56). One of
 * them is this build's PQF_HYBRID_COSE_ALG (selected by
 * PQF_HYBRID_VARIANT); all three are advertised in getInfo -- see the
 * 0x0a block below for why. Named rather than written out so the
 * advertised list and hybrid.h cannot drift apart: the getInfo block
 * once hard-coded -50/-49/-48, the RFC 9964 *pure* ML-DSA ids, which no
 * current build mints. */

_Static_assert(PQF_HYBRID_COSE_ALG == COSE_ALG_MLDSA44_ES256 ||
               PQF_HYBRID_COSE_ALG == COSE_ALG_MLDSA65_ES256 ||
               PQF_HYBRID_COSE_ALG == COSE_ALG_MLDSA87_ES384,
               "this build's hybrid alg is not one of the advertised "
               "composite code points");

/* authenticatorData flags (WebAuthn sec. 6.1). */
#define AD_FLAG_UP              0x01   /* user present            */
#define AD_FLAG_UV              0x04   /* user verified           */
#define AD_FLAG_AT              0x40   /* attested cred data      */
#define AD_FLAG_ED              0x80   /* extension data          */

/* Signature counter is persisted in flash (Phase C-6) via
 * flash_store_next_sign_count(); a single global counter across all
 * credentials is spec-legal (CTAP 2.1 sec. 6.1.1). */

/* User-presence gate hook -- see ctap2.h. NULL until the transport
 * installs it; NULL means auto-confirm (host tests, and the buttonless
 * boards whose hook returns true immediately). */
bool (*ctap2_user_presence_hook)(uint32_t timeout_us) = NULL;

/* UP timeout matching the Rust port (main.rs WaitForUp): 10 s. */
#define UP_TIMEOUT_US (10u * 1000u * 1000u)

/* Solicit a test of user presence (CTAP 2.1 sec. 6.1.2 / sec. 6.2.2). Returns
 * CTAP2_OK once presence is confirmed, or CTAP2_ERR_OPERATION_DENIED
 * (0x27) on timeout -- the same status byte the Rust port returns, so
 * the two ports stay wire-identical on a UP timeout. With no hook
 * installed (host tests) presence auto-confirms. */
static int require_user_presence(void)
{
    if (ctap2_user_presence_hook == NULL)
        return CTAP2_OK;                       /* host test: auto-confirm */
    if (ctap2_user_presence_hook(UP_TIMEOUT_US))
        return CTAP2_OK;
    return CTAP2_ERR_OPERATION_DENIED;
}

void ctap2_init(void)
{
    /* Bring up the persistent store first (loads / mints master keys
     * + primes the counter), then hand its keys to the credential
     * layer, then the PIN module. */
    flash_store_init();
    credential_init();
    client_pin_init();
    resident_store_init();
    large_blobs_init();
}

/* ---- CBOR request helpers (over the pqcbor decoder) ------------ */

/* Find the value for an unsigned integer key in a decoded CBOR map.
 * Returns the value item, or NULL if absent / not a map. */
static const pqfido_cbor_item_t *
map_get_uint(const pqfido_cbor_item_t *map, uint64_t key)
{
    if (!pqfido_cbor_is_map(map))
        return NULL;
    size_t n = pqfido_cbor_map_size(map);
    const pqfido_cbor_pair_t *pairs = pqfido_cbor_map_pairs(map);
    for (size_t i = 0; i < n; i++) {
        if (pqfido_cbor_is_uint(pairs[i].key)
            && pqfido_cbor_uint(pairs[i].key) == key)
            return pairs[i].value;
    }
    return NULL;
}

/* Find the value for a text-string key in a decoded CBOR map. */
static const pqfido_cbor_item_t *
map_get_text(const pqfido_cbor_item_t *map, const char *key)
{
    if (!pqfido_cbor_is_map(map))
        return NULL;
    size_t klen = strlen(key);
    size_t n = pqfido_cbor_map_size(map);
    const pqfido_cbor_pair_t *pairs = pqfido_cbor_map_pairs(map);
    for (size_t i = 0; i < n; i++) {
        if (pqfido_cbor_is_string(pairs[i].key)
            && pqfido_cbor_string_len(pairs[i].key) == klen
            && memcmp(pqfido_cbor_string(pairs[i].key), key, klen) == 0)
            return pairs[i].value;
    }
    return NULL;
}

/* Tri-state lookup of a boolean option in the options map (key 0x07 on
 * MakeCredential, 0x05 on GetAssertion). Returns 1/0 for an explicit
 * true/false, or -1 when the option is absent or not a boolean (so the
 * caller can apply the spec default). */
static int option_bool(const pqfido_cbor_item_t *opts, const char *name)
{
    if (opts == NULL)
        return -1;
    const pqfido_cbor_item_t *v = map_get_text(opts, name);
    if (v == NULL || !pqfido_cbor_is_bool(v))
        return -1;
    return pqfido_cbor_bool(v) ? 1 : 0;
}

/* A pubKeyCredParams entry's alg, as a COSE integer (negints come
 * back as their negative value), or 0 if the entry is malformed or
 * unrepresentable.
 *
 * int64_t, not int. CBOR carries 64-bit integers and `int` is 32 bits
 * here, so a cast truncates: 0x1A FFFFFFF9 (4294967289) became -7 and
 * minted an ES256 credential for an algorithm the relying party never
 * named. The Rust port widens and compares as i64; so does this now.
 * Anything outside int64 is not an algorithm anyone has assigned. */
static int64_t param_entry_alg(const pqfido_cbor_item_t *e)
{
    const pqfido_cbor_item_t *alg = map_get_text(e, "alg");
    if (alg == NULL) return 0;
    if (pqfido_cbor_is_negint(alg)) {
        uint64_t arg = pqfido_cbor_negint_arg(alg);
        if (arg > (uint64_t)INT64_MAX) return 0;
        return -(int64_t)arg - 1;                        /* -1-arg */
    }
    if (pqfido_cbor_is_uint(alg)) {
        uint64_t v = pqfido_cbor_uint(alg);
        if (v > (uint64_t)INT64_MAX) return 0;
        return (int64_t)v;
    }
    return 0;
}

/* Pick the credential algorithm from pubKeyCredParams. Policy mirrors
 * the Rust firmware: prefer this build's hybrid PQC variant if the RP
 * lists it; otherwise fall back to ES256 if listed. Returns the
 * chosen COSE alg, or 0 if neither is offered.
 *
 * The other two composite ids are deliberately NOT matched here even
 * though getInfo advertises all three. Matching one would mean minting
 * this build's variant under a code point that names a different
 * parameter set -- the COSE_Key alg, the credentialID's recorded alg and
 * the ML-DSA public-key length would all disagree with the label, and
 * every verifier would reject the assertion. Falling through is the
 * correct outcome: the RP's ES256 entry wins if it has one, and if not
 * the caller emits CTAP2_ERR_UNSUPPORTED_ALGORITHM (0x26), which is
 * exactly the status CTAP 2.1 sec. 6.1 defines for "no algorithm in the
 * list is supported" and is visible to the host, unlike Chrome's
 * silent pre-flight kNoCommonAlgorithms exclusion. */
static int pick_alg(const pqfido_cbor_item_t *params)
{
    if (!pqfido_cbor_is_array(params)) return 0;
    size_t n = pqfido_cbor_array_size(params);
    bool have_hybrid = false, have_es256 = false;
    for (size_t i = 0; i < n; i++) {
        int64_t a = param_entry_alg(pqfido_cbor_array_get(params, i));
        if (a == PQF_HYBRID_COSE_ALG) have_hybrid = true;
        else if (a == COSE_ALG_ES256) have_es256 = true;
    }
    if (have_hybrid) return PQF_HYBRID_COSE_ALG;
    if (have_es256)  return COSE_ALG_ES256;
    return 0;
}

/* ---- COSE_Key (ES256 / EC2) ------------------------------------ */

/* Emit the credential's COSE_Key. For ES256 it's the standard EC2
 * 5-entry map; for hybrid it's the same EC2 fields with the hybrid
 * alg id plus a 6th entry -4 carrying the ML-DSA public key -- the
 * exact shape the Rust firmware emits. Canonical key order:
 * 1, 3, -1, -2, -3 [, -4]. */
static void emit_cose(cbor_writer_t *w, int alg,
                      const uint8_t x[32], const uint8_t y[32],
                      const uint8_t *mldsa_pub, size_t mldsa_pub_len)
{
    bool hybrid = (alg == PQF_HYBRID_COSE_ALG);
    cbor_w_map_header(w, hybrid ? 6 : 5);
    cbor_w_uint(w, 1);  cbor_w_uint(w, COSE_KTY_EC2);
    cbor_w_uint(w, 3);  cbor_w_int(w, alg);
    cbor_w_int(w, -1);  cbor_w_uint(w, COSE_CRV_P256);
    cbor_w_int(w, -2);  cbor_w_bytes(w, x, 32);
    cbor_w_int(w, -3);  cbor_w_bytes(w, y, 32);
    if (hybrid)
        { cbor_w_int(w, -4); cbor_w_bytes(w, mldsa_pub, mldsa_pub_len); }
}

/* ---- authenticatorData ----------------------------------------- */

/* Build authenticatorData into `out` (caller sized generously).
 * If `attested` is non-NULL, includes attestedCredentialData
 * (sets the AT flag) with the given credentialID + COSE_Key.
 * Returns the byte length, or 0 on overflow. */
struct attested_cred {
    const uint8_t *cred_id;
    size_t         cred_id_len;
    int            alg;
    const uint8_t *pub_x;
    const uint8_t *pub_y;
    const uint8_t *mldsa_pub;     /* hybrid only; NULL for ES256 */
    size_t         mldsa_pub_len;
};

static size_t build_auth_data(uint8_t *out, size_t cap,
                              const uint8_t rp_id_hash[32],
                              bool up, uint8_t extra_flags,
                              uint32_t sign_count,
                              const struct attested_cred *attested,
                              const uint8_t *ext, size_t ext_len)
{
    size_t off = 0;
    if (cap < 37) return 0;

    memcpy(out, rp_id_hash, 32);
    off = 32;

    /* AD_FLAG_UP reflects whether user presence was asserted. A
     * GetAssertion with options.up=false (silent assertion, CTAP 2.1
     * sec. 6.2) clears it; every other path sets it. */
    uint8_t flags = extra_flags;
    if (up) flags |= AD_FLAG_UP;
    if (attested != NULL) flags |= AD_FLAG_AT;
    if (ext != NULL && ext_len) flags |= AD_FLAG_ED;
    out[off++] = flags;

    out[off++] = (uint8_t)(sign_count >> 24);
    out[off++] = (uint8_t)(sign_count >> 16);
    out[off++] = (uint8_t)(sign_count >> 8);
    out[off++] = (uint8_t)(sign_count);

    if (attested != NULL) {
        if (off + 16 + 2 + attested->cred_id_len > cap) return 0;
        memcpy(out + off, k_aaguid, 16);
        off += 16;
        out[off++] = (uint8_t)(attested->cred_id_len >> 8);
        out[off++] = (uint8_t)(attested->cred_id_len & 0xff);
        memcpy(out + off, attested->cred_id, attested->cred_id_len);
        off += attested->cred_id_len;

        /* COSE_Key appended as canonical CBOR. */
        cbor_writer_t kw;
        cbor_w_init(&kw, out + off, cap - off);
        emit_cose(&kw, attested->alg, attested->pub_x, attested->pub_y,
                  attested->mldsa_pub, attested->mldsa_pub_len);
        if (!cbor_w_ok(&kw)) return 0;
        off += cbor_w_off(&kw);
    }

    /* Extension-data output (the ED flag is set above). The caller
     * passes a fully-encoded CBOR map; it goes last in authData. */
    if (ext != NULL && ext_len) {
        if (off + ext_len > cap) return 0;
        memcpy(out + off, ext, ext_len);
        off += ext_len;
    }

    return off;
}

/* ---- authenticatorMakeCredential (CTAP 2.1 sec. 6.1) --------------- */

static int handle_make_credential(const uint8_t *params, size_t params_len,
                                  uint8_t *resp, size_t resp_cap,
                                  size_t *resp_len)
{
    pqfido_cbor_item_t *root = NULL;
    if (pqfido_cbor_decode(params, params_len, &root) != PQFIDO_OK) {
        resp[0] = CTAP2_ERR_INVALID_CBOR;
        *resp_len = 1;
        return 0;
    }

    int status = CTAP2_ERR_OTHER;

    const pqfido_cbor_item_t *cdh   = map_get_uint(root, 0x01);
    const pqfido_cbor_item_t *rp    = map_get_uint(root, 0x02);
    const pqfido_cbor_item_t *params_arr = map_get_uint(root, 0x04);

    if (cdh == NULL || !pqfido_cbor_is_bytes(cdh)
        || pqfido_cbor_bytes_len(cdh) != 32
        || rp == NULL || params_arr == NULL) {
        status = CTAP2_ERR_MISSING_PARAMETER;
        goto done;
    }

    const pqfido_cbor_item_t *rp_id = map_get_text(rp, "id");
    if (rp_id == NULL || !pqfido_cbor_is_string(rp_id)) {
        status = CTAP2_ERR_MISSING_PARAMETER;
        goto done;
    }

    /* user entity (key 0x03): id (required for a discoverable
     * credential), name + displayName (optional metadata surfaced by
     * CredentialManagement enumeration / account pickers). Captured
     * into the resident slot below. */
    const pqfido_cbor_item_t *user = map_get_uint(root, 0x03);
    uint8_t user_id[RES_USER_ID_MAX];          uint8_t user_id_len = 0;
    uint8_t user_name[RES_USER_NAME_MAX];      uint8_t user_name_len = 0;
    uint8_t user_disp[RES_DISPLAY_NAME_MAX];   uint8_t user_disp_len = 0;
    if (user != NULL) {
        const pqfido_cbor_item_t *uid = map_get_text(user, "id");
        if (uid && pqfido_cbor_is_bytes(uid)) {
            /* Refuse, do not clamp. A truncated user handle is a
             * DIFFERENT user handle: the relying party would get back
             * an id it never issued and match it to nobody. The name
             * and displayName clamps below are fine -- those are
             * cosmetic, and the Rust port clamps them the same way. */
            size_t l = pqfido_cbor_bytes_len(uid);
            if (l > 0 && l <= RES_USER_ID_MAX) {
                memcpy(user_id, pqfido_cbor_bytes(uid), l);
                user_id_len = (uint8_t)l;
            }
        }
        const pqfido_cbor_item_t *un = map_get_text(user, "name");
        if (un && pqfido_cbor_is_string(un)) {
            size_t l = pqfido_cbor_string_len(un);
            if (l > RES_USER_NAME_MAX) l = RES_USER_NAME_MAX;
            memcpy(user_name, pqfido_cbor_string(un), l);
            user_name_len = (uint8_t)l;
        }
        const pqfido_cbor_item_t *ud = map_get_text(user, "displayName");
        if (ud && pqfido_cbor_is_string(ud)) {
            size_t l = pqfido_cbor_string_len(ud);
            if (l > RES_DISPLAY_NAME_MAX) l = RES_DISPLAY_NAME_MAX;
            memcpy(user_disp, pqfido_cbor_string(ud), l);
            user_disp_len = (uint8_t)l;
        }
    }
    /* user (0x03) and user.id are required (CTAP 2.1 sec. 6.1). Minting a
     * credential with no user handle -- or an over-long one refused
     * above -- produces a discoverable credential whose GetAssertion
     * response can never carry the user it belongs to. The Rust port
     * refuses this at ctap2.rs; this port accepted it silently. */
    if (user_id_len == 0) {
        status = CTAP2_ERR_MISSING_PARAMETER;
        goto done;
    }

    /* Pick the algorithm: this build's hybrid PQC variant if the RP
     * offers it, else ES256. */
    int chosen_alg = pick_alg(params_arr);
    if (chosen_alg == 0) {
        status = CTAP2_ERR_UNSUPPORTED_ALGORITHM;
        goto done;
    }

    /* options map (key 0x07): rk / up / uv (CTAP 2.1 sec. 6.1). Defaults
     * per spec: rk = false (server-side credential), up = true, uv =
     * false. We honor each option presence-explicitly:
     *   - rk: only a true value makes the credential discoverable and
     *     consumes a resident slot.
     *   - up: MakeCredential always requires user presence; up=false is
     *     not a valid option here -> CTAP2_ERR_INVALID_OPTION (0x2c).
     *   - uv: validated after PIN/UV gating below -- an explicit uv=true
     *     that nothing can satisfy must fail rather than silently
     *     downgrading the ceremony. */
    const pqfido_cbor_item_t *opts = map_get_uint(root, 0x07);
    bool want_rk = (option_bool(opts, "rk") == 1);
    int opt_uv = option_bool(opts, "uv");
    if (option_bool(opts, "up") == 0) {
        status = CTAP2_ERR_INVALID_OPTION;
        goto done;
    }

    /* rpIdHash = SHA-256(rp.id). */
    uint8_t rp_id_hash[32];
    pqf_sha256(pqfido_cbor_string(rp_id),
               pqfido_cbor_string_len(rp_id), rp_id_hash);

    const uint8_t *client_data_hash = pqfido_cbor_bytes(cdh);

    /* PIN/UV gating (CTAP 2.1 sec. 6.1) -- structure mirrors the Rust base.
     * We advertise makeCredUvNotRqd=true, so a PIN being set does NOT by
     * itself force user verification: a NON-discoverable credential may
     * be created on user-presence (touch) alone, exactly like a YubiKey
     * in a second-factor (userVerification=discouraged) registration.
     * The cases that DO require UV are enforced by dedicated gates just
     * below -- want_rk (discoverable), opt_uv (explicit uv=true), and
     * alwaysUv -- each failing with PUAT_REQUIRED when uv_flag==0.
     *
     * So when a PIN is set we only VERIFY a supplied pinUvAuthParam; we
     * do NOT refuse when one is absent. (A prior revision returned
     * PUAT_REQUIRED for an absent param unconditionally, forcing UV on
     * every registration once a PIN existed and making Chrome drive our
     * token differently from a YubiKey -- the "hijacking" symptom.)
     *
     * Error codes when a param IS present (0x08 / protocol 0x09):
     *   protocol missing/unknown, no active token, wrong permission/RP
     *   scope, or MAC mismatch -> 0x33 PIN_AUTH_INVALID (never 0x36).
     * Chrome's silent probe (param = h'', protocol = 1) is "present",
     * so it lands in the verify-fail path and gets 0x33, which keeps us
     * surfaced in the WebAuthn picker. */
    uint8_t uv_flag = 0;
    if (client_pin_is_set()) {
        const pqfido_cbor_item_t *puap = map_get_uint(root, 0x08);
        const pqfido_cbor_item_t *prot = map_get_uint(root, 0x09);
        if (puap != NULL && pqfido_cbor_is_bytes(puap)) {
            if (prot == NULL || !pqfido_cbor_is_uint(prot)
                || (pqfido_cbor_uint(prot) != PIN_PROTOCOL_V1
                    && pqfido_cbor_uint(prot) != PIN_PROTOCOL_V2)) {
                status = CTAP2_ERR_PIN_AUTH_INVALID;
                goto done;
            }
            int pe = client_pin_verify_token(pqfido_cbor_bytes(puap),
                                             pqfido_cbor_bytes_len(puap),
                                             (uint8_t)pqfido_cbor_uint(prot),
                                             client_data_hash, 32,
                                             PIN_PERM_MAKE_CREDENTIAL, rp_id_hash);
            if (pe != 0) {
                /* param present -> invalid is 0x33, never 0x36. */
                status = CTAP2_ERR_PIN_AUTH_INVALID;
                goto done;
            }
            uv_flag = AD_FLAG_UV;
        }
    }

    /* makeCredUvNotRqd exempts only NON-discoverable credentials. A
     * discoverable (resident / rk=true) credential can be asserted with
     * no allowList, so presence-only creation would let anyone holding
     * the device use it silently -- it still requires UV once a PIN is
     * configured. (With no PIN there is no UV method and resident creds
     * remain up-only, unchanged.) Matches a YubiKey: second-factor
     * registrations go through on a touch, passkeys demand the PIN. */
    if (want_rk && client_pin_is_set() && uv_flag == 0) {
        status = CTAP2_ERR_PUAT_REQUIRED;
        goto done;
    }

    /* alwaysUv (CTAP 2.1 sec. 6.11.4): when the device-wide policy is on,
     * every MakeCredential requires user verification -- even if the RP
     * didn't ask, and even if no PIN is set (in which case nothing can
     * satisfy it and the device stays locked until a PIN is set). */
    if (flash_store_always_uv() && uv_flag == 0) {
        status = CTAP2_ERR_PUAT_REQUIRED;
        goto done;
    }

    /* Explicit options.uv = true with no user verification performed.
     * The status distinguishes two situations the client acts on
     * differently, matching the Rust port: with no PIN set there is no
     * user-verification method on this hardware at all, so the request
     * can never be satisfied (UNSUPPORTED_OPTION); with a PIN set the
     * client simply has to fetch a token first, and PUAT_REQUIRED is
     * the retriable code that says so. This port answered
     * INVALID_OPTION for both, which tells a platform to give up in the
     * case where it should have prompted for the PIN. */
    if (opt_uv == 1 && uv_flag == 0) {
        status = client_pin_is_set() ? CTAP2_ERR_PUAT_REQUIRED
                                     : CTAP2_ERR_UNSUPPORTED_OPTION;
        goto done;
    }

    /* excludeList (key 0x05): if any listed credentialID was minted by
     * this device for this RP, registering again would duplicate-enroll
     * the authenticator. credential_recover() verifies the HMAC tag AND
     * the rp_id_hash binding, so a successful recover under this rp is a
     * match -> refuse with CREDENTIAL_EXCLUDED (WebAuthn excludeCredentials,
     * CTAP 2.1 sec. 6.1.2). */
    /* The match is recorded here and ANSWERED only after the
     * user-presence gate below. CTAP 2.1 sec. 6.1.2 step 11 is explicit
     * that the authenticator waits for the gesture before returning
     * CREDENTIAL_EXCLUDED, and the Rust port does so; this one used to
     * answer at once, which made the excludeList a way to ask the token
     * "is this credential yours?" with no one at the keyboard. */
    bool excluded = false;
    {
        const pqfido_cbor_item_t *excl = map_get_uint(root, 0x05);
        if (excl != NULL && pqfido_cbor_is_array(excl)) {
            size_t en = pqfido_cbor_array_size(excl);
            for (size_t i = 0; i < en && !excluded; i++) {
                const pqfido_cbor_item_t *e = pqfido_cbor_array_get(excl, i);
                const pqfido_cbor_item_t *eid = e ? map_get_text(e, "id") : NULL;
                if (eid && pqfido_cbor_is_bytes(eid)
                    && pqfido_cbor_bytes_len(eid) == CRED_ID_LEN) {
                    credential_source_t tmp;
                    int r = credential_recover(pqfido_cbor_bytes(eid),
                                               CRED_ID_LEN, rp_id_hash, &tmp);
                    memset(&tmp, 0, sizeof tmp);
                    if (r == 0) excluded = true;
                }
            }
        }
    }

    /* Parse extensions input (key 0x06 for MakeCredential):
     *   - credProtect: uint 1..3 (default level 1) -- gates use w/o UV.
     *   - hmac-secret: bool -- per-credential symmetric secrets.
     * credProtect is baked into the credentialID so it's known at
     * GetAssertion; hmac-secret is derived on demand. */
    const pqfido_cbor_item_t *exts_in = map_get_uint(root, 0x06);
    uint8_t cred_protect = 1;
    bool want_hmac_secret = false;
    bool want_min_pin = false;
    bool want_lbk = false;
    bool want_cred_blob = false;
    bool cred_blob_too_long = false;
    uint8_t cred_blob_in[RES_CRED_BLOB_MAX];
    uint8_t cred_blob_len_in = 0;
    if (exts_in != NULL) {
        const pqfido_cbor_item_t *cp = map_get_text(exts_in, "credProtect");
        if (cp != NULL && pqfido_cbor_is_uint(cp)) {
            uint64_t v = pqfido_cbor_uint(cp);
            if (v >= 1 && v <= 3) cred_protect = (uint8_t)v;
        }
        want_hmac_secret = (map_get_text(exts_in, "hmac-secret") != NULL);
        /* Presence-based, like hmac-secret above: clients send
         * `minPinLength: true`. */
        want_min_pin = (map_get_text(exts_in, "minPinLength") != NULL);
        /* largeBlobKey is a CTAP 2.1 sec. 12.3 boolean extension: require the
         * value to be the boolean true (matching the spec semantics and
         * the Rust parity base), not mere key presence. The decoder DOES
         * expose pqfido_cbor_is_bool/pqfido_cbor_bool (used by
         * option_bool() above), so a value check is trivial. Baking the
         * bit into the credentialID on a `largeBlobKey: false` (or any
         * non-bool) input would durably and wrongly mark the credential
         * as largeBlobKey-enabled for every future GetAssertion (#23). */
        {
            const pqfido_cbor_item_t *lbk_in =
                map_get_text(exts_in, "largeBlobKey");
            want_lbk = (lbk_in != NULL && pqfido_cbor_is_bool(lbk_in)
                        && pqfido_cbor_bool(lbk_in));
        }
        /* credBlob: an opaque RP payload (<= 32 B) stored with the
         * credential (CTAP 2.1 sec. 12.4). Over-long blobs are refused but
         * don't fail MakeCredential -- we just echo credBlob:false. */
        const pqfido_cbor_item_t *cb = map_get_text(exts_in, "credBlob");
        if (cb != NULL) {
            want_cred_blob = true;
            if (pqfido_cbor_is_bytes(cb)) {
                size_t l = pqfido_cbor_bytes_len(cb);
                if (l > RES_CRED_BLOB_MAX) cred_blob_too_long = true;
                else {
                    memcpy(cred_blob_in, pqfido_cbor_bytes(cb), l);
                    cred_blob_len_in = (uint8_t)l;
                }
            }
        }
    }
    /* minPinLength is echoed only when the RP id is in the allowlist
     * registered via AuthenticatorConfig setMinPINLength (sec. 11.3). */
    bool emit_min_pin = want_min_pin
                        && flash_store_min_pin_rpid_match(rp_id_hash);
    bool cred_blob_accepted = (cred_blob_len_in > 0) && !cred_blob_too_long;

    /* User-presence gate (CTAP 2.1 sec. 6.1.2 step 14). PIN/UV, the
     * excludeList scan and the extension inputs have all been evaluated
     * above; nothing has been generated or persisted yet, so a timeout
     * leaves no state behind. This sits BEFORE credential_make on
     * purpose: it used to come after the key generation and authData
     * build, which meant every request that was going to be refused for
     * want of a touch first paid for a full hybrid keygen. The Rust port
     * gates here. Auto-confirms on buttonless boards / host tests.
     * Timeout -> 0x27, matching the Rust port. */
    status = require_user_presence();
    if (status != CTAP2_OK) goto done;

    /* Now the excludeList answer, with a human confirmed present. */
    if (excluded) {
        status = CTAP2_ERR_CREDENTIAL_EXCLUDED;
        goto done;
    }

    /* Make a credential bound to this RP with the chosen algorithm.
     * The largeBlobKey-requested bit is baked into the credentialID so
     * GetAssertion can gate the extension output (L11). */
    static uint8_t cred_id[CRED_ID_LEN];
    credential_source_t src;
    uint8_t pub_x[32], pub_y[32];
    if (credential_make(rp_id_hash, chosen_alg, cred_protect, want_lbk,
                        cred_id, &src, pub_x, pub_y) != 0) {
        status = CTAP2_ERR_OTHER;
        goto done;
    }

    /* NOTE (#22): the resident-credential slot for an rk=true request is
     * NOT committed here. It is built into `rc` below and inserted only
     * AFTER the attestation signature succeeds, so a sign failure (or a
     * cancelled hybrid sign) can never leave a phantom discoverable
     * credential in flash. See the deferred resident_store_insert() after
     * credential_sign(). The slot holds no key material; keys are
     * recovered by re-decrypting the credentialID on demand. */

    /* Public key for the COSE_Key. The P-256 point came out of
     * credential_make's keygen -- re-deriving it here (the old
     * hybrid_public / pqf_p256_derive_public call) cost another scalar
     * multiplication, ~2.4 s from XIP flash in the mixed build. Only the
     * ML-DSA public key still needs deriving, for hybrid. */
    static uint8_t mldsa_pub[PQF_HYBRID_PK_LEN];
    size_t  mldsa_pub_len = 0;
    if (src.alg == PQF_HYBRID_COSE_ALG) {
        /* Routed through the signing core: in the mixed build the
         * keygen behind pub-from-seed needs more heap than core 0's
         * window holds at level 87 (see core1_signer.h). */
        if (core1_mldsa_pub(src.mldsa_seed, mldsa_pub, &mldsa_pub_len) != 0) {
            status = CTAP2_ERR_OTHER; goto done;
        }
    }

    /* authData with attestedCredentialData. Sized for a hybrid COSE
     * key (the ~2 KB ML-DSA pubkey dominates). */
    static uint8_t auth_data[PQF_HYBRID_PK_LEN + 512];
    struct attested_cred ac = {
        .cred_id = cred_id, .cred_id_len = CRED_ID_LEN,
        .alg = src.alg, .pub_x = pub_x, .pub_y = pub_y,
        .mldsa_pub = (src.alg == PQF_HYBRID_COSE_ALG) ? mldsa_pub : NULL,
        .mldsa_pub_len = mldsa_pub_len,
    };
    /* signCount. A resident slot's counter starts at 1 (rc.counter
     * below) and GetAssertion bumps it; a server-side credential has no
     * slot, so GetAssertion signs it with 0. Registration must say the
     * same: 1 here and 0 at every login reads, to a relying party, as a
     * counter that went backwards -- WebAuthn's cloned-key signal -- and
     * a strict RP refuses the login. 0 from the start means "this
     * credential keeps no counter". Same rule as the Rust port. */
    uint32_t sc = want_rk ? 1u : 0u;

    /* Extensions output map, in canonical key order: "credProtect"
     * (echo the stored policy) then "hmac-secret" (ack). Both are
     * optional; emit only the ones the RP requested. cred_random for
     * hmac-secret is derived on demand, never stored. */
    uint8_t ext[64]; size_t ext_len = 0;
    {
        /* credProtect is echoed for every credential, hybrid included.
         * It used to be suppressed on hybrid ones on the grounds that the
         * ML-DSA public key left no room under maxMsgSize -- a claim
         * about a number nothing measured. test_hybrid_msgsize measures
         * it: 5659 bytes against a 7609 ceiling at ML-DSA-65, so the
         * 14-byte echo has ~1950 bytes of headroom. The echo is what
         * tells a relying party using enforceCredentialProtectionPolicy
         * that the policy was applied, and the Rust port emits it since
         * 4ef3c74; this line kept the two ports different. */
        bool out_cp = (exts_in != NULL
                       && map_get_text(exts_in, "credProtect") != NULL);
        unsigned n = (want_cred_blob ? 1u : 0u) + (out_cp ? 1u : 0u)
                     + (want_hmac_secret ? 1u : 0u) + (emit_min_pin ? 1u : 0u);
        if (n > 0) {
            /* Canonical key order (len-then-lex): credBlob(8) <
             * credProtect(11) < hmac-secret(11) < minPinLength(12). */
            cbor_writer_t ew; cbor_w_init(&ew, ext, sizeof ext);
            cbor_w_map_header(&ew, n);
            if (want_cred_blob) {
                cbor_w_text(&ew, "credBlob");
                cbor_w_bool(&ew, cred_blob_accepted);
            }
            if (out_cp) {
                cbor_w_text(&ew, "credProtect");
                cbor_w_uint(&ew, cred_protect);
            }
            if (want_hmac_secret) {
                cbor_w_text(&ew, "hmac-secret");
                cbor_w_bool(&ew, true);
            }
            if (emit_min_pin) {
                uint8_t mpl = flash_store_min_pin_length();
                if (mpl == 0) mpl = PIN_MIN_LENGTH;
                cbor_w_text(&ew, "minPinLength");
                cbor_w_uint(&ew, mpl);
            }
            if (cbor_w_ok(&ew)) ext_len = cbor_w_off(&ew);
        }
    }

    size_t ad_len = build_auth_data(auth_data, sizeof auth_data,
                                    rp_id_hash, true, uv_flag, sc, &ac,
                                    ext_len ? ext : NULL, ext_len);
    if (ad_len == 0) { status = CTAP2_ERR_OTHER; goto done; }

    /* (The user-presence gate ran above, before credential_make.) */

    /* Packed self-attestation over (authData || clientDataHash).
     *
     * ES256 credential: signed with the credential's own key, as usual.
     *
     * Hybrid credential: the FULL dual (ECDSA-DER || ML-DSA) signature,
     * with attStmt.alg == the credential's hybrid COSE alg -- at levels
     * 44 and 65. That is what a relying party is entitled to expect: an
     * attStmt.alg differing from the credential's alg is a PQC
     * downgrade an RP is NOT required to accept, and conformant
     * verifiers refuse it (the conformance suite returns a flag-policy
     * error for exactly this). Since the dual signature fits at these
     * levels, there is no justification for sending anything less.
     *
     * Level 87 is the sole exception, and only because of a hard
     * transport limit: the full dual attStmt there measures 7617 B
     * against the CTAPHID structural ceiling of 7609 B (57 + 128/59 --
     * the 7-bit continuation sequence number caps a message at 128
     * frames), which no buffer size can raise. At 87 alone we fall back
     * to an ECDSA-P256-only self-attestation (alg ES256, ~72 B sig),
     * taking the response to ~2.9 KB; the ~2.6 KB ML-DSA public key
     * still rides in authData, so the credential remains hybrid and
     * ML-DSA still signs every GetAssertion (no public key in that
     * response, so it fits at every level). An RP that wants to accept
     * level-87 registrations must opt into that fallback deliberately.
     *
     * Note the hybrid ECDSA half is NOT reusable for the 87 fallback:
     * hybrid_sign signs SHA-256(LABEL || msg), but packed ES256 must
     * sign SHA-256(authData || clientDataHash) with no label -- so that
     * path is a dedicated ECDSA sign (routed through the signing core;
     * in the mixed build core 0's XIP copy of the EC stack is
     * ~5 s/scalar-mul).
     *
     * Sizes are pinned by test/test_hybrid_msgsize.c, which builds at
     * each level and asserts both the ceiling and which attestation
     * shape that level must emit. */
    static uint8_t to_sign[PQF_HYBRID_PK_LEN + 600];
    if (ad_len + 32 > sizeof to_sign) { status = CTAP2_ERR_OTHER; goto done; }
    memcpy(to_sign, auth_data, ad_len);
    memcpy(to_sign + ad_len, client_data_hash, 32);

    static uint8_t sig[PQF_HYBRID_MAX_SIG];
    size_t sig_len = 0;
    int att_alg = src.alg;
#if PQF_HYBRID_VARIANT == 87
    /* Level 87 only: the dual attStmt overruns CTAPHID by 8 bytes, so
     * downgrade the ATTESTATION (not the credential) to ES256. */
    if (src.alg == PQF_HYBRID_COSE_ALG) {
        uint8_t h[32];
        pqf_sha256(to_sign, ad_len + 32, h);
        if (core1_p256_sign(src.ecdsa_scalar, h, sig, &sig_len) != 0) {
            status = CTAP2_ERR_OTHER; goto done;
        }
        att_alg = COSE_ALG_ES256;
    } else
#endif
    /* 44/65 hybrid, and every ES256 credential: sign with the
     * credential's own algorithm. credential_sign() routes a hybrid
     * source through core1_hybrid_sign (LABEL applied internally), so
     * attStmt.alg stays equal to the credential's alg. */
    if (credential_sign(&src, to_sign, ad_len + 32, sig, &sig_len) != 0) {
        status = CTAP2_ERR_OTHER; goto done;
    }

    /* Index the credential for discoverability ONLY when rk=true (the
     * residentKey option, CTAP 2.1 sec. 6.1). Deferred to AFTER the
     * signature succeeds (#22): committing the slot before signing would
     * leave a phantom discoverable credential in flash if the sign fails
     * (or a hybrid sign is cancelled), even though the RP is told the
     * registration failed. A server-side credential (rk absent / false)
     * stays fully recoverable statelessly from its credentialID and must
     * NOT consume one of the finite resident slots. When rk=true and the
     * store is full (no free slot and no matching (rp_id_hash, user.id)
     * to replace), refuse with CTAP2_ERR_KEY_STORE_FULL (0x28) rather
     * than evicting a still-valid credential (reported post-sign, which
     * is acceptable since no signature is returned on that error). The
     * slot holds no key material; keys are recovered by re-decrypting the
     * credentialID on demand. counter starts at 1 (matches authData). */
    if (want_rk) {
        resident_cred_t rc;
        memset(&rc, 0, sizeof rc);
        memcpy(rc.cred_id, cred_id, CRED_ID_LEN);
        memcpy(rc.rp_id_hash, rp_id_hash, 32);
        /* Persist the UTF-8 rp.id so CredentialManagement enumerateRPs
         * can return a human-readable id (F4); clamp to the slot cap. */
        {
            size_t rl = pqfido_cbor_string_len(rp_id);
            if (rl > RES_RP_ID_MAX) rl = RES_RP_ID_MAX;
            memcpy(rc.rp_id, pqfido_cbor_string(rp_id), rl);
            rc.rp_id_len = (uint8_t)rl;
        }
        rc.counter = 1;
        rc.cred_protect = cred_protect;
        rc.user_id_len = user_id_len;
        memcpy(rc.user_id, user_id, user_id_len);
        rc.user_name_len = user_name_len;
        memcpy(rc.user_name, user_name, user_name_len);
        rc.user_display_name_len = user_disp_len;
        memcpy(rc.user_display_name, user_disp, user_disp_len);
        if (cred_blob_accepted) {
            rc.cred_blob_len = cred_blob_len_in;
            memcpy(rc.cred_blob, cred_blob_in, cred_blob_len_in);
        }
        /* creation_order assigned by insert. A full store with no slot
         * to replace fails the registration (KEY_STORE_FULL). */
        if (resident_store_insert(&rc) != 0) {
            status = CTAP2_ERR_KEY_STORE_FULL;
            goto done;
        }
    }

    /* Response map { 1: "packed", 2: authData, 3: attStmt }. The
     * attStmt alg matches the attestation signature above: the
     * credential's algorithm for ES256, ES256 for hybrid (size-capped
     * self-attestation -- see the comment at the sign). */
    /* largeBlobKey (CTAP 2.1 sec. 6.1.5): a 32-byte per-credential key
     * derived deterministically from the credentialID, returned at the
     * top of the response (key 0x05), NOT in authData extensions. */
    uint8_t lbk[32];
    if (want_lbk)
        credential_large_blob_key(cred_id, CRED_ID_LEN, lbk);

    resp[0] = CTAP2_OK;
    cbor_writer_t w;
    cbor_w_init(&w, &resp[1], resp_cap - 1);
    cbor_w_map_header(&w, want_lbk ? 4 : 3);
    cbor_w_uint(&w, 0x01);
    cbor_w_text(&w, "packed");
    cbor_w_uint(&w, 0x02);
    cbor_w_bytes(&w, auth_data, ad_len);
    cbor_w_uint(&w, 0x03);
    cbor_w_map_header(&w, 2);                 /* attStmt { alg, sig } */
    cbor_w_text(&w, "alg");
    cbor_w_int(&w, att_alg);
    cbor_w_text(&w, "sig");
    cbor_w_bytes(&w, sig, sig_len);
    if (want_lbk) {
        cbor_w_uint(&w, 0x05);
        cbor_w_bytes(&w, lbk, 32);
    }

    if (!cbor_w_ok(&w)) { status = CTAP2_ERR_OTHER; goto done; }
    *resp_len = 1 + cbor_w_off(&w);
    pqfido_cbor_free(root);
    return 0;

done:
    resp[0] = (uint8_t)status;
    *resp_len = 1;
    pqfido_cbor_free(root);
    return 0;
}

/* ---- GetAssertion / GetNextAssertion shared state + emitter ---- */

/* Stateful iterator for a username-less (no-allowList) GetAssertion
 * that matched more than one resident credential. The first match is
 * returned by GetAssertion; the platform pulls the rest with
 * authenticatorGetNextAssertion (CTAP 2.1 sec. 6.3), which re-signs the
 * same clientDataHash under each remaining credential in turn.
 *
 * Unlike the Rust base we don't impose the 30-second stateful-command
 * timeout here: ctap2_dispatch has no wall-clock parameter, so instead
 * we invalidate the iterator on any command other than
 * GetNextAssertion (see the reset in ctap2_dispatch). It holds only
 * slot indices + the clientDataHash + rpIdHash -- no key material. */
static uint32_t s_current_cid;

void ctap2_set_cid(uint32_t cid)
{
    s_current_cid = cid;
}

static struct {
    bool     active;
    uint32_t cid;                   /* channel that began the ceremony */
    size_t   remaining[RESIDENT_MAX_SLOTS];
    size_t   remaining_n;
    size_t   next;
    uint8_t  client_data_hash[32];
    uint8_t  rp_id_hash[32];
    bool     up_flag;               /* UP the originating GA's gate verified */
    uint8_t  uv_flag;
    uint32_t total;                 /* numberOfCredentials reported */
} s_assert_iter;

static void assert_iter_reset(void)
{
    memset(&s_assert_iter, 0, sizeof s_assert_iter);
}

/* Build authData + sign + emit one assertion response. `src` is the
 * recovered credential; `chosen_cred`/`len` the credentialID echoed in
 * 0x01; when `has_slot`, `slot_idx` backs the bumped per-credential
 * counter + the user handle (0x04). `ext`/`ext_len` is the optional
 * authData extension output (GetAssertion hmac-secret). `num_creds`>0
 * emits numberOfCredentials (0x05). Returns 0 / <0. */
static int emit_assertion(credential_source_t *src,
                          const uint8_t *chosen_cred, size_t chosen_cred_len,
                          bool has_slot, size_t slot_idx,
                          bool up, uint8_t uv_flag,
                          const uint8_t rp_id_hash[32],
                          const uint8_t client_data_hash[32],
                          const uint8_t *ext, size_t ext_len,
                          uint32_t num_creds, const uint8_t *lbk,
                          uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    static uint8_t auth_data[256];
    /* Per-credential counter (bumped + persisted) for a resident
     * credential; 0 for a purely stateless one -- both legal per
     * WebAuthn sec. 6.1.1. */
    uint32_t sc = has_slot ? resident_store_bump_counter(slot_idx) : 0;

    size_t ad_len = build_auth_data(auth_data, sizeof auth_data,
                                    rp_id_hash, up, uv_flag, sc, NULL,
                                    ext_len ? ext : NULL, ext_len);
    if (ad_len == 0) return -1;

    static uint8_t to_sign[320];
    if (ad_len + 32 > sizeof to_sign) return -1;
    memcpy(to_sign, auth_data, ad_len);
    memcpy(to_sign + ad_len, client_data_hash, 32);

    static uint8_t sig[PQF_HYBRID_MAX_SIG];
    size_t sig_len = 0;
    if (credential_sign(src, to_sign, ad_len + 32, sig, &sig_len) != 0)
        return -1;

    /* Resident credential -> surface the user handle (id only) so a
     * discoverable login can complete. */
    resident_cred_t rc_out;
    bool have_user = has_slot
                     && resident_store_get(slot_idx, &rc_out) == 0
                     && rc_out.user_id_len > 0;

    resp[0] = CTAP2_OK;
    cbor_writer_t w;
    cbor_w_init(&w, &resp[1], resp_cap - 1);
    unsigned n = 3u + (have_user ? 1u : 0u) + (num_creds > 0 ? 1u : 0u)
                 + (lbk ? 1u : 0u);
    cbor_w_map_header(&w, n);
    cbor_w_uint(&w, 0x01);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "id");
    cbor_w_bytes(&w, chosen_cred, chosen_cred_len);
    cbor_w_text(&w, "type");
    cbor_w_text(&w, "public-key");
    cbor_w_uint(&w, 0x02);
    cbor_w_bytes(&w, auth_data, ad_len);
    cbor_w_uint(&w, 0x03);
    cbor_w_bytes(&w, sig, sig_len);
    if (have_user) {
        cbor_w_uint(&w, 0x04);
        cbor_w_map_header(&w, 1);
        cbor_w_text(&w, "id");
        cbor_w_bytes(&w, rc_out.user_id, rc_out.user_id_len);
    }
    if (num_creds > 0) {
        cbor_w_uint(&w, 0x05);
        cbor_w_uint(&w, num_creds);
    }
    if (lbk) {                                 /* largeBlobKey (sec. 6.10) */
        cbor_w_uint(&w, 0x07);
        cbor_w_bytes(&w, lbk, 32);
    }
    if (!cbor_w_ok(&w)) return -1;
    *resp_len = 1 + cbor_w_off(&w);
    return 0;
}

/* authenticatorGetNextAssertion (CTAP 2.1 sec. 6.3) -- pop the next
 * pre-staged resident credential and re-sign the originating
 * clientDataHash. ERR_NOT_ALLOWED if no iterator is active. */
static int emit_get_next_assertion(uint8_t *resp, size_t resp_cap,
                                   size_t *resp_len)
{
    /* Wrong channel is the same refusal as no ceremony. Answering
     * differently would tell a second host that another one is mid-way
     * through an assertion, which is itself information. */
    if (!s_assert_iter.active
        || s_assert_iter.cid != s_current_cid
        || s_assert_iter.next >= s_assert_iter.remaining_n) {
        s_assert_iter.active = false;
        resp[0] = CTAP2_ERR_NOT_ALLOWED;
        *resp_len = 1;
        return 0;
    }
    size_t slot = s_assert_iter.remaining[s_assert_iter.next++];
    resident_cred_t rc;
    credential_source_t src;
    if (resident_store_get(slot, &rc) != 0
        || credential_recover(rc.cred_id, CRED_ID_LEN,
                              s_assert_iter.rp_id_hash, &src) != 0) {
        resp[0] = CTAP2_ERR_NO_CREDENTIALS;
        *resp_len = 1;
        return 0;
    }
    static uint8_t next_cred_id[CRED_ID_LEN];
    memcpy(next_cred_id, rc.cred_id, CRED_ID_LEN);
    /* GetNextAssertion responses carry no extensions and no
     * numberOfCredentials (CTAP 2.1 sec. 6.3). */
    int er = emit_assertion(&src, next_cred_id, CRED_ID_LEN, true, slot,
                            s_assert_iter.up_flag, s_assert_iter.uv_flag,
                            s_assert_iter.rp_id_hash,
                            s_assert_iter.client_data_hash, NULL, 0, 0, NULL,
                            resp, resp_cap, resp_len);
    memset(&src, 0, sizeof src);
    if (er != 0) { resp[0] = CTAP2_ERR_OTHER; *resp_len = 1; }
    if (s_assert_iter.next >= s_assert_iter.remaining_n)
        s_assert_iter.active = false;
    return 0;
}

/* ---- authenticatorGetAssertion (CTAP 2.1 sec. 6.2) ----------------- */

static int handle_get_assertion(const uint8_t *params, size_t params_len,
                                uint8_t *resp, size_t resp_cap,
                                size_t *resp_len)
{
    pqfido_cbor_item_t *root = NULL;
    if (pqfido_cbor_decode(params, params_len, &root) != PQFIDO_OK) {
        resp[0] = CTAP2_ERR_INVALID_CBOR;
        *resp_len = 1;
        return 0;
    }

    int status = CTAP2_ERR_OTHER;

    const pqfido_cbor_item_t *rp_id = map_get_uint(root, 0x01);
    const pqfido_cbor_item_t *cdh   = map_get_uint(root, 0x02);
    const pqfido_cbor_item_t *allow = map_get_uint(root, 0x03);

    if (rp_id == NULL || !pqfido_cbor_is_string(rp_id)
        || cdh == NULL || !pqfido_cbor_is_bytes(cdh)
        || pqfido_cbor_bytes_len(cdh) != 32) {
        status = CTAP2_ERR_MISSING_PARAMETER;
        goto done;
    }

    uint8_t rp_id_hash[32];
    pqf_sha256(pqfido_cbor_string(rp_id),
               pqfido_cbor_string_len(rp_id), rp_id_hash);
    const uint8_t *client_data_hash = pqfido_cbor_bytes(cdh);

    /* options map (key 0x05): up / uv (CTAP 2.1 sec. 6.2). Defaults: up =
     * true, uv = false. up=false performs a silent assertion -- no user
     * presence is solicited and the UP flag in authData is cleared
     * (browser pre-flight / conditional mediation). up_requested only
     * decides whether the gate below runs; the UP bit signed, and the
     * one GetNextAssertion inherits, is up_verified -- what the gate
     * established. An explicit uv=true that no verification can satisfy
     * is rejected below, after the PIN/UV gating. */
    const pqfido_cbor_item_t *opts = map_get_uint(root, 0x05);
    bool up_requested = (option_bool(opts, "up") != 0);   /* default true */
    bool up_verified = false;
    int opt_uv = option_bool(opts, "uv");

    /* PIN/UV gating (CTAP 2.1 sec. 6.2) -- done first so credProtect can key
     * off whether the request is user-verified. A PIN being set does NOT
     * force UV on GetAssertion: a normal assertion proceeds on
     * user-presence (touch) alone, like a YubiKey. We only VERIFY a
     * supplied pinUvAuthParam; we do NOT refuse when one is absent. The
     * cases that genuinely require UV are enforced below and unchanged:
     * alwaysUv, an explicit uv=true, and credProtect level 2/3 all check
     * uv_flag and reject when it's 0.
     *
     * (A prior revision returned PUAT_REQUIRED for an absent param once
     * a PIN existed, forcing the full UV flow on every authentication --
     * the "hijacking" difference from a YubiKey.)
     *
     * With a param present (0x06 / protocol 0x07): missing/unknown
     * protocol, no token, wrong permission/scope, or MAC mismatch -> 0x33
     * PIN_AUTH_INVALID (never 0x36). Chrome's silent probe (param = h'',
     * protocol = 1) is "present", lands in the verify-fail path, gets
     * 0x33, and stays surfaced in the picker. */
    uint8_t uv_flag = 0;
    if (client_pin_is_set()) {
        const pqfido_cbor_item_t *puap = map_get_uint(root, 0x06);
        const pqfido_cbor_item_t *prot = map_get_uint(root, 0x07);
        if (puap != NULL && pqfido_cbor_is_bytes(puap)) {
            if (prot == NULL || !pqfido_cbor_is_uint(prot)
                || (pqfido_cbor_uint(prot) != PIN_PROTOCOL_V1
                    && pqfido_cbor_uint(prot) != PIN_PROTOCOL_V2)) {
                status = CTAP2_ERR_PIN_AUTH_INVALID;
                goto done;
            }
            int pe = client_pin_verify_token(pqfido_cbor_bytes(puap),
                                             pqfido_cbor_bytes_len(puap),
                                             (uint8_t)pqfido_cbor_uint(prot),
                                             client_data_hash, 32,
                                             PIN_PERM_GET_ASSERTION, rp_id_hash);
            if (pe != 0) {
                status = CTAP2_ERR_PIN_AUTH_INVALID;
                goto done;
            }
            uv_flag = AD_FLAG_UV;
        }
    }

    /* alwaysUv (CTAP 2.1 sec. 6.11.4): require user verification for every
     * assertion when the device-wide policy is on. */
    if (flash_store_always_uv() && uv_flag == 0) {
        status = CTAP2_ERR_PUAT_REQUIRED;
        goto done;
    }

    /* Explicit options.uv = true with no user verification performed.
     * The status distinguishes two situations the client acts on
     * differently, matching the Rust port: with no PIN set there is no
     * user-verification method on this hardware at all, so the request
     * can never be satisfied (UNSUPPORTED_OPTION); with a PIN set the
     * client simply has to fetch a token first, and PUAT_REQUIRED is
     * the retriable code that says so. This port answered
     * INVALID_OPTION for both, which tells a platform to give up in the
     * case where it should have prompted for the PIN. */
    if (opt_uv == 1 && uv_flag == 0) {
        status = client_pin_is_set() ? CTAP2_ERR_PUAT_REQUIRED
                                     : CTAP2_ERR_UNSUPPORTED_OPTION;
        goto done;
    }

    /* Locate the credential to assert with, plus the resident slot
     * backing it (for the per-credential counter + user handle):
     *
     *   allowList present -> recover each entry; the first that
     *     decrypts (and isn't a hidden credProtect-3 cred without UV)
     *     wins. If it's also in the resident index, use that slot.
     *   allowList absent  -> discover resident credentials for this RP
     *     (rk / passkeys), most-recent first.
     *
     * credProtect gating (CTAP 2.1 sec. 12.1.1): level 3 needs UV in both
     * paths; level 2 additionally needs UV in the no-allowList path
     * (userVerificationOptionalWithCredentialIDList). */
    credential_source_t src;
    const uint8_t *chosen_cred = NULL;
    size_t chosen_cred_len = 0;
    bool found = false;
    size_t slot_idx = 0;
    bool has_slot = false;
    static uint8_t resident_cred_id[CRED_ID_LEN];
    /* Discovery's matches, newest first. passing[1..np) is what
     * GetNextAssertion will walk -- but only once this assertion has
     * been signed; see the commit after emit_assertion(). */
    size_t passing[RESIDENT_MAX_SLOTS];
    size_t np = 0;

    /* CTAP 2.1 sec. 6.2 branches on whether the PARAMETER is present. A
     * present allowList that is not an array is a malformed request,
     * not an absent parameter -- reading it as absent sent the token
     * into discoverable-credential selection and had it sign with
     * whichever resident credential it held for the rpId, which is the
     * wrong-account substitution the allowList exists to prevent. An
     * empty array IS "not present and non-empty" per the spec text, so
     * that one still falls through to discovery. */
    if (allow != NULL && !pqfido_cbor_is_array(allow)) {
        status = CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        goto done;
    }
    bool have_allow = pqfido_cbor_is_array(allow)
                      && pqfido_cbor_array_size(allow) > 0;

    if (have_allow) {
        size_t n = pqfido_cbor_array_size(allow);
        for (size_t i = 0; i < n && !found; i++) {
            const pqfido_cbor_item_t *e = pqfido_cbor_array_get(allow, i);
            const pqfido_cbor_item_t *id = map_get_text(e, "id");
            if (id == NULL || !pqfido_cbor_is_bytes(id))
                continue;
            const uint8_t *cid = pqfido_cbor_bytes(id);
            size_t clen = pqfido_cbor_bytes_len(id);
            if (credential_recover(cid, clen, rp_id_hash, &src) != 0)
                continue;
            if (src.cred_protect == 3 && uv_flag == 0)
                continue;   /* level 3 needs UV -- hide it */
            chosen_cred = cid;
            chosen_cred_len = clen;
            if (resident_store_find_by_cred_id(cid, clen, &slot_idx) == 0)
                has_slot = true;
            found = true;
        }
    } else {
        /* No allowList -- discover resident credentials for this RP,
         * most-recent first. credProtect levels 2/3 are hidden without
         * UV (gated on the slot's stored policy -- no decrypt needed).
         * The newest match is returned now; any remainder is kept for
         * GetNextAssertion and counted in numberOfCredentials. */
        size_t idxs[RESIDENT_MAX_SLOTS];
        size_t nm = resident_store_find_by_rp(rp_id_hash, idxs,
                                              RESIDENT_MAX_SLOTS);
        /* find_by_rp returns the total match count, documented as
         * possibly exceeding `cap`; only `cap` indices were written.
         * Clamp so the reverse-index loop below can never read past
         * idxs[RESIDENT_MAX_SLOTS]. */
        if (nm > RESIDENT_MAX_SLOTS) nm = RESIDENT_MAX_SLOTS;
        for (size_t k = 0; k < nm; k++) {
            size_t cand = idxs[nm - 1 - k];   /* reverse -> newest first */
            resident_cred_t rc;
            if (resident_store_get(cand, &rc) != 0) continue;
            if (rc.cred_protect >= 2 && uv_flag == 0) continue;
            passing[np++] = cand;
        }
        if (np > 0) {
            resident_cred_t rc0;
            if (resident_store_get(passing[0], &rc0) == 0
                && credential_recover(rc0.cred_id, CRED_ID_LEN,
                                      rp_id_hash, &src) == 0) {
                memcpy(resident_cred_id, rc0.cred_id, CRED_ID_LEN);
                chosen_cred = resident_cred_id;
                chosen_cred_len = CRED_ID_LEN;
                slot_idx = passing[0];
                has_slot = true;
                found = true;
            }
        }
    }

    if (!found) {
        status = CTAP2_ERR_NO_CREDENTIALS;
        goto done;
    }

    /* hmac-secret extension (CTAP 2.1 sec. 11.2). The RP sends, under
     * extensions key 0x06 -> "hmac-secret", a map { 1: keyAgreement
     * COSE, 2: saltEnc, 3: saltAuth, 4?: pinProtocol }. We derive the
     * shared secret from our keyAgreement key, verify saltAuth,
     * decrypt the salt(s), compute HMAC(cred_random, salt) for each,
     * and return the outputs encrypted under the shared secret. */
    uint8_t ext[160]; size_t ext_len = 0;
    /* GetAssertion extensions are request key 0x04 (0x06 is
     * pinUvAuthParam here -- unlike MakeCredential, where extensions
     * are 0x06). */
    const pqfido_cbor_item_t *exts = map_get_uint(root, 0x04);

    /* credBlob (CTAP 2.1 sec. 12.4): when requested, return the blob stored
     * with this credential (empty bytes if none / non-resident). */
    bool emit_cred_blob = (exts && map_get_text(exts, "credBlob") != NULL);
    uint8_t cred_blob_out[RES_CRED_BLOB_MAX]; size_t cred_blob_out_len = 0;
    if (emit_cred_blob && has_slot) {
        resident_cred_t rcb;
        if (resident_store_get(slot_idx, &rcb) == 0 && rcb.cred_blob_len) {
            cred_blob_out_len = rcb.cred_blob_len;
            memcpy(cred_blob_out, rcb.cred_blob, cred_blob_out_len);
        }
    }

    /* hmac-secret (CTAP 2.1 sec. 11.2): derive the shared secret from our
     * keyAgreement key, verify saltAuth, decrypt the salt(s), compute
     * HMAC(cred_random, salt) per salt, encrypt the outputs. */
    uint8_t hmac_enc[80]; size_t hmac_enc_len = 0;
    bool emit_hmac = false;
    const pqfido_cbor_item_t *hs = exts ? map_get_text(exts, "hmac-secret")
                                        : NULL;
    if (hs != NULL && pqfido_cbor_is_map(hs)) {
        const pqfido_cbor_item_t *ka  = map_get_uint(hs, 1);
        const pqfido_cbor_item_t *se  = map_get_uint(hs, 2);
        const pqfido_cbor_item_t *sa  = map_get_uint(hs, 3);
        const pqfido_cbor_item_t *hpr = map_get_uint(hs, 4);
        uint8_t kx[32], ky[32];
        if (ka && se && sa && pqfido_cbor_is_bytes(se)
            && pqfido_cbor_is_bytes(sa) && cbor_cose_ec2_xy(ka, kx, ky)) {
            uint8_t hproto = (hpr && pqfido_cbor_is_uint(hpr))
                             ? (uint8_t)pqfido_cbor_uint(hpr) : PIN_PROTOCOL_V1;
            pin_shared_secret_t ss;
            size_t se_len = pqfido_cbor_bytes_len(se);
            const uint8_t *se_b = pqfido_cbor_bytes(se);
            /* saltEnc must be a legal length BEFORE we decrypt it into the
             * fixed salts[] buffer, so an over-length ciphertext can't
             * overrun it: v1 carries 1-2 raw 32-B salts (32/64 B); v2
             * prepends a 16-B IV (48/80 B). */
            bool se_ok = (hproto == PIN_PROTOCOL_V2)
                            ? (se_len == 48 || se_len == 80)
                            : (se_len == 32 || se_len == 64);
            if (client_pin_shared_secret(hproto, kx, ky, &ss) == 0
                && se_ok
                && pin_verify(&ss, se_b, se_len,
                              pqfido_cbor_bytes(sa), pqfido_cbor_bytes_len(sa))) {
                uint8_t salts[64]; size_t salts_len = 0;
                if (pin_decrypt(&ss, se_b, se_len, salts, sizeof salts,
                                &salts_len) == 0
                    && (salts_len == 32 || salts_len == 64)) {
                    uint8_t cred_random[32];
                    credential_cred_random(chosen_cred, chosen_cred_len,
                                           uv_flag != 0, cred_random);
                    /* outputs = HMAC(cred_random, salt_i) per 32-B salt. */
                    uint8_t outs[64];
                    for (size_t off = 0; off < salts_len; off += 32)
                        pqf_hmac_sha256(cred_random, 32, salts + off, 32,
                                        outs + off);
                    if (pin_encrypt(&ss, outs, salts_len, hmac_enc,
                                    &hmac_enc_len) == 0)
                        emit_hmac = true;
                    memset(cred_random, 0, sizeof cred_random);
                }
            }
        }
    }

    /* Extensions output map, canonical key order: credBlob(8) <
     * hmac-secret(11). */
    if (emit_cred_blob || emit_hmac) {
        cbor_writer_t ew; cbor_w_init(&ew, ext, sizeof ext);
        cbor_w_map_header(&ew, (emit_cred_blob ? 1u : 0u) + (emit_hmac ? 1u : 0u));
        if (emit_cred_blob) {
            cbor_w_text(&ew, "credBlob");
            cbor_w_bytes(&ew, cred_blob_out, cred_blob_out_len);
        }
        if (emit_hmac) {
            cbor_w_text(&ew, "hmac-secret");
            cbor_w_bytes(&ew, hmac_enc, hmac_enc_len);
        }
        if (cbor_w_ok(&ew)) ext_len = cbor_w_off(&ew);
    }

    /* User-presence gate (CTAP 2.1 sec. 6.2.2). Only the initial
     * GetAssertion solicits UP, and only when up=true (a silent
     * up=false assertion skips it and clears the flag). GetNextAssertion
     * reuses this decision via the stored iterator and must NOT
     * re-solicit -- hence the gate lives here, not in the shared
     * emit_assertion(). A credential has already been selected at this
     * point, so we never solicit UP just to then report "no
     * credentials". Timeout -> 0x27, matching the Rust port. */
    if (up_requested) {
        status = require_user_presence();
        if (status != CTAP2_OK) { memset(&src, 0, sizeof src); goto done; }
        up_verified = true;
    }

    /* Emit the assertion via the shared signer. A no-allowList
     * discovery that matched more than one credential reports the
     * count (numberOfCredentials) and, once this is signed, arms the
     * iterator for GetNextAssertion. */
    /* largeBlobKey (sec. 6.2.5): return the deterministic per-credential
     * key (response 0x07) ONLY when the RP requested it (CTAP 2.1 sec. 12.3
     * boolean extension -- value must be true, not mere key presence,
     * #23) AND the matched credential was registered with the
     * largeBlobKey extension. The minted-with-largeBlobKey bit travels in
     * the credentialID (src.large_blob_key), so the gate holds for
     * resident AND non-resident (allowList) creds alike (#14); emitting
     * it for credentials created without the extension would be a
     * per-credential key over-disclosure (L11). Derived from the
     * credentialID. */
    uint8_t lbk[32]; const uint8_t *lbk_p = NULL;
    {
        const pqfido_cbor_item_t *lbk_in = exts
            ? map_get_text(exts, "largeBlobKey") : NULL;
        bool want_lbk_out = (lbk_in != NULL && pqfido_cbor_is_bool(lbk_in)
                             && pqfido_cbor_bool(lbk_in));
        if (want_lbk_out && src.large_blob_key) {
            credential_large_blob_key(chosen_cred, chosen_cred_len, lbk);
            lbk_p = lbk;
        }
    }
    uint32_t num_creds = (np > 1) ? (uint32_t)np : 0;
    int er = emit_assertion(&src, chosen_cred, chosen_cred_len,
                            has_slot, slot_idx, up_verified, uv_flag,
                            rp_id_hash, client_data_hash,
                            ext_len ? ext : NULL, ext_len,
                            num_creds, lbk_p, resp, resp_cap, resp_len);
    memset(&src, 0, sizeof src);
    if (er != 0) { status = CTAP2_ERR_OTHER; goto done; }

    /* Arm GetNextAssertion only now, with the assertion it continues
     * signed, and with the flags of the checks that completed. It used
     * to be armed at discovery, before the presence gate, with UP copied
     * from the request: a touch that timed out answered 0x27 and left
     * it armed, and a GetNextAssertion sent straight after on the same
     * channel signed the next credential with UP set although nobody had
     * touched the token. Every `goto done` above leaves it as
     * ctap2_dispatch reset it. */
    if (np > 1) {
        s_assert_iter.active = true;
        s_assert_iter.cid = s_current_cid;
        s_assert_iter.total = (uint32_t)np;
        s_assert_iter.remaining_n = np - 1;
        s_assert_iter.next = 0;
        for (size_t i = 1; i < np; i++)
            s_assert_iter.remaining[i - 1] = passing[i];
        memcpy(s_assert_iter.client_data_hash, client_data_hash, 32);
        memcpy(s_assert_iter.rp_id_hash, rp_id_hash, 32);
        s_assert_iter.up_flag = up_verified;
        s_assert_iter.uv_flag = uv_flag;
    }
    pqfido_cbor_free(root);
    return 0;

done:
    resp[0] = (uint8_t)status;
    *resp_len = 1;
    pqfido_cbor_free(root);
    return 0;
}

/* ---- authenticatorGetInfo (CTAP 2.1 sec. 6.4) ---------------------- */

static int build_get_info_response(uint8_t *resp, size_t resp_cap,
                                   size_t *resp_len)
{
    if (resp_cap < 1) return -1;
    resp[0] = CTAP2_OK;

    cbor_writer_t w;
    cbor_w_init(&w, &resp[1], resp_cap - 1);

    /* Effective minPINLength: the AuthenticatorConfig override, or the
     * built-in default when unset. */
    uint8_t min_pin = flash_store_min_pin_length();
    if (min_pin == 0) min_pin = PIN_MIN_LENGTH;

    /* Top-level map, keys in canonical ascending order: 0x01..0x10, 0x14. */
    cbor_w_map_header(&w, 17);

    /* 0x01 versions -- advertise BOTH FIDO_2_0 and FIDO_2_1. We
     * implement the 2.1 feature surface a platform relies on
     * (pinUvAuthToken w/ permissions, full credMgmt, authnrCfg,
     * largeBlobs, setMinPINLength, makeCredUvNotRqd, and the
     * authenticatorSelection 0x0B touch-to-choose command), so the
     * claim is honest. This is load-bearing for passkeys: Chrome/macOS
     * route discoverable-credential ceremonies through the modern 2.1
     * path for 2.1 authenticators but a legacy security-key path for
     * 2.0-only devices -- the legacy path is the forceful flow that reads
     * as "hijacking". A getInfo diff against a YubiKey (which advertises
     * 2.1 with the same feature scope) surfaced this as the divergence. */
    cbor_w_uint(&w, 0x01);
    cbor_w_array_header(&w, 2);
    cbor_w_text(&w, "FIDO_2_0");
    cbor_w_text(&w, "FIDO_2_1");

    cbor_w_uint(&w, 0x02);                    /* extensions */
    cbor_w_array_header(&w, 5);               /* canonical len-then-lex */
    cbor_w_text(&w, "credBlob");              /* 8  */
    cbor_w_text(&w, "credProtect");           /* 11 */
    cbor_w_text(&w, "hmac-secret");           /* 11 */
    cbor_w_text(&w, "largeBlobKey");          /* 12 -- l < m */
    cbor_w_text(&w, "minPinLength");          /* 12 */

    cbor_w_uint(&w, 0x03);                    /* aaguid */
    cbor_w_bytes(&w, k_aaguid, sizeof k_aaguid);

    /* 0x04 options, canonical key order (length-then-lex):
     *   "rk"(2) < "up"(2) < "plat"(4) < "alwaysUv"(8) < "credMgmt"(8) <
     *   "authnrCfg"(9) < "clientPin"(9) < "largeBlobs"(10) <
     *   "pinUvAuthToken"(14) < "setMinPINLength"(15).
     * (An earlier revision miscounted the last two keys' lengths and
     * emitted them swapped -- libfido2 tolerated it, python-fido2's
     * canonical-CBOR check rejected the whole getInfo.)
     * alwaysUv reflects the persisted AuthenticatorConfig state;
     * clientPin reflects whether a PIN is currently set.
     *
     * "ep" (enterprise attestation) is NOT advertised (#29): this device
     * only does self-attestation (no batch/individual attestation key is
     * provisioned and MakeCredential never emits epAtt), so advertising
     * "ep" would mis-signal an enterprise-attestation guarantee we can't
     * honour. authenticatorConfig 0x01 still stores the advisory bit but
     * it has no protocol-visible effect.
     *
     * "pinUvAuthToken": true (#30) -- we implement
     * getPinUvAuthTokenUsingPinWithPermissions (ClientPIN 0x09), so per
     * CTAP 2.1 sec. 6.4 a spec-strict platform keys off this to use the
     * permission-scoped token flow instead of the legacy all-permissions
     * token. "setMinPINLength": true (#31) -- we implement
     * authenticatorConfig setMinPINLength (0x03). */
    cbor_w_uint(&w, 0x04);
    cbor_w_map_header(&w, 11);
    cbor_w_text(&w, "rk");        cbor_w_bool(&w, true);   /* discoverable creds */
    cbor_w_text(&w, "up");        cbor_w_bool(&w, true);
    cbor_w_text(&w, "plat");      cbor_w_bool(&w, false);
    cbor_w_text(&w, "alwaysUv");  cbor_w_bool(&w, flash_store_always_uv());
    cbor_w_text(&w, "credMgmt");  cbor_w_bool(&w, true);
    cbor_w_text(&w, "authnrCfg"); cbor_w_bool(&w, true);
    cbor_w_text(&w, "clientPin"); cbor_w_bool(&w, client_pin_is_set());
    cbor_w_text(&w, "largeBlobs"); cbor_w_bool(&w, true);
    cbor_w_text(&w, "pinUvAuthToken");  cbor_w_bool(&w, true);
    cbor_w_text(&w, "setMinPINLength"); cbor_w_bool(&w, true);
    /* makeCredUvNotRqd (16 chars) sorts LAST in canonical CBOR order
     * (longest key). A non-discoverable credential may be created with
     * user-presence only even when a PIN is set -- see the gate in
     * handle_make_credential. */
    cbor_w_text(&w, "makeCredUvNotRqd"); cbor_w_bool(&w, true);

    cbor_w_uint(&w, 0x05);                    /* maxMsgSize */
    cbor_w_uint(&w, CTAP2_MAX_RESPONSE);

    cbor_w_uint(&w, 0x06);                    /* pinUvAuthProtocols */
    cbor_w_array_header(&w, 2);
    cbor_w_uint(&w, 1);
    cbor_w_uint(&w, 2);

    cbor_w_uint(&w, 0x07);                    /* maxCredentialCountInList */
    cbor_w_uint(&w, 8);

    cbor_w_uint(&w, 0x08);                    /* maxCredentialIdLength */
    cbor_w_uint(&w, CRED_ID_LEN);

    cbor_w_uint(&w, 0x09);                    /* transports */
    cbor_w_array_header(&w, 1);
    cbor_w_text(&w, "usb");

    /* 0x0a algorithms -- advertise ALL three composite hybrid variants
     * (-56 MLDSA87-ES384, -55 MLDSA65-ES256, -54 MLDSA44-ES256) plus
     * ES256, regardless of which variant this build implements --
     * matching the Rust base, which emits the same four in the same
     * order. Chrome intersects the RP's pubKeyCredParams with this
     * list BEFORE sending any CTAP frame; an empty intersection is a
     * silent kNoCommonAlgorithms failure, so over-advertising is what
     * keeps a PQC-only RP reachable from an arbitrarily-configured
     * build. The MakeCredential picker still only mints this build's
     * variant or ES256; a request for one of the other two composite
     * ids falls through to ES256, or to
     * CTAP2_ERR_UNSUPPORTED_ALGORITHM if the RP offered no fallback.
     * That trade -- a visible MakeCredential error instead of an
     * invisible browser-side exclusion -- is the whole point.
     *
     * These MUST be the ids pick_alg() and emit_cose() actually use.
     * They previously read -50/-49/-48 -- the RFC 9964 *pure* ML-DSA
     * code points, left behind when the construction was relabelled to
     * the composite ids. A host that trusted getInfo then asked for a
     * pure id, pick_alg refused it, and every registration silently
     * degraded to ES256, which is to say the PQC path was unreachable
     * from any conformant host. */
    cbor_w_uint(&w, 0x0a);
    cbor_w_array_header(&w, 4);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg");  cbor_w_int(&w, COSE_ALG_MLDSA87_ES384);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg");  cbor_w_int(&w, COSE_ALG_MLDSA65_ES256);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg");  cbor_w_int(&w, COSE_ALG_MLDSA44_ES256);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "alg");  cbor_w_int(&w, COSE_ALG_ES256);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");

    cbor_w_uint(&w, 0x0b);                    /* maxSerializedLargeBlobArray */
    cbor_w_uint(&w, MAX_LARGE_BLOB_LEN);

    cbor_w_uint(&w, 0x0c);                    /* forcePINChange (X13) */
    /* Reflect the persisted force_pin_change flag: set by
     * authenticatorConfig setMinPINLength's forceChangePin, cleared by a
     * successful changePIN (#34). */
    cbor_w_bool(&w, flash_store_force_pin_change());

    cbor_w_uint(&w, 0x0d);                    /* minPINLength */
    cbor_w_uint(&w, min_pin);

    cbor_w_uint(&w, 0x0e);                    /* firmwareVersion */
    cbor_w_uint(&w, 1);

    cbor_w_uint(&w, 0x0f);                    /* maxCredBlobLength */
    cbor_w_uint(&w, RES_CRED_BLOB_MAX);

    cbor_w_uint(&w, 0x10);                    /* maxRPIDsForSetMinPINLength */
    cbor_w_uint(&w, MAX_MIN_PIN_LEN_RPIDS);

    /* 0x14 remainingDiscoverableCredentials (CTAP 2.1 sec. 6.4, #35): the
     * estimated number of additional discoverable (resident) credentials
     * that can still be created -- the same quantity CredentialManagement
     * getCredsMetadata reports, surfaced here so a platform can show
     * remaining-slot capacity without an authenticated credMgmt
     * round-trip. Canonical ascending key order places it after 0x10. */
    {
        size_t used = resident_store_count();
        size_t cap  = resident_store_max();
        size_t remaining = (cap > used) ? (cap - used) : 0;
        cbor_w_uint(&w, 0x14);
        cbor_w_uint(&w, (uint64_t)remaining);
    }

    if (!cbor_w_ok(&w)) return -1;
    *resp_len = 1 + cbor_w_off(&w);
    return 0;
}

/* ---- authenticatorReset (CTAP 2.1 sec. 6.6) ------------------------ */

/* Wipe the master keys -- which invalidates every stateless
 * credentialID minted before now -- and clear the PIN and all config
 * policy, then reload the freshly-regenerated keys into the
 * credential + client-PIN layers so subsequent commands use the new
 * keys (not the stale boot-time copies). The spec's power-on + 10 s
 * user-presence gate is relaxed (this build has no real-time clock);
 * we still require a fresh CMD_CBOR call. */
static void handle_reset(uint8_t *resp, size_t *resp_len)
{
    flash_store_wipe();    /* regenerate master keys; clear PIN + config */
    resident_store_wipe(); /* drop every discoverable credential         */
    large_blobs_wipe();    /* clear the large-blob array                 */
    credential_init();     /* reload the new master keys                 */
    client_pin_init();     /* drop any active token; rotate keyAgreement */
    resp[0] = CTAP2_OK;
    *resp_len = 1;
}

/* ---- Dispatch -------------------------------------------------- */

/* Bring-up diagnostic hook: weak no-op default so host builds (no CDC)
 * link without main.c's CDC-logging override. */
void __attribute__((weak)) pqf_ctap2_dbg(uint8_t cmd) { (void)cmd; }

int ctap2_dispatch(const uint8_t *payload, size_t payload_len,
                    uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    if (payload_len < 1 || resp_cap < 1) {
        if (resp_cap >= 1) {
            resp[0] = CTAP2_ERR_INVALID_LENGTH;
            *resp_len = 1;
        }
        return 0;
    }

    uint8_t cmd = payload[0];
    const uint8_t *params = payload + 1;
    size_t params_len = payload_len - 1;

    /* Bring-up diagnostic (the riscv32 freeze investigation): log every
     * dispatched command over CDC so the exact sequence leading to a
     * hang is visible. Weak no-op below; main.c overrides it only when
     * the build defines PQF_CTAP2_DBG=1. */
    pqf_ctap2_dbg(cmd);

    /* Any command other than GetNextAssertion ends a pending
     * discoverable-assertion sequence (CTAP 2.1 sec. 6.3 -- GetNext is only
     * valid immediately after the originating GetAssertion). This is
     * our stand-in for the spec's 30 s stateful-command timeout, which
     * we can't measure without a wall-clock in the dispatcher. */
    if (cmd != CTAP2_CMD_GET_NEXT_ASSERTION)
        assert_iter_reset();
    /* CredentialManagement enumerate-Begin/GetNext spans several 0x0A
     * calls, so its iterators are only invalidated by a *different*
     * command (same stand-in for the sec. 6.8 30 s timeout).
     *
     * clientPIN is exempt. Each enumerate call carries a pinUvAuthParam
     * over a pinUvAuthToken with a bounded lifetime, so a store with
     * more credentials than fit in one token lifetime FORCES the client
     * to re-run getPinUvAuthToken part-way through the walk. Counting
     * that refresh as "a different command" made the very next GetNext
     * fail with CTAP2_ERR_NOT_ALLOWED and stranded the client with no
     * way to finish enumerating: re-running Begin just restarts at
     * credential 0 with a token that will expire again. Refreshing the
     * token is not a new operation, it is the same operation continuing,
     * so it must not drop the iterator.
     *
     * The Rust port never had this: its iterators live in the PIN
     * session, keyed on channel plus a real 30 s deadline, and no
     * command invalidates them. That divergence is why the C port alone
     * failed the enumerate-next check on all nine of its silicon
     * configurations while all nine Rust ones passed (2026-08-17).
     * Exempting clientPIN closes the gap without pretending this
     * dispatcher has a clock; everything else still resets, so the
     * stand-in keeps whatever value it had. */
    if (cmd != CTAP2_CMD_CREDENTIAL_MANAGEMENT
        && cmd != CTAP2_CMD_CLIENT_PIN)
        credential_management_reset_iters();

    switch (cmd) {
    case CTAP2_CMD_GET_INFO:
        if (payload_len != 1) {
            resp[0] = CTAP2_ERR_INVALID_LENGTH;
            *resp_len = 1;
            return 0;
        }
        if (build_get_info_response(resp, resp_cap, resp_len) != 0) {
            resp[0] = CTAP2_ERR_OTHER;
            *resp_len = 1;
        }
        return 0;

    case CTAP2_CMD_MAKE_CREDENTIAL:
        return handle_make_credential(params, params_len,
                                      resp, resp_cap, resp_len);

    case CTAP2_CMD_GET_ASSERTION:
        return handle_get_assertion(params, params_len,
                                    resp, resp_cap, resp_len);

    case CTAP2_CMD_CLIENT_PIN:
        return client_pin_handle(params, params_len,
                                 resp, resp_cap, resp_len);

    case CTAP2_CMD_RESET:
        if (payload_len != 1) {
            resp[0] = CTAP2_ERR_INVALID_LENGTH;
            *resp_len = 1;
            return 0;
        }
        /* CTAP 2.1 sec. 6.6: reset requires a test of user presence. It is
         * the one command that destroys every credential and the PIN,
         * and it takes no PIN and no token -- the touch is the ONLY thing
         * between a plugged-in authenticator and an empty one. This
         * dispatch wiped on request from any software. (The spec's
         * further "within 10 s of power-up" window is not applied: this
         * dispatcher has no clock, which the iterator comment above
         * already records.) */
        {
            int up = require_user_presence();
            if (up != CTAP2_OK) {
                resp[0] = (uint8_t)up;
                *resp_len = 1;
                return 0;
            }
        }
        handle_reset(resp, resp_len);
        return 0;

    case CTAP2_CMD_SELECTION:
        /* authenticatorSelection (CTAP 2.1 sec. 6.9): this IS the
         * touch-to-choose gesture. When several authenticators could
         * satisfy a ceremony the platform sends this to every connected
         * one, and the device the user TOUCHES is the one selected. We
         * must wait for a real user-presence touch and ACK only then, or
         * return 0x27 (require_user_presence()'s timeout code) otherwise.
         *
         * Answering OK immediately (as an earlier revision did, back
         * when no board had a readable button) makes us always win the
         * selection race the instant we're plugged in -- the browser then
         * never offers the user another authenticator and never prompts
         * for a press, so the device "hijacks" every registration. A
         * YubiKey waits for its touch here; now that user presence is
         * real (BOOTSEL / GP0) we must too. */
        if (payload_len != 1) {
            resp[0] = CTAP2_ERR_INVALID_LENGTH;
            *resp_len = 1;
            return 0;
        }
        resp[0] = (uint8_t)require_user_presence();
        *resp_len = 1;
        return 0;

    case CTAP2_CMD_CONFIG:
        return authenticator_config_handle(params, params_len,
                                           resp, resp_cap, resp_len);

    case CTAP2_CMD_GET_NEXT_ASSERTION:
        if (payload_len != 1) {
            resp[0] = CTAP2_ERR_INVALID_LENGTH;
            *resp_len = 1;
            return 0;
        }
        return emit_get_next_assertion(resp, resp_cap, resp_len);

    case CTAP2_CMD_CREDENTIAL_MANAGEMENT:
        return credential_management_handle(params, params_len,
                                            resp, resp_cap, resp_len);

    case CTAP2_CMD_LARGE_BLOBS:
        return large_blobs_handle(params, params_len,
                                  resp, resp_cap, resp_len);

    default:
        resp[0] = CTAP2_ERR_INVALID_COMMAND;
        *resp_len = 1;
        return 0;
    }
}
