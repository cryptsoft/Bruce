/* client_pin.c -- authenticatorClientPIN (CTAP 2.1 sec. 6.5).
 *
 * Subcommands implemented:
 *   0x01 getPinRetries
 *   0x02 getKeyAgreement
 *   0x03 setPIN
 *   0x04 changePIN
 *   0x05 getPinToken                          (legacy, all-permissions)
 *   0x09 getPinUvAuthTokenUsingPinWithPermissions
 *
 * PIN protocols v1 and v2 are both accepted (see pin_protocol.c).
 * The PIN itself is never stored -- only SHA-256(PIN)[:16]. A
 * successful PIN proof issues a PIN/UV-auth token (a random key)
 * that ctap2.c uses to gate MakeCredential / GetAssertion via
 * client_pin_verify_token().
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "client_pin.h"
#include "ctap2.h"
#include "cbor_encode.h"
#include "cbor_read.h"
#include "pin_protocol.h"
#include "flash_store.h"
#include "pqf_crypto.h"
#include "pqf_cleanse.h"
#include "openssl/rand.h"

/* ---- Authenticator key-agreement key + PIN token --------------- */

static uint8_t s_ka_priv[32];          /* ephemeral ECDH private    */
static uint8_t s_ka_x[32], s_ka_y[32]; /* ... public coordinates    */

static uint8_t  s_token[32];           /* PIN/UV-auth token         */
static bool     s_token_active;
static uint32_t s_token_perms;
static bool     s_token_rp_scoped;
static uint8_t  s_token_rp_id_hash[32];

/* Per-power-cycle consecutive-failure lockout (CTAP 2.1 sec. 6.5.5.6).
 * A volatile (RAM-only) counter, separate from the persistent 8-retry
 * counter: after MAX_CONSECUTIVE_PIN_FAILURES wrong PINs in one power
 * cycle the PIN paths refuse with CTAP2_ERR_PIN_AUTH_BLOCKED (0x34)
 * until the next boot, even if persistent retries remain. Reset to 0 on
 * boot (client_pin_init), on a correct PIN, and on Reset
 * (client_pin_init runs again from handle_reset). */
#define MAX_CONSECUTIVE_PIN_FAILURES 3
static uint8_t  s_consec_pin_failures;

static void regen_key_agreement(void)
{
    /* A fresh ephemeral ECDH key. Invalidates any in-flight shared
     * secret the platform may have derived (spec-allowed). */
    pqf_p256_keygen(s_ka_priv, s_ka_x, s_ka_y);
}

static void new_token(void)
{
    RAND_bytes(s_token, sizeof s_token);
    s_token_active = false;
    s_token_perms = 0;
    s_token_rp_scoped = false;
}

void client_pin_init(void)
{
    regen_key_agreement();
    new_token();
    /* Fresh power cycle (or Reset, which re-runs this) clears the
     * volatile consecutive-failure lockout. */
    s_consec_pin_failures = 0;
}

bool client_pin_is_set(void)
{
    return flash_store_pin_is_set();
}

int client_pin_shared_secret(uint8_t protocol,
                             const uint8_t plat_x[32],
                             const uint8_t plat_y[32],
                             pin_shared_secret_t *out)
{
    return pin_shared_secret(protocol, s_ka_priv, plat_x, plat_y, out);
}

/* ---- COSE_Key (EC2) emit for getKeyAgreement ------------------- */

static void emit_cose_ec2(cbor_writer_t *w,
                          const uint8_t x[32], const uint8_t y[32])
{
    cbor_w_map_header(w, 5);
    cbor_w_uint(w, 1);  cbor_w_uint(w, 2);    /* kty: EC2   */
    cbor_w_uint(w, 3);  cbor_w_int(w, -25);   /* alg: ECDH-ES+HKDF (-25) */
    cbor_w_int(w, -1);  cbor_w_uint(w, 1);    /* crv: P-256 */
    cbor_w_int(w, -2);  cbor_w_bytes(w, x, 32);
    cbor_w_int(w, -3);  cbor_w_bytes(w, y, 32);
}

/* ---- Response builders ----------------------------------------- */

static int respond_status(uint8_t *resp, size_t *resp_len, uint8_t status)
{
    resp[0] = status;
    *resp_len = 1;
    return 0;
}

/* ---- Subcommand: getPinRetries (0x01) -------------------------- */

/* CTAP 2.1 sec. 6.5.5.2. pinRetries (0x03) is the persistent budget;
 * powerCycleState (0x04) is "present and true if the authenticator
 * requires a power cycle before any future PIN operation", so it is
 * emitted only while the volatile per-boot lockout is engaged and the
 * common-case response stays a one-entry map.
 *
 * Reporting it matters more than it looks. While blocked the device
 * refuses every PIN -- including the correct one -- but pinRetries still
 * reads whatever is left, so a client with only that number tells the
 * user to keep typing. The flag is the only thing on the wire that says
 * "replug". */
static int sub_get_retries(uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    const bool blocked = (s_consec_pin_failures >= MAX_CONSECUTIVE_PIN_FAILURES);

    resp[0] = CTAP2_OK;
    cbor_writer_t w; cbor_w_init(&w, resp + 1, resp_cap - 1);
    cbor_w_map_header(&w, blocked ? 2 : 1);
    cbor_w_uint(&w, 0x03);
    cbor_w_uint(&w, flash_store_pin_retries());
    if (blocked) {
        cbor_w_uint(&w, 0x04);
        cbor_w_bool(&w, true);
    }
    if (!cbor_w_ok(&w)) return respond_status(resp, resp_len, CTAP2_ERR_OTHER);
    *resp_len = 1 + cbor_w_off(&w);
    return 0;
}

/* ---- Subcommand: getKeyAgreement (0x02) ------------------------ */

static int sub_get_key_agreement(uint8_t *resp, size_t resp_cap,
                                 size_t *resp_len)
{
    resp[0] = CTAP2_OK;
    cbor_writer_t w; cbor_w_init(&w, resp + 1, resp_cap - 1);
    cbor_w_map_header(&w, 1);
    cbor_w_uint(&w, 0x01);            /* keyAgreement */
    emit_cose_ec2(&w, s_ka_x, s_ka_y);
    if (!cbor_w_ok(&w)) return respond_status(resp, resp_len, CTAP2_ERR_OTHER);
    *resp_len = 1 + cbor_w_off(&w);
    return 0;
}

/* Validate a decrypted, zero-padded PIN buffer (CTAP pads the PIN to
 * a multiple of 16, min 64 bytes for v-protocol). Returns the PIN
 * length (bytes up to the first NUL), or 0 if the policy is violated.
 *
 * The minimum honours the AuthenticatorConfig setMinPINLength override
 * (flash_store_min_pin_length()) when one has been set, falling back to
 * the built-in PIN_MIN_LENGTH otherwise. setMinPINLength only ever
 * raises the value (>= PIN_MIN_LENGTH), so this never drops below 4. */
static size_t pin_padded_length(const uint8_t *pin, size_t buf_len)
{
    size_t len = 0;
    while (len < buf_len && pin[len] != 0)
        len++;
    size_t min_len = flash_store_min_pin_length();
    if (min_len < PIN_MIN_LENGTH) min_len = PIN_MIN_LENGTH;
    if (len < min_len || len > PIN_MAX_LENGTH)
        return 0;
    return len;
}

/* Common: derive the shared secret from the request's keyAgreement +
 * pinUvAuthProtocol. Returns 0 + fills `ss`, or a CTAP error. */
static int derive_ss(const pqfido_cbor_item_t *root, uint8_t protocol,
                     pin_shared_secret_t *ss)
{
    const pqfido_cbor_item_t *ka = cbor_map_get_uint(root, 0x03);
    if (ka == NULL) return CTAP2_ERR_MISSING_PARAMETER;
    uint8_t px[32], py[32];
    if (!cbor_cose_ec2_xy(ka, px, py))
        return CTAP2_ERR_INVALID_PARAMETER;
    if (pin_shared_secret(protocol, s_ka_priv, px, py, ss) != 0)
        return CTAP2_ERR_INVALID_PARAMETER;
    return 0;
}

/* Exact on-the-wire lengths of the encrypted PIN-material blobs, per
 * CTAP 2.1 sec. 6.5.5: the PIN hash is one 16-B AES block and the padded
 * new PIN is 64 B; protocol v2 prepends a 16-B IV to each. Requests are
 * length-checked against these BEFORE decryption so an attacker-supplied
 * over-length ciphertext can never be driven into a fixed stack buffer. */
static size_t new_pin_enc_len(uint8_t protocol)
{
    return (protocol == PIN_PROTOCOL_V2) ? 80 : 64;
}
static size_t pin_hash_enc_len(uint8_t protocol)
{
    return (protocol == PIN_PROTOCOL_V2) ? 32 : 16;
}

/* ---- Subcommand: setPIN (0x03) --------------------------------- */

static int sub_set_pin(const pqfido_cbor_item_t *root, uint8_t protocol,
                       uint8_t *resp, size_t *resp_len)
{
    if (flash_store_pin_is_set())
        return respond_status(resp, resp_len, CTAP2_ERR_PIN_AUTH_INVALID);

    const pqfido_cbor_item_t *puap = cbor_map_get_uint(root, 0x04);
    const pqfido_cbor_item_t *npe  = cbor_map_get_uint(root, 0x05);
    if (puap == NULL || !pqfido_cbor_is_bytes(puap)
        || npe == NULL || !pqfido_cbor_is_bytes(npe))
        return respond_status(resp, resp_len, CTAP2_ERR_MISSING_PARAMETER);

    if (pqfido_cbor_bytes_len(npe) != new_pin_enc_len(protocol))
        return respond_status(resp, resp_len, CTAP2_ERR_MISSING_PARAMETER);

    pin_shared_secret_t ss;
    int e = derive_ss(root, protocol, &ss);
    if (e) return respond_status(resp, resp_len, (uint8_t)e);

    /* From here `ss` holds live AES/HMAC key material; every exit path
     * below must run through `out:` so it's cleansed off the stack (M2). */
    int status;
    uint8_t pin[80]; size_t pin_len = 0;
    uint8_t full[32];

    /* pinUvAuthParam = authenticate(sharedSecret, newPinEnc). */
    if (!pin_verify(&ss, pqfido_cbor_bytes(npe), pqfido_cbor_bytes_len(npe),
                    pqfido_cbor_bytes(puap), pqfido_cbor_bytes_len(puap))) {
        status = CTAP2_ERR_PIN_AUTH_INVALID;
        goto out;
    }

    /* Decrypt newPinEnc -> padded PIN (must be 64 bytes). */
    if (pin_decrypt(&ss, pqfido_cbor_bytes(npe), pqfido_cbor_bytes_len(npe),
                    pin, sizeof pin, &pin_len) != 0 || pin_len < 64) {
        status = CTAP2_ERR_PIN_POLICY_VIOLATION;
        goto out;
    }

    if (pin_padded_length(pin, pin_len) == 0) {
        status = CTAP2_ERR_PIN_POLICY_VIOLATION;
        goto out;
    }

    /* Store SHA-256(PIN)[:16]. */
    pqf_sha256(pin, pin_padded_length(pin, pin_len), full);
    flash_store_pin_set(full);    /* sets pin_set, retries = MAX */
    status = CTAP2_OK;

out:
    pqf_cleanse(pin, sizeof pin);
    pqf_cleanse(full, sizeof full);
    pqf_cleanse(&ss, sizeof ss);
    return respond_status(resp, resp_len, (uint8_t)status);
}

/* ---- changePIN (0x04) + getPinToken (0x05/0x09) shared: verify
 *      the current PIN via pinHashEnc against the stored hash. ----
 * Returns 0 on match, or a CTAP error (decrementing retries). */
static int verify_pin_hash_enc(const pin_shared_secret_t *ss,
                               const pqfido_cbor_item_t *phe)
{
    uint8_t retries = flash_store_pin_retries();
    if (retries == 0)
        return CTAP2_ERR_PIN_BLOCKED;

    /* pinHashEnc must be exactly one encrypted PIN-hash block before we
     * decrypt it into `got` (16 B for v1; 16-B IV + 16-B ct = 32 B for
     * v2). Reject any other length up front. */
    if (pqfido_cbor_bytes_len(phe) != pin_hash_enc_len(ss->protocol))
        return CTAP2_ERR_MISSING_PARAMETER;

    /* Decrement + persist the retry counter BEFORE comparing the PIN, so
     * losing power between the compare and the flash write can't refund a
     * wrong guess (CTAP 2.1 sec. 6.5.5.7). A correct PIN restores it below. */
    flash_store_pin_set_retries((uint8_t)(retries - 1));

    uint8_t got[16]; size_t got_len = 0;
    if (pin_decrypt(ss, pqfido_cbor_bytes(phe), pqfido_cbor_bytes_len(phe),
                    got, sizeof got, &got_len) != 0 || got_len < 16) {
        /* Bump the volatile consecutive-failure counter and rotate the
         * key-agreement key so the next attempt forces a fresh ECDH
         * handshake (CTAP 2.1 sec. 6.5.5.6). */
        if (s_consec_pin_failures < 0xff) s_consec_pin_failures++;
        regen_key_agreement();
        return CTAP2_ERR_PIN_INVALID;
    }

    uint8_t stored[16];
    flash_store_pin_get_hash(stored);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)(got[i] ^ stored[i]);
    pqf_cleanse(got, sizeof got);
    pqf_cleanse(stored, sizeof stored);

    if (diff != 0) {
        /* Wrong PIN -- persistent counter already decremented; bump the
         * volatile consecutive-failure counter and rotate the
         * key-agreement key so each guess costs a new ECDH handshake
         * (sec. 6.5.5.6/.7). */
        if (s_consec_pin_failures < 0xff) s_consec_pin_failures++;
        regen_key_agreement();
        return CTAP2_ERR_PIN_INVALID;
    }
    /* Correct PIN: restore the retry counter to the maximum and clear the
     * volatile consecutive-failure lockout (CTAP 2.1 sec. 6.5.5.6). */
    flash_store_pin_set_retries(PIN_MAX_RETRIES);
    s_consec_pin_failures = 0;
    return 0;
}

static int sub_change_pin(const pqfido_cbor_item_t *root, uint8_t protocol,
                          uint8_t *resp, size_t *resp_len)
{
    if (!flash_store_pin_is_set())
        return respond_status(resp, resp_len, CTAP2_ERR_PIN_NOT_SET);

    /* Per-power-cycle lockout (CTAP 2.1 sec. 6.5.5.6): once this boot has
     * seen MAX_CONSECUTIVE_PIN_FAILURES wrong PINs, refuse with
     * PIN_AUTH_BLOCKED (0x34) BEFORE spending a persistent retry, even
     * if persistent retries remain. Cleared only by a reboot/Reset or a
     * correct PIN. */
    if (s_consec_pin_failures >= MAX_CONSECUTIVE_PIN_FAILURES)
        return respond_status(resp, resp_len, CTAP2_ERR_PIN_AUTH_BLOCKED);

    const pqfido_cbor_item_t *puap = cbor_map_get_uint(root, 0x04);
    const pqfido_cbor_item_t *npe  = cbor_map_get_uint(root, 0x05);
    const pqfido_cbor_item_t *phe  = cbor_map_get_uint(root, 0x06);
    if (!puap || !pqfido_cbor_is_bytes(puap) || !npe || !pqfido_cbor_is_bytes(npe)
        || !phe || !pqfido_cbor_is_bytes(phe))
        return respond_status(resp, resp_len, CTAP2_ERR_MISSING_PARAMETER);

    if (pqfido_cbor_bytes_len(npe) != new_pin_enc_len(protocol)
        || pqfido_cbor_bytes_len(phe) != pin_hash_enc_len(protocol))
        return respond_status(resp, resp_len, CTAP2_ERR_MISSING_PARAMETER);

    pin_shared_secret_t ss;
    int e = derive_ss(root, protocol, &ss);
    if (e) return respond_status(resp, resp_len, (uint8_t)e);

    /* From here `ss` holds live key material; every exit path runs
     * through `out:` so it's cleansed off the stack (M2). */
    int status;
    uint8_t pin[80]; size_t pin_len = 0;
    uint8_t full[32];

    /* pinUvAuthParam = authenticate(ss, newPinEnc || pinHashEnc). */
    uint8_t macbuf[256]; size_t ne = pqfido_cbor_bytes_len(npe);
    size_t pe = pqfido_cbor_bytes_len(phe);
    if (ne + pe > sizeof macbuf) {
        status = CTAP2_ERR_PIN_AUTH_INVALID;
        goto out;
    }
    memcpy(macbuf, pqfido_cbor_bytes(npe), ne);
    memcpy(macbuf + ne, pqfido_cbor_bytes(phe), pe);
    if (!pin_verify(&ss, macbuf, ne + pe,
                    pqfido_cbor_bytes(puap), pqfido_cbor_bytes_len(puap))) {
        status = CTAP2_ERR_PIN_AUTH_INVALID;
        goto out;
    }

    /* Verify the current PIN (decrements + persists the retry counter
     * and bumps the volatile failure counter on a wrong guess). */
    int v = verify_pin_hash_enc(&ss, phe);
    if (v) {
        status = v;
        goto out;
    }

    /* Decrypt + store the new PIN. */
    if (pin_decrypt(&ss, pqfido_cbor_bytes(npe), ne, pin, sizeof pin, &pin_len) != 0
        || pin_len < 64 || pin_padded_length(pin, pin_len) == 0) {
        status = CTAP2_ERR_PIN_POLICY_VIOLATION;
        goto out;
    }
    pqf_sha256(pin, pin_padded_length(pin, pin_len), full);
    flash_store_pin_set(full);

    /* A successful changePIN clears a pending forcePINChange (X13,
     * CTAP 2.1 sec. 6.5.5.7.2) and invalidates outstanding tokens. */
    if (flash_store_force_pin_change())
        flash_store_set_force_pin_change(false);
    new_token();
    status = CTAP2_OK;

out:
    pqf_cleanse(pin, sizeof pin);
    pqf_cleanse(full, sizeof full);
    pqf_cleanse(&ss, sizeof ss);
    return respond_status(resp, resp_len, (uint8_t)status);
}

/* ---- getPinToken (0x05) + ...WithPermissions (0x09) ------------ */

static int sub_get_token(const pqfido_cbor_item_t *root, uint8_t protocol,
                         bool with_perms,
                         uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    if (!flash_store_pin_is_set())
        return respond_status(resp, resp_len, CTAP2_ERR_PIN_NOT_SET);

    /* Per-power-cycle lockout (CTAP 2.1 sec. 6.5.5.6): once this boot has
     * seen MAX_CONSECUTIVE_PIN_FAILURES wrong PINs, refuse with
     * PIN_AUTH_BLOCKED (0x34) BEFORE spending a persistent retry, even
     * if persistent retries remain. Applies to both 0x05 and 0x09. */
    if (s_consec_pin_failures >= MAX_CONSECUTIVE_PIN_FAILURES)
        return respond_status(resp, resp_len, CTAP2_ERR_PIN_AUTH_BLOCKED);

    const pqfido_cbor_item_t *phe = cbor_map_get_uint(root, 0x06);
    if (!phe || !pqfido_cbor_is_bytes(phe))
        return respond_status(resp, resp_len, CTAP2_ERR_MISSING_PARAMETER);

    pin_shared_secret_t ss;
    int e = derive_ss(root, protocol, &ss);
    if (e) return respond_status(resp, resp_len, (uint8_t)e);

    /* From here `ss` holds live key material; every exit path runs
     * through `out:` so it's cleansed off the stack (M2). */
    int status;
    uint8_t enc[48]; size_t enc_len = 0;

    int v = verify_pin_hash_enc(&ss, phe);
    if (v) { status = v; goto out; }

    /* Validate the permissions parameter BEFORE minting/activating the
     * token: a malformed get-token-with-permissions must not destroy a
     * previously valid token (CTAP 2.1 sec. 6.5.5.7). */
    const pqfido_cbor_item_t *perm = NULL;
    const pqfido_cbor_item_t *rpid = NULL;
    /* requested_perms = what THIS request asks for: the explicit 0x09
     * permissions for the WithPermissions path, or the implicit mc+ga
     * for the legacy 0x05 token. Used by the forcePINChange gate. */
    uint32_t requested_perms;
    if (with_perms) {
        perm = cbor_map_get_uint(root, 0x09);
        rpid = cbor_map_get_uint(root, 0x0a);
        if (perm == NULL || !pqfido_cbor_is_uint(perm)
            || pqfido_cbor_uint(perm) == 0) {
            status = CTAP2_ERR_MISSING_PARAMETER;
            goto out;
        }
        /* Mask on the full 64-bit value BEFORE narrowing, so a high bit
         * cannot vanish in the cast and be granted as nothing. This
         * used to store the requested bitmask verbatim -- bioEnrollment
         * included -- and a token then carried a permission no check
         * on this device ever looked at. Refusing here, before
         * new_token(), leaves any existing token intact (sec. 6.5.5.7). */
        uint64_t asked = pqfido_cbor_uint(perm);
        if (asked & ~(uint64_t)PIN_PERM_SUPPORTED) {
            status = CTAP2_ERR_UNAUTHORIZED_PERMISSION;
            goto out;
        }
        requested_perms = (uint32_t)asked;
    } else {
        requested_perms = PIN_PERM_MAKE_CREDENTIAL | PIN_PERM_GET_ASSERTION;
    }

    /* forcePINChange (X13, CTAP 2.1 sec. 6.5.5.7.2): when a forced PIN change
     * is pending, refuse to mint a token carrying makeCredential (0x01)
     * or getAssertion (0x02) permissions with PIN_POLICY_VIOLATION (0x37)
     * so the host must run changePIN first. Tokens scoped only to
     * credMgmt / authnrCfg / largeBlobWrite are still issued so the host
     * can complete the change. The PIN was verified above, so a wrong
     * PIN still reports 0x31, not 0x37. */
    if (flash_store_force_pin_change()
        && (requested_perms
            & (PIN_PERM_MAKE_CREDENTIAL | PIN_PERM_GET_ASSERTION))) {
        status = CTAP2_ERR_PIN_POLICY_VIOLATION;
        goto out;
    }

    /* Establish a fresh token + its permission scope. */
    new_token();
    s_token_active = true;
    s_token_perms = requested_perms;
    if (with_perms) {
        /* rpId is OPTIONAL even for mc/ga: CTAP 2.1 sec. 6.5.5.7 permits an
         * unscoped token (bound to the RP on first use). We don't
         * reject mc/ga-without-rpId -- matching the Rust firmware. */
        if (rpid != NULL && pqfido_cbor_is_string(rpid)) {
            pqf_sha256(pqfido_cbor_string(rpid),
                       pqfido_cbor_string_len(rpid), s_token_rp_id_hash);
            s_token_rp_scoped = true;
        }
    } else {
        /* Legacy 0x05: all permissions, no RP scope (CTAP 2.1 maps
         * the legacy token to mc + ga). */
        s_token_rp_scoped = false;
    }

    /* Encrypt the token to the platform under the shared secret. */
    if (pin_encrypt(&ss, s_token, 32, enc, &enc_len) != 0) {
        status = CTAP2_ERR_OTHER;
        goto out;
    }

    resp[0] = CTAP2_OK;
    cbor_writer_t w; cbor_w_init(&w, resp + 1, resp_cap - 1);
    cbor_w_map_header(&w, 1);
    cbor_w_uint(&w, 0x02);                  /* pinUvAuthToken */
    cbor_w_bytes(&w, enc, enc_len);
    if (!cbor_w_ok(&w)) {
        status = CTAP2_ERR_OTHER;
        goto out;
    }
    *resp_len = 1 + cbor_w_off(&w);
    pqf_cleanse(&ss, sizeof ss);
    return 0;

out:
    pqf_cleanse(&ss, sizeof ss);
    return respond_status(resp, resp_len, (uint8_t)status);
}

/* ---- Public: handle a ClientPIN request ------------------------ */

int client_pin_handle(const uint8_t *params, size_t params_len,
                      uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    pqfido_cbor_item_t *root = NULL;
    if (pqfido_cbor_decode(params, params_len, &root) != PQFIDO_OK)
        return respond_status(resp, resp_len, CTAP2_ERR_INVALID_CBOR);

    const pqfido_cbor_item_t *proto_i = cbor_map_get_uint(root, 0x01);
    const pqfido_cbor_item_t *sub_i   = cbor_map_get_uint(root, 0x02);
    if (sub_i == NULL || !pqfido_cbor_is_uint(sub_i)) {
        pqfido_cbor_free(root);
        return respond_status(resp, resp_len, CTAP2_ERR_MISSING_PARAMETER);
    }
    uint8_t protocol = (proto_i && pqfido_cbor_is_uint(proto_i))
                       ? (uint8_t)pqfido_cbor_uint(proto_i) : PIN_PROTOCOL_V1;
    if (protocol != PIN_PROTOCOL_V1 && protocol != PIN_PROTOCOL_V2) {
        pqfido_cbor_free(root);
        return respond_status(resp, resp_len, CTAP2_ERR_INVALID_PARAMETER);
    }

    uint64_t sub = pqfido_cbor_uint(sub_i);
    int rc;
    switch (sub) {
    case 0x01: rc = sub_get_retries(resp, resp_cap, resp_len); break;
    case 0x02: rc = sub_get_key_agreement(resp, resp_cap, resp_len); break;
    case 0x03: rc = sub_set_pin(root, protocol, resp, resp_len); break;
    case 0x04: rc = sub_change_pin(root, protocol, resp, resp_len); break;
    case 0x05: rc = sub_get_token(root, protocol, false, resp, resp_cap, resp_len); break;
    case 0x09: rc = sub_get_token(root, protocol, true, resp, resp_cap, resp_len); break;
    /* An unknown subCommand is INVALID_SUBCOMMAND (0x3E), as in the
     * other two ports and the rest of this one since the 0x16 -> 0x3E
     * correction -- which missed this module because it used a literal
     * INVALID_PARAMETER rather than the shared constant. */
    default:   rc = respond_status(resp, resp_len, CTAP2_ERR_INVALID_SUBCOMMAND); break;
    }
    pqfido_cbor_free(root);
    return rc;
}

/* ---- Public: token verification for MakeCred / GetAssert ------- */

int client_pin_verify_token(const uint8_t *pin_uv_auth_param,
                            size_t param_len, uint8_t protocol,
                            const uint8_t *data, size_t data_len,
                            uint32_t required_perm,
                            const uint8_t rp_id_hash[32])
{
    if (!s_token_active)
        return CTAP2_ERR_PUAT_REQUIRED;
    if (protocol != PIN_PROTOCOL_V1 && protocol != PIN_PROTOCOL_V2)
        return CTAP2_ERR_PIN_AUTH_INVALID;

    /* pinUvAuthParam = authenticate(token, data). */
    uint8_t expect[32]; size_t expect_len = 0;
    pin_authenticate(protocol, s_token, 32, data, data_len, expect, &expect_len);
    if (param_len != expect_len)
        return CTAP2_ERR_PIN_AUTH_INVALID;
    uint8_t diff = 0;
    for (size_t i = 0; i < expect_len; i++)
        diff |= (uint8_t)(expect[i] ^ pin_uv_auth_param[i]);
    if (diff != 0)
        return CTAP2_ERR_PIN_AUTH_INVALID;

    /* Permission + RP-scope checks. */
    if ((s_token_perms & required_perm) == 0)
        return CTAP2_ERR_PIN_AUTH_INVALID;
    if (s_token_rp_scoped && rp_id_hash != NULL
        && memcmp(s_token_rp_id_hash, rp_id_hash, 32) != 0)
        return CTAP2_ERR_PIN_AUTH_INVALID;

    return 0;
}
