/* authenticator_config.c -- authenticatorConfig (CTAP 2.1 sec. 6.11).
 *
 * Subcommands (CTAP 2.1 sec. 6.11.1):
 *   0x01 enableEnterpriseAttestation -- flag stored, but attestation
 *        stays self-attestation (we ship no vendor cert chain), so the
 *        flag is purely advisory and has no protocol-visible effect.
 *        getInfo does NOT advertise the "ep" option (#29): we never
 *        emit epAtt, so advertising it would mis-signal an
 *        enterprise-attestation guarantee we can't honour.
 *   0x02 toggleAlwaysUv             -- flips the device-wide alwaysUv.
 *   0x03 setMinPINLength            -- raises the min PIN length and/or
 *        replaces the minPinLengthRPIDs allowlist.
 *   0xFF vendorPrototype            -- rejected (ERR_INVALID_SUBCOMMAND).
 *
 * Wire layout mirrors the Bruce Rust firmware (the parity base for
 * this port):
 *   request map { 0x01 subCommand        (uint),
 *                 0x02 subCommandParams   (map, optional),
 *                 0x03 pinUvAuthProtocol  (uint),
 *                 0x04 pinUvAuthParam     (bytes) }
 *   setMinPINLength params { 0x01 newMinPINLength    (uint),
 *                            0x02 minPinLengthRPIDs   (array<text>),
 *                            0x03 forceChangePin      (bool) }
 *
 * The pinUvAuthParam authenticates, under a token carrying the
 * authnrCfg permission (0x20):
 *     0xFFx32 || 0x0D || subCommand || subCommandParams_cbor
 * (CTAP 2.1 sec. 6.11.2 step 3). subCommandParams_cbor is the verbatim
 * bytes the platform sent, located via cbor_raw_map_value() so we MAC
 * over exactly what was signed rather than a re-encoding.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "ctap2.h"
#include "client_pin.h"
#include "flash_store.h"
#include "pin_protocol.h"
#include "pqf_crypto.h"
#include "cbor_read.h"
#include "pqcbor.h"

/* AC subcommand identifiers (CTAP 2.1 sec. 6.11.1). */
#define SUB_ENABLE_ENT_ATTESTATION  0x01u
#define SUB_TOGGLE_ALWAYS_UV        0x02u
#define SUB_SET_MIN_PIN_LENGTH      0x03u
#define SUB_VENDOR_PROTOTYPE        0xFFu

/* 0x3E. CTAP 2.1 sec. 8.1's table puts CTAP2_ERR_INVALID_SUBCOMMAND
 * at 0x3E; 0x16 is CTAP2_ERR_UNSUPPORTED_EXTENSION. All six in-house
 * declarations said 0x16 and agreed with each other, so every test
 * passed and a client was told the wrong thing about the wrong field. */
#define ERR_INVALID_SUBCOMMAND      0x3e

/* A zero RP-id-hash sentinel: passing this (not NULL) to
 * client_pin_verify_token rejects RP-scoped tokens, since a scoped
 * token's hash will never equal all-zero -- matching the Rust base's
 * check_token_permission(.., &[0u8; 32]) for device-wide AC tokens. */
static const uint8_t ZERO32[32] = {0};

int authenticator_config_handle(const uint8_t *params, size_t params_len,
                                uint8_t *resp, size_t resp_cap,
                                size_t *resp_len)
{
    (void)resp_cap;
    pqfido_cbor_item_t *root = NULL;
    if (pqfido_cbor_decode(params, params_len, &root) != PQFIDO_OK) {
        resp[0] = CTAP2_ERR_INVALID_CBOR;
        *resp_len = 1;
        return 0;
    }

    int status = CTAP2_ERR_OTHER;

    const pqfido_cbor_item_t *sub_i  = cbor_map_get_uint(root, 0x01);
    const pqfido_cbor_item_t *parm_i = cbor_map_get_uint(root, 0x02);
    /* CTAP 2.1 sec. 6.11: protocol at 0x03 (uint), param at 0x04 (bytes). */
    const pqfido_cbor_item_t *prot_i = cbor_map_get_uint(root, 0x03);
    const pqfido_cbor_item_t *puap_i = cbor_map_get_uint(root, 0x04);

    if (sub_i == NULL || !pqfido_cbor_is_uint(sub_i)) {
        status = CTAP2_ERR_MISSING_PARAMETER;
        goto done;
    }
    uint64_t sub = pqfido_cbor_uint(sub_i);

    /* vendorPrototype is defined but unimplemented. */
    if (sub == SUB_VENDOR_PROTOTYPE) {
        status = ERR_INVALID_SUBCOMMAND;
        goto done;
    }

    /* Locate the verbatim subCommandParams bytes for the auth message.
     * Absent for toggleAlwaysUv / enableEnterpriseAttestation. */
    const uint8_t *sp = NULL;
    size_t sp_len = 0;
    cbor_raw_map_value(params, params_len, 0x02, &sp, &sp_len);

    /* PIN-token authentication (CTAP 2.1 sec. 6.11.2 step 1). The single
     * exception: toggleAlwaysUv may run WITHOUT a token on a fresh
     * device (no PIN set AND alwaysUv currently off) -- this is how a
     * device opts into alwaysUv as its first configuration step. */
    bool needs_auth = !(sub == SUB_TOGGLE_ALWAYS_UV
                        && !client_pin_is_set()
                        && !flash_store_always_uv());
    if (needs_auth) {
        if (puap_i == NULL || !pqfido_cbor_is_bytes(puap_i)) {
            /* A token is required and none was sent. PUAT_REQUIRED
             * (0x36) is retriable -- it tells the platform to go and
             * get one -- where MISSING_PARAMETER (0x14) reads as a
             * malformed request. The Rust port has answered 0x36 here
             * since M16, with the same reasoning written down. */
            status = CTAP2_ERR_PUAT_REQUIRED;
            goto done;
        }
        if (prot_i == NULL || !pqfido_cbor_is_uint(prot_i)) {
            status = CTAP2_ERR_PIN_AUTH_INVALID;
            goto done;
        }
        uint8_t proto = (uint8_t)pqfido_cbor_uint(prot_i);
        if (proto != PIN_PROTOCOL_V1 && proto != PIN_PROTOCOL_V2) {
            status = CTAP2_ERR_PIN_AUTH_INVALID;
            goto done;
        }

        /* msg = 0xFFx32 || 0x0D || subCommand || subCommandParams. */
        static uint8_t msg[34 + 1024];
        if (sp_len > sizeof msg - 34) {     /* defensive -- AC params are tiny */
            status = CTAP2_ERR_PIN_AUTH_INVALID;
            goto done;
        }
        size_t mlen = 0;
        memset(msg, 0xFF, 32);
        mlen = 32;
        msg[mlen++] = CTAP2_CMD_CONFIG;     /* 0x0D */
        msg[mlen++] = (uint8_t)sub;
        if (sp_len) {
            memcpy(msg + mlen, sp, sp_len);
            mlen += sp_len;
        }

        int pe = client_pin_verify_token(pqfido_cbor_bytes(puap_i),
                                         pqfido_cbor_bytes_len(puap_i), proto,
                                         msg, mlen,
                                         PIN_PERM_AUTH_CONFIG, ZERO32);
        if (pe != 0) {
            status = pe;
            goto done;
        }
    }

    switch (sub) {
    case SUB_ENABLE_ENT_ATTESTATION:
        /* Store the advisory bit; attestation stays self-attestation and
         * getInfo does not advertise "ep" (#29). Hosts that toggle this
         * expect a bare CTAP2_OK. */
        flash_store_set_enterprise_attestation(true);
        status = CTAP2_OK;
        break;

    case SUB_TOGGLE_ALWAYS_UV:
        flash_store_set_always_uv(!flash_store_always_uv());
        status = CTAP2_OK;
        break;

    case SUB_SET_MIN_PIN_LENGTH: {
        /* Any of newMinPINLength (0x01), minPinLengthRPIDs (0x02), and
         * forceChangePin (0x03) may be present (X13). */
        const pqfido_cbor_item_t *nm = cbor_map_get_uint(parm_i, 0x01);
        const pqfido_cbor_item_t *rp = cbor_map_get_uint(parm_i, 0x02);
        const pqfido_cbor_item_t *fc = cbor_map_get_uint(parm_i, 0x03);

        if (nm != NULL && pqfido_cbor_is_uint(nm)) {
            uint64_t newv = pqfido_cbor_uint(nm);
            uint8_t cur = flash_store_min_pin_length();
            if (cur == 0) cur = PIN_MIN_LENGTH;
            /* CTAP 2.1 sec. 6.11.4: the minimum may only be raised. */
            if (newv < cur || newv > PIN_MAX_LENGTH) {
                status = CTAP2_ERR_PIN_POLICY_VIOLATION;
                goto done;
            }
            flash_store_set_min_pin_length((uint8_t)newv);
        }

        if (rp != NULL && pqfido_cbor_is_array(rp)) {
            uint8_t hashes[MAX_MIN_PIN_LEN_RPIDS][32];
            uint8_t cnt = 0;
            size_t n = pqfido_cbor_array_size(rp);
            for (size_t i = 0; i < n && cnt < MAX_MIN_PIN_LEN_RPIDS; i++) {
                const pqfido_cbor_item_t *e = pqfido_cbor_array_get(rp, i);
                if (!pqfido_cbor_is_string(e)) continue;
                pqf_sha256(pqfido_cbor_string(e),
                           pqfido_cbor_string_len(e), hashes[cnt]);
                cnt++;
            }
            flash_store_set_min_pin_rpids(hashes, cnt);
        }

        /* forceChangePin (X13, CTAP 2.1 sec. 6.11.4): a boolean true demands
         * that the host run authenticatorClientPin.changePIN before any
         * further PIN-token use. Persist the flag (surfaced as getInfo
         * 0x0C forcePINChange, enforced in getPinUvAuthToken, and cleared
         * by a successful changePIN). Only an explicit boolean true sets
         * it; absent / false / non-bool leaves it unchanged. */
        if (fc != NULL && pqfido_cbor_is_bool(fc) && pqfido_cbor_bool(fc))
            flash_store_set_force_pin_change(true);

        status = CTAP2_OK;
        break;
    }

    default:
        status = ERR_INVALID_SUBCOMMAND;
        break;
    }

done:
    resp[0] = (uint8_t)status;
    *resp_len = 1;
    pqfido_cbor_free(root);
    return 0;
}
