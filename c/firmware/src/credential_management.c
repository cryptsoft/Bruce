/* credential_management.c -- authenticatorCredentialManagement (0x0A,
 * CTAP 2.1 sec. 6.8). Seven subcommands let the host inspect, enumerate,
 * delete, and rename the device's resident credentials.
 *
 * Wire layout mirrors the Bruce Rust firmware (the parity base):
 *   request { 0x01 subCommand (uint),
 *             0x02 subCommandParams (map, optional),
 *             0x03 pinUvAuthProtocol (uint),
 *             0x04 pinUvAuthParam (bytes) }
 *   subCommandParams { 0x01 rpIDHash (bytes32),
 *                      0x02 credentialId (descriptor {id,type}),
 *                      0x03 user ({id?,name?,displayName?}) }
 *
 * Every subcommand except the GetNext* iterators verifies a
 * pinUvAuthParam over  subCommand || subCommandParams  (note: NO
 * 0xFFx32 prefix -- that's authenticatorConfig only) under a token
 * carrying the credMgmt permission (0x04). getCredsMetadata and
 * enumerateRPsBegin additionally require an UNSCOPED token; the rest
 * accept unscoped or matching-RP-scoped tokens -- both enforced by
 * passing the right rp_id_hash to client_pin_verify_token.
 *
 * publicKey (response 0x08) IS emitted, per CTAP 2.1 6.8.3. It used to
 * be omitted here on the grounds that a hybrid credential would need
 * its ~1-2 KB ML-DSA public key recomputed -- but that is not what the
 * response needs, and the comment's claim that this "matched the Rust
 * base" went stale: the Rust port emits the ES256 half for every
 * credential, hybrid included (es256_cose_public_key in ctap2.rs), and
 * so does this. Only the P-256 point is re-derived, never ML-DSA.
 *
 * Found by running the conformance suite against BOTH ports: their failure
 * sets were identical except "enumerated credential 0 (ES256) carries a
 * parseable COSE key", which C failed only because the key was absent
 * rather than malformed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "ctap2.h"
#include "credential.h"
#include "pqf_crypto.h"
#include "client_pin.h"
#include "resident_store.h"
#include "credential.h"
#include "credential_management.h"
#include "cbor_encode.h"
#include "cbor_read.h"
#include "pqcbor.h"

#define SUB_GET_CREDS_METADATA      0x01u
#define SUB_ENUMERATE_RPS_BEGIN     0x02u
#define SUB_ENUMERATE_RPS_GET_NEXT  0x03u
#define SUB_ENUMERATE_CREDS_BEGIN   0x04u
#define SUB_ENUMERATE_CREDS_GET_NEXT 0x05u
#define SUB_DELETE_CREDENTIAL       0x06u
#define SUB_UPDATE_USER_INFORMATION 0x07u

/* 0x3E. CTAP 2.1 sec. 8.1's table puts CTAP2_ERR_INVALID_SUBCOMMAND
 * at 0x3E; 0x16 is CTAP2_ERR_UNSUPPORTED_EXTENSION. All six in-house
 * declarations said 0x16 and agreed with each other, so every test
 * passed and a client was told the wrong thing about the wrong field. */
#define ERR_INVALID_SUBCOMMAND      0x3e

static const uint8_t ZERO32[32] = {0};

/* Channel id of the CBOR command currently being dispatched, set by
 * the transport (ctaphid.c) via credential_management_set_cid() before
 * ctap2_dispatch runs. enumerate*Begin captures it into the iterator;
 * enumerate*GetNext compares against it so the enumeration stays bound
 * to its originating channel (CTAP 2.1 sec. 6.8/sec. 11.2). A direct caller
 * (host tests) never sets it, so it stays 0 and Begin/GetNext match. */
static uint32_t s_current_cid;

/* In-flight enumerateRPs iterator: distinct RPs in creation order, plus
 * a read cursor. Each entry carries the rp_id_hash and the persisted
 * UTF-8 rp.id (F4) so GetNext can emit a human-readable id. `cid` binds
 * the iterator to the channel that issued Begin. */
static struct {
    bool     active;
    uint32_t cid;
    uint8_t  rps[RESIDENT_MAX_SLOTS][32];
    uint8_t  rp_id[RESIDENT_MAX_SLOTS][RES_RP_ID_MAX];
    uint8_t  rp_id_len[RESIDENT_MAX_SLOTS];
    size_t   n;
    size_t   next;
} s_rp_iter;

/* In-flight enumerateCredentials iterator: slot indices for one RP in
 * creation order. `cid` binds the iterator to the channel that issued
 * Begin; `rp_id_hash` is the frozen RP so GetNext can re-verify a slot
 * still belongs to this RP (a slot tombstoned or reused between Begin
 * and GetNext must not surface stale data under the wrong RP). */
static struct {
    bool     active;
    uint32_t cid;
    uint8_t  rp_id_hash[32];
    size_t   slots[RESIDENT_MAX_SLOTS];
    size_t   n;
    size_t   next;
    uint32_t total;
} s_cred_iter;

void credential_management_reset_iters(void)
{
    s_rp_iter.active = false;
    s_cred_iter.active = false;
}

void credential_management_set_cid(uint32_t cid)
{
    s_current_cid = cid;
}

/* ---- response builders ---------------------------------------- */

static int emit_metadata(uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    size_t existing = resident_store_count();
    size_t maxs = resident_store_max();
    size_t remaining = (maxs > existing) ? (maxs - existing) : 0;

    resp[0] = CTAP2_OK;
    cbor_writer_t w; cbor_w_init(&w, resp + 1, resp_cap - 1);
    cbor_w_map_header(&w, 2);
    cbor_w_uint(&w, 0x01); cbor_w_uint(&w, existing);
    cbor_w_uint(&w, 0x02); cbor_w_uint(&w, remaining);
    if (!cbor_w_ok(&w)) { resp[0] = CTAP2_ERR_OTHER; *resp_len = 1; return 0; }
    *resp_len = 1 + cbor_w_off(&w);
    return 0;
}

/* Emit an RP entry { 0x03 rp{id}, 0x04 rpIDHash[, 0x05 total] }.
 * The persisted UTF-8 rp.id (F4) is emitted under the RP entity's "id"
 * key (CTAP 2.1 sec. 6.8.3); an empty string is used only when no rp.id was
 * stored (e.g. a credential minted before the field existed). */
static int emit_rp(const uint8_t rp_id_hash[32],
                   const uint8_t *rp_id, size_t rp_id_len, long total,
                   uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    resp[0] = CTAP2_OK;
    cbor_writer_t w; cbor_w_init(&w, resp + 1, resp_cap - 1);
    cbor_w_map_header(&w, total >= 0 ? 3 : 2);
    cbor_w_uint(&w, 0x03);
    cbor_w_map_header(&w, 1);
    cbor_w_text(&w, "id"); cbor_w_text_n(&w, (const char *)rp_id, rp_id_len);
    cbor_w_uint(&w, 0x04); cbor_w_bytes(&w, rp_id_hash, 32);
    if (total >= 0) { cbor_w_uint(&w, 0x05); cbor_w_uint(&w, (uint64_t)total); }
    if (!cbor_w_ok(&w)) { resp[0] = CTAP2_ERR_OTHER; *resp_len = 1; return 0; }
    *resp_len = 1 + cbor_w_off(&w);
    return 0;
}

/* Emit a credential entry { 0x06 user, 0x07 credDesc, 0x08 publicKey
 * [, 0x09 total], 0x0A credProtect }. */
static int emit_cred(size_t slot_idx, long total,
                     uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    resident_cred_t rc;
    if (resident_store_get(slot_idx, &rc) != 0) {
        resp[0] = CTAP2_ERR_NO_CREDENTIALS; *resp_len = 1; return 0;
    }

    unsigned user_n = 1u + (rc.user_name_len ? 1u : 0u)
                         + (rc.user_display_name_len ? 1u : 0u);

    resp[0] = CTAP2_OK;
    cbor_writer_t w; cbor_w_init(&w, resp + 1, resp_cap - 1);
    /* 0x08 publicKey. Re-derive the credential's P-256 point from the
     * scalar sealed in its own credentialID; we minted it, so we can
     * decrypt it. Hybrid credentials report the ES256 half under alg
     * -7, exactly as the Rust port does -- the ML-DSA half is NOT
     * recomputed, which is what makes this affordable.
     *
     * It still costs one scalar multiplication per enumerated
     * credential (credential.h notes ~2.4 s from XIP on the mixed
     * build), so it is emitted only when the derivation succeeds; a
     * failure degrades to the previous behaviour of omitting the key
     * rather than failing the whole enumeration. */
    credential_source_t src;
    uint8_t pub_x[32], pub_y[32];
    bool have_pub = credential_recover(rc.cred_id, CRED_ID_LEN,
                                       rc.rp_id_hash, &src) == 0
                 && pqf_p256_derive_public(src.ecdsa_scalar, pub_x, pub_y) == 0;

    unsigned n = 2u + (have_pub ? 1u : 0u)
                    + (total >= 0 ? 1u : 0u) + (rc.cred_protect ? 1u : 0u);
    cbor_w_map_header(&w, n);

    /* 0x06 user { id [, name] [, displayName] }. */
    cbor_w_uint(&w, 0x06);
    cbor_w_map_header(&w, user_n);
    cbor_w_text(&w, "id");
    cbor_w_bytes(&w, rc.user_id, rc.user_id_len);
    if (rc.user_name_len) {
        cbor_w_text(&w, "name");
        cbor_w_text_n(&w, (const char *)rc.user_name, rc.user_name_len);
    }
    if (rc.user_display_name_len) {
        cbor_w_text(&w, "displayName");
        cbor_w_text_n(&w, (const char *)rc.user_display_name,
                      rc.user_display_name_len);
    }

    /* 0x07 credentialId { id, type }. */
    cbor_w_uint(&w, 0x07);
    cbor_w_map_header(&w, 2);
    cbor_w_text(&w, "id"); cbor_w_bytes(&w, rc.cred_id, CRED_ID_LEN);
    cbor_w_text(&w, "type"); cbor_w_text(&w, "public-key");

    /* 0x08 publicKey: plain ES256 COSE_Key (kty EC2, alg -7, P-256,
     * x, y). Canonical key order 1, 3, -1, -2, -3. */
    if (have_pub) {
        cbor_w_uint(&w, 0x08);
        cbor_w_map_header(&w, 5);
        cbor_w_uint(&w, 1);  cbor_w_uint(&w, 2);      /* kty: EC2      */
        cbor_w_uint(&w, 3);  cbor_w_int(&w, -7);      /* alg: ES256    */
        cbor_w_int(&w, -1);  cbor_w_uint(&w, 1);      /* crv: P-256    */
        cbor_w_int(&w, -2);  cbor_w_bytes(&w, pub_x, 32);
        cbor_w_int(&w, -3);  cbor_w_bytes(&w, pub_y, 32);
    }

    if (total >= 0) { cbor_w_uint(&w, 0x09); cbor_w_uint(&w, (uint64_t)total); }
    if (rc.cred_protect) { cbor_w_uint(&w, 0x0A); cbor_w_uint(&w, rc.cred_protect); }

    if (!cbor_w_ok(&w)) { resp[0] = CTAP2_ERR_OTHER; *resp_len = 1; return 0; }
    *resp_len = 1 + cbor_w_off(&w);
    return 0;
}

/* ---- subcommand handlers -------------------------------------- */

static int do_enumerate_rps_begin(uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    size_t idxs[RESIDENT_MAX_SLOTS];
    size_t n = resident_store_iter_by_creation(idxs, RESIDENT_MAX_SLOTS);
    s_rp_iter.active = false;
    s_rp_iter.n = 0;
    s_rp_iter.next = 0;
    for (size_t i = 0; i < n; i++) {
        resident_cred_t rc;
        if (resident_store_get(idxs[i], &rc) != 0) continue;
        bool seen = false;
        for (size_t j = 0; j < s_rp_iter.n; j++)
            if (memcmp(s_rp_iter.rps[j], rc.rp_id_hash, 32) == 0) { seen = true; break; }
        if (!seen) {
            memcpy(s_rp_iter.rps[s_rp_iter.n], rc.rp_id_hash, 32);
            uint8_t rl = rc.rp_id_len;
            if (rl > RES_RP_ID_MAX) rl = RES_RP_ID_MAX;
            memcpy(s_rp_iter.rp_id[s_rp_iter.n], rc.rp_id, rl);
            s_rp_iter.rp_id_len[s_rp_iter.n] = rl;
            s_rp_iter.n++;
        }
    }
    if (s_rp_iter.n == 0) {
        resp[0] = CTAP2_ERR_NO_CREDENTIALS; *resp_len = 1; return 0;
    }
    s_rp_iter.active = true;
    s_rp_iter.cid = s_current_cid;
    s_rp_iter.next = 1;
    return emit_rp(s_rp_iter.rps[0], s_rp_iter.rp_id[0], s_rp_iter.rp_id_len[0],
                   (long)s_rp_iter.n, resp, resp_cap, resp_len);
}

static int do_enumerate_rps_get_next(uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    /* Bound to the originating channel (CTAP 2.1 sec. 6.8/sec. 11.2): a GetNext
     * on a different channel drops the iterator and is refused. */
    if (!s_rp_iter.active || s_rp_iter.cid != s_current_cid
        || s_rp_iter.next >= s_rp_iter.n) {
        s_rp_iter.active = false;
        resp[0] = CTAP2_ERR_NOT_ALLOWED; *resp_len = 1; return 0;
    }
    size_t i = s_rp_iter.next++;
    int rc = emit_rp(s_rp_iter.rps[i], s_rp_iter.rp_id[i], s_rp_iter.rp_id_len[i],
                     -1, resp, resp_cap, resp_len);
    if (s_rp_iter.next >= s_rp_iter.n) s_rp_iter.active = false;
    return rc;
}

static int do_enumerate_creds_begin(const uint8_t rp_id_hash[32],
                                    uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    size_t idxs[RESIDENT_MAX_SLOTS];
    size_t n = resident_store_find_by_rp(rp_id_hash, idxs, RESIDENT_MAX_SLOTS);
    if (n == 0) {
        resp[0] = CTAP2_ERR_NO_CREDENTIALS; *resp_len = 1; return 0;
    }
    s_cred_iter.active = true;
    s_cred_iter.cid = s_current_cid;
    memcpy(s_cred_iter.rp_id_hash, rp_id_hash, 32);
    s_cred_iter.n = n;
    s_cred_iter.next = 1;
    s_cred_iter.total = (uint32_t)n;
    for (size_t i = 0; i < n; i++) s_cred_iter.slots[i] = idxs[i];
    return emit_cred(idxs[0], (long)n, resp, resp_cap, resp_len);
}

static int do_enumerate_creds_get_next(uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    /* Bound to the originating channel (CTAP 2.1 sec. 6.8/sec. 11.2): a GetNext
     * on a different channel drops the iterator and is refused. */
    if (!s_cred_iter.active || s_cred_iter.cid != s_current_cid) {
        s_cred_iter.active = false;
        resp[0] = CTAP2_ERR_NOT_ALLOWED; *resp_len = 1; return 0;
    }
    /* Advance to the next frozen slot index that is STILL active and
     * still belongs to this RP. A credential deleted (tombstoned) or
     * its slot reused by another RP between Begin and this GetNext must
     * not surface stale user.id / name / credentialId data, and must
     * not abort the whole listing -- skip past such slots and continue
     * with the next still-valid credential (matching the Rust port's
     * skip loop). */
    for (;;) {
        if (s_cred_iter.next >= s_cred_iter.n) {
            s_cred_iter.active = false;
            resp[0] = CTAP2_ERR_NOT_ALLOWED; *resp_len = 1; return 0;
        }
        size_t slot = s_cred_iter.slots[s_cred_iter.next++];
        resident_cred_t rc;
        if (resident_store_get(slot, &rc) != 0) continue;       /* deleted */
        if (memcmp(rc.rp_id_hash, s_cred_iter.rp_id_hash, 32) != 0)
            continue;                                            /* reused by another RP */
        if (s_cred_iter.next >= s_cred_iter.n) s_cred_iter.active = false;
        return emit_cred(slot, -1, resp, resp_cap, resp_len);
    }
}

/* ---- entry point ---------------------------------------------- */

int credential_management_handle(const uint8_t *params, size_t params_len,
                                 uint8_t *resp, size_t resp_cap,
                                 size_t *resp_len)
{
    pqfido_cbor_item_t *root = NULL;
    if (pqfido_cbor_decode(params, params_len, &root) != PQFIDO_OK) {
        resp[0] = CTAP2_ERR_INVALID_CBOR; *resp_len = 1; return 0;
    }

    int status = CTAP2_ERR_OTHER;

    const pqfido_cbor_item_t *sub_i  = cbor_map_get_uint(root, 0x01);
    const pqfido_cbor_item_t *parm_i = cbor_map_get_uint(root, 0x02);
    /* CTAP 2.1 sec. 6.8: protocol at 0x03 (uint), param at 0x04 (bytes). */
    const pqfido_cbor_item_t *prot_i = cbor_map_get_uint(root, 0x03);
    const pqfido_cbor_item_t *puap_i = cbor_map_get_uint(root, 0x04);

    if (sub_i == NULL || !pqfido_cbor_is_uint(sub_i)) {
        status = CTAP2_ERR_MISSING_PARAMETER; goto done;
    }
    uint64_t sub = pqfido_cbor_uint(sub_i);

    /* subCommandParams fields we may need. */
    const uint8_t *rp_hash = NULL;
    const uint8_t *cred_id = NULL; size_t cred_id_len = 0;
    const pqfido_cbor_item_t *user = NULL;
    if (parm_i != NULL && pqfido_cbor_is_map(parm_i)) {
        const pqfido_cbor_item_t *h = cbor_map_get_uint(parm_i, 0x01);
        if (h && pqfido_cbor_is_bytes(h) && pqfido_cbor_bytes_len(h) == 32)
            rp_hash = pqfido_cbor_bytes(h);
        const pqfido_cbor_item_t *d = cbor_map_get_uint(parm_i, 0x02);
        if (d && pqfido_cbor_is_map(d)) {
            const pqfido_cbor_item_t *id = cbor_map_get_text(d, "id");
            if (id && pqfido_cbor_is_bytes(id)) {
                cred_id = pqfido_cbor_bytes(id);
                cred_id_len = pqfido_cbor_bytes_len(id);
            }
        }
        user = cbor_map_get_uint(parm_i, 0x03);
    }

    /* GetNext iterators don't reauthenticate. */
    bool needs_auth = !(sub == SUB_ENUMERATE_RPS_GET_NEXT
                        || sub == SUB_ENUMERATE_CREDS_GET_NEXT);
    if (needs_auth) {
        if (puap_i == NULL || !pqfido_cbor_is_bytes(puap_i)) {
            /* As authenticator_config.c: retriable, not malformed. */
            status = CTAP2_ERR_PUAT_REQUIRED; goto done;
        }
        if (prot_i == NULL || !pqfido_cbor_is_uint(prot_i)) {
            status = CTAP2_ERR_PIN_AUTH_INVALID; goto done;
        }
        uint8_t proto = (uint8_t)pqfido_cbor_uint(prot_i);
        if (proto != PIN_PROTOCOL_V1 && proto != PIN_PROTOCOL_V2) {
            status = CTAP2_ERR_PIN_AUTH_INVALID; goto done;
        }

        /* message = subCommand || subCommandParams (verbatim bytes). */
        static uint8_t msg[1 + 512];
        const uint8_t *sp = NULL; size_t sp_len = 0;
        cbor_raw_map_value(params, params_len, 0x02, &sp, &sp_len);
        if (sp_len > sizeof msg - 1) {
            status = CTAP2_ERR_PIN_AUTH_INVALID; goto done;
        }
        size_t mlen = 0;
        msg[mlen++] = (uint8_t)sub;
        if (sp_len) { memcpy(msg + mlen, sp, sp_len); mlen += sp_len; }

        /* getCredsMetadata + enumerateRPsBegin require an unscoped
         * token (pass ZERO32 -> a scoped token's hash can't match);
         * enumerateCredsBegin accepts unscoped or a token scoped to
         * the requested RP. delete / update have no rpIdHash -> ZERO32
         * (unscoped only), matching the Rust base. */
        const uint8_t *check_rp = (rp_hash != NULL) ? rp_hash : ZERO32;
        int pe = client_pin_verify_token(pqfido_cbor_bytes(puap_i),
                                         pqfido_cbor_bytes_len(puap_i), proto,
                                         msg, mlen,
                                         PIN_PERM_CRED_MGMT, check_rp);
        /* A pinUvAuthParam WAS supplied and did not check out. That is
         * PIN_AUTH_INVALID whatever the helper's internal reason was --
         * propagating its raw code leaked 0x36 "fetch a token" for a
         * request that had presented one, which sends the platform round
         * a loop it cannot exit. The Rust port collapses it here too. */
        if (pe != 0) { status = CTAP2_ERR_PIN_AUTH_INVALID; goto done; }
    }

    switch (sub) {
    case SUB_GET_CREDS_METADATA:
        pqfido_cbor_free(root);
        return emit_metadata(resp, resp_cap, resp_len);

    case SUB_ENUMERATE_RPS_BEGIN:
        pqfido_cbor_free(root);
        return do_enumerate_rps_begin(resp, resp_cap, resp_len);

    case SUB_ENUMERATE_RPS_GET_NEXT:
        pqfido_cbor_free(root);
        return do_enumerate_rps_get_next(resp, resp_cap, resp_len);

    case SUB_ENUMERATE_CREDS_BEGIN:
        if (rp_hash == NULL) { status = CTAP2_ERR_MISSING_PARAMETER; goto done; }
        {
            uint8_t h[32]; memcpy(h, rp_hash, 32);
            pqfido_cbor_free(root);
            return do_enumerate_creds_begin(h, resp, resp_cap, resp_len);
        }

    case SUB_ENUMERATE_CREDS_GET_NEXT:
        pqfido_cbor_free(root);
        return do_enumerate_creds_get_next(resp, resp_cap, resp_len);

    case SUB_DELETE_CREDENTIAL: {
        size_t idx;
        if (cred_id == NULL
            || resident_store_find_by_cred_id(cred_id, cred_id_len, &idx) != 0) {
            status = CTAP2_ERR_NO_CREDENTIALS; goto done;
        }
        resident_store_delete(idx);
        status = CTAP2_OK;
        break;
    }

    case SUB_UPDATE_USER_INFORMATION: {
        size_t idx;
        if (cred_id == NULL
            || resident_store_find_by_cred_id(cred_id, cred_id_len, &idx) != 0) {
            status = CTAP2_ERR_NO_CREDENTIALS; goto done;
        }
        const uint8_t *nm = NULL; size_t nm_len = 0;
        const uint8_t *dn = NULL; size_t dn_len = 0;
        if (user && pqfido_cbor_is_map(user)) {
            const pqfido_cbor_item_t *n = cbor_map_get_text(user, "name");
            if (n && pqfido_cbor_is_string(n)) {
                nm = pqfido_cbor_string(n); nm_len = pqfido_cbor_string_len(n);
            }
            const pqfido_cbor_item_t *d = cbor_map_get_text(user, "displayName");
            if (d && pqfido_cbor_is_string(d)) {
                dn = pqfido_cbor_string(d); dn_len = pqfido_cbor_string_len(d);
            }
        }
        resident_store_update_user(idx, nm, nm_len, dn, dn_len);
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
