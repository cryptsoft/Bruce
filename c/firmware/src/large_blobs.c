/* large_blobs.c -- authenticatorLargeBlobs (0x0C, CTAP 2.1 sec. 6.10).
 *
 * A single device-wide byte array, read/written in offset+length
 * chunks. See large_blobs.h. Wire layout:
 *
 *   request { 0x01 get    (uint -- read length; exclusive with set),
 *             0x02 set    (bytes -- write payload),
 *             0x03 offset (uint, required),
 *             0x04 length (uint -- total array length, required on a
 *                          write at offset 0; absent on later fragments),
 *             0x05 pinUvAuthParam (bytes), 0x06 pinUvAuthProtocol }
 *   read response  { 0x01 config (bytes) }
 *   write response : bare CTAP2_OK
 *
 * The array carries a 16-byte SHA-256 trailer over its body (sec. 6.10.3);
 * writes are rejected unless the trailer is valid. The initial value
 * (never-written) is 0x80 (CBOR empty array) || SHA-256("\x80")[..16].
 *
 * Writes are authenticated (when a PIN is set) under a token carrying
 * the largeBlobWrite permission, over the byte sequence
 *     0xFFx32 || 0x0C || 0x00 || offset(4 LE) || SHA-256(set)
 * Writes may be fragmented (CTAP 2.1 sec. 11.5): the first fragment has
 * offset 0 and the total `length`; each later fragment carries the
 * running offset (no `length`). Fragments are buffered until the full
 * declared length is assembled, then the trailer is validated and the
 * array persisted.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#ifndef PQF_RESIDENT_HOST
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "core1_signer.h"       /* core1_run_flash_op (M1 lockout) */
#endif

#include "large_blobs.h"
#include "ctap2.h"
#include "client_pin.h"
#include "flash_store.h"
#include "pin_protocol.h"
#include "pqf_crypto.h"
#include "cbor_encode.h"
#include "cbor_read.h"
#include "pqcbor.h"

#ifndef PQF_RESIDENT_HOST
#ifndef PICO_FLASH_SIZE_BYTES
#define PICO_FLASH_SIZE_BYTES (2u * 1024u * 1024u)
#endif
#define LB_SECTOR_SIZE   FLASH_SECTOR_SIZE
#define LB_OFFSET        (PICO_FLASH_SIZE_BYTES - 3u * LB_SECTOR_SIZE)
#define LB_XIP           ((const uint8_t *)(XIP_BASE + LB_OFFSET))
#define LB_MAGIC         0x424C424Cu   /* "LBLB" */
#define LB_VERSION       1u
#define LB_HEADER        16u           /* magic+version+len+pad */
_Static_assert(LB_HEADER + MAX_LARGE_BLOB_LEN <= LB_SECTOR_SIZE,
               "large-blob array overflows its flash sector");
#endif

/* sec. 6.10 length-error status. */
/* 0x29 is CTAP2_ERR_NOT_BUSY. The length errors below are
 * CTAP1_ERR_INVALID_LENGTH (0x03), and an array that will not fit is
 * CTAP2_ERR_LARGE_BLOB_STORAGE_FULL (0x18) -- a different condition
 * the client can act on differently. Both ports said 0x29. */
#define LB_ERR_INVALID_LENGTH   CTAP2_ERR_INVALID_LENGTH
#define LB_ERR_STORAGE_FULL     0x18

static const uint8_t ZERO32[32] = {0};

static uint8_t  s_array[MAX_LARGE_BLOB_LEN];
static uint32_t s_len;

/* Multi-fragment write state (CTAP 2.1 sec. 11.5). A write may span several
 * authenticatorLargeBlobs commands: the first carries offset == 0 and
 * the total `length` (0x04); each subsequent fragment carries the
 * running offset (and no `length`). Fragments accumulate in s_wr_buf
 * until s_wr_have == s_wr_total, at which point the SHA-256 trailer is
 * validated and the array persisted. s_wr_active gates the in-progress
 * write so a fresh offset-0 chunk always restarts cleanly. */
static bool     s_wr_active;
static uint32_t s_wr_total;             /* declared total length        */
static uint32_t s_wr_have;              /* bytes buffered so far        */
static uint8_t  s_wr_buf[MAX_LARGE_BLOB_LEN];

static void wr_reset(void)
{
    s_wr_active = false;
    s_wr_total = 0;
    s_wr_have = 0;
}

/* Spec initial value: 0x80 (CBOR empty array) || SHA-256("\x80")[..16]. */
static void set_initial(void)
{
    uint8_t b = 0x80, h[32];
    s_array[0] = 0x80;
    pqf_sha256(&b, 1, h);
    memcpy(s_array + 1, h, 16);
    s_len = 17;
}

#ifdef PQF_RESIDENT_HOST

static void commit(void) { }
void large_blobs_init(void) { set_initial(); wr_reset(); }
void large_blobs_wipe(void) { set_initial(); wr_reset(); }

#else /* firmware: QSPI-backed */

static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint8_t s_commit_page[LB_SECTOR_SIZE];

static void commit(void)
{
    memset(s_commit_page, 0, sizeof s_commit_page);
    wr_u32(s_commit_page + 0, LB_MAGIC);
    wr_u32(s_commit_page + 4, LB_VERSION);
    wr_u32(s_commit_page + 8, s_len);
    memcpy(s_commit_page + LB_HEADER, s_array, s_len);

    /* Erase + program through flash_store's guarded direct-ROM path
     * (core 1 parked in its RAM spin + IRQs masked + boot-ROM flash
     * calls, M1). The pico-sdk flash_range_* wrappers this used to call
     * hang nondeterministically on pure-RISC-V silicon -- see
     * flash_op_cb in flash_store.c. */
    flash_store_guarded_op(LB_OFFSET, LB_SECTOR_SIZE,
                           s_commit_page, LB_SECTOR_SIZE);
}

void large_blobs_init(void)
{
    wr_reset();
    const uint8_t *s = LB_XIP;
    if (rd_u32(s + 0) == LB_MAGIC && rd_u32(s + 4) == LB_VERSION) {
        uint32_t n = rd_u32(s + 8);
        if (n <= MAX_LARGE_BLOB_LEN) {
            s_len = n;
            memcpy(s_array, s + LB_HEADER, n);
            return;
        }
    }
    set_initial();   /* never-written: serve the spec initial value */
}

void large_blobs_wipe(void) { set_initial(); wr_reset(); commit(); }

#endif /* PQF_RESIDENT_HOST */

int large_blobs_handle(const uint8_t *params, size_t params_len,
                       uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    pqfido_cbor_item_t *root = NULL;
    if (pqfido_cbor_decode(params, params_len, &root) != PQFIDO_OK) {
        resp[0] = CTAP2_ERR_INVALID_CBOR; *resp_len = 1; return 0;
    }

    int status = CTAP2_ERR_OTHER;

    const pqfido_cbor_item_t *get_i = cbor_map_get_uint(root, 0x01);
    const pqfido_cbor_item_t *set_i = cbor_map_get_uint(root, 0x02);
    const pqfido_cbor_item_t *off_i = cbor_map_get_uint(root, 0x03);
    const pqfido_cbor_item_t *len_i = cbor_map_get_uint(root, 0x04);
    const pqfido_cbor_item_t *puap_i = cbor_map_get_uint(root, 0x05);
    const pqfido_cbor_item_t *prot_i = cbor_map_get_uint(root, 0x06);

    uint32_t offset = (off_i && pqfido_cbor_is_uint(off_i))
                      ? (uint32_t)pqfido_cbor_uint(off_i) : 0;
    bool is_write = (set_i != NULL && pqfido_cbor_is_bytes(set_i));

    if (is_write && get_i != NULL) {       /* get + set mutually exclusive */
        status = CTAP2_ERR_INVALID_PARAMETER; goto done;
    }

    if (is_write) {
        const uint8_t *set = pqfido_cbor_bytes(set_i);
        size_t set_len = pqfido_cbor_bytes_len(set_i);

        /* Write auth is required when a PIN is set OR the device-wide
         * alwaysUv policy is on (CTAP 2.1 sec. 6.10.4, L24). On this
         * hardware no UV method exists without a PIN, so an
         * alwaysUv=true device with no PIN simply cannot write the
         * large-blob array -- the missing-token branch returns
         * ERR_PUAT_REQUIRED below, so the write stays authenticated
         * rather than slipping through unauthenticated. */
        if (client_pin_is_set() || flash_store_always_uv()) {
            if (puap_i == NULL || !pqfido_cbor_is_bytes(puap_i)) {
                /* PIN/UV required but no token supplied: PUAT_REQUIRED
                 * (0x36), not MISSING_PARAMETER (0x14), so the host
                 * knows to obtain a token and retry (CTAP 2.1 sec. 6.10). */
                status = CTAP2_ERR_PUAT_REQUIRED; goto done;
            }
            if (prot_i == NULL || !pqfido_cbor_is_uint(prot_i)) {
                status = CTAP2_ERR_PIN_AUTH_INVALID; goto done;
            }
            uint8_t proto = (uint8_t)pqfido_cbor_uint(prot_i);
            if (proto != PIN_PROTOCOL_V1 && proto != PIN_PROTOCOL_V2) {
                status = CTAP2_ERR_PIN_AUTH_INVALID; goto done;
            }
            /* msg = 0xFFx32 || h'0c00' || offset(4 LE) || SHA-256(set).
             * The second byte is a literal zero per CTAP 2.1 sec. 6.10, not
             * the `set` parameter's map key. */
            uint8_t msg[32 + 2 + 4 + 32];
            memset(msg, 0xFF, 32);
            msg[32] = CTAP2_CMD_LARGE_BLOBS;   /* 0x0c */
            msg[33] = 0x00;
            msg[34] = (uint8_t)offset;
            msg[35] = (uint8_t)(offset >> 8);
            msg[36] = (uint8_t)(offset >> 16);
            msg[37] = (uint8_t)(offset >> 24);
            pqf_sha256(set, set_len, msg + 38);
            int pe = client_pin_verify_token(pqfido_cbor_bytes(puap_i),
                                             pqfido_cbor_bytes_len(puap_i), proto,
                                             msg, sizeof msg,
                                             PIN_PERM_LARGE_BLOB_WRITE, ZERO32);
            if (pe != 0) { status = pe; goto done; }
        }

        /* Fragmented write (CTAP 2.1 sec. 11.5). A write may arrive in one
         * or several fragments:
         *   - First fragment: offset == 0, `length` (0x04) REQUIRED and
         *     gives the total array size to assemble. This (re)starts a
         *     buffered write, discarding any partial one in progress.
         *   - Later fragments: offset == bytes already buffered, and
         *     `length` MUST be absent.
         * Each fragment is appended at its offset; when the buffered
         * length reaches the declared total the SHA-256 trailer is
         * validated over the body and the array is persisted. Everything
         * is bounded by MAX_LARGE_BLOB_LEN so a fragment can never write
         * past s_wr_buf. */
        if (offset == 0) {
            /* Start (or restart) a buffered write. */
            if (len_i == NULL || !pqfido_cbor_is_uint(len_i)) {
                wr_reset();
                status = CTAP2_ERR_MISSING_PARAMETER; goto done;
            }
            uint64_t total = pqfido_cbor_uint(len_i);
            /* Too big to ever store is a different answer from
              * malformed: the client can free space and retry one and
              * not the other. 17 is the minimum serialised array. */
            if (total > MAX_LARGE_BLOB_LEN) {
                wr_reset();
                status = LB_ERR_STORAGE_FULL; goto done;
            }
            if (total < 17) {
                wr_reset();
                status = LB_ERR_INVALID_LENGTH; goto done;
            }
            /* The first fragment cannot exceed the declared total. */
            if (set_len > total) {
                wr_reset();
                status = LB_ERR_INVALID_LENGTH; goto done;
            }
            s_wr_active = true;
            s_wr_total = (uint32_t)total;
            s_wr_have = 0;
        } else {
            /* Continuation fragment: a buffered write must be in
             * progress, `length` must be absent, and the offset must
             * pick up exactly where the buffered data ends. */
            if (len_i != NULL) {
                wr_reset();
                status = CTAP2_ERR_INVALID_PARAMETER; goto done;
            }
            if (!s_wr_active || offset != s_wr_have) {
                wr_reset();
                status = CTAP2_ERR_INVALID_PARAMETER; goto done;
            }
            /* This fragment must not overrun the declared total. */
            if (set_len > (size_t)(s_wr_total - s_wr_have)) {
                wr_reset();
                status = LB_ERR_INVALID_LENGTH; goto done;
            }
        }

        /* Append this fragment at its offset (bounds enforced above). */
        memcpy(s_wr_buf + s_wr_have, set, set_len);
        s_wr_have += (uint32_t)set_len;

        /* Not done yet -- acknowledge and wait for the next fragment. */
        if (s_wr_have < s_wr_total) {
            status = CTAP2_OK;
            resp[0] = (uint8_t)status;
            *resp_len = 1;
            pqfido_cbor_free(root);
            return 0;
        }

        /* Full array assembled: validate the 16-byte SHA-256 trailer
         * (sec. 6.10.3) over the body, then persist. */
        uint8_t h[32];
        pqf_sha256(s_wr_buf, s_wr_total - 16, h);
        if (memcmp(h, s_wr_buf + s_wr_total - 16, 16) != 0) {
            wr_reset();
            status = CTAP2_ERR_INVALID_PARAMETER; goto done;
        }
        memcpy(s_array, s_wr_buf, s_wr_total);
        s_len = s_wr_total;
        wr_reset();
        commit();
        status = CTAP2_OK;
        resp[0] = (uint8_t)status;
        *resp_len = 1;
        pqfido_cbor_free(root);
        return 0;
    }

    /* Read path. */
    if (get_i == NULL || !pqfido_cbor_is_uint(get_i)) {
        status = CTAP2_ERR_MISSING_PARAMETER; goto done;
    }
    size_t want = (size_t)pqfido_cbor_uint(get_i);
    if (offset > s_len) { status = LB_ERR_INVALID_LENGTH; goto done; }
    size_t end = offset + want;
    if (end > s_len) end = s_len;
    size_t chunk_len = end - offset;

    resp[0] = CTAP2_OK;
    cbor_writer_t w; cbor_w_init(&w, resp + 1, resp_cap - 1);
    cbor_w_map_header(&w, 1);
    cbor_w_uint(&w, 0x01);
    cbor_w_bytes(&w, s_array + offset, chunk_len);
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
