/* resident_store.c -- discoverable-credential index in QSPI flash.
 *
 * See resident_store.h for the model. We use the flash sector one
 * below the device store. Flash map (flash_store.c owns two sectors):
 *
 *     last sector        : store -- counter + PIN + config (flash_store.c)
 *     last - 1 sector    : resident credentials           (this file)
 *     last - 2 sector    : large blobs                    (C-10r-5)
 *     last - 3 sector    : device master keys             (flash_store.c, H1)
 *     last - 4 - k       : resident overflow sector k     (this file;
 *                          k < PQF_RESIDENT_EXTRA_SECTORS, none by
 *                          default)
 *
 * Sector layout: an 8-byte header (magic + version) followed by the
 * RAM slot array copied verbatim. The array is read back by the same
 * firmware build that wrote it, so the in-memory struct layout is the
 * persisted format -- no field-by-field serialisation needed.
 *
 * Overflow sector layout: a 16-byte header -- magic "RKOV", RS_VERSION,
 * the sector's own index k, and a tag bound to the master keys -- then
 * RESIDENT_OVERFLOW_SLOTS slots in the same format. The primary sector
 * is untouched by the option, so a store written by a default build is
 * read the same by a build with overflow sectors, and the other way
 * round (the overflow slots are simply not seen by a smaller build).
 * Only the sector holding a changed slot is rewritten. An overflow
 * sector is written slots first, header last: one guarded op erases it
 * and programs everything but the header, a second programs page 0
 * again with the header filled in. A power loss in between leaves the
 * header erased, so the sector reads as empty rather than as a valid
 * header over partial slots; no other sector is touched. The tag
 * (the first four bytes of HMAC(mac key, "pqf-rk-overflow")) makes a
 * sector left behind across an authenticatorReset by a build that did
 * not know about it read as empty too: its credentialIDs no longer
 * decrypt under the new keys.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

/* The store logic is shared between the firmware (QSPI-backed) and the
 * host test harness (RAM only). Define PQF_RESIDENT_HOST for the host
 * build to drop the pico-sdk flash machinery; everything else -- the
 * slot array, insert/find/sort logic -- is identical on both. */
#ifndef PQF_RESIDENT_HOST
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "flash_store.h"        /* flash_store_guarded_op (M1-safe commit) */
#endif

#include "resident_store.h"

#if !defined(PQF_RESIDENT_HOST) && PQF_RESIDENT_EXTRA_SECTORS > 0
#include "pqf_crypto.h"         /* pqf_hmac_sha256 (overflow key tag) */
#include "pqf_cleanse.h"
#endif

#ifndef PQF_RESIDENT_HOST

#ifndef PICO_FLASH_SIZE_BYTES
#define PICO_FLASH_SIZE_BYTES (2u * 1024u * 1024u)
#endif

#define RS_SECTOR_SIZE   FLASH_SECTOR_SIZE                          /* 4096 */
#define RS_OFFSET        (PICO_FLASH_SIZE_BYTES - 2u * RS_SECTOR_SIZE)
#define RS_XIP           ((const uint8_t *)(XIP_BASE + RS_OFFSET))

#define RS_MAGIC         0x4F444946u   /* "FIDO" little-endian */
/* v3 (#15): RES_RP_ID_MAX grew 64 -> 128 (Rust parity, no rp.id
 * truncation), which enlarges the slot struct and changes both the
 * per-slot layout and RESIDENT_MAX_SLOTS (8 -> 7). The magic is
 * unchanged, so an older (v1/v2) sector is detected by the version
 * mismatch and treated as a fresh (empty) store -- a one-time
 * invalidation of pre-upgrade discoverable credentials, which is
 * expected and approved for this schema bump.
 *   v2 (F4): slot struct gained the UTF-8 rp_id string.
 *   v1     : original layout (rp_id_hash only). */
#define RS_VERSION       3u
#define RS_HEADER        8u            /* magic(4) + version(4) */

/* The whole slot array must fit one sector behind the header. */
_Static_assert(RS_HEADER + sizeof(resident_cred_t) * RESIDENT_PRIMARY_SLOTS
               <= RS_SECTOR_SIZE,
               "resident slot array overflows its flash sector");

/* Overflow sector k sits below the master-key sector (last - 3). */
#define RS_OV_OFFSET(k)  (PICO_FLASH_SIZE_BYTES \
                          - (5u + (uint32_t)(k)) * RS_SECTOR_SIZE)
#define RS_OV_XIP(k)     ((const uint8_t *)(XIP_BASE + RS_OV_OFFSET(k)))
#define RS_OV_MAGIC      0x564F4B52u   /* "RKOV" little-endian */
#define RS_OV_HEADER     16u           /* magic, version, index, tag */

_Static_assert(RS_OV_HEADER
               + sizeof(resident_cred_t) * RESIDENT_OVERFLOW_SLOTS
               <= RS_SECTOR_SIZE,
               "overflow slot array overflows its flash sector");
_Static_assert(RS_OV_HEADER
               + sizeof(resident_cred_t) * (RESIDENT_OVERFLOW_SLOTS + 1)
               > RS_SECTOR_SIZE,
               "RESIDENT_OVERFLOW_SLOTS no longer fills its sector");
_Static_assert(RS_OV_HEADER <= FLASH_PAGE_SIZE,
               "overflow header must sit in page 0");

#endif /* !PQF_RESIDENT_HOST */

#define STATE_EMPTY      0u
#define STATE_ACTIVE     1u

static resident_cred_t s_slots[RESIDENT_MAX_SLOTS];

/* Which sector holds slot `idx`: 0 = primary, 1 + k = overflow k. */
static size_t sector_of(size_t idx)
{
    if (idx < RESIDENT_PRIMARY_SLOTS)
        return 0;
    return 1 + (idx - RESIDENT_PRIMARY_SLOTS) / RESIDENT_OVERFLOW_SLOTS;
}

/* Defend against a corrupted flash sector: a persisted slot whose
 * variable-length field exceeds its array cap would drive an
 * intra-struct over-read in the downstream cbor_w_bytes/memcpy
 * emitters. Insert paths always clamp, so this is unreachable over USB
 * -- only a garbage sector can trip it. Treat any over-cap slot as
 * empty (zeroed) rather than trusting the length. Call after loading
 * the slot array from flash. */
static void sanitise_slots(void)
{
    for (size_t i = 0; i < RESIDENT_MAX_SLOTS; i++) {
        resident_cred_t *s = &s_slots[i];
        if (s->state != STATE_ACTIVE)
            continue;
        if (s->user_id_len          > RES_USER_ID_MAX
         || s->user_name_len        > RES_USER_NAME_MAX
         || s->user_display_name_len > RES_DISPLAY_NAME_MAX
         || s->cred_blob_len        > RES_CRED_BLOB_MAX
         || s->rp_id_len            > RES_RP_ID_MAX)
            memset(s, 0, sizeof *s);   /* -> STATE_EMPTY */
    }
}

#ifndef PQF_RESIDENT_HOST
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
#endif

#ifdef PQF_RESIDENT_HOST

/* Host build: the RAM mirror IS the store; "commit" is a no-op and a
 * fresh process starts with an empty table. */
static void commit(void) { }
static void commit_sector(size_t sec) { (void)sec; }
static void erase_overflow(void) { }

void resident_store_init(void)
{
    memset(s_slots, 0, sizeof s_slots);
    sanitise_slots();   /* no-op on a zeroed table; keeps the helper live */
}

#else /* firmware: QSPI-backed */

static uint8_t s_commit_page[RS_SECTOR_SIZE];

static void commit(void)
{
    memset(s_commit_page, 0, sizeof s_commit_page);
    wr_u32(s_commit_page + 0, RS_MAGIC);
    wr_u32(s_commit_page + 4, RS_VERSION);
    memcpy(s_commit_page + RS_HEADER, s_slots,
           sizeof(resident_cred_t) * RESIDENT_PRIMARY_SLOTS);

    /* Erase + program through flash_store's guarded direct-ROM path
     * (core 1 parked in its RAM spin + IRQs masked + boot-ROM flash
     * calls, M1). The pico-sdk flash_range_* wrappers this used to call
     * hang nondeterministically on pure-RISC-V silicon -- see
     * flash_op_cb in flash_store.c. */
    flash_store_guarded_op(RS_OFFSET, RS_SECTOR_SIZE,
                           s_commit_page, RS_SECTOR_SIZE);
}

#if PQF_RESIDENT_EXTRA_SECTORS > 0

static uint32_t s_ov_tag;   /* overflow key tag under the current keys */

/* Recompute the overflow tag from the current master keys. */
static void refresh_tag(void)
{
    static const uint8_t label[] = "pqf-rk-overflow";
    uint8_t aes[32], mac[32], t[32];
    flash_store_keys(aes, mac);
    pqf_hmac_sha256(mac, sizeof mac, label, sizeof label - 1, t);
    s_ov_tag = rd_u32(t);
    pqf_cleanse(aes, sizeof aes);
    pqf_cleanse(mac, sizeof mac);
    pqf_cleanse(t, sizeof t);
}

/* Rewrite overflow sector k from its RAM slots, header last. */
static void commit_overflow(size_t k)
{
    const resident_cred_t *first =
        &s_slots[RESIDENT_PRIMARY_SLOTS + k * RESIDENT_OVERFLOW_SLOTS];
    uint32_t off = RS_OV_OFFSET(k);

    memset(s_commit_page, 0, sizeof s_commit_page);
    memcpy(s_commit_page + RS_OV_HEADER, first,
           sizeof(resident_cred_t) * RESIDENT_OVERFLOW_SLOTS);
    /* Pass 1: erase, and program everything but the header, which is
     * left erased -- a tear from here on reads as an empty sector. */
    memset(s_commit_page, 0xFF, RS_OV_HEADER);
    flash_store_guarded_op(off, RS_SECTOR_SIZE,
                           s_commit_page, RS_SECTOR_SIZE);
    /* Pass 2: page 0 again, header filled in. The slot bytes in it are
     * already programmed with the same bits, so only the header moves. */
    wr_u32(s_commit_page + 0, RS_OV_MAGIC);
    wr_u32(s_commit_page + 4, RS_VERSION);
    wr_u32(s_commit_page + 8, (uint32_t)k);
    wr_u32(s_commit_page + 12, s_ov_tag);
    flash_store_guarded_op(off, 0, s_commit_page, FLASH_PAGE_SIZE);
}

/* Load overflow sector k if its header is ours; else leave it empty.
 * Nothing is written for an absent sector: it is materialised by the
 * first credential that lands in it. */
static void load_overflow(size_t k)
{
    const uint8_t *o = RS_OV_XIP(k);
    if (rd_u32(o + 0) == RS_OV_MAGIC && rd_u32(o + 4) == RS_VERSION
        && rd_u32(o + 8) == (uint32_t)k && rd_u32(o + 12) == s_ov_tag)
        memcpy(&s_slots[RESIDENT_PRIMARY_SLOTS
                        + k * RESIDENT_OVERFLOW_SLOTS],
               o + RS_OV_HEADER,
               sizeof(resident_cred_t) * RESIDENT_OVERFLOW_SLOTS);
}

static void erase_overflow(void)
{
    refresh_tag();
    for (size_t k = 0; k < PQF_RESIDENT_EXTRA_SECTORS; k++)
        flash_store_guarded_op(RS_OV_OFFSET(k), RS_SECTOR_SIZE, NULL, 0);
}

#else /* no overflow sectors */

static void erase_overflow(void) { }

#endif /* PQF_RESIDENT_EXTRA_SECTORS > 0 */

/* Persist the one sector `sec` (see sector_of). */
static void commit_sector(size_t sec)
{
#if PQF_RESIDENT_EXTRA_SECTORS > 0
    if (sec != 0) {
        commit_overflow(sec - 1);
        return;
    }
#else
    (void)sec;
#endif
    commit();
}

void resident_store_init(void)
{
    const uint8_t *s = RS_XIP;
    if (rd_u32(s + 0) == RS_MAGIC && rd_u32(s + 4) == RS_VERSION) {
        memset(s_slots, 0, sizeof s_slots);
        memcpy(s_slots, s + RS_HEADER,
               sizeof(resident_cred_t) * RESIDENT_PRIMARY_SLOTS);
    } else {
        memset(s_slots, 0, sizeof s_slots);   /* all STATE_EMPTY */
        commit();
    }
#if PQF_RESIDENT_EXTRA_SECTORS > 0
    /* Independent of the primary sector: a primary reset for any
     * reason leaves the overflow sectors as they are. */
    refresh_tag();
    for (size_t k = 0; k < PQF_RESIDENT_EXTRA_SECTORS; k++)
        load_overflow(k);
#endif
    /* Clamp persisted lengths: a corrupt sector must not drive an
     * intra-struct over-read in the CBOR emitters (L3). */
    sanitise_slots();
}

#endif /* PQF_RESIDENT_HOST */

void resident_store_wipe(void)
{
    memset(s_slots, 0, sizeof s_slots);
    erase_overflow();
    commit();
}

static uint32_t next_creation_order(void)
{
    uint32_t mx = 0;
    for (size_t i = 0; i < RESIDENT_MAX_SLOTS; i++)
        if (s_slots[i].state == STATE_ACTIVE && s_slots[i].creation_order > mx)
            mx = s_slots[i].creation_order;
    return mx + 1;
}

int resident_store_insert(const resident_cred_t *cred)
{
    /* Slot selection (CTAP 2.1 sec. 6.1, step "discoverable credential"):
     *   1. If an active slot already holds a credential for the same
     *      (rp_id_hash, user.id), overwrite it -- re-registering the same
     *      user on the same RP replaces the prior discoverable credential
     *      rather than consuming a second slot.
     *   2. Otherwise take the first empty slot.
     *   3. Otherwise the store is full: refuse with -1 so the caller can
     *      return CTAP2_ERR_KEY_STORE_FULL. (Earlier builds FIFO-evicted
     *      slot 0, silently destroying a still-valid credential; that is
     *      replaced here per sec. 6.1's full-store handling.) */
    size_t slot = RESIDENT_MAX_SLOTS;   /* sentinel: none chosen yet */

    for (size_t i = 0; i < RESIDENT_MAX_SLOTS; i++) {
        if (s_slots[i].state != STATE_ACTIVE) continue;
        if (memcmp(s_slots[i].rp_id_hash, cred->rp_id_hash, 32) == 0
            && s_slots[i].user_id_len == cred->user_id_len
            && cred->user_id_len > 0
            && memcmp(s_slots[i].user_id, cred->user_id,
                      cred->user_id_len) == 0) {
            slot = i;
            break;
        }
    }
    if (slot == RESIDENT_MAX_SLOTS) {
        for (size_t i = 0; i < RESIDENT_MAX_SLOTS; i++) {
            if (s_slots[i].state != STATE_ACTIVE) { slot = i; break; }
        }
    }
    if (slot == RESIDENT_MAX_SLOTS)
        return -1;                       /* store full -> KEY_STORE_FULL */

    uint32_t order = next_creation_order();
    s_slots[slot] = *cred;
    s_slots[slot].state = STATE_ACTIVE;
    s_slots[slot].creation_order = order;
    commit_sector(sector_of(slot));
    return 0;
}

size_t resident_store_count(void)
{
    size_t n = 0;
    for (size_t i = 0; i < RESIDENT_MAX_SLOTS; i++)
        if (s_slots[i].state == STATE_ACTIVE) n++;
    return n;
}

size_t resident_store_max(void)
{
    return RESIDENT_MAX_SLOTS;
}

/* Collect active slot indices passing `keep`, sorted by creation_order
 * ascending. Returns the total match count; writes up to `cap`. */
static size_t collect_sorted(size_t *idxs, size_t cap,
                             int (*keep)(const resident_cred_t *, const void *),
                             const void *ctx)
{
    size_t order[RESIDENT_MAX_SLOTS];
    size_t cand[RESIDENT_MAX_SLOTS];
    size_t n = 0;
    for (size_t i = 0; i < RESIDENT_MAX_SLOTS; i++) {
        if (s_slots[i].state != STATE_ACTIVE) continue;
        if (keep && !keep(&s_slots[i], ctx)) continue;
        cand[n] = i;
        order[n] = s_slots[i].creation_order;
        n++;
    }
    /* Insertion sort by creation_order ascending (n <= RESIDENT_MAX_SLOTS). */
    for (size_t i = 1; i < n; i++) {
        size_t ci = cand[i], oi = order[i];
        size_t j = i;
        while (j > 0 && order[j - 1] > oi) {
            order[j] = order[j - 1];
            cand[j] = cand[j - 1];
            j--;
        }
        order[j] = oi;
        cand[j] = ci;
    }
    for (size_t i = 0; i < n && i < cap; i++) idxs[i] = cand[i];
    return n;
}

static int keep_rp(const resident_cred_t *s, const void *ctx)
{
    return memcmp(s->rp_id_hash, (const uint8_t *)ctx, 32) == 0;
}

size_t resident_store_find_by_rp(const uint8_t rp_id_hash[32],
                                 size_t *idxs, size_t cap)
{
    return collect_sorted(idxs, cap, keep_rp, rp_id_hash);
}

int resident_store_find_by_cred_id(const uint8_t *cred_id, size_t len,
                                   size_t *idx_out)
{
    if (len != CRED_ID_LEN) return -1;
    for (size_t i = 0; i < RESIDENT_MAX_SLOTS; i++) {
        if (s_slots[i].state != STATE_ACTIVE) continue;
        if (memcmp(s_slots[i].cred_id, cred_id, CRED_ID_LEN) == 0) {
            *idx_out = i;
            return 0;
        }
    }
    return -1;
}

int resident_store_get(size_t idx, resident_cred_t *out)
{
    if (idx >= RESIDENT_MAX_SLOTS || s_slots[idx].state != STATE_ACTIVE)
        return -1;
    *out = s_slots[idx];
    return 0;
}

uint32_t resident_store_bump_counter(size_t idx)
{
    if (idx >= RESIDENT_MAX_SLOTS || s_slots[idx].state != STATE_ACTIVE)
        return 0;
    s_slots[idx].counter += 1;
    commit_sector(sector_of(idx));
    return s_slots[idx].counter;
}

void resident_store_delete(size_t idx)
{
    if (idx >= RESIDENT_MAX_SLOTS) return;
    s_slots[idx].state = STATE_EMPTY;
    commit_sector(sector_of(idx));
}

void resident_store_update_user(size_t idx,
                                const uint8_t *name, size_t name_len,
                                const uint8_t *disp, size_t disp_len)
{
    if (idx >= RESIDENT_MAX_SLOTS || s_slots[idx].state != STATE_ACTIVE)
        return;
    if (name) {
        if (name_len > RES_USER_NAME_MAX) name_len = RES_USER_NAME_MAX;
        memset(s_slots[idx].user_name, 0, RES_USER_NAME_MAX);
        memcpy(s_slots[idx].user_name, name, name_len);
        s_slots[idx].user_name_len = (uint8_t)name_len;
    }
    if (disp) {
        if (disp_len > RES_DISPLAY_NAME_MAX) disp_len = RES_DISPLAY_NAME_MAX;
        memset(s_slots[idx].user_display_name, 0, RES_DISPLAY_NAME_MAX);
        memcpy(s_slots[idx].user_display_name, disp, disp_len);
        s_slots[idx].user_display_name_len = (uint8_t)disp_len;
    }
    commit_sector(sector_of(idx));
}

size_t resident_store_iter_by_creation(size_t *idxs, size_t cap)
{
    return collect_sorted(idxs, cap, NULL, NULL);
}
