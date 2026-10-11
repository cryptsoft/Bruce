/* resident_store.h -- discoverable (resident) credential index.
 *
 * The stateless credentialID model (credential.c) lets the device
 * recover any credential's keys from the credentialID alone, so
 * server-side (allowList) credentials need no on-device storage. But
 * *discoverable* credentials (rk / passkeys) must be found at
 * GetAssertion time with no allowList -- by rp_id_hash -- and must
 * carry a per-credential signature counter and the user entity so the
 * authenticator can present an account picker. That bookkeeping lives
 * here, in a dedicated flash sector separate from the device-key store
 * (flash_store.c): the slot does NOT hold key material -- keys are
 * still recovered by decrypting the credentialID on demand.
 *
 * MakeCredential inserts a slot only for a discoverable (rk=true)
 * credential (counter starts at 1). Insert overwrites a slot already
 * holding the same (rp_id_hash, user.id), else takes the first empty
 * slot, else fails (the store is full -> CTAP2_ERR_KEY_STORE_FULL per
 * CTAP 2.1 sec. 6.1 -- no silent eviction). creation_order = max(active)+1
 * gives CredentialManagement a stable iteration order.
 *
 * Both builds link the same resident_store.c: the firmware build
 * compiles it against the QSPI sector, while the host test build
 * (test/Makefile) compiles it with -DPQF_RESIDENT_HOST to select the
 * RAM-only branch.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_RESIDENT_STORE_H
#define PQF_RESIDENT_STORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "credential.h"   /* CRED_ID_LEN */

/* Per-credential field caps (match the Rust CredStore). */
#define RES_USER_ID_MAX        64
#define RES_USER_NAME_MAX      64
#define RES_DISPLAY_NAME_MAX   64
#define RES_CRED_BLOB_MAX      32

/* Cap for the persisted UTF-8 RP id string (F4). WebAuthn places no
 * hard limit on rp.id; this is set to 128 to match the Rust firmware's
 * MAX_RP_ID_LEN, so a long rp.id round-trips through enumerateRPs
 * without being truncated on the C port. The string is stored so
 * CredentialManagement enumerateRPs can return a human-readable rp.id
 * instead of an empty placeholder (CTAP 2.1 sec. 6.8.3) -- only rp_id_hash
 * was previously kept. An rp.id still longer than this is truncated for
 * the stored copy; the rp_id_hash (over the full id) is unaffected, so
 * matching/assertion still work. */
#define RES_RP_ID_MAX          128

/* Discoverable-credential slots. The C resident store is its own flash
 * sector with an 8-byte header (magic + version); each slot is 564
 * bytes (with RES_RP_ID_MAX = 128 and CRED_ID_LEN = 161). The most that
 * fit one 4 KiB sector behind the header is
 *   floor((4096 - 8) / 564) = 7
 * slots (8 slots = 4520 B would overflow the sector -- see the
 * _Static_assert in resident_store.c). The Rust port packs credentials
 * into the shared device sector behind a 240-byte header and holds 6;
 * the two ports therefore differ slightly in raw capacity, but both
 * report their real remaining-count via getCredsMetadata. */
#define RESIDENT_PRIMARY_SLOTS 7

/* Optional overflow sectors (build time: the CMake cache variable
 * PQF_RESIDENT_EXTRA_SECTORS, default 0). Each is one more 4 KiB
 * sector, below the master-key sector, with a 16-byte header (magic,
 * version, its index, a tag bound to the master keys) and
 *   floor((4096 - 16) / 564) = 7
 * further slots. Slot indices 0..6 are the primary sector's; overflow
 * sector k holds 7 + 7k .. 13 + 7k. With none (the default) the store
 * is exactly the 7-slot primary sector, byte for byte. The cap of 8
 * bounds the RAM mirror: every slot is held in RAM (564 B each, about
 * 5 KiB of .bss per sector with the enumeration iterators). */
#ifndef PQF_RESIDENT_EXTRA_SECTORS
#define PQF_RESIDENT_EXTRA_SECTORS 0
#endif
#if PQF_RESIDENT_EXTRA_SECTORS < 0 || PQF_RESIDENT_EXTRA_SECTORS > 8
#error "PQF_RESIDENT_EXTRA_SECTORS must be 0..8"
#endif
#define RESIDENT_OVERFLOW_SLOTS 7
#define RESIDENT_MAX_SLOTS      (RESIDENT_PRIMARY_SLOTS \
                                 + PQF_RESIDENT_EXTRA_SECTORS \
                                 * RESIDENT_OVERFLOW_SLOTS)

/* One discoverable-credential record. */
typedef struct {
    uint8_t  state;                                  /* 0 empty, 1 active */
    uint8_t  cred_id[CRED_ID_LEN];                   /* the issued credentialID */
    uint8_t  rp_id_hash[32];
    uint8_t  rp_id_len;                              /* bytes of rp_id below (F4) */
    uint8_t  rp_id[RES_RP_ID_MAX];                   /* UTF-8 rp.id for enumerateRPs */
    uint32_t counter;                                /* per-credential sign count */
    uint8_t  user_id_len;
    uint8_t  user_id[RES_USER_ID_MAX];
    uint8_t  cred_protect;                           /* policy 1/2/3 */
    uint8_t  cred_blob_len;
    uint8_t  cred_blob[RES_CRED_BLOB_MAX];           /* credBlob ext (C-10r-4) */
    uint8_t  user_name_len;
    uint8_t  user_name[RES_USER_NAME_MAX];
    uint8_t  user_display_name_len;
    uint8_t  user_display_name[RES_DISPLAY_NAME_MAX];
    uint32_t creation_order;                         /* stable enumeration key */
} resident_cred_t;

/* Load (or first-time create) the resident-credential sector. Call at
 * boot after flash_store_init(). */
void resident_store_init(void);

/* Erase all slots (factory reset / authenticatorReset). Persists the
 * empty primary sector and erases every overflow sector. Call after
 * flash_store_wipe(), so the overflow tag follows the new keys. */
void resident_store_wipe(void);

/* Insert `cred`: overwrite an active slot with the same (rp_id_hash,
 * user.id) if one exists, else use the first empty slot. Assigns
 * creation_order = max(active)+1 (the caller's creation_order field is
 * ignored). Persists. Returns 0 on success, or -1 when the store is
 * full (no free slot and no matching credential to replace) -- the
 * caller surfaces CTAP2_ERR_KEY_STORE_FULL. */
int resident_store_insert(const resident_cred_t *cred);

/* Number of active credentials / total slot capacity. */
size_t resident_store_count(void);
size_t resident_store_max(void);

/* Fill `idxs` (cap entries) with the slot indices of active
 * credentials whose rp_id_hash matches, sorted by creation_order
 * ascending. Returns the match count (may exceed `cap`; only `cap`
 * are written). */
size_t resident_store_find_by_rp(const uint8_t rp_id_hash[32],
                                 size_t *idxs, size_t cap);

/* Locate an active slot whose stored credentialID equals
 * cred_id[0..len). On a match sets *idx_out and returns 0; else -1. */
int resident_store_find_by_cred_id(const uint8_t *cred_id, size_t len,
                                   size_t *idx_out);

/* Copy slot `idx` into `*out`. Returns 0 on an active slot, else -1. */
int resident_store_get(size_t idx, resident_cred_t *out);

/* Increment slot `idx`'s counter, persist, and return the new value
 * (0 if idx is invalid/empty). */
uint32_t resident_store_bump_counter(size_t idx);

/* Tombstone slot `idx` (CredentialManagement deleteCredential).
 * Every mutator (insert, bump, delete, update) rewrites only the one
 * sector holding the slot. */
void resident_store_delete(size_t idx);

/* Replace user.name / user.displayName on slot `idx`
 * (updateUserInformation). A NULL field is left untouched. Persists. */
void resident_store_update_user(size_t idx,
                                const uint8_t *name, size_t name_len,
                                const uint8_t *disp, size_t disp_len);

/* Fill `idxs` with all active slot indices sorted by creation_order
 * ascending (CredentialManagement enumeration). Returns the count. */
size_t resident_store_iter_by_creation(size_t *idxs, size_t cap);

#endif /* PQF_RESIDENT_STORE_H */
