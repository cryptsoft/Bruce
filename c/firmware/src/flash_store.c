/* flash_store.c -- persistent device state across two QSPI sectors.
 *
 * H1 fix: the device master keys now live in a DEDICATED sector that
 * routine commits never touch, so a power glitch during a counter /
 * PIN / config write can lose those volatile fields (a clean reset of
 * that state) but can NEVER lose the master keys and orphan every
 * credential.
 *
 * Flash map (offsets measured back from the end of flash, each 4 KiB):
 *
 *     last - 0 sector : STORE  -- counter HWM + PIN + config + CRC
 *                                 (this file's commit(); rewritten on
 *                                  every counter-block / PIN / config
 *                                  change)
 *     last - 1 sector : resident credentials      (resident_store.c)
 *     last - 2 sector : large blobs                (large_blobs.c)
 *     last - 3 sector : KEYS   -- magic + version + aes_key + mac_key
 *                                 (this file's commit_keys(); written
 *                                  ONLY on first-boot provisioning and
 *                                  on flash_store_wipe / Reset)
 *
 * STORE sector layout (one 256-byte flash page):
 *
 *     off  0:  magic      "PQCF"  (4)
 *     off  4:  version    = 5     (u32 LE)
 *     off  8:  sign_hwm           (u32 LE -- reserved-up-to counter)
 *     off 12:  pin_set            (1)
 *     off 13:  pin_retries        (1)
 *     off 14:  pad                (2)
 *     off 16:  pin_hash           (16  -- SHA-256(PIN) truncated)
 *     off 32:  always_uv          (1)
 *     off 33:  enterprise_attest  (1)
 *     off 34:  min_pin_length     (1   -- 0 => built-in default)
 *     off 35:  min_pin_rpid_count (1)
 *     off 36:  min_pin_rpid_hashes(MAX_MIN_PIN_LEN_RPIDS * 32 = 128)
 *                                       -> ends at off 164
 *     off 164: force_pin_change   (1   -- X13, v5)
 *     off 252: crc32              (u32 LE -- over bytes [0,252))
 *
 * Torn-write protection: a single page can't be programmed atomically,
 * so instead of relying on a header magic written last we checksum the
 * whole store page. On load an invalid CRC => the store is treated as
 * empty (counter/PIN/config revert to defaults), never as a valid-but-
 * stale record. The keys are in their own sector, so they survive
 * regardless.
 *
 * KEY sector layout (first bytes of its sector):
 *
 *     off  0:  magic      "PQKY"  (4)
 *     off  4:  version    = 1     (u32 LE)
 *     off  8:  aes_key            (32)
 *     off 40:  mac_key            (32)
 *     off 256: PIN-armed word     (4   -- page 1; erased until a PIN is
 *                                       set under these keys)
 *
 * PIN-armed word: keys that survive a torn store commit would otherwise
 * outlive the PIN that guarded them -- the token would boot PIN-less,
 * anyone could set a new PIN, and every credential id it ever issued
 * would still decrypt, user verification included. So the first PIN
 * set also programs a word in the key sector (arm_pin), and a token
 * that boots with that word set and no PIN in the store comes up
 * PIN-blocked (flash_store_init): no PIN can be set or used until
 * authenticatorReset, which wipes the keys and so retires every old
 * credential id. commit_keys() programs only page 0, so on every token
 * -- including one whose keys an older build minted -- the word reads
 * erased until arm_pin() programs it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "pico/stdlib.h"
#include "pico/bootrom.h"       /* rom_func_lookup_inline (direct ROM flash calls) */
#include "hardware/flash.h"
#include "hardware/structs/qmi.h"   /* QMI window-0 fast-read save/restore */
#include "hardware/sync.h"
#include "core1_signer.h"       /* core1_run_flash_op (M1 lockout) */

#include "flash_store.h"
#include "openssl/rand.h"

#ifndef PICO_FLASH_SIZE_BYTES
/* Fallback: the Waveshare RP2350-LCD-1.47 carries 16 MiB; the pico2
 * board header normally defines this. Use 2 MiB as a safe floor only
 * if nothing set it (the store sits relative to the end of flash). */
#define PICO_FLASH_SIZE_BYTES (2u * 1024u * 1024u)
#endif

#define STORE_SECTOR_SIZE   FLASH_SECTOR_SIZE                 /* 4096 */
#define STORE_OFFSET        (PICO_FLASH_SIZE_BYTES - STORE_SECTOR_SIZE)
#define STORE_XIP           ((const uint8_t *)(XIP_BASE + STORE_OFFSET))

/* Master-key sector: the fourth sector from the end, below the
 * resident-store (last-1) and large-blob (last-2) sectors so it
 * collides with neither. Never erased by a routine commit(). */
#define KEY_OFFSET          (PICO_FLASH_SIZE_BYTES - 4u * STORE_SECTOR_SIZE)
#define KEY_XIP             ((const uint8_t *)(XIP_BASE + KEY_OFFSET))

#define STORE_MAGIC         0x46435150u   /* "PQCF" little-endian */
#define STORE_VERSION       5u            /* v5: + force_pin_change (X13) */

#define KEY_MAGIC           0x594B5150u   /* "PQKY" little-endian */
#define KEY_VERSION         1u

/* STORE-page field offsets (keys removed; everything shifted down). */
#define ST_OFF_SIGN_HWM         8
#define ST_OFF_PIN_SET          12
#define ST_OFF_PIN_RETRIES      13
#define ST_OFF_PIN_HASH         16
#define CFG_OFF_ALWAYS_UV       32
#define CFG_OFF_ENT_ATTEST      33
#define CFG_OFF_MIN_PIN_LEN     34
#define CFG_OFF_MIN_PIN_COUNT   35
#define CFG_OFF_MIN_PIN_RPIDS   36   /* MAX_MIN_PIN_LEN_RPIDS * 32 -> 164 */
#define CFG_OFF_FORCE_PIN_CHG   164  /* X13 forcePINChange (v5)          */
#define ST_OFF_CRC              252  /* CRC32 over bytes [0, ST_OFF_CRC) */

/* KEY-sector field offsets. */
#define KEY_OFF_AES             8
#define KEY_OFF_MAC             40
#define KEY_OFF_PIN_ARMED       FLASH_PAGE_SIZE   /* first word of page 1 */

/* Arming programs only page 1, so a power loss while arming cannot
 * reach the keys in page 0. */
_Static_assert(KEY_OFF_MAC + 32 <= KEY_OFF_PIN_ARMED,
               "the PIN-armed word shares a page with the keys");

/* The config block plus its CRC must fit one flash page. */
_Static_assert(CFG_OFF_MIN_PIN_RPIDS + MAX_MIN_PIN_LEN_RPIDS * 32 <= CFG_OFF_FORCE_PIN_CHG,
               "store config block overruns the force_pin_change byte");
_Static_assert(CFG_OFF_FORCE_PIN_CHG + 1 <= ST_OFF_CRC,
               "store config block overruns the CRC slot");
_Static_assert(ST_OFF_CRC + 4 <= FLASH_PAGE_SIZE,
               "store page exceeds one flash page");

/* How many counter values we reserve per flash write. Bigger = fewer
 * flash writes (longer flash life) at the cost of skipping up to
 * STRIDE-1 counter values on an unclean reboot. RPs only require the
 * counter to be monotonic-increasing, so skips are harmless. */
#define SIGN_COUNT_STRIDE   32u

/* In-RAM mirror of the persisted record + the live counter. */
static uint8_t  s_aes_key[32];
static uint8_t  s_mac_key[32];
static uint32_t s_sign_hwm;       /* reserved-up-to (persisted)   */
static uint32_t s_sign_next;      /* next value to hand out (RAM) */
static uint8_t  s_pin_set;        /* 0/1                          */
static uint8_t  s_pin_retries;    /* attempts before lockout      */
static uint8_t  s_pin_hash[PIN_HASH_LEN];
/* authenticatorConfig policy (v3). */
static uint8_t  s_always_uv;      /* 0/1                          */
static uint8_t  s_ent_attest;     /* 0/1 (advisory)               */
static uint8_t  s_min_pin_len;    /* 0 => built-in default         */
static uint8_t  s_min_pin_count;  /* # of RP-id hashes below      */
static uint8_t  s_min_pin_rpids[MAX_MIN_PIN_LEN_RPIDS][32];
static uint8_t  s_force_pin_chg;  /* 0/1 (X13 forcePINChange)     */

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

/* CRC-32 (IEEE 802.3, reflected) over the store page body. A torn
 * program leaves a mismatching CRC, so an interrupted commit reads back
 * as an invalid (empty) store rather than a falsely-valid record. */
static uint32_t crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ---- lockout-safe flash primitives (H1 + M1) ------------------- *
 *
 * Erase + program take QSPI out of XIP. Core 1 runs the signing worker
 * from XIP flash, so it must be parked first. core1_run_flash_op()
 * (core1_signer.c) masks interrupts on this core AND parks core 1 in a
 * RAM-resident spin for the XIP-off window, then runs the callback that
 * does the actual erase/program. It replaces pico-sdk flash_safe_execute
 * -- see core1_signer.h for why that hangs on the Hazard3 cores. */

typedef struct {
    uint32_t       offset;
    uint32_t       erase_len;
    const uint8_t *prog;        /* NULL => erase only */
    uint32_t       prog_len;
} flash_op_t;

/* Direct boot-ROM flash sequence, byte-for-byte the Rust port's
 * erase_region()/program() (crates/firmware/src/flash_store.rs) --
 * NOT pico-sdk's flash_range_erase/flash_range_program.
 *
 * Why: on pure-RISC-V (both cores Hazard3) silicon, the pico-sdk
 * wrappers hang nondeterministically after a few back-to-back commits
 * (observed as "freezes right after entering the PIN"), while the Rust
 * port's direct-ROM sequence runs the identical workload on the same
 * chip reliably. The pico-sdk wrappers differ in three ways -- they
 * re-enter XIP by CALLING a RAM copy of boot2 as a function (instead of
 * the ROM's flash_enter_cmd_xip), run xip_cache_clean_all(), and
 * save/restore the QMI CS1 window -- and at least one of those
 * misbehaves on Hazard3. Rather than bisect pico-sdk, mirror the
 * proven Rust sequence exactly:
 *
 *     connect_internal_flash(); flash_exit_xip();
 *     flash_range_erase(off, 4K, 4K, 0x20);   // W25Q sector erase
 *     [flash_range_program(off, buf, len);]
 *     flash_flush_cache(); flash_enter_cmd_xip();
 *
 * RAM-resident (M1): no XIP fetch on this core while QSPI is in
 * command mode; the boot-ROM routines run from ROM, not flash. After
 * flash_enter_cmd_xip XIP is back in (slow, 03h serial) read mode --
 * same post-op state the Rust firmware runs in. */
static void __no_inline_not_in_flash_func(flash_op_cb)(void *arg)
{
    const flash_op_t *op = (const flash_op_t *)arg;

    rom_connect_internal_flash_fn connect_internal_flash_func =
        (rom_connect_internal_flash_fn)rom_func_lookup_inline(ROM_FUNC_CONNECT_INTERNAL_FLASH);
    rom_flash_exit_xip_fn flash_exit_xip_func =
        (rom_flash_exit_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_EXIT_XIP);
    rom_flash_range_erase_fn flash_range_erase_func =
        (rom_flash_range_erase_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_RANGE_ERASE);
    rom_flash_range_program_fn flash_range_program_func =
        (rom_flash_range_program_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_RANGE_PROGRAM);
    rom_flash_flush_cache_fn flash_flush_cache_func =
        (rom_flash_flush_cache_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_FLUSH_CACHE);
    rom_flash_enter_cmd_xip_fn flash_enter_cmd_xip_func =
        (rom_flash_enter_cmd_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_ENTER_CMD_XIP);

    /* Snapshot the QMI window-0 read configuration. The bootrom's
     * flash_enter_cmd_xip() below restores XIP as slow single-bit 03h
     * serial reads, discarding the fast quad setup boot stage 2 put
     * here. On a copy_to_ram image nobody notices -- no code is fetched
     * from flash again. On an XIP image EVERY subsequent instruction
     * fetch pays for it: measured 1327 cycles per 8-byte cache line
     * (~0.9 MB/s), which turns a ~1 s ML-DSA-65 sign into ~13 s and
     * blows past the host's CTAP timeout. Since ctap2 reserves the
     * signature counter (a flash write) immediately BEFORE every sign,
     * every sign on an XIP build ran in the slow mode.
     *
     * pico-sdk has the same gap: its RP2040 path re-runs boot2 to
     * restore fast mode (flash_enable_xip_via_boot2), but the RP2350
     * path only calls the ROM helper. */
    uint32_t qmi_timing = qmi_hw->m[0].timing;
    uint32_t qmi_rfmt   = qmi_hw->m[0].rfmt;
    uint32_t qmi_rcmd   = qmi_hw->m[0].rcmd;

    __compiler_memory_barrier();    /* no flash accesses past this point */

    connect_internal_flash_func();
    flash_exit_xip_func();
    /* 0x20 = W25Q 4 KiB sector erase; block_size == FLASH_SECTOR_SIZE so
     * every sector goes through the sector-erase command -- exactly the
     * Rust port's (SECTOR_SIZE, SECTOR_SIZE, BLOCK_ERASE_CMD) call. */
    if (op->erase_len != 0)         /* 0: program only (resident_store) */
        flash_range_erase_func(op->offset, op->erase_len,
                               FLASH_SECTOR_SIZE, 0x20);
    if (op->prog != NULL)
        flash_range_program_func(op->offset, op->prog, op->prog_len);
    flash_flush_cache_func();       /* also clears the CSn IO force */
    flash_enter_cmd_xip_func();

    /* Put the fast quad read configuration back. Register writes only --
     * no flash access -- and the cache was just flushed, so the next
     * fetch refills through the restored window. */
    qmi_hw->m[0].timing = qmi_timing;
    qmi_hw->m[0].rfmt   = qmi_rfmt;
    qmi_hw->m[0].rcmd   = qmi_rcmd;
    __compiler_memory_barrier();
}

/* Run an erase (+ optional program) with core 1 parked in its
 * RAM-resident spin for the XIP-off window. core1_run_flash_op is the
 * firmware's own M1 lockout (see core1_signer.h) -- it replaces pico-sdk
 * flash_safe_execute, whose FIFO-IRQ multicore_lockout hangs core 0
 * between the two Hazard3 (RISC-V) cores. */
static void flash_guarded(const flash_op_t *op)
{
    core1_run_flash_op(flash_op_cb, (void *)op);
}

/* Public wrapper so resident_store.c / large_blobs.c reuse the SAME
 * direct-ROM sequence instead of carrying their own pico-sdk
 * flash_range_* callbacks (which hang on pure-RISC-V silicon -- see
 * flash_op_cb). */
void flash_store_guarded_op(uint32_t offset, uint32_t erase_len,
                            const uint8_t *prog, uint32_t prog_len)
{
    flash_op_t op = {
        .offset    = offset,
        .erase_len = erase_len,
        .prog      = prog,
        .prog_len  = prog_len,
    };
    flash_guarded(&op);
}

/* Serialise the volatile store (counter HWM + PIN + config) and commit
 * it to its own sector. NEVER touches the master-key sector, so a torn
 * write here can lose counter/PIN/config but never the keys. */
static void commit(void)
{
    uint8_t page[FLASH_PAGE_SIZE];
    memset(page, 0, sizeof page);
    wr_u32(page + 0, STORE_MAGIC);
    wr_u32(page + 4, STORE_VERSION);
    wr_u32(page + ST_OFF_SIGN_HWM, s_sign_hwm);
    page[ST_OFF_PIN_SET]     = s_pin_set;
    page[ST_OFF_PIN_RETRIES] = s_pin_retries;
    memcpy(page + ST_OFF_PIN_HASH, s_pin_hash, PIN_HASH_LEN);
    page[CFG_OFF_ALWAYS_UV]     = s_always_uv;
    page[CFG_OFF_ENT_ATTEST]    = s_ent_attest;
    page[CFG_OFF_MIN_PIN_LEN]   = s_min_pin_len;
    page[CFG_OFF_MIN_PIN_COUNT] = s_min_pin_count;
    memcpy(page + CFG_OFF_MIN_PIN_RPIDS, s_min_pin_rpids,
           sizeof s_min_pin_rpids);
    page[CFG_OFF_FORCE_PIN_CHG] = s_force_pin_chg;
    wr_u32(page + ST_OFF_CRC, crc32(page, ST_OFF_CRC));

    flash_op_t op = { STORE_OFFSET, STORE_SECTOR_SIZE, page, FLASH_PAGE_SIZE };
    flash_guarded(&op);
}

/* Persist the master keys to their dedicated sector. Called ONLY on
 * first-boot provisioning and on flash_store_wipe -- never by a routine
 * counter/PIN/config commit(). */
static void commit_keys(void)
{
    uint8_t page[FLASH_PAGE_SIZE];
    memset(page, 0, sizeof page);
    wr_u32(page + 0, KEY_MAGIC);
    wr_u32(page + 4, KEY_VERSION);
    memcpy(page + KEY_OFF_AES, s_aes_key, 32);
    memcpy(page + KEY_OFF_MAC, s_mac_key, 32);

    flash_op_t op = { KEY_OFFSET, STORE_SECTOR_SIZE, page, FLASH_PAGE_SIZE };
    flash_guarded(&op);
}

/* True once a PIN has been set under the current master keys. Any value
 * but the erased one counts: a power loss while arming leaves some bits
 * cleared, and that fails closed. */
static bool pin_armed(void)
{
    return rd_u32(KEY_XIP + KEY_OFF_PIN_ARMED) != 0xFFFFFFFFu;
}

/* Record in the key sector that a PIN has been set under these keys.
 * Program-only, no erase: NOR programming only clears bits, every byte
 * of the page but the marker is 0xFF (a no-op), and the keys are in
 * page 0. Erased again only with the key sector (first-boot
 * provisioning, flash_store_wipe). A no-op once armed. */
static void arm_pin(void)
{
    if (pin_armed())
        return;
    uint8_t page[FLASH_PAGE_SIZE];
    memset(page, 0xFF, sizeof page);
    memset(page, 0, 4);
    flash_op_t op = { KEY_OFFSET + KEY_OFF_PIN_ARMED, 0, page, FLASH_PAGE_SIZE };
    flash_guarded(&op);
}

/* Load the master keys from the key sector. Returns true if a valid
 * key record was present; false => a fresh device needs provisioning. */
static bool load_keys(void)
{
    const uint8_t *k = KEY_XIP;
    if (rd_u32(k + 0) == KEY_MAGIC && rd_u32(k + 4) == KEY_VERSION) {
        memcpy(s_aes_key, k + KEY_OFF_AES, 32);
        memcpy(s_mac_key, k + KEY_OFF_MAC, 32);
        return true;
    }
    return false;
}

/* Load the volatile store (counter/PIN/config). Returns true if a valid
 * (magic + matching CRC) record was present; false => defaults. */
static bool load_store(void)
{
    const uint8_t *s = STORE_XIP;
    if (rd_u32(s + 0) != STORE_MAGIC || rd_u32(s + 4) != STORE_VERSION)
        return false;
    if (crc32(s, ST_OFF_CRC) != rd_u32(s + ST_OFF_CRC))
        return false;   /* torn write -- treat as empty */
    s_sign_hwm    = rd_u32(s + ST_OFF_SIGN_HWM);
    s_pin_set     = s[ST_OFF_PIN_SET];
    s_pin_retries = s[ST_OFF_PIN_RETRIES];
    memcpy(s_pin_hash, s + ST_OFF_PIN_HASH, PIN_HASH_LEN);
    s_always_uv     = s[CFG_OFF_ALWAYS_UV];
    s_ent_attest    = s[CFG_OFF_ENT_ATTEST];
    s_min_pin_len   = s[CFG_OFF_MIN_PIN_LEN];
    s_min_pin_count = s[CFG_OFF_MIN_PIN_COUNT];
    if (s_min_pin_count > MAX_MIN_PIN_LEN_RPIDS)
        s_min_pin_count = MAX_MIN_PIN_LEN_RPIDS;
    memcpy(s_min_pin_rpids, s + CFG_OFF_MIN_PIN_RPIDS, sizeof s_min_pin_rpids);
    s_force_pin_chg = s[CFG_OFF_FORCE_PIN_CHG] ? 1 : 0;
    return true;
}

static void store_defaults(void)
{
    s_sign_hwm    = 0;
    s_pin_set     = 0;
    s_pin_retries = PIN_MAX_RETRIES;
    memset(s_pin_hash, 0, PIN_HASH_LEN);
    s_always_uv = s_ent_attest = s_min_pin_len = s_min_pin_count = 0;
    memset(s_min_pin_rpids, 0, sizeof s_min_pin_rpids);
    s_force_pin_chg = 0;
}

void flash_store_init(void)
{
    /* Master keys come from their dedicated sector and survive any torn
     * routine commit. Absent => a fresh device: mint and persist them
     * once. This is the ONLY place (besides Reset) that writes keys. */
    if (!load_keys()) {
        RAND_bytes(s_aes_key, sizeof s_aes_key);
        RAND_bytes(s_mac_key, sizeof s_mac_key);
        commit_keys();
    }

    /* Counter/PIN/config come from the store sector. A missing or
     * torn (bad-CRC) record reverts these to defaults WITHOUT touching
     * the keys, so a power glitch mid-commit never orphans credentials. */
    if (!load_store())
        store_defaults();

    /* A PIN set under these keys (the PIN-armed word) but missing from
     * the store was lost to a torn or corrupt commit: come up
     * PIN-blocked rather than PIN-less. A PIN with no armed word was set
     * by a build without the word, or its arming was cut short: arm it
     * now. The blocked state is persisted by the commit() below. */
    if (s_pin_set) {
        arm_pin();
    } else if (pin_armed()) {
        s_pin_set     = 1;
        s_pin_retries = 0;
        memset(s_pin_hash, 0, PIN_HASH_LEN);
    }

    /* Resume at the persisted high-water mark, then reserve the next
     * block (one flash write per boot) so we never reissue a value
     * even across an unclean shutdown. */
    s_sign_next = s_sign_hwm;
    s_sign_hwm  = s_sign_next + SIGN_COUNT_STRIDE;
    commit();
}

void flash_store_keys(uint8_t aes_key[32], uint8_t mac_key[32])
{
    memcpy(aes_key, s_aes_key, 32);
    memcpy(mac_key, s_mac_key, 32);
}

uint32_t flash_store_next_sign_count(void)
{
    uint32_t v = s_sign_next++;
    if (s_sign_next >= s_sign_hwm) {
        /* Reservation exhausted -- reserve the next block. */
        s_sign_hwm = s_sign_next + SIGN_COUNT_STRIDE;
        commit();
    }
    return v;
}

void flash_store_wipe(void)
{
    /* Factory reset: erase BOTH the store and the key sector so the
     * next flash_store_init() mints fresh master keys (invalidating all
     * previously-issued credentials) and clears counter/PIN/config. */
    flash_op_t store_op = { STORE_OFFSET, STORE_SECTOR_SIZE, NULL, 0 };
    flash_op_t key_op   = { KEY_OFFSET,   STORE_SECTOR_SIZE, NULL, 0 };
    flash_guarded(&store_op);
    flash_guarded(&key_op);
    flash_store_init();
}

/* ---- PIN state ------------------------------------------------ */

bool flash_store_pin_is_set(void)
{
    return s_pin_set != 0;
}

void flash_store_pin_get_hash(uint8_t hash[PIN_HASH_LEN])
{
    memcpy(hash, s_pin_hash, PIN_HASH_LEN);
}

uint8_t flash_store_pin_retries(void)
{
    return s_pin_retries;
}

void flash_store_pin_set(const uint8_t hash[PIN_HASH_LEN])
{
    memcpy(s_pin_hash, hash, PIN_HASH_LEN);
    s_pin_set     = 1;
    s_pin_retries = PIN_MAX_RETRIES;
    commit();
    /* After the store holds the PIN, so a power loss in between leaves a
     * PIN that the next boot arms. */
    arm_pin();
}

void flash_store_pin_set_retries(uint8_t retries)
{
    s_pin_retries = retries;
    commit();
}

/* ---- Device configuration (v3) -------------------------------- */

bool flash_store_always_uv(void)
{
    return s_always_uv != 0;
}

void flash_store_set_always_uv(bool on)
{
    s_always_uv = on ? 1 : 0;
    commit();
}

bool flash_store_enterprise_attestation(void)
{
    return s_ent_attest != 0;
}

void flash_store_set_enterprise_attestation(bool on)
{
    s_ent_attest = on ? 1 : 0;
    commit();
}

uint8_t flash_store_min_pin_length(void)
{
    return s_min_pin_len;
}

void flash_store_set_min_pin_length(uint8_t len)
{
    s_min_pin_len = len;
    commit();
}

uint8_t flash_store_min_pin_rpid_count(void)
{
    return s_min_pin_count;
}

void flash_store_set_min_pin_rpids(const uint8_t hashes[][32], uint8_t count)
{
    if (count > MAX_MIN_PIN_LEN_RPIDS) count = MAX_MIN_PIN_LEN_RPIDS;
    for (uint8_t i = 0; i < count; i++)
        memcpy(s_min_pin_rpids[i], hashes[i], 32);
    s_min_pin_count = count;
    commit();
}

bool flash_store_min_pin_rpid_match(const uint8_t rp_id_hash[32])
{
    for (uint8_t i = 0; i < s_min_pin_count; i++)
        if (memcmp(s_min_pin_rpids[i], rp_id_hash, 32) == 0)
            return true;
    return false;
}

bool flash_store_force_pin_change(void)
{
    return s_force_pin_chg != 0;
}

void flash_store_set_force_pin_change(bool on)
{
    s_force_pin_chg = on ? 1 : 0;
    commit();
}
