/* The real c/firmware/src/flash_store.c, against a simulated NOR die.
 *
 * Until now this file was never compiled on the host at all: the test
 * Makefile substitutes host_flash_stub.c, 124 lines of RAM variables,
 * for all 529 lines of it. So the CRC, the versioning, the commit path
 * and the signature-counter reservation had no coverage on either side
 * of the boundary.
 *
 * The counter is the reason this suite exists. On the device
 * flash_store_init() resumes at the persisted high-water mark, so a
 * value once handed out is never handed out again -- WebAuthn relying
 * parties use exactly that to detect a cloned authenticator. The stub
 * does the precise inverse: flash_store_init() sets s_count = 0 and
 * next_sign_count() is "return s_count++". The one assertion in the
 * tree that looks like counter coverage (test_resident.c:299,
 * "counter increments across assertions") passes on s_count++ alone and
 * would pass identically if the real reservation logic were deleted.
 *
 * This suite links the real module. Everything above the write
 * primitive runs as it does on silicon; only the ROM routines and the
 * die underneath them are simulated, and the die enforces NOR rules so
 * that a program over an unerased sector is caught rather than
 * memcpy'd away.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "hardware/flash.h"
#include "hardware/structs/qmi.h"
#include "flash_store.h"

/* ---- die controls, from host_flash_die.c -------------------------- */
extern uint8_t pqf_host_die[];
void pqf_die_reset(void);
void pqf_die_clear_trace(void);
extern unsigned pqf_die_erases, pqf_die_programs, pqf_die_bit_violations;
extern unsigned pqf_die_unaligned, pqf_die_xip_exits, pqf_die_xip_enters;
extern unsigned pqf_die_flushes, pqf_die_connects;
extern uint8_t  pqf_die_last_erase_cmd;
extern uint32_t pqf_die_last_erase_size;
extern char     pqf_die_trace[];
extern size_t   pqf_die_tear_after_n_bytes;
extern long     pqf_die_power_budget;
extern bool     pqf_die_powered_off;

/* Layout, mirroring flash_store.c. Duplicated deliberately: if the
 * firmware moves a field, this suite should fail rather than follow. */
#define DIE_SIZE        (32u * 1024u)
#define STORE_OFFSET    (DIE_SIZE - FLASH_SECTOR_SIZE)
#define KEY_OFFSET      (DIE_SIZE - 4u * FLASH_SECTOR_SIZE)
#define STORE_MAGIC     0x46435150u
#define STORE_VERSION   5u
#define KEY_MAGIC       0x594B5150u
#define ST_OFF_SIGN_HWM 8
#define ST_OFF_CRC      252
#define KEY_OFF_PIN_ARMED 256u
#define SIGN_STRIDE     32u

static int failures;
static int checks;
#define CHECK(cond, label) do {                                         \
    checks++;                                                           \
    if (cond) { printf("  ok: %s\n", (label)); }                        \
    else { printf("  FAIL: %s\n", (label)); failures++; }               \
} while (0)

/* A deterministic RAND_bytes: the real one would make "the key sector
 * holds what RAND_bytes produced" unassertable. Counts calls so key
 * minting can be distinguished from key reuse. */
unsigned pqf_rand_calls;
static uint8_t s_rand_next;
int RAND_bytes(unsigned char *buf, int num)
{
    pqf_rand_calls++;
    for (int i = 0; i < num; i++) buf[i] = s_rand_next++;
    return 1;
}

static uint32_t rd_u32(uint32_t off)
{
    uint32_t v;
    memcpy(&v, pqf_host_die + off, 4);
    return v;
}
static void wr_u32(uint32_t off, uint32_t v) { memcpy(pqf_host_die + off, &v, 4); }

/* A fresh, blank device. */
static void fresh(void)
{
    pqf_die_reset();
    s_rand_next = 0x10;
    pqf_rand_calls = 0;
    flash_store_init();
}

/* Model a power cycle: RAM state is lost, flash persists. Only
 * flash_store_init() runs again -- exactly what the device does. */
static void reboot(void) { flash_store_init(); }

/* ---- the signature counter: the property nothing has ever tested --- */

static void test_counter_never_repeats_across_reboots(void)
{
    printf("-- signature counter --\n");
    fresh();

    uint32_t first = flash_store_next_sign_count();
    uint32_t a = flash_store_next_sign_count();
    CHECK(a == first + 1, "counter increments within a boot");

    /* Take a handful, well short of the stride, then reboot. A device
     * that resumed from the last ISSUED value would hand `a` back out;
     * one that resumes from the persisted high-water mark cannot. */
    for (int i = 0; i < 5; i++) (void)flash_store_next_sign_count();
    uint32_t last_before = flash_store_next_sign_count();
    reboot();
    uint32_t after = flash_store_next_sign_count();
    CHECK(after > last_before,
          "a reboot never reissues a counter value already handed out");
    CHECK(after >= SIGN_STRIDE,
          "after a reboot the counter resumes at the reserved high-water mark");

    /* Monotonic across many reboots -- the actual RP-visible property. */
    uint32_t prev = after;
    bool monotonic = true;
    for (int i = 0; i < 20; i++) {
        reboot();
        for (int j = 0; j < 3; j++) {
            uint32_t v = flash_store_next_sign_count();
            if (v <= prev) monotonic = false;
            prev = v;
        }
    }
    CHECK(monotonic, "counter is strictly increasing across 20 reboots");
}

static void test_counter_reserves_in_blocks(void)
{
    printf("-- counter reservation --\n");
    fresh();
    /* The reservation exists to spare the flash: one write per STRIDE
     * values, not one per signature. Assert the write count, not just
     * that the numbers grow -- a correct-looking counter that committed
     * every time would pass every other test here and wear the part
     * out in the field. */
    pqf_die_clear_trace();
    unsigned before = pqf_die_programs;
    for (unsigned i = 0; i < SIGN_STRIDE; i++) (void)flash_store_next_sign_count();
    unsigned writes = pqf_die_programs - before;
    CHECK(writes <= 2, "at most one commit per stride of signatures");

    before = pqf_die_programs;
    for (unsigned i = 0; i < SIGN_STRIDE * 4; i++) (void)flash_store_next_sign_count();
    writes = pqf_die_programs - before;
    CHECK(writes <= 6, "four strides cost about four commits, not 128");
}

/* ---- store page integrity ----------------------------------------- */

static void test_blank_flash_yields_defaults(void)
{
    printf("-- blank flash --\n");
    pqf_die_reset();
    s_rand_next = 0x10;
    CHECK(rd_u32(STORE_OFFSET) == 0xFFFFFFFFu, "die starts erased, not zeroed");
    flash_store_init();
    CHECK(!flash_store_pin_is_set(), "blank flash: no PIN set");
    CHECK(flash_store_pin_retries() == PIN_MAX_RETRIES,
          "blank flash: full retry budget");
    CHECK(!flash_store_always_uv(), "blank flash: alwaysUv off");
    CHECK(flash_store_min_pin_rpid_count() == 0, "blank flash: no min-PIN RPs");
    CHECK(rd_u32(STORE_OFFSET) == STORE_MAGIC,
          "init writes a valid store page over blank flash");
}

static void test_a_corrupt_crc_is_rejected(void)
{
    printf("-- CRC --\n");
    fresh();
    flash_store_pin_set_retries(3);
    CHECK(flash_store_pin_retries() == 3, "retries persisted before corruption");

    /* Flip a byte the CRC covers. The page still has the right magic
     * and version, so only the CRC can catch this. */
    pqf_host_die[STORE_OFFSET + ST_OFF_SIGN_HWM] ^= 0xFF;
    reboot();
    CHECK(flash_store_pin_retries() == PIN_MAX_RETRIES,
          "a CRC mismatch falls back to defaults rather than trusting the page");
}

static void test_bad_magic_and_version_are_rejected(void)
{
    printf("-- magic and version --\n");
    fresh();
    flash_store_pin_set_retries(2);

    wr_u32(STORE_OFFSET, 0xDEADBEEFu);
    reboot();
    CHECK(flash_store_pin_retries() == PIN_MAX_RETRIES,
          "a wrong magic falls back to defaults");

    fresh();
    flash_store_pin_set_retries(2);
    wr_u32(STORE_OFFSET + 4, STORE_VERSION + 1u);
    reboot();
    CHECK(flash_store_pin_retries() == PIN_MAX_RETRIES,
          "a future store version falls back to defaults rather than misreading it");
}

/* ---- PIN and config round trips ----------------------------------- */

static void test_pin_state_persists(void)
{
    printf("-- PIN state --\n");
    fresh();
    uint8_t hash[PIN_HASH_LEN];
    for (int i = 0; i < PIN_HASH_LEN; i++) hash[i] = (uint8_t)(0xA0 + i);
    flash_store_pin_set(hash);
    CHECK(flash_store_pin_is_set(), "PIN reads back as set");
    CHECK(flash_store_pin_retries() == PIN_MAX_RETRIES,
          "setting a PIN restores the retry budget");

    flash_store_pin_set_retries(5);
    reboot();
    CHECK(flash_store_pin_is_set(), "PIN survives a reboot");
    CHECK(flash_store_pin_retries() == 5, "retry count survives a reboot");
    uint8_t got[PIN_HASH_LEN];
    flash_store_pin_get_hash(got);
    CHECK(memcmp(got, hash, PIN_HASH_LEN) == 0, "PIN hash survives a reboot byte for byte");
}

static void test_every_config_flag_round_trips(void)
{
    printf("-- config flags --\n");
    fresh();
    flash_store_set_always_uv(true);
    flash_store_set_enterprise_attestation(true);
    flash_store_set_min_pin_length(9);
    flash_store_set_force_pin_change(true);
    reboot();
    CHECK(flash_store_always_uv(), "alwaysUv survives a reboot");
    CHECK(flash_store_enterprise_attestation(), "enterprise attestation survives a reboot");
    CHECK(flash_store_min_pin_length() == 9, "minPinLength survives a reboot");
    CHECK(flash_store_force_pin_change(), "forcePINChange survives a reboot");

    flash_store_set_always_uv(false);
    flash_store_set_force_pin_change(false);
    reboot();
    CHECK(!flash_store_always_uv(), "alwaysUv clears and stays clear");
    CHECK(!flash_store_force_pin_change(), "forcePINChange clears and stays clear");
}

static void test_min_pin_rpid_allow_list(void)
{
    printf("-- min-PIN RP allow-list --\n");
    fresh();
    uint8_t rps[2][32];
    memset(rps[0], 0x11, 32);
    memset(rps[1], 0x22, 32);
    flash_store_set_min_pin_rpids(rps, 2);
    reboot();
    CHECK(flash_store_min_pin_rpid_count() == 2, "allow-list count survives a reboot");
    CHECK(flash_store_min_pin_rpid_match(rps[0]), "a listed RP matches");
    CHECK(flash_store_min_pin_rpid_match(rps[1]), "the second listed RP matches");
    uint8_t other[32];
    memset(other, 0x33, 32);
    CHECK(!flash_store_min_pin_rpid_match(other), "an unlisted RP does not match");
}

/* ---- the key sector ------------------------------------------------ */

static void test_keys_are_minted_once_and_then_persist(void)
{
    printf("-- master keys --\n");
    fresh();
    uint8_t aes1[32], mac1[32], aes2[32], mac2[32];
    flash_store_keys(aes1, mac1);
    CHECK(rd_u32(KEY_OFFSET) == KEY_MAGIC, "key sector written with its magic");

    reboot();
    flash_store_keys(aes2, mac2);
    CHECK(memcmp(aes1, aes2, 32) == 0, "AES key is the same after a reboot");
    CHECK(memcmp(mac1, mac2, 32) == 0, "MAC key is the same after a reboot");
    /* If these ever differ, every credential on the token is orphaned:
     * credential ids are sealed under them. */

    unsigned calls_before = pqf_rand_calls;
    reboot();
    CHECK(pqf_rand_calls == calls_before,
          "a reboot with a valid key sector mints no new keys");
}

static void test_wipe_mints_fresh_keys(void)
{
    printf("-- wipe --\n");
    fresh();
    uint8_t aes1[32], mac1[32], aes2[32], mac2[32];
    flash_store_keys(aes1, mac1);
    flash_store_pin_set_retries(4);

    flash_store_wipe();
    flash_store_keys(aes2, mac2);
    CHECK(memcmp(aes1, aes2, 32) != 0,
          "wipe mints a new AES key, orphaning old credentials");
    CHECK(flash_store_pin_retries() == PIN_MAX_RETRIES, "wipe restores the retry budget");
    CHECK(!flash_store_pin_is_set(), "wipe clears the PIN");
}

/* ---- the write path itself ----------------------------------------- */

static void test_the_flash_sequence_is_well_formed(void)
{
    printf("-- flash operation --\n");
    fresh();
    pqf_die_clear_trace();
    flash_store_pin_set_retries(6);

    CHECK(pqf_die_bit_violations == 0,
          "no program asked a cleared bit to become 1 (every page was erased first)");
    CHECK(pqf_die_unaligned == 0, "every erase was sector-aligned");
    CHECK(pqf_die_last_erase_size == FLASH_SECTOR_SIZE,
          "erases use the sector block size");
    CHECK(pqf_die_last_erase_cmd == 0x20,
          "erases use the 0x20 sector-erase opcode");
    CHECK(pqf_die_xip_exits > 0 && pqf_die_xip_enters == pqf_die_xip_exits,
          "XIP is re-entered exactly as many times as it is exited");
    CHECK(pqf_die_flushes > 0, "the cache is flushed after writing");
    /* Order matters: programming before the erase would be undone by
     * it, and re-entering XIP early would fault the next read. */
    CHECK(strstr(pqf_die_trace, "E") != NULL && strstr(pqf_die_trace, "P") != NULL
          && strstr(pqf_die_trace, "E") < strstr(pqf_die_trace, "P"),
          "erase precedes program");
    CHECK(pqf_die_trace[strlen(pqf_die_trace) - 1] == 'e',
          "the sequence ends by re-entering XIP");
}

static void test_qmi_window_is_restored(void)
{
    printf("-- QMI window --\n");
    fresh();
    /* The regression this guards: leaving QMI window 0 in slow serial
     * mode after a flash write turned a 1-second ML-DSA signature into
     * 13 and timed the host out. Plant a recognisable configuration,
     * do a write, and require it back. */
    qmi_hw->m[0].timing = 0xAAAA5555u;
    qmi_hw->m[0].rfmt   = 0x12345678u;
    qmi_hw->m[0].rcmd   = 0x0000A5A5u;
    flash_store_pin_set_retries(7);
    CHECK(qmi_hw->m[0].timing == 0xAAAA5555u, "QMI timing restored after a flash write");
    CHECK(qmi_hw->m[0].rfmt == 0x12345678u, "QMI read format restored");
    CHECK(qmi_hw->m[0].rcmd == 0x0000A5A5u, "QMI read command restored");
}

static void test_a_torn_write_is_caught_by_the_crc(void)
{
    printf("-- torn write --\n");
    fresh();
    flash_store_pin_set_retries(3);
    reboot();
    CHECK(flash_store_pin_retries() == 3, "baseline: the value persisted");

    /* Lose power part way through the page program. The CRC lives at
     * the end of the page, so a partial write leaves it unwritten
     * (0xFFFFFFFF) and the page must be rejected rather than half
     * believed. */
    pqf_die_tear_after_n_bytes = 16;
    flash_store_pin_set_retries(9);
    pqf_die_tear_after_n_bytes = 0;
    reboot();
    CHECK(flash_store_pin_retries() != 9,
          "a torn commit is not accepted as a complete one");
    CHECK(flash_store_pin_retries() == PIN_MAX_RETRIES,
          "a torn commit falls back to defaults");
}

/* ---- a store that loses the PIN boots PIN-blocked ------------------ */

static const uint8_t k_pin_hash[PIN_HASH_LEN] = {
    0x5a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static bool armed_on_die(void)
{
    return rd_u32(KEY_OFFSET + KEY_OFF_PIN_ARMED) != 0xFFFFFFFFu;
}

static void test_setting_a_pin_arms_the_key_sector(void)
{
    printf("-- the PIN-armed word --\n");
    fresh();
    CHECK(!armed_on_die(), "a fresh device has no PIN-armed word");
    uint8_t keys[FLASH_PAGE_SIZE];
    memcpy(keys, pqf_host_die + KEY_OFFSET, sizeof keys);
    unsigned erases = pqf_die_erases;
    flash_store_pin_set(k_pin_hash);
    CHECK(armed_on_die(), "setting a PIN arms the word in the key sector");
    CHECK(memcmp(keys, pqf_host_die + KEY_OFFSET, sizeof keys) == 0,
          "arming leaves the keys' page untouched");
    CHECK(pqf_die_erases == erases + 1,
          "arming erases nothing (the one erase is the store commit)");
    CHECK(pqf_die_bit_violations == 0, "arming programs erased bits only");
    unsigned programs = pqf_die_programs;
    flash_store_pin_set(k_pin_hash);
    CHECK(pqf_die_programs == programs + 1,
          "a second PIN set does not program the word again");
}

static void test_a_torn_commit_after_a_pin_blocks_the_pin(void)
{
    printf("-- a torn commit after a PIN is set --\n");
    /* Lose power after every possible number of programmed bytes of a
     * routine commit (the store is one page). The page either lands
     * whole -- PIN intact, change applied -- or reads back invalid, and
     * then the device must come up PIN-blocked: never PIN-less, which
     * would let anyone set a PIN in front of the surviving keys. */
    bool never_pinless = true, keys_kept = true, torn_blocks = true;
    bool complete_seen = false, torn_seen = false;
    for (long tear = 0; tear <= (long)FLASH_PAGE_SIZE; tear++) {
        fresh();
        flash_store_pin_set(k_pin_hash);
        reboot();
        uint8_t keys[FLASH_PAGE_SIZE];
        memcpy(keys, pqf_host_die + KEY_OFFSET, sizeof keys);
        pqf_die_power_budget = tear;
        flash_store_set_always_uv(true);
        pqf_die_power_budget = -1;
        pqf_die_powered_off = false;
        reboot();
        if (!flash_store_pin_is_set()) never_pinless = false;
        if (memcmp(keys, pqf_host_die + KEY_OFFSET, sizeof keys) != 0) keys_kept = false;
        if (flash_store_always_uv()) {
            complete_seen = true;
        } else {
            torn_seen = true;
            if (flash_store_pin_retries() != 0) torn_blocks = false;
        }
    }
    CHECK(complete_seen && torn_seen, "both outcomes were exercised");
    CHECK(never_pinless, "no cut point leaves the device without a PIN");
    CHECK(torn_blocks, "every torn commit boots PIN-blocked (0 retries)");
    CHECK(keys_kept, "no cut point disturbs the master keys");

    /* Blocked survives further reboots, and a PIN cannot be set. */
    fresh();
    flash_store_pin_set(k_pin_hash);
    pqf_die_power_budget = 0;
    flash_store_set_always_uv(true);
    pqf_die_power_budget = -1;
    pqf_die_powered_off = false;
    reboot();
    reboot();
    CHECK(flash_store_pin_is_set() && flash_store_pin_retries() == 0,
          "the blocked state survives a second reboot");

    /* authenticatorReset is the way out: fresh keys, no PIN, no word. */
    uint8_t old_keys[64];
    memcpy(old_keys, pqf_host_die + KEY_OFFSET + 8, sizeof old_keys);
    flash_store_wipe();
    CHECK(!flash_store_pin_is_set(), "a wipe clears the blocked PIN");
    CHECK(flash_store_pin_retries() == PIN_MAX_RETRIES, "a wipe restores the retries");
    CHECK(!armed_on_die(), "a wipe erases the PIN-armed word");
    CHECK(memcmp(old_keys, pqf_host_die + KEY_OFFSET + 8, sizeof old_keys) != 0,
          "the wipe rotated the keys that every old credential id needs");
    flash_store_pin_set(k_pin_hash);
    CHECK(armed_on_die() && flash_store_pin_retries() == PIN_MAX_RETRIES,
          "after the wipe a new PIN can be set, and arms the word again");
}

static void test_a_torn_commit_without_a_pin_is_not_blocked(void)
{
    printf("-- a torn commit with no PIN --\n");
    fresh();
    pqf_die_power_budget = 0;
    flash_store_set_always_uv(true);
    pqf_die_power_budget = -1;
    pqf_die_powered_off = false;
    reboot();
    CHECK(!flash_store_pin_is_set(), "no PIN was ever set: still none");
    CHECK(flash_store_pin_retries() == PIN_MAX_RETRIES, "and not blocked");
    CHECK(!armed_on_die(), "and no PIN-armed word");
}

static void test_a_pin_from_an_older_build_is_armed_at_boot(void)
{
    printf("-- a PIN set by a build without the word --\n");
    fresh();
    flash_store_pin_set(k_pin_hash);
    /* What an older build leaves: the PIN in the store, the word erased. */
    memset(pqf_host_die + KEY_OFFSET + KEY_OFF_PIN_ARMED, 0xFF, 4);
    CHECK(!armed_on_die(), "baseline: the word is erased");
    reboot();
    CHECK(armed_on_die(), "the first boot arms it");
    CHECK(flash_store_pin_is_set() && flash_store_pin_retries() == PIN_MAX_RETRIES,
          "and the PIN is untouched");
}

int main(void)
{
    printf("== flash_store (real module, simulated NOR die) ==\n");
    test_counter_never_repeats_across_reboots();
    test_counter_reserves_in_blocks();
    test_blank_flash_yields_defaults();
    test_a_corrupt_crc_is_rejected();
    test_bad_magic_and_version_are_rejected();
    test_pin_state_persists();
    test_every_config_flag_round_trips();
    test_min_pin_rpid_allow_list();
    test_keys_are_minted_once_and_then_persist();
    test_wipe_mints_fresh_keys();
    test_the_flash_sequence_is_well_formed();
    test_qmi_window_is_restored();
    test_a_torn_write_is_caught_by_the_crc();
    test_setting_a_pin_arms_the_key_sector();
    test_a_torn_commit_after_a_pin_blocks_the_pin();
    test_a_torn_commit_without_a_pin_is_not_blocked();
    test_a_pin_from_an_older_build_is_armed_at_boot();
    printf("\n%d checks, %d failure(s)\n", checks, failures);
    return failures != 0;
}
