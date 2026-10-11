/* The real resident_store.c on its flash path, against a simulated NOR
 * die -- including the optional overflow sectors.
 *
 * test_resident.c drives the store with -DPQF_RESIDENT_HOST, the
 * RAM-only branch, so nothing there ever reads a sector back. This
 * suite links the QSPI branch against host_flash_die.c (with the real
 * flash_store.c for the keys and the guarded flash op) and checks what
 * lands on flash:
 *
 *   - the primary sector's bytes are what they were before the
 *     capacity option existed (a hash taken from that code);
 *   - with PQF_RESIDENT_EXTRA_SECTORS > 0: every sector fills, the
 *     count and the full-store refusal are right, a counter bump /
 *     delete / rename rewrites only its own sector and survives a
 *     reboot, a wipe clears every sector, a torn overflow write reads
 *     back as that sector empty and nothing else changed, and a sector
 *     left behind across a reset (new master keys) stays dead.
 *
 * Built twice by the Makefile: test_resident_flash-rk0 (the default)
 * and test_resident_flash-rk3 (three overflow sectors). The rk0 binary
 * saves its die next to itself (rk-default.die); the rk3 binary, run
 * after it, boots that die -- the enlarge path on a store a default
 * build really wrote.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "hardware/flash.h"
#include "flash_store.h"
#include "resident_store.h"

/* ---- die controls, from host_flash_die.c -------------------------- */
extern uint8_t pqf_host_die[];
void pqf_die_reset(void);
extern unsigned pqf_die_erases, pqf_die_programs, pqf_die_bit_violations;
extern long     pqf_die_power_budget;
extern bool     pqf_die_powered_off;

/* Layout, mirroring resident_store.c. Duplicated deliberately: if the
 * firmware moves a sector, this suite should fail rather than follow. */
#define DIE_SIZE      PICO_FLASH_SIZE_BYTES
#define SEC           FLASH_SECTOR_SIZE
#define RS_OFFSET     (DIE_SIZE - 2u * SEC)
#define STORE_OFFSET  (DIE_SIZE - 1u * SEC)
#define OV_OFFSET(k)  (DIE_SIZE - (5u + (uint32_t)(k)) * SEC)
#define EXTRA         PQF_RESIDENT_EXTRA_SECTORS
#define PRIMARY       RESIDENT_PRIMARY_SLOTS
#define PER           RESIDENT_OVERFLOW_SLOTS

/* FNV-1a 64 of the primary sector after golden_fill(), taken from
 * resident_store.c before the capacity option existed. */
#define GOLDEN_PRIMARY 0x83080813704d31edull

/* Helpers only the overflow checks use; a default build compiles them
 * without calling them. */
#define UNUSED_OK __attribute__((unused))

static int failures;
static int checks;
#define CHECK(cond, label) do {                                         \
    checks++;                                                           \
    if (cond) { printf("  ok: %s\n", (label)); }                        \
    else { printf("  FAIL: %s\n", (label)); failures++; }               \
} while (0)

/* A deterministic RAND_bytes for flash_store.c's key minting. */
static uint8_t s_rand_next;
int RAND_bytes(unsigned char *buf, int num)
{
    for (int i = 0; i < num; i++) buf[i] = s_rand_next++;
    return 1;
}

static uint64_t fnv(const uint8_t *p, size_t n)
{
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

static bool erased(uint32_t off, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (pqf_host_die[off + i] != 0xFF) return false;
    return true;
}

static UNUSED_OK void snap(uint8_t *dst, uint32_t off)
{
    memcpy(dst, pqf_host_die + off, SEC);
}

static UNUSED_OK bool same(const uint8_t *a, uint32_t off)
{
    return memcmp(a, pqf_host_die + off, SEC) == 0;
}

static void mk(resident_cred_t *c, int n)
{
    memset(c, 0, sizeof *c);
    memset(c->cred_id, n, CRED_ID_LEN);
    memset(c->rp_id_hash, n ^ 0x5a, 32);
    c->rp_id_len = 9;
    memcpy(c->rp_id, "a.example", 9);
    c->counter = 1;
    c->user_id_len = 4;
    memset(c->user_id, n, 4);
    c->user_name_len = 5;
    memcpy(c->user_name, "alice", 5);
}

static void fresh(void)
{
    pqf_die_reset();
    s_rand_next = 0x10;
    flash_store_init();
    resident_store_init();
}

/* A power cycle: RAM lost, flash kept. */
static UNUSED_OK void reboot(void)
{
    flash_store_init();
    resident_store_init();
}

/* Insert n distinct credentials 1..n; returns how many were taken. */
static size_t fill(size_t n)
{
    resident_cred_t c;
    size_t ok = 0;
    for (size_t i = 1; i <= n; i++) {
        mk(&c, (int)i);
        if (resident_store_insert(&c) == 0) ok++;
    }
    return ok;
}

static UNUSED_OK bool find(int n, size_t *idx)
{
    resident_cred_t c;
    mk(&c, n);
    return resident_store_find_by_cred_id(c.cred_id, CRED_ID_LEN, idx) == 0;
}

/* The same sequence the pre-option hash was taken over. */
static void golden_fill(void)
{
    resident_cred_t c;
    for (int i = 1; i <= 7; i++) { mk(&c, i); resident_store_insert(&c); }
    resident_store_bump_counter(3);
    resident_store_delete(5);
    mk(&c, 9);
    resident_store_insert(&c);
}

static char s_die_path[1024];

/* ---- every build -------------------------------------------------- */

static void test_primary_is_byte_identical(void)
{
    printf("-- primary sector layout --\n");
    fresh();
    golden_fill();
    CHECK(fnv(pqf_host_die + RS_OFFSET, SEC) == GOLDEN_PRIMARY,
          "the primary sector's bytes are the pre-option bytes");
    CHECK(resident_store_max() == (size_t)(PRIMARY + EXTRA * PER),
          "capacity is 7 + 7 per overflow sector");
    bool clean = true;
    for (unsigned k = 0; k < EXTRA; k++)
        if (!erased(OV_OFFSET(k), SEC)) clean = false;
    CHECK(clean, "seven credentials never touch an overflow sector");
    CHECK(pqf_die_bit_violations == 0, "no program over unerased flash");
}

static void test_save_default_die(void)
{
    if (EXTRA != 0) return;
    printf("-- saving the default-layout die --\n");
    fresh();
    flash_store_pin_set((const uint8_t *)"0123456789abcdef");
    CHECK(fill(7) == 7, "seven stored");
    resident_store_bump_counter(0);
    resident_store_bump_counter(0);
    FILE *f = fopen(s_die_path, "wb");
    bool w = f && fwrite(pqf_host_die, 1, DIE_SIZE, f) == DIE_SIZE;
    if (f) fclose(f);
    CHECK(w, "saved the die for the enlarged build");
}

/* ---- overflow builds ---------------------------------------------- */

#if PQF_RESIDENT_EXTRA_SECTORS > 0

static void test_enlarge_boots_the_default_die(void)
{
    printf("-- enlarging over a default build's store --\n");
    FILE *f = fopen(s_die_path, "rb");
    if (!f) {
        printf("  skipped: no %s (run test_resident_flash-rk0 first)\n",
               s_die_path);
        return;
    }
    pqf_die_reset();
    size_t got = fread(pqf_host_die, 1, DIE_SIZE, f);
    fclose(f);
    CHECK(got == DIE_SIZE, "loaded the default build's die");
    reboot();
    uint8_t h[PIN_HASH_LEN];
    flash_store_pin_get_hash(h);
    CHECK(flash_store_pin_is_set()
          && memcmp(h, "0123456789abcdef", PIN_HASH_LEN) == 0,
          "the PIN survived");
    CHECK(resident_store_count() == 7, "all seven passkeys are there");
    CHECK(resident_store_max() - resident_store_count()
          == (size_t)(EXTRA * PER), "the new room is all free");
    size_t idx;
    resident_cred_t c;
    CHECK(find(1, &idx) && resident_store_get(idx, &c) == 0
          && c.counter == 3, "the counter carried over");
    uint8_t primary[SEC];
    snap(primary, RS_OFFSET);
    mk(&c, 50);
    CHECK(resident_store_insert(&c) == 0, "an eighth is accepted");
    CHECK(same(primary, RS_OFFSET),
          "the eighth did not rewrite the primary sector");
    CHECK(!erased(OV_OFFSET(0), 16), "the eighth is in overflow sector 0");
    reboot();
    CHECK(resident_store_count() == 8 && find(50, &idx) && find(7, &idx),
          "all eight after a reboot");
}

static void test_fill_every_sector(void)
{
    printf("-- filling every sector --\n");
    fresh();
    size_t max = resident_store_max();
    CHECK(fill(max) == max, "every slot in every sector takes one");
    CHECK(resident_store_count() == max, "count is the capacity");
    resident_cred_t c;
    mk(&c, 200);
    CHECK(resident_store_insert(&c) == -1, "one more is refused (full)");
    mk(&c, (int)max);
    c.counter = 77;
    CHECK(resident_store_insert(&c) == 0,
          "re-registering the last one replaces it in place");
    CHECK(resident_store_count() == max, "no second slot for it");
    bool written = true;
    for (unsigned k = 0; k < EXTRA; k++)
        if (erased(OV_OFFSET(k), 16)) written = false;
    CHECK(written, "every overflow sector has a header");
    reboot();
    CHECK(resident_store_count() == max, "everything back after a reboot");
    size_t idxs[RESIDENT_MAX_SLOTS];
    CHECK(resident_store_iter_by_creation(idxs, RESIDENT_MAX_SLOTS) == max,
          "enumeration sees every sector");
    uint8_t rp[32];
    memset(rp, (int)(max ^ 0x5a), 32);
    CHECK(resident_store_find_by_rp(rp, idxs, RESIDENT_MAX_SLOTS) == 1
          && idxs[0] == max - 1, "rp lookup reaches the last slot");
    CHECK(pqf_die_bit_violations == 0, "no program over unerased flash");
}

static void test_mutations_touch_one_sector(void)
{
    printf("-- one sector per mutation --\n");
    fresh();
    fill(PRIMARY + PER + 2);           /* ov 0 full, ov 1 (if any) has 2 */
    size_t idx;
    uint8_t prim[SEC], ov0[SEC], store[SEC];
    CHECK(find(PRIMARY + 2, &idx) && idx == PRIMARY + 1,
          "credential 9 sits in overflow sector 0");
    snap(prim, RS_OFFSET);
    snap(store, STORE_OFFSET);
    unsigned e0 = pqf_die_erases;
    uint32_t v = resident_store_bump_counter(idx);
    CHECK(v == 2, "counter bumped");
    CHECK(pqf_die_erases - e0 == 1, "one erase for one bump");
    CHECK(same(prim, RS_OFFSET) && same(store, STORE_OFFSET),
          "the primary and store sectors were not rewritten");
    reboot();
    resident_cred_t c;
    CHECK(resident_store_get(idx, &c) == 0 && c.counter == 2,
          "the bumped counter persisted");

    snap(prim, RS_OFFSET);
    resident_store_update_user(idx, (const uint8_t *)"bob", 3, NULL, 0);
    CHECK(same(prim, RS_OFFSET), "rename rewrote only its sector");
    reboot();
    CHECK(resident_store_get(idx, &c) == 0 && c.user_name_len == 3
          && memcmp(c.user_name, "bob", 3) == 0, "the rename persisted");

    snap(ov0, OV_OFFSET(0));
    CHECK(find(1, &idx) && idx == 0, "credential 1 is in the primary");
    resident_store_bump_counter(idx);
    CHECK(same(ov0, OV_OFFSET(0)),
          "a primary bump left the overflow sector alone");

    CHECK(find(PRIMARY + 3, &idx), "credential 10 found");
    snap(prim, RS_OFFSET);
    resident_store_delete(idx);
    CHECK(same(prim, RS_OFFSET), "delete rewrote only its sector");
    reboot();
    CHECK(!find(PRIMARY + 3, &idx), "the delete persisted");
    CHECK(resident_store_count() == PRIMARY + PER + 1, "count after delete");
    mk(&c, 222);
    CHECK(resident_store_insert(&c) == 0 && find(222, &idx)
          && idx == PRIMARY + 2, "the freed overflow slot is reused");
}

static void test_wipe_clears_every_sector(void)
{
    printf("-- wipe --\n");
    fresh();
    fill(resident_store_max());
    flash_store_wipe();
    resident_store_wipe();
    bool clean = true;
    for (unsigned k = 0; k < EXTRA; k++)
        if (!erased(OV_OFFSET(k), SEC)) clean = false;
    CHECK(clean, "every overflow sector erased");
    CHECK(resident_store_count() == 0, "nothing left in RAM");
    reboot();
    CHECK(resident_store_count() == 0, "nothing back after a reboot");
}

static void test_stale_sector_after_foreign_reset(void)
{
    printf("-- a sector left behind by a smaller build's reset --\n");
    fresh();
    fill(PRIMARY + 3);
    uint8_t ov0[SEC];
    snap(ov0, OV_OFFSET(0));
    /* What a default build's reset does: new keys, primary rewritten
     * empty. It does not know the overflow sector exists. */
    flash_store_wipe();
    memset(pqf_host_die + RS_OFFSET, 0xFF, SEC);
    CHECK(same(ov0, OV_OFFSET(0)), "the overflow sector is still there");
    reboot();
    CHECK(resident_store_count() == 0,
          "it reads as empty under the new keys");
}

static void test_wrong_index_refused(void)
{
    if (EXTRA < 2) return;
    printf("-- a sector at the wrong index --\n");
    fresh();
    fill(PRIMARY + 2);
    size_t before = resident_store_count();
    memcpy(pqf_host_die + OV_OFFSET(1), pqf_host_die + OV_OFFSET(0), SEC);
    reboot();
    CHECK(resident_store_count() == before,
          "sector 0's copy is refused at index 1");
}

static void test_torn_overflow_write(void)
{
    printf("-- a torn overflow write --\n");
    /* The last overflow sector holds three; every sector before it is
     * full. A fourth is added there with power lost after `tear`
     * programmed bytes. One overflow write is pass 1 (erase, then the
     * whole sector with the header left erased: 4096 bytes) and pass 2
     * (page 0 again with the header: budget bytes 4096..4111 are the
     * header). */
    unsigned t = EXTRA - 1;
    size_t before_t = PRIMARY + t * PER;
    static const long tears[] = {
        0, 1, 15, 16, 1000, SEC - 1, SEC, SEC + 1, SEC + 11,
        SEC + 12, SEC + 15, SEC + 16, SEC + 100
    };
    for (size_t i = 0; i < sizeof tears / sizeof tears[0]; i++) {
        char label[96];
        long tear = tears[i];
        fresh();
        fill(before_t + 3);
        uint8_t prim[SEC], other[8][SEC];
        snap(prim, RS_OFFSET);
        for (unsigned k = 0; k < EXTRA; k++) snap(other[k], OV_OFFSET(k));
        resident_cred_t c;
        mk(&c, 111);
        pqf_die_power_budget = tear;
        (void)resident_store_insert(&c);
        bool cut = pqf_die_powered_off;
        pqf_die_power_budget = -1;
        pqf_die_powered_off = false;
        snprintf(label, sizeof label, "tear %ld: power was lost", tear);
        CHECK(cut, label);
        reboot();

        bool others = true;
        for (unsigned k = 0; k < EXTRA; k++)
            if (k != t && !same(other[k], OV_OFFSET(k))) others = false;
        snprintf(label, sizeof label,
                 "tear %ld: no other sector changed", tear);
        CHECK(same(prim, RS_OFFSET) && others, label);

        /* Empty, or -- once every slot byte and the whole header are
         * down -- the complete new content. Never a partial slot. */
        size_t in_t = resident_store_count() - before_t;
        size_t idx;
        bool ok;
        if (tear < (long)SEC + 12)
            ok = in_t == 0 && !find(111, &idx);
        else if (tear >= (long)SEC + 16)
            ok = in_t == 4 && find(111, &idx);
        else
            ok = (in_t == 0 && !find(111, &idx))
                 || (in_t == 4 && find(111, &idx));
        snprintf(label, sizeof label,
                 "tear %ld: the torn sector is empty or complete", tear);
        CHECK(ok, label);
        snprintf(label, sizeof label,
                 "tear %ld: the primary passkeys and PIN store intact",
                 tear);
        CHECK(find(1, &idx) && find(PRIMARY, &idx)
              && resident_store_count() >= before_t, label);
    }
}

#endif /* PQF_RESIDENT_EXTRA_SECTORS > 0 */

int main(int argc, char **argv)
{
    (void)argc;
    /* The saved die lives next to the binaries (build/). */
    const char *slash = strrchr(argv[0], '/');
    size_t dir = slash ? (size_t)(slash - argv[0]) + 1 : 0;
    snprintf(s_die_path, sizeof s_die_path, "%.*srk-default.die",
             (int)dir, argv[0]);

    printf("resident_store on flash, PQF_RESIDENT_EXTRA_SECTORS=%d\n",
           EXTRA);
    test_primary_is_byte_identical();
    test_save_default_die();
#if PQF_RESIDENT_EXTRA_SECTORS > 0
    test_enlarge_boots_the_default_die();
    test_fill_every_sector();
    test_mutations_touch_one_sector();
    test_wipe_clears_every_sector();
    test_stale_sector_after_foreign_reset();
    test_wrong_index_refused();
    test_torn_overflow_write();
#endif
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
