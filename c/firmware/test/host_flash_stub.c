/* host_flash_stub.c -- RAM-backed flash_store for host tests.
 *
 * The real flash_store.c uses pico-sdk's QSPI flash routines, which
 * don't exist off-device. For host-side CTAP2 tests we provide the
 * same flash_store.h interface backed by RAM: master keys come from
 * the host RAND stub, the sign counter is a plain incrementing
 * variable. Behaviour matches the firmware within a single run
 * (persistence across "reboots" isn't meaningful in a host process).
 *
 * Note on H1 (dedicated master-key sector): the firmware now keeps the
 * master keys in a sector routine commits never erase, so a torn
 * counter/PIN/config write can lose those fields but never the keys.
 * That durability split is not modelled here -- each flash_store_init()
 * stands in for a clean fresh-device boot (keys regenerated, state
 * cleared), which is all the host ceremonies need.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "flash_store.h"
#include "openssl/rand.h"

static uint8_t  s_aes[32];
static uint8_t  s_mac[32];
static uint32_t s_count;

/* PIN state (declared up here so flash_store_init can reset it). */
static uint8_t s_pin_set;
static uint8_t s_pin_retries = PIN_MAX_RETRIES;
static uint8_t s_pin_hash[PIN_HASH_LEN];

/* authenticatorConfig policy (RAM mirror of the v3 record). */
static uint8_t s_always_uv;
static uint8_t s_ent_attest;
static uint8_t s_min_pin_len;
static uint8_t s_min_pin_count;
static uint8_t s_min_pin_rpids[MAX_MIN_PIN_LEN_RPIDS][32];
static uint8_t s_force_pin_chg;   /* X13 forcePINChange */

/* Each call models a fresh device boot/reset (host tests that want a
 * clean slate just call ctap2_init() again). Master keys are
 * regenerated and the PIN + config are cleared. */
void flash_store_init(void)
{
    RAND_bytes(s_aes, sizeof s_aes);
    RAND_bytes(s_mac, sizeof s_mac);
    s_count = 0;
    s_pin_set = 0;
    s_pin_retries = PIN_MAX_RETRIES;
    memset(s_pin_hash, 0, sizeof s_pin_hash);
    s_always_uv = s_ent_attest = s_min_pin_len = s_min_pin_count = 0;
    memset(s_min_pin_rpids, 0, sizeof s_min_pin_rpids);
    s_force_pin_chg = 0;
}

void flash_store_keys(uint8_t aes_key[32], uint8_t mac_key[32])
{
    memcpy(aes_key, s_aes, 32);
    memcpy(mac_key, s_mac, 32);
}

uint32_t flash_store_next_sign_count(void)
{
    return s_count++;
}

void flash_store_wipe(void)
{
    flash_store_init();
}

/* ---- PIN state (RAM) -- state declared near flash_store_init ---- */

bool flash_store_pin_is_set(void) { return s_pin_set != 0; }

void flash_store_pin_get_hash(uint8_t hash[PIN_HASH_LEN])
{
    memcpy(hash, s_pin_hash, PIN_HASH_LEN);
}

uint8_t flash_store_pin_retries(void) { return s_pin_retries; }

void flash_store_pin_set(const uint8_t hash[PIN_HASH_LEN])
{
    memcpy(s_pin_hash, hash, PIN_HASH_LEN);
    s_pin_set = 1;
    s_pin_retries = PIN_MAX_RETRIES;
}

void flash_store_pin_set_retries(uint8_t r) { s_pin_retries = r; }

/* ---- Device configuration (RAM) ------------------------------- */

bool    flash_store_always_uv(void) { return s_always_uv != 0; }
void    flash_store_set_always_uv(bool on) { s_always_uv = on ? 1 : 0; }

bool    flash_store_enterprise_attestation(void) { return s_ent_attest != 0; }
void    flash_store_set_enterprise_attestation(bool on) { s_ent_attest = on ? 1 : 0; }

uint8_t flash_store_min_pin_length(void) { return s_min_pin_len; }
void    flash_store_set_min_pin_length(uint8_t len) { s_min_pin_len = len; }

uint8_t flash_store_min_pin_rpid_count(void) { return s_min_pin_count; }

void flash_store_set_min_pin_rpids(const uint8_t hashes[][32], uint8_t count)
{
    if (count > MAX_MIN_PIN_LEN_RPIDS) count = MAX_MIN_PIN_LEN_RPIDS;
    for (uint8_t i = 0; i < count; i++)
        memcpy(s_min_pin_rpids[i], hashes[i], 32);
    s_min_pin_count = count;
}

bool flash_store_min_pin_rpid_match(const uint8_t rp_id_hash[32])
{
    for (uint8_t i = 0; i < s_min_pin_count; i++)
        if (memcmp(s_min_pin_rpids[i], rp_id_hash, 32) == 0)
            return true;
    return false;
}

bool flash_store_force_pin_change(void) { return s_force_pin_chg != 0; }
void flash_store_set_force_pin_change(bool on) { s_force_pin_chg = on ? 1 : 0; }
