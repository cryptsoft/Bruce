/* flash_store.h -- persistent device state in QSPI flash.
 *
 * Holds the device master keys (used to encrypt/authenticate
 * credentialIDs) plus a monotonic signature-counter high-water mark,
 * the PIN state, and authenticatorConfig policy. The master key is
 * stable across boots, so a credentialID minted in one session still
 * decrypts in the next.
 *
 * Durability model (H1): the master keys live in their OWN flash
 * sector that routine writes never erase. The frequently-rewritten
 * volatile state (counter HWM, PIN, config) lives in a separate store
 * sector guarded by a CRC. So a power glitch during a routine commit
 * can lose counter/PIN/config (they revert to defaults -- effectively a
 * reset of that state) but can NEVER lose the master keys and orphan
 * every credential. A lost PIN is the exception to "revert to
 * defaults": once a PIN has been set, the key sector's PIN-armed word
 * makes the next boot come up PIN-blocked, not PIN-less, until
 * authenticatorReset. See flash_store.c for the full flash map.
 *
 * Sign-counter wear strategy: we don't write flash on every
 * signature. Instead we reserve a block of counter values (STRIDE)
 * by persisting a high-water mark, hand them out from RAM, and only
 * touch flash again when the block is exhausted. On boot we resume
 * from the persisted high-water mark (never reusing a value, and
 * staying monotonic as RPs require) and immediately reserve the next
 * block. Worst-case one sector erase per STRIDE signatures.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_FLASH_STORE_H
#define PQF_FLASH_STORE_H

#include <stdint.h>
#include <stdbool.h>

/* Load (or first-time create) the persistent store.
 *
 * On a fresh device (no valid record in the sector) this generates
 * new master keys from the TRNG and writes them. Either way, on
 * return the master keys are available via flash_store_keys() and
 * the signature counter is primed.
 *
 * Must be called once at boot, after the SDK RNG is usable. */
void flash_store_init(void);

/* Copy the 32-byte master AES + HMAC keys out of the store. */
void flash_store_keys(uint8_t aes_key[32], uint8_t mac_key[32]);

/* Return the next signature counter value (monotonic across boots),
 * persisting a new reservation to flash when needed. */
uint32_t flash_store_next_sign_count(void);

/* Wipe the store (factory reset): erases the sector so the next
 * flash_store_init() regenerates fresh master keys, invalidating all
 * previously-issued credentials. Used by authenticatorReset later. */
void flash_store_wipe(void);

/* Guarded raw flash op for the OTHER persisted sectors (resident
 * store, large blobs): erase `erase_len` bytes at flash offset
 * `offset` (none when `erase_len` is 0 -- a program-only op, over
 * bytes already erased or programmed with the same bits), then (if
 * `prog` != NULL) program `prog_len` bytes there.
 * Runs the direct boot-ROM flash sequence from RAM with core 1 parked
 * and IRQs masked (M1) -- the pico-sdk flash_range_* wrappers hang
 * nondeterministically on pure-RISC-V silicon (see flash_op_cb in
 * flash_store.c), so every flash write in the firmware must funnel
 * through this one proven path. Firmware builds only. */
void flash_store_guarded_op(uint32_t offset, uint32_t erase_len,
                            const uint8_t *prog, uint32_t prog_len);

/* ---- PIN state (Phase C-7) ------------------------------------ *
 *
 * The PIN is never stored in the clear; we keep the left 16 bytes of
 * SHA-256(PIN) plus a retry counter in the store sector. Setting a PIN
 * also arms a word in the key sector, so a store that loses the PIN
 * boots PIN-blocked (retries 0) rather than PIN-less. */

#define PIN_HASH_LEN        16
#define PIN_MAX_RETRIES     8

/* Whether a PIN has been set on this device. */
bool flash_store_pin_is_set(void);

/* Copy the stored 16-byte PIN hash (SHA-256(PIN) truncated). Only
 * meaningful when flash_store_pin_is_set(). */
void flash_store_pin_get_hash(uint8_t hash[PIN_HASH_LEN]);

/* Remaining PIN retry attempts before lockout. */
uint8_t flash_store_pin_retries(void);

/* Set / replace the PIN hash: marks the PIN as set and resets the
 * retry counter to PIN_MAX_RETRIES. Persists. */
void flash_store_pin_set(const uint8_t hash[PIN_HASH_LEN]);

/* Update the retry counter (decrement on a bad attempt, reset on a
 * good one). Persists. */
void flash_store_pin_set_retries(uint8_t retries);

/* ---- Device configuration (Phase C-10a, authenticatorConfig sec. 6.11) -- *
 *
 * Three device-wide policy settings the host can toggle via
 * authenticatorConfig (0x0D), persisted alongside the master keys so
 * they survive reboots. authenticatorReset clears them back to the
 * defaults (alwaysUv off, no enterprise flag, default min PIN). */

/* How many RP-id hashes may be registered for the minPinLength
 * extension allowlist (CTAP 2.1 sec. 6.11.4 setMinPINLength). */
#define MAX_MIN_PIN_LEN_RPIDS   4

/* alwaysUv: when set, MakeCredential / GetAssertion require a
 * PIN/UV-auth token even when the RP didn't request user verification
 * (CTAP 2.1 sec. 6.11.2 toggleAlwaysUv). */
bool flash_store_always_uv(void);
void flash_store_set_always_uv(bool on);

/* enterpriseAttestation: stored when the host enables it, but our
 * attestation stays self-attestation (we ship no vendor cert chain),
 * so the flag is advisory -- surfaced only as getInfo option "ep". */
bool flash_store_enterprise_attestation(void);
void flash_store_set_enterprise_attestation(bool on);

/* minPINLength override in bytes. 0 => "use the built-in default"
 * (PIN_MIN_LENGTH). setMinPINLength may only raise the effective
 * value, never lower it (enforced by the caller). */
uint8_t flash_store_min_pin_length(void);
void    flash_store_set_min_pin_length(uint8_t len);

/* forcePINChange (CTAP 2.1 sec. 6.5.5.7.2 / sec. 6.11.4): when set, the host
 * must run authenticatorClientPin.changePIN before any further PIN-token
 * use. Set by authenticatorConfig setMinPINLength's forceChangePin flag,
 * surfaced as getInfo 0x0C forcePINChange, and cleared by a successful
 * changePIN. Persisted (survives reboots) and cleared on Reset. */
bool flash_store_force_pin_change(void);
void flash_store_set_force_pin_change(bool on);

/* minPinLengthRPIDs allowlist -- the RP-id hashes for which the
 * minPinLength MakeCredential extension output is emitted. Replacing
 * the set overwrites any previous entries (count clamped to
 * MAX_MIN_PIN_LEN_RPIDS). Persists. */
uint8_t flash_store_min_pin_rpid_count(void);
void    flash_store_set_min_pin_rpids(const uint8_t hashes[][32],
                                      uint8_t count);
bool    flash_store_min_pin_rpid_match(const uint8_t rp_id_hash[32]);

#endif /* PQF_FLASH_STORE_H */
