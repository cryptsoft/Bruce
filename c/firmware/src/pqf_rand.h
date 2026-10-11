/* pqf_rand.h -- the firmware's entropy picker (behind OpenSSL's RAND_*).
 *
 * pqf_rand.c satisfies RAND_bytes and friends for the vendored crypto
 * and for every firmware caller that needs randomness (master keys,
 * ML-DSA seeds, IVs, PIN tokens, the vendor RNG command). This header
 * is the small extra surface: the one-time probe of the optional
 * external QRNG, and what the CDC banner reports about which source is
 * live.
 *
 * Source order: the QRNG on I2C if one answered at boot
 * (pqf_qrng.h), otherwise the source the port has always used --
 * pico-sdk's get_rand_64(), a xoshiro state re-seeded on every call
 * from the RP2350's on-die TRNG (plus the timer). The fallback also
 * completes any request the QRNG leaves short, so a caller never sees
 * a partial fill.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_RAND_H
#define PQF_RAND_H

#include <stddef.h>
#include <stdint.h>

struct pqf_rand_stats {
    uint32_t qrng_bytes;      /* bytes served by the QRNG               */
    uint32_t fallback_bytes;  /* bytes served by get_rand_64()          */
};

/* Probe the QRNG and pick the source. Call once, after the board pins
 * are set up and before anything mints a key -- and before core 1 is
 * launched, since core 1 draws randomness too. RAND_bytes works before
 * this (fallback only); after it, the QRNG is preferred when present. */
void pqf_rand_init(void);

/* Fill `buf` from the picker -- the same source order RAND_bytes uses,
 * for firmware callers that do not speak OpenSSL's RAND_* surface (the
 * per-boot USB serial). Never fails: whatever the QRNG cannot supply,
 * the fallback does. */
void pqf_rand_bytes(uint8_t *buf, size_t len);

/* "QRNG" while the external chip is live, "TRNG" otherwise. */
const char *pqf_rand_source_name(void);

const struct pqf_rand_stats *pqf_rand_stats(void);

#endif /* PQF_RAND_H */
