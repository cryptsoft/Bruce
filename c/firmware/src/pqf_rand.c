/* pqf_rand.c -- firmware-side RAND_* with the QRNG first in the queue.
 *
 * The vendored OpenSSL BN / EC / ML-DSA code (nonce generation,
 * ephemeral keys, seeds) calls RAND_bytes / RAND_priv_bytes /
 * RAND_bytes_ex / RAND_priv_bytes_ex, and so does the firmware itself
 * (master keys, IVs, PIN tokens, the vendor RNG command, the per-boot
 * USB serial via pqf_rand_bytes). All of it lands here; nothing in the
 * firmware reads a raw source directly.
 *
 * Two sources, in order:
 *   1. the external quantum RNG over I2C (pqf_qrng.c), if -- and only
 *      if -- a chip answered at boot. Its output is SHA-256 conditioned
 *      before it gets here; see pqf_qrng.h for why that is not optional.
 *   2. pico-sdk's get_rand_64(), which the SDK re-seeds on every call
 *      from the RP2350 on-die TRNG (and the timer). This is what the
 *      port used exclusively before the QRNG existed and is the C-port
 *      equivalent of the Rust firmware's trng.rs.
 * Whatever the QRNG leaves short -- it failed mid-request, or it was
 * never there -- the fallback completes, so no caller ever sees fewer
 * bytes than it asked for.
 *
 * Both cores call this. In the single-ISA builds core 1 runs the same
 * image and draws ECDSA hedge bytes (and, at level 87, generates P-256
 * keys) through RAND_bytes while core 0 may be minting an IV, so the
 * QRNG path -- one I2C controller, one output buffer -- is serialised
 * with a hardware spin lock. pico_rand serialises itself. The lock does
 * not mask interrupts: a QRNG draw is milliseconds of bus time and no
 * interrupt handler ever asks for randomness, so there is nothing to
 * protect against and USB service must not be held off that long.
 *
 * The host test rig has its own arc4random-backed stub
 * (test/host_rand_stub.c) for the protocol suites; test/test_qrng.c
 * links THIS file with -DPQF_QRNG_HOST to test the picker itself.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdint.h>

#include "pico/rand.h"

#include "openssl/rand.h"
#include "pqf_rand.h"

#if defined(PQF_QRNG)
#include "pqf_qrng.h"
#if !defined(PQF_QRNG_HOST)
#include "hardware/sync.h"
static spin_lock_t *s_lock;
#endif
static bool s_inited;
static struct pqf_rand_stats s_stats;

static void lock(void)
{
#if !defined(PQF_QRNG_HOST)
    spin_lock_unsafe_blocking(s_lock);
#endif
}

static void unlock(void)
{
#if !defined(PQF_QRNG_HOST)
    spin_unlock_unsafe(s_lock);
#endif
}
#endif /* PQF_QRNG */

/* Fill `buf` with `num` bytes from the SDK CSPRNG. */
static void fill_sdk(unsigned char *buf, size_t num)
{
    size_t i = 0;
    while (i < num) {
        uint64_t r = get_rand_64();
        size_t take = num - i;
        if (take > sizeof r) take = sizeof r;
        for (size_t j = 0; j < take; j++)
            buf[i + j] = (unsigned char)(r >> (j * 8));
        i += take;
    }
}

static int fill(unsigned char *buf, size_t num)
{
    if (buf == NULL)
        return 0;
#if defined(PQF_QRNG)
    if (s_inited && pqf_qrng_present()) {
        lock();
        size_t got = pqf_qrng_bytes(buf, num);
        s_stats.qrng_bytes     += (uint32_t)got;
        s_stats.fallback_bytes += (uint32_t)(num - got);
        unlock();
        buf += got;
        num -= got;
    } else if (s_inited) {
        lock();
        s_stats.fallback_bytes += (uint32_t)num;
        unlock();
    }
#endif
    fill_sdk(buf, num);
    return 1;
}

void pqf_rand_init(void)
{
#if defined(PQF_QRNG)
#if !defined(PQF_QRNG_HOST)
    s_lock = spin_lock_instance((uint)spin_lock_claim_unused(true));
#endif
    s_stats.qrng_bytes = 0;
    s_stats.fallback_bytes = 0;
    (void)pqf_qrng_init();
    s_inited = true;
#endif
}

void pqf_rand_bytes(uint8_t *buf, size_t len)
{
    (void)fill(buf, len);
}

const char *pqf_rand_source_name(void)
{
#if defined(PQF_QRNG)
    if (s_inited && pqf_qrng_present())
        return "QRNG";
#endif
    return "TRNG";
}

const struct pqf_rand_stats *pqf_rand_stats(void)
{
#if defined(PQF_QRNG)
    return &s_stats;
#else
    static const struct pqf_rand_stats none;
    return &none;
#endif
}

int RAND_bytes(unsigned char *buf, int num)
{
    if (num < 0) return 0;
    return fill(buf, (size_t)num);
}

int RAND_priv_bytes(unsigned char *buf, int num)
{
    return RAND_bytes(buf, num);
}

int RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                  unsigned int strength)
{
    (void)ctx; (void)strength;
    return fill(buf, num);
}

int RAND_priv_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                       unsigned int strength)
{
    (void)ctx; (void)strength;
    return fill(buf, num);
}

int RAND_status(void) { return 1; }
