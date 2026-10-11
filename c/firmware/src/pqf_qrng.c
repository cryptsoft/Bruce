/* pqf_qrng.c -- external quantum RNG: probe, framing, conditioning.
 *
 * See pqf_qrng.h for the protocol and why the output is conditioned.
 * Bus access goes through pqf_qrng_hw.h; nothing here touches the SoC.
 *
 * Failure policy. A single bad packet (header or health) is dropped
 * and the next one read; a bus error is retried a few times. If a
 * 64-byte draw still cannot complete, the request returns short and
 * pqf_rand.c fills the remainder from its fallback source -- no caller
 * ever sees fewer bytes than it asked for, and none of them are raw.
 * After a failed draw one status read decides what happened: a chip
 * that no longer answers has been unplugged and is written off on the
 * spot (bus released, the TRNG serving from the next byte), while a
 * chip that still answers had a transient fault and is written off only
 * after a run of those. A chip that was absent at boot, or written off,
 * is not looked for again until the next boot.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "pqf_qrng.h"
#include "pqf_qrng_hw.h"
#include "pqf_cleanse.h"
#include "pqf_crypto.h"
#if defined(PQF_SINGLE_CORE)
/* A 32-byte draw is four I2C packets, ~2 ms each at 100 kHz, and a
 * request of a few blocks is tens of milliseconds -- long enough to be
 * the widest stretch of a single-core op with no keepalive in it. Yield
 * between packets so the crypto's hook fires here too. */
#include "pqf_yield.h"
#define QRNG_YIELD() pqf_yield()
#else
#define QRNG_YIELD() ((void)0)
#endif

/* Power-up initial (~260 us) + calibration + first frame; the datasheet's
 * numbers are small, the margin here is generous. */
#define READY_TRIES            100     /* x 1 ms */
#define PD_HOLD_US             5000    /* PD low >= 3 ms guarantees a clean power-down */
#define PROBE_TRIES            2
/* Rejects tolerated inside one 64-byte draw before it is abandoned. */
#define BAD_PACKETS_PER_DRAW   8
#define BUS_RETRIES_PER_PACKET 3
/* Consecutive short requests before the chip is declared lost. */
#define LOST_AFTER_FAILURES    8

static bool     s_present;
/* Conditioned output not yet handed out: the LAST s_out_len bytes of
 * s_out. Draining advances from the front of that window so every byte
 * is served exactly once, and served bytes are wiped. */
static uint8_t  s_out[PQF_QRNG_HASH_OUT];
static size_t   s_out_len;
static uint32_t s_consecutive_failures;
static struct pqf_qrng_stats s_stats;

static int read_status(uint8_t *status)
{
    *status = 0xFF;
    return pqf_qrng_hw_read_regs(PQF_QRNG_REG_STATUS, status, 1);
}

static bool wait_ready(int tries)
{
    for (int t = 0; t < tries; t++) {
        uint8_t st;
        if (read_status(&st) == 0 && st == 0x00)
            return true;
        pqf_qrng_hw_delay_us(1000);
    }
    return false;
}

bool pqf_qrng_init(void)
{
    s_present = false;
    s_out_len = 0;
    s_consecutive_failures = 0;
    memset(&s_stats, 0, sizeof s_stats);

    if (!pqf_qrng_hw_init()) {
        s_stats.bus_stuck = 1;
        return false;
    }

    /* Is anything there? A missing chip NAKs its address inside one
     * byte time, so an unpopulated bus costs microseconds here and
     * never toggles PD. Two tries, in case the first transaction after
     * bus recovery is the one that resynchronises a confused slave. */
    bool acked = false;
    for (int t = 0; t < PROBE_TRIES && !acked; t++) {
        uint8_t st;
        if (read_status(&st) == 0)
            acked = true;
        else
            pqf_qrng_hw_delay_us(500);
    }
    if (!acked) {
        pqf_qrng_hw_release();
        return false;
    }

    /* Clean restart through PD. SP 800-90B builds its restart tests on
     * exactly this -- a source that resumes a fixed sequence after
     * power-up is exposed by it -- and a fresh calibration per boot
     * costs ~10 ms. No-op when PD is not wired: the breakout idles PD
     * high through its own pull-up and the part simply keeps running. */
    pqf_qrng_hw_pd(false);
    pqf_qrng_hw_delay_us(PD_HOLD_US);
    pqf_qrng_hw_pd(true);
    pqf_qrng_hw_delay_us(PD_HOLD_US);

    if (!wait_ready(READY_TRIES)) {
        /* Answers on the bus but never calibrates: treat as absent. The
         * fallback source is known-good; a part that cannot report
         * ready is not something to draw keys from. */
        s_stats.not_ready = 1;
        pqf_qrng_hw_release();
        return false;
    }
    s_present = true;
    return true;
}

bool pqf_qrng_present(void)
{
    return s_present;
}

enum pqf_qrng_state pqf_qrng_state(void)
{
    if (s_present)
        return PQF_QRNG_LIVE;
    return s_stats.lost ? PQF_QRNG_LOST : PQF_QRNG_ABSENT;
}

const struct pqf_qrng_stats *pqf_qrng_stats(void)
{
    return &s_stats;
}

/* One packet -> 16 entropy bytes.
 *   0  ok
 *  -1  bus error (retryable)
 *   1  packet rejected: bad header or health nibble set (dropped whole)
 * Header and health are framing; letting them through would put a
 * constant into the stream every 16 bytes. */
static int read_packet(uint8_t out[PQF_QRNG_ENTROPY_PER_PKT])
{
    uint8_t pkt[PQF_QRNG_PACKET_LEN];

    if (pqf_qrng_hw_read_regs(PQF_QRNG_REG_PACKET, pkt, sizeof pkt) != 0) {
        s_stats.bus_err++;
        return -1;
    }
    s_stats.packets++;
    if (pkt[0] != PQF_QRNG_HEADER_BYTE) {
        s_stats.header_err++;
        pqf_cleanse(pkt, sizeof pkt);
        return 1;
    }
    if ((pkt[1] & PQF_QRNG_HEALTH_MASK) != 0) {
        s_stats.health_err++;
        pqf_cleanse(pkt, sizeof pkt);
        return 1;
    }
    memcpy(out, &pkt[2], PQF_QRNG_ENTROPY_PER_PKT);
    pqf_cleanse(pkt, sizeof pkt);
    return 0;
}

/* Refill s_out: 64 raw bytes -> SHA-256 -> 32 conditioned. Only called
 * with the window empty, so no unconsumed byte is ever overwritten.
 * false = the draw could not complete; nothing is buffered. */
static bool draw(void)
{
    uint8_t raw[PQF_QRNG_RAW_PER_HASH];
    size_t  got = 0;
    int     rejected = 0;
    int     bus_failures = 0;

    while (got < sizeof raw) {
        int rc;

        QRNG_YIELD();
        rc = read_packet(&raw[got]);
        if (rc == 0) {
            got += PQF_QRNG_ENTROPY_PER_PKT;
            bus_failures = 0;
            continue;
        }
        if (rc < 0) {
            if (++bus_failures > BUS_RETRIES_PER_PACKET)
                goto fail;
            continue;
        }
        if (++rejected > BAD_PACKETS_PER_DRAW)
            goto fail;
    }
    pqf_sha256(raw, sizeof raw, s_out);
    /* The raw bytes are spent; do not leave them in RAM. */
    pqf_cleanse(raw, sizeof raw);
    s_out_len = PQF_QRNG_HASH_OUT;
    return true;

fail:
    pqf_cleanse(raw, sizeof raw);
    return false;
}

size_t pqf_qrng_bytes(uint8_t *out, size_t len)
{
    size_t done = 0;

    if (!s_present || out == NULL)
        return 0;

    while (done < len) {
        if (s_out_len == 0 && !draw())
            break;
        size_t start = PQF_QRNG_HASH_OUT - s_out_len;
        size_t take  = len - done;
        if (take > s_out_len)
            take = s_out_len;
        memcpy(&out[done], &s_out[start], take);
        pqf_cleanse(&s_out[start], take);
        s_out_len -= take;
        done      += take;
    }
    s_stats.served += (uint32_t)done;

    if (done == len) {
        s_consecutive_failures = 0;
        return done;
    }

    /* Short. The caller tops up from its fallback; here, decide whether
     * the chip is worth asking again. One status read settles it: a
     * part that has been unplugged does not answer -- it NAKs, or an
     * unpowered breakout drags the lines down and the read times out --
     * and is written off at once, so the very next request is served by
     * the TRNG alone and nobody keeps paying for a dead bus. A part that
     * still answers had a transient fault (a reset mid-stream, a burst
     * of rejects); that is counted, and written off only after
     * LOST_AFTER_FAILURES of them in a row. */
    s_stats.short_requests++;
    uint8_t st;
    bool alive = (read_status(&st) == 0);
    if (!alive || ++s_consecutive_failures >= LOST_AFTER_FAILURES) {
        s_present = false;
        s_stats.lost = 1;
        s_out_len = 0;
        pqf_cleanse(s_out, sizeof s_out);
        pqf_qrng_hw_release();
    }
    return done;
}
