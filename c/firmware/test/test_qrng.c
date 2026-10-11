/* test_qrng.c -- the QRNG driver and the RAND picker above it,
 * driven on the host against a scripted bus.
 *
 * The chip itself cannot be here, and that is the point: on hardware
 * the driver almost always sees a healthy part, so the paths that
 * matter most -- a bad header, a set health bit, a bus that dies half
 * way through a draw, a chip that answers but never readies -- are the
 * ones silicon never runs. pqf_qrng_hw.h is implemented below as a
 * model the test scripts, and pqf_rand.c is linked with
 * -DPQF_QRNG_HOST so its spin lock becomes a no-op and its fallback
 * source is a counter this file defines. What is under test is
 * therefore the real src/pqf_qrng.c and the real src/pqf_rand.c.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pqf_qrng.h"
#include "pqf_qrng_hw.h"
#include "pqf_rand.h"
#include "pqf_crypto.h"
#include "openssl/rand.h"
#include "pico/rand.h"

static int checks, failures;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); } } while (0)

/* ---- the scripted bus ------------------------------------------------ */

static struct {
    bool     init_ok;           /* pqf_qrng_hw_init() result             */
    bool     chip;              /* something ACKs at 0x37                */
    int      status_busy_reads; /* status reads answering "not ready" first */
    int      bus_fail_after;    /* packet index from which reads fail (-1 never) */
    int      bus_fail_count;    /* consecutive failures then (-1 forever) */
    uint32_t bad_header_mask;   /* bit i: packet i carries a bad header  */
    uint32_t bad_health_mask;   /* bit i: packet i carries a health flag */

    int      inits, releases, pd_low, pd_high;
    int      reads_status, reads_packet, fails_so_far, packet_index;
    uint32_t delay_us;
    uint8_t  next_raw;          /* the entropy stream is a byte counter  */
    /* Oracle: the entropy bytes of every packet the driver ACCEPTED, in
     * order. Hash k of the stream is SHA-256 over good_raw[64k..64k+64]
     * as long as no draw was abandoned part way. */
    uint8_t  good_raw[4096];
    size_t   good_len;
} m;

static void model_reset(void)
{
    memset(&m, 0, sizeof m);
    m.init_ok = true;
    m.chip = true;
    m.bus_fail_after = -1;
    m.bus_fail_count = -1;
    m.next_raw = 1;
}

bool pqf_qrng_hw_init(void)          { m.inits++; return m.init_ok; }
void pqf_qrng_hw_release(void)       { m.releases++; }
void pqf_qrng_hw_pd(bool high)       { if (high) m.pd_high++; else m.pd_low++; }
void pqf_qrng_hw_delay_us(uint32_t us) { m.delay_us += us; }
const char *pqf_qrng_hw_describe(void) { return "scripted bus"; }

int pqf_qrng_hw_read_regs(uint8_t reg, uint8_t *buf, size_t len)
{
    if (!m.chip)
        return -1;
    if (reg == PQF_QRNG_REG_STATUS) {
        m.reads_status++;
        if (len != 1) return -1;
        if (m.status_busy_reads > 0) {
            m.status_busy_reads--;
            buf[0] = 0x01;
        } else {
            buf[0] = 0x00;
        }
        return 0;
    }
    if (reg == PQF_QRNG_REG_PACKET) {
        if (len != PQF_QRNG_PACKET_LEN) return -1;
        int idx = m.packet_index++;
        m.reads_packet++;
        if (m.bus_fail_after >= 0 && idx >= m.bus_fail_after
            && (m.bus_fail_count < 0 || m.fails_so_far < m.bus_fail_count)) {
            m.fails_so_far++;
            return -1;
        }
        bool bad_hdr = idx < 32 && ((m.bad_header_mask >> idx) & 1u);
        bool bad_hlt = idx < 32 && ((m.bad_health_mask >> idx) & 1u);
        buf[0] = bad_hdr ? 0x00 : PQF_QRNG_HEADER_BYTE;
        buf[1] = bad_hlt ? 0x04 : 0x00;
        for (int i = 0; i < PQF_QRNG_ENTROPY_PER_PKT; i++)
            buf[2 + i] = m.next_raw++;
        if (!bad_hdr && !bad_hlt && m.good_len + 16 <= sizeof m.good_raw) {
            memcpy(&m.good_raw[m.good_len], &buf[2], 16);
            m.good_len += 16;
        }
        return 0;
    }
    return -1;
}

/* ---- the fallback source pqf_rand.c falls through to ------------------ */

static uint64_t fb_state;
static int      fb_calls;

uint64_t get_rand_64(void)
{
    fb_calls++;
    fb_state += 0x9e3779b97f4a7c15ULL;
    return fb_state;
}

/* What fill_sdk() in pqf_rand.c would produce from a given state. */
static void expect_fallback(uint64_t state, uint8_t *out, size_t n)
{
    size_t i = 0;
    while (i < n) {
        state += 0x9e3779b97f4a7c15ULL;
        size_t take = n - i;
        if (take > 8) take = 8;
        for (size_t j = 0; j < take; j++) out[i + j] = (uint8_t)(state >> (j * 8));
        i += take;
    }
}

static void expect_hash(size_t k, uint8_t out[32])
{
    pqf_sha256(&m.good_raw[64 * k], 64, out);
}

static void fresh(void)
{
    model_reset();
    fb_state = 0;
    fb_calls = 0;
    pqf_rand_init();
}

/* ---- checks ------------------------------------------------------------ */

static void t_sha256_anchor(void)
{
    printf("--- SHA-256 anchor ---\n");
    /* The conditioner is the vendored SHA-256. Pin it to FIPS 180-4's
     * "abc" vector, so the hashes the other checks compute are known
     * to be SHA-256 and not merely self-consistent. */
    static const uint8_t want[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    uint8_t got[32];
    pqf_sha256((const uint8_t *)"abc", 3, got);
    CHECK(memcmp(got, want, 32) == 0, "pqf_sha256 is not SHA-256");
}

static void t_absent_chip_falls_back(void)
{
    printf("--- no chip on the bus ---\n");
    model_reset();
    m.chip = false;
    fb_state = 0; fb_calls = 0;
    pqf_rand_init();

    CHECK(!pqf_qrng_present(), "a bus with no chip was reported present");
    CHECK(pqf_qrng_state() == PQF_QRNG_ABSENT, "state should be ABSENT, not LOST");
    CHECK(strcmp(pqf_rand_source_name(), "TRNG") == 0, "source name should be TRNG");
    CHECK(m.releases == 1, "the pins were not released after the miss");
    CHECK(m.pd_low == 0 && m.pd_high == 0, "PD was toggled although nothing answered");
    CHECK(m.reads_packet == 0, "a packet was requested from an absent chip");

    uint8_t got[20], want[20];
    expect_fallback(fb_state, want, sizeof want);
    CHECK(RAND_bytes(got, sizeof got) == 1, "RAND_bytes failed with no QRNG");
    CHECK(memcmp(got, want, sizeof got) == 0, "fallback bytes are not get_rand_64 output");
    CHECK(pqf_rand_stats()->fallback_bytes == 20 && pqf_rand_stats()->qrng_bytes == 0,
          "stats did not attribute the bytes to the fallback");
    CHECK(m.reads_packet == 0, "RAND_bytes touched the bus with no chip present");
}

static void t_stuck_bus_is_not_a_chip(void)
{
    printf("--- SDA/SCL held low ---\n");
    model_reset();
    m.init_ok = false;
    fb_state = 0; fb_calls = 0;
    pqf_rand_init();
    CHECK(!pqf_qrng_present(), "a stuck bus was reported as a present chip");
    CHECK(pqf_qrng_stats()->bus_stuck == 1, "bus_stuck not recorded");
    CHECK(m.reads_status == 0, "the driver talked on a bus it was told was stuck");
    uint8_t b[8];
    CHECK(RAND_bytes(b, 8) == 1 && fb_calls == 1, "fallback did not serve the request");
}

static void t_chip_that_never_readies_is_absent(void)
{
    printf("--- chip ACKs but never calibrates ---\n");
    model_reset();
    m.status_busy_reads = 100000;
    pqf_rand_init();
    CHECK(!pqf_qrng_present(), "a chip that never reads ready was used");
    CHECK(pqf_qrng_stats()->not_ready == 1, "not_ready not recorded");
    CHECK(m.pd_low == 1 && m.pd_high == 1, "no PD power-cycle although the chip ACKed");
    CHECK(m.releases == 1, "pins not released");
    CHECK(m.delay_us < 2000000, "the ready wait is not bounded (took >2 s of modelled time)");
    uint8_t b[4];
    CHECK(RAND_bytes(b, 4) == 1 && m.reads_packet == 0, "fallback not used after not-ready");
}

static void t_present_output_is_conditioned(void)
{
    printf("--- present: output is SHA-256 over 64 raw bytes ---\n");
    fresh();
    /* ready on the 4th status read, to prove the wait is a wait */
    model_reset(); m.status_busy_reads = 3; fb_state = 0; fb_calls = 0;
    pqf_rand_init();
    CHECK(pqf_qrng_present(), "chip not detected");
    CHECK(strcmp(pqf_rand_source_name(), "QRNG") == 0, "source name should be QRNG");
    CHECK(m.pd_low == 1 && m.pd_high == 1, "PD was not pulsed once");
    CHECK(m.reads_status >= 4, "ready was not waited for");

    uint8_t got[32], want[32];
    CHECK(RAND_bytes(got, 32) == 1, "RAND_bytes failed");
    expect_hash(0, want);
    CHECK(memcmp(got, want, 32) == 0, "output is not SHA-256(first 64 raw bytes)");
    CHECK(m.reads_packet == 4, "a 32-byte request should read exactly 4 packets");
    CHECK(fb_calls == 0, "the fallback was consulted while the QRNG served");
    CHECK(pqf_qrng_stats()->served == 32 && pqf_rand_stats()->qrng_bytes == 32,
          "served/qrng_bytes wrong");
    /* framing dropped: neither the header nor the health byte can be in
     * the hashed input, so hashing a packet WITH them must differ */
    uint8_t with_frame[72], h2[32];
    for (int p = 0; p < 4; p++) {
        with_frame[p * 18] = PQF_QRNG_HEADER_BYTE;
        with_frame[p * 18 + 1] = 0;
        memcpy(&with_frame[p * 18 + 2], &m.good_raw[p * 16], 16);
    }
    pqf_sha256(with_frame, 72, h2);
    CHECK(memcmp(got, h2, 32) != 0, "framing bytes leaked into the conditioner input");
}

static void t_residual_is_buffered_and_served_once(void)
{
    printf("--- small requests drain the buffered hash ---\n");
    fresh();
    uint8_t a[16], b[16], want[32];
    RAND_bytes(a, 16);
    RAND_bytes(b, 16);
    expect_hash(0, want);
    CHECK(memcmp(a, want, 16) == 0, "first half wrong");
    CHECK(memcmp(b, want + 16, 16) == 0, "second half did not continue where the first stopped");
    CHECK(m.reads_packet == 4, "two 16-byte requests should cost one draw");
    CHECK(memcmp(a, b, 16) != 0, "the two halves are identical -- bytes were re-served");
}

static void t_request_spanning_draws_stays_in_order(void)
{
    printf("--- a request spanning two draws ---\n");
    fresh();
    uint8_t got[40], h0[32], h1[32], tail[24];
    RAND_bytes(got, 40);
    expect_hash(0, h0);
    expect_hash(1, h1);
    CHECK(memcmp(got, h0, 32) == 0, "first 32 wrong");
    CHECK(memcmp(got + 32, h1, 8) == 0, "bytes 32..40 are not the start of the next hash");
    RAND_bytes(tail, 24);
    CHECK(memcmp(tail, h1 + 8, 24) == 0, "the rest of the second hash was not what followed");
    CHECK(m.reads_packet == 8, "40 + 24 bytes should be exactly two draws");
}

static void t_bad_header_packet_is_dropped(void)
{
    printf("--- bad header ---\n");
    fresh();
    model_reset(); m.bad_header_mask = 1u << 1; fb_state = 0; fb_calls = 0;
    pqf_rand_init();
    uint8_t got[32], want[32];
    RAND_bytes(got, 32);
    expect_hash(0, want);
    CHECK(memcmp(got, want, 32) == 0, "the bad packet's bytes reached the conditioner");
    CHECK(pqf_qrng_stats()->header_err == 1, "header_err not counted");
    CHECK(m.reads_packet == 5, "dropping one packet should cost one extra read");
    CHECK(fb_calls == 0, "a single bad packet should not fall back");
}

static void t_health_flag_packet_is_dropped(void)
{
    printf("--- health nibble set ---\n");
    fresh();
    model_reset(); m.bad_health_mask = (1u << 0) | (1u << 3); fb_state = 0; fb_calls = 0;
    pqf_rand_init();
    uint8_t got[32], want[32];
    RAND_bytes(got, 32);
    expect_hash(0, want);
    CHECK(memcmp(got, want, 32) == 0, "an unhealthy packet's bytes reached the conditioner");
    CHECK(pqf_qrng_stats()->health_err == 2, "health_err not counted");
    CHECK(m.reads_packet == 6, "two drops should cost two extra reads");
}

static void t_too_many_rejects_fall_back(void)
{
    printf("--- a stream of rejects ---\n");
    fresh();
    model_reset(); m.bad_header_mask = 0x1FF; fb_state = 0; fb_calls = 0;  /* 9 bad in a row */
    pqf_rand_init();
    uint8_t got[16], want[16];
    uint64_t st = fb_state;
    RAND_bytes(got, 16);
    expect_fallback(st, want, 16);
    CHECK(memcmp(got, want, 16) == 0, "the request was not completed from the fallback");
    CHECK(pqf_qrng_stats()->header_err == 9, "expected the draw to give up after the ninth reject");
    CHECK(pqf_qrng_stats()->short_requests == 1, "short request not counted");
    CHECK(pqf_qrng_present(), "one failed request must not write the chip off");
}

static void t_unplugged_chip_is_written_off_at_once(void)
{
    printf("--- cable pulled: the chip stops answering ---\n");
    fresh();
    CHECK(pqf_qrng_state() == PQF_QRNG_LIVE, "state should be LIVE after a good probe");
    m.chip = false;                          /* nothing answers any more */
    uint8_t b[8], want[8];
    uint64_t st = fb_state;
    RAND_bytes(b, 8);
    expect_fallback(st, want, 8);
    CHECK(memcmp(b, want, 8) == 0, "the very first request after the unplug was not completed by the fallback");
    CHECK(!pqf_qrng_present(), "a chip that no longer answers was kept after one failed request");
    CHECK(pqf_qrng_state() == PQF_QRNG_LOST, "state should be LOST");
    CHECK(pqf_qrng_stats()->lost == 1 && pqf_qrng_stats()->short_requests == 1,
          "lost/short not recorded");
    CHECK(m.releases == 1, "the bus was not released");
    CHECK(strcmp(pqf_rand_source_name(), "TRNG") == 0, "source name should read TRNG");
    int reads = m.reads_packet + m.reads_status;
    RAND_bytes(b, 8);
    CHECK(m.reads_packet + m.reads_status == reads, "a written-off chip is still being asked");
    CHECK(pqf_rand_stats()->fallback_bytes == 16, "both requests should be on the fallback");
}

static void t_bus_dies_mid_request(void)
{
    printf("--- bus error half way through a request ---\n");
    fresh();
    model_reset(); m.bus_fail_after = 4; fb_state = 0; fb_calls = 0;   /* first draw ok, then dead */
    pqf_rand_init();
    uint8_t got[64], h0[32], fb[32];
    uint64_t st = fb_state;
    int status_before = m.reads_status;
    CHECK(RAND_bytes(got, 64) == 1, "RAND_bytes must still report success");
    expect_hash(0, h0);
    expect_fallback(st, fb, 32);
    CHECK(memcmp(got, h0, 32) == 0, "the QRNG half is wrong");
    CHECK(memcmp(got + 32, fb, 32) == 0, "the remainder did not come from the fallback");
    CHECK(pqf_qrng_stats()->bus_err == 4, "expected 4 bus errors (3 retries + the one that gave up)");
    CHECK(pqf_qrng_stats()->short_requests == 1, "short request not counted");
    CHECK(pqf_rand_stats()->qrng_bytes == 32 && pqf_rand_stats()->fallback_bytes == 32,
          "stats did not split the request 32/32");
    CHECK(m.reads_status == status_before + 1, "expected exactly one liveness read after the failure");
    CHECK(pqf_qrng_present(), "a chip that still answers must not be written off by one failure");
}

static void t_persistent_failure_writes_the_chip_off(void)
{
    printf("--- eight failures in a row ---\n");
    fresh();
    model_reset(); m.bus_fail_after = 0; fb_state = 0; fb_calls = 0;
    pqf_rand_init();
    CHECK(pqf_qrng_present(), "chip should be present at init (status reads are fine)");
    uint8_t b[8];
    for (int i = 0; i < 7; i++) RAND_bytes(b, 8);
    CHECK(pqf_qrng_present(), "written off too early (after 7)");
    RAND_bytes(b, 8);
    CHECK(!pqf_qrng_present(), "still present after 8 consecutive failures");
    CHECK(pqf_qrng_stats()->lost == 1, "lost not recorded");
    CHECK(m.releases == 1, "bus not released after being written off");
    CHECK(strcmp(pqf_rand_source_name(), "TRNG") == 0, "source name should read TRNG once lost");
    int reads = m.reads_packet;
    RAND_bytes(b, 8);
    CHECK(m.reads_packet == reads, "a written-off chip is still being asked");
    CHECK(fb_calls == 9, "every one of the nine requests should have hit the fallback once");
}

static void t_transient_failure_recovers(void)
{
    printf("--- transient bus failure then recovery ---\n");
    fresh();
    /* draw 1 (packets 0-3) ok; packets 4-9 fail (6 failures); then fine */
    model_reset(); m.bus_fail_after = 4; m.bus_fail_count = 6; fb_state = 0; fb_calls = 0;
    pqf_rand_init();
    uint8_t a[32], b[32], want[32];
    RAND_bytes(a, 32);                       /* draw 1 */
    RAND_bytes(a, 32);                       /* 4 failures -> short -> fallback */
    CHECK(pqf_qrng_stats()->short_requests == 1, "expected exactly one short request");
    CHECK(fb_calls == 4, "the short request should have taken 32 fallback bytes (4 calls)");
    RAND_bytes(b, 32);                       /* 2 failures, then 4 good packets */
    expect_hash(1, want);
    CHECK(memcmp(b, want, 32) == 0, "after recovery the QRNG output is wrong");
    CHECK(fb_calls == 4, "the recovered request still touched the fallback");
    CHECK(pqf_qrng_present(), "chip written off after a transient fault");
    /* and the consecutive-failure counter really reset: 7 more failures
     * must not write it off */
    m.bus_fail_after = m.packet_index; m.bus_fail_count = -1; m.fails_so_far = 0;
    for (int i = 0; i < 7; i++) RAND_bytes(a, 8);
    CHECK(pqf_qrng_present(), "the failure counter did not reset after a good request");
}

static void t_rand_api_edges(void)
{
    printf("--- RAND_* edges ---\n");
    fresh();
    uint8_t b[8], want[32];
    CHECK(RAND_bytes(NULL, 4) == 0, "NULL buffer accepted");
    CHECK(RAND_bytes(b, -1) == 0, "negative length accepted");
    CHECK(RAND_bytes(b, 0) == 1, "zero-length request failed");
    CHECK(m.reads_packet == 0, "an empty request drew from the chip");
    CHECK(RAND_status() == 1, "RAND_status");
    /* every entry point routes to the same picker */
    uint8_t p[8], e[8], pe[8];
    RAND_priv_bytes(p, 8);
    RAND_bytes_ex(NULL, e, 8, 0);
    RAND_priv_bytes_ex(NULL, pe, 8, 0);
    expect_hash(0, want);
    CHECK(memcmp(p, want, 8) == 0 && memcmp(e, want + 8, 8) == 0 && memcmp(pe, want + 16, 8) == 0,
          "the _priv/_ex entry points did not draw from the QRNG in order");
}

int main(void)
{
    t_sha256_anchor();
    t_absent_chip_falls_back();
    t_stuck_bus_is_not_a_chip();
    t_chip_that_never_readies_is_absent();
    t_present_output_is_conditioned();
    t_residual_is_buffered_and_served_once();
    t_request_spanning_draws_stays_in_order();
    t_bad_header_packet_is_dropped();
    t_health_flag_packet_is_dropped();
    t_too_many_rejects_fall_back();
    t_bus_dies_mid_request();
    t_unplugged_chip_is_written_off_at_once();
    t_persistent_failure_writes_the_chip_off();
    t_transient_failure_recovers();
    t_rand_api_edges();
    printf("test_qrng: %d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
