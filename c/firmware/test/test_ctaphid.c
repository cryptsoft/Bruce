/* test_ctaphid.c -- host test of the CTAP-HID transport (src/ctaphid.c).
 *
 * This is the layer every byte from the host passes through before
 * anything else looks at it, and it is reachable by anything that can
 * send USB frames: no PIN, no user presence, nothing. 564 lines, and
 * until now the only thing exercising it was a real board running real
 * ceremonies, which drives the happy path and nothing else.
 *
 * So what is covered here is the other path: truncated and out-of-order
 * frames, channel arbitration, a declared length past the maximum, a
 * stalled reassembly, and the two vendor commands. The Rust port's
 * equivalent suite is crates/firmware-hosttest/tests/ctaphid.rs; these
 * mirror it, which is the point -- two independent implementations of
 * one wire format should agree, and where they do not, one is wrong.
 *
 * Platform seams: PQF_CTAPHID_HOST swaps the RP2350 timer for the
 * settable clock below (a frozen clock could never reach the reassembly
 * timeout, so the seam had to be widened to test it), and
 * pqf_board_reboot is recorded rather than performed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "ctaphid.h"
#include "board.h"

/* Mirrors CTAPHID_MSG_TIMEOUT_US, which is private to ctaphid.c. If
 * the two ever diverge the timeout test stops proving anything, so it
 * checks the boundary from both sides. */
#define HOST_MSG_TIMEOUT_US 500000ull

static int failures;
static int checks;
#define CHECK(cond, ...) do {                                       \
        checks++;                                                   \
        if (!(cond)) {                                              \
            failures++;                                             \
            printf("  [FAIL] " __VA_ARGS__);                        \
            printf("\n         at %s:%d\n", __FILE__, __LINE__);    \
        }                                                           \
    } while (0)

/* ---- the seams ------------------------------------------------- */

static uint64_t host_clock_us;
uint64_t pqf_ctaphid_host_now_us(void) { return host_clock_us; }

static int reboot_calls;
static enum pqf_reboot_mode reboot_mode;
void pqf_board_reboot(enum pqf_reboot_mode mode)
{
    reboot_calls++;
    reboot_mode = mode;
}

/* Whether BOOTSEL is available, as the OTP fuses would report it. The
 * firmware reads BOOT_FLAGS0 for this; the harness sets it directly so
 * a test can drive a fused-off board without one. */
static bool bootsel_available = true;
bool pqf_board_bootsel_available(void) { return bootsel_available; }

/* ---- captured output ------------------------------------------- */

#define MAX_FRAMES 512
static uint8_t sent[MAX_FRAMES][CTAPHID_FRAME_SIZE];
static size_t  sent_n;

static void capture(const uint8_t *frame)
{
    if (sent_n < MAX_FRAMES) memcpy(sent[sent_n], frame, CTAPHID_FRAME_SIZE);
    sent_n++;
}

static void reset_capture(void) { sent_n = 0; }

static void fresh(void)
{
    ctaphid_init();
    ctaphid_set_wink(NULL);
    host_clock_us = 0;
    reboot_calls = 0;
    reset_capture();
}

/* ---- frame builders -------------------------------------------- */

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* An initialisation frame: CID | 0x80|cmd | BE16 total length | data. */
static void init_frame(uint8_t *f, uint32_t cid, uint8_t cmd,
                       const uint8_t *data, size_t data_len, size_t total)
{
    memset(f, 0, CTAPHID_FRAME_SIZE);
    put_be32(f, cid);
    f[4] = (uint8_t)(cmd | CTAPHID_INIT_BIT);
    f[5] = (uint8_t)(total >> 8);
    f[6] = (uint8_t)total;
    if (data_len > CTAPHID_INIT_PAYLOAD) data_len = CTAPHID_INIT_PAYLOAD;
    if (data && data_len) memcpy(f + 7, data, data_len);
}

/* A continuation frame: CID | seq | data. */
static void cont_frame(uint8_t *f, uint32_t cid, uint8_t seq,
                       const uint8_t *data, size_t data_len)
{
    memset(f, 0, CTAPHID_FRAME_SIZE);
    put_be32(f, cid);
    f[4] = seq;
    if (data_len > CTAPHID_CONT_PAYLOAD) data_len = CTAPHID_CONT_PAYLOAD;
    if (data && data_len) memcpy(f + 5, data, data_len);
}

static void feed_init(uint32_t cid, uint8_t cmd, const uint8_t *data,
                      size_t data_len, size_t total)
{
    uint8_t f[CTAPHID_FRAME_SIZE];
    init_frame(f, cid, cmd, data, data_len, total);
    ctaphid_recv_frame(f, capture);
}

static void feed_cont(uint32_t cid, uint8_t seq, const uint8_t *data,
                      size_t data_len)
{
    uint8_t f[CTAPHID_FRAME_SIZE];
    cont_frame(f, cid, seq, data, data_len);
    ctaphid_recv_frame(f, capture);
}

/* Send a whole message, fragmenting as the transport requires. */
static void feed_message(uint32_t cid, uint8_t cmd,
                         const uint8_t *data, size_t len)
{
    size_t first = len < CTAPHID_INIT_PAYLOAD ? len : CTAPHID_INIT_PAYLOAD;
    feed_init(cid, cmd, data, first, len);
    size_t off = first;
    uint8_t seq = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > CTAPHID_CONT_PAYLOAD) n = CTAPHID_CONT_PAYLOAD;
        feed_cont(cid, seq++, data + off, n);
        off += n;
    }
}

/* ---- response readers ------------------------------------------ */

static uint8_t resp_cmd(size_t i)   { return sent[i][4] & 0x7fu; }
static uint32_t resp_cid(size_t i)  { return be32(sent[i]); }
static size_t resp_len(size_t i)
{
    return ((size_t)sent[i][5] << 8) | sent[i][6];
}
/* The error byte of an ERROR response. */
static uint8_t resp_err(size_t i)   { return sent[i][7]; }

/* Reassemble the payload of the response starting at frame `i`. */
static size_t resp_payload(size_t i, uint8_t *out, size_t cap)
{
    size_t total = resp_len(i);
    size_t n = total < CTAPHID_INIT_PAYLOAD ? total : CTAPHID_INIT_PAYLOAD;
    if (n > cap) n = cap;
    memcpy(out, sent[i] + 7, n);
    size_t got = n, f = i + 1;
    while (got < total && f < sent_n) {
        size_t want = total - got;
        if (want > CTAPHID_CONT_PAYLOAD) want = CTAPHID_CONT_PAYLOAD;
        if (got + want > cap) want = cap - got;
        memcpy(out + got, sent[f] + 5, want);
        got += want;
        f++;
    }
    return got;
}

/* Open a channel and return its CID. */
static uint32_t open_channel(void)
{
    uint8_t nonce[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    reset_capture();
    feed_message(CTAPHID_BROADCAST_CID, CTAPHID_CMD_INIT, nonce, 8);
    if (sent_n == 0) return 0;
    /* INIT response: nonce(8) | CID(4) | versions... */
    return be32(sent[0] + 7 + 8);
}

/* ---- channels --------------------------------------------------- */

static void t_init(void)
{
    printf("--- INIT and channel allocation ---\n");
    fresh();
    uint8_t nonce[8] = { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
    feed_message(CTAPHID_BROADCAST_CID, CTAPHID_CMD_INIT, nonce, 8);

    CHECK(sent_n == 1, "INIT produced %zu frames, want 1", sent_n);
    CHECK(resp_cmd(0) == CTAPHID_CMD_INIT, "INIT answered cmd %#04x", resp_cmd(0));
    CHECK(resp_cid(0) == CTAPHID_BROADCAST_CID,
          "the INIT reply came back on %#010x, not the broadcast channel",
          resp_cid(0));
    CHECK(memcmp(sent[0] + 7, nonce, 8) == 0,
          "the nonce did not come back -- a host uses it to tell its own "
          "INIT reply from another process's");
    CHECK(resp_len(0) >= 17, "INIT response is %zu bytes, too short for a "
          "CID and version block", resp_len(0));

    uint32_t cid = be32(sent[0] + 7 + 8);
    CHECK(cid != 0, "INIT handed out channel 0");
    CHECK(cid != CTAPHID_BROADCAST_CID, "INIT handed out the broadcast CID");

    /* The channel it handed out has to work. */
    reset_capture();
    uint8_t ping[4] = { 9, 9, 9, 9 };
    feed_message(cid, CTAPHID_CMD_PING, ping, 4);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_PING,
          "the freshly allocated channel did not answer a PING");
}

static void t_distinct_channels(void)
{
    printf("--- every allocation is distinct ---\n");
    fresh();
    uint32_t seen[8];
    for (int i = 0; i < 8; i++) {
        seen[i] = open_channel();
        CHECK(seen[i] != 0, "allocation %d returned channel 0", i);
        for (int j = 0; j < i; j++)
            CHECK(seen[i] != seen[j],
                  "allocations %d and %d both got %#010x -- two hosts would "
                  "interleave on one channel", j, i, seen[i]);
    }
}

static void t_channel_zero(void)
{
    printf("--- channel 0 and the broadcast channel ---\n");
    fresh();
    uint8_t ping[2] = { 1, 2 };
    feed_message(0, CTAPHID_CMD_PING, ping, 2);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "channel 0 was served rather than refused");

    /* Only INIT is legal on the broadcast channel. */
    fresh();
    feed_message(CTAPHID_BROADCAST_CID, CTAPHID_CMD_PING, ping, 2);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "a PING on the broadcast channel was answered");

    fresh();
    feed_message(CTAPHID_BROADCAST_CID, CTAPHID_CMD_CBOR, ping, 2);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "a CBOR command on the broadcast channel was answered");
}

/* ---- PING ------------------------------------------------------- */

static void t_ping(void)
{
    printf("--- PING ---\n");
    fresh();
    uint32_t cid = open_channel();

    /* A payload spanning several frames must come back byte for byte;
     * this is the only command whose whole contract is "echo", so it is
     * the cleanest test of reassembly and fragmentation together. */
    static uint8_t payload[600];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i * 7 + 3);
    reset_capture();
    feed_message(cid, CTAPHID_CMD_PING, payload, sizeof payload);

    CHECK(sent_n >= 1, "a %zu-byte PING produced no answer", sizeof payload);
    CHECK(resp_cmd(0) == CTAPHID_CMD_PING, "PING answered cmd %#04x", resp_cmd(0));
    CHECK(resp_len(0) == sizeof payload,
          "PING answered %zu bytes for a %zu-byte request",
          resp_len(0), sizeof payload);
    static uint8_t back[sizeof payload];
    size_t n = resp_payload(0, back, sizeof back);
    CHECK(n == sizeof payload, "reassembled %zu of %zu bytes", n, sizeof payload);
    CHECK(memcmp(back, payload, sizeof payload) == 0, "PING altered its payload");

    /* Zero length is legal and must be answered, not ignored. */
    reset_capture();
    feed_init(cid, CTAPHID_CMD_PING, NULL, 0, 0);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_PING && resp_len(0) == 0,
          "an empty PING was not answered");
}

/* ---- commands --------------------------------------------------- */

static int wink_calls;
static void wink_cb(void) { wink_calls++; }

static void t_wink(void)
{
    printf("--- WINK ---\n");
    fresh();
    uint32_t cid = open_channel();
    ctaphid_set_wink(wink_cb);
    wink_calls = 0;
    reset_capture();
    feed_init(cid, CTAPHID_CMD_WINK, NULL, 0, 0);
    CHECK(wink_calls == 1, "WINK ran the callback %d times, want 1", wink_calls);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_WINK,
          "WINK was not acknowledged");
    ctaphid_set_wink(NULL);
}

static void t_unknown_command(void)
{
    printf("--- unknown commands ---\n");
    fresh();
    uint32_t cid = open_channel();
    const uint8_t unknown[] = { 0x02, 0x05, 0x07, 0x20, 0x33, 0x7e };
    for (size_t i = 0; i < sizeof unknown; i++) {
        reset_capture();
        feed_init(cid, unknown[i], NULL, 0, 0);
        CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
              "command %#04x was not refused", unknown[i]);
        CHECK(sent_n == 1 && resp_err(0) == CTAPHID_ERR_INVALID_CMD,
              "command %#04x answered error %#04x, want INVALID_CMD",
              unknown[i], sent_n ? resp_err(0) : 0);
    }
}

static void t_cancel(void)
{
    printf("--- CANCEL ---\n");
    fresh();
    uint32_t cid = open_channel();
    reset_capture();
    feed_init(cid, CTAPHID_CMD_CANCEL, NULL, 0, 0);
    /* CTAP sec. 11.2.9.1.5: CANCEL is not itself answered. A reply here
     * would arrive interleaved with the cancelled command's own. */
    CHECK(sent_n == 0, "CANCEL produced %zu frames, want none", sent_n);

    /* And the channel still works afterwards. */
    uint8_t ping[3] = { 1, 2, 3 };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_PING, ping, 3);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_PING,
          "the channel stopped answering after a CANCEL");
}

/* ---- reassembly -------------------------------------------------- */

static void t_out_of_order(void)
{
    printf("--- reassembly: sequence and state ---\n");
    fresh();
    uint32_t cid = open_channel();

    /* Sequence numbers must run 0,1,2... A gap means a frame was lost,
     * and continuing would splice unrelated bytes into the message. */
    static uint8_t payload[200];
    memset(payload, 0xA5, sizeof payload);
    reset_capture();
    feed_init(cid, CTAPHID_CMD_PING, payload, CTAPHID_INIT_PAYLOAD, sizeof payload);
    feed_cont(cid, 1, payload, CTAPHID_CONT_PAYLOAD);   /* want seq 0 */
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "an out-of-order continuation was accepted");
    CHECK(sent_n == 1 && resp_err(0) == CTAPHID_ERR_INVALID_SEQ,
          "out-of-order answered %#04x, want INVALID_SEQ",
          sent_n ? resp_err(0) : 0);

    /* CTAP HID sec. 11.2.5.4: "Spurious continuation packets appearing
     * without a prior initialization packet will be ignored." Silence
     * is the specified answer, and it must not index into an empty
     * reassembly buffer on the way to producing it.
     *
     * This is where the two ports disagreed: the Rust port answered
     * ERR_INVALID_SEQ here, and its own note claimed both ports did.
     * Mirroring this suite across is what turned that up. */
    fresh();
    cid = open_channel();
    reset_capture();
    feed_cont(cid, 0, payload, 8);
    CHECK(sent_n == 0, "a stray continuation drew %zu frames, want silence",
          sent_n);
}

static void t_busy(void)
{
    printf("--- channel arbitration ---\n");
    fresh();
    uint32_t a = open_channel();
    uint32_t b = open_channel();
    CHECK(a != b, "setup: two distinct channels");

    static uint8_t payload[200];
    memset(payload, 0x5A, sizeof payload);
    reset_capture();
    feed_init(a, CTAPHID_CMD_PING, payload, CTAPHID_INIT_PAYLOAD, sizeof payload);

    /* CTAP sec. 11.2.5: one transaction at a time. A second channel gets
     * CHANNEL_BUSY rather than having its frames folded into the
     * first one's message. */
    reset_capture();
    feed_init(b, CTAPHID_CMD_PING, payload, 4, 4);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "a second channel was served mid-transaction");
    CHECK(sent_n == 1 && resp_err(0) == CTAPHID_ERR_CHANNEL_BUSY,
          "the second channel got %#04x, want CHANNEL_BUSY",
          sent_n ? resp_err(0) : 0);
    CHECK(sent_n == 1 && resp_cid(0) == b,
          "the busy error went to the wrong channel");

    /* A continuation from the other channel is a *spurious* one -- B has
     * nothing in flight -- so sec. 11.2.5.4 says ignore it rather than
     * answer. What matters either way is the next check: channel A's
     * half-received message survives. Without that, any host could drop
     * any other host's transaction with one frame, on a transport with
     * no authentication at all. */
    reset_capture();
    feed_cont(b, 0, payload, 8);
    CHECK(sent_n == 0, "B's spurious continuation drew %zu frames", sent_n);

    reset_capture();
    size_t off = CTAPHID_INIT_PAYLOAD;
    uint8_t seq = 0;
    while (off < sizeof payload) {
        size_t n = sizeof payload - off;
        if (n > CTAPHID_CONT_PAYLOAD) n = CTAPHID_CONT_PAYLOAD;
        feed_cont(a, seq++, payload + off, n);
        off += n;
    }
    CHECK(sent_n >= 1 && resp_cmd(0) == CTAPHID_CMD_PING,
          "channel A's message did not complete after B interfered");
    static uint8_t back[sizeof payload];
    CHECK(sent_n >= 1 && resp_payload(0, back, sizeof back) == sizeof payload
          && memcmp(back, payload, sizeof payload) == 0,
          "channel A's message was corrupted by channel B's frames");
}

static void t_length_bounds(void)
{
    printf("--- declared lengths ---\n");
    fresh();
    uint32_t cid = open_channel();

    /* The declared length is a 16-bit field the host controls. Past the
     * reassembly buffer it must be refused up front, not accumulated
     * until something overflows. */
    reset_capture();
    feed_init(cid, CTAPHID_CMD_PING, NULL, 0, 0xffff);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "a 65535-byte declared length was accepted");
    CHECK(sent_n == 1 && resp_err(0) == CTAPHID_ERR_INVALID_LEN,
          "an oversized length answered %#04x, want INVALID_LEN",
          sent_n ? resp_err(0) : 0);

    /* And exactly the maximum must be accepted, or the advertised
     * ceiling is a lie. */
    fresh();
    cid = open_channel();
    static uint8_t big[CTAPHID_MAX_MSG_BYTES];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)i;
    reset_capture();
    feed_message(cid, CTAPHID_CMD_PING, big, sizeof big);
    CHECK(sent_n >= 1 && resp_cmd(0) == CTAPHID_CMD_PING,
          "a message of exactly CTAPHID_MAX_MSG_BYTES (%d) was refused",
          CTAPHID_MAX_MSG_BYTES);
    CHECK(sent_n >= 1 && resp_len(0) == sizeof big,
          "the maximum-length echo came back %zu bytes",
          sent_n ? resp_len(0) : 0);
}

static void t_timeout(void)
{
    printf("--- stalled reassembly ---\n");
    fresh();
    uint32_t a = open_channel();
    uint32_t b = open_channel();

    static uint8_t payload[200];
    memset(payload, 0x33, sizeof payload);
    reset_capture();
    feed_init(a, CTAPHID_CMD_PING, payload, CTAPHID_INIT_PAYLOAD, sizeof payload);

    /* A host that opens a transaction and vanishes must not hold the
     * device forever -- one frame would wedge it for every other host. */
    host_clock_us += HOST_MSG_TIMEOUT_US + 1;
    reset_capture();
    ctaphid_poll_timeout(capture);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "a stalled transaction did not time out");
    CHECK(sent_n == 1 && resp_err(0) == CTAPHID_ERR_MSG_TIMEOUT,
          "the timeout answered %#04x, want MSG_TIMEOUT",
          sent_n ? resp_err(0) : 0);
    CHECK(sent_n == 1 && resp_cid(0) == a,
          "the timeout error went to the wrong channel");

    /* And the channel is free again. */
    reset_capture();
    uint8_t ping[4] = { 4, 3, 2, 1 };
    feed_message(b, CTAPHID_CMD_PING, ping, 4);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_PING,
          "the device stayed busy after the timeout freed the channel");
}

static void t_init_abandons_partial(void)
{
    printf("--- INIT during a partial message ---\n");
    fresh();
    uint32_t cid = open_channel();

    static uint8_t payload[200];
    memset(payload, 0x77, sizeof payload);
    feed_init(cid, CTAPHID_CMD_PING, payload, CTAPHID_INIT_PAYLOAD, sizeof payload);

    /* CTAP sec. 11.2.5.3: INIT on a channel with a transaction in flight
     * abandons it. That is how a host resynchronises after losing
     * frames, so it must work without a timeout first. */
    uint8_t nonce[8] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_INIT, nonce, 8);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_INIT,
          "INIT mid-transaction was not answered");
    CHECK(sent_n == 1 && memcmp(sent[0] + 7, nonce, 8) == 0,
          "the resynchronising INIT echoed the wrong nonce");

    /* The abandoned message must not be resumable. With nothing in
     * flight the continuation is spurious, so it is ignored (sec. 11.2.5.4)
     * rather than answered -- what matters is that it does not resume
     * or complete anything. */
    reset_capture();
    feed_cont(cid, 0, payload, CTAPHID_CONT_PAYLOAD);
    CHECK(sent_n == 0, "a continuation of an abandoned message drew %zu frames",
          sent_n);
}

/* ---- vendor commands --------------------------------------------- */

static void t_rng_status(void)
{
    printf("--- vendor RNG status (0x52) ---\n");
    fresh();
    uint32_t cid = open_channel();
    uint8_t pl[64];

    reset_capture();
    feed_init(cid, CTAPHID_CMD_RNG_STATUS, NULL, 0, 0);
    CHECK(sent_n >= 1 && resp_cmd(0) == CTAPHID_CMD_RNG_STATUS,
          "an RNG status request was refused");
    CHECK(sent_n >= 1 && resp_len(0) == CTAPHID_RNG_STATUS_LEN,
          "status length is %zu, want %d",
          sent_n ? resp_len(0) : 0, CTAPHID_RNG_STATUS_LEN);
    size_t got = resp_payload(0, pl, sizeof pl);
    /* The host build has no PQF_QRNG, so the source byte must say the
     * support is not built in -- not claim a TRNG it never probed for --
     * and every counter must be zero. */
    CHECK(got == CTAPHID_RNG_STATUS_LEN && pl[0] == CTAPHID_RNG_SRC_NO_QRNG,
          "source byte is %u, want %d (no QRNG support in this build)",
          got ? pl[0] : 0xffu, CTAPHID_RNG_SRC_NO_QRNG);
    int zeros = (got == CTAPHID_RNG_STATUS_LEN);
    for (size_t i = 1; i < got; i++)
        if (pl[i] != 0) zeros = 0;
    CHECK(zeros, "counters must be zero without a QRNG");

    /* No arguments are defined; a payload is a length error, not ignored. */
    uint8_t junk[1] = { 0 };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_RNG_STATUS, junk, 1);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR
          && resp_err(0) == CTAPHID_ERR_INVALID_LEN,
          "a status request with a payload was served");
}

static void t_rng(void)
{
    printf("--- vendor RNG (0x50) ---\n");
    fresh();
    uint32_t cid = open_channel();

    /* No arguments: one INIT frame's worth. */
    reset_capture();
    feed_init(cid, CTAPHID_CMD_RNG, NULL, 0, 0);
    CHECK(sent_n >= 1 && resp_cmd(0) == CTAPHID_CMD_RNG,
          "an empty RNG request was refused");
    CHECK(sent_n >= 1 && resp_len(0) == CTAPHID_RNG_DEFAULT,
          "the default RNG length is %zu, want %d",
          sent_n ? resp_len(0) : 0, CTAPHID_RNG_DEFAULT);

    /* An explicit count, and the boundaries of it. The count is
     * host-controlled and unauthenticated, so the ceiling is the only
     * thing bounding one request's work. */
    uint8_t want[2] = { 0x00, 0x20 };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_RNG, want, 2);
    CHECK(sent_n >= 1 && resp_len(0) == 0x20, "a 32-byte RNG request gave %zu",
          sent_n ? resp_len(0) : 0);

    uint8_t max[2] = { (uint8_t)(CTAPHID_RNG_MAX >> 8), (uint8_t)CTAPHID_RNG_MAX };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_RNG, max, 2);
    CHECK(sent_n >= 1 && resp_cmd(0) == CTAPHID_CMD_RNG
          && resp_len(0) == CTAPHID_RNG_MAX,
          "the advertised RNG maximum (%d) was not honoured", CTAPHID_RNG_MAX);

    uint8_t over[2] = { (uint8_t)((CTAPHID_RNG_MAX + 1) >> 8),
                        (uint8_t)(CTAPHID_RNG_MAX + 1) };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_RNG, over, 2);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "a request past the RNG maximum was served");

    uint8_t zero[2] = { 0, 0 };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_RNG, zero, 2);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "a zero-byte RNG request was served");

    /* A malformed count -- one byte, or three -- is a length error. */
    uint8_t one[1] = { 4 };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_RNG, one, 1);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "a one-byte RNG count was accepted");

    /* Two calls must not return the same bytes. This is the stub RNG on
     * the host, so it says nothing about the TRNG -- only that the
     * command is not returning a fixed buffer. */
    static uint8_t a[64], b[64];
    reset_capture();
    feed_message(cid, CTAPHID_CMD_RNG, want, 2);
    resp_payload(0, a, 0x20);
    reset_capture();
    feed_message(cid, CTAPHID_CMD_RNG, want, 2);
    resp_payload(0, b, 0x20);
    CHECK(memcmp(a, b, 0x20) != 0, "two RNG reads returned identical bytes");
}

/* The request shape and the fused-off refusal only. Whether a request
 * that passes them waits for a touch first is a per-board policy
 * (board.h, PQF_REBOOT_NEEDS_UP), and this suite is built with no board
 * macro -- buttonless as far as board.h is concerned -- so the gate is
 * compiled out here and every legal request reboots at once. The gate
 * itself, and the sealed USB-C token that must never have one, are
 * pinned by test_reboot_policy.c, built once per board (Makefile). */
static void t_reboot(void)
{
    printf("--- vendor REBOOT (0x51) ---\n");
    fresh();
    uint32_t cid = open_channel();

    /* The mode byte is the whole request. An empty or over-long payload
     * is a length error; an unknown mode is a parameter error. Getting
     * this wrong knocks the token offline on a malformed frame. */
    reset_capture();
    feed_init(cid, CTAPHID_CMD_REBOOT, NULL, 0, 0);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "an empty REBOOT payload was accepted");
    CHECK(reboot_calls == 0, "an empty REBOOT payload rebooted the device");

    uint8_t two[2] = { CTAPHID_REBOOT_WARM, 0 };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_REBOOT, two, 2);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
          "a two-byte REBOOT payload was accepted");
    CHECK(reboot_calls == 0, "a two-byte REBOOT payload rebooted the device");

    const uint8_t bad_modes[] = { 0x02, 0x7f, 0xff };
    for (size_t i = 0; i < sizeof bad_modes; i++) {
        uint8_t m[1] = { bad_modes[i] };
        reset_capture();
        feed_message(cid, CTAPHID_CMD_REBOOT, m, 1);
        CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR,
              "REBOOT mode %#04x was accepted", bad_modes[i]);
        CHECK(reboot_calls == 0, "REBOOT mode %#04x rebooted the device",
              bad_modes[i]);
    }

    /* The two legal modes reach the board layer, with the mode intact --
     * confusing them would send a user asking for a warm reboot into
     * the bootloader instead. */
    uint8_t warm[1] = { CTAPHID_REBOOT_WARM };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_REBOOT, warm, 1);
    CHECK(reboot_calls == 1, "a warm REBOOT did not reach the board layer");
    CHECK(reboot_mode == PQF_REBOOT_WARM, "a warm REBOOT asked for mode %d",
          (int)reboot_mode);

    reboot_calls = 0;
    uint8_t boot[1] = { CTAPHID_REBOOT_BOOTSEL };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_REBOOT, boot, 1);
    CHECK(reboot_calls == 1, "a BOOTSEL REBOOT did not reach the board layer");
    CHECK(reboot_mode == PQF_REBOOT_BOOTSEL,
          "a BOOTSEL REBOOT asked for mode %d", (int)reboot_mode);

    /* With the BOOTSEL fuses blown, the request must be REFUSED with an
     * error the host can see -- not accepted and turned into a warm
     * reboot, which takes the token off the bus with no explanation.
     * pqf_board_bootsel_available() existed for this and nothing in
     * this port called it; board.h and SECUREBOOT.md both said it was
     * obeyed. The Rust port has always called its equivalent. */
    bootsel_available = false;
    reboot_calls = 0;
    reset_capture();
    feed_message(cid, CTAPHID_CMD_REBOOT, boot, 1);
    CHECK(reboot_calls == 0,
          "BOOTSEL fused off: the reboot happened anyway");
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_ERROR
          && resp_err(0) == CTAPHID_ERR_INVALID_PAR,
          "BOOTSEL fused off: the host got no error frame");

    /* A warm reboot is unaffected -- the fuses say nothing about it. */
    reboot_calls = 0;
    reset_capture();
    feed_message(cid, CTAPHID_CMD_REBOOT, warm, 1);
    CHECK(reboot_calls == 1,
          "BOOTSEL fused off also blocked an unrelated warm reboot");
    bootsel_available = true;
}

/* ---- INIT on an allocated channel keeps that channel ------------ */

static void t_init_resync_keeps_cid(void)
{
    printf("--- INIT on an allocated CID ---\n");
    fresh();
    uint32_t cid = open_channel();
    uint8_t nonce[8] = { 9,8,7,6,5,4,3,2 };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_INIT, nonce, 8);
    CHECK(sent_n == 1 && resp_cmd(0) == CTAPHID_CMD_INIT, "INIT on an allocated CID is answered");
    uint8_t body[17]; size_t n = resp_payload(0, body, sizeof body);
    uint32_t back = ((uint32_t)body[8] << 24) | ((uint32_t)body[9] << 16)
                  | ((uint32_t)body[10] << 8) | body[11];
    CHECK(n == 17 && memcmp(body, nonce, 8) == 0, "INIT echoes the nonce");
    CHECK(back == cid, "INIT on an allocated CID answers with THAT CID, not a fresh one");
    CHECK(resp_cid(0) == cid, "...on that channel");
}

/* ---- CBOR routing ------------------------------------------------ */

static void t_cbor_routes(void)
{
    printf("--- CBOR routing ---\n");
    fresh();
    uint32_t cid = open_channel();

    /* getInfo, through the transport. The transport's job is to hand
     * the bytes to ctap2_dispatch and frame whatever comes back; this
     * checks the seam between the two, which nothing else does without
     * a board. */
    uint8_t get_info[1] = { 0x04 };
    reset_capture();
    feed_message(cid, CTAPHID_CMD_CBOR, get_info, 1);
    CHECK(sent_n >= 1 && resp_cmd(0) == CTAPHID_CMD_CBOR,
          "a CBOR command answered cmd %#04x", sent_n ? resp_cmd(0) : 0);
    CHECK(sent_n >= 1 && resp_len(0) > 1,
          "getInfo came back %zu bytes -- a status byte and nothing else",
          sent_n ? resp_len(0) : 0);
    CHECK(sent_n >= 1 && sent[0][7] == 0x00,
          "getInfo answered status %#04x through the transport",
          sent_n ? sent[0][7] : 0xff);

    /* An empty CBOR message still has to be answered, not dropped. */
    reset_capture();
    feed_init(cid, CTAPHID_CMD_CBOR, NULL, 0, 0);
    CHECK(sent_n >= 1, "an empty CBOR message produced no answer");
    CHECK(sent_n >= 1 && resp_cmd(0) == CTAPHID_CMD_CBOR
          && sent[0][7] != 0x00,
          "an empty CBOR message was answered OK");
}

int main(void)
{
    printf("CTAP-HID transport host test\n");
    t_init();
    t_distinct_channels();
    t_channel_zero();
    t_ping();
    t_wink();
    t_unknown_command();
    t_cancel();
    t_out_of_order();
    t_busy();
    t_length_bounds();
    t_timeout();
    t_init_abandons_partial();
    t_rng();
    t_rng_status();
    t_reboot();
    t_init_resync_keeps_cid();
    t_cbor_routes();
    printf("%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
