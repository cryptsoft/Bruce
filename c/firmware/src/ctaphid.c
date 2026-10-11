/* ctaphid.c -- CTAP-HID dispatcher, device side.
 *
 * Frame-level state machine for the CTAPHID transport (FIDO CTAP
 * sec. 8.1). Handles INIT, PING (echo), CBOR (CTAP2 command + response,
 * possibly multi-frame), and synthesises ERR_INVALID_CMD for
 * commands later phases haven't reached.
 *
 * State invariant: at most one transaction in flight at a time,
 * identified by `s_active_cid`. A second init frame on a *different*
 * CID arriving mid-transaction gets ERR_CHANNEL_BUSY per CTAP
 * sec. 8.1.5.3; a second init frame on the *same* CID atomically
 * restarts the transaction.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <string.h>

#ifndef PQF_CTAPHID_HOST
#include "pico/time.h"          /* time_us_64() -- reassembly timeout clock */
#endif

#include "openssl/rand.h"        /* RAND_bytes -- pqf_rand.c (TRNG) on
                                  * firmware, host_rand_stub.c in tests */

#include "ctaphid.h"
#if defined(PQF_QRNG)
#include "pqf_rand.h"            /* CMD_RNG_STATUS: which source is serving */
#include "pqf_qrng.h"
#endif
#include "ctap2.h"
#include "credential_management.h"
#include "board.h"               /* pqf_board_reboot (CMD_REBOOT) */

/* Monotonic microsecond clock for the reassembly timeout. The firmware
 * uses the RP2350 timer (time_us_64); a host build defines
 * PQF_CTAPHID_HOST and supplies its own, which is what makes the
 * reassembly timeout testable -- a clock frozen at zero could never
 * reach it. */
#ifndef PQF_CTAPHID_HOST
static uint64_t now_us(void) { return time_us_64(); }
#else
uint64_t pqf_ctaphid_host_now_us(void);
static uint64_t now_us(void) { return pqf_ctaphid_host_now_us(); }
#endif

/* Inactivity window for an in-progress multi-frame reassembly, in
 * microseconds. CTAP HID sec. 11.2.5.2 specifies a transaction timeout on
 * the order of 500 ms; once `now - last_frame_us` exceeds this we abort
 * the partial message with ERR_MSG_TIMEOUT (0x05) and free the single
 * reassembly slot a stalled host would otherwise wedge forever. */
#define CTAPHID_MSG_TIMEOUT_US   500000ull

/* CTAP 2.1 protocol version reported in INIT response. */
#define CTAPHID_PROTOCOL_VERSION    2

/* Device version triple in the INIT response (wire-format only --
 * the project semver lives in CMakeLists.txt). */
#define CTAPHID_DEVICE_MAJOR        0
#define CTAPHID_DEVICE_MINOR        1
#define CTAPHID_DEVICE_BUILD        0

/* Capabilities advertised in INIT -- matches the Rust base byte
 * (0x01 | 0x04 | 0x08):
 *   WINK  : cosmetic "blink me" supported (LED hook below).
 *   CBOR  : speaks CTAP2.
 *   NMSG  : does NOT speak CTAP1/U2F MSG -- deliberate, so browsers use
 *           CTAP2 and attestation stays fmt="packed" (a PQC-aware
 *           RP may reject fmt="fido-u2f"). */
#define CTAPHID_CAPS \
    (CTAPHID_CAP_WINK | CTAPHID_CAP_CBOR | CTAPHID_CAP_NMSG)

/* Board hook fired on CTAPHID_CMD_WINK (LED flash). NULL -> no-op
 * (host tests never register one). */
static ctaphid_wink_fn s_wink_cb;

/* Monotonic CID allocator. CID 0 is reserved, broadcast (0xffffffff)
 * is reserved -- we skip both. */
static uint32_t s_next_cid;

/* In-flight transaction state. `s_active_cid` is the CID we are
 * currently buffering frames for; 0 means no transaction. */
static uint32_t s_active_cid;
static uint8_t  s_active_cmd;
static uint16_t s_active_total;       /* expected payload bytes      */
static uint16_t s_active_have;        /* payload bytes received      */
static uint8_t  s_active_seq;         /* next expected cont seq      */
static uint64_t s_active_last_us;     /* timestamp of the last frame */
static uint8_t  s_active_buf[CTAPHID_MAX_MSG_BYTES];

static void reset_active(void)
{
    s_active_cid     = 0;
    s_active_cmd     = 0;
    s_active_total   = 0;
    s_active_have    = 0;
    s_active_seq     = 0;
    s_active_last_us = 0;
}

/* KEEPALIVE pump state: the channel + send fn for the CBOR command
 * currently being processed, so a long op can emit KEEPALIVE frames
 * on it. Set/cleared around the ctap2_dispatch call. */
static uint32_t        s_keepalive_cid;
static ctaphid_send_fn s_keepalive_send;

/* Re-entrancy guard for dispatch_complete. send_response() and the
 * long-op KEEPALIVE tick both spin tud_task(), which can deliver a
 * fresh completed OUT report and re-enter ctaphid_recv_frame ->
 * dispatch_complete. A nested dispatch would clobber the shared static
 * scratch/resp buffers and reset s_keepalive_* out from under the
 * outer command that is still mid-send. We forbid it: while a dispatch
 * is in flight, a second transaction that completes is answered
 * ERR_CHANNEL_BUSY (CTAP sec. 8.1.5.3) and dropped, leaving the outer
 * response intact. */
static bool s_dispatching;

/* Forward decl -- defined in the frame-builders section below. */
static void build_init_frame(uint8_t *out, uint32_t cid, uint8_t cmd,
                             uint16_t total_payload,
                             const uint8_t *chunk, size_t chunk_len);

void ctaphid_init(void)
{
    s_next_cid = 1;
    reset_active();
    s_keepalive_cid  = 0;
    s_keepalive_send = NULL;
    s_dispatching    = false;
}

/* Emit one KEEPALIVE(status) frame on the in-flight CBOR channel
 * (CTAP sec. 8.1.9.1.5). No-op if no CBOR command is in flight. */
void ctaphid_send_keepalive(uint8_t status)
{
    if (s_keepalive_cid == 0 || s_keepalive_send == NULL)
        return;
    uint8_t frame[CTAPHID_FRAME_SIZE];
    build_init_frame(frame, s_keepalive_cid, CTAPHID_CMD_KEEPALIVE,
                     1, &status, 1);
    s_keepalive_send(frame);
}

/* PROCESSING KEEPALIVE -- called from the long-op tick while a hybrid
 * PQC signature is being computed on core 1. */
void ctaphid_keepalive_pump(void)
{
    ctaphid_send_keepalive(CTAPHID_STATUS_PROCESSING);
}

/* ---- Big-endian CID helpers ----------------------------------- */

#if defined(PQF_QRNG)
static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}
#endif

/* CMD_RNG_STATUS payload (layout in ctaphid.h). Without PQF_QRNG there
 * is nothing to count and no picker to ask: the source byte says the
 * support is not built in, which is a different answer from "probed and
 * found nothing". */
static void rng_status_payload(uint8_t out[CTAPHID_RNG_STATUS_LEN])
{
    memset(out, 0, CTAPHID_RNG_STATUS_LEN);
#if defined(PQF_QRNG)
    const struct pqf_rand_stats *rs = pqf_rand_stats();
    const struct pqf_qrng_stats *qs = pqf_qrng_stats();
    switch (pqf_qrng_state()) {
    case PQF_QRNG_LIVE: out[0] = CTAPHID_RNG_SRC_QRNG;      break;
    case PQF_QRNG_LOST: out[0] = CTAPHID_RNG_SRC_QRNG_LOST; break;
    default:            out[0] = CTAPHID_RNG_SRC_TRNG;      break;
    }
    put_be32(out + 1,  rs->qrng_bytes);
    put_be32(out + 5,  rs->fallback_bytes);
    put_be32(out + 9,  qs->packets);
    put_be32(out + 13, qs->header_err);
    put_be32(out + 17, qs->health_err);
    put_be32(out + 21, qs->bus_err);
    put_be32(out + 25, qs->short_requests);
#else
    out[0] = CTAPHID_RNG_SRC_NO_QRNG;
#endif
}

static uint32_t unpack_cid(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8)
         |  (uint32_t)p[3];
}

static void pack_cid(uint8_t *p, uint32_t cid)
{
    p[0] = (uint8_t)(cid >> 24);
    p[1] = (uint8_t)(cid >> 16);
    p[2] = (uint8_t)(cid >>  8);
    p[3] = (uint8_t)(cid);
}

/* ---- Outbound: build one HID frame ---------------------------- */

static void build_init_frame(uint8_t *out, uint32_t cid, uint8_t cmd,
                              uint16_t total_payload,
                              const uint8_t *chunk, size_t chunk_len)
{
    memset(out, 0, CTAPHID_FRAME_SIZE);
    pack_cid(out, cid);
    out[4] = CTAPHID_INIT_BIT | cmd;
    out[5] = (uint8_t)(total_payload >> 8);
    out[6] = (uint8_t)(total_payload & 0xff);
    if (chunk_len > 0) {
        memcpy(&out[7], chunk, chunk_len);
    }
}

static void build_cont_frame(uint8_t *out, uint32_t cid, uint8_t seq,
                              const uint8_t *chunk, size_t chunk_len)
{
    memset(out, 0, CTAPHID_FRAME_SIZE);
    pack_cid(out, cid);
    out[4] = (uint8_t)(seq & 0x7f);
    if (chunk_len > 0) {
        memcpy(&out[5], chunk, chunk_len);
    }
}

/* Send a complete CTAPHID message (multi-frame if needed). */
static void send_response(ctaphid_send_fn send, uint32_t cid, uint8_t cmd,
                           const uint8_t *payload, size_t len)
{
    uint8_t frame[CTAPHID_FRAME_SIZE];
    size_t  off;
    size_t  chunk;

    /* The init frame's BCNT field is 16 bits -- refuse to ship
     * anything larger. The dispatcher should never produce a body
     * bigger than CTAPHID_MAX_MSG_BYTES (7609), well under 64 KiB. */
    if (len > 0xffff) return;

    chunk = (len < CTAPHID_INIT_PAYLOAD) ? len : CTAPHID_INIT_PAYLOAD;
    build_init_frame(frame, cid, cmd, (uint16_t)len, payload, chunk);
    send(frame);

    off = chunk;
    uint8_t seq = 0;
    while (off < len) {
        chunk = len - off;
        if (chunk > CTAPHID_CONT_PAYLOAD) chunk = CTAPHID_CONT_PAYLOAD;
        build_cont_frame(frame, cid, seq, &payload[off], chunk);
        send(frame);
        off += chunk;
        seq++;
    }
}

static void send_error(ctaphid_send_fn send, uint32_t cid,
                       uint8_t err_code)
{
    uint8_t err[1] = { err_code };
    send_response(send, cid, CTAPHID_CMD_ERROR, err, 1);
}

/* ---- Reassembly inactivity timeout (CTAP HID sec. 11.2.5.2) -------- */

/* Abort a stalled multi-frame reassembly. If a transaction is mid-
 * assembly (some but not all payload bytes received) and no frame has
 * advanced it within CTAPHID_MSG_TIMEOUT_US, drop the partial message
 * and answer ERR_MSG_TIMEOUT on the owning channel -- freeing the single
 * reassembly slot a silent host would otherwise wedge forever, after
 * which any other channel would get ERR_CHANNEL_BUSY until reboot.
 * Returns true if it timed out (and sent the error). A single-frame
 * transaction never sits half-assembled, so this only fires on a
 * genuinely stalled multi-frame host. */
static bool sweep_timeout(ctaphid_send_fn send)
{
    if (s_active_cid == 0 || s_active_have >= s_active_total)
        return false;
    if (now_us() - s_active_last_us < CTAPHID_MSG_TIMEOUT_US)
        return false;
    uint32_t cid = s_active_cid;
    reset_active();
    send_error(send, cid, CTAPHID_ERR_MSG_TIMEOUT);
    return true;
}

/* Public sweep, callable from the main loop / SOF when no frame is
 * arriving, so a host that announces a multi-frame BCNT and then goes
 * silent is timed out even with no further inbound traffic. Safe to
 * call at any cadence; a no-op when nothing is mid-assembly. (Wiring
 * this into the main loop is recommended; the on-frame sweep in
 * ctaphid_recv_frame already covers the case where other traffic
 * continues.) */
void ctaphid_poll_timeout(ctaphid_send_fn send)
{
    if (send == NULL) return;
    (void)sweep_timeout(send);
}

/* ---- INIT response -------------------------------------------- */

static uint32_t alloc_cid(void)
{
    uint32_t c = s_next_cid++;
    if (c == 0 || c == CTAPHID_BROADCAST_CID) {
        /* Theoretical wrap after 2^32 transactions -- reroll. */
        c = s_next_cid++;
    }
    return c;
}

static void handle_init(ctaphid_send_fn send, uint32_t reply_cid,
                         const uint8_t *nonce)
{
    uint8_t  body[17];
    /* sec. 11.2.9.1.3: on the broadcast CID, INIT allocates a channel; on an
     * allocated CID it resynchronises THAT channel and the response
     * carries the same CID. This handed back a fresh CID in both cases,
     * so a host recovering a wedged channel was silently moved to a new
     * one -- and the channel it was recovering stayed allocated. */
    uint32_t allocated = (reply_cid == CTAPHID_BROADCAST_CID) ? alloc_cid() : reply_cid;

    memcpy(&body[0], nonce, 8);
    pack_cid(&body[8], allocated);
    body[12] = CTAPHID_PROTOCOL_VERSION;
    body[13] = CTAPHID_DEVICE_MAJOR;
    body[14] = CTAPHID_DEVICE_MINOR;
    body[15] = CTAPHID_DEVICE_BUILD;
    body[16] = CTAPHID_CAPS;

    send_response(send, reply_cid, CTAPHID_CMD_INIT, body, sizeof body);

    /* Drop any pending transaction on the reply CID -- INIT is the
     * spec's explicit "reset this channel" signal. */
    if (s_active_cid == reply_cid) {
        reset_active();
    }
}

/* ---- Dispatch a completed transaction ------------------------- */

static void dispatch_complete(ctaphid_send_fn send)
{
    uint32_t cid = s_active_cid;
    uint8_t  cmd = s_active_cmd;
    uint16_t len = s_active_have;

    /* Re-entrancy guard (CTAP sec. 8.1.5.3): if a transaction completed
     * while an outer dispatch is still emitting its response (a nested
     * tud_task() pumped a new report through), do NOT touch the shared
     * scratch/resp/keepalive state -- answer ERR_CHANNEL_BUSY and drop
     * this transaction so the outer response stays intact. */
    if (s_dispatching) {
        reset_active();
        send_error(send, cid, CTAPHID_ERR_CHANNEL_BUSY);
        return;
    }
    s_dispatching = true;

    /* Snapshot, then reset BEFORE dispatching so the dispatcher
     * can recurse / start a new transaction freely. */
    static uint8_t scratch[CTAPHID_MAX_MSG_BYTES];
    memcpy(scratch, s_active_buf, len);
    reset_active();

    switch (cmd) {
    case CTAPHID_CMD_PING: {
        /* Echo the payload back verbatim. */
        send_response(send, cid, CTAPHID_CMD_PING, scratch, len);
        break;
    }

    case CTAPHID_CMD_CBOR: {
        static uint8_t resp[CTAP2_MAX_RESPONSE];
        size_t  resp_len = 0;
        /* Bind any CredentialManagement enumeration this command starts
         * to its originating channel (CTAP 2.1 sec. 6.8/sec. 11.2): a later
         * enumerate*GetNext on a different channel is then refused. */
        credential_management_set_cid(cid);
        ctap2_set_cid(cid);
        /* Arm the KEEPALIVE pump: a long op (hybrid PQC sign on core 1)
         * calls ctaphid_keepalive_pump() via the long-op tick, which
         * emits KEEPALIVE(PROCESSING) on this channel so the host
         * doesn't time out. Disarm once the response is built. */
        s_keepalive_cid  = cid;
        s_keepalive_send = send;
        (void)ctap2_dispatch(scratch, len, resp, sizeof resp, &resp_len);
        s_keepalive_cid  = 0;
        s_keepalive_send = NULL;
        send_response(send, cid, CTAPHID_CMD_CBOR, resp, resp_len);
        break;
    }

    case CTAPHID_CMD_RNG: {
        /* Vendor command: hand back raw TRNG output (header comment in
         * ctaphid.h). Payload is empty (default count) or a 2-byte
         * big-endian count; anything else is a length error. */
        static uint8_t rng[CTAPHID_RNG_MAX];
        uint16_t want = CTAPHID_RNG_DEFAULT;
        if (len == 2) {
            want = (uint16_t)((scratch[0] << 8) | scratch[1]);
        } else if (len != 0) {
            send_error(send, cid, CTAPHID_ERR_INVALID_LEN);
            break;
        }
        if (want == 0 || want > CTAPHID_RNG_MAX) {
            send_error(send, cid, CTAPHID_ERR_INVALID_PAR);
            break;
        }
        if (!RAND_bytes(rng, (int)want)) {
            send_error(send, cid, CTAPHID_ERR_OTHER);
            break;
        }
        send_response(send, cid, CTAPHID_CMD_RNG, rng, want);
        break;
    }

    case CTAPHID_CMD_RNG_STATUS: {
        /* Vendor command: which entropy source is serving, and the
         * picker's counters (header comment in ctaphid.h). No payload. */
        if (len != 0) {
            send_error(send, cid, CTAPHID_ERR_INVALID_LEN);
            break;
        }
        uint8_t st[CTAPHID_RNG_STATUS_LEN];
        rng_status_payload(st);
        send_response(send, cid, CTAPHID_CMD_RNG_STATUS, st, sizeof st);
        break;
    }

    case CTAPHID_CMD_REBOOT: {
        /* Vendor command: reboot the token (header comment in
         * ctaphid.h). Exactly one mode byte. Whether the two modes wait
         * for a test of user presence is a per-board policy,
         * PQF_REBOOT_NEEDS_UP in board.h. */
        if (len != 1) {
            send_error(send, cid, CTAPHID_ERR_INVALID_LEN);
            break;
        }
        uint8_t mode = scratch[0];
        if (mode != CTAPHID_REBOOT_WARM && mode != CTAPHID_REBOOT_BOOTSEL) {
            send_error(send, cid, CTAPHID_ERR_INVALID_PAR);
            break;
        }
        /* BOOTSEL fused off: refuse, rather than accept and warm-reboot.
         * pqf_board_bootsel_available() existed, board.h declared it and
         * SECUREBOOT.md said both ports obeyed it -- and nothing in this
         * port ever called it. The host asked for BOOTSEL, got no error,
         * and the token vanished off the bus into a warm reboot instead,
         * which is exactly the confusion the function was written to
         * prevent. The Rust port has called its equivalent all along. */
        if (mode == CTAPHID_REBOOT_BOOTSEL && !pqf_board_bootsel_available()) {
            send_error(send, cid, CTAPHID_ERR_INVALID_PAR);
            break;
        }
#if PQF_REBOOT_NEEDS_UP
        /* Test of user presence, same gesture as MakeCredential. Arm
         * the KEEPALIVE channel first (as the CBOR case does) so the
         * gate can emit UPNEEDED / blink the LED while it waits. A NULL
         * hook (host harness) auto-confirms.
         *
         * Compiled in only where board.h's PQF_REBOOT_NEEDS_UP says so:
         * a board with a button AND a power-on BOOTSEL path, and not
         * built -DPQF_REBOOT_NO_UP=ON (flash-station convenience). The
         * buttonless boards have nothing to press; and the sealed USB-C
         * token (PQF_BOARD_FEITIAN_RP2350_USBC) is ungated BY DESIGN --
         * its power-on BOOTSEL sensing does not work, so this command is
         * its only way back into the bootloader, and a touch it could
         * not deliver would make it unflashable for good. FIDO user
         * presence for MakeCredential / GetAssertion is unaffected
         * either way. */
        bool present = true;
        if (ctap2_user_presence_hook != NULL) {
            s_keepalive_cid  = cid;
            s_keepalive_send = send;
            present = ctap2_user_presence_hook(CTAPHID_REBOOT_UP_TIMEOUT_US);
            s_keepalive_cid  = 0;
            s_keepalive_send = NULL;
        }
        if (!present) {
            send_error(send, cid, CTAPHID_ERR_OTHER);
            break;
        }
#endif
        /* Confirmed. The device is about to disappear and re-enumerate,
         * so no response frame can reliably reach the host first -- the
         * host-side reboot() does not wait for one. pqf_board_reboot
         * does not return. */
        pqf_board_reboot(mode == CTAPHID_REBOOT_BOOTSEL
                         ? PQF_REBOOT_BOOTSEL : PQF_REBOOT_WARM);
        break;  /* not reached */
    }

    case CTAPHID_CMD_WINK: {
        /* "Blink me" -- the RP wants the user to identify this device
         * among several. Fire the board hook (LED flash; no-op when
         * unregistered, e.g. host tests) and echo an empty WINK. */
        if (s_wink_cb != NULL)
            s_wink_cb();
        send_response(send, cid, CTAPHID_CMD_WINK, NULL, 0);
        break;
    }

    case CTAPHID_CMD_CANCEL: {
        /* CTAP HID sec. 11.2.9.1.4: CANCEL aborts the outstanding
         * transaction on this channel and itself produces NO direct
         * reply (the cancelled CBOR command answers
         * CTAP2_ERR_KEEPALIVE_CANCEL). We do NOT echo it.
         *
         * The reassembly slot was already cleared by reset_active()
         * above, so any partial transaction this channel had in flight
         * is dropped. No reply is emitted.
         *
         * Mid-sign CANCEL limitation (honest disclosure): a CBOR
         * command is dispatched synchronously inside this function, and
         * a hybrid PQC signature runs to completion in core1_hybrid_sign
         * (core1_signer.c), which is a blocking poll loop with no
         * cancellation checkpoint -- core 1's hybrid_sign is monolithic
         * and keeps writing into the shared signature buffer until done,
         * so core 0 cannot return early without a use-after-return race.
         * A CANCEL frame that arrives during a sign is delivered by the
         * nested tud_task() in the keepalive pump, re-enters
         * ctaphid_recv_frame, and hits the s_dispatching re-entrancy
         * guard in dispatch_complete -- so it is answered
         * ERR_CHANNEL_BUSY and the sign completes normally rather than
         * being aborted. True mid-sign abort would require a
         * cancellable core-1 signer (cooperative checkpoints + a clean
         * core-0 wait-abort handshake); that is left for the signer
         * rework. The conformant transport pieces (no CANCEL echo,
         * reassembly MSG_TIMEOUT) are implemented here regardless. */
        (void)cid;
        break;
    }

    default:
        send_error(send, cid, CTAPHID_ERR_INVALID_CMD);
        break;
    }

    /* Response fully emitted -- release the guard so the next inbound
     * transaction can be dispatched. */
    s_dispatching = false;
}

void ctaphid_set_wink(ctaphid_wink_fn cb)
{
    s_wink_cb = cb;
}

/* ---- Main entry: one inbound 64-byte report ------------------- */

void ctaphid_recv_frame(const uint8_t *frame, ctaphid_send_fn send)
{
    if (send == NULL) return;

    /* Sweep a stalled prior reassembly first (CTAP HID sec. 11.2.5.2): if
     * the channel that held the single reassembly slot went silent
     * mid-message, time it out and free the slot now -- otherwise a new
     * frame on another channel would wrongly get ERR_CHANNEL_BUSY
     * forever. (The error reply goes to the stalled channel.) */
    (void)sweep_timeout(send);

    uint32_t rx_cid = unpack_cid(frame);
    uint8_t  byte4  = frame[4];

    if (byte4 & CTAPHID_INIT_BIT) {
        /* ---- Init frame ---- */
        uint8_t  cmd  = (uint8_t)(byte4 & 0x7f);
        uint16_t bcnt = (uint16_t)((frame[5] << 8) | frame[6]);

        if (cmd == CTAPHID_CMD_INIT) {
            if (bcnt != 8) {
                send_error(send, rx_cid, CTAPHID_ERR_INVALID_LEN);
                return;
            }
            handle_init(send, rx_cid, &frame[7]);
            return;
        }

        /* CTAP HID sec. 11.2.3: "Channel ID 0 is reserved and 0xffffffff is
         * reserved for broadcast commands, i.e. at the time of channel
         * allocation." Both are shared by every host that has not been
         * allocated a channel yet, so serving anything but INIT on them
         * runs a transaction on a channel with no owner -- two hosts
         * would interleave with no arbitration, and a response would go
         * to whoever else is listening. Refuse with INVALID_CHANNEL so
         * the host runs INIT and gets a channel of its own. */
        if (rx_cid == 0 || rx_cid == CTAPHID_BROADCAST_CID) {
            send_error(send, rx_cid, CTAPHID_ERR_INVALID_CHAN);
            return;
        }

        /* Non-INIT init frame. If something is already in flight on
         * a DIFFERENT CID, refuse with ERR_CHANNEL_BUSY (CTAP
         * sec. 8.1.5.3). On the same CID, restart the transaction. */
        if (s_active_cid != 0 && s_active_cid != rx_cid) {
            send_error(send, rx_cid, CTAPHID_ERR_CHANNEL_BUSY);
            return;
        }

        if (bcnt > CTAPHID_MAX_MSG_BYTES) {
            send_error(send, rx_cid, CTAPHID_ERR_INVALID_LEN);
            return;
        }

        s_active_cid     = rx_cid;
        s_active_cmd     = cmd;
        s_active_total   = bcnt;
        s_active_have    = 0;
        s_active_seq     = 0;
        s_active_last_us = now_us();   /* start the reassembly clock */

        size_t first = (bcnt < CTAPHID_INIT_PAYLOAD)
                         ? bcnt : CTAPHID_INIT_PAYLOAD;
        memcpy(&s_active_buf[0], &frame[7], first);
        s_active_have = (uint16_t)first;

        if (s_active_have >= s_active_total) {
            dispatch_complete(send);
        }
        return;
    }

    /* ---- Continuation frame ---- */
    uint8_t seq = (uint8_t)(byte4 & 0x7f);

    if (s_active_cid == 0 || s_active_cid != rx_cid) {
        /* Stray cont frame outside / wrong-CID transaction. Drop
         * silently -- the spec lets us return ERR_INVALID_CHANNEL
         * but most authenticators stay quiet here. */
        return;
    }

    if (seq != s_active_seq) {
        send_error(send, rx_cid, CTAPHID_ERR_INVALID_SEQ);
        reset_active();
        return;
    }

    size_t remaining = (size_t)(s_active_total - s_active_have);
    size_t take = (remaining < CTAPHID_CONT_PAYLOAD)
                    ? remaining : CTAPHID_CONT_PAYLOAD;
    memcpy(&s_active_buf[s_active_have], &frame[5], take);
    s_active_have += (uint16_t)take;
    s_active_seq++;
    s_active_last_us = now_us();   /* progress: restart the timeout window */

    if (s_active_have >= s_active_total) {
        dispatch_complete(send);
    }
}
