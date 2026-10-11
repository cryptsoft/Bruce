/* ctaphid.h -- CTAP-HID transport, device side.
 *
 * Implements the framing protocol described in FIDO CTAP sec. 8.1:
 * parse incoming OUT reports, reassemble multi-frame transactions,
 * and dispatch INIT / PING / CBOR / WINK / CANCEL. Commands the
 * firmware does not implement return ERR_INVALID_CMD.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CTAPHID_H
#define PQF_CTAPHID_H

#include <stdint.h>
#include <stddef.h>

/* ---- Wire constants (CTAP sec. 8.1.4) ------------------------------ */

#define CTAPHID_FRAME_SIZE          64
#define CTAPHID_INIT_PAYLOAD        57
#define CTAPHID_CONT_PAYLOAD        59
#define CTAPHID_BROADCAST_CID       0xffffffffu
#define CTAPHID_INIT_BIT            0x80

/* Command identifiers without the INIT bit. The init-bit OR with
 * 0x80 is applied at frame-build time. */
#define CTAPHID_CMD_PING            0x01
#define CTAPHID_CMD_MSG             0x03
#define CTAPHID_CMD_LOCK            0x04
#define CTAPHID_CMD_INIT            0x06
#define CTAPHID_CMD_WINK            0x08
#define CTAPHID_CMD_CBOR            0x10
#define CTAPHID_CMD_CANCEL          0x11
#define CTAPHID_CMD_KEEPALIVE       0x3b
#define CTAPHID_CMD_ERROR           0x3f

/* Vendor command (CTAP sec. 11.2.9.2 reserves 0x40..0x7f for vendor use):
 * return raw TRNG output. Request payload is empty (57 bytes back -- one
 * INIT frame's worth) or a 2-byte big-endian count of 1..CTAPHID_RNG_MAX.
 * Response payload is exactly that many random bytes. No authentication
 * and no user-presence gesture -- the entropy is not a secret, the host
 * mixes it into its own pool (PKCS#11 C_GenerateRandom, `openssl rand`). */
#define CTAPHID_CMD_RNG             0x50
#define CTAPHID_RNG_MAX             1024
#define CTAPHID_RNG_DEFAULT         57

/* Vendor command (same range): which entropy source CMD_RNG and every
 * key draw are being served from, with the picker's counters -- the
 * answer a host cannot get from the bytes themselves (QRNG and TRNG
 * output are indistinguishable) and should not have to infer from a
 * stopwatch. Request payload is empty (anything else is
 * ERR_INVALID_LEN). Response payload, CTAPHID_RNG_STATUS_LEN bytes:
 *   [0]      source: CTAPHID_RNG_SRC_*
 *   [1..5)   qrng_bytes      u32 big-endian, bytes served by the QRNG
 *   [5..9)   fallback_bytes  bytes served by the on-die TRNG
 *   [9..13)  packets         QRNG packets read
 *   [13..17) header_err      packets dropped: bad header
 *   [17..21) health_err      packets dropped: health flag
 *   [21..25) bus_err         I2C transactions that failed or timed out
 *   [25..29) short_requests  requests the QRNG could not complete
 * Counters are zero when the source is TRNG or NO_QRNG. */
#define CTAPHID_CMD_RNG_STATUS      0x52
#define CTAPHID_RNG_STATUS_LEN      29
#define CTAPHID_RNG_SRC_TRNG        0x00 /* no QRNG answered at boot        */
#define CTAPHID_RNG_SRC_QRNG        0x01 /* external QRNG live, first in queue */
#define CTAPHID_RNG_SRC_QRNG_LOST   0x02 /* found at boot, since written off */
#define CTAPHID_RNG_SRC_NO_QRNG     0x03 /* firmware built without PQF_QRNG  */

/* Vendor command (CTAP sec. 11.2.9.2 vendor range): reboot the token.
 * Request payload is exactly one mode byte:
 *   CTAPHID_REBOOT_WARM    (0x00) -- warm reboot back into the firmware
 *                                   (re-enumerates without reflashing);
 *   CTAPHID_REBOOT_BOOTSEL (0x01) -- reboot into the RP2350 USB
 *                                   mass-storage / DFU bootloader.
 * Empty or non-1-byte payloads are ERR_INVALID_LEN; any other mode
 * byte is ERR_INVALID_PAR. On boards with a button and a power-on
 * BOOTSEL path BOTH modes are gated behind a test of user presence
 * (the same touch gesture as MakeCredential) so a host cannot knock
 * the token offline without the user's physical confirmation; whether
 * a given build gates is board.h's PQF_REBOOT_NEEDS_UP -- buttonless
 * boards, -DPQF_REBOOT_NO_UP builds and the sealed USB-C token (whose
 * only way into the bootloader is this command) act at once. The
 * device vanishes and re-enumerates on success, so no response frame
 * is emitted (a declined/timed-out presence gate answers ERR_OTHER).
 * This is the shipping-safe successor to the never-ship CDC
 * <STX>BOOTSEL<ETX> reflash hook. */
#define CTAPHID_CMD_REBOOT          0x51
#define CTAPHID_REBOOT_WARM         0x00
#define CTAPHID_REBOOT_BOOTSEL      0x01
#define CTAPHID_REBOOT_UP_TIMEOUT_US (10u * 1000u * 1000u)

/* KEEPALIVE status bytes (CTAP sec. 8.1.9.1.5). PROCESSING = a long op
 * (e.g. a hybrid sign) is running; UPNEEDED = waiting on the user to
 * confirm presence, which is what makes the browser show "touch your
 * key". */
#define CTAPHID_STATUS_PROCESSING   0x01
#define CTAPHID_STATUS_UPNEEDED     0x02

/* Capability flags advertised in INIT response. */
#define CTAPHID_CAP_WINK            0x01
#define CTAPHID_CAP_CBOR            0x04
#define CTAPHID_CAP_NMSG            0x08

/* Error codes carried in CTAPHID_CMD_ERROR responses (CTAP sec. 8.1.9.1.6). */
#define CTAPHID_ERR_INVALID_CMD     0x01
#define CTAPHID_ERR_INVALID_PAR     0x02
#define CTAPHID_ERR_INVALID_LEN     0x03
#define CTAPHID_ERR_INVALID_SEQ     0x04
#define CTAPHID_ERR_MSG_TIMEOUT     0x05
#define CTAPHID_ERR_CHANNEL_BUSY    0x06
#define CTAPHID_ERR_LOCK_REQUIRED   0x0a
#define CTAPHID_ERR_INVALID_CHAN    0x0b
#define CTAPHID_ERR_OTHER           0x7f

/* ---- API ------------------------------------------------------- */

/* Maximum CTAP message size we accept on the wire -- also the
 * maxMsgSize reported in authenticatorGetInfo (CTAP sec. 6.4). Both
 * inbound and outbound buffers honour this; outbound responses (esp.
 * hybrid PQC attestation, which embeds a multi-KB ML-DSA public key)
 * can approach the cap. */
#define CTAPHID_MAX_MSG_BYTES       7609

/* Reset internal CID allocator + transaction state. Call once at
 * boot, before tud_task() starts pumping reports. */
void ctaphid_init(void);

/* Emit a KEEPALIVE(PROCESSING) frame on the in-flight CBOR channel.
 * Called from the long-op tick during a core-1 hybrid PQC signature
 * so the host's WebAuthn watchdog doesn't fire. No-op when idle. */
void ctaphid_keepalive_pump(void);

/* Emit a KEEPALIVE(status) frame on the in-flight CBOR channel -- the
 * general form of ctaphid_keepalive_pump(). Used by the WaitForUp gate
 * to send UPNEEDED while soliciting a button press. No-op when idle. */
void ctaphid_send_keepalive(uint8_t status);

/* Send-frame callback the dispatcher uses to push one 64-byte HID
 * report up to the USB transport. Implemented in fido_hid.c. */
typedef void (*ctaphid_send_fn)(const uint8_t *frame);

/* Board hook fired when the host sends CTAPHID_CMD_WINK ("blink me" --
 * the RP wants the user to identify this device among several). The
 * firmware registers an LED flash at boot; unregistered (host tests)
 * means WINK just ACKs. */
typedef void (*ctaphid_wink_fn)(void);
void ctaphid_set_wink(ctaphid_wink_fn cb);

/* Hand the dispatcher one inbound 64-byte OUT report from USB.
 *
 * Multi-frame transactions accumulate state across calls -- only a
 * single CID can have a transaction in flight at any time, per
 * CTAP sec. 8.1.5.3. A second init frame on a different CID while one
 * is in flight is rejected with ERR_CHANNEL_BUSY.
 *
 * Back-pressure / rx ring: this transport has no separate inbound
 * frame queue -- TinyUSB delivers one OUT report at a time straight
 * into ctaphid_recv_frame (fido_hid.c), and only one transaction
 * reassembles at a time. A frame for a *different* channel while a
 * reassembly is in flight is dropped with ERR_CHANNEL_BUSY rather than
 * buffered, so there is no ring to overflow (the equivalent of the
 * spec's bounded-rx handling falls out of the synchronous one-report
 * delivery model). */
void ctaphid_recv_frame(const uint8_t *frame, ctaphid_send_fn send);

/* Sweep an in-progress multi-frame reassembly for a stalled host and,
 * after ~500 ms of inactivity, abort it with ERR_MSG_TIMEOUT (0x05) so
 * the single reassembly slot can't be wedged forever (CTAP HID
 * sec. 11.2.5.2). ctaphid_recv_frame already sweeps on every inbound frame;
 * call this from the main loop / SOF as well to cover a host that
 * announces a multi-frame BCNT and then sends nothing more. No-op when
 * nothing is mid-assembly. */
void ctaphid_poll_timeout(ctaphid_send_fn send);

#endif /* PQF_CTAPHID_H */
