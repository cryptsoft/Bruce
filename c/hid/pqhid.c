/* pqhid.c
 *
 * CTAP-over-USB-HID transport for FIDO authenticators -- the
 * platform-independent core. Written from the FIDO CTAP
 * specification sec. 8.1 ("HID protocol").
 *
 * This file owns everything above the raw 64-byte report boundary:
 * frame packing/parsing, the transaction state machine (init +
 * continuation packets in both directions, KEEPALIVE skipping),
 * the INIT channel handshake, and the public pqhid_* API. The
 * actual report I/O, device enumeration, and CSPRNG access live in
 * exactly one per-OS backend (pqhid_linux.c / pqhid_macos.c /
 * pqhid_windows.c) behind the pqhid_os.h contract.
 *
 * Framing refresher (CTAP sec. 8.1.4):
 *
 *   Every HID report is exactly 64 bytes. The first packet in a
 *   transaction is an "initialization" packet; any subsequent packets
 *   are "continuation" packets.
 *
 *   Initialization packet (64 bytes):
 *     0..3   channel identifier (CID)
 *     4      command identifier; bit 7 set marks an init packet
 *     5      high byte of payload length (BCNTH)
 *     6      low byte of payload length (BCNTL)
 *     7..63  up to 57 bytes of payload (rest padded)
 *
 *   Continuation packet (64 bytes):
 *     0..3   channel identifier (CID)
 *     4      packet sequence (0..127); bit 7 clear
 *     5..63  up to 59 bytes of payload (rest padded)
 *
 * Commands implemented here (CTAP sec. 8.1.9):
 *   0x86  CTAPHID_INIT      negotiate a private channel
 *   0x81  CTAPHID_PING      echo
 *   0x88  CTAPHID_WINK      flash device LED
 *   0x10  CTAPHID_CBOR      CTAP2 command (CBOR-encoded)
 *   0x03  CTAPHID_MSG       CTAP1/U2F APDU
 *
 *   0xbb  CTAPHID_KEEPALIVE incoming, transparently skipped
 *   0xbf  CTAPHID_ERROR     incoming, surfaced as PQFIDO_ERR_PROTO
 *
 * pqhid_rng() (bottom of this file) is the client side of this repo's
 * vendor CTAPHID_CMD_RNG (0x50).
 *
 * Copyright (C) 2010-2026 Cryptsoft Pty Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include "pqhid.h"
#include "pqhid_os.h"

/* ---- Constants -------------------------------------------------- */

#define HID_FRAME_SIZE          PQHID_OS_FRAME_SIZE
#define HID_INIT_PAYLOAD        57
#define HID_CONT_PAYLOAD        59
#define HID_BROADCAST_CID       0xffffffffu
#define HID_DEFAULT_TIMEOUT_MS  5000

/* Largest payload CTAP-HID framing can carry: one init frame plus
 * 128 continuation frames (SEQ is 7 bits, 0..127) -- CTAP sec. 8.1.4.
 * 57 + 128*59 = 7609. Anything larger would wrap SEQ on the wire. */
#define HID_MAX_MSG             (HID_INIT_PAYLOAD + 128 * HID_CONT_PAYLOAD)

/* Ceiling on frames read while waiting for one response. KEEPALIVEs
 * arrive at most every ~100 ms during long device-side operations
 * (CTAP sec. 8.1.5.2), so 1024 skipped frames is ~100 s of a live,
 * talking device -- past that we declare the transaction wedged.
 * Without this cap, steady KEEPALIVE (or foreign-channel) chatter
 * would re-arm the 5 s per-read timeout forever. */
#define HID_XACT_FRAME_BUDGET   1024

#define CMD_PING        0x81
#define CMD_MSG         0x03
#define CMD_LOCK        0x84
#define CMD_INIT        0x86
#define CMD_WINK        0x88
#define CMD_CBOR        0x10
#define CMD_CANCEL      0x91
#define CMD_KEEPALIVE   0xbb
#define CMD_ERROR       0xbf
#define CMD_RNG         0x50    /* Bruce vendor command -- pqhid_rng() */
#define CMD_RNG_STATUS  0x52    /* Bruce vendor command -- pqhid_rng_status() */
#define RNG_STATUS_LEN  29      /* source byte + seven big-endian u32 */
#define CMD_REBOOT      0x51    /* Bruce vendor command -- pqhid_reboot() */

#define INIT_BIT        0x80

/* INIT response layout (CTAP sec. 8.1.9.1.3): 17 bytes minimum, more if
 * capability bits expand. We read exactly the standard fields. */
#define INIT_RESP_MIN   17

/* ---- Device handle ---------------------------------------------- */

struct pqhid_dev {
	pqhid_os_dev_t *os;
	uint32_t        cid;
	pqhid_info_t    info;
};

/* ---- Version ---------------------------------------------------- */

const char *pqhid_version(void)
{
	return PQHID_VERSION_STRING;
}

/* ---- Frame builders --------------------------------------------- */

static void pqhid_pack_cid(unsigned char *frame, uint32_t cid)
{
	frame[0] = (unsigned char)(cid >> 24);
	frame[1] = (unsigned char)(cid >> 16);
	frame[2] = (unsigned char)(cid >> 8);
	frame[3] = (unsigned char)(cid);
}

static uint32_t pqhid_unpack_cid(const unsigned char *frame)
{
	return ((uint32_t)frame[0] << 24)
	     | ((uint32_t)frame[1] << 16)
	     | ((uint32_t)frame[2] << 8)
	     |  (uint32_t)frame[3];
}

static void pqhid_pack_init(unsigned char frame[HID_FRAME_SIZE],
                            uint32_t cid, unsigned char cmd, uint16_t bcnt,
                            const unsigned char *payload, size_t pLen)
{
	memset(frame, 0, HID_FRAME_SIZE);
	pqhid_pack_cid(frame, cid);
	frame[4] = INIT_BIT | cmd;
	frame[5] = (unsigned char)(bcnt >> 8);
	frame[6] = (unsigned char)(bcnt & 0xff);
	if(pLen > 0)
		memcpy(frame + 7, payload, pLen);
}

static void pqhid_pack_cont(unsigned char frame[HID_FRAME_SIZE],
                            uint32_t cid, unsigned char seq,
                            const unsigned char *payload, size_t pLen)
{
	memset(frame, 0, HID_FRAME_SIZE);
	pqhid_pack_cid(frame, cid);
	frame[4] = seq & 0x7f;
	if(pLen > 0)
		memcpy(frame + 5, payload, pLen);
}

/* ---- Transaction core ------------------------------------------- */

/* Send one CTAP-HID command and gather the response.
 *
 *   os:      opened backend handle
 *   cid:     channel id to use (HID_BROADCAST_CID for the initial INIT)
 *   cmd:     command byte (without the INIT bit)
 *   payload, pLen: outgoing payload
 *   resp, respCap: caller's response buffer
 *   respLen: out -- bytes written into resp on success
 *   respCmdOut: out (optional) -- command byte returned by device
 */
static int pqhid_xact(pqhid_os_dev_t *os, uint32_t cid, unsigned char cmd,
                      const unsigned char *payload, size_t pLen,
                      unsigned char *resp, size_t respCap, size_t *respLen,
                      unsigned char *respCmdOut)
{
	unsigned char frame[HID_FRAME_SIZE];
	int rc;
	size_t sent;
	unsigned char seq;
	size_t firstChunk;
	size_t chunk;
	uint16_t bcnt;
	size_t total;
	size_t received;
	uint32_t rxCid;
	uint32_t respCid;
	unsigned char rxCmd;
	int budget;

	if(pLen > HID_MAX_MSG)
		return PQFIDO_ERR_INVAL;   /* SEQ would wrap on the wire */

	/* Outbound: init frame + continuation frames. */
	firstChunk = (pLen < HID_INIT_PAYLOAD) ? pLen : HID_INIT_PAYLOAD;
	pqhid_pack_init(frame, cid, cmd, (uint16_t)pLen,
	  payload, firstChunk);
	rc = pqhid_os_write(os, frame);
	if(rc != PQFIDO_OK) return rc;

	sent = firstChunk;
	seq = 0;
	while(sent < pLen){
		chunk = pLen - sent;
		if(chunk > HID_CONT_PAYLOAD) chunk = HID_CONT_PAYLOAD;
		pqhid_pack_cont(frame, cid, seq, payload + sent, chunk);
		rc = pqhid_os_write(os, frame);
		if(rc != PQFIDO_OK) return rc;
		sent += chunk;
		seq++;
	}

	/* Inbound: skip frames not addressed to our CID and KEEPALIVE
	 * frames; the first init frame for our CID begins the response.
	 * The frame budget bounds the whole wait -- see its comment. */
	budget = HID_XACT_FRAME_BUDGET;
	for(;;){
		if(budget-- <= 0)
			return PQFIDO_ERR_TIMEOUT;
		rc = pqhid_os_read(os, frame, HID_DEFAULT_TIMEOUT_MS);
		if(rc != PQFIDO_OK) return rc;

		/* On the broadcast channel (INIT handshake) accept any
		 * CID: the spec answers on broadcast, but some devices
		 * reply on the CID they just allocated. The caller
		 * validates the response by its nonce echo either way. */
		rxCid = pqhid_unpack_cid(frame);
		if(cid != HID_BROADCAST_CID && rxCid != cid) continue;

		rxCmd = frame[4];
		if(!(rxCmd & INIT_BIT))
			continue;   /* stray continuation, ignore */
		rxCmd = (unsigned char)(rxCmd & 0x7f);

		if(rxCmd == (CMD_KEEPALIVE & 0x7f))
			continue;

		bcnt = (uint16_t)((frame[5] << 8) | frame[6]);

		if(rxCmd == (CMD_ERROR & 0x7f))
			return PQFIDO_ERR_PROTO;

		/* A response must carry the command it answers (CTAP
		 * sec. 8.1.4). Anything else on our channel is a stale reply
		 * from an earlier, timed-out transaction -- returning its
		 * payload as ours would corrupt the caller's view, so
		 * surface a protocol error instead. rxCmd was masked to
		 * 7 bits above; the CMD_* constants carry the init bit,
		 * so mask the sent command the same way. */
		if(rxCmd != (cmd & 0x7f))
			return PQFIDO_ERR_PROTO;

		if(respCmdOut) *respCmdOut = rxCmd;

		total = bcnt;
		if(total > respCap) return PQFIDO_ERR_INVAL;

		/* Continuations must arrive on the same CID the response's
		 * init frame used (which on broadcast may be the freshly
		 * allocated CID rather than the broadcast address). */
		respCid = rxCid;

		chunk = (total < HID_INIT_PAYLOAD) ? total : HID_INIT_PAYLOAD;
		memcpy(resp, frame + 7, chunk);
		received = chunk;
		seq = 0;

		while(received < total){
			if(budget-- <= 0)
				return PQFIDO_ERR_TIMEOUT;
			rc = pqhid_os_read(os, frame,
			  HID_DEFAULT_TIMEOUT_MS);
			if(rc != PQFIDO_OK) return rc;

			rxCid = pqhid_unpack_cid(frame);
			if(rxCid != respCid) continue;
			if(frame[4] & INIT_BIT)
				return PQFIDO_ERR_PROTO;
			if(frame[4] != seq)
				return PQFIDO_ERR_PROTO;

			chunk = total - received;
			if(chunk > HID_CONT_PAYLOAD) chunk = HID_CONT_PAYLOAD;
			memcpy(resp + received, frame + 5, chunk);
			received += chunk;
			seq++;
		}

		if(respLen) *respLen = received;
		return PQFIDO_OK;
	}
}

/* ---- Public API ------------------------------------------------- */

int pqhid_enumerate(pqhid_devinfo_t *infos, size_t cap, size_t *count)
{
	if(infos == NULL || count == NULL) return PQFIDO_ERR_INVAL;
	*count = 0;
	if(cap == 0) return PQFIDO_OK;
	return pqhid_os_enumerate(infos, cap, count);
}

int pqhid_open(const char *path, pqhid_dev_t **out)
{
	pqhid_dev_t *dev;
	pqhid_os_dev_t *os;
	int rc;
	int attempt;
	unsigned char nonce[8];
	unsigned char resp[64];
	size_t respLen;

	if(path == NULL || out == NULL) return PQFIDO_ERR_INVAL;
	*out = NULL;

	rc = pqhid_os_open(path, &os);
	if(rc != PQFIDO_OK) return rc;

	dev = (pqhid_dev_t *)calloc(1, sizeof(*dev));
	if(dev == NULL){ pqhid_os_close(os); return PQFIDO_ERR_NOMEM; }
	dev->os = os;
	dev->cid = HID_BROADCAST_CID;

	/* INIT on the broadcast channel, which is shared with every
	 * other host process talking to this device. A response there
	 * may answer someone ELSE's INIT (nonce echo mismatch -- CTAP
	 * sec. 8.1.9.1.3), and a busy device may answer ERR_CHANNEL_BUSY
	 * (surfaced as PQFIDO_ERR_PROTO). Both deserve a bounded retry
	 * with a fresh nonce rather than a hard failure. Real transport
	 * failures (I/O, timeout) abort immediately. */
	for(attempt = 0; attempt < 4; attempt++){
		rc = pqhid_os_random(nonce, sizeof nonce);
		if(rc != PQFIDO_OK) goto err;

		rc = pqhid_xact(os, HID_BROADCAST_CID, CMD_INIT,
		  nonce, 8, resp, sizeof resp, &respLen, NULL);
		if(rc == PQFIDO_ERR_PROTO) continue;
		if(rc != PQFIDO_OK) goto err;

		if(respLen >= INIT_RESP_MIN
		  && memcmp(resp, nonce, 8) == 0)
			break;   /* our response, well-formed */
		rc = PQFIDO_ERR_PROTO;
	}
	if(rc != PQFIDO_OK) goto err;

	memcpy(dev->info.nonce, nonce, 8);
	dev->info.cid = ((uint32_t)resp[8] << 24)
	              | ((uint32_t)resp[9] << 16)
	              | ((uint32_t)resp[10] << 8)
	              |  (uint32_t)resp[11];
	dev->info.protocol_version = resp[12];
	dev->info.device_major     = resp[13];
	dev->info.device_minor     = resp[14];
	dev->info.device_build     = resp[15];
	dev->info.capabilities     = resp[16];
	dev->cid = dev->info.cid;

	*out = dev;
	return PQFIDO_OK;

err:
	pqhid_os_close(os);
	free(dev);
	return rc;
}

void pqhid_close(pqhid_dev_t *dev)
{
	if(dev == NULL) return;
	pqhid_os_close(dev->os);
	free(dev);
}

int pqhid_get_info(const pqhid_dev_t *dev, pqhid_info_t *out)
{
	if(dev == NULL || out == NULL) return PQFIDO_ERR_INVAL;
	*out = dev->info;
	return PQFIDO_OK;
}

int pqhid_ping(pqhid_dev_t *dev, const unsigned char *data, size_t dataLen)
{
	unsigned char resp[2048];
	size_t respLen;
	int rc;

	if(dev == NULL || data == NULL) return PQFIDO_ERR_INVAL;
	if(dataLen > sizeof resp) return PQFIDO_ERR_INVAL;

	rc = pqhid_xact(dev->os, dev->cid, CMD_PING,
	  data, dataLen, resp, sizeof resp, &respLen, NULL);
	if(rc != PQFIDO_OK) return rc;
	if(respLen != dataLen) return PQFIDO_ERR_PROTO;
	if(memcmp(resp, data, dataLen) != 0) return PQFIDO_ERR_VERIFY;
	return PQFIDO_OK;
}

int pqhid_wink(pqhid_dev_t *dev)
{
	unsigned char resp[8];
	size_t respLen;

	if(dev == NULL) return PQFIDO_ERR_INVAL;
	if(!(dev->info.capabilities & PQHID_CAP_WINK))
		return PQFIDO_ERR_PROTO;

	return pqhid_xact(dev->os, dev->cid, CMD_WINK,
	  NULL, 0, resp, sizeof resp, &respLen, NULL);
}

int pqhid_cbor(pqhid_dev_t *dev,
  const unsigned char *data, size_t dataLen,
  unsigned char *resp, size_t respCap, size_t *respLen)
{
	if(dev == NULL || data == NULL
	  || resp == NULL || respLen == NULL)
		return PQFIDO_ERR_INVAL;

	return pqhid_xact(dev->os, dev->cid, CMD_CBOR,
	  data, dataLen, resp, respCap, respLen, NULL);
}

int pqhid_msg(pqhid_dev_t *dev,
  const unsigned char *apdu, size_t apduLen,
  unsigned char *resp, size_t respCap, size_t *respLen)
{
	if(dev == NULL || apdu == NULL
	  || resp == NULL || respLen == NULL)
		return PQFIDO_ERR_INVAL;

	return pqhid_xact(dev->os, dev->cid, CMD_MSG,
	  apdu, apduLen, resp, respCap, respLen, NULL);
}

/* ---- Local extension (Bruce) ---------------------------------- */

int pqhid_rng(pqhid_dev_t *dev, unsigned char *buf, size_t len)
{
	unsigned char req[2];
	size_t got;
	size_t want;
	size_t respLen;
	int rc;

	if(dev == NULL || buf == NULL) return PQFIDO_ERR_INVAL;

	/* One transaction per PQHID_RNG_MAX_XACT-byte chunk. The request
	 * payload is the chunk size as 2 bytes big-endian; the device
	 * answers with exactly that many random bytes (firmware contract
	 * in c/firmware/src/ctaphid.h). */
	got = 0;
	while(got < len){
		want = len - got;
		if(want > PQHID_RNG_MAX_XACT) want = PQHID_RNG_MAX_XACT;
		req[0] = (unsigned char)(want >> 8);
		req[1] = (unsigned char)(want & 0xff);
		rc = pqhid_xact(dev->os, dev->cid, CMD_RNG,
		  req, sizeof req, buf + got, want, &respLen, NULL);
		if(rc != PQFIDO_OK) return rc;
		if(respLen != want) return PQFIDO_ERR_PROTO;
		got += want;
	}
	return PQFIDO_OK;
}

static uint32_t be32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
	  | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int pqhid_rng_status(pqhid_dev_t *dev, pqhid_rng_status_t *out)
{
	unsigned char resp[RNG_STATUS_LEN];
	size_t respLen = 0;
	int rc;

	if(dev == NULL || out == NULL) return PQFIDO_ERR_INVAL;
	rc = pqhid_xact(dev->os, dev->cid, CMD_RNG_STATUS,
	  NULL, 0, resp, sizeof resp, &respLen, NULL);
	if(rc != PQFIDO_OK) return rc;
	if(respLen != RNG_STATUS_LEN) return PQFIDO_ERR_PROTO;
	out->source         = resp[0];
	out->qrng_bytes     = be32(resp + 1);
	out->fallback_bytes = be32(resp + 5);
	out->packets        = be32(resp + 9);
	out->header_err     = be32(resp + 13);
	out->health_err     = be32(resp + 17);
	out->bus_err        = be32(resp + 21);
	out->short_requests = be32(resp + 25);
	return PQFIDO_OK;
}

int pqhid_vendor(pqhid_dev_t *dev, unsigned char cmd,
  const unsigned char *req, size_t reqLen,
  unsigned char *resp, size_t respCap, size_t *respLen)
{
	size_t n = 0;

	if(dev == NULL) return PQFIDO_ERR_INVAL;
	/* CTAPHID reserves 0x40..0x7f for vendor use (CTAP 11.2.9.2).
	 * Refusing anything else keeps this from becoming a back door
	 * around pqhid_cbor() / pqhid_msg() and their validation. */
	if(cmd < 0x40 || cmd > 0x7f) return PQFIDO_ERR_INVAL;
	if(req == NULL && reqLen != 0) return PQFIDO_ERR_INVAL;
	if(resp == NULL && respCap != 0) return PQFIDO_ERR_INVAL;

	return pqhid_xact(dev->os, dev->cid, cmd,
	  req, reqLen, resp, respCap, respLen ? respLen : &n, NULL);
}

int pqhid_reboot(pqhid_dev_t *dev, int mode)
{
	unsigned char frame[HID_FRAME_SIZE];
	unsigned char m;

	if(dev == NULL) return PQFIDO_ERR_INVAL;
	if(mode != PQHID_REBOOT_WARM && mode != PQHID_REBOOT_BOOTSEL)
		return PQFIDO_ERR_INVAL;
	m = (unsigned char)mode;

	/* Fire-and-forget: the token runs its user-presence gate and then
	 * reboots, re-enumerating off the bus, so there is no response to
	 * read (unlike pqhid_xact). Send just the init frame carrying the
	 * one-byte mode and return once it is on the wire. */
	pqhid_pack_init(frame, dev->cid, CMD_REBOOT, 1, &m, 1);
	return pqhid_os_write(dev->os, frame);
}
