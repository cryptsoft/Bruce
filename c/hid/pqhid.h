/* pqhid.h
 *
 * CTAP-over-USB-HID transport for FIDO authenticators.
 *
 * Implements the CTAP HID protocol (FIDO CTAP sec. 8.1). Provides the
 * surface needed to act as a FIDO client against a token locally:
 * enumeration of attached authenticators, open + channel negotiation,
 * ping (echo), wink (flash the device LED), CBOR (CTAP2 commands),
 * and msg (CTAP1/U2F APDU passthrough).
 *
 * Supported platforms -- one backend is compiled in per target:
 *
 *   Linux    /dev/hidraw + poll()                (pqhid_linux.c)
 *   macOS    IOKit IOHIDManager / IOHIDDevice    (pqhid_macos.c)
 *   Windows  SetupAPI + hid.dll, overlapped I/O  (pqhid_windows.c)
 *
 * Windows note: since Windows 10 1903 the OS reserves FIDO-usage-page
 * HID devices for its own WebAuthn stack; opening them directly
 * requires the process to run elevated (Administrator). That is a
 * platform policy, not a library limitation. Enumeration works
 * unelevated.
 *
 * Spec references: "CTAP sec. 8.1.*" throughout this library uses the
 * CTAP 2.0 numbering; CTAP 2.1 renumbers the same HID-transport text
 * to sec. 11.2.*. Same normative content either way.
 *
 * SDK conventions:
 *   - all public symbols use the pqhid_ / PQHID_ prefix
 *   - every function returns PQFIDO_OK or a negative PQFIDO_ERR_*
 *     value (defined in this header -- see the "Result codes" section
 *     below)
 *
 * The transport is self-contained (core + per-OS backends): this
 * header declares its own minimal set of PQFIDO_OK / PQFIDO_ERR_* /
 * version macros, so nothing else has to be linked to use it.
 * pqhid_rng() -- the vendor CTAPHID_CMD_RNG (0x50) client for this
 * repo's firmware -- is declared at the bottom of this header and
 * implemented in pqhid.c.
 *
 * Copyright (C) 2010-2026 Cryptsoft Pty Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQFIDO_PQHID_H
#define PQFIDO_PQHID_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Result codes ----
 *
 * Declared here so this transport is standalone. The numeric values
 * are shared with pqcbor.h so a caller that links both can pass codes
 * between the two unchanged. */

#ifndef PQFIDO_OK
#define PQFIDO_OK                        0
#endif
#ifndef PQFIDO_ERR_INVAL
#define PQFIDO_ERR_INVAL                -1   /* invalid argument */
#endif
#ifndef PQFIDO_ERR_NOMEM
#define PQFIDO_ERR_NOMEM                -2   /* memory allocation failed */
#endif
#ifndef PQFIDO_ERR_VERIFY
#define PQFIDO_ERR_VERIFY               -11  /* signature/echo mismatch */
#endif
#ifndef PQFIDO_ERR_IO
#define PQFIDO_ERR_IO                   -13  /* I/O error */
#endif
#ifndef PQFIDO_ERR_TIMEOUT
#define PQFIDO_ERR_TIMEOUT              -14  /* operation timed out */
#endif
#ifndef PQFIDO_ERR_PROTO
#define PQFIDO_ERR_PROTO                -15  /* protocol violation */
#endif

/* ---- Version ----
 *
 * These macros and the corresponding pqhid_version() function report
 * the transport's own version. */

#ifndef PQFIDO_VERSION_MAJOR
#define PQFIDO_VERSION_MAJOR    0
#endif
#ifndef PQFIDO_VERSION_MINOR
#define PQFIDO_VERSION_MINOR    5
#endif
#ifndef PQFIDO_VERSION_PATCH
#define PQFIDO_VERSION_PATCH    0
#endif
#ifndef PQFIDO_VERSION_STRING
#define PQFIDO_VERSION_STRING   "0.5.0"
#endif

#define PQHID_VERSION_MAJOR    PQFIDO_VERSION_MAJOR
#define PQHID_VERSION_MINOR    PQFIDO_VERSION_MINOR
#define PQHID_VERSION_PATCH    PQFIDO_VERSION_PATCH
#define PQHID_VERSION_STRING   PQFIDO_VERSION_STRING

const char *pqhid_version(void);

/* ---- Types ---- */

typedef struct pqhid_dev pqhid_dev_t;

/* Capability flags reported by the device during INIT (CTAP sec. 8.1.9.1.3). */
#define PQHID_CAP_WINK          0x01    /* device supports the WINK command */
#define PQHID_CAP_CBOR          0x04    /* device supports CTAP2 (CBOR) */
#define PQHID_CAP_NMSG          0x08    /* device does NOT support CTAP1 MSG */

/* Information returned by INIT. */
typedef struct pqhid_info {
	unsigned char  nonce[8];            /* echoed back by the device */
	uint32_t       cid;                 /* allocated channel id */
	unsigned char  protocol_version;
	unsigned char  device_major;
	unsigned char  device_minor;
	unsigned char  device_build;
	unsigned char  capabilities;        /* bitmask of PQHID_CAP_* */
} pqhid_info_t;

/* ---- Enumeration ----
 *
 * Fixed-size fields, caller-owned storage -- consistent with the rest
 * of the API, the library never allocates on the caller's behalf. */

#define PQHID_MAX_PATH 256
#define PQHID_MAX_STR  128

/* One attached FIDO authenticator, as found by pqhid_enumerate(). */
typedef struct pqhid_devinfo {
	/* Platform-specific device path; pass verbatim to pqhid_open().
	 * Opaque -- its shape differs per OS and may change on replug. */
	char           path[PQHID_MAX_PATH];
	uint16_t       vendor_id;
	uint16_t       product_id;
	/* USB descriptor strings, UTF-8, NUL-terminated; empty string
	 * when the device doesn't provide one. */
	char           manufacturer[PQHID_MAX_STR];
	char           product[PQHID_MAX_STR];
	char           serial[PQHID_MAX_STR];
} pqhid_devinfo_t;

/* Walk the OS HID bus and report every device advertising the FIDO
 * usage page (0xf1d0, usage 0x0001 -- CTAP sec. 8.1.8.2). Fills up to
 * `cap` entries of `infos`; *count receives the number filled.
 * Devices this process lacks permission to probe are skipped.
 *
 * Returns PQFIDO_OK (zero devices found is still success -- *count
 * is simply 0) or a negative PQFIDO_ERR_* on OS-level failure. */
int pqhid_enumerate(pqhid_devinfo_t *infos, size_t cap, size_t *count);

/* ---- Device lifecycle ----
 *
 * pqhid_open() opens a device by the path reported in
 * pqhid_devinfo_t.path (on Linux e.g. "/dev/hidraw0"), negotiates a
 * private channel ID via CMD_INIT, and verifies the nonce echo. On
 * success *out receives an owned handle which the caller must
 * release with pqhid_close().
 *
 * Returns PQFIDO_OK or a negative PQFIDO_ERR_* code. Typical failures:
 *   PQFIDO_ERR_INVAL    NULL arguments
 *   PQFIDO_ERR_IO       open()/read()/write() failed
 *   PQFIDO_ERR_NOMEM    handle allocation failed
 *   PQFIDO_ERR_TIMEOUT  device did not respond to INIT within 5s
 *   PQFIDO_ERR_PROTO    INIT response malformed or nonce mismatch
 */
int pqhid_open(const char *path, pqhid_dev_t **out);

/* Free resources associated with a device. Safe to call with NULL. */
void pqhid_close(pqhid_dev_t *dev);

/* Read back the cached INIT result (channel id, version, capabilities). */
int pqhid_get_info(const pqhid_dev_t *dev, pqhid_info_t *out);

/* ---- Commands ----
 *
 * Each command returns PQFIDO_OK on success. All buffers are owned by
 * the caller; the library never allocates on the caller's behalf. */

/* PING: send `dataLen` bytes; expect them echoed verbatim. Useful as a
 * liveness / round-trip test. */
int pqhid_ping(pqhid_dev_t *dev,
  const unsigned char *data, size_t dataLen);

/* WINK: ask the device to flash its LED. No payload either direction.
 * Returns PQFIDO_ERR_PROTO if the device does not advertise PQHID_CAP_WINK. */
int pqhid_wink(pqhid_dev_t *dev);

/* CBOR: send a CTAP2 command (raw CBOR bytes, with the command byte as
 * the first byte) and receive the response (status byte + CBOR). The
 * caller passes a response buffer of capacity respCap; *respLen receives
 * the actual byte count written. */
int pqhid_cbor(pqhid_dev_t *dev,
  const unsigned char *data, size_t dataLen,
  unsigned char *resp, size_t respCap, size_t *respLen);

/* MSG: send a CTAP1/U2F APDU and receive the response. Mirrors pqhid_cbor
 * but uses the CTAP1 framing command (0x03). */
int pqhid_msg(pqhid_dev_t *dev,
  const unsigned char *apdu, size_t apduLen,
  unsigned char *resp, size_t respCap, size_t *respLen);

/* ---- Local extension (Bruce) ---- */

/* Largest count a single CTAPHID_CMD_RNG transaction may request --
 * mirrors CTAPHID_RNG_MAX in the firmware (c/firmware/src/ctaphid.h).
 * pqhid_rng() chunks larger requests transparently. */
#define PQHID_RNG_MAX_XACT 1024

/* RNG: fill `buf` with `len` bytes of raw TRNG output from the token,
 * via the Bruce vendor command CTAPHID_CMD_RNG (0x50; CTAP
 * sec. 8.1.9.2 reserves 0x40..0x7f for vendor use). Requests larger than
 * PQHID_RNG_MAX_XACT are split into multiple transactions. No
 * authentication and no user-presence gesture is involved.
 *
 * A token that doesn't implement the vendor command answers
 * CTAPHID_ERROR(INVALID_CMD), surfaced as PQFIDO_ERR_PROTO. */
int pqhid_rng(pqhid_dev_t *dev, unsigned char *buf, size_t len);

/* Which entropy source the token is serving from (vendor command
 * CTAPHID_CMD_RNG_STATUS, 0x52), with the picker's counters. QRNG and
 * TRNG bytes are indistinguishable, so this is how a host finds out
 * rather than timing the transfer. Source codes match the firmware's
 * CTAPHID_RNG_SRC_*. */
#define PQHID_RNG_SRC_TRNG       0   /* no QRNG answered at boot: on-die TRNG */
#define PQHID_RNG_SRC_QRNG       1   /* external QRNG live, first in the queue */
#define PQHID_RNG_SRC_QRNG_LOST  2   /* QRNG found at boot, written off since   */
#define PQHID_RNG_SRC_NO_QRNG    3   /* firmware built without QRNG support     */

typedef struct pqhid_rng_status {
	unsigned char  source;          /* PQHID_RNG_SRC_* */
	uint32_t       qrng_bytes;      /* served by the QRNG since boot */
	uint32_t       fallback_bytes;  /* served by the on-die TRNG since boot */
	uint32_t       packets;         /* QRNG packets read */
	uint32_t       header_err;      /* packets dropped: bad header */
	uint32_t       health_err;      /* packets dropped: health flag set */
	uint32_t       bus_err;         /* I2C transactions failed / timed out */
	uint32_t       short_requests;  /* requests the QRNG could not complete */
} pqhid_rng_status_t;

int pqhid_rng_status(pqhid_dev_t *dev, pqhid_rng_status_t *out);

/* Reboot mode for pqhid_reboot(). Wire values match the firmware's
 * CTAPHID_REBOOT_* mode byte. */
#define PQHID_REBOOT_WARM     0   /* warm reboot back into the firmware   */
#define PQHID_REBOOT_BOOTSEL  1   /* into RP2350 USB mass storage / DFU   */

/* REBOOT: ask the token to reboot via the Bruce vendor command
 * CTAPHID_CMD_REBOOT (0x51). PQHID_REBOOT_BOOTSEL enters the RP2350 USB
 * bootloader (mass storage) for reflashing; PQHID_REBOOT_WARM restarts
 * the firmware.
 *
 * Both modes are gated on the device behind a test of user presence: on
 * a board with a user button the token waits for a physical touch before
 * rebooting; on a buttonless build it reboots immediately.
 *
 * Fire-and-forget: the device re-enumerates away on success, so this
 * sends the one-byte request and returns without reading a response
 * (a returned PQFIDO_OK means the request reached the wire, NOT that
 * the reboot completed -- poll for the device to reappear). A token
 * whose firmware predates the command silently ignores it; detect that
 * by observing that the device never rebooted. */
/* Raw vendor CTAPHID transaction.
 *
 * `cmd` is the command byte WITHOUT the init-frame bit (the framing
 * layer sets it), and must be in the CTAPHID vendor range 0x40..0x7f --
 * anything else is rejected, so this cannot be used to forge a
 * standard command behind the typed calls above.
 *
 * Sends `reqLen` bytes and writes up to `respCap` bytes of reply into
 * `resp`; *respLen receives the actual count. Either buffer may be NULL
 * with the matching length zero for commands that take or return
 * nothing.
 *
 * This exists because the firmware grows vendor commands faster than
 * this header does -- the DFU reboot, the RNG, and the TrustZone build's
 * test hooks are all vendor commands. Without it every new one needs a
 * new typed wrapper before it can be exercised at all, which is how
 * test code ends up reaching for a third-party client library. */
int pqhid_vendor(pqhid_dev_t *dev, unsigned char cmd,
  const unsigned char *req, size_t reqLen,
  unsigned char *resp, size_t respCap, size_t *respLen);

int pqhid_reboot(pqhid_dev_t *dev, int mode);

#ifdef __cplusplus
}
#endif

#endif /* PQFIDO_PQHID_H */
