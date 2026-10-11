/* pqhid_os.h
 *
 * Internal contract between the platform-independent CTAP-HID core
 * (pqhid.c) and the per-OS transport backends:
 *
 *   pqhid_linux.c    /dev/hidraw + poll()
 *   pqhid_macos.c    IOKit IOHIDManager / IOHIDDevice
 *   pqhid_windows.c  SetupAPI enumeration + overlapped ReadFile/WriteFile
 *
 * Exactly one backend is compiled into libpqhid; the Makefile picks
 * it by target OS. This header is NOT installed -- callers only ever
 * see pqhid.h.
 *
 * All functions return PQFIDO_OK or a negative PQFIDO_ERR_* code
 * (defined in pqhid.h) unless documented otherwise.
 *
 * Copyright (C) 2010-2026 Cryptsoft Pty Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQFIDO_PQHID_OS_H
#define PQFIDO_PQHID_OS_H

#include <stddef.h>

#include "pqhid.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One CTAP-HID report is always exactly 64 bytes on the wire
 * (CTAP sec. 8.1.4). Report-ID plumbing is a per-OS quirk and is owned
 * by the backend: hidraw and Windows want a leading 0x00 report-ID
 * byte on writes, IOKit passes the report ID out-of-band. The core
 * always hands the backend the bare 64-byte frame. */
#define PQHID_OS_FRAME_SIZE 64

/* Opaque per-backend device handle. Each backend defines its own
 * struct pqhid_os_dev. */
typedef struct pqhid_os_dev pqhid_os_dev_t;

/* Enumerate attached HID devices that advertise the FIDO usage page
 * (0xf1d0) with usage 0x0001 (CTAP sec. 8.1.8.2). Fills up to `cap`
 * entries of `infos`; *count receives the number filled. Devices
 * that cannot be probed are skipped silently. Note "probed", not
 * "opened for traffic": on Linux probing needs the same read/write
 * access as traffic, so what enumerates is what opens; on macOS
 * properties are readable without opening at all; on Windows the
 * probe uses an access-0 handle, so an unelevated process can
 * enumerate FIDO devices it cannot subsequently pqhid_os_open().
 *
 * The `path` written into each entry is backend-defined and only
 * guaranteed to be meaningful to pqhid_os_open() of the same
 * backend:
 *
 *   Linux    "/dev/hidraw3"
 *   macOS    "ioreg:4295261796"  (decimal IORegistry entry ID)
 *   Windows  "\\?\hid#vid_...#..."  (device interface path)
 */
int pqhid_os_enumerate(pqhid_devinfo_t *infos, size_t cap, size_t *count);

/* Open a device by backend-defined path. On success *out receives an
 * owned handle to release with pqhid_os_close(). The device is opened
 * for shared read/write; no CTAP traffic is exchanged here -- the
 * INIT handshake belongs to the core. */
int pqhid_os_open(const char *path, pqhid_os_dev_t **out);

/* Release the handle. Safe to call with NULL. */
void pqhid_os_close(pqhid_os_dev_t *dev);

/* Write one 64-byte report to the interrupt-OUT endpoint. Blocks
 * until the report is accepted by the OS HID stack. */
int pqhid_os_write(pqhid_os_dev_t *dev,
  const unsigned char frame[PQHID_OS_FRAME_SIZE]);

/* Read one 64-byte report from the interrupt-IN endpoint, waiting at
 * most timeoutMs milliseconds; a negative timeoutMs means wait
 * indefinitely. Returns PQFIDO_ERR_TIMEOUT if nothing arrived in
 * time, PQFIDO_ERR_IO if the device went away. */
int pqhid_os_read(pqhid_os_dev_t *dev,
  unsigned char frame[PQHID_OS_FRAME_SIZE], int timeoutMs);

/* Fill `buf` with `len` bytes from the OS CSPRNG. Used for the
 * 8-byte INIT nonce (CTAP sec. 8.1.9.1.3 asks for unpredictable bytes).
 *
 *   Linux    getrandom(2), falling back to /dev/urandom
 *   macOS    arc4random_buf(3)
 *   Windows  BCryptGenRandom (system-preferred RNG)
 */
int pqhid_os_random(unsigned char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PQFIDO_PQHID_OS_H */
