/* large_blobs.h -- authenticatorLargeBlobs (0x0C, CTAP 2.1 sec. 6.10).
 *
 * A single device-wide opaque byte array the host reads / writes in
 * offset+length chunks. RPs encrypt their per-credential contributions
 * with the largeBlobKey extension key, so to us the array is just
 * bytes carrying a SHA-256 integrity trailer.
 *
 * Stored in a dedicated 4 KiB flash sector below the resident-credential
 * sector. Firmware links large_blobs.c (QSPI); host tests build it with
 * -DPQF_RESIDENT_HOST (RAM only).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_LARGE_BLOBS_H
#define PQF_LARGE_BLOBS_H

#include <stdint.h>
#include <stddef.h>

/* Maximum serialized large-blob array (getInfo 0x0b). */
#define MAX_LARGE_BLOB_LEN   2048

/* Load (or initialise) the large-blob array at boot. */
void large_blobs_init(void);

/* Reset the array to the spec's initial value (authenticatorReset). */
void large_blobs_wipe(void);

/* Handle an authenticatorLargeBlobs request (CBOR params after the
 * 0x0C command byte). Writes a CTAP response to `resp`. */
int large_blobs_handle(const uint8_t *params, size_t params_len,
                       uint8_t *resp, size_t resp_cap, size_t *resp_len);

#endif /* PQF_LARGE_BLOBS_H */
