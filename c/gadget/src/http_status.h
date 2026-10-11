/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PQF_GADGET_HTTP_STATUS_H
#define PQF_GADGET_HTTP_STATUS_H

/* Plaintext HTTP status endpoint on :80 -- the Phase-2 stand-in for the TLS
 * management channel (Phase 4 replaces this with mbedTLS/altcp + the real
 * management protocol; docs/NETWORK-GADGET.md sec. 5). GET anything -> JSON. */
void pqf_http_status_start(void);

#endif /* PQF_GADGET_HTTP_STATUS_H */
