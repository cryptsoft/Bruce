/* credential_management.h -- authenticatorCredentialManagement (0x0A,
 * CTAP 2.1 sec. 6.8). On-device admin of resident credentials: metadata,
 * enumerate RPs, enumerate credentials per RP, delete, rename.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CREDENTIAL_MANAGEMENT_H
#define PQF_CREDENTIAL_MANAGEMENT_H

#include <stdint.h>
#include <stddef.h>

/* Handle an authenticatorCredentialManagement request (the CBOR params
 * after the 0x0A command byte). Writes a CTAP response to `resp`. */
int credential_management_handle(const uint8_t *params, size_t params_len,
                                 uint8_t *resp, size_t resp_cap,
                                 size_t *resp_len);

/* Invalidate any in-flight enumerateRPs / enumerateCredentials
 * iterator. Called by the dispatcher whenever a command other than
 * authenticatorCredentialManagement runs (our stand-in for the spec's
 * 30 s stateful-command timeout, which needs a wall-clock the
 * dispatcher doesn't carry). */
void credential_management_reset_iters(void);

/* Bind subsequent enumeration to the originating CTAPHID channel
 * (CTAP 2.1 sec. 6.8/sec. 11.2). The transport (ctaphid.c) calls this with the
 * channel id of the CBOR command about to be dispatched, BEFORE
 * ctap2_dispatch runs. enumerate*Begin captures this id; a later
 * enumerate*GetNext on a different channel is refused (the iterator is
 * dropped and ERR_NOT_ALLOWED returned), so a second host process can
 * neither drive nor read another channel's in-flight enumeration. A
 * caller that drives ctap2_dispatch directly (host tests) never sets a
 * cid, so the bound id stays 0 on both Begin and GetNext and matches. */
void credential_management_set_cid(uint32_t cid);

#endif /* PQF_CREDENTIAL_MANAGEMENT_H */
