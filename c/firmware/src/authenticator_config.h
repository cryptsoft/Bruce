/* authenticator_config.h -- authenticatorConfig (CTAP 2.1 sec. 6.11).
 *
 * Device-wide policy the platform can toggle via CTAP command 0x0D:
 * the enterprise-attestation flag, alwaysUv, and the minimum PIN
 * length (plus an RP-id allowlist that drives the minPinLength
 * MakeCredential extension). State is persisted by flash_store.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_AUTHENTICATOR_CONFIG_H
#define PQF_AUTHENTICATOR_CONFIG_H

#include <stdint.h>
#include <stddef.h>

/* Handle an authenticatorConfig request (the CBOR params after the
 * 0x0D command byte). Writes a CTAP response (status byte, no payload
 * -- all AC subcommands return a bare status) to `resp`. */
int authenticator_config_handle(const uint8_t *params, size_t params_len,
                                uint8_t *resp, size_t resp_cap,
                                size_t *resp_len);

#endif /* PQF_AUTHENTICATOR_CONFIG_H */
