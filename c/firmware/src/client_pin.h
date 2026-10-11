/* client_pin.h -- authenticatorClientPIN (CTAP 2.1 sec. 6.5) + the
 * PIN/UV-auth-token permission model.
 *
 * Handles the ClientPIN subcommands (key agreement, set/change PIN,
 * get PIN token, get-token-with-permissions) and issues PIN/UV-auth
 * tokens. ctap2.c consults this module to gate MakeCredential /
 * GetAssertion when a PIN is set.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CLIENT_PIN_H
#define PQF_CLIENT_PIN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "pin_protocol.h"

/* PIN/UV-auth-token permission bits (CTAP 2.1 sec. 6.5.5.7.1). */
#define PIN_PERM_MAKE_CREDENTIAL     0x01
#define PIN_PERM_GET_ASSERTION       0x02
#define PIN_PERM_CRED_MGMT           0x04
#define PIN_PERM_BIO_ENROLL          0x08   /* reserved, never granted */
#define PIN_PERM_LARGE_BLOB_WRITE    0x10
#define PIN_PERM_AUTH_CONFIG         0x20

/* The permissions this device can honour. A request naming any other
 * bit -- BIO_ENROLL, which has no enrolment hardware behind it, or a
 * bit CTAP has not assigned -- is refused with UNAUTHORIZED_PERMISSION
 * (CTAP 2.1 sec. 6.5.5.7.1) rather than stored and never checked. */
#define PIN_PERM_SUPPORTED  (PIN_PERM_MAKE_CREDENTIAL | PIN_PERM_GET_ASSERTION \
                           | PIN_PERM_CRED_MGMT | PIN_PERM_LARGE_BLOB_WRITE \
                           | PIN_PERM_AUTH_CONFIG)

/* Minimum / maximum PIN length in bytes (UTF-8). */
#define PIN_MIN_LENGTH               4
#define PIN_MAX_LENGTH               63

void client_pin_init(void);

/* Handle an authenticatorClientPIN request (the CBOR params, i.e.
 * everything after the 0x06 command byte). Writes a CTAP response
 * (status + optional CBOR) to `resp`. */
int client_pin_handle(const uint8_t *params, size_t params_len,
                      uint8_t *resp, size_t resp_cap, size_t *resp_len);

/* Whether a PIN is configured on this device. */
bool client_pin_is_set(void);

/* Derive a PIN-protocol shared secret from the authenticator's
 * current keyAgreement key and the platform's public point. Used by
 * the hmac-secret extension (which reuses the PIN-protocol ECDH +
 * salt encryption). Returns 0 / < 0. */
int client_pin_shared_secret(uint8_t protocol,
                             const uint8_t plat_x[32],
                             const uint8_t plat_y[32],
                             pin_shared_secret_t *out);

/* Verify a pinUvAuthParam presented with a MakeCredential /
 * GetAssertion request. `data` is what the param MACs (the
 * clientDataHash). Checks: a token is active, the MAC matches the
 * token under `protocol`, the token carries `required_perm`, and --
 * if the token is RP-scoped -- that `rp_id_hash` matches.
 *
 * Returns 0 on success, or a CTAP2 status code (e.g.
 * CTAP2_ERR_PIN_AUTH_INVALID) on failure, suitable to return to the
 * host. */
int client_pin_verify_token(const uint8_t *pin_uv_auth_param,
                            size_t param_len, uint8_t protocol,
                            const uint8_t *data, size_t data_len,
                            uint32_t required_perm,
                            const uint8_t rp_id_hash[32]);

#endif /* PQF_CLIENT_PIN_H */
