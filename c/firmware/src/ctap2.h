/* ctap2.h -- CTAP 2.1 command dispatcher, device side.
 *
 * The CTAPHID transport (`ctaphid.c`) forwards every CMD_CBOR
 * payload through ctap2_dispatch(). The first byte of the payload
 * is the CTAP2 command identifier (CTAP sec. 6.0 / sec. 6.1); the rest is
 * the (optional) CBOR-encoded parameter map.
 *
 * Responses always begin with a 1-byte CTAP2 status code (0x00 =
 * success); if there's a CBOR body it follows immediately.
 *
 * Phase C-3 scope: only authenticatorGetInfo (cmd 0x04) is wired
 * end-to-end. All other commands return CTAP2_ERR_INVALID_COMMAND
 * until later phases reach them.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CTAP2_H
#define PQF_CTAP2_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ---- CTAP2 command codes (CTAP 2.1 sec. 6.0) ----------------------- */
#define CTAP2_CMD_MAKE_CREDENTIAL           0x01
#define CTAP2_CMD_GET_ASSERTION             0x02
#define CTAP2_CMD_GET_INFO                  0x04
#define CTAP2_CMD_CLIENT_PIN                0x06
#define CTAP2_CMD_RESET                     0x07
#define CTAP2_CMD_GET_NEXT_ASSERTION        0x08
#define CTAP2_CMD_CREDENTIAL_MANAGEMENT     0x0a
#define CTAP2_CMD_SELECTION                 0x0b
#define CTAP2_CMD_LARGE_BLOBS               0x0c
#define CTAP2_CMD_CONFIG                    0x0d

/* ---- CTAP2 status codes (CTAP 2.1 sec. 11.2.5.1) ------------------- */
#define CTAP2_OK                            0x00
#define CTAP2_ERR_INVALID_COMMAND           0x01
#define CTAP2_ERR_INVALID_PARAMETER         0x02
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE      0x11
#define CTAP2_ERR_INVALID_SUBCOMMAND        0x3e
#define CTAP2_ERR_INVALID_LENGTH            0x03
#define CTAP2_ERR_INVALID_CBOR              0x12
#define CTAP2_ERR_MISSING_PARAMETER         0x14
#define CTAP2_ERR_CREDENTIAL_EXCLUDED       0x19
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM     0x26
#define CTAP2_ERR_OPERATION_DENIED          0x27
#define CTAP2_ERR_KEY_STORE_FULL            0x28
#define CTAP2_ERR_NO_CREDENTIALS            0x2e
#define CTAP2_ERR_NOT_ALLOWED               0x30
#define CTAP2_ERR_PIN_INVALID               0x31
#define CTAP2_ERR_PIN_BLOCKED               0x32
#define CTAP2_ERR_PIN_AUTH_INVALID          0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED          0x34
#define CTAP2_ERR_PIN_NOT_SET               0x35
#define CTAP2_ERR_PUAT_REQUIRED             0x36   /* PIN required  */
#define CTAP2_ERR_PIN_POLICY_VIOLATION      0x37
#define CTAP2_ERR_PIN_TOKEN_EXPIRED         0x38
#define CTAP2_ERR_UNSUPPORTED_OPTION        0x2b
#define CTAP2_ERR_INVALID_OPTION            0x2c
#define CTAP2_ERR_UNAUTHORIZED_PERMISSION   0x40
#define CTAP2_ERR_OTHER                     0x7f

/* Maximum CTAP2 response payload we'll ever produce. CTAP sec. 6.4
 * caps maxMsgSize at 7609 in the spec, but a real getInfo / MakeCred
 * response fits well under 2 KiB. We keep the buffer pre-sized so
 * dispatch is fully allocation-free. */
#define CTAP2_MAX_RESPONSE                  7609

/* User-presence gate hook (CTAP 2.1 sec. 6.1.2 / sec. 6.2.2 "test of user
 * presence"). Installed by the transport layer at boot
 * (fido_hid_install_tick); left NULL in the host-test harness, where
 * presence auto-confirms. Returns true if the user asserted presence
 * within `timeout_us`, false on timeout. Mirrors the Rust port's
 * `host(HostOp::WaitForUp)` closure -- MakeCredential and the initial
 * GetAssertion call it before signing; GetNextAssertion does not
 * re-solicit. */
extern bool (*ctap2_user_presence_hook)(uint32_t timeout_us);

/* Reset internal state at boot. Called once from main. */
void ctap2_init(void);

/* Record the CTAPHID channel the next dispatch belongs to.
 *
 * GetNextAssertion continues a GetAssertion, and the continuation has
 * to be bound to the channel that began it: the iterator holds the
 * client data hash and rp id hash of a ceremony one host started, and
 * without this a second host on another channel could collect the
 * remaining assertions. credential_management_set_cid() already does
 * the same for the enumerate iterators; this is the one stateful
 * iterator that did not have it. Called by ctaphid.c before every
 * CBOR dispatch. */
void ctap2_set_cid(uint32_t cid);

/* Dispatch one CTAP2 message.
 *
 *   payload[0]            CTAP2 command identifier
 *   payload[1..payload_len] (optional) CBOR-encoded parameter map
 *
 * Writes the response (1-byte status + optional CBOR body) into
 * `resp` and updates `*resp_len`. The caller (`ctaphid.c`) wraps
 * the result in HID continuation frames. Returns 0 on success;
 * the response itself carries the CTAP2 status. */
int ctap2_dispatch(const uint8_t *payload, size_t payload_len,
                    uint8_t *resp, size_t resp_cap, size_t *resp_len);

#endif /* PQF_CTAP2_H */
