/* host_core1_stub.c -- single-core stand-in for core1_signer.
 *
 * The firmware offloads the hybrid PQC signature to core 1; on the
 * host there's no second core, so core1_hybrid_sign() just runs the
 * signature inline (same for the small EC ops the mixed build routes
 * to the RISC-V blob). core1_signer_init() is a no-op and the long-op
 * tick stays NULL (no USB/KEEPALIVE to pump in a host process).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core1_signer.h"
#include "hybrid.h"
#include "pqf_crypto.h"

void (*core1_long_op_tick)(void) = NULL;

/* Test hook: make the next signature fail, as core 1 failing would on
 * the board. One-shot, and it covers the hybrid and the ES256 sign
 * alike, so a caller's error path is reachable whichever algorithm the
 * credential holds. */
int host_core1_fail_next_sign = 0;

static int take_forced_failure(void)
{
    if (!host_core1_fail_next_sign) return 0;
    host_core1_fail_next_sign = 0;
    return 1;
}

void core1_signer_init(void) { /* no second core on the host */ }

int core1_hybrid_sign(const uint8_t ecdsa_scalar[32],
                      const uint8_t mldsa_seed[32],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t *sig_len)
{
    if (take_forced_failure()) return -1;
    return hybrid_sign(ecdsa_scalar, mldsa_seed, msg, msg_len, sig, sig_len);
}

int core1_p256_keygen(uint8_t priv[32], uint8_t pub_x[32], uint8_t pub_y[32])
{
    return pqf_p256_keygen(priv, pub_x, pub_y);
}

int core1_p256_sign(const uint8_t scalar[32], const uint8_t prehash[32],
                    uint8_t *sig, size_t *sig_len)
{
    if (take_forced_failure()) return -1;
    return pqf_ecdsa_p256_sign(scalar, prehash, sig, sig_len);
}

int core1_mldsa_pub(const uint8_t seed[32], uint8_t *pub, size_t *pub_len)
{
    return pqf_mldsa_pub_from_seed(PQF_HYBRID_MLDSA, seed, pub, pub_len);
}
