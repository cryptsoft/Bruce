/* pqf_yield.h -- a cooperative yield point inside long-running crypto.
 *
 * The ML-DSA and EC code calls pqf_yield() from inside its heavy loops:
 * once per sampled matrix element, per NTT, per rejection-sampling
 * iteration, per Montgomery-ladder step. Each call is a few
 * microseconds apart at most, so whoever sits behind the hook can keep
 * a deadline.
 *
 * The default (weak) definition does nothing, and the compiler is free
 * to leave a call to an empty function in place at negligible cost.
 * The single-core firmware (src/core0_signer.c, PQF_SINGLE_CORE)
 * overrides it with a rate-limited USB service + CTAPHID KEEPALIVE
 * pump, which is what lets a ~1 s hybrid signature run on the same
 * core that talks to the host without the browser's watchdog firing.
 * The dual-core builds never override it: there core 0 pumps keepalives
 * while core 1 signs, and the hook stays a no-op on both cores.
 *
 * Rules for a real implementation: it must be safe to call at any
 * point in the crypto (no allocation through the crypto's allocator,
 * no re-entry into the signer), and it must return.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_YIELD_H
#define PQF_YIELD_H

void pqf_yield(void);

#endif /* PQF_YIELD_H */
