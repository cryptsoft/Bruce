/* rsaz_exp.h -- stubbed declarations for the RSA accelerated exp
 * helpers that upstream bn_exp.c references unconditionally.
 *
 * The vendored bn_exp.c includes this header up front, but the
 * actual code paths that call these functions are guarded by
 * `OPENSSL_BN_ASM_MONT` / `RSAZ_ENABLED` macros that are never
 * defined in our build. The prototypes here exist solely so the
 * include line at the top of bn_exp.c resolves; the functions
 * themselves are never linked.
 *
 * If a future change actually starts calling RSAZ_* helpers,
 * vendor the upstream `crypto/bn/rsaz_exp.c` + `rsaz_exp.h` pair
 * to back them.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_RSAZ_EXP_H
#define PQF_RSAZ_EXP_H

#include <openssl/bn.h>

void RSAZ_1024_mod_exp_avx2(BN_ULONG result[16],
                              const BN_ULONG base_norm[16],
                              const BN_ULONG exponent[16],
                              const BN_ULONG m_norm[16],
                              const BN_ULONG RR[16], BN_ULONG k0);
int rsaz_avx2_eligible(void);

void RSAZ_512_mod_exp(BN_ULONG result[8],
                       const BN_ULONG base_norm[8],
                       const BN_ULONG exponent[8],
                       const BN_ULONG m_norm[8],
                       BN_ULONG k0, const BN_ULONG RR[8]);

#endif
