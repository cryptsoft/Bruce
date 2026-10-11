/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* measure_heap.c -- host-side heap-peak measurement for the ML-DSA ops
 * the firmware runs (macOS malloc_zone_statistics). Not part of the
 * test suite; build ad hoc:
 *   make build/measure_heap CC="cc -DPQF_HYBRID_VARIANT=87"
 */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include "hybrid.h"
#include "pqf_crypto.h"

/* Provided by the DYLD_INSERT_LIBRARIES malloc shim, if loaded. */
static size_t (*p_peak)(void);
static void   (*p_reset)(void);

int main(void)
{
    p_peak  = (size_t (*)(void))dlsym(RTLD_DEFAULT, "shim_peak");
    p_reset = (void (*)(void))dlsym(RTLD_DEFAULT, "shim_reset");
    if (!p_peak || !p_reset) {
        fprintf(stderr, "run with DYLD_INSERT_LIBRARIES=heap_shim.dylib\n");
        return 1;
    }

    uint8_t seed[32];  memset(seed, 0x42, sizeof seed);
    uint8_t scalar[32]; memset(scalar, 0x17, sizeof scalar);
    scalar[31] = 1;

    printf("variant %d\n", PQF_HYBRID_VARIANT);

    /* pub-from-seed (registration path) */
    p_reset();
    static uint8_t pk[PQF_HYBRID_PK_LEN]; size_t pk_len = 0;
    pqf_mldsa_pub_from_seed(PQF_HYBRID_MLDSA, seed, pk, &pk_len);
    printf("pub_from_seed peak: %zu KiB\n", (p_peak() + 512) / 1024);

    /* hybrid sign (assertion path) -- small msg like a GetAssertion */
    p_reset();
    uint8_t msg[69]; memset(msg, 0xAB, sizeof msg);
    static uint8_t sig[PQF_HYBRID_MAX_SIG]; size_t sig_len = 0;
    hybrid_sign(scalar, seed, msg, sizeof msg, sig, &sig_len);
    printf("hybrid_sign peak:   %zu KiB (sig_len %zu)\n",
           (p_peak() + 512) / 1024, sig_len);
    return 0;
}
