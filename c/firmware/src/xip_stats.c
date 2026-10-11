/* xip_stats.c -- XIP cache hit-rate readout (PQF_XIP_STATS builds only).
 *
 * The RP2350 XIP block keeps two 32-bit saturating counters,
 * XIP_CTR_HIT and XIP_CTR_ACC (hardware/structs/xip.h; both are
 * write-to-clear -- writing any value zeroes them). Clearing them before
 * a hybrid signature and reading them after gives the cache hit rate
 * for exactly the operation whose wall time we care about.
 *
 * Reading it correctly needs three caveats:
 *
 *   1. The counters are global to the XIP subsystem, not per core.
 *      During a sign, core 1 runs the ML-DSA and core 0 spins in
 *      core1_hybrid_sign()'s poll loop pumping TinyUSB and CTAPHID
 *      KEEPALIVEs -- code that also lives in XIP on these builds. So a
 *      sample is BOTH cores' flash traffic. That is the right number
 *      for "is this image thrashing", but it means the hit rate does
 *      not attribute to the crypto alone, and an idle-USB host will
 *      measure slightly differently from a busy one.
 *
 *   2. Saturating, not wrapping. 2^32 accesses is minutes of thrash at
 *      150 MHz, well past any single sign, but the report flags a
 *      pegged counter rather than quietly printing 100%.
 *
 *   3. On a copy_to_ram image there is no XIP traffic to speak of and
 *      the counters stay near zero -- which is the expected reading, not
 *      a broken instrument.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "xip_stats.h"

/* CMake only adds this file to the target when the option is on, but a
 * stray build without the define would collide with the empty inlines
 * in the header. Compile to nothing instead. */
#if defined(PQF_XIP_STATS)

#include "hardware/structs/xip.h"
#include "hardware/sync.h"      /* __dmb() */

volatile uint32_t pqf_xip_acc;
volatile uint32_t pqf_xip_hit;
volatile uint32_t pqf_xip_seq;

void xip_stats_begin(void)
{
    /* Write-to-clear. Order matters only in that both must be zeroed
     * before the measured work starts; the two writes are a handful of
     * cycles apart, which is noise against a multi-second sign. */
    xip_ctrl_hw->ctr_hit = 0;
    xip_ctrl_hw->ctr_acc = 0;
}

void xip_stats_end(void)
{
    uint32_t hit = xip_ctrl_hw->ctr_hit;
    uint32_t acc = xip_ctrl_hw->ctr_acc;

    pqf_xip_hit = hit;
    pqf_xip_acc = acc;
    __dmb();                    /* publish the pair before the seq bump */
    pqf_xip_seq++;
}

#endif /* PQF_XIP_STATS */
