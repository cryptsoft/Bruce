/* xip_stats.h -- XIP cache hit-rate readout around the hybrid sign.
 *
 * Compiled (with xip_stats.c) only when CMake sets PQF_XIP_STATS=1
 * (-DPQF_XIP_STATS=ON). With the option off the two hooks below are
 * empty static inlines and nothing else in this header exists, so the
 * sign path links byte-identically to a build that never heard of the
 * instrument -- callers do NOT need to #if around the calls.
 *
 * What it measures: the RP2350's XIP_CTR_HIT / XIP_CTR_ACC counters
 * across one hybrid signature. That number is the whole argument for
 * PQF_HOT_IN_RAM / copy_to_ram -- an XIP image whose ML-DSA working set
 * is being evicted runs at roughly CPI 200, and the hit rate is what
 * says whether that is still happening. See xip_stats.c for the
 * caveats (both cores counted, saturation, what the sample window
 * actually contains).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_XIP_STATS_H
#define PQF_XIP_STATS_H

#if defined(PQF_XIP_STATS)

#include <stdint.h>

/* Clear both counters and open a sample window. Core 0 only, and only
 * with core 1 idle -- the counters are a single global pair. */
void xip_stats_begin(void);

/* Close the window: latch the counters into the report globals below
 * and bump pqf_xip_seq. */
void xip_stats_end(void);

/* Latest closed sample. main.c polls pqf_xip_seq and prints one CDC
 * line per new sample, the same way it reports the level-87 arena
 * high-water. pqf_xip_seq == 0 means nothing measured yet. */
extern volatile uint32_t pqf_xip_acc;   /* XIP_CTR_ACC over the window */
extern volatile uint32_t pqf_xip_hit;   /* XIP_CTR_HIT over the window */
extern volatile uint32_t pqf_xip_seq;   /* completed-sample counter    */

#else  /* !PQF_XIP_STATS */

static inline void xip_stats_begin(void) { }
static inline void xip_stats_end(void)   { }

#endif /* PQF_XIP_STATS */

#endif /* PQF_XIP_STATS_H */
