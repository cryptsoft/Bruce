/* Host shim for the pico-sdk absolute_time API.
 *
 * The presence gate is a timing loop -- a debounced hold, a deadline, a
 * blink interval, a keepalive interval -- so the clock has to be under
 * the test's control. Real time would make the suite slow and flaky and
 * would not let it test a timeout at all.
 *
 * Used by test_fido_hid.c; test_ctaphid.c supplies its own time_us_64
 * through PQF_CTAPHID_HOST instead.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_HOST_PICO_TIME_H
#define PQF_HOST_PICO_TIME_H

#include <stdint.h>
#include <stdbool.h>

typedef struct { uint64_t us; } absolute_time_t;

/* The test drives this. */
extern uint64_t pqf_host_now_us;

static inline uint64_t time_us_64(void) { return pqf_host_now_us; }
static inline absolute_time_t get_absolute_time(void)
{
    absolute_time_t t = { pqf_host_now_us };
    return t;
}
static inline absolute_time_t make_timeout_time_us(uint64_t us)
{
    absolute_time_t t = { pqf_host_now_us + us };
    return t;
}
static inline absolute_time_t make_timeout_time_ms(uint32_t ms)
{
    return make_timeout_time_us((uint64_t)ms * 1000u);
}
static inline bool time_reached(absolute_time_t t)
{
    return pqf_host_now_us >= t.us;
}
static inline int64_t absolute_time_diff_us(absolute_time_t from,
                                            absolute_time_t to)
{
    return (int64_t)to.us - (int64_t)from.us;
}
static inline void sleep_us(uint64_t us) { pqf_host_now_us += us; }
static inline void sleep_ms(uint32_t ms) { pqf_host_now_us += (uint64_t)ms * 1000u; }

#endif
