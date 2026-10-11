/* bootsel.h -- runtime BOOTSEL-button sampling via the QSPI chip-select
 * line. See bootsel.c for the mechanism, provenance, and constraints.
 *
 * This declaration file is trivial; the implementation in bootsel.c is
 * a BSD-3-Clause derivation from Raspberry Pi pico-examples (see that
 * file's header and THIRD_PARTY.md).
 *
 * SPDX-License-Identifier: BSD-3-Clause; the licence's conditions and
 * disclaimer are in LICENSE-BSD-3-CLAUSE-PICO-EXAMPLES at the repository root.
 */

#ifndef PQF_BOOTSEL_H
#define PQF_BOOTSEL_H

#include <stdbool.h>

/* Sample the BOOTSEL button -- true while it is held down.
 *
 * Costs a few microseconds of flash blackout per call (interrupts
 * masked, both cores must avoid XIP fetches during the window), so
 * callers must rate-limit and must never call it while a flash write
 * or a core-1 hybrid sign is in flight. See bootsel.c. */
bool pqf_bootsel_pressed(void);

#endif /* PQF_BOOTSEL_H */
