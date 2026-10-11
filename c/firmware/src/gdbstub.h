/* gdbstub.h -- on-token GDB remote-serial-protocol stub, served
 * over the USB link (no SWD probe, no hardware debug assist).
 *
 * Compiled in only when the build sets -DPQF_GDB_STUB=ON (see
 * CMakeLists.txt); production images never carry it. When disabled,
 * the hooks below compile to nothing, so call sites need no #ifdefs.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_GDBSTUB_H
#define PQF_GDBSTUB_H

#if defined(PQF_GDB_STUB)

/* One-time setup, called from main() after tud_init(): installs the
 * DebugMonitor handler into the RAM vector table, enables monitor-mode
 * debug (DEMCR.MON_EN) at the highest configurable exception priority,
 * and arms the Flash Patch & Breakpoint unit. Core 0 only. */
void pqf_gdb_init(void);

/* Transport poll, called from thread-level wait loops (the main loop,
 * the core-1 long-op tick, the user-presence gate). Drains the GDB CDC
 * interface and, on a halt request (Ctrl-C / fresh attach), pends the
 * DebugMonitor exception -- the monitor session then runs entirely
 * inside that handler and this call returns after resume. Cheap no-op
 * (one FIFO emptiness check) when no debugger is talking. */
void pqf_gdb_poll(void);

#else /* !PQF_GDB_STUB */

static inline void pqf_gdb_init(void) {}
static inline void pqf_gdb_poll(void) {}

#endif /* PQF_GDB_STUB */

#endif /* PQF_GDBSTUB_H */
