/* gdbstub_host.h -- host-build platform seam for src/gdbstub.c.
 *
 * Included by gdbstub.c when built with -DPQF_GDB_HOST (see the
 * test/Makefile `test_gdbstub` rule). It replaces the four things the
 * stub touches that only exist on an RP2350:
 *
 *   1. ARMv8-M debug MMIO (DEMCR / DFSR / DHCSR / SHPR3 / VTOR, and the
 *      FPB comparator block) -> a small simulated register file, so the
 *      test can assert on what the stub programmed (comparator values,
 *      MON_STEP, MON_EN) instead of needing a chip.
 *   2. Target memory -> a simulated SRAM window at the real device
 *      address (0x2000_0000), so the m/M whitelist logic under test is
 *      the SAME code the firmware runs, addresses included.
 *   3. TinyUSB CDC -> a pty (or a plain byte queue), so a REAL
 *      arm-none-eabi-gdb can `target remote` the stub.
 *   4. pqf_board_reboot -> recorded, not performed.
 *
 * Nothing here is compiled into firmware.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_GDBSTUB_HOST_H
#define PQF_GDBSTUB_HOST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* --- 1. Simulated debug MMIO ------------------------------------- */

/* Returns a pointer to the simulated 32-bit register backing `addr`.
 * Unknown addresses share a scratch cell (writes land, reads return
 * what was written) -- the stub only touches the handful the real
 * hardware defines, and a scratch cell keeps a typo from crashing the
 * test instead of failing it. */
uint32_t *pqf_gdb_host_reg(uintptr_t addr);

#define GDB_REG32(a)        (*pqf_gdb_host_reg((uintptr_t)(a)))

/* --- 2. Simulated target memory --------------------------------- */

/* Simulated SRAM: device addresses 0x2000_0000 .. +size map into a
 * host buffer. Out-of-window accesses are recorded as faults (the
 * test asserts the stub's whitelist never let one through) and read
 * back as 0xFF. */
#define PQF_GDB_HOST_SRAM_BASE  0x20000000u
#define PQF_GDB_HOST_SRAM_SIZE  0x00082000u      /* matches RP2350 520 KiB */

uint8_t  pqf_gdb_host_mem_rd8(uint32_t addr);
void     pqf_gdb_host_mem_wr8(uint32_t addr, uint8_t v);
unsigned pqf_gdb_host_mem_faults(void);
/* Host pointer for a simulated device address (test setup helper). */
void    *pqf_gdb_host_mem_ptr(uint32_t addr);

#define GDB_MEM_RD8(a)      pqf_gdb_host_mem_rd8((uint32_t)(a))
#define GDB_MEM_WR8(a, v)   pqf_gdb_host_mem_wr8((uint32_t)(a), (v))

/* The stub bounds flash reads against this; give it the 4 MB window
 * the targeted boards carry. */
#ifndef PICO_FLASH_SIZE_BYTES
#define PICO_FLASH_SIZE_BYTES   (4u * 1024u * 1024u)
#endif

/* --- 3. TinyUSB CDC transport ----------------------------------- */

#define PQF_GDB_CDC_ITF     1

uint32_t pqf_gdb_host_cdc_read(uint8_t itf, void *buf, uint32_t len);
uint32_t pqf_gdb_host_cdc_write(uint8_t itf, const void *buf, uint32_t len);
uint32_t pqf_gdb_host_cdc_available(uint8_t itf);
bool     pqf_gdb_host_cdc_connected(uint8_t itf);
void     pqf_gdb_host_usb_task(void);

#define tud_cdc_n_read(i, b, l)     pqf_gdb_host_cdc_read((i), (b), (l))
#define tud_cdc_n_write(i, b, l)    pqf_gdb_host_cdc_write((i), (b), (l))
#define tud_cdc_n_write_str(i, s)   pqf_gdb_host_cdc_write((i), (s), \
                                        (uint32_t)strlen(s))
#define tud_cdc_n_write_flush(i)    ((void)0)
#define tud_cdc_n_available(i)      pqf_gdb_host_cdc_available(i)
#define tud_cdc_n_connected(i)      pqf_gdb_host_cdc_connected(i)
#define tud_task()                  pqf_gdb_host_usb_task()
#define tud_int_handler(rhport)     ((void)(rhport))

/* --- 4. Board hooks + barriers ---------------------------------- */

enum pqf_reboot_mode {
    PQF_REBOOT_WARM    = 0,
    PQF_REBOOT_BOOTSEL = 1,
};
void pqf_board_reboot(enum pqf_reboot_mode mode);   /* records, returns */

#define __dsb()     ((void)0)
#define __isb()     ((void)0)

#endif /* PQF_GDBSTUB_HOST_H */
