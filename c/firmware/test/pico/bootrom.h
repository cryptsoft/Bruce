/* Host shim for the boot-ROM flash routines.
 *
 * On target flash_store.c does not use the pico-sdk flash wrappers; it
 * looks the five routines up in the ROM table and drives them directly,
 * so that the whole erase/program window is one RAM-resident sequence
 * with XIP off. rom_func_lookup_inline dereferences an absolute address
 * in the boot ROM, which cannot exist off-target -- replacing it IS the
 * seam. The pointers it hands back here land on host_flash_die.c, so
 * the real call sequence, the real erase opcode and the real QMI
 * save/restore all still execute and are all observable.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_HOST_PICO_BOOTROM_H
#define PQF_HOST_PICO_BOOTROM_H
#include <stdint.h>

typedef void (*rom_connect_internal_flash_fn)(void);
typedef void (*rom_flash_exit_xip_fn)(void);
typedef void (*rom_flash_range_erase_fn)(uint32_t, size_t, uint32_t, uint8_t);
typedef void (*rom_flash_range_program_fn)(uint32_t, const uint8_t *, size_t);
typedef void (*rom_flash_flush_cache_fn)(void);
typedef void (*rom_flash_enter_cmd_xip_fn)(void);

/* Codes are arbitrary here; only the mapping below has to be consistent. */
#define ROM_FUNC_CONNECT_INTERNAL_FLASH  1
#define ROM_FUNC_FLASH_EXIT_XIP          2
#define ROM_FUNC_FLASH_RANGE_ERASE       3
#define ROM_FUNC_FLASH_RANGE_PROGRAM     4
#define ROM_FUNC_FLASH_FLUSH_CACHE       5
#define ROM_FUNC_FLASH_ENTER_CMD_XIP     6

void pqf_die_connect_internal_flash(void);
void pqf_die_flash_exit_xip(void);
void pqf_die_flash_range_erase(uint32_t off, size_t count, uint32_t block_size,
                               uint8_t block_cmd);
void pqf_die_flash_range_program(uint32_t off, const uint8_t *data, size_t count);
void pqf_die_flash_flush_cache(void);
void pqf_die_flash_enter_cmd_xip(void);

static inline void *rom_func_lookup_inline(uint32_t code)
{
    switch (code) {
    case ROM_FUNC_CONNECT_INTERNAL_FLASH: return (void *)pqf_die_connect_internal_flash;
    case ROM_FUNC_FLASH_EXIT_XIP:         return (void *)pqf_die_flash_exit_xip;
    case ROM_FUNC_FLASH_RANGE_ERASE:      return (void *)pqf_die_flash_range_erase;
    case ROM_FUNC_FLASH_RANGE_PROGRAM:    return (void *)pqf_die_flash_range_program;
    case ROM_FUNC_FLASH_FLUSH_CACHE:      return (void *)pqf_die_flash_flush_cache;
    case ROM_FUNC_FLASH_ENTER_CMD_XIP:    return (void *)pqf_die_flash_enter_cmd_xip;
    default:                              return (void *)0;
    }
}
#endif
