/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Non-secure image memory map (Milestone 1). Must match the NS regions
 * the Secure image's SAU set up (see fw-secure/memory-secure.x and
 * docs/TRUSTZONE.md). Kept in the low 2 MiB -- picotool assumes a 2 MiB
 * flash on these Feitian samples (unprogrammed FLASH_DEVINFO):
 *   FLASH 0x10100000..0x101EFFFF  (SAU region 0, Non-secure)
 *   RAM   0x20040000..0x2007FFFF  (SAU region 1, Non-secure)
 *
 * The image's vector table sits at 0x10100000 (start of NS flash); the
 * Secure launcher reads MSP_NS + reset vector from there. No boot-ROM
 * blocks here -- the ROM never sees this image; the Secure world loads
 * and launches it directly. cortex-m-rt's default link.x places the
 * vector table at the start of FLASH, which is exactly the NS base. */

MEMORY {
    FLASH : ORIGIN = 0x10100000, LENGTH = 0xF0000    /* 960 KiB NS code */
    RAM   : ORIGIN = 0x20070000, LENGTH = 64K        /* NS SRAM         */
}
