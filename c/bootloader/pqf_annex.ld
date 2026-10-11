/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* pqf_annex.ld -- pin the picobin end block at the block-loop annex.
 *
 * Supplement script (passed as an extra -T next to the SDK's
 * memmap_default.ld). The SDK's crt0 already emits a two-block loop:
 * the IMAGE_DEF block early in .text links forward to an IGNORED end
 * block (.embedded_end_block) and that links back -- both links are
 * linker-resolved symbol differences, so they follow wherever the
 * sections are placed. The SDK parks the end block at the tail of the
 * image (.flash_end); this script claims it first and pins it at the
 * bootloader's last sector instead, turning it into the ANNEX the
 * bootloader rewrites at boot with the installed RISC-V app's
 * IMAGE_DEF (see try_boot_app in src/main.c and PQF_ANNEX_OFF in
 * c/common/pqf_image.h -- 0x1F000 here must equal PQF_ANNEX_OFF).
 *
 * Placement is also the overflow guard: if the bootloader ever grows
 * past 0x1F000 the link fails ("cannot move location counter
 * backwards") instead of silently overlapping the annex.
 */
/* Literal address, not ORIGIN(FLASH) + 0x1F000: INSERT supplements are
 * parsed before the main script's MEMORY block, so naming the region
 * here only earns "memory region not declared" warnings. The value is
 * XIP_BASE + PQF_ANNEX_OFF; ld's overlap check still fails the link if
 * the image grows into it. */
SECTIONS
{
    .pqf_annex 0x1001F000 :
    {
        __pqf_annex_start = .;
        KEEP(*(.embedded_end_block*))
        __pqf_annex_end = .;
    }

    ASSERT(SIZEOF(.pqf_annex) >= 20,
           "pqf_annex.ld: embedded_end_block missing -- the slot-0 block loop would not close")
} INSERT BEFORE .flash_end;
