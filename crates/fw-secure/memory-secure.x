/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Secure-image memory map for the TrustZone-M split (Milestone 1).
 * See docs/TRUSTZONE.md for the full picture. Addresses match the
 * table there; refined as real image sizes land.
 *
 * FLASH (4 MiB @ 0x10000000) is split S | NSC | NS. These addresses are
 * the ones the build actually uses -- cross-check against build.rs's
 * --section-start, SAU regions 0 and 2 in main.rs, _ns_image_base below,
 * and fw-nonsecure/memory-nonsecure.x; all five must agree:
 *   0x10000000..0x100F0000  Secure code + data (this image), 960 KiB
 *   0x100F0000..0x10100000  NSC veneers (.gnu.sgstubs) -- 64 KiB
 *   0x10100000..0x101F0000  Non-secure image (fw-nonsecure), 960 KiB
 *   above 0x10200000        store sectors (reserved, Secure, unused yet)
 *
 * An earlier draft of this map put the veneers at 0x101F0000 and NS at
 * 0x10200000. That was revised down to keep everything under 2 MiB (see
 * the DEVINFO note below) and these comments were left behind describing
 * the old numbers -- corrected 2026-08-14.
 *
 * RAM (512 KiB @ 0x20000000): low half Secure, high half Non-secure.
 */

/* Everything is kept under the 2 MiB mark: on these Feitian samples the
 * FLASH_DEVINFO OTP row is unprogrammed, so picotool assumes a 2 MiB
 * flash and refuses to load an image at/after offset 0x200000 -- even
 * though the chip is really >=4 MiB. So for M1 the whole split lives in
 * the low 2 MiB (the store sectors above 2 MiB aren't used until FIDO
 * integration, which will address the DEVINFO quirk properly).
 *
 * FLASH covers the Secure span INCLUDING the veneer window at the top --
 * "Non-secure-Callable" is an SAU *runtime* attribute (region 2 in
 * main.rs), not a separate linker region. Veneers are pinned to
 * 0x100F0000 via `--section-start` (build.rs); FLASH must extend past
 * that or lld reports the section overflowing the region. NS flash
 * begins at 0x10100000, where this region ends.
 *
 * Because FLASH spans the veneer window, nothing stops Secure code from
 * growing into it -- the ASSERT at the bottom of this file is that guard.
 * Secure .text was 5,212 bytes when this was written, so there is ~955
 * KiB of headroom; the check exists because the failure mode otherwise
 * is silent veneer corruption, not a link error. */
MEMORY {
    FLASH  : ORIGIN = 0x10000000, LENGTH = 0x100000   /* 1 MiB: secure code + veneer window */
    /* M4f: 448K, up from 256K. ML-DSA signing needs a real heap and
     * core 1 needs a 64 KiB stack, and both are now Secure-side. The
     * 64 KiB left to NS is ample -- the NS image's static RAM measured
     * under 1 KiB, its buffers are a few KiB of stack. Kept in step
     * with SAU region 1 in main.rs and memory-nonsecure.x; all three
     * must agree or NS faults on its own stack. */
    RAM    : ORIGIN = 0x20000000, LENGTH = 448K       /* secure SRAM                        */
}

/* Address the Non-secure image is linked at (its vector table sits at
 * the very start). The Secure launch code reads MSP_NS / reset vector
 * from here. Kept in sync with fw-nonsecure's memory-nonsecure.x. */
_ns_image_base = 0x10100000;

SECTIONS {
    /* RP2350 boot ROM info -- first 4 KiB of flash, after the vectors. */
    .start_block : ALIGN(4) {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH
} INSERT AFTER .vector_table;

_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    .bi_entries : ALIGN(4) {
        __bi_entries_start = .;
        KEEP(*(.bi_entries));
        . = ALIGN(4);
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

/* Secure-gateway veneers (`.gnu.sgstubs`) are synthesized late by lld,
 * too late for an `INSERT`-based placement to give them an address, so
 * the build passes `--section-start=.gnu.sgstubs=0x100F0000` (the NSC
 * region base) instead. They MUST land in the NSC-attributed region so
 * the Non-secure world can execute the SG instruction that fronts each
 * gateway. */

SECTIONS {
    .end_block : ALIGN(4) {
        __end_block_addr = .;
        KEEP(*(.end_block));
        __flash_binary_end = .;
    } > FLASH
} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

/* Guard the NSC veneer window.
 *
 * `.gnu.sgstubs` is placed by an absolute --section-start, so it does NOT
 * participate in the FLASH region's overflow accounting. If the Secure
 * image ever grows up to 0x100F0000 the link SUCCEEDS and the veneers are
 * silently overwritten; the symptom is an NS world that faults on its
 * first gateway call, not a build error. So check it here.
 *
 * The check is against the end of .rodata, the last Secure-content
 * section before the veneer window (verified 2026-08-14: .rodata ends at
 * 0x1000143c, leaving ~977 KiB of headroom). Note `__flash_binary_end` is
 * NOT usable for this -- .end_block is emitted after the veneers, so that
 * symbol is already past 0x100F0000 by design. If a future change gives
 * this image a non-empty .data, extend the check to cover its flash LMA
 * too. If it fires, move the veneer window (build.rs --section-start, SAU
 * region 2 in main.rs, and the map at the top of this file, together)
 * rather than deleting the check. */
ASSERT(ADDR(.rodata) + SIZEOF(.rodata) <= 0x100F0000,
    "Secure image has grown into the NSC veneer window at 0x100F0000 -- see memory-secure.x")
