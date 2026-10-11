/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* RP2350A memory map (Pimoroni Tiny 2350: 4 MiB QSPI flash, 520 KiB SRAM).
 *
 * We don't ship a boot stage 2 -- the RP2350 boot ROM handles XIP setup
 * for standard W25Q-class flash automatically. The mandatory pieces are:
 *
 *   1. A .start_block right after .vector_table, in the first 4 KiB of
 *      flash, containing the IMAGE_DEF the boot ROM scans for.
 *   2. .bi_entries after .text so picotool can find the metadata array.
 *   3. .end_block after .uninit (empty for unsigned secure_exe; reserved
 *      for signature blocks if we ever sign images).
 *
 * The three `INSERT AFTER` directives splice these into cortex-m-rt's
 * link.x without us having to vendor that script.
 */

MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 4096K

    /* cortex-m-rt expects the SRAM region to be named RAM. RP2350 has
     * 512 KiB of striped SRAM in banks 0-7 starting at 0x20000000. */
    RAM   : ORIGIN = 0x20000000, LENGTH = 512K

    /* SRAM8/SRAM9 are 4 KiB direct-mapped banks -- useful later for
     * per-core stacks. Declared so link.x can resolve them if needed. */
    SRAM8 : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9 : ORIGIN = 0x20081000, LENGTH = 4K
}

SECTIONS {
    /* RP2350 boot ROM info. Must live in the first 4 KiB of flash, so
     * we splice it right after .vector_table. */
    .start_block : ALIGN(4) {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH
} INSERT AFTER .vector_table;

/* Push .text past the boot info block so code doesn't overlap it. */
_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    /* Picotool 'Binary Info' entries. The IMAGE_DEF in .start_block
     * points to this range via __bi_entries_start / __bi_entries_end. */
    .bi_entries : ALIGN(4) {
        __bi_entries_start = .;
        KEEP(*(.bi_entries));
        . = ALIGN(4);
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

SECTIONS {
    /* RP2350 boot ROM trailing info -- holds an optional signature on
     * signed images. Empty on secure_exe(). */
    .end_block : ALIGN(4) {
        __end_block_addr = .;
        KEEP(*(.end_block));
        __flash_binary_end = .;
    } > FLASH
} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

/* M1: reserve the persistent-storage sectors at the very top of flash
 * so a large `.text` can never grow into them and have `erase_region`
 * wipe live code. Three 4 KiB sectors are reserved (highest first),
 * plus PQF_RESIDENT_EXTRA_SECTORS overflow sectors below them (none by
 * default):
 *
 *   0x103FF000  store sector       (flash_store::STORE_OFFSET)
 *   0x103FE000  large-blob sector  (flash_store::LARGE_BLOB_OFFSET)
 *   0x103FD000  master-key sector  (flash_store::KEY_OFFSET / H1)
 *   0x103FC000  overflow sector 0  (flash_store::overflow_offset(0)), ...
 *
 * `__flash_binary_end` (end of the linked image, set in .end_block
 * above) must stay strictly below the lowest reserved sector. The
 * value below is ORIGIN(FLASH) + LENGTH(FLASH) - (3 + N) * 4 KiB,
 * computed from the MEMORY block so it tracks any future flash-size
 * change. build.rs writes `_pqf_reserved_sectors` (3 + N) into
 * pqf_reserve.x from the same PQF_RESIDENT_EXTRA_SECTORS that sizes the
 * store, so the reservation cannot fall behind it. */
INCLUDE pqf_reserve.x
_reserved_flash_start = ORIGIN(FLASH) + LENGTH(FLASH) - (_pqf_reserved_sectors * 4K);
ASSERT(__flash_binary_end <= _reserved_flash_start,
  "ERROR: firmware image overlaps the reserved flash-store/key sectors at the top of flash");
