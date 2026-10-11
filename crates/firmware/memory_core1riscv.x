/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* RP2350A memory map for the MIXED-ARCHITECTURE build (`core1_riscv`
 * feature): Arm firmware on core 0 + embedded RISC-V payload for
 * core 1. build.rs installs this file AS `memory.x` in OUT_DIR when
 * the feature is on; the plain memory.x is used otherwise.
 *
 * Differences from memory.x (the single normative home for the
 * shared addresses is `pqf_signer_core::mixed` -- keep all three in
 * sync: that module, this file, and crates/fw-core1-riscv/blob.x):
 *
 *   - FLASH shrinks to 1.5 MiB; the next 512 KiB window (0x1018_0000,
 *     ending at the 2 MiB mark -- see the MEMORY comment below)
 *     becomes the BLOB region, holding the riscv32 core-1 payload
 *     that build.rs compiles from crates/fw-core1-riscv and embeds
 *     via the `.core1_blob` section. Core 1 executes it from there
 *     over XIP.
 *   - RAM shrinks to 384 KiB; 0x2006_0000..0x2008_0000 (128 KiB)
 *     becomes core 1's private window (.data/.bss/heap + 64 KiB
 *     stack), owned by the payload's own linker script.
 *
 * Everything else -- the boot blocks, the flash-store reserve -- is
 * identical to memory.x; see the comments there.
 */

MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 1536K

    /* RISC-V core-1 payload window -- pqf_signer_core::mixed::BLOB_FLASH_*.
     * Ends exactly at the 2 MiB mark so the whole mixed image stays
     * loadable by picotool on boards with an unprogrammed
     * FLASH_DEVINFO row (assumed-2 MiB flash) and on real 2 MiB
     * parts. */
    BLOB  : ORIGIN = 0x10180000, LENGTH = 512K

    /* Striped SRAM banks 0-7, minus the 128 KiB granted to core 1.
     * cortex-m-rt puts core 0's stack top at the end of this region
     * (0x2006_0000), so nothing on core 0 can reach the blob window. */
    RAM   : ORIGIN = 0x20000000, LENGTH = 384K

    /* Blob RAM window (core 1) -- pqf_signer_core::mixed::BLOB_RAM_*.
     * Declared for documentation; no firmware section lands here. */
    BRAM  : ORIGIN = 0x20060000, LENGTH = 128K

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

SECTIONS {
    /* The riscv32 core-1 payload, embedded as raw bytes (the
     * include_bytes! static in core1_launch.rs). Its internal layout
     * is linked by crates/fw-core1-riscv/blob.x against this exact
     * base address -- ASSERTed on both sides. */
    .core1_blob : ALIGN(4) {
        __core1_blob_start = .;
        KEEP(*(.core1_blob));
        __core1_blob_end = .;
    } > BLOB
} INSERT AFTER .end_block;

/* Guarded two ways: SIZEOF()==0 lets the `button_scan` helper bin --
 * which never references the payload static -- link with an empty
 * (discarded) .core1_blob; and ADDR() is used rather than the
 * section-internal __core1_blob_start symbol, which rust-lld
 * evaluates section-relative (i.e. 0) in a top-level ASSERT. */
ASSERT(SIZEOF(.core1_blob) == 0 || ADDR(.core1_blob) == ORIGIN(BLOB),
  "ERROR: .core1_blob did not land at the launch address pqf_signer_core::mixed::BLOB_FLASH_ORIGIN");

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

/* M1: reserve the persistent-storage sectors at the very top of flash
 * so nothing can grow into them and have `erase_region` wipe live
 * code. Three 4 KiB sectors are reserved (highest first), plus the
 * PQF_RESIDENT_EXTRA_SECTORS overflow sectors below them (none by
 * default; build.rs writes `_pqf_reserved_sectors` = 3 + N into
 * pqf_reserve.x):
 *
 *   0x103FF000  store sector       (flash_store::STORE_OFFSET)
 *   0x103FE000  large-blob sector  (flash_store::LARGE_BLOB_OFFSET)
 *   0x103FD000  master-key sector  (flash_store::KEY_OFFSET / H1)
 *
 * The firmware image is capped by its 1.5 MiB FLASH region and the
 * blob by its 512 KiB BLOB region (ending 0x1020_0000), so both stay
 * clear of the reserve; the ASSERTs keep it that way if the regions
 * ever change. The store offsets themselves are absolute, so a mixed
 * image reflash never strands persisted credentials. */
INCLUDE pqf_reserve.x
_reserved_flash_start = 0x10400000 - (_pqf_reserved_sectors * 4K);
ASSERT(__flash_binary_end <= _reserved_flash_start,
  "ERROR: firmware image overlaps the reserved flash-store/key sectors at the top of flash");
ASSERT(ORIGIN(BLOB) + LENGTH(BLOB) <= _reserved_flash_start,
  "ERROR: core-1 blob window overlaps the reserved flash-store/key sectors at the top of flash");
