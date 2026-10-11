/* flash_reserve_assert.ld -- build-time guard for the reserved
 * top-of-flash sectors (audit #24, the C-port analog of the Rust
 * memory.x ASSERT).
 *
 * The firmware reserves FOUR 4 KiB sectors at the very top of flash,
 * each at PICO_FLASH_SIZE_BYTES - N*FLASH_SECTOR_SIZE, plus one more
 * per PQF_RESIDENT_EXTRA_SECTORS (none by default):
 *
 *     last - 1 sector : store  -- counter + PIN + config (flash_store.c)
 *     last - 2 sector : resident credentials            (resident_store.c)
 *     last - 3 sector : large blobs                     (large_blobs.c)
 *     last - 4 sector : device master keys              (flash_store.c, H1)
 *     last - 5 - k    : resident overflow sector k      (resident_store.c)
 *
 * This file is a template: CMakeLists.txt configure_file()s it into the
 * build directory with @PQF_RESERVED_SECTORS@ / @PQF_RESERVED_BYTES@
 * filled in from the same PQF_RESIDENT_EXTRA_SECTORS it compiles
 * resident_store.c with, and links that copy.
 *
 * The pico-sdk default linker grows .text/.rodata upward from
 * ORIGIN(FLASH) with no check, so a sufficiently large image could
 * collide with these sectors; the first commit()'s flash_range_erase
 * would then erase live code. This is a NON-replacing fragment: the
 * `INSERT AFTER .text` keeps the SDK's default linker script and only
 * adds the link-time ASSERT below, which fires if the linked image
 * does not end strictly below the first reserved sector.
 * ORIGIN(FLASH)/LENGTH(FLASH) come from the SDK's generated
 * pico_flash_region.ld (LENGTH == PICO_FLASH_SIZE_BYTES), so the bound
 * tracks whatever flash window the selected board uses.
 *
 * @PQF_RESERVED_BYTES@ == (4 + PQF_RESIDENT_EXTRA_SECTORS) * 4096
 * (16384 by default) on the RP2350. If the SDK ever changes
 * FLASH_SECTOR_SIZE, update CMakeLists.txt and the per-sector offsets
 * in flash_store.c / resident_store.c / large_blobs.c together.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

ASSERT(__flash_binary_end <= ORIGIN(FLASH) + LENGTH(FLASH) - @PQF_RESERVED_BYTES@, "firmware image overlaps the @PQF_RESERVED_SECTORS@ reserved top-of-flash sectors (store/resident/large-blob/key/resident overflow)")

INSERT AFTER .text
