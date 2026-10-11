/* core1_blob.S -- embed the RISC-V core-1 signing blob into the Arm
 * image. The bytes go in the .core1_blob section, which
 * memmap_core1riscv.ld pins at PQF_BLOB_FLASH_ORIGIN (0x1018_0000) so
 * they execute in place (XIP) at exactly the addresses blob.ld linked
 * them for. This is the C analog of the Rust port's
 *   #[link_section = ".core1_blob"] static CORE1_BLOB = *include_bytes!(...)
 *
 * core1_blob.bin is produced by build_blob.sh (cross-compiled riscv32)
 * at build time; CMake adds the build dir to the assembler's include
 * path so the relative .incbin resolves. "a" (alloc, non-exec): the Arm
 * core never executes these bytes -- only the Hazard3 core 1 does -- so
 * from the Arm linker's view it is allocated flash data.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
    .section .core1_blob, "a"
    .balign 4
    .global core1_blob_start
core1_blob_start:
    .incbin "core1_blob.bin"
    .balign 4
    .global core1_blob_end
core1_blob_end:
