/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Linker script for the pqf-core1-riscv payload -- the RISC-V core-1
 * blob embedded in the mixed-architecture Arm firmware image.
 *
 * The addresses here are cross-link-unit ABI shared with the Arm
 * firmware; the single normative definition is
 * `pqf_signer_core::mixed` (crates/signer-core/src/mixed.rs). If you
 * change one, change all three (this file, that module, and the
 * firmware's memory_core1riscv.x), and the ASSERTs below will catch
 * most mismatches.
 *
 * Layout contract with the launcher (see the ASSERTs):
 *   BFLASH+0  trap parking loop  (handed to core 1 as MTVEC)
 *   BFLASH+8  entry point        (handed to core 1 as initial PC)
 *   initial SP = top of BRAM     (16-byte aligned)
 *
 * No riscv-rt: the boot-ROM launch handshake sets PC/SP/MTVEC, and
 * the payload's own `.blob_entry` asm (src/main.rs) does gp init and
 * the .data copy / .bss zero. There is no vector table and no
 * IMAGE_DEF -- this is not a bootable image, just machine code the
 * firmware places and launches.
 */

MEMORY {
    /* Flash execution window (XIP) -- pqf_signer_core::mixed::BLOB_FLASH_*. */
    BFLASH : ORIGIN = 0x10180000, LENGTH = 512K
    /* RAM window -- pqf_signer_core::mixed::BLOB_RAM_*. Data/bss/heap
     * grow up from the bottom; the 64 KiB stack grows down from the
     * top (initial SP = 0x20080000, set by the launcher). */
    BRAM   : ORIGIN = 0x20060000, LENGTH = 128K
}

ENTRY(pqf_blob_trap)

SECTIONS
{
  .text ORIGIN(BFLASH) :
  {
    /* Entry/trap asm first -- pins the +0 / +8 offsets. */
    KEEP(*(.blob_entry));
    *(.text .text.*);
    . = ALIGN(4);
  } > BFLASH

  .rodata : ALIGN(4)
  {
    *(.srodata .srodata.*);
    *(.rodata .rodata.*);
    . = ALIGN(4);
  } > BFLASH

  .data : ALIGN(4)
  {
    __sdata = .;
    /* Must be called __global_pointer$ for linker relaxations to work. */
    PROVIDE(__global_pointer$ = . + 0x800);
    *(.sdata .sdata.* .sdata2 .sdata2.*);
    /* Includes .data.ramfunc -- Core1Signer::park_spin must execute
     * from RAM while core 0 holds the QSPI in command mode. */
    *(.data .data.*);
    . = ALIGN(4);
    __edata = .;
  } > BRAM AT > BFLASH
  __sidata = LOADADDR(.data);

  .bss (NOLOAD) : ALIGN(4)
  {
    __sbss = .;
    *(.sbss .sbss.* .bss .bss.*);
    . = ALIGN(4);
    __ebss = .;
  } > BRAM

  /* Detect accidental PIC / dynamic relocations, riscv-rt style. */
  .got (INFO) :
  {
    KEEP(*(.got .got.*));
  }

  .eh_frame (INFO) : { KEEP(*(.eh_frame)) }
  .eh_frame_hdr (INFO) : { *(.eh_frame_hdr) }
}

ASSERT(pqf_blob_trap == ORIGIN(BFLASH), "
ERROR(blob.x): trap loop is not at BFLASH+0 -- the launcher's MTVEC word
(pqf_signer_core::mixed::BLOB_TRAP_OFFSET) would point at garbage");

ASSERT(pqf_blob_entry == ORIGIN(BFLASH) + 8, "
ERROR(blob.x): entry point is not at BFLASH+8 -- the launcher's PC word
(pqf_signer_core::mixed::BLOB_ENTRY_OFFSET) would point at garbage");

ASSERT(SIZEOF(.got) == 0, "
ERROR(blob.x): .got section detected -- dynamic relocations are not
supported in the blob");

/* Keep .data/.bss (and the heap static inside .bss) clear of the
 * 64 KiB stack window at the top of BRAM. */
ASSERT(__ebss <= ORIGIN(BRAM) + LENGTH(BRAM) - 64K, "
ERROR(blob.x): blob .data/.bss/heap overlap the 64 KiB core-1 stack
window at the top of BRAM");
