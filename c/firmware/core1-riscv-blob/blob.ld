/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Linker script for the RISC-V core-1 signing blob (C port mixed mode).
 *
 * Addresses are cross-link-unit ABI -- keep in sync with
 * c/firmware/src/core1_mailbox.h (PQF_BLOB_*) and the CMake
 * memory_core1riscv layout for the Arm image. Not a bootable image: no
 * vector table, no RP2350 IMAGE_DEF. The core-0 firmware places these
 * bytes at BFLASH and launches them (MTVEC=+0, PC=+8, SP=stack top).
 *
 * RAM window is 320 KiB (vs the Rust blob's 128 KiB) because
 * openssl-mini's ML-DSA-65 is the full-fat variant, not the low-memory
 * one, AND (2026-07-16) the ENTIRE image -- .text and .rodata included --
 * is copied to BRAM at startup and executes from SRAM. Executing the
 * blob from its BFLASH XIP window shares the RP2350's single XIP cache
 * -- 16 KiB, 8-byte lines, 2-way (XIP_CTRL.SPLIT_WAYS is 0 at reset;
 * set it and you get two 8 KiB direct-mapped halves instead) -- with
 * core 0's whole firmware (which runs from XIP in mixed mode); two
 * ways are no defence against a 12x oversubscribed image, and that
 * thrash was the mixed-mode ~CPI-21 stall
 * (~15 s MakeCredential, silicon-measured). Only the trap/entry stub
 * and the startup copy code (.boot_text) stay in BFLASH.
 *
 * Heap sizing (silicon-confirmed 2026-07-14, pre-ExpandA-cache): the
 * ML-DSA-65 sign does a SINGLE contiguous OPENSSL_malloc of ~89 KiB
 * (88 polynomials + the w1 buffer) ON TOP OF a heap already ~78 KiB
 * deep -- ECDSA's freed-but-fragmented allocations sit below, and
 * ML-DSA keygen's expanded key is live -- a ~167 KiB contiguous peak;
 * the ExpandA matrix cache (44ca0fb) drops it to ~137 KiB. This layout
 * leaves ~160 KiB of heap. If a sign ever OOMs here, _sbrk stamps
 * MB_DBG_HEAP_OOM with the bytes in use -- trim STACK_SIZE before
 * touching the window split.
 */

MEMORY {
    BFLASH : ORIGIN = 0x10180000, LENGTH = 512K
    BRAM   : ORIGIN = 0x20020000, LENGTH = 384K   /* was 0x20030000/320K;
                                                   * grown 320->336 (2026-07-16)
                                                   * after the ExpandA cache was
                                                   * removed (clean vendored
                                                   * crypto), raising the ML-DSA
                                                   * -65 sign heap peak ~137->167;
                                                   * grown 336->384 (2026-07-17)
                                                   * for ML-DSA-87, whose sign
                                                   * peak is ~199 KiB host-
                                                   * measured (44/65/87 =
                                                   * 99/143/199) + newlib
                                                   * fragmentation on silicon.
                                                   * ~233 KiB heap now. */
}

/* 40 KiB. NOTE: a 32->48 KiB bump was made during 2026-07-10 bring-up on
 * a "stack-overflow" hypothesis for signs failing at an unpredictable
 * point with heap "under 80 KiB and no OOM reported". That diagnosis
 * was WRONG -- the real cause was the heap OOM described in the header
 * comment (the failing _sbrk never updated the high-water, so heap
 * looked stuck ~80 KiB, and its HEAP_OOM marker was clobbered by
 * MLDSA_FAIL). Trimmed 48->40 KiB in the 2026-07-16 all-RAM relayout,
 * then ->32 KiB when the ExpandA cache was removed (clean vendored
 * crypto): the freed 8 KiB goes to the heap, which now has to clear the
 * ~167 KiB (not ~137) sign peak. 32 KiB is still several times any
 * plausible frame depth for this EC + lattice code (and was the
 * pre-2026-07-10 historical value). Heap keeps ML-DSA's polynomial
 * buffers (OPENSSL_malloc), not the stack. */
STACK_SIZE = 0x8000;

ENTRY(pqf_blob_trap)

SECTIONS
{
  /* Flash-resident boot: the +0/+8 entry contract plus blob_startup,
   * which copies .text/.rodata/.data into BRAM (it cannot itself run
   * from a section it is still copying). Everything else executes from
   * SRAM. */
  .boot ORIGIN(BFLASH) : {
    KEEP(*(.blob_entry));          /* pins the +0 / +8 offset contract */
    *(.boot_text .boot_text.*);
    . = ALIGN(4);
  } > BFLASH

  /* The launch contract: MTVEC = origin+0, PC = origin+8 (see
   * core1_mailbox.h PQF_BLOB_{TRAP,ENTRY}_OFFSET). .option norvc keeps
   * the assembler from compressing the two entry instructions, but
   * LINKER relaxation could still shrink the trap's `j` to a 2-byte
   * c.j and slide pqf_blob_entry off +8. Fail the link loudly if it
   * ever does rather than ship a blob that faults on launch. */
  ASSERT(pqf_blob_trap  == ORIGIN(BFLASH),     "blob: trap not at flash origin")
  ASSERT(pqf_blob_entry == ORIGIN(BFLASH) + 8, "blob: entry not at origin+8 (relaxation moved it?)")

  /* Code + read-only data, resident in BRAM, loaded from BFLASH.
   * One output section so blob_startup copies it as one range
   * ([__text_start,__text_end) from __text_load). */
  .text : ALIGN(4) {
    __text_start = .;
    *(.text .text.*);
    . = ALIGN(4);
    *(.srodata .srodata.*);
    *(.rodata .rodata.*);
    . = ALIGN(4);
    __text_end = .;
  } > BRAM AT > BFLASH
  __text_load = LOADADDR(.text);

  /* .data + .ram_text: resident in BRAM, loaded from BFLASH. The C
   * crt0 (blob_startup) copies [__data_start,__data_end) from
   * __data_load. .ram_text (park_spin) rides along; it predates the
   * all-RAM layout (when only it was RAM-resident) and keeping the
   * section costs nothing. */
  .data : ALIGN(4) {
    __data_start = .;
    PROVIDE(__global_pointer$ = . + 0x800);
    *(.sdata .sdata.* .sdata2 .sdata2.*);
    *(.data .data.*);
    . = ALIGN(4);
    *(.ram_text .ram_text.*);
    . = ALIGN(4);
    __data_end = .;
  } > BRAM AT > BFLASH
  __data_load = LOADADDR(.data);

  .bss (NOLOAD) : ALIGN(4) {
    __bss_start = .;
    *(.sbss .sbss.* .bss .bss.*);
    *(COMMON);
    . = ALIGN(8);
    __bss_end = .;
  } > BRAM

  /* Heap grows up from here to __heap_end; stack grows down from the
   * top of BRAM. _sbrk (blob_main.c) hands out the heap. */
  __heap_start = .;
  __blob_stack_top = ORIGIN(BRAM) + LENGTH(BRAM);
  __heap_end = __blob_stack_top - STACK_SIZE;

  ASSERT(__heap_end > __heap_start, "blob: no room for heap")
  ASSERT(__heap_end - __heap_start >= 0x2B000,
         "blob: heap < 172 KiB -- ML-DSA-65 sign's fragmented peak is ~167 KiB (no ExpandA cache; clean vendored crypto)")

  /* Dynamic relocations unsupported -- catch accidental PIC. */
  .got (INFO) : { KEEP(*(.got .got.*)); }
  ASSERT(SIZEOF(.got) == 0, "blob: .got present -- build with -fno-pic")

  /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
