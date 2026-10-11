/* memmap_core1riscv.ld -- linker script for the C port's MIXED build
 * (Arm core 0 + RISC-V core 1, CMake -DPQF_CORE1_RISCV=ON).
 *
 * DERIVED FROM pico-sdk's src/rp2_common/pico_crt0/rp2350/
 * memmap_default.ld. It is a verbatim copy of that script with exactly
 * TWO changes -- re-sync this file if you bump the SDK and its default
 * script changes:
 *
 *   1. RAM LENGTH 512k -> 128k. This caps core 0's heap/stack
 *      (__HeapLimit/__StackLimit = ORIGIN(RAM)+LENGTH(RAM)) at
 *      0x2002_0000, leaving 0x2002_0000..0x2008_0000 (384 KiB) for the
 *      RISC-V blob (see core1-riscv-blob/blob.ld). SCRATCH_X/Y (core-0
 *      stacks, 0x2008_0000+) are untouched -- the blob uses its own
 *      stack in its RAM window.
 *      (History: 320k/192-KiB-blob until 2026-07-14 -- the blob's
 *      ML-DSA-65 sign OOM'd at a ~167 KiB fragmented peak -- then
 *      256/256; then 2026-07-16: 192/320, because the blob now copies
 *      its ENTIRE image (.text/.rodata included) into its RAM window at
 *      startup (executing blob code from XIP flash shared the XIP
 *      cache -- 16 KiB, 8-byte lines, 2-way, not direct-mapped unless
 *      XIP_CTRL.SPLIT_WAYS is set -- with core 0's whole firmware, the
 *      mixed-mode CPI-21 stall); then 176/336 later 2026-07-16, because
 *      removing the ExpandA-cache optimization to keep openssl-mini a
 *      clean vendored tree raised the blob's ML-DSA sign heap peak
 *      ~137->167 KiB, so the 320 KiB blob window (162 KiB heap) OOM'd.
 *      Then 128/384 2026-07-17 for ML-DSA-87: its sign heap peak is
 *      ~199 KiB host-measured (+ newlib fragmentation on silicon), over
 *      the 336K window's ~186 KiB heap. Core 0 can spare the 48 KiB:
 *      its last big heap user -- the ML-DSA public-key derive, whose
 *      ~127 KiB L87 keygen peak OOM'd core 0's window and pico_malloc
 *      PANICKED (silicon 2026-07-17, hard MakeCredential wedge) -- moved
 *      to the blob (MB_OP_MLDSA_PUB). What remains on core 0 (CBOR
 *      parse, AES/HMAC credential wrap, PIN-protocol EC at ~20 KiB
 *      peak) fits in the ~45 KiB left after ~81 KiB of bss; the link
 *      fails loudly if statics ever outgrow the window.)
 *
 *   2. A new .core1_blob output section pinned at 0x1018_0000
 *      (PQF_BLOB_FLASH_ORIGIN, core1_mailbox.h). The blob was linked to
 *      run in place there; core 0's own flash (.text/.rodata/.data
 *      init image/.binary_info) must therefore end below 0x1018_0000,
 *      which the explicit section address enforces (the link fails with
 *      "cannot move location counter backwards" if core 0 overruns it).
 *
 * Everything else is the stock SDK layout.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

MEMORY
{
    INCLUDE "pico_flash_region.ld"
    RAM(rwx) : ORIGIN =  0x20000000, LENGTH = 128k   /* CHANGE 1: was 512k (192k/176k during 2026-07-16) */
    SCRATCH_X(rwx) : ORIGIN = 0x20080000, LENGTH = 4k
    SCRATCH_Y(rwx) : ORIGIN = 0x20081000, LENGTH = 4k
}

ENTRY(_entry_point)

SECTIONS
{
    .flash_begin : {
        __flash_binary_start = .;
    } > FLASH

    .text : {
        __logical_binary_start = .;
        KEEP (*(.vectors))
        KEEP (*(.binary_info_header))
        __binary_info_header_end = .;
        KEEP (*(.embedded_block))
        __embedded_block_end = .;
        KEEP (*(.reset))
        *(.init)
        *libgcc.a:cmse_nonsecure_call.o
        /* CHANGE 3: keep the ML-DSA keygen crypto out of XIP flash .text
         * so it falls through to the .data->RAM catch-all below and runs
         * from zero-wait SRAM. On silicon, executing this Keccak/SHAKE-
         * bound path from XIP flash dominated core-0 MakeCredential wall
         * time (flash-fetch stalls, ~17x); from RAM it collapses to ~1 s.
         * Only the keygen path is moved -- core 0 in mixed mode offloads
         * the signature to the RISC-V blob (already in RAM) and does only
         * the ML-DSA public-key derivation here. The P-256 derive (bn/ec)
         * is ms-scale and stays in flash. ~22 KiB; the 256 KiB core-0
         * window holds it with room to spare (see the __StackLimit >=
         * __HeapLimit assert). The object-name list must stay in sync
         * with the .rodata EXCLUDE_FILE list below. */
        *(EXCLUDE_FILE(*libgcc.a: *libc.a:*lib_a-mem*.o *libm.a:
                       *keccak1600.c.o *sha3.c.o *sha256.c.o
                       *ml_dsa_key.c.o *ml_dsa_sample.c.o *ml_dsa_ntt.c.o
                       *ml_dsa_matrix.c.o *ml_dsa_encoders.c.o
                       *ml_dsa_params.c.o *ml_dsa_key_compress.c.o
                       *pqf_mldsa.c.o) .text*)
        *(.fini)
        *crtbegin.o(.ctors)
        *crtbegin?.o(.ctors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .ctors)
        *(SORT(.ctors.*))
        *(.ctors)
        *crtbegin.o(.dtors)
        *crtbegin?.o(.dtors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .dtors)
        *(SORT(.dtors.*))
        *(.dtors)

        . = ALIGN(4);
        PROVIDE_HIDDEN (__preinit_array_start = .);
        KEEP(*(SORT(.preinit_array.*)))
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN (__preinit_array_end = .);

        . = ALIGN(4);
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE_HIDDEN (__init_array_end = .);

        . = ALIGN(4);
        PROVIDE_HIDDEN (__fini_array_start = .);
        *(SORT(.fini_array.*))
        *(.fini_array)
        PROVIDE_HIDDEN (__fini_array_end = .);

        *(.eh_frame*)
        . = ALIGN(4);
    } > FLASH

    .boot2 : {
        __boot2_start__ = .;
        *(.boot2)
        __boot2_end__ = .;
    } > FLASH

    ASSERT(__boot2_end__ - __boot2_start__ <= 256,
        "ERROR: Pico second stage bootloader must be no more than 256 bytes in size")

    .rodata : {
        /* CHANGE 3 (cont.): keep the ML-DSA keygen objects' .rodata (the
         * NTT zeta table, Keccak round constants, etc.) out of flash too,
         * so it rides into RAM with their code. Keep in sync with .text. */
        *(EXCLUDE_FILE(*libgcc.a: *libc.a:*lib_a-mem*.o *libm.a:
                       *keccak1600.c.o *sha3.c.o *sha256.c.o
                       *ml_dsa_key.c.o *ml_dsa_sample.c.o *ml_dsa_ntt.c.o
                       *ml_dsa_matrix.c.o *ml_dsa_encoders.c.o
                       *ml_dsa_params.c.o *ml_dsa_key_compress.c.o
                       *pqf_mldsa.c.o) .rodata*)
        *(.srodata*)
        . = ALIGN(4);
        *(SORT_BY_ALIGNMENT(SORT_BY_NAME(.flashdata*)))
        . = ALIGN(4);
    } > FLASH

    .ARM.extab :
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > FLASH

    __exidx_start = .;
    .ARM.exidx :
    {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > FLASH
    __exidx_end = .;

    /* Machine inspectable binary information */
    . = ALIGN(4);
    __binary_info_start = .;
    .binary_info :
    {
        KEEP(*(.binary_info.keep.*))
        *(.binary_info.*)
    } > FLASH
    __binary_info_end = .;
    . = ALIGN(4);

    .ram_vector_table (NOLOAD): {
        *(.ram_vector_table)
    } > RAM

    .uninitialized_data (NOLOAD): {
        . = ALIGN(4);
        *(.uninitialized_data*)
    } > RAM

    .data : {
        __data_start__ = .;
        *(vtable)

        *(.time_critical*)

        /* remaining .text and .rodata; i.e. stuff we exclude above because we want it in RAM */
        *(.text*)
        . = ALIGN(4);
        *(.rodata*)
        . = ALIGN(4);

        *(.data*)
        *(.sdata*)

        . = ALIGN(4);
        *(.after_data.*)
        . = ALIGN(4);
        PROVIDE_HIDDEN (__mutex_array_start = .);
        KEEP(*(SORT(.mutex_array.*)))
        KEEP(*(.mutex_array))
        PROVIDE_HIDDEN (__mutex_array_end = .);

        *(.jcr)
        . = ALIGN(4);
    } > RAM AT> FLASH

    .tdata : {
        . = ALIGN(4);
		*(.tdata .tdata.* .gnu.linkonce.td.*)
        __tdata_end = .;
    } > RAM AT> FLASH
    PROVIDE(__data_end__ = .);

    __etext = LOADADDR(.data);

    .tbss (NOLOAD) : {
        . = ALIGN(4);
        __bss_start__ = .;
        __tls_base = .;
        *(.tbss .tbss.* .gnu.linkonce.tb.*)
        *(.tcommon)

        __tls_end = .;
    } > RAM

    .bss (NOLOAD) : {
        . = ALIGN(4);
        __tbss_end = .;

        *(SORT_BY_ALIGNMENT(SORT_BY_NAME(.bss*)))
        *(COMMON)
        PROVIDE(__global_pointer$ = . + 2K);
        *(.sbss*)
        . = ALIGN(4);
        __bss_end__ = .;
    } > RAM

    .heap (NOLOAD):
    {
        __end__ = .;
        end = __end__;
        KEEP(*(.heap*))
    } > RAM
    __HeapLimit = ORIGIN(RAM) + LENGTH(RAM);

    /* Start and end symbols must be word-aligned */
    .scratch_x : {
        __scratch_x_start__ = .;
        *(.scratch_x.*)
        . = ALIGN(4);
        __scratch_x_end__ = .;
    } > SCRATCH_X AT > FLASH
    __scratch_x_source__ = LOADADDR(.scratch_x);

    .scratch_y : {
        __scratch_y_start__ = .;
        *(.scratch_y.*)
        . = ALIGN(4);
        __scratch_y_end__ = .;
    } > SCRATCH_Y AT > FLASH
    __scratch_y_source__ = LOADADDR(.scratch_y);

    .stack1_dummy (NOLOAD):
    {
        *(.stack1*)
    } > SCRATCH_X
    .stack_dummy (NOLOAD):
    {
        KEEP(*(.stack*))
    } > SCRATCH_Y

    /* CHANGE 2: the RISC-V core-1 blob, pinned to its link address so it
     * executes in place. Must sit above core 0's flash usage (enforced
     * by the explicit address) and below the 2 MiB mark (Feitian, whose
     * unprogrammed FLASH_DEVINFO makes picotool assume a 2 MiB part). */
    .core1_blob 0x10180000 : {
        . = ALIGN(4);
        __core1_blob_start = .;
        KEEP(*(.core1_blob))
        . = ALIGN(4);
        __core1_blob_end = .;
    } > FLASH

    .flash_end : {
        KEEP(*(.embedded_end_block*))
        PROVIDE(__flash_binary_end = .);
    } > FLASH =0xaa

    __StackLimit = ORIGIN(RAM) + LENGTH(RAM);
    __StackOneTop = ORIGIN(SCRATCH_X) + LENGTH(SCRATCH_X);
    __StackTop = ORIGIN(SCRATCH_Y) + LENGTH(SCRATCH_Y);
    __StackOneBottom = __StackOneTop - SIZEOF(.stack1_dummy);
    __StackBottom = __StackTop - SIZEOF(.stack_dummy);
    PROVIDE(__stack = __StackTop);

    /* picolibc and LLVM */
    PROVIDE (__heap_start = __end__);
    PROVIDE (__heap_end = __HeapLimit);
    PROVIDE( __tls_align = MAX(ALIGNOF(.tdata), ALIGNOF(.tbss)) );
    PROVIDE( __tls_size_align = (__tls_size + __tls_align - 1) & ~(__tls_align - 1));
    PROVIDE( __arm32_tls_tcb_offset = MAX(8, __tls_align) );

    /* llvm-libc */
    PROVIDE (_end = __end__);
    PROVIDE (__llvm_libc_heap_limit = __HeapLimit);

    ASSERT(__StackLimit >= __HeapLimit, "region RAM overflowed")

    ASSERT( __binary_info_header_end - __logical_binary_start <= 1024, "Binary info must be in first 1024 bytes of the binary")
    ASSERT( __embedded_block_end - __logical_binary_start <= 4096, "Embedded block must be in first 4096 bytes of the binary")

    /* CHANGE 2 guards: blob at its link address, and the whole image
     * below the 2 MiB Feitian ceiling. */
    ASSERT(__core1_blob_start == 0x10180000,
        "core1 blob not at 0x10180000 (core 0 flash overran its 1.5 MiB budget?)")
    ASSERT(__core1_blob_end <= 0x10200000,
        "core1 blob overruns the 2 MiB mark (Feitian FLASH_DEVINFO ceiling)")
}
