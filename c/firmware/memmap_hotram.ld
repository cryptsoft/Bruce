/* memmap_hotram.ld -- linker script for SINGLE-ISA builds that run from
 * XIP flash (CMake -DPQF_HOT_IN_RAM=ON; the default whenever
 * PQF_COPY_TO_RAM is off and PQF_CORE1_RISCV is off, i.e. the level-87
 * arena build and any -DPQF_COPY_TO_RAM=0 build).
 *
 * DERIVED FROM pico-sdk's src/rp2_common/pico_crt0/rp2350/
 * memmap_default.ld. It is a verbatim copy of that script with exactly
 * ONE change, applied in two places -- re-sync this file if you bump
 * the SDK and its default script changes:
 *
 *   1. The ML-DSA + Keccak/SHA3 hot object set is EXCLUDE_FILE'd out of
 *      the flash .text and .rodata wildcards, so it falls through to
 *      the `.data { *(.text*) *(.rodata*) } > RAM AT> FLASH` catch-all
 *      near the bottom and executes from zero-wait SRAM (crt0 copies it
 *      with the rest of .data at boot).
 *
 * Why: the RP2350's XIP cache is 16 KiB, 8-byte lines, 2-way
 * (XIP_CTRL.SPLIT_WAYS = 0 at reset; set it and you get two 8 KiB
 * direct-mapped halves instead). The linked image is ~170 KiB of .text
 * plus ~25 KiB of .rodata -- 12x oversubscribed -- but the ML-DSA sign
 * path's own working set is only ~18 KiB of .text and ~1.7 KiB of
 * .rodata, which WOULD fit. What kills it is conflict misses against
 * the other ~175 KiB, not capacity: on silicon, running this path from
 * XIP costs roughly CPI 200 (a ~15 s sign) against roughly CPI 1.2 from
 * SRAM. Copying only the hot set out of the cache's way leaves the
 * remaining cold code with the whole cache to itself.
 *
 * Cost, measured on the level-87 Feitian build: 20,096 bytes move from
 * flash .text/.rodata into .data, i.e. 20 KiB of SRAM, which takes the
 * core-0 newlib heap from 185,136 B down to 165,040 B -- still eight
 * times core 0's ~20 KiB working peak (the sign itself runs on the
 * PQF_SIGN_ARENA, not the heap). Note the FLASH image does not shrink:
 * the same bytes are still stored there, now as part of .data's LOAD
 * image, and crt0 copies 20 KiB more at boot.
 *
 * Builds at levels 44/65 don't need this -- they are copy_to_ram, so
 * every byte of .text is already in SRAM and CMake forces the option
 * off. The mixed Arm+RISC-V build doesn't use it either: it selects
 * memmap_core1riscv.ld, which carries its own (deliberately shorter)
 * copy of the same exclusion -- see the two notes on ml_dsa_sign.c.o
 * below.
 *
 * Original SDK header follows.
 *
 * Based on GCC ARM embedded samples.
 * Defines the following symbols for use by code:
 *  __exidx_start
 *  __exidx_end
 *  __etext
 *  __data_start__
 *  __preinit_array_start
 *  __preinit_array_end
 *  __init_array_start
 *  __init_array_end
 *  __fini_array_start
 *  __fini_array_end
 *  __data_end__
 *  __bss_start__
 *  __bss_end__
 *  __end__
 *  end
 *  __HeapLimit
 *  __StackLimit
 *  __StackTop
 *  __stack (== StackTop)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

MEMORY
{
    INCLUDE "pico_flash_region.ld"
    RAM(rwx) : ORIGIN =  0x20000000, LENGTH = 512k
    SCRATCH_X(rwx) : ORIGIN = 0x20080000, LENGTH = 4k
    SCRATCH_Y(rwx) : ORIGIN = 0x20081000, LENGTH = 4k
}

ENTRY(_entry_point)

SECTIONS
{
    .flash_begin : {
        __flash_binary_start = .;
    } > FLASH

    /* The bootrom will enter the image at the point indicated in your
       IMAGE_DEF, which is usually the reset handler of your vector table.

       The debugger will use the ELF entry point, which is the _entry_point
       symbol, and in our case is *different from the bootrom's entry point.*
       This is used to go back through the bootrom on debugger launches only,
       to perform the same initial flash setup that would be performed on a
       cold boot.
    */

    .text : {
        __logical_binary_start = .;
        KEEP (*(.vectors))
        KEEP (*(.binary_info_header))
        __binary_info_header_end = .;
        KEEP (*(.embedded_block))
        __embedded_block_end = .;
        KEEP (*(.reset))
        /* TODO revisit this now memset/memcpy/float in ROM */
        /* bit of a hack right now to exclude all floating point and time critical (e.g. memset, memcpy) code from
         * FLASH ... we will include any thing excluded here in .data below by default */
        *(.init)
        *libgcc.a:cmse_nonsecure_call.o
        /* CHANGE 1: keep the ML-DSA / Keccak / SHA3 hot set out of XIP
         * flash .text so it drops through to the .data->RAM catch-all
         * below and runs from zero-wait SRAM.
         *
         * The list is memmap_core1riscv.ld's plus ml_dsa_sign.c.o. The
         * mixed script omits the signer on purpose -- there core 0 only
         * derives the ML-DSA public key and the RISC-V blob (already
         * all-RAM) does the signature, so the ~2.8 KiB would be dead
         * weight in a 128 KiB window. Single-ISA has no blob: core 1
         * signs out of this same image, and ossl_ml_dsa_sign is the
         * single largest hot function in it, so it MUST be here.
         *
         * ld's file globs span '/', so *sha256.c.o also catches
         * pqf_sha256.c.o and pqf_hmac_sha256.c.o. That is wanted (both
         * are on the credential path and total well under 1 KiB), but
         * it is why the moved footprint is a little larger than the
         * object names suggest.
         *
         * The object-name list must stay in sync with the .rodata
         * EXCLUDE_FILE list below -- an object whose code moves to RAM
         * while its tables stay in flash still pays the XIP stall on
         * every table lookup, which is most of what Keccak and the NTT
         * do. */
        *(EXCLUDE_FILE(*libgcc.a: *libc.a:*lib_a-mem*.o *libm.a:
                       *keccak1600.c.o *sha3.c.o *sha256.c.o
                       *ml_dsa_key.c.o *ml_dsa_sample.c.o *ml_dsa_ntt.c.o
                       *ml_dsa_matrix.c.o *ml_dsa_encoders.c.o
                       *ml_dsa_params.c.o *ml_dsa_key_compress.c.o
                       *ml_dsa_sign.c.o *pqf_mldsa.c.o) .text*)
        *(.fini)
        /* Pull all c'tors into .text */
        *crtbegin.o(.ctors)
        *crtbegin?.o(.ctors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .ctors)
        *(SORT(.ctors.*))
        *(.ctors)
        /* Followed by destructors */
        *crtbegin.o(.dtors)
        *crtbegin?.o(.dtors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .dtors)
        *(SORT(.dtors.*))
        *(.dtors)

        . = ALIGN(4);
        /* preinit data */
        PROVIDE_HIDDEN (__preinit_array_start = .);
        KEEP(*(SORT(.preinit_array.*)))
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN (__preinit_array_end = .);

        . = ALIGN(4);
        /* init data */
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE_HIDDEN (__init_array_end = .);

        . = ALIGN(4);
        /* finit data */
        PROVIDE_HIDDEN (__fini_array_start = .);
        *(SORT(.fini_array.*))
        *(.fini_array)
        PROVIDE_HIDDEN (__fini_array_end = .);

        *(.eh_frame*)
        . = ALIGN(4);
    } > FLASH

    /* Note the boot2 section is optional, and should be discarded if there is
       no reference to it *inside* the binary, as it is not called by the
       bootrom. (The bootrom performs a simple best-effort XIP setup and
       leaves it to the binary to do anything more sophisticated.) However
       there is still a size limit of 256 bytes, to ensure the boot2 can be
       stored in boot RAM.

       Really this is a "XIP setup function" -- the name boot2 is historic and
       refers to its dual-purpose on RP2040, where it also handled vectoring
       from the bootrom into the user image.
    */

    .boot2 : {
        __boot2_start__ = .;
        *(.boot2)
        __boot2_end__ = .;
    } > FLASH

    ASSERT(__boot2_end__ - __boot2_start__ <= 256,
        "ERROR: Pico second stage bootloader must be no more than 256 bytes in size")

    .rodata : {
        /* CHANGE 1 (cont.): the same objects' .rodata -- the NTT zeta
         * table, the Keccak round constants, the SHA-256 K table --
         * rides into RAM with their code. Keep in sync with .text. */
        *(EXCLUDE_FILE(*libgcc.a: *libc.a:*lib_a-mem*.o *libm.a:
                       *keccak1600.c.o *sha3.c.o *sha256.c.o
                       *ml_dsa_key.c.o *ml_dsa_sample.c.o *ml_dsa_ntt.c.o
                       *ml_dsa_matrix.c.o *ml_dsa_encoders.c.o
                       *ml_dsa_params.c.o *ml_dsa_key_compress.c.o
                       *ml_dsa_sign.c.o *pqf_mldsa.c.o) .rodata*)
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
        /* preinit data */
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
        /* All data end */
        __tdata_end = .;
    } > RAM AT> FLASH
    PROVIDE(__data_end__ = .);

    /* __etext is (for backwards compatibility) the name of the .data init source pointer (...) */
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
    /* historically on GCC sbrk was growing past __HeapLimit to __StackLimit, however
       to be more compatible, we now set __HeapLimit explicitly to where the end of the heap is */
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

    /* .stack*_dummy section doesn't contains any symbols. It is only
     * used for linker to calculate size of stack sections, and assign
     * values to stack symbols later
     *
     * stack1 section may be empty/missing if platform_launch_core1 is not used */

    /* by default we put core 0 stack at the end of scratch Y, so that if core 1
     * stack is not used then all of SCRATCH_X is free.
     */
    .stack1_dummy (NOLOAD):
    {
        *(.stack1*)
    } > SCRATCH_X
    .stack_dummy (NOLOAD):
    {
        KEEP(*(.stack*))
    } > SCRATCH_Y

    .flash_end : {
        KEEP(*(.embedded_end_block*))
        PROVIDE(__flash_binary_end = .);
    } > FLASH =0xaa

    /* stack limit is poorly named, but historically is maximum heap ptr */
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

    /* Check if data + heap + stack exceeds RAM limit */
    ASSERT(__StackLimit >= __HeapLimit, "region RAM overflowed")

    ASSERT( __binary_info_header_end - __logical_binary_start <= 1024, "Binary info must be in first 1024 bytes of the binary")
    ASSERT( __embedded_block_end - __logical_binary_start <= 4096, "Embedded block must be in first 4096 bytes of the binary")

    /* todo assert on extra code */
}

