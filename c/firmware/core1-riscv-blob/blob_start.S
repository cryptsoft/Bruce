/* blob_start.S -- RISC-V core-1 blob entry/trap, at fixed offsets the
 * core-0 launcher hands the boot ROM (see core1_mailbox.h):
 *   BFLASH + 0  pqf_blob_trap   -> MTVEC (a wfi parking loop; a fault
 *                                  in the blob spins here rather than
 *                                  jumping wild)
 *   BFLASH + 8  pqf_blob_entry  -> initial PC
 * The boot-ROM FIFO launch also sets SP; we re-load it from the linker
 * symbol anyway (belt-and-braces) and set gp before any global access
 * (gp/linker-relaxation is not set by the launch), then hand off to the
 * C crt0 (blob_startup), which never returns.
 *
 * .option norvc keeps every instruction 4 bytes so the +0 / +8 offset
 * contract holds; norelax around the gp load stops the assembler
 * relaxing `la gp` into a gp-relative load of gp itself.
 * SPDX-License-Identifier: Apache-2.0
 */
    .section .blob_entry, "ax"
    .option norvc

    .globl pqf_blob_trap
pqf_blob_trap:                 /* offset 0 -- MTVEC (direct mode) */
    wfi
    j       pqf_blob_trap

    .globl pqf_blob_entry
pqf_blob_entry:                /* offset 8 -- initial PC */
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop
    la      sp, __blob_stack_top
    call    blob_startup       /* C crt0 (.data copy, .bss zero, blob_main) */
1:  wfi                        /* unreachable -- blob_startup is noreturn */
    j       1b
