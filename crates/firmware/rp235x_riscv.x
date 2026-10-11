/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* RISC-V (Hazard3) linker script for the RP2350A PQC FIDO2 firmware.
 *
 * Adapted from rp-hal's `rp235x-hal-examples/rp235x_riscv.x` at the
 * rp235x-hal-0.4.0 tag (MIT OR Apache-2.0), which is in turn derived
 * from riscv-rt 0.12's `link.x`. Unlike the Arm build -- where
 * cortex-m-rt's `link.x` is used as-is and `memory.x` splices our
 * sections in via INSERT AFTER -- the RISC-V build uses this single
 * self-contained script (passed via `-Trp235x_riscv.x` in
 * `.cargo/config.toml`; riscv-rt's own `link.x` is not used).
 *
 * Local changes versus the rp-hal original:
 *   - MEMORY block matches ours in `memory.x`: 4 MiB flash (Tiny 2350
 *     et al.), 512 KiB striped SRAM, SRAM8/SRAM9 declared.
 *   - The M1 flash-store reserve ASSERT from `memory.x` is reproduced
 *     at the bottom: the image must stay clear of the persistent 4 KiB
 *     sectors at the top of flash (three, plus any overflow sectors).
 *   - `.data.ramfunc` needs no special handling here: the `.data` glob
 *     below (`*(.data .data.*)`) already places it in RAM with a flash
 *     load address, and riscv-rt's startup copies it over -- same
 *     mechanism as cortex-m-rt on the Arm side.
 */

MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 4096K

    /* 512 KiB of striped SRAM in banks 0-7 starting at 0x20000000. */
    RAM   : ORIGIN = 0x20000000, LENGTH = 512K

    /* SRAM8/SRAM9 are 4 KiB direct-mapped banks -- useful later for
     * per-core stacks. Declared for parity with memory.x. */
    SRAM8 : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9 : ORIGIN = 0x20081000, LENGTH = 4K
}

PROVIDE(_stext = ORIGIN(FLASH));
PROVIDE(_stack_start = ORIGIN(RAM) + LENGTH(RAM));
PROVIDE(_max_hart_id = 0);
PROVIDE(_hart_stack_size = 2K);
PROVIDE(_heap_size = 0);

PROVIDE(InstructionMisaligned = ExceptionHandler);
PROVIDE(InstructionFault = ExceptionHandler);
PROVIDE(IllegalInstruction = ExceptionHandler);
PROVIDE(Breakpoint = ExceptionHandler);
PROVIDE(LoadMisaligned = ExceptionHandler);
PROVIDE(LoadFault = ExceptionHandler);
PROVIDE(StoreMisaligned = ExceptionHandler);
PROVIDE(StoreFault = ExceptionHandler);
PROVIDE(UserEnvCall = ExceptionHandler);
PROVIDE(SupervisorEnvCall = ExceptionHandler);
PROVIDE(MachineEnvCall = ExceptionHandler);
PROVIDE(InstructionPageFault = ExceptionHandler);
PROVIDE(LoadPageFault = ExceptionHandler);
PROVIDE(StorePageFault = ExceptionHandler);

PROVIDE(SupervisorSoft = DefaultHandler);
PROVIDE(MachineSoft = DefaultHandler);
PROVIDE(SupervisorTimer = DefaultHandler);
PROVIDE(MachineTimer = DefaultHandler);
PROVIDE(SupervisorExternal = DefaultHandler);
PROVIDE(MachineExternal = DefaultHandler);

PROVIDE(DefaultHandler = DefaultInterruptHandler);
PROVIDE(ExceptionHandler = DefaultExceptionHandler);

/* If the user overrides this using the `#[pre_init]` attribute or by
   creating a `__pre_init` function, then the function this points to
   will be called before the RAM is initialized. */
PROVIDE(__pre_init = default_pre_init);

/* A PAC/HAL defined routine that should initialize custom interrupt
   controller if needed. */
PROVIDE(_setup_interrupts = default_setup_interrupts);

PROVIDE(TIMER0_IRQ_0 = DefaultIrqHandler);
PROVIDE(TIMER0_IRQ_1 = DefaultIrqHandler);
PROVIDE(TIMER0_IRQ_2 = DefaultIrqHandler);
PROVIDE(TIMER0_IRQ_3 = DefaultIrqHandler);
PROVIDE(TIMER1_IRQ_0 = DefaultIrqHandler);
PROVIDE(TIMER1_IRQ_1 = DefaultIrqHandler);
PROVIDE(TIMER1_IRQ_2 = DefaultIrqHandler);
PROVIDE(TIMER1_IRQ_3 = DefaultIrqHandler);
PROVIDE(PWM_IRQ_WRAP_0 = DefaultIrqHandler);
PROVIDE(PWM_IRQ_WRAP_1 = DefaultIrqHandler);
PROVIDE(DMA_IRQ_0 = DefaultIrqHandler);
PROVIDE(DMA_IRQ_1 = DefaultIrqHandler);
PROVIDE(DMA_IRQ_2 = DefaultIrqHandler);
PROVIDE(DMA_IRQ_3 = DefaultIrqHandler);
PROVIDE(USBCTRL_IRQ = DefaultIrqHandler);
PROVIDE(PIO0_IRQ_0 = DefaultIrqHandler);
PROVIDE(PIO0_IRQ_1 = DefaultIrqHandler);
PROVIDE(PIO1_IRQ_0 = DefaultIrqHandler);
PROVIDE(PIO1_IRQ_1 = DefaultIrqHandler);
PROVIDE(PIO2_IRQ_0 = DefaultIrqHandler);
PROVIDE(PIO2_IRQ_1 = DefaultIrqHandler);
PROVIDE(IO_IRQ_BANK0 = DefaultIrqHandler);
PROVIDE(IO_IRQ_BANK0_NS = DefaultIrqHandler);
PROVIDE(IO_IRQ_QSPI = DefaultIrqHandler);
PROVIDE(IO_IRQ_QSPI_NS = DefaultIrqHandler);
PROVIDE(SIO_IRQ_FIFO = DefaultIrqHandler);
PROVIDE(SIO_IRQ_BELL = DefaultIrqHandler);
PROVIDE(SIO_IRQ_FIFO_NS = DefaultIrqHandler);
PROVIDE(SIO_IRQ_BELL_NS = DefaultIrqHandler);
PROVIDE(SIO_IRQ_MTIMECMP = DefaultIrqHandler);
PROVIDE(CLOCKS_IRQ = DefaultIrqHandler);
PROVIDE(SPI0_IRQ = DefaultIrqHandler);
PROVIDE(SPI1_IRQ = DefaultIrqHandler);
PROVIDE(UART0_IRQ = DefaultIrqHandler);
PROVIDE(UART1_IRQ = DefaultIrqHandler);
PROVIDE(ADC_IRQ_FIFO = DefaultIrqHandler);
PROVIDE(I2C0_IRQ = DefaultIrqHandler);
PROVIDE(I2C1_IRQ = DefaultIrqHandler);
PROVIDE(OTP_IRQ = DefaultIrqHandler);
PROVIDE(TRNG_IRQ = DefaultIrqHandler);
PROVIDE(PLL_SYS_IRQ = DefaultIrqHandler);
PROVIDE(PLL_USB_IRQ = DefaultIrqHandler);
PROVIDE(POWMAN_IRQ_POW = DefaultIrqHandler);
PROVIDE(POWMAN_IRQ_TIMER = DefaultIrqHandler);
PROVIDE(SW0_IRQ = DefaultIrqHandler);
PROVIDE(SW1_IRQ = DefaultIrqHandler);
PROVIDE(SW2_IRQ = DefaultIrqHandler);
PROVIDE(SW3_IRQ = DefaultIrqHandler);
PROVIDE(SW4_IRQ = DefaultIrqHandler);
PROVIDE(SW5_IRQ = DefaultIrqHandler);

/* # Multi-processing hook function
   fn _mp_hook() -> bool;

   This function is called from all the harts and must return true only
   for one hart, which will perform memory initialization. For other
   harts it must return false and implement wake-up in platform-
   dependent way (e.g. after waiting for a user interrupt).

   Note core 1 never runs riscv-rt's `_start` in this firmware -- it is
   launched through the boot ROM FIFO handshake directly into
   `_pqf_core1_entry_rv` (see `src/core1_launch.rs`). */
PROVIDE(_mp_hook = default_mp_hook);

/* # Start trap function override
   By default uses the riscv crates default trap handler but by
   providing the `_start_trap` symbol external crates can override. */
PROVIDE(_start_trap = default_start_trap);

SECTIONS
{
  .text.dummy (NOLOAD) :
  {
    /* This section is intended to make _stext address work */
    . = ABSOLUTE(_stext);
  } > FLASH

  .text _stext :
  {
    /* Put reset handler first in .text section so it ends up as the entry */
    /* point of the program. */
    KEEP(*(.init));
    KEEP(*(.init.rust));
    . = ALIGN(4);
    /* The RP2350 boot ROM scans the first 4 KiB of flash for this
       IMAGE_DEF block -- same requirement as the Arm build, but here it
       sits just after riscv-rt's reset handler instead of after the
       vector table. */
    __start_block_addr = .;
    KEEP(*(.start_block));
    KEEP(*(.boot_info));
    . = ALIGN(4);
    *(.trap);
    *(.trap.rust);
    *(.text.abort);
    *(.text .text.*);
    . = ALIGN(4);
  } > FLASH

  /* ### Picotool 'Binary Info' Entries
    *
    * Picotool looks through this block (as we have pointers to it in our
    * header) to find interesting information.
    */
  .bi_entries : ALIGN(4)
  {
      /* We put this in the header */
      __bi_entries_start = .;
      /* Here are the entries */
      KEEP(*(.bi_entries));
      /* Keep this block a nice round size */
      . = ALIGN(4);
      /* We put this in the header */
      __bi_entries_end = .;
  } > FLASH

  .rodata : ALIGN(4)
  {
    *(.srodata .srodata.*);
    *(.rodata .rodata.*);

    /* 4-byte align the end (VMA) of this section.
       This is required by LLD to ensure the LMA of the following .data
       section will have the correct alignment. */
    . = ALIGN(4);
  } > FLASH

  .data : ALIGN(32)
  {
    _sidata = LOADADDR(.data);
    __sidata = LOADADDR(.data);
    _sdata = .;
    __sdata = .;
    /* Must be called __global_pointer$ for linker relaxations to work. */
    PROVIDE(__global_pointer$ = . + 0x800);
    *(.sdata .sdata.* .sdata2 .sdata2.*);
    *(.data .data.*);
    . = ALIGN(32);
    _edata = .;
    __edata = .;
  } > RAM AT > FLASH

  .bss (NOLOAD) : ALIGN(32)
  {
    _sbss = .;
    *(.sbss .sbss.* .bss .bss.*);
    . = ALIGN(32);
    _ebss = .;
  } > RAM

  .end_block : ALIGN(4)
  {
      __end_block_addr = .;
      KEEP(*(.end_block));
      __flash_binary_end = .;
  } > FLASH

  /* fictitious region that represents the memory available for the heap */
  .heap (NOLOAD) :
  {
    _sheap = .;
    . += _heap_size;
    . = ALIGN(4);
    _eheap = .;
  } > RAM

  /* fictitious region that represents the memory available for the stack */
  .stack (NOLOAD) :
  {
    _estack = .;
    . = ABSOLUTE(_stack_start);
    _sstack = .;
  } > RAM

  /* fake output .got section */
  /* Dynamic relocations are unsupported. This section is only used to detect
     relocatable code in the input files and raise an error if relocatable code
     is found */
  .got (INFO) :
  {
    KEEP(*(.got .got.*));
  }

  .eh_frame (INFO) : { KEEP(*(.eh_frame)) }
  .eh_frame_hdr (INFO) : { *(.eh_frame_hdr) }
}

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

/* Do not exceed this mark in the error messages above                                    | */
ASSERT(ORIGIN(FLASH) % 4 == 0, "
ERROR(riscv-rt): the start of the FLASH must be 4-byte aligned");

ASSERT(ORIGIN(RAM) % 32 == 0, "
ERROR(riscv-rt): the start of the RAM must be 32-byte aligned");

ASSERT(_stext % 4 == 0, "
ERROR(riscv-rt): `_stext` must be 4-byte aligned");

ASSERT(_sdata % 32 == 0 && _edata % 32 == 0, "
BUG(riscv-rt): .data is not 32-byte aligned");

ASSERT(_sidata % 32 == 0, "
BUG(riscv-rt): the LMA of .data is not 32-byte aligned");

ASSERT(_sbss % 32 == 0 && _ebss % 32 == 0, "
BUG(riscv-rt): .bss is not 32-byte aligned");

ASSERT(_sheap % 4 == 0, "
BUG(riscv-rt): start of .heap is not 4-byte aligned");

ASSERT(_stext + SIZEOF(.text) < ORIGIN(FLASH) + LENGTH(FLASH), "
ERROR(riscv-rt): The .text section must be placed inside the FLASH region.
Set _stext to an address smaller than 'ORIGIN(FLASH) + LENGTH(FLASH)'");

ASSERT(SIZEOF(.stack) > (_max_hart_id + 1) * _hart_stack_size, "
ERROR(riscv-rt): .stack section is too small for allocating stacks for all the harts.
Consider changing `_max_hart_id` or `_hart_stack_size`.");

ASSERT(SIZEOF(.got) == 0, "
.got section detected in the input files. Dynamic relocations are not
supported. If you are linking to C code compiled using the `gcc` crate
then modify your build script to compile the C code _without_ the
-fPIC flag. See the documentation of the `gcc::Config.fpic` method for
details.");

/* M1: reserve the persistent-storage sectors at the very top of flash
 * so a large `.text` can never grow into them and have `erase_region`
 * wipe live code. Three 4 KiB sectors are reserved (highest first),
 * plus PQF_RESIDENT_EXTRA_SECTORS overflow sectors below them (none by
 * default; build.rs writes `_pqf_reserved_sectors` = 3 + N into
 * pqf_reserve.x):
 *
 *   0x103FF000  store sector       (flash_store::STORE_OFFSET)
 *   0x103FE000  large-blob sector  (flash_store::LARGE_BLOB_OFFSET)
 *   0x103FD000  master-key sector  (flash_store::KEY_OFFSET / H1)
 *   0x103FC000  overflow sector 0  (flash_store::overflow_offset(0)), ...
 *
 * `__flash_binary_end` (end of the linked image, set in .end_block
 * above) must stay strictly below the lowest reserved sector -- same
 * invariant as the Arm build's memory.x. */
INCLUDE pqf_reserve.x
_reserved_flash_start = ORIGIN(FLASH) + LENGTH(FLASH) - (_pqf_reserved_sectors * 4K);
ASSERT(__flash_binary_end <= _reserved_flash_start,
  "ERROR: firmware image overlaps the reserved flash-store/key sectors at the top of flash");
