/* bootsel.c -- runtime BOOTSEL-button sampling via the QSPI chip-select
 * line.
 *
 * Direct port of the BOOTSEL button-reading routine from Raspberry Pi
 * pico-examples, picoboard/button/button.c (`get_bootsel_button`):
 *
 *     Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *     SPDX-License-Identifier: BSD-3-Clause
 *
 * The licence's conditions and disclaimer are reproduced in
 * LICENSE-BSD-3-CLAUSE-PICO-EXAMPLES at the repository root.
 *
 * The routine is reproduced essentially verbatim against the pico-sdk
 * (which supplies `__no_inline_not_in_flash_func`, the interrupt
 * save/restore, `hw_write_masked`, and the ioqspi/sio struct headers),
 * so the C port stays close to the upstream original -- unlike the Rust
 * port (crates/firmware/src/board/bootsel.rs), which had to open-code
 * the same register pokes.
 *
 * This file is kept under its original BSD-3-Clause license and
 * combined into the otherwise Apache-2.0 C firmware; both are
 * permissive, so the combined image ships under Apache-2.0 while this
 * file's BSD notice is retained (see THIRD_PARTY.md). The
 * copyleft-licensed adaptations of the same routine in pico-fido /
 * pico-keys-sdk were NOT consulted; the BSD upstream is the sole
 * source.
 *
 * ## How it works
 *
 * On reference-design RP2350 boards (e.g. the Feitian RP2350) the
 * BOOTSEL button isn't on a GPIO: it shorts the flash chip-select
 * (QSPI_SS) to ground through a 1 kOhm resistor, which only the bootrom
 * senses at reset. To read it at runtime we override the QSPI_SS pad's
 * output-enable to Hi-Z, let the pad pull-up (or the button, through
 * its 1k to ground) settle the line, sample it through SIO's HI GPIO
 * input bank, then hand the pad back to the QMI peripheral.
 *
 * ## Why it must run from RAM with interrupts off
 *
 * While CS is floated the flash doesn't see its chip select, so the XIP
 * window (0x1000_0000..) is unreadable -- any instruction fetch or data
 * load from flash on either core would fault. Hence:
 *   - `__no_inline_not_in_flash_func` places this function in SRAM;
 *   - interrupts are masked across the window (an ISR is in flash);
 *   - the settle delay is a volatile busy loop (`sleep_*` is in flash);
 *   - the pico-sdk helpers used here are all `__force_inline`, so they
 *     inline into this RAM frame rather than becoming flash calls.
 * The other core must not fetch flash during the window either; the
 * board profile only ever calls this from the WaitForUp gate, i.e.
 * before any core-1 hybrid sign starts, while core 1 sits idle.
 */

#include "pico/stdlib.h"
#include "hardware/sync.h"
#include "hardware/gpio.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"

#include "bootsel.h"

bool __no_inline_not_in_flash_func(pqf_bootsel_pressed)(void)
{
    /* QSPI_SS is chip-select, index 1 in the IO_QSPI GPIO array. */
    const uint CS_PIN_INDEX = 1;

    /* Interrupt handlers may live in flash, which we're about to make
     * unreachable -- mask interrupts for the duration. */
    uint32_t flags = save_and_disable_interrupts();

    /* Float the chip-select pad: OEOVER = disable output driver. */
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    /* Settle. No flash-resident calls (e.g. sleep_us) allowed here. */
    for (volatile int i = 0; i < 1000; ++i)
        ;

    /* SIO's HI GPIO input bank mirrors the six QSPI pads. The button
     * pulls the line LOW when pressed.
     *
     * Sample several times and require unanimity. A single read is not
     * trustworthy here: save_and_disable_interrupts() masks only THIS
     * core, so anything core 1 does with flash drives chip-select low
     * underneath us and reads exactly like a press. Measured on silicon
     * 2026-08-17 with PQF_UP_DEBUG: a single-read version produced 20
     * spurious "pressed" samples and 2 release->press edges out of 7,551
     * polls on a completely untouched board -- enough for wait_for_up()
     * to confirm user presence with no human, which is the bug in
     * docs/notes/UP-GATE-RETRACTED.md.
     *
     * A real press holds the line low for milliseconds, so it survives
     * every sample; a transient driven by the other core does not. */
    bool button_state = true;
    for (int s = 0; s < 8; ++s) {
        if (sio_hw->gpio_hi_in & SIO_GPIO_HI_IN_QSPI_CSN_BITS) {
            button_state = false;      /* read HIGH => not pressed */
            break;
        }
        for (volatile int i = 0; i < 200; ++i)
            ;
    }

    /* Restore normal chip-select operation before we touch flash. */
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    restore_interrupts(flags);

    return button_state;
}
