/* board.c -- per-board pins + quirks. See board.h for the board list.
 *
 * Pin assignments are copied from the Rust firmware's board profiles
 * (crates/firmware/src/board/), which document the schematic-level
 * "why" for every quirk; this file keeps just the numbers + a one-line
 * reminder each.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pico/stdlib.h"
#include "pico/bootrom.h"       /* rom_reset_usb_boot -- BOOTSEL reboot   */
#include "hardware/regs/addressmap.h" /* OTP_DATA_RAW_BASE            */
#include "hardware/regs/otp_data.h"  /* BOOT_FLAGS0 row + bit masks   */
#include "hardware/gpio.h"
#include "hardware/watchdog.h"  /* watchdog_reboot   -- warm reboot       */

#include "board.h"
#include "bootsel.h"

/* Exactly one PQF_BOARD_* macro arrives from CMake. */
#if !defined(PQF_BOARD_TINY2350) && !defined(PQF_BOARD_XIAO_RP2350) \
    && !defined(PQF_BOARD_FEITIAN_RP2350) \
    && !defined(PQF_BOARD_FEITIAN_RP2350_USBC) \
    && !defined(PQF_BOARD_WAVESHARE_LCD_1_47) \
    && !defined(PQF_BOARD_SPOTPEAR_LCD_1_28)
#error "No PQF_BOARD_* selected -- configure with -DPQF_BOARD=<board>"
#endif

static void out_pin(unsigned pin, bool level)
{
    gpio_init(pin);
    gpio_set_dir(pin, GPIO_OUT);
    gpio_put(pin, level);
}

#if defined(PQF_BOARD_TINY2350)

/* Pimoroni Tiny 2350: common-anode RGB LED, GP18 R / GP19 G / GP20 B,
 * all ACTIVE-LOW. The wink/status channel is the green leg (the Rust
 * g-channel = UP-wait + wink); red and blue are parked off (high).
 * User presence is the BOOT button, which sits on QSPI_SS like the
 * Feitian's BOOTSEL and is read by the shared sampler below; no GPIO
 * setup is needed for it. */
#define LED_G_PIN 19

void pqf_board_init(void)
{
    out_pin(18, true);          /* R off */
    out_pin(LED_G_PIN, true);   /* G off */
    out_pin(20, true);          /* B off */
}

void pqf_board_led_set(bool on)
{
    gpio_put(LED_G_PIN, !on);   /* active-low */
}

const char *pqf_board_name(void) { return "Pimoroni Tiny 2350"; }

#elif defined(PQF_BOARD_XIAO_RP2350)

/* Seeed XIAO RP2350: single user LED GP25 (ACTIVE-LOW). GP23 gates the
 * WS2812 power rail -- drive LOW before USB enumeration or the 5 V rail
 * sags and enumeration fails intermittently. */
#define LED_PIN 25

void pqf_board_init(void)
{
    out_pin(23, false);         /* NeoPixel power rail OFF */
    out_pin(LED_PIN, true);     /* LED off */
}

void pqf_board_led_set(bool on)
{
    gpio_put(LED_PIN, !on);     /* active-low */
}

const char *pqf_board_name(void) { return "Seeed XIAO RP2350"; }

#elif defined(PQF_BOARD_FEITIAN_RP2350) || defined(PQF_BOARD_FEITIAN_RP2350_USBC)

/* Feitian RP2350 (Pi Pico 2 reference design), USB-A board and sealed
 * USB-C token alike: single user LED GP25, ACTIVE-HIGH (drive high to
 * light -- OPPOSITE polarity to the XIAO's GP25). User presence is the
 * BOOTSEL button (USB-A) or the capacitive touch pad (USB-C) on
 * QSPI_SS, read at runtime through the shared sampler below; no GPIO
 * pin setup is needed for it (the flash interface owns QSPI_SS). The
 * two profiles differ only in name here; what separates them is in
 * board.h -- the USB-C token has no working power-on BOOTSEL, so its
 * CMD_REBOOT carries no presence gate. */
#define LED_PIN 25

void pqf_board_init(void)
{
    out_pin(LED_PIN, false);    /* active-high -> low = off */
}

void pqf_board_led_set(bool on)
{
    gpio_put(LED_PIN, on);      /* active-high */
}

#if defined(PQF_BOARD_FEITIAN_RP2350_USBC)
const char *pqf_board_name(void) { return "Feitian RP2350 USB-C"; }
#else
const char *pqf_board_name(void) { return "Feitian RP2350"; }
#endif

#elif defined(PQF_BOARD_WAVESHARE_LCD_1_47)

/* Waveshare RP2350-LCD-1.47: no discrete user LED (the on-board lamp
 * is a WS2812 chain whose data line, GP23, we hold LOW to keep dark;
 * the LCD panel is not driven by this port). LED is a no-op. */
void pqf_board_init(void)
{
    out_pin(23, false);         /* WS2812 data held low -> dark */
}

void pqf_board_led_set(bool on) { (void)on; }

const char *pqf_board_name(void) { return "Waveshare RP2350-LCD-1.47"; }

#elif defined(PQF_BOARD_SPOTPEAR_LCD_1_28)

/* Spotpear RP2350-LCD-1.28: no discrete user LED; the status surface
 * is the round LCD, which this port doesn't drive. LED is a no-op. */
void pqf_board_init(void) { }

void pqf_board_led_set(bool on) { (void)on; }

const char *pqf_board_name(void) { return "Spotpear RP2350-LCD-1.28"; }

#endif

/* User presence. The button boards (Feitian USB-A and USB-C, Tiny 2350)
 * all have their BOOT button or touch pad on QSPI_SS, so they share one
 * reader over bootsel.c; the buttonless boards share one no-op. Keeps
 * the board interface uniform so ctap2.c's gate need not know which
 * board it's on. */
#if PQF_BOARD_HAS_USER_BUTTON
#if defined(PQF_UP_DEBUG)
volatile uint32_t pqf_up_dbg_samples, pqf_up_dbg_rising, pqf_up_dbg_high;
#endif

bool pqf_board_user_present(void)
{
    /* Rate-limit the BOOTSEL sample to one chip-select float per 2 ms
     * (bootsel.c's documented contract, and what the Rust board
     * profiles do). wait_for_up polls this every loop pass; an
     * unthrottled sampler would float the flash chip-select -- with
     * interrupts masked -- for a large fraction of wall time for the
     * whole presence wait. Between samples, return the cached level. */
    static absolute_time_t next_sample;
    static bool last_pressed;
    if (time_reached(next_sample)) {
        bool now = pqf_bootsel_pressed();
#if defined(PQF_UP_DEBUG)
        /* Count every sample and every rising edge, so a quiet minute
         * with nothing touching the board can be checked for spurious
         * presses -- the suspected cause of the user-presence gate
         * self-satisfying (docs/notes/UP-GATE-RETRACTED.md). */
        pqf_up_dbg_samples++;
        if (now && !last_pressed) pqf_up_dbg_rising++;
        if (now) pqf_up_dbg_high++;
#endif
        last_pressed = now;
        next_sample = make_timeout_time_ms(2);
    }
    return last_pressed;
}
#else
bool pqf_board_user_present(void) { return false; }
#endif

/* Reboot the MCU (board-independent). BOOTSEL hands control to the boot
 * ROM's USB bootloader (the device re-enumerates as RP2350 mass
 * storage); WARM restarts the firmware through the watchdog. Both are
 * noreturn -- the trailing loop only reassures the compiler. */
/* True when the BOOTSEL USB interfaces have been fused off
 * (BOOT_FLAGS0 bits 17/18, OTP row 0x48, read through the raw 32-bit
 * window). On such a part entering BOOTSEL is a one-way trip: the ROM
 * enters the mode and exposes nothing, so the device sits awake and
 * invisible until someone physically power-cycles it. Refusing is the
 * only useful answer -- the host cannot know, and any host can send
 * CMD_REBOOT. Learned by doing it: testing "is BOOTSEL disabled?" the
 * obvious way took a board off the bus and needed a replug. */
static bool bootsel_is_fused_off(void)
{
    const uint32_t row = *(const volatile uint32_t *)
        (OTP_DATA_RAW_BASE + OTP_DATA_BOOT_FLAGS0_ROW * 4u);
    return (row & (OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_USB_PICOBOOT_IFC_BITS
                 | OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_USB_MSD_IFC_BITS)) != 0;
}

bool pqf_board_bootsel_available(void)
{
    return !bootsel_is_fused_off();
}

void pqf_board_reboot(enum pqf_reboot_mode mode)
{
    if (mode == PQF_REBOOT_BOOTSEL && !bootsel_is_fused_off()) {
        rom_reset_usb_boot(0, 0);       /* -> USB mass storage / DFU */
    } else if (mode == PQF_REBOOT_BOOTSEL) {
        /* Fused off: fall through to a warm reboot rather than
         * stranding the device. The caller should have refused before
         * getting here; this is the backstop. */
        watchdog_reboot(0, 0, 0);
    } else {
        watchdog_reboot(0, 0, 0);       /* pc=0 -> normal boot into flash */
    }
    for (;;) { }
}
