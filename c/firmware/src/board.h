/* board.h -- per-board pins + quirks, one profile per board.
 *
 * Mirrors the Rust firmware's `src/board/` profiles: one compile-time
 * board selection (CMake `-DPQF_BOARD=...`) provides the status-LED
 * control and any board-quirk pin setup, so main.c never touches pin
 * numbers. Boards without a usable discrete LED implement the LED
 * call as a no-op (same contract as the Rust profiles).
 *
 * Supported boards (matching the Rust feature set):
 *   PQF_BOARD_TINY2350           Pimoroni Tiny 2350 -- common-anode RGB
 *                                LED GP18/19/20 (active-low); the wink/
 *                                status channel drives the GREEN leg,
 *                                matching the Rust g-channel semantics.
 *                                User presence = the BOOT button on
 *                                QSPI_SS, sampled at runtime through
 *                                bootsel.c exactly as on the Feitian.
 *   PQF_BOARD_XIAO_RP2350        Seeed XIAO RP2350 -- single user LED
 *                                GP25 (active-low). Quirk: GP23 gates
 *                                the WS2812 power rail and must be
 *                                driven LOW before USB enumeration or
 *                                the 5 V rail sags and enumeration
 *                                fails intermittently.
 *   PQF_BOARD_FEITIAN_RP2350     Feitian RP2350 (Pi Pico 2 reference
 *                                design) -- single user LED GP25
 *                                (ACTIVE-HIGH, opposite polarity to
 *                                the XIAO). User presence = the BOOTSEL
 *                                button on QSPI_SS, sampled at runtime
 *                                via bootsel.c (shared with the Tiny
 *                                2350 above).
 *   PQF_BOARD_FEITIAN_RP2350_USBC
 *                                Feitian RP2350 USB-C token -- sealed,
 *                                a capacitive touch pad in place of the
 *                                button, otherwise the same profile as
 *                                the USB-A board above (GP25 active-
 *                                high, presence on QSPI_SS). The
 *                                bootrom's power-on BOOTSEL sensing
 *                                does not work on it, so CMD_REBOOT is
 *                                its only way back into the bootloader
 *                                and is NOT presence-gated (see
 *                                PQF_REBOOT_NEEDS_UP below).
 *   PQF_BOARD_WAVESHARE_LCD_1_47 Waveshare RP2350-LCD-1.47 -- no
 *                                discrete user LED (panel not driven
 *                                by this port); GP23 is the WS2812
 *                                data line, held LOW to keep the lamp
 *                                chain dark. LED call is a no-op.
 *   PQF_BOARD_SPOTPEAR_LCD_1_28  Spotpear RP2350-LCD-1.28 -- no
 *                                discrete user LED. LED call is a
 *                                no-op.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_BOARD_H
#define PQF_BOARD_H

#include <stdbool.h>

/* Compile-time capability flag: 1 if this board wires a
 * firmware-readable user-presence button, 0 otherwise. When 1, the
 * WaitForUp gate in ctap2.c enforces a real press (via
 * pqf_board_user_present); when 0, presence auto-confirms. Mirrors the
 * Rust profiles' `HAS_USER_BUTTON` const. */
#if defined(PQF_TEST_NO_USER_BUTTON)
/* TEST-ONLY (never ship): force user-presence auto-confirm even on a
 * board that wires a button, so automated on-silicon tests run without
 * a physical press. Disables the UP gate entirely. */
#define PQF_BOARD_HAS_USER_BUTTON 0
#elif defined(PQF_BOARD_FEITIAN_RP2350) || defined(PQF_BOARD_TINY2350) \
    || defined(PQF_BOARD_FEITIAN_RP2350_USBC)
/* All three put their presence input on QSPI_SS; bootsel.c reads it.
 * For the USB-C token this began as the working assumption from the one
 * sample we had -- its touch pad read as a press at runtime through
 * this same sampler, while the bootrom's power-on BOOTSEL sensing did
 * not react to it -- and was confirmed on the first production token on
 * 2026-10-02 (docs/TESTING.md). If a later batch wires the pad
 * differently the token still reflashes: its CMD_REBOOT does not
 * depend on this flag (PQF_REBOOT_NEEDS_UP below). */
#define PQF_BOARD_HAS_USER_BUTTON 1
#else
#define PQF_BOARD_HAS_USER_BUTTON 0
#endif

/* Compile-time capability flag: 1 if this board has a PHYSICAL way into
 * the RP2350 ROM bootloader at power-on -- a BOOT/BOOTSEL button you
 * can hold while plugging in -- 0 if the host-issued CTAPHID_CMD_REBOOT
 * is the only road back to BOOTSEL. Feeds PQF_REBOOT_NEEDS_UP below: a
 * board with no power-on path must never gate that command on a
 * gesture, because an image that does so on a token that cannot deliver
 * the gesture can never be reflashed. */
#if defined(PQF_BOARD_FEITIAN_RP2350_USBC)
/* Sealed USB-C token: holding the pad while plugging in does nothing
 * (observed on the one sample), so there is no power-on fallback. */
#define PQF_BOARD_HAS_POWER_ON_BOOTSEL 0
#else
/* Every dev board, the Feitian USB-A, and the host harness (no board
 * macro at all). */
#define PQF_BOARD_HAS_POWER_ON_BOOTSEL 1
#endif

/* -DPQF_REBOOT_NO_UP=ON as a 0/1 value, so it can sit in one arithmetic
 * #if with the two capability flags. */
#if defined(PQF_REBOOT_NO_UP)
#define PQF_REBOOT_NO_UP_SET 1
#else
#define PQF_REBOOT_NO_UP_SET 0
#endif

/* CTAPHID_CMD_REBOOT policy: 1 = both reboot modes (warm and BOOTSEL)
 * wait for a test of user presence first, 0 = they act at once. Gate
 * only where a gesture can be given AND a power-on BOOTSEL exists as
 * the fallback should the gate ever misbehave; no gate where the board
 * has nothing to press, where CMD_REBOOT is its only way into the
 * bootloader (the USB-C token), or where the flash station asked for
 * none (PQF_REBOOT_NO_UP). PQF_TEST_NO_USER_BUTTON lands here through
 * PQF_BOARD_HAS_USER_BUTTON = 0. ctaphid.c compiles the gate in on
 * this; main.c reports it as the pqf-reboot= picotool feature. FIDO
 * user presence (MakeCredential / GetAssertion) is a separate matter
 * and is not touched by any of it. */
#define PQF_REBOOT_NEEDS_UP \
    (PQF_BOARD_HAS_USER_BUTTON && PQF_BOARD_HAS_POWER_ON_BOOTSEL && !PQF_REBOOT_NO_UP_SET)

#if defined(PQF_UP_DEBUG)
/* TEST-ONLY counters for the user-presence read (docs/notes/UP-GATE-RETRACTED.md).
 * samples = every 2 ms poll; high = polls that read PRESSED; rising =
 * release->press edges, which is what wait_for_up() acts on. With nothing
 * touching the board, high and rising must both stay 0. */
extern volatile uint32_t pqf_up_dbg_samples, pqf_up_dbg_rising, pqf_up_dbg_high;
#endif

/* Claim the board's LED + quirk pins and drive them to their safe
 * initial state. Must run BEFORE USB enumeration (tud_init) -- the
 * XIAO's WS2812 power gate has to be low before the host starts
 * drawing descriptors. */
void pqf_board_init(void);

/* Status/wink LED. Boards without a usable LED ignore it. */
void pqf_board_led_set(bool on);

/* User-presence button state -- true while the board's user-presence
 * button is pressed. Boards without one (PQF_BOARD_HAS_USER_BUTTON = 0)
 * always return false. Polled by the WaitForUp gate. */
bool pqf_board_user_present(void);

/* Human-readable board name for the CDC banner. */
const char *pqf_board_name(void);

/* Reboot mode for pqf_board_reboot(). Wire-compatible with the
 * CTAPHID_CMD_REBOOT mode byte (CTAPHID_REBOOT_WARM / _BOOTSEL). */
enum pqf_reboot_mode {
    PQF_REBOOT_WARM    = 0,  /* warm reboot back into the firmware       */
    PQF_REBOOT_BOOTSEL = 1,  /* reboot into RP2350 USB mass-storage / DFU */
};

/* Reboot the MCU. Does NOT return. PQF_REBOOT_BOOTSEL enters the USB
 * bootloader (mass storage) via the boot ROM; PQF_REBOOT_WARM restarts
 * the firmware via the watchdog. The caller is responsible for any
 * user-presence gating (see CTAPHID_CMD_REBOOT). */
void pqf_board_reboot(enum pqf_reboot_mode mode);

/* False once the BOOTSEL USB interfaces are fused off in OTP. Entering
 * BOOTSEL on such a part exposes nothing, so the device disappears from
 * the bus until it is physically power-cycled -- callers must refuse a
 * BOOTSEL reboot rather than perform one. DFU is unaffected: it is the
 * bootloader's own USB device, not the ROM's. */
bool pqf_board_bootsel_available(void);

#endif /* PQF_BOARD_H */
