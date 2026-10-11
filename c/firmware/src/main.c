/* main.c -- Phase C-2 entry point.
 *
 * Replaces the Phase C-1 stdio-only main with one that brings up
 * a composite USB device (CDC for banners + HID for FIDO) under
 * TinyUSB, and pumps the device task in a loop.
 *
 * CDC banner output remains so the user keeps the
 * `screen /dev/cu.usbmodem*` debug flow, even though pico-sdk's
 * built-in `pico_enable_stdio_usb` is now off (we own the USB
 * descriptors directly -- see `usb_descriptors.c`).
 *
 * The CTAPHID logic itself lives in `ctaphid.{c,h}`; this file
 * just wires the USB transport's set-report callback through to
 * it (via `fido_hid.c`).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
/* Unconditional: pqf_boot_checkin() below stands down the DFU
 * bootloader's launch guard and must build in every configuration,
 * not just DFU-runtime ones. */
#include "hardware/watchdog.h"
#include "hardware/structs/watchdog.h"
#include "pico/binary_info.h"
/* The CDC reflash hook is implied by PQF_TEST_NO_USER_BUTTON but is a
 * SEPARATE concern from the user-presence bypass: a build can keep a real
 * UP gate and still want hands-free reflashing (that combination is how
 * the UP gate itself gets tested on silicon). -DPQF_CDC_BOOTSEL_HOOK=1
 * enables it on its own. */
#if defined(PQF_TEST_NO_USER_BUTTON) && !defined(PQF_CDC_BOOTSEL_HOOK)
#define PQF_CDC_BOOTSEL_HOOK 1
#endif
#if defined(PQF_CDC_BOOTSEL_HOOK)
#include "pico/bootrom.h"       /* rom_reset_usb_boot (CDC reflash hook) */
#include "boot/picoboot_constants.h" /* REBOOT2_FLAG_* (RISC-V DFU return) */
#endif
#include "hardware/clocks.h"
#include "hardware/irq.h"       /* USBCTRL_IRQ off on RISC-V (below) */
#include "tusb.h"

#include "ctaphid.h"
#include "ctap2.h"
#include "fido_hid.h"
#include "core1_signer.h"
#include "board.h"
#include "resident_store.h"   /* RESIDENT_MAX_SLOTS (pqf-rk-slots) */
#if defined(PQF_UP_DEBUG)
#include "bootsel.h"
volatile uint32_t pqf_up_idle_samples, pqf_up_idle_high, pqf_up_idle_rising;
#endif
#include "usb_descriptors.h"
#include "pqf_rand.h"        /* entropy picker: QRNG first, TRNG otherwise */
#if defined(PQF_QRNG)
#include "pqf_qrng.h"
#include "pqf_qrng_hw.h"
#endif
#include "gdbstub.h"        /* on-token GDB stub (no-op unless PQF_GDB_STUB) */

#if defined(PQF_SIGN_ARENA)
#include "core1_arena.h"   /* level-87 sign-heap diagnostics (below) */
#endif

#if defined(PQF_XIP_STATS)
#include "xip_stats.h"     /* XIP cache hit rate per sign (below) */
#endif

/* picotool metadata -- the only place these strings live for now;
 * a Rust-side unification could share the table. */
bi_decl(bi_program_name("Bruce (C port)"))
bi_decl(bi_program_description(
    "Bare-metal C port of the Bruce Rust firmware "
    "(multi-board, full CTAP 2.1 parity)"))
#if defined(PQF_PROGRAM_URL)
bi_decl(bi_program_url(PQF_PROGRAM_URL))
#endif

/* Board id and the two presence policies, as picotool "features", so an
 * image can be identified BEFORE it is flashed: `picotool info -a
 * <file.uf2>`. The board id is the PQF_BOARD string CMake was given
 * (PQF_BOARD_ID); the two policies are derived from the same board.h
 * macros the code is compiled from, so what the tool prints is what the
 * image does. This matters most for the sealed USB-C token: an image
 * whose CMD_REBOOT waits for a touch that token cannot give is one that
 * can never be reflashed, so check for pqf-reboot=no-touch first. The
 * spellings have no spaces so a script can grep them whole. */
#if !defined(PQF_BOARD_ID)
#error "PQF_BOARD_ID (the PQF_BOARD string) must come from CMake"
#endif
bi_decl(bi_program_feature("pqf-board=" PQF_BOARD_ID))
#if PQF_REBOOT_NEEDS_UP
bi_decl(bi_program_feature("pqf-reboot=touch"))
#else
bi_decl(bi_program_feature("pqf-reboot=no-touch"))
#endif
#if PQF_BOARD_HAS_USER_BUTTON
bi_decl(bi_program_feature("pqf-fido-up=touch"))
#else
/* Includes PQF_TEST_NO_USER_BUTTON builds, which force the flag to 0. */
bi_decl(bi_program_feature("pqf-fido-up=auto"))
#endif

/* Discoverable-credential capacity, as pqf-rk-slots=<n> (the Rust port
 * emits the same marker with its own count). Spelled out per value so
 * the string is a literal; the assert ties it to RESIDENT_MAX_SLOTS. */
#if PQF_RESIDENT_EXTRA_SECTORS == 0
#define PQF_RK_SLOTS_STR "7"
#define PQF_RK_SLOTS_NUM 7
#elif PQF_RESIDENT_EXTRA_SECTORS == 1
#define PQF_RK_SLOTS_STR "14"
#define PQF_RK_SLOTS_NUM 14
#elif PQF_RESIDENT_EXTRA_SECTORS == 2
#define PQF_RK_SLOTS_STR "21"
#define PQF_RK_SLOTS_NUM 21
#elif PQF_RESIDENT_EXTRA_SECTORS == 3
#define PQF_RK_SLOTS_STR "28"
#define PQF_RK_SLOTS_NUM 28
#elif PQF_RESIDENT_EXTRA_SECTORS == 4
#define PQF_RK_SLOTS_STR "35"
#define PQF_RK_SLOTS_NUM 35
#elif PQF_RESIDENT_EXTRA_SECTORS == 5
#define PQF_RK_SLOTS_STR "42"
#define PQF_RK_SLOTS_NUM 42
#elif PQF_RESIDENT_EXTRA_SECTORS == 6
#define PQF_RK_SLOTS_STR "49"
#define PQF_RK_SLOTS_NUM 49
#elif PQF_RESIDENT_EXTRA_SECTORS == 7
#define PQF_RK_SLOTS_STR "56"
#define PQF_RK_SLOTS_NUM 56
#else
#define PQF_RK_SLOTS_STR "63"
#define PQF_RK_SLOTS_NUM 63
#endif
_Static_assert(PQF_RK_SLOTS_NUM == RESIDENT_MAX_SLOTS,
               "pqf-rk-slots marker disagrees with RESIDENT_MAX_SLOTS");
bi_decl(bi_program_feature("pqf-rk-slots=" PQF_RK_SLOTS_STR))

/* Pump a small banner over our composite CDC interface so a user
 * watching the serial port still sees liveness, without needing
 * pico-sdk's `pico_enable_stdio_usb` (which is incompatible with
 * a custom USB descriptor). */
static void cdc_log(const char *msg)
{
    if (!tud_cdc_connected()) return;
    tud_cdc_write_str(msg);
    tud_cdc_write_flush();
}

/* Bring-up diagnostic (the riscv32 first-flash-write freeze): overrides
 * the weak hook in core1_signer.c so each stage of core1_run_flash_op
 * emits a CDC marker; a hang shows as "last stage printed". Off unless
 * the build defines PQF_CTAP2_DBG=1, like the command log below; a
 * release image keeps the weak no-op. */
#if defined(PQF_CTAP2_DBG) && PQF_CTAP2_DBG
void pqf_flash_op_dbg(unsigned stage)
{
    switch (stage) {
    case 1: cdc_log("  [flash dbg] 1: park requested\r\n"); break;
    case 2: cdc_log("  [flash dbg] 2: park acked, running flash op\r\n"); break;
    case 3: cdc_log("  [flash dbg] 3: flash op returned\r\n"); break;
    case 4: cdc_log("  [flash dbg] 4: core 1 released\r\n"); break;
    case 9: cdc_log("  [flash dbg] 9: PARK ACK TIMEOUT - core 1 dead? proceeding\r\n"); break;
    case 10: cdc_log("  [flash dbg] 10: RELEASE ACK TIMEOUT\r\n"); break;
    default: break;
    }
}
#endif

/* Bring-up diagnostic (the riscv32 freeze investigation): log every
 * CTAP2 command byte dispatched, so the exact command sequence leading
 * to a hang is visible over CDC. Off unless the build defines
 * PQF_CTAP2_DBG=1 (for example CMAKE_EXTRA="-DCMAKE_C_FLAGS=-DPQF_CTAP2_DBG=1"
 * ./build-c.sh ...); a release image keeps ctap2.c's weak no-op, so
 * nothing about a user's traffic goes out over the serial port. */
#if defined(PQF_CTAP2_DBG) && PQF_CTAP2_DBG
void pqf_ctap2_dbg(uint8_t cmd)
{
    char buf[48];
    snprintf(buf, sizeof buf, "  [ctap2 dbg] cmd=0x%02x\r\n", cmd);
    cdc_log(buf);
}
#endif

#if defined(__riscv)
/* Core-0 trap reporter (overrides the weak spin in core1_signer.c):
 * the device is dead for CTAP purposes, but keep pumping the polled
 * USB stack and repeat the trap record over CDC so the wedge tells us
 * mcause/mepc instead of going silent. Best-effort by design -- if the
 * trap corrupted TinyUSB state this stays a silent spin, which is no
 * worse than before. */
void pqf_core0_trap_report(uint32_t cause, uint32_t epc)
{
    absolute_time_t next = get_absolute_time();
    for (;;) {
        pqf_usb_task();
        if (time_reached(next)) {
            char buf[64];
            snprintf(buf, sizeof buf,
                     "!! CORE 0 TRAP mcause=%lu mepc=0x%08lx\r\n",
                     (unsigned long)cause, (unsigned long)epc);
            cdc_log(buf);
            next = make_timeout_time_ms(1000);
        }
    }
}
#endif

/* ---- Status LED: idle heartbeat + CTAPHID WINK pulses ---------- *
 *
 * The wink callback runs inside the TinyUSB dispatch stack, so it
 * must not block; it just arms a pulse count that the main loop
 * drains (toggle every 100 ms -> three visible blinks) through the
 * board layer's status LED (no-op on LED-less boards).
 *
 * Between winks the LED is SOLID -- the same idle "powered and ready"
 * signal as the Rust port's blue channel (on single-LED boards like
 * the Feitian RP2350 both ports share the one GP25 LED, so the two
 * firmwares look alike at idle). The only blinking patterns are the
 * wink pulses here and the WaitForUp gate's rapid press prompt
 * (fido_hid.c); the gate runs inside a CBOR dispatch, so this task
 * never runs concurrently with it. */
static volatile unsigned s_wink_pulses;

static void on_wink(void)
{
    s_wink_pulses = 6;
}

#if defined(PQF_DFU_RUNTIME)
/* ---- DFU runtime detach -------------------------------------- *
 *
 * `dfu-util -D` sends DFU_DETACH to our runtime interface; TinyUSB
 * calls this hook at the SETUP stage. Don't reboot from inside the
 * callback -- arm a deadline instead so the control transfer's status
 * stage completes and the host sees the detach ACKed, then reboot
 * with the watchdog-scratch handshake the bootloader looks for
 * (c/bootloader/src/main.c, PQF_DFU_SCRATCH_MAGIC). */
#define PQF_DFU_SCRATCH_MAGIC   0x50514446u   /* "PQDF" */

static volatile bool s_dfu_detach;

void tud_dfu_runtime_reboot_to_dfu_cb(void)
{
    s_dfu_detach = true;
}

static void dfu_detach_task(void)
{
    static absolute_time_t due;
    static bool armed;
    if (!s_dfu_detach) return;
    if (!armed) {
        armed = true;
        due = make_timeout_time_ms(100);
        return;
    }
    if (!time_reached(due)) return;
#if defined(__riscv)
    /* The bootloader is an Arm image; on a RISC-V core a plain watchdog
     * reboot keeps ARCHSEL as-is and the ROM's scan relaunches THIS app
     * through the block-loop annex -- the bootloader never runs. Reboot
     * to Arm through the ROM instead, with the DFU magic riding its own
     * p0/p1 parameters: the ROM stores those in watchdog scratch 2/3
     * (datasheet sec. 5.2.4.1), which is exactly where the bootloader looks.
     * Writing scratch 2/3 by hand here would be futile -- rom_reboot()
     * overwrites them. */
    rom_reboot(REBOOT2_FLAG_REBOOT_TYPE_NORMAL
             | REBOOT2_FLAG_REBOOT_TO_ARM
             | REBOOT2_FLAG_NO_RETURN_ON_SUCCESS, 1,
               PQF_DFU_SCRATCH_MAGIC, ~PQF_DFU_SCRATCH_MAGIC);
    /* Only reached if the ROM refused the switch -- cannot happen where
     * Arm is fused on; fall through to the plain reboot regardless. */
#endif
    watchdog_hw->scratch[2] = PQF_DFU_SCRATCH_MAGIC;
    watchdog_hw->scratch[3] = ~PQF_DFU_SCRATCH_MAGIC;
    watchdog_reboot(0, 0, 0);
    while (true) tight_loop_contents();
}
#endif /* PQF_DFU_RUNTIME */

static void led_task(void)
{
    static absolute_time_t next;
    static bool lit;
    static bool winking;
    if (s_wink_pulses > 0 && !winking) {
        winking = true;
        next = get_absolute_time();   /* start the wink pattern now */
    }
    if (winking) {
        if (!time_reached(next)) return;
        lit = !lit;
        s_wink_pulses--;
        if (s_wink_pulses == 0) {
            winking = false;
        }
        pqf_board_led_set(lit);
        next = make_timeout_time_ms(100);
        return;
    }
    /* Idle/ready: a SOLID (non-blinking) light, per the LED model the
     * Rust port settled on -- solid whenever the device is powered and
     * working, rapid blink ONLY when it wants a button press
     * (wait_for_up), so the press prompt is the one unmistakable
     * pattern. The old 500 ms idle heartbeat is gone. Repainting every
     * main-loop pass also restores the light after a dispatch's busy
     * handling or a timed-out presence wait left it dark. */
    pqf_board_led_set(true);
}

/* ---- Boot progress breadcrumb + bootloader launch guard --------- *
 *
 * When the DFU bootloader started this image it armed the hardware
 * watchdog immediately before branching here (c/bootloader/src/main.c)
 * and left its trace magic in watchdog scratch 0. Anything we write to
 * scratch 1 therefore SURVIVES a guard reset and is reported by the
 * bootloader in its USB serial string, so a firmware that hangs during
 * init names the step it died on -- with no debugger, no UART and
 * nobody touching the board.
 *
 * This matters because the known worst case here is silent: if a flash
 * commit runs before core 1 is up, core1_run_flash_op()'s park
 * handshake spins forever and the token is simply dark -- no LED, no
 * USB, indistinguishable from a brick.
 *
 * Check-in (standing the guard down) deliberately waits until USB is
 * actually ENUMERATED, not merely until main() is entered. Checking in
 * early is worse than useless: it disarms the guard and then lets the
 * image hang anyway, which is exactly how a dark token survived a
 * launch guard on silicon 2026-08-18. The cost is that a token in a
 * port that never enumerates falls back to DFU mode -- recoverable and
 * harmless, and much preferable to a permanent brick while the bootrom
 * BOOTSEL path is still available (before secure boot is enabled).
 *
 * All of it is harmless in a standalone build: nothing armed the
 * watchdog, so the check-in clears a bit that is already clear, and the
 * scratch writes are read by nobody. */
#define PQF_BOOT_STAGE_MARK   0x40u   /* "this came from the firmware" */

#define PQF_BOOT_MAIN         1u
#define PQF_BOOT_STDIO        2u
#define PQF_BOOT_BOARD        3u
#define PQF_BOOT_SERIAL       4u
#define PQF_BOOT_TUD_INIT     5u
#define PQF_BOOT_GDB          6u
#define PQF_BOOT_CTAPHID      7u
#define PQF_BOOT_CORE1        8u   /* core-1 worker launched           */
#define PQF_BOOT_CTAP2        9u   /* flash_store_init(): commits flash */
#define PQF_BOOT_TICK        10u
#define PQF_BOOT_LOOP        11u   /* main loop entered                 */
#define PQF_BOOT_MOUNTED     12u   /* host enumerated us -> check in    */

static void pqf_boot_stage(uint32_t stage)
{
    watchdog_hw->scratch[1] = (stage << 8) | PQF_BOOT_STAGE_MARK;
}

static void pqf_boot_checkin(void)
{
    hw_clear_bits(&watchdog_hw->ctrl, WATCHDOG_CTRL_ENABLE_BITS);
    /* Drop the bootloader's "come back into DFU" magic: now that we are
     * demonstrably up, a later ordinary reboot must boot the app. */
    watchdog_hw->scratch[2] = 0;
    watchdog_hw->scratch[3] = 0;
    watchdog_hw->scratch[0] = 0;
    /* Stand down the bootloader's RISC-V bounce sentinel (scratch 7):
     * this launch demonstrably worked, so the next Arm-side boot may
     * fire the annex launch again. No-op on Arm and standalone builds --
     * nothing else uses scratch 7 (the ROM only writes it for its magic
     * one-shot reboot types). */
    watchdog_hw->scratch[7] = 0;
}

int main(void)
{
    pqf_boot_stage(PQF_BOOT_MAIN);

    /* Brings the clocks up; with stdio_usb disabled this is a
     * no-op for serial, but still configures clk_sys etc. */
    stdio_init_all();
    pqf_boot_stage(PQF_BOOT_STDIO);

    /* Board pins first -- the XIAO's WS2812 power gate must be low
     * BEFORE USB enumeration starts or the 5 V rail sags and the
     * host's descriptor reads fail intermittently. */
    pqf_board_init();
    pqf_boot_stage(PQF_BOOT_BOARD);

    /* Pick the entropy source. Probes the I2C bus for a QRNG
     * and, if one answers and calibrates, puts it ahead of the on-die
     * TRNG for every RAND_bytes from here on. Must precede ctap2_init()
     * (which mints the master keys on a fresh device) and
     * core1_signer_init() (core 1 draws randomness too). Bounded: every
     * bus operation has a timeout and an empty bus is decided by a NAK,
     * so a hang here is not a possibility worth its own boot stage --
     * it would read as "stuck after BOARD". */
    pqf_rand_init();

    /* Fresh random USB serial before enumeration -- the macOS
     * HID-cache workaround (see usb_descriptors.c): a fixed serial
     * makes macOS serve stale cached capability bits across a
     * reflash until a physical replug. Matches the Rust port. */
    pqf_usb_serial_randomize();
    pqf_boot_stage(PQF_BOOT_SERIAL);

    /* Take direct ownership of the USB peripheral via TinyUSB.
     * RP2350 exposes a single USB Full Speed controller as root
     * hub port 0. */
    tud_init(0);
    pqf_boot_stage(PQF_BOOT_TUD_INIT);

    /* GDB stub debug builds: arm the on-token GDB stub (DebugMonitor
     * handler + FPB) before any breakpoint-able code runs. The USB
     * side is passive until a host opens the GDB CDC port. */
    pqf_gdb_init();
    pqf_boot_stage(PQF_BOOT_GDB);

#if defined(__riscv)
    /* Pure-RISC-V builds run INTERRUPT-FREE, like the silicon-
     * validated Rust RISC-V port: tud_init just enabled the USBCTRL
     * IRQ -- turn it back off and poll the controller handler from
     * pqf_usb_task() (fido_hid.c) instead. Rationale: the RISC-V
     * build froze non-deterministically at runtime flash commits,
     * always bracketing the two points where a pended IRQ burst gets
     * delivered around the XIP-off window (see pqf_usb_task's
     * comment); the Rust port -- identical flash sequence, identical
     * park handshake, zero interrupts -- never freezes on the same
     * silicon. The default alarm pool (TIMER0 IRQ) is disabled for
     * this build via PICO_TIME_DEFAULT_ALARM_POOL_DISABLED in
     * CMakeLists.txt, so after this line NO interrupt fires on
     * either Hazard3 core, ever. */
    irq_set_enabled(USBCTRL_IRQ, false);
#endif

    ctaphid_init();
    pqf_boot_stage(PQF_BOOT_CTAPHID);

    /* Launch the core-1 hybrid-PQC signing worker BEFORE ctap2_init().
     * ctap2_init() -> flash_store_init() commits the reserved
     * sign-counter block on every boot (and mints+commits the master
     * keys on a fresh device), and every flash commit parks core 1 via
     * core1_run_flash_op()'s handshake. Core 1 MUST already be running or
     * that handshake spins forever waiting for an ack that never comes --
     * a boot deadlock (dark LED, no USB enumeration). This mirrors the
     * Rust port, which spawns core 1 before CredStore::load for exactly
     * this reason. (Regression window: the handshake replaced pico-sdk
     * flash_safe_execute, whose lockout timed out + fell back when core 1
     * wasn't up, masking the ordering requirement.) */
    core1_signer_init();
    pqf_boot_stage(PQF_BOOT_CORE1);

    ctap2_init();
    pqf_boot_stage(PQF_BOOT_CTAP2);
    ctaphid_set_wink(on_wink);

    /* Install the long-op tick (USB service + CTAPHID KEEPALIVE) core 0
     * pumps while a core-1 signature is in flight, plus the user-presence
     * hook. Core 1 itself was already launched above. */
    fido_hid_install_tick();
    pqf_boot_stage(PQF_BOOT_TICK);

    /* Spin until the host is reading the CDC port; once it is,
     * print the banner. We don't gate the FIDO HID functionality
     * on this -- `fido2-token -L` works even with nothing
     * connected to CDC. */
    absolute_time_t banner_due = get_absolute_time();
    bool banner_sent = false;
    unsigned long tick = 0;

    pqf_boot_stage(PQF_BOOT_LOOP);
    bool checked_in = false;

    while (true) {
        pqf_usb_task();
        pqf_gdb_poll();            /* GDB stub: service GDB attach / Ctrl-C */

        /* Stand the bootloader's launch guard down only once the host
         * has actually enumerated us -- see the note above on why the
         * top of main() is the wrong place for this. */
        if (!checked_in && tud_mounted()) {
            pqf_boot_stage(PQF_BOOT_MOUNTED);
            pqf_boot_checkin();
            checked_in = true;
        }
#if defined(PQF_DFU_RUNTIME)
        dfu_detach_task();         /* DFU_DETACH -> bootloader        */
#endif
        led_task();
        fido_hid_poll_timeout();   /* L16: abort a stalled CTAPHID reassembly */

        if (!banner_sent && tud_cdc_connected()) {
            char buf[160];
            cdc_log("\r\n");
            cdc_log("Bruce C port -- multi-board, full CTAP 2.1 parity\r\n");
            snprintf(buf, sizeof buf,
                     "  board:         %s (sdk profile: %s)\r\n"
                     "  pico-sdk:      %s\r\n"
                     "  sys clk:       %u MHz\r\n",
                     pqf_board_name(), PICO_BOARD, PICO_SDK_VERSION_STRING,
                     (unsigned)(clock_get_hz(clk_sys) / 1000000u));
            cdc_log(buf);
#if defined(PQF_QRNG)
            if (pqf_qrng_present()) {
                snprintf(buf, sizeof buf,
                         "  rng:           QRNG @0x%02x on %s "
                         "(SHA-256, 64 raw -> 32); TRNG completes any shortfall\r\n",
                         PQF_QRNG_I2C_ADDR, pqf_qrng_hw_describe());
            } else {
                snprintf(buf, sizeof buf,
                         "  rng:           TRNG via pico_rand (no QRNG answered on %s)\r\n",
                         pqf_qrng_hw_describe());
            }
            cdc_log(buf);
#else
            cdc_log("  rng:           TRNG via pico_rand (QRNG support compiled out)\r\n");
#endif
#ifdef PQF_CORE1_RISCV
            cdc_log(core1_riscv_blob_running()
                    ? "  core 1:        RISC-V (Hazard3) signing blob -- MIXED mode\r\n"
                    : "  core 1:        RISC-V launch FAILED -- signing inline on core 0 (Arm)\r\n");
#endif
#if defined(PQF_SINGLE_CORE)
            snprintf(buf, sizeof buf,
                     "  cores:         SINGLE-CORE -- signer inline on core 0; the "
                     "crypto's yield hook pumps USB + KEEPALIVE every %u ms\r\n",
                     (unsigned)(PQF_YIELD_US / 1000u));
            cdc_log(buf);
#endif
#ifdef PQF_GDB_STUB
            cdc_log("  gdb stub:      ACTIVE (GDB stub debug build -- never ship). "
                    "Attach: target remote <the OTHER usbmodem tty>\r\n");
#endif
            cdc_log("  expect:        register + login (ES256 / hybrid PQC), "
                    "PIN, extensions, config via Chrome/libfido2\r\n");
            cdc_log("\r\n");
            banner_sent = true;
            banner_due = make_timeout_time_ms(1000);
        }

#if defined(PQF_UP_DEBUG)
        /* Free-running presence sampler, independent of wait_for_up().
         * The discriminator: if the pad reads PRESSED while the device is
         * idle with no CTAP operation running, the read itself is
         * unreliable. If it only misreads during an operation, something
         * in that path drives chip-select. docs/notes/UP-GATE-RETRACTED.md */
        {
            static absolute_time_t nxt;
            static bool last;
            if (time_reached(nxt)) {
                bool now = pqf_bootsel_pressed();
                pqf_up_idle_samples++;
                if (now) pqf_up_idle_high++;
                if (now && !last) pqf_up_idle_rising++;
                last = now;
                nxt = make_timeout_time_ms(2);
            }
        }
#endif

        if (banner_sent
            && time_reached(banner_due)
            && tud_cdc_connected())
        {
            char buf[160];
            /* Carry the core-1 state on the HEARTBEAT, not only the
             * one-shot boot banner. A host that opens the CDC port at
             * enumeration (macOS does) consumes that banner before any
             * human or script can read it, and the mixed-ISA build fails
             * SILENTLY: if the RISC-V blob does not launch, signing falls
             * back to core 0 and still returns correct signatures, so a
             * round trip cannot tell the two apart. Observed while
             * validating the relocated blob over DFU, 2026-08-20. */
            snprintf(buf, sizeof buf,
                     "Bruce C port, banner #%lu%s\r\n",
                     tick++,
#if defined(PQF_CORE1_RISCV)
                     core1_riscv_blob_running() ? "  core1=RISCV-BLOB"
                                                : "  core1=FALLBACK-ARM"
#else
                     ""
#endif
                     );

            cdc_log(buf);
            banner_due = make_timeout_time_ms(1000);
            /* Which entropy source is live, and how the bytes split. The
             * boot banner names the source once; a host that opened the
             * port at enumeration has already consumed that, and a QRNG
             * that fell over mid-session shows up only here. */
            {
                const struct pqf_rand_stats *rs = pqf_rand_stats();
#if defined(PQF_QRNG)
                const struct pqf_qrng_stats *qs = pqf_qrng_stats();
                snprintf(buf, sizeof buf,
                         "  [rng] src=%s qrng=%lu fallback=%lu | pkts=%lu hdr=%lu "
                         "hlth=%lu bus=%lu short=%lu%s\r\n",
                         pqf_rand_source_name(),
                         (unsigned long)rs->qrng_bytes,
                         (unsigned long)rs->fallback_bytes,
                         (unsigned long)qs->packets,
                         (unsigned long)qs->header_err,
                         (unsigned long)qs->health_err,
                         (unsigned long)qs->bus_err,
                         (unsigned long)qs->short_requests,
                         qs->lost ? " LOST" : "");
#else
                snprintf(buf, sizeof buf,
                         "  [rng] src=%s fallback=%lu (QRNG compiled out)\r\n",
                         pqf_rand_source_name(),
                         (unsigned long)rs->fallback_bytes);
#endif
                cdc_log(buf);
            }
#if defined(PQF_SINGLE_CORE)
            /* The single-core witness. `gap` is the worst stretch of any
             * inline op between two yield calls, tick time excluded: the
             * crypto's blind spot, where no KEEPALIVE can be sent -- it
             * has to stay well under ~100 ms. `tick` is the longest one
             * tick took (USB service + one KEEPALIVE frame, which waits
             * for the host to fetch the previous report): a long one
             * means a slow host poll, not a silent device. */
            /* One line, and a short one: the heartbeat burst (banner, [rng],
             * this) has to fit the 256-byte CDC TX FIFO or the tail is cut. */
            snprintf(buf, sizeof buf,
                     "  [1core] ops=%lu y=%lu ticks=%lu tick=%lu.%03lums gap=%lu.%03lums "
                     "sign=%lu.%03lu keygen=%lu.%03lu p256s=%lu.%03lu mlpub=%lu.%03lu\r\n",
                     (unsigned long)pqf_1core.ops,
                     (unsigned long)pqf_1core.yields,
                     (unsigned long)pqf_1core.ticks,
                     (unsigned long)(pqf_1core.max_tick_us / 1000u),
                     (unsigned long)(pqf_1core.max_tick_us % 1000u),
                     (unsigned long)(pqf_1core.max_gap_us / 1000u),
                     (unsigned long)(pqf_1core.max_gap_us % 1000u),
                     (unsigned long)(pqf_1core.kind_gap_us[0] / 1000u),
                     (unsigned long)(pqf_1core.kind_gap_us[0] % 1000u),
                     (unsigned long)(pqf_1core.kind_gap_us[1] / 1000u),
                     (unsigned long)(pqf_1core.kind_gap_us[1] % 1000u),
                     (unsigned long)(pqf_1core.kind_gap_us[2] / 1000u),
                     (unsigned long)(pqf_1core.kind_gap_us[2] % 1000u),
                     (unsigned long)(pqf_1core.kind_gap_us[3] / 1000u),
                     (unsigned long)(pqf_1core.kind_gap_us[3] % 1000u));
            cdc_log(buf);
#endif
#if defined(PQF_UP_DEBUG)
            /* Quiet-board check for the user-presence read: with nothing
             * touching it, high and rising must both stay 0 forever. Any
             * rising edge is a spurious press and is exactly what would
             * let wait_for_up() confirm with no human
             * (docs/notes/UP-GATE-RETRACTED.md). */
            snprintf(buf, sizeof buf,
                     "  [up-dbg] wait s=%lu h=%lu r=%lu | idle s=%lu h=%lu r=%lu\r\n",
                     (unsigned long)pqf_up_dbg_samples,
                     (unsigned long)pqf_up_dbg_high,
                     (unsigned long)pqf_up_dbg_rising,
                     (unsigned long)pqf_up_idle_samples,
                     (unsigned long)pqf_up_idle_high,
                     (unsigned long)pqf_up_idle_rising);
            cdc_log(buf);
#endif
        }

#if defined(PQF_TEST_NO_USER_BUTTON)
        /* TEST-ONLY (same never-ship gate as the buttonless UP): the
         * Feitian has no picotool reset interface, so every reflash
         * needs a physical BOOTSEL-hold replug. For automated
         * flash+test cycles, let the harness reboot the device into
         * BOOTSEL by writing <STX>BOOTSEL<ETX> to the CDC port. */
        {
            static const char magic[] = "\x02" "BOOTSEL" "\x03";
            static unsigned mi;
            uint8_t b;
            while (tud_cdc_available() && tud_cdc_read(&b, 1) == 1) {
                if (b == (uint8_t)magic[mi]) {
                    mi++;
                    if (magic[mi] == '\0')
                        rom_reset_usb_boot(0, 0);   /* noreturn */
                } else {
                    mi = (b == (uint8_t)magic[0]) ? 1 : 0;
                }
            }
        }
#endif

#if defined(PQF_SIGN_ARENA)
        /* Level-87 sign-heap forensics. The old failure mode here was
         * BLIND (newlib OOM -> pico_malloc panic -> wedge / poisoned
         * core); now an OOM on either allocator is a one-line CDC
         * report, and every new arena high-water prints so the margin
         * against PQF_SIGN_ARENA_BYTES is visible per sign. */
        static uint32_t arena_hw_logged;
        if (pqf_sign_arena_hw != arena_hw_logged) {
            arena_hw_logged = pqf_sign_arena_hw;
            char buf[80];
            snprintf(buf, sizeof buf,
                     "  [sign] arena high-water %lu B\r\n",
                     (unsigned long)arena_hw_logged);
            cdc_log(buf);
        }
        static bool arena_oom_logged;
        if (!arena_oom_logged && pqf_arena_oom_req) {
            arena_oom_logged = true;
            char buf[96];
            snprintf(buf, sizeof buf,
                     "!! SIGN ARENA OOM req=%lu B in-use=%lu B\r\n",
                     (unsigned long)pqf_arena_oom_req,
                     (unsigned long)pqf_arena_oom_hw);
            cdc_log(buf);
        }
        static bool heap_oom_logged;
        if (!heap_oom_logged && pqf_heap_oom_req) {
            heap_oom_logged = true;
            char buf[80];
            snprintf(buf, sizeof buf,
                     "!! CORE-0 HEAP OOM req=%lu B\r\n",
                     (unsigned long)pqf_heap_oom_req);
            cdc_log(buf);
        }
#endif

#if defined(PQF_XIP_STATS)
        /* XIP cache hit rate for the last hybrid sign (xip_stats.c).
         * One line per completed signature. Rate is basis points done
         * in integer math -- printf's float support is compiled out
         * (PICO_PRINTF_SUPPORT_FLOAT=0 in CMakeLists.txt) and a %f here
         * would print garbage. A saturated access counter is called
         * out rather than reported as a rate. */
        static uint32_t xip_seq_logged;
        if (pqf_xip_seq != xip_seq_logged) {
            xip_seq_logged = pqf_xip_seq;
            uint32_t acc = pqf_xip_acc, hit = pqf_xip_hit;
            char buf[96];
            if (acc == 0xFFFFFFFFu || hit == 0xFFFFFFFFu) {
                snprintf(buf, sizeof buf,
                         "  [xip] counter saturated -- sample invalid\r\n");
            } else {
                uint32_t bp = acc ? (uint32_t)(((uint64_t)hit * 10000u) / acc) : 0u;
                snprintf(buf, sizeof buf,
                         "  [xip] sign #%lu: %lu hits / %lu accesses "
                         "= %lu.%02lu%%\r\n",
                         (unsigned long)xip_seq_logged,
                         (unsigned long)hit, (unsigned long)acc,
                         (unsigned long)(bp / 100u),
                         (unsigned long)(bp % 100u));
            }
            cdc_log(buf);
        }
#endif

#if defined(__riscv)
        /* Trap forensics: if a core took a machine exception, say so
         * once over CDC. Core 1's handler keeps the device alive
         * (park handshake serviced, signs fail cleanly), so this line
         * is the difference between "device randomly broke" and
         * "misaligned access at mepc=0x...". mcause 4/6 = misaligned
         * load/store -- the Hazard3 trap the M33 doesn't have. */
        static bool trap_logged;
        if (!trap_logged && (pqf_trap_mcause[0] | pqf_trap_mcause[1])
            & 0x80000000u) {
            unsigned c = (pqf_trap_mcause[1] & 0x80000000u) ? 1 : 0;
            char buf[96];
            snprintf(buf, sizeof buf,
                     "!! CORE %u TRAP mcause=%lu mepc=0x%08lx\r\n",
                     c,
                     (unsigned long)(pqf_trap_mcause[c] & 0x7FFFFFFFu),
                     (unsigned long)pqf_trap_mepc[c]);
            cdc_log(buf);
            trap_logged = true;
        }
#endif
    }
}
