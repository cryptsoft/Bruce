/* main.c -- Bruce USB DFU bootloader.
 *
 * A second-stage bootloader occupying the first 128 KiB of flash. The
 * RP2350 bootrom boots this image; this image decides between:
 *
 *   - chaining into the application (the normal path), via the
 *     bootrom's rom_chain_image() -- which re-verifies the app's
 *     picobin signature once OTP secure boot is enabled, and
 *     handles copy_to_ram LOAD_MAPs and XIP setup either way; or
 *   - DFU mode: a USB DFU 1.1 device (TinyUSB class driver) that
 *     stock `dfu-util` can talk to. Incoming images stream into the
 *     STAGING slot, are signature-checked there (ECDSA-P256 over the
 *     pqf_image header -- see c/common/pqf_image.h), and only then
 *     copied over the app slot. A failed download or bad signature
 *     leaves the old application untouched.
 *
 * DFU mode is entered when any of these hold:
 *   1. the application requested it (DFU_DETACH on its runtime DFU
 *      interface -> watchdog-scratch handshake -> reboot lands here);
 *   2. the BOOTSEL button is held at boot (matters once secure boot disables
 *      the bootrom's own BOOTSEL paths -- until then the bootrom
 *      swallows the button first);
 *   3. the app slot fails signature verification (empty/corrupt/
 *      unsigned app), so a bricked app always leaves an update path.
 *
 * Power-loss safety: before the staging->app copy starts, an install
 * journal is written to the boot-state sector. If power is lost mid-
 * copy, the next boot finds the journal, re-verifies staging, and
 * redoes the copy. The persisted credential sectors at the top of
 * flash are never touched by any path in this file.
 *
 * The USB stack is interrupt-driven (USBCTRL IRQ on, the Arm model --
 * see dfu_mode_run()). Flash erase/program cannot race the ISR
 * fetching from XIP because flash_rom_op() masks interrupts across the
 * whole op, and is itself RAM-resident.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "pico/bootrom.h"
#include "hardware/flash.h"
#include "hardware/structs/qmi.h"   /* QMI window-0 fast-read save/restore */
#include "hardware/irq.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "hardware/structs/watchdog.h"
#include "hardware/structs/scb.h"    /* VTOR for the in-place app jump */
#include "boot/picobin.h"        /* partition permission bits */
#include "boot/picoboot_constants.h" /* REBOOT2_FLAG_* */        /* partition permission bits */
#include "pico/bootrom/lock.h"  /* bootrom locks for rom_chain_image */
#include "tusb.h"

#include "pqf_image.h"
#include "pqf_boot_pubkey.h"
#include "bootsel.h"
#include "usb_descriptors.h"

/* ---- the dev key must not leave the bench ------------------------ *
 *
 * pqf_boot_pubkey.h is generated, and it records whether the key it
 * carries is one of the two published in keys/. Their private halves are
 * in the repository on purpose, so a bootloader built against one will
 * install firmware signed by anybody who has cloned this tree -- the
 * signature check runs, passes, and means nothing.
 *
 * That is exactly right for development and catastrophic in the field,
 * and the two builds differ by nothing an operator would notice: same
 * source, same size, same behaviour, right up until someone else's image
 * installs. So the distinction is made where it cannot be overlooked --
 * a production build that reaches this line does not compile.
 *
 * To build a real one: run the ceremony in docs/SECUREBOOT.md, re-run
 * `pqf_sign.py export-pubkey --production`, and build with
 * -DPQF_PRODUCTION=1.
 */
#if defined(PQF_PRODUCTION) && PQF_BOOT_PUBKEY_IS_DEV
#error "PQF_PRODUCTION build against the published dev signing key: this bootloader would install firmware signed by anyone. Regenerate pqf_boot_pubkey.h from an offline key -- see 'Production key ceremony' in docs/SECUREBOOT.md."
#endif

bi_decl(bi_program_name("Bruce DFU bootloader"))
bi_decl(bi_program_description(
    "USB DFU 1.1 bootloader for the Bruce authenticator "
    "(signed-image enforcement; app slot at +0x21000)"))
#if defined(PQF_PROGRAM_URL)
bi_decl(bi_program_url(PQF_PROGRAM_URL))
#endif

/* ---- DFU-entry handshake (app -> bootloader) -------------------- *
 *
 * The application's DFU runtime interface writes this pair into the
 * watchdog scratch registers and reboots; scratch 2/3 are outside the
 * set pico-sdk's watchdog_reboot()/bootrom use (4..7). Cleared on
 * read so a later plain reboot boots the app again. */
#define PQF_DFU_SCRATCH_MAGIC   0x50514446u   /* "PQDF" */

/* Marker that the once-per-boot-chain REBOOT_TO_ARM has already run. */
#define PQF_ARM_FORCE_MAGIC     0x41524D46u   /* "ARMF" */

/* ---- RISC-V launch bounce sentinel (scratch 7) -------------------- *
 *
 * The RISC-V launch is a rom_reboot(NORMAL | TO_RISCV): the ROM's own
 * scan then finds the app's IMAGE_DEF in the block-loop annex and
 * launches it. If instead the RISC-V side rejects the annex, its only
 * other candidate is this (Arm) bootloader, so the ROM auto-switches
 * straight back here -- and without a marker we would re-fire the launch
 * forever (architecture reboot-tennis, USB never up: the exact failure
 * measured on 2026-08-20). scratch 7 is the marker: the ROM never
 * touches it on NORMAL reboots (it writes 2/3/4 every rom_reboot(), and
 * 5/6/7 only for its magic one-shot boot types -- datasheet sec. 5.2.4), and
 * the firmware clears it at check-in. Seeing it set here means the last
 * launch attempt did not end in a healthy app: fall into DFU instead of
 * trying again. */
#define PQF_RV_BOUNCE_MAGIC     0x52564131u   /* "RVA1" */

static bool dfu_requested_via_scratch(void)
{
    bool req = watchdog_hw->scratch[2] == PQF_DFU_SCRATCH_MAGIC
            && watchdog_hw->scratch[3] == ~PQF_DFU_SCRATCH_MAGIC;
    watchdog_hw->scratch[2] = 0;
    watchdog_hw->scratch[3] = 0;
    return req;
}

/* ---- Flash-op watchdog guard + trace ----------------------------- *
 *
 * A flash op that wedges used to take the whole token with it: the
 * bootloader is the reflash path, so a hang inside it left BOOT+RESET
 * by hand as the only way back. That is bad for a field update (a
 * flaky sector on a user's device bricks it) and it is what made this
 * bug so expensive to chase.
 *
 * So: arm the hardware watchdog across every flash op. If the op
 * completes, the watchdog is disarmed and nothing happened. If it
 * hangs, the watchdog resets the chip, the DFU-request magic we left
 * in scratch 2/3 brings us straight back into DFU mode, and the device
 * re-enumerates on its own. A wedge becomes a reboot, not a brick.
 *
 * scratch 0/1 carry a breadcrumb across that reset -- the last stage
 * the op reached -- which tud_descriptor_string_cb() bakes into the USB
 * serial string. `dfu-util -l` then names the step that hung without a
 * debugger, a UART, or anyone touching the board. */
#define PQF_TRACE_MAGIC     0x54524331u   /* "TRC1" */

/* Stage codes, in execution order. The one reported is the last stage
 * ENTERED, so the hang is in the step that code names. */
#define PQF_TR_IDLE         0x00u
#define PQF_TR_ENTER        0x01u   /* called, before touching QMI      */
#define PQF_TR_CONNECT      0x02u   /* in connect_internal_flash()      */
#define PQF_TR_EXIT_XIP     0x03u   /* in flash_exit_xip()              */
#define PQF_TR_ERASE        0x04u   /* in flash_range_erase()           */
#define PQF_TR_PROGRAM      0x05u   /* in flash_range_program()         */
#define PQF_TR_FLUSH        0x06u   /* in flash_flush_cache()           */
#define PQF_TR_ENTER_XIP    0x07u   /* in flash_enter_cmd_xip()         */
#define PQF_TR_QMI          0x08u   /* restoring the QMI fast-read cfg  */
#define PQF_TR_DONE         0x09u   /* returned cleanly                 */
#define PQF_TR_SELFTEST     0x7Fu   /* deliberate hang; proves the WD    */
#define PQF_TR_APP_LAUNCH   0x20u   /* jumped to the app; awaiting checkin*/
#define PQF_TR_CHAIN_TRY    0x30u   /* about to call rom_chain_image()    */
#define PQF_TR_CHAIN_ERR    0x31u   /* it returned; sector = -rc          */
#define PQF_TR_ANNEX_SYNC   0x32u   /* rewriting the block-loop annex     */
#define PQF_TR_ANNEX_ERR    0x33u   /* annex build/verify refused; in DFU */
#define PQF_TR_ANNEX_BOUNCE 0x34u   /* RISC-V launch bounced back; in DFU */

/* How long the launched app has to call watchdog_disable() before the
 * bootloader takes the chip back. Generous: the firmware reaches its
 * check-in long before it brings USB up. */
#define PQF_APP_CHECKIN_MS  10000u
/* Download-path stages. The flash op is only part of the story: the
 * readback below runs AFTER flash_rom_op returns, and both earlier
 * bisect builds (NOFLASH, ERASEONLY) return before reaching it, so
 * neither ever tested it. Give it its own code. */
#define PQF_TR_DL_BLOCK     0x10u   /* download block being handled     */
#define PQF_TR_FLUSH        0x11u   /* flush_sector entered             */
#define PQF_TR_READBACK     0x12u   /* memcmp against XIP after the op  */
#define PQF_TR_DL_OK        0x13u   /* block fully handled              */
#define PQF_TR_MANIFEST     0x14u   /* manifest / verify stage          */
#define PQF_TR_LOOP         0x15u   /* idle in the DFU service loop     */

/* How long a single 4 KiB erase+program may take before we call it
 * hung. A W25Q sector erase is ~45 ms typical, 400 ms worst case; 2 s
 * is far outside that and still quick enough to iterate on. */
#define PQF_FLASH_WD_MS     2000u

/* Last stage recorded by the run that reset us, 0 if we booted clean.
 * Read once in main(), before the scratch cells are reused. */
uint32_t pqf_dfu_trace_last;
uint32_t pqf_dfu_trace_sector;

/* Set when the previous boot died in the post-write XIP readback. That
 * readback is a belt-and-braces check only: the manifest stage
 * ECDSA-verifies the whole staged image before anything is copied over
 * the app slot, so a bad write is caught there regardless. Skipping it
 * costs early per-sector detection and nothing else -- which is a much
 * better trade than a download that cannot complete at all. */
static bool s_skip_readback;

static void trace_capture_and_clear(void)
{
    if (watchdog_hw->scratch[0] == PQF_TRACE_MAGIC) {
        pqf_dfu_trace_last   = watchdog_hw->scratch[1] & 0xFFu;
        pqf_dfu_trace_sector = watchdog_hw->scratch[1] >> 8;
    }
    watchdog_hw->scratch[0] = 0;
    watchdog_hw->scratch[1] = 0;
}

/* Which sector the in-flight op is writing, for the breadcrumb. */
static uint32_t s_trace_sector;

static inline void trace(uint32_t stage)
{
    /* MMIO only -- safe to call with the flash out of XIP mode. */
    watchdog_hw->scratch[0] = PQF_TRACE_MAGIC;
    watchdog_hw->scratch[1] = (s_trace_sector << 8) | (stage & 0xFFu);
}

static void flash_wd_arm(void)
{
    /* Come back into DFU mode, not into the app, if this bites. */
    watchdog_hw->scratch[2] = PQF_DFU_SCRATCH_MAGIC;
    watchdog_hw->scratch[3] = ~PQF_DFU_SCRATCH_MAGIC;
    /* scratch[4] == 0 tells the RP2350 bootrom "ordinary boot" rather
     * than one of its reboot-vector protocols. */
    watchdog_hw->scratch[4] = 0;
    watchdog_enable(PQF_FLASH_WD_MS, false);
}

/* Stand the guard down completely, and drop the DFU-return magic and
 * the breadcrumb, so a deliberate reboot boots the APP rather than
 * coming back here reporting a stale trace. */
static void flash_wd_disarm(void)
{
    hw_clear_bits(&watchdog_hw->ctrl, WATCHDOG_CTRL_ENABLE_BITS);
    watchdog_hw->scratch[2] = 0;
    watchdog_hw->scratch[3] = 0;
    watchdog_hw->scratch[0] = 0;
    watchdog_hw->scratch[1] = 0;
}

/* ---- Flash helpers ----------------------------------------------- */

static const uint8_t *xip(uint32_t flash_off)
{
    return (const uint8_t *)(XIP_BASE + flash_off);
}

/* Erase one 4 KiB sector and program `len` bytes into it (len <=
 * FLASH_SECTOR_SIZE; tail padded 0xFF to a page boundary). IRQs are
 * masked across the op -- nothing here may fetch or read XIP while the
 * flash is out of XIP mode. */
/* Direct boot-ROM flash sequence -- NOT pico-sdk's flash_range_erase /
 * flash_range_program.
 *
 * Why: c/firmware/src/flash_store.c abandoned the pico-sdk wrappers
 * because they hang nondeterministically after a few back-to-back
 * commits, and mirrors the Rust port's direct-ROM sequence instead.
 * This bootloader was written before that was understood and kept the
 * wrappers, and its DFU download died on the very first block:
 *
 *     Download [   ] 0%  0 bytes
 *     dfu-util: Error during download get_status (LIBUSB_ERROR_TIMEOUT)
 *
 * leaving the device unable to even SET_INTERFACE on retry (silicon,
 * 2026-08-17). Same wrappers, same class of hang, one flash write in.
 *
 * The sequence below is byte-for-byte the one both ports already run
 * reliably on this chip. Note it also explains why adding a QMI
 * window-0 save/restore here changed nothing: the pico-sdk wrappers
 * already save/restore the QMI CS1 window, so that was never the
 * missing piece.
 *
 * RAM-resident and interrupts masked: no XIP fetch may occur on this
 * core while QSPI is in command mode. */
typedef void (*rom_connect_internal_flash_fn)(void);
typedef void (*rom_flash_exit_xip_fn)(void);
typedef void (*rom_flash_range_erase_fn)(uint32_t, size_t, uint32_t, uint8_t);
typedef void (*rom_flash_range_program_fn)(uint32_t, const uint8_t *, size_t);
typedef void (*rom_flash_flush_cache_fn)(void);
typedef void (*rom_flash_enter_cmd_xip_fn)(void);

static void __no_inline_not_in_flash_func(flash_rom_op)(uint32_t off,
                                                        const uint8_t *prog,
                                                        uint32_t prog_len)
{
    rom_connect_internal_flash_fn connect_internal_flash_func =
        (rom_connect_internal_flash_fn)rom_func_lookup_inline(ROM_FUNC_CONNECT_INTERNAL_FLASH);
    rom_flash_exit_xip_fn flash_exit_xip_func =
        (rom_flash_exit_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_EXIT_XIP);
    rom_flash_range_erase_fn flash_range_erase_func =
        (rom_flash_range_erase_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_RANGE_ERASE);
    rom_flash_range_program_fn flash_range_program_func =
        (rom_flash_range_program_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_RANGE_PROGRAM);
    rom_flash_flush_cache_fn flash_flush_cache_func =
        (rom_flash_flush_cache_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_FLUSH_CACHE);
    rom_flash_enter_cmd_xip_fn flash_enter_cmd_xip_func =
        (rom_flash_enter_cmd_xip_fn)rom_func_lookup_inline(ROM_FUNC_FLASH_ENTER_CMD_XIP);

    /* flash_enter_cmd_xip() leaves XIP in slow 03h serial mode; this
     * bootloader executes from XIP, so put the fast-read setup back or
     * every fetch afterwards runs ~100x slower. */
    uint32_t qmi_timing = qmi_hw->m[0].timing;
    uint32_t qmi_rfmt   = qmi_hw->m[0].rfmt;
    uint32_t qmi_rcmd   = qmi_hw->m[0].rcmd;

    s_trace_sector = off / FLASH_SECTOR_SIZE;
    trace(PQF_TR_ENTER);

    uint32_t irq = save_and_disable_interrupts();
    __compiler_memory_barrier();

    trace(PQF_TR_CONNECT);   connect_internal_flash_func();
    trace(PQF_TR_EXIT_XIP);  flash_exit_xip_func();
    trace(PQF_TR_ERASE);
    flash_range_erase_func(off, FLASH_SECTOR_SIZE, FLASH_SECTOR_SIZE, 0x20);
    if (prog != NULL && prog_len != 0) {
        trace(PQF_TR_PROGRAM);
        flash_range_program_func(off, prog, prog_len);
    }
    trace(PQF_TR_FLUSH);      flash_flush_cache_func();
    trace(PQF_TR_ENTER_XIP);  flash_enter_cmd_xip_func();

    trace(PQF_TR_QMI);
    qmi_hw->m[0].timing = qmi_timing;
    qmi_hw->m[0].rfmt   = qmi_rfmt;
    qmi_hw->m[0].rcmd   = qmi_rcmd;
    __compiler_memory_barrier();

    restore_interrupts(irq);

    trace(PQF_TR_DONE);
}

/* Erase one 4 KiB sector and program `len` bytes into it. */
static void flash_write_sector(uint32_t flash_off, const uint8_t *data,
                               uint32_t len)
{
    static uint8_t page_buf[FLASH_SECTOR_SIZE];
    memcpy(page_buf, data, len);
    if (len < FLASH_SECTOR_SIZE)
        memset(page_buf + len, 0xFF, FLASH_SECTOR_SIZE - len);
    uint32_t prog_len = (len + FLASH_PAGE_SIZE - 1) & ~(uint32_t)(FLASH_PAGE_SIZE - 1);
    flash_rom_op(flash_off, page_buf, prog_len);
}

/* ---- Install journal (power-loss-safe staging->app copy) --------- */

#define PQF_BOOT_STATE_MAGIC    0x53425150u   /* "PQBS" */
#define PQF_BOOT_STATE_PENDING  1u
#define PQF_BOOT_STATE_CHECK    0xA5A5A5A5u

typedef struct {
    uint32_t magic;
    uint32_t state;
    uint32_t total_len;    /* header sector + image bytes staged */
    uint32_t check;        /* magic ^ state ^ total_len ^ CHECK  */
} pqf_boot_state_t;

static void boot_state_set_pending(uint32_t total_len)
{
    pqf_boot_state_t st = {
        .magic = PQF_BOOT_STATE_MAGIC,
        .state = PQF_BOOT_STATE_PENDING,
        .total_len = total_len,
        .check = PQF_BOOT_STATE_MAGIC ^ PQF_BOOT_STATE_PENDING
               ^ total_len ^ PQF_BOOT_STATE_CHECK,
    };
    flash_write_sector(PQF_BOOT_STATE_OFF, (const uint8_t *)&st, sizeof st);
}

static void boot_state_clear(void)
{
    flash_rom_op(PQF_BOOT_STATE_OFF, NULL, 0);   /* erase only */
}

static bool boot_state_is_pending(uint32_t *total_len)
{
    const pqf_boot_state_t *st = (const pqf_boot_state_t *)xip(PQF_BOOT_STATE_OFF);
    if (st->magic != PQF_BOOT_STATE_MAGIC
        || st->state != PQF_BOOT_STATE_PENDING
        || st->check != (st->magic ^ st->state ^ st->total_len
                         ^ PQF_BOOT_STATE_CHECK))
        return false;
    if (st->total_len < PQF_IMAGE_HDR_SIZE
        || st->total_len > PQF_SLOT_SIZE)
        return false;
    *total_len = st->total_len;
    return true;
}

/* Copy `total_len` bytes (header sector + image) from the staging
 * slot over the app slot, sector by sector through a RAM bounce
 * buffer, verifying each sector after programming. Returns false on a
 * readback mismatch (worn flash). */
static bool install_copy(uint32_t total_len)
{
    static uint8_t bounce[FLASH_SECTOR_SIZE];
    for (uint32_t off = 0; off < total_len; off += FLASH_SECTOR_SIZE) {
        /* Feed the session watchdog per sector. This loop is the one
         * legitimately long-running thing in the bootloader -- a 200 KiB
         * image is ~52 erase+program cycles and never returns to the
         * service loop that normally does the feeding, so without this
         * the guard fires PART WAY THROUGH A GOOD INSTALL and looks
         * exactly like the hang it exists to catch. Observed on silicon:
         * trace E04-S0076, an erase inside the app slot, which was the
         * watchdog interrupting healthy work rather than a fault. */
        watchdog_update();

        uint32_t n = total_len - off;
        if (n > FLASH_SECTOR_SIZE) n = FLASH_SECTOR_SIZE;
        /* Read the source into RAM BEFORE the destination erase -- both
         * slots live in the same QSPI part and XIP reads are illegal
         * while the flash op is in flight. */
        memcpy(bounce, xip(PQF_STAGE_SLOT_OFF + off), n);
        flash_write_sector(PQF_APP_SLOT_OFF + off, bounce, n);
        if (memcmp(bounce, xip(PQF_APP_SLOT_OFF + off), n) != 0)
            return false;
    }
    return true;
}

/* Verify whichever slot's header+image `slot_off` points at. */
static pqf_img_result_t verify_slot(uint32_t slot_off)
{
    const pqf_image_hdr_t *hdr = (const pqf_image_hdr_t *)xip(slot_off);
    return pqf_image_verify(hdr, xip(slot_off + PQF_IMAGE_HDR_SIZE),
                            PQF_BOOT_BOARD_ID,
                            pqf_boot_pubkey_x, pqf_boot_pubkey_y);
}

/* Boot-time recovery: a pending journal means a staging->app copy was
 * interrupted. Staging is intact (it was fully verified before the
 * journal was written), so verify it again and redo the copy. */
static void recover_pending_install(void)
{
    uint32_t total_len;
    if (!boot_state_is_pending(&total_len))
        return;
    const pqf_image_hdr_t *st = (const pqf_image_hdr_t *)xip(PQF_STAGE_SLOT_OFF);
    if (verify_slot(PQF_STAGE_SLOT_OFF) == PQF_IMG_OK
        && total_len == PQF_IMAGE_HDR_SIZE + st->image_len)
        install_copy(total_len);
    boot_state_clear();
}

/* ---- The block-loop annex (RISC-V launch) ------------------------- *
 *
 * ARCHSEL is the bootrom's decision, and the ROM only ever launches
 * what its own boot scan finds -- an architecture-switch reboot forgets
 * everything except the scan (docs/RISCV-DFU-BOOTROM-ANALYSIS.md). So
 * to run a RISC-V app the ROM's scan itself must find a RISC-V
 * IMAGE_DEF in slot 0. The annex arranges exactly that.
 *
 * This bootloader's picobin loop is the SDK's own two-block loop --
 * IMAGE_DEF block early in .text, IGNORED end block linked forward and
 * back -- with the end block pinned at the last bootloader sector
 * (PQF_ANNEX_OFF) by pqf_annex.ld. That sector is the annex. When a
 * verified RISC-V app is installed, the boot path below copies the
 * app's own IMAGE_DEF block into it (items verbatim, our loop-closing
 * link appended) and reboots NORMAL | TO_RISCV. The RISC-V-side scan
 * then sees two executable IMAGE_DEFs in slot 0 and prefers the one
 * for the current CPU (bootrom varm_flash_boot.c) -- the app's -- and
 * launches it from the slot-0 window: flash_start_offset 0, roll 0, no
 * ATRANS, entry at its linked 0x10021036. Identity-mapped, exactly
 * like the silicon-validated standalone boots, so the absolute
 * credential-store accesses stay valid.
 *
 * On the Arm side the same two blocks resolve the other way (this
 * bootloader wins), so Arm boots are untouched. If the annex is bad,
 * the RISC-V side falls back to the only other candidate -- this Arm
 * bootloader -- and the ROM's auto-switch bounces the chip straight
 * back here; the scratch-7 sentinel turns that bounce into DFU mode
 * instead of a launch loop. */

/* One parsed picobin block: where it is, how far its items run, and
 * what launch-relevant items it carries. */
typedef struct {
    uint32_t off;            /* flash offset of the 0xffffded3 marker  */
    uint32_t words;          /* marker..LAST item inclusive, in words  */
    uint32_t cpu;            /* IMAGE_TYPE EXE_CPU field, ~0u if none  */
    bool     entry_present;  /* has ENTRY_POINT (pc, sp)               */
    bool     portable;       /* only items that survive being copied   */
} pqf_block_t;

/* Item sizes: type bit 7 selects an 8-bit (1BS) or 16-bit (2BS) word
 * count in the byte(s) above the type -- same decode as the bootrom. */
static uint32_t item_size_words(uint32_t item)
{
    return (item & 0x80u) ? ((item >> 8) & 0xFFFFu) : ((item >> 8) & 0xFFu);
}

/* ROM-faithful validation of one candidate block starting at w[0]:
 * items to a LAST whose size equals the words before it, then the end
 * marker two words on. Fills `out` (out->off is the caller's). */
static bool parse_block(const uint32_t *w, uint32_t max_words, pqf_block_t *out)
{
    if (w[0] != PICOBIN_BLOCK_MARKER_START)
        return false;
    out->cpu = ~0u;
    out->entry_present = false;
    out->portable = true;
    if (max_words > PICOBIN_MAX_BLOCK_SIZE / 4u)
        max_words = PICOBIN_MAX_BLOCK_SIZE / 4u;   /* ROM buffer bound */
    uint32_t pos = 1;
    while (pos + 2u < max_words) {
        uint32_t it = w[pos];
        uint32_t type = it & 0xFFu;
        uint32_t size = item_size_words(it);
        if (size == 0)
            return false;
        if (type == PICOBIN_BLOCK_ITEM_2BS_LAST) {
            if (size != pos - 1u)
                return false;                       /* size mismatch */
            if (w[pos + 2u] != PICOBIN_BLOCK_MARKER_END)
                return false;
            out->words = pos + 1u;                  /* marker..LAST  */
            return true;
        }
        switch (type) {
        case PICOBIN_BLOCK_ITEM_1BS_IMAGE_TYPE & 0xFFu:
            out->cpu = (it >> 24) & 0x07u;          /* EXE_CPU field */
            break;
        case PICOBIN_BLOCK_ITEM_1BS_ENTRY_POINT & 0xFFu:
            if (size >= 3u)
                out->entry_present = true;          /* pc, sp present */
            break;
        case PICOBIN_BLOCK_ITEM_1BS_VECTOR_TABLE & 0xFFu:
        case PICOBIN_BLOCK_ITEM_1BS_VERSION & 0xFFu:
        case PICOBIN_BLOCK_ITEM_2BS_IGNORED & 0xFFu:
            break;               /* absolute/inert: safe to transplant */
        case PICOBIN_BLOCK_ITEM_LOAD_MAP & 0xFFu:
            /* Absolute-address load maps stay valid wherever the block
             * sits; window-relative ones do not survive a copy. The
             * relative flag is the header sign bit (boot/picobin.h:
             * picobin_load_map_is_relative). */
            if ((int32_t)it >= 0)
                out->portable = false;
            break;
        default:
            /* HASH_DEF, SIGNATURE, ROLLING_WINDOW_DELTA, anything
             * unknown: position-dependent or launch-altering. A block
             * carrying these must not be transplanted -- refusing keeps
             * the failure a visible DFU fallback instead of a corrupt
             * launch. */
            out->portable = false;
            break;
        }
        pos += size;
    }
    return false;
}

/* Find the first valid block in the first 4 KiB of a window -- the same
 * hunt the ROM performs, including walking on past words that merely
 * look like a start marker (this image contains that constant in its
 * literal pool). */
static bool find_first_block(uint32_t window_off, pqf_block_t *out)
{
    const uint32_t *w = (const uint32_t *)xip(window_off);
    for (uint32_t i = 0; i < 0x1000u / 4u; i++) {
        if (w[i] != PICOBIN_BLOCK_MARKER_START)
            continue;
        if (parse_block(w + i, PICOBIN_MAX_BLOCK_SIZE / 4u, out)) {
            out->off = window_off + i * 4u;
            return true;
        }
    }
    return false;
}

/* Compose the annex sector: the app's IMAGE_DEF block verbatim through
 * its LAST item (or the IGNORED placeholder), then OUR link word -- the
 * loop-closing signed byte offset back to the loop's first block -- and
 * the end marker. Returns the byte length. */
static uint32_t annex_compose(uint32_t *w, const pqf_block_t *app,
                              uint32_t first_block_off)
{
    uint32_t n = 0;
    if (app != NULL) {
        const uint32_t *src = (const uint32_t *)xip(app->off);
        for (uint32_t i = 0; i < app->words; i++)
            w[n++] = src[i];
    } else {
        w[n++] = PICOBIN_BLOCK_MARKER_START;
        w[n++] = (1u << 8) | (PICOBIN_BLOCK_ITEM_2BS_IGNORED & 0xFFu);
        w[n++] = (1u << 8) | (PICOBIN_BLOCK_ITEM_2BS_LAST & 0xFFu);
    }
    w[n++] = (uint32_t)((int32_t)first_block_off - (int32_t)PQF_ANNEX_OFF);
    w[n++] = PICOBIN_BLOCK_MARKER_END;
    return n * 4u;
}

/* Make the annex hold `app`'s IMAGE_DEF (NULL = the inert placeholder).
 * Idempotent: no flash touched when the sector already matches, so the
 * common boot pays one memcmp, not an erase. */
static bool annex_sync(const pqf_block_t *app)
{
    /* A copied block is capped at the ROM's own block-size bound, plus
     * our two trailing words. */
    static uint32_t desired[PICOBIN_MAX_BLOCK_SIZE / 4u + 2u];

    pqf_block_t first;
    if (!find_first_block(0, &first))
        return false;   /* no loop head in our own first 4 KiB?! */
    if (first.off >= PQF_ANNEX_OFF)
        return false;   /* the annex must not be the loop head */

    uint32_t len = annex_compose(desired, app, first.off);
    if (memcmp(desired, xip(PQF_ANNEX_OFF), len) == 0)
        return true;

    /* Guard the rewrite like every other flash op in this file: a
     * wedged erase here would otherwise hang a pre-USB boot forever.
     * If it bites, the reset lands in DFU with the stage named. */
    s_trace_sector = PQF_ANNEX_OFF / FLASH_SECTOR_SIZE;
    trace(PQF_TR_ANNEX_SYNC);
    flash_wd_arm();
    flash_write_sector(PQF_ANNEX_OFF, (const uint8_t *)desired, len);
    bool ok = memcmp(desired, xip(PQF_ANNEX_OFF), len) == 0;
    flash_wd_disarm();
    return ok;
}

/* ---- Boot the application ---------------------------------------- */

static void try_boot_app(void)
{
    if (verify_slot(PQF_APP_SLOT_OFF) != PQF_IMG_OK)
        return;   /* fall through into DFU mode */

    const pqf_image_hdr_t *hdr = (const pqf_image_hdr_t *)xip(PQF_APP_SLOT_OFF);
    (void)hdr;

#if defined(PQF_BOOT_LAUNCH_CHAIN)
    /* rom_chain_image(): the bootrom parses the app's picobin block
     * loop and -- once OTP secure boot is enabled -- re-verifies
     * the picotool seal against the OTP boot keys before entry.
     *
     * KNOWN ISSUE (Tiny 2350, 2026-07-20): chaining an app linked
     * in-place at 0x10021000 hangs -- the standalone app at 0x10000000
     * enumerates perfectly, so the fault is the chain launch, not the
     * app. The bootrom's partition/ATRANS model wants the image linked
     * at 0x10000000 and remaps it, but this app does ABSOLUTE
     * top-of-flash credential access (0x103FF000, flash_store.c), which
     * ATRANS would break.
     *
     * ROOT-CAUSED (2026-08-21, bootrom source + datasheet sec. 5.1.19-20):
     * the "hang" was never a hang. An Arm app is launched ROLLED (the
     * ROM always ATRANS-maps a chained window to 0x10000000; identity
     * needs roll==0, and negative ROLLING_WINDOW_DELTAs only come in
     * -4MiB steps, so an image at 0x21000 cannot opt out) -- it runs,
     * dies on its first absolute reference, and the launch guard reads
     * that as a hang. A RISC-V app passes verification and the ROM
     * redo-reboots for the arch switch (NO_RETURN, so the call cannot
     * come back) -- but the redo re-issues the PREVIOUS boot's type and
     * params, the chain window is forgotten, and the post-switch scan
     * finds only this Arm bootloader and flips back. Chaining this
     * layout can never work. Full story with citations:
     * docs/RISCV-DFU-BOOTROM-ANALYSIS.md.
     *
     * CORRECTION (2026-08-20): the older wording here said secure boot
     * "needs" this path. That is overstated. With OTP secure boot on,
     * the ROM verifies and launches THIS bootloader, and the bootloader
     * then ECDSA-verifies the app against pqf_boot_pubkey.h -- a key
     * compiled into an image the ROM has already authenticated, so the
     * trust chain is unbroken either way. What the ROM path adds is an
     * OTP-anchored root key and ROM-enforced rollback, which is
     * hardening rather than a precondition.
     *
     * What genuinely DOES require this path, both measured:
     *   - RISC-V apps. ARCHSEL is a bootrom decision; the in-place
     *     handover below is Arm instructions and cannot switch
     *     architecture. All six RISC-V configs install, verify, and
     *     never run.
     *   - copy_to_ram apps. Only the ROM processes the picobin
     *     LOAD_MAP, which is why PQF_APP_OFFSET forces XIP -- and
     *     ML-DSA-87 is about twice as fast from SRAM. Until then the in-place jump below is the launch
     * path (the bootloader's own ECDSA verify above is the trust gate). */
    /* The ROM wants >= 3264 bytes of word-aligned scratch (SDK: "3.25K is
     * a good choice"); 4 KiB is comfortably over. */
    static __attribute__((aligned(4))) uint8_t workarea[4096];

    /* Guard the attempt. Historically a failed chain here was recorded
     * only as "it hangs", which conflates two very different things: the
     * ROM refusing the image (it RETURNS a negative code, per the SDK
     * contract) and the ROM never coming back at all. Arm the launch
     * guard so a true hang resets into DFU instead of stranding the
     * token, and capture the return code so a refusal names itself in
     * the USB serial string rather than vanishing. */
    /* Guard WITHOUT the DFU magic: a hang must land in an ordinary boot
     * so try_boot_app() runs again and picks up the next strategy. With
     * the magic set we would drop into DFU and the cycle would stall
     * after a single attempt. */
    watchdog_hw->scratch[2] = 0;
    watchdog_hw->scratch[3] = 0;
    watchdog_hw->scratch[4] = 0;
    watchdog_enable(PQF_APP_CHECKIN_MS, false);

    /* Call the ROM entry DIRECTLY rather than through pico-sdk's
     * rom_chain_image() wrapper. The wrapper's epilogue is
     *
     *     bootrom_release_lock(BOOTROM_LOCK_ENABLE);
     *     rc = func(...);
     *     bootrom_acquire_lock_blocking(BOOTROM_LOCK_ENABLE);
     *
     * and that re-acquire is a hardware boot-lock spin with NO timeout.
     * If the ROM's failure path leaves the lock held, the wrapper
     * deadlocks AFTER the ROM has already answered -- which is
     * indistinguishable from the ROM itself hanging, and is exactly how
     * this was recorded as "chaining hangs" since 2026-07-20. Bypassing
     * the wrapper turns that class of failure back into a return code.
     *
     * We do the interrupt masking ourselves, which is all the wrapper
     * otherwise contributed. */
    typedef int (*chain_fn)(uint8_t *, uint32_t, uint32_t, uint32_t);
    chain_fn chain = (chain_fn)rom_func_lookup_inline(ROM_FUNC_CHAIN_IMAGE);

    /* Strategy cycling. Measured 2026-08-20:
     *
     *   no lock handling            -> -19 LOCK_REQUIRED (fails early)
     *   hold SHA/FLASH/OTP          -> hangs (past the gate, dies deeper)
     *   release BOOTROM_LOCK_ENABLE -> hangs (same)
     *
     * So the lock check is a gate, not the bug: satisfy it either way and
     * the ROM gets further and then hangs. Each hypothesis for THAT hang
     * used to cost a physical BOOT+RESET, so instead the strategy index
     * lives in watchdog scratch 5, survives the guard reset, and advances
     * on every attempt. One press now walks the whole list: try, hang,
     * guard resets into DFU, reinstall, next strategy.
     *
     * scratch 5 is outside the DFU magic (2/3), the trace (0/1) and the
     * bootrom's own reboot vector (4). */
    /* Walk state must be self-validating. scratch 5/6 are uninitialised
     * on a cold boot, and the results accumulator only ORs into
     * scratch 6 -- so garbage there would make every nibble read as 15
     * and the whole table would be fiction. A magic in the high half
     * says "this is a walk in progress"; anything else starts a fresh
     * walk and clears the accumulator. */
/* NOTE ON CYCLING (silicon, 2026-08-20): the strategies are NOT
 * independent. rom_load_partition_table() caches the table in BOOTRAM,
 * which SURVIVES a watchdog reset, so any strategy that runs after one
 * which loaded a table sees different ROM state than it would on a cold
 * boot. Proof: the release(ENABLE) control returned -4 when it ran
 * first, and hung when the same code ran fourth. Only the FIRST
 * strategy of a walk is a clean measurement; treat the rest as
 * suggestive at best. PQF_CHAIN_ONLY pins the walk to a single strategy
 * so it always runs from a clean boot. */
#define PQF_CHAIN_WALK_MAGIC 0x5A5A0000u
    uint32_t walk = watchdog_hw->scratch[5];
    uint32_t strat;
    if ((walk & 0xFFFF0000u) != PQF_CHAIN_WALK_MAGIC) {
#if defined(PQF_CHAIN_ONLY)
        strat = (uint32_t)(PQF_CHAIN_ONLY);    /* pinned single strategy */
#else
        strat = 0u;                            /* fresh walk */
#endif
        watchdog_hw->scratch[6] = 0u;          /* clear the accumulator */
    } else {
        strat = walk & 0xFFu;
        if (strat > 4u) strat = 4u;
    }
#if defined(PQF_CHAIN_ONLY)
    /* Pinned: run this one strategy on a clean boot, then stop. Setting
     * only the START index was not enough -- the walk still advanced and
     * strategies 2..3 ran contaminated again (observed 2026-08-20). */
    if ((walk & 0xFFFF0000u) != PQF_CHAIN_WALK_MAGIC) {
        watchdog_hw->scratch[5] = PQF_CHAIN_WALK_MAGIC | 4u;   /* one shot */
    } else {
        strat = 4u;
    }
    if (strat < 4u) {
    } else {
#else
    if (strat < 4u) {
        watchdog_hw->scratch[5] = PQF_CHAIN_WALK_MAGIC | (strat + 1u);
    } else {
#endif
        /* All four tried. Publish the accumulated results and give up on
         * chaining for this boot -- scratch 6 holds one nibble per
         * strategy: 0 = hung (never came back to record anything),
         * otherwise the absolute value of the ROM's return code,
         * saturated at 15. */
        pqf_dfu_trace_last   = PQF_TR_CHAIN_ERR;
        pqf_dfu_trace_sector = watchdog_hw->scratch[6] & 0xFFFFu;
        watchdog_hw->scratch[5] = 0;           /* invalidate the walk */
        goto chain_done;
    }

    uint32_t region = XIP_BASE + PQF_APP_IMAGE_OFF;
    uint32_t rsize  = hdr->image_len;
    int rc = 0;

    /* Strategy 0 mirrors the ONE known-working reference:
     * pico-examples bootloaders/encrypted/enc_bootloader.c. It does two
     * things before chaining, and no earlier attempt of ours did both:
     *
     *     rom_load_partition_table(workarea, sizeof workarea, false);
     *     rc = rom_chain_image(workarea, sizeof workarea, base, size);
     *
     * Both through the pico-sdk WRAPPERS, with no manual lock handling.
     * That is safe because a pico-sdk image already owns
     * BOOTROM_LOCK_ENABLE (runtime_init_bootrom_locking_enable, which
     * this bootloader links -- verified in the ELF), so the wrappers'
     * release/re-acquire pairs are balanced and the blocking re-acquire
     * cannot deadlock. Earlier attempts each missed one piece: no
     * partition-table load, or hand-rolled locks, or the wrapper
     * bypassed entirely.
     *
     * 1 and 3 are CONTROLS reproducing previously measured behaviour, so
     * a harness regression shows up instead of hiding. */
    if (strat == 0u || strat == 2u) {
        if (strat == 2u) {
            /* As 0, plus flash permissions for the app slot in the
             * bootrom's RUNTIME view only -- nothing written to flash,
             * so this cannot lock picotool out the way an embedded
             * partition table did on 2026-08-20. */
            (void)rom_add_flash_runtime_partition(
                PQF_APP_SLOT_OFF, PQF_SLOT_SIZE,
                PICOBIN_PARTITION_PERMISSION_S_R_BITS
              | PICOBIN_PARTITION_PERMISSION_S_W_BITS
              | PICOBIN_PARTITION_PERMISSION_NS_R_BITS
              | PICOBIN_PARTITION_PERMISSION_NS_W_BITS
              | PICOBIN_PARTITION_PERMISSION_NSBOOT_R_BITS
              | PICOBIN_PARTITION_PERMISSION_NSBOOT_W_BITS);
        }
        (void)rom_load_partition_table(workarea, sizeof workarea, false);
        s_trace_sector = 0xFF00u | strat;
        trace(PQF_TR_CHAIN_TRY);
        rc = rom_chain_image(workarea, sizeof workarea, region, rsize);
        goto chain_returned;
    }

    if (strat == 1u) {
        (void)bootrom_try_acquire_lock(BOOTROM_LOCK_SHA_256);  /* SHA only */
    } else {
        bootrom_release_lock(BOOTROM_LOCK_ENABLE);             /* expect -4 */
    }

    s_trace_sector = 0xFF00u | strat;
    trace(PQF_TR_CHAIN_TRY);
    {
        uint32_t chain_irq = save_and_disable_interrupts();
        rc = chain(workarea, sizeof workarea, region, rsize);
        restore_interrupts(chain_irq);
    }
    if (strat == 1u) bootrom_release_lock(BOOTROM_LOCK_SHA_256);
    else             (void)bootrom_try_acquire_lock(BOOTROM_LOCK_ENABLE);

chain_returned:

    {   /* Record this strategy's outcome; a hang leaves its nibble 0. */
        uint32_t a = (uint32_t)(rc < 0 ? -rc : rc);
        if (a > 15u) a = 15u;
        if (a == 0u) a = 15u;               /* 0 would read as "hung" */
        watchdog_hw->scratch[6] |= (a << (4u * strat));
    }


    /* Only reached when the ROM refused the image: on success the call
     * does not return. Publish this strategy's code, then let the guard
     * reboot us into the next strategy rather than falling into DFU --
     * a returned error is just as much a "try the next idea" as a hang.
     * The accumulated results are reported once all four are done. */
    pqf_dfu_trace_last   = PQF_TR_CHAIN_ERR;
    pqf_dfu_trace_sector = (uint32_t)((strat * 1000u) + (uint32_t)(rc < 0 ? -rc : rc));
    watchdog_reboot(0, 0, 0);
    while (true) tight_loop_contents();

chain_done:
    hw_clear_bits(&watchdog_hw->ctrl, WATCHDOG_CTRL_ENABLE_BITS);
    watchdog_hw->scratch[2] = 0;
    watchdog_hw->scratch[3] = 0;
    /* Bootrom codes: 4 NOT_PERMITTED, 5 INVALID_ARG, 10 INVALID_ADDRESS,
     * 11 BAD_ALIGNMENT, 12 INVALID_STATE, 13 BUFFER_TOO_SMALL,
     * 14 PRECONDITION_NOT_MET, 16 INVALID_DATA, 17 NOT_FOUND,
     * 19 LOCK_REQUIRED.  Falls through into DFU mode below. */
#else
    /* In-place vector-table jump (the RP2040-style launch). The app is
     * linked to run at PQF_APP_IMAGE_OFF and executes there via XIP
     * with an IDENTITY address map, so its absolute flash accesses
     * (credential store at the top of flash) stay valid -- unlike the
     * ATRANS remap a partition/chain launch imposes. The bootloader
     * has already ECDSA-verified the image (verify_slot above).
     *
     * The vector table sits at the image base: [0] = initial MSP,
     * [1] = reset handler. Point VTOR there, load SP, branch. */
    const uint32_t *vt = (const uint32_t *)(XIP_BASE + PQF_APP_IMAGE_OFF);
    uint32_t sp = vt[0];
    uint32_t entry = vt[1];

    /* ---- Put both cores back on Arm before an Arm launch ---------- *
     *
     * A RISC-V launch switches BOTH cores with rom_reboot(TO_RISCV), and
     * that selection is NOT undone by a reset or by erasing flash -- only
     * by power loss. Boot an Arm image afterwards and core 0 runs Arm
     * while core 1 is still Hazard3, so the firmware's core-1 launch
     * handshake never completes: it hangs at core1_signer_init, which
     * the breadcrumb reports as stage 8 (E64-S0008). Measured
     * 2026-08-24, and `picotool erase -a` plus a clean bootloader does
     * not fix it because the state is ARCHSEL, not flash.
     *
     * REBOOT_TO_ARM is the counterpart of the TO_RISCV we already use.
     * Fire it once per boot chain, guarded by a scratch marker so it
     * cannot loop; the marker is absent after power-on (scratch is
     * cleared) so the cost is one extra reboot on a cold start, and
     * nothing at all once set. Cleared on the RISC-V path below so the
     * next Arm boot re-arms it. */
    if (watchdog_hw->scratch[6] != PQF_ARM_FORCE_MAGIC) {
        watchdog_hw->scratch[6] = PQF_ARM_FORCE_MAGIC;
        rom_reboot(REBOOT2_FLAG_REBOOT_TYPE_NORMAL
                 | REBOOT2_FLAG_REBOOT_TO_ARM
                 | REBOOT2_FLAG_NO_RETURN_ON_SUCCESS, 1, 0, 0);
        /* Falls through if the ROM refuses (already Arm on some parts). */
    }

    /* Which architecture is this image? Its picobin IMAGE_DEF says.
     * (Every SDK image embeds one; an image without one is treated as
     * Arm and takes the in-place jump, same as always. The earlier
     * PC_SP / FLASH_UPDATE reboot experiments that lived here are
     * root-caused dead ends -- docs/RISCV-DFU-BOOTROM-ANALYSIS.md.) */
    pqf_block_t app;
    bool have_app_block = find_first_block(PQF_APP_IMAGE_OFF, &app);

    /* Consume any bounce sentinel from a previous RISC-V attempt no
     * matter what is installed now, so it can never go stale. */
    uint32_t bounce = watchdog_hw->scratch[7];
    watchdog_hw->scratch[7] = 0;

    if (have_app_block && app.cpu == PICOBIN_IMAGE_TYPE_EXE_CPU_RISCV) {
        /* ---- RISC-V: launch through the ROM via the annex --------- */
        if (bounce == PQF_RV_BOUNCE_MAGIC) {
            /* The last TO_RISCV reboot came back here without the app
             * checking in: the RISC-V side rejected the annex (the ROM
             * auto-switched straight back), or the app died and the
             * board was reset. Re-firing would loop the architectures
             * forever; fall into DFU and let the serial string say why. */
            s_trace_sector = 0xFFF9u;
            trace(PQF_TR_ANNEX_BOUNCE);
            return;
        }
        if (!app.entry_present || !app.portable || !annex_sync(&app)) {
            /* Block not transplantable (no entry point, or it carries
             * hash/signature/relative-load-map items), or the annex
             * write failed its readback. The app cannot be launched;
             * stay recoverable in DFU. */
            s_trace_sector = 0xFFF8u;
            trace(PQF_TR_ANNEX_ERR);
            return;
        }
        /* Hand over to the ROM. It owns the watchdog and scratch 2/3/4
         * from here (its reboot parameter registers), which is why the
         * launch guard cannot cover this path: the sentinel covers the
         * bounce case, the firmware's check-in clears it on success,
         * and an app that verifies, launches and then crashes before
         * check-in still costs a button -- the same exposure the
         * standalone boots have always had. */
        watchdog_hw->scratch[6] = 0;   /* re-arm the Arm forcing */
        watchdog_hw->scratch[7] = PQF_RV_BOUNCE_MAGIC;
        s_trace_sector = 0xFFFBu;
        trace(PQF_TR_APP_LAUNCH);
        rom_reboot(REBOOT2_FLAG_REBOOT_TYPE_NORMAL
                 | REBOOT2_FLAG_REBOOT_TO_RISCV
                 | REBOOT2_FLAG_NO_RETURN_ON_SUCCESS, 1, 0, 0);
        /* Only reached if the ROM refused the switch (RISC-V disabled
         * by OTP on this part). Nothing else can launch this image. */
        watchdog_hw->scratch[7] = 0;
        s_trace_sector = 0xFFF7u;
        trace(PQF_TR_ANNEX_ERR);
        return;
    }

    /* Arm image from here on. Hygiene first: if the annex still carries
     * a RISC-V IMAGE_DEF from a previous install, neutralize it -- a
     * stale annex entry would hand any RISC-V-side boot a dangling
     * entry point into what is now an Arm image. Best-effort: failure
     * is not fatal to the Arm app (ARCHSEL only ever becomes RISC-V
     * through the launch above). */
    pqf_block_t annex_now;
    if (parse_block((const uint32_t *)xip(PQF_ANNEX_OFF),
                    PICOBIN_MAX_BLOCK_SIZE / 4u, &annex_now)
        && annex_now.cpu == PICOBIN_IMAGE_TYPE_EXE_CPU_RISCV)
        (void)annex_sync(NULL);

    /* USB was never brought up on this path (tud_init only runs in
     * dfu_mode_run), so nothing to tear down -- just mask interrupts,
     * repoint the vector table at the app, load its stack pointer and
     * branch to its reset handler.
     *
     * Interrupts are masked only across the VTOR/MSP switch and are
     * RE-ENABLED in the branch below. Leaving PRIMASK set is not
     * survivable: the bootrom starts an app with interrupts on and
     * nothing in the pico-sdk runtime clears PRIMASK, so the app
     * inherits a fully masked core. On Arm the firmware's USB is
     * interrupt-driven (fido_hid.c: "the USBCTRL IRQ is live"; only
     * the RISC-V build polls), so the token runs, reaches main() and
     * checks in -- and then never enumerates. Dark, with the launch
     * guard already stood down. Cost most of a day on silicon
     * 2026-08-18, and the tell was that a shim calling
     * reset_usb_boot() chain-loaded perfectly: it needs no
     * interrupts. */
    /* Launch guard. The app must check in (watchdog_disable(), which
     * pqf_boot_checkin() does once USB is enumerated) within
     * PQF_APP_CHECKIN_MS or the chip resets straight back into DFU
     * mode. Without this, an app that verifies but does not boot is a
     * BRICK: the bootloader jumps into it every time, so there is no
     * FIDO, no DFU and no BOOTSEL, and the only way back is holding
     * BOOT and tapping RESET by hand. A DFU bootloader whose whole
     * purpose is recovering a bad image must not have that hole -- it
     * is the one failure it cannot afford. Observed on silicon
     * 2026-08-18 with an image that installed perfectly and then never
     * enumerated. */
    s_trace_sector = 0xFFFEu;
    trace(PQF_TR_APP_LAUNCH);
    watchdog_hw->scratch[2] = PQF_DFU_SCRATCH_MAGIC;
    watchdog_hw->scratch[3] = ~PQF_DFU_SCRATCH_MAGIC;
    watchdog_hw->scratch[4] = 0;
    watchdog_enable(PQF_APP_CHECKIN_MS, false);

    (void)save_and_disable_interrupts();   /* mask IRQs; no restore -- we jump away */
    scb_hw->vtor = (uintptr_t)vt;
    __dsb();
    __isb();
    __asm volatile (
        "msr msp, %0\n"
        "cpsie i\n"          /* hand the app a core with IRQs ENABLED */
        "bx  %1\n"
        : : "r"(sp), "r"(entry) : "memory");
    __builtin_unreachable();
#endif
}

/* ---- DFU state machine -------------------------------------------- *
 *
 * TinyUSB invokes the download/manifest callbacks from tud_task();
 * both are completed asynchronously from the main loop via
 * tud_dfu_finish_flashing() while the host sleeps out the
 * bwPollTimeout we return from tud_dfu_get_timeout_cb(). */

static struct {
    volatile bool pending;
    uint16_t block;
    uint16_t len;
    uint8_t  buf[CFG_TUD_DFU_XFER_BUFSIZE];
} s_dl;

static volatile bool s_manifest_pending;
static uint32_t s_received;          /* bytes streamed into staging   */

/* Blocks are addressed by a RUNNING byte offset, not block_num *
 * wTransferSize: DFU downloads are strictly sequential, and this
 * keeps a host using a smaller transfer size (dfu-util -t) correct.
 * Sub-sector blocks accumulate in RAM and flush per 4 KiB sector. */
static uint8_t  s_sector_buf[FLASH_SECTOR_SIZE];
static uint32_t s_sector_fill;       /* bytes buffered for this sector */

static bool flush_sector(void)
{
    if (s_sector_fill == 0)
        return true;
#if defined(PQF_DFU_ERASEONLY)
    /* DIAGNOSTIC (never ship): erase the sector but do not program it.
     * Splits "the erase wedges the device" from "the program does". */
    flash_rom_op(PQF_STAGE_SLOT_OFF + (s_received - s_sector_fill), NULL, 0);
    s_sector_fill = 0;
    return true;
#endif
#if defined(PQF_DFU_NOFLASH)
    /* DIAGNOSTIC (never ship): accept and discard. Splits "the flash
     * path wedges the device" from "the DFU/USB state machine never
     * answers GETSTATUS" -- the download either streams to completion
     * or dies at block 0 exactly as before. */
    s_sector_fill = 0;
    return true;
#endif
    uint32_t base = s_received - s_sector_fill;   /* sector-aligned */
    trace(PQF_TR_FLUSH);
    flash_write_sector(PQF_STAGE_SLOT_OFF + base, s_sector_buf, s_sector_fill);
    /* Reading staging back through XIP. This is NOT covered by either
     * of the earlier bisect builds -- both return before they get here
     * -- so "the flash write is the fault" was never separated from
     * "the readback is the fault". Its own stage code settles it. */
    bool ok = true;
    if (!s_skip_readback) {
        trace(PQF_TR_READBACK);
        ok = memcmp(s_sector_buf, xip(PQF_STAGE_SLOT_OFF + base),
                    s_sector_fill) == 0;
    }
    s_sector_fill = 0;
    trace(PQF_TR_DL_OK);
    return ok;
}
static bool s_reboot_armed;
static absolute_time_t s_reboot_at;

static void arm_reboot(uint32_t delay_ms)
{
    s_reboot_armed = true;
    s_reboot_at = make_timeout_time_ms(delay_ms);
}

uint32_t tud_dfu_get_timeout_cb(uint8_t alt, uint8_t state)
{
    (void)alt;
    if (state == DFU_DNBUSY)
        return 60;   /* one sector erase+program per 4 KiB block */
    if (state == DFU_MANIFEST) {
        /* Verify (SHA over the image) + journal + sector-by-sector
         * install copy. ~50 ms per 4 KiB sector, plus crypto slack. */
        uint32_t sectors = (s_received + FLASH_SECTOR_SIZE - 1) / FLASH_SECTOR_SIZE;
        return sectors * 50 + 500;
    }
    return 0;
}

void tud_dfu_download_cb(uint8_t alt, uint16_t block_num,
                         uint8_t const *data, uint16_t length)
{
    (void)alt;
    if (length > sizeof(s_dl.buf)) {           /* can't happen: wTransferSize */
        tud_dfu_finish_flashing(DFU_STATUS_ERR_UNKNOWN);
        return;
    }
    memcpy(s_dl.buf, data, length);
    s_dl.block = block_num;
    s_dl.len = length;
    s_dl.pending = true;                        /* main loop takes over */
}

void tud_dfu_manifest_cb(uint8_t alt)
{
    (void)alt;
    s_manifest_pending = true;                  /* main loop takes over */
}

void tud_dfu_abort_cb(uint8_t alt)
{
    (void)alt;
    s_dl.pending = false;
    s_manifest_pending = false;
    s_received = 0;
    s_sector_fill = 0;
}

/* In DFU mode a DETACH means "leave the bootloader": reboot, which
 * boots the (possibly just-updated) application. */
void tud_dfu_detach_cb(void)
{
    arm_reboot(100);
}

static uint8_t dfu_status_for(pqf_img_result_t rc)
{
    switch (rc) {
    case PQF_IMG_OK:          return DFU_STATUS_OK;
    case PQF_IMG_WRONG_BOARD: return DFU_STATUS_ERR_TARGET;
    case PQF_IMG_BAD_HASH:
    case PQF_IMG_BAD_SIG:     return DFU_STATUS_ERR_VERIFY;
    default:                  return DFU_STATUS_ERR_FILE;
    }
}

/* One deferred download block: append it to the staging stream. */
static void handle_download(void)
{
    trace(PQF_TR_DL_BLOCK);
    s_dl.pending = false;

    if (s_dl.block == 0) {
        s_received = 0;
        s_sector_fill = 0;
        /* The first block usually carries the whole image header --
         * cheap format sanity now (magic/version/length), so a wrong
         * file fails in milliseconds instead of after a 700 KiB
         * stream. Crypto happens at manifest time. */
        if (s_dl.len >= sizeof(pqf_image_hdr_t)
            && pqf_image_check_format((const pqf_image_hdr_t *)s_dl.buf)
               != PQF_IMG_OK) {
            tud_dfu_finish_flashing(DFU_STATUS_ERR_FILE);
            return;
        }
    }
    if (s_received + s_dl.len > PQF_SLOT_SIZE) {
        tud_dfu_finish_flashing(DFU_STATUS_ERR_ADDRESS);
        return;
    }

    /* Accumulate into the RAM sector buffer, flushing each time a
     * full 4 KiB sector is ready. With dfu-util's default transfer
     * size (= wTransferSize = 4096) this is one flush per block. */
    uint32_t off = 0;
    while (off < s_dl.len) {
        uint32_t room = FLASH_SECTOR_SIZE - s_sector_fill;
        uint32_t n = s_dl.len - off;
        if (n > room) n = room;
        memcpy(s_sector_buf + s_sector_fill, s_dl.buf + off, n);
        s_sector_fill += n;
        s_received += n;
        off += n;
        if (s_sector_fill == FLASH_SECTOR_SIZE && !flush_sector()) {
            tud_dfu_finish_flashing(DFU_STATUS_ERR_PROG);
            return;
        }
    }
    tud_dfu_finish_flashing(DFU_STATUS_OK);
}

/* Deferred manifest: verify staging, then install it over the app
 * slot. Any failure leaves the app slot untouched and reports a DFU
 * error status (dfu-util prints e.g. `status(7) = errVERIFY` and
 * exits non-zero). */
static void handle_manifest(void)
{
    trace(PQF_TR_MANIFEST);
    s_manifest_pending = false;

    if (!flush_sector()) {          /* tail bytes of the stream */
        tud_dfu_finish_flashing(DFU_STATUS_ERR_PROG);
        return;
    }

    const pqf_image_hdr_t *hdr = (const pqf_image_hdr_t *)xip(PQF_STAGE_SLOT_OFF);
    pqf_img_result_t rc = verify_slot(PQF_STAGE_SLOT_OFF);
    if (rc == PQF_IMG_OK
        && s_received < PQF_IMAGE_HDR_SIZE + hdr->image_len)
        rc = PQF_IMG_BAD_FORMAT;    /* truncated stream */

#if PQF_BOOT_ANTI_ROLLBACK
    /* Refuse images older than the one installed. Opt-in: with the
     * bootrom BOOTSEL path disabled in production (secure boot), DFU is the
     * ONLY update path, so rollback blocking also blocks legitimate
     * downgrades -- enable deliberately. */
    if (rc == PQF_IMG_OK && verify_slot(PQF_APP_SLOT_OFF) == PQF_IMG_OK) {
        const pqf_image_hdr_t *cur =
            (const pqf_image_hdr_t *)xip(PQF_APP_SLOT_OFF);
        if (hdr->fw_version < cur->fw_version)
            rc = PQF_IMG_ROLLBACK;
    }
#endif

    if (rc != PQF_IMG_OK) {
        tud_dfu_finish_flashing(dfu_status_for(rc));
        return;
    }

    uint32_t total_len = PQF_IMAGE_HDR_SIZE + hdr->image_len;
    boot_state_set_pending(total_len);
    bool ok = install_copy(total_len);
    boot_state_clear();
    if (!ok) {
        tud_dfu_finish_flashing(DFU_STATUS_ERR_PROG);
        return;
    }
    tud_dfu_finish_flashing(DFU_STATUS_OK);
    /* Give the host time to read the final GETSTATUS, then reboot
     * into the freshly installed application. */
    arm_reboot(1500);
}

/* ---- DFU mode main loop ------------------------------------------- */

static void led_init(void)
{
#if defined(PICO_DEFAULT_LED_PIN)
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
#endif
}

static void led_task(void)
{
#if defined(PICO_DEFAULT_LED_PIN)
    /* Rapid 10 Hz blink: the unmistakable "bootloader, not app" cue
     * (the app idles solid, blinks only for user-presence). */
    static absolute_time_t next;
    static bool lit;
    if (!time_reached(next)) return;
    lit = !lit;
    gpio_put(PICO_DEFAULT_LED_PIN, lit);
    next = make_timeout_time_ms(50);
#endif
}

static void __attribute__((noreturn)) dfu_mode_run(void)
{
    led_init();
    tud_init(0);
    /* USB uses the proven Arm model: the USBCTRL IRQ (enabled by
     * tud_init) services the controller; we just pump tud_task() from
     * the loop. This mirrors the firmware's Arm path (fido_hid.c
     * pqf_usb_task) -- the interrupt-free/polled model is a RISC-V-only
     * workaround and must NOT be forced here (an Arm-only bootloader).
     * Flash erase/program can't race the ISR because flash_write_sector
     * masks all interrupts across the op (save_and_disable_interrupts). */

    /* Guard the WHOLE session, not just the flash op. A hang anywhere
     * in here -- the erase, the program, the XIP readback after it, or
     * the USB stack -- now resets the chip and comes back into DFU with
     * the last stage recorded, instead of stranding the token. The loop
     * feeds it every pass; the longest legitimate stall is one sector
     * erase, far inside this budget. */
    flash_wd_arm();

    while (true) {
        watchdog_update();
        trace(PQF_TR_LOOP);

        tud_task();
        led_task();

        if (s_dl.pending)
            handle_download();
        else if (s_manifest_pending)
            handle_manifest();

        if (s_reboot_armed && time_reached(s_reboot_at)) {
            /* Deliberate reboot: stand the guard down first so we chain
             * the app instead of landing back here with a stale trace. */
            flash_wd_disarm();
            watchdog_reboot(0, 0, 0);
            while (true) tight_loop_contents();
        }
    }
}

int main(void)
{
    /* Before anything else touches the scratch cells: recover the
     * breadcrumb from a watchdog-killed flash op, if there was one. It
     * ends up in the USB serial string (see usb_descriptors.c). */
    trace_capture_and_clear();
    /* Self-heal: if the last run hung in the readback, route around it
     * this time instead of wedging in the same place forever. */
    s_skip_readback = (pqf_dfu_trace_last == PQF_TR_READBACK);

#if defined(PQF_DFU_WDSELFTEST)
    /* DIAGNOSTIC (never ship). One press, two answers.
     *
     * Step A runs a REAL erase at exactly the offset the DFU download
     * uses (0x200000 -- the staging slot), fully instrumented and
     * watchdog-guarded, but with no USB stack running yet. If the
     * erase itself is what wedges the token, the watchdog resets us and
     * the serial string names the ROM call that hung.
     *
     * Step B only runs if step A returned. It hangs on purpose inside
     * an armed window, which proves the watchdog really does reset this
     * chip and that the breadcrumb survives the reset. Without step B a
     * silent device is ambiguous -- "nothing hung" and "my instrument is
     * broken" look identical, and hours have already been lost to
     * exactly that confusion.
     *
     * Reading the result: reboot into DFU and look at the serial.
     *   E127 -> step A passed, watchdog VALID. Erase at 0x200000 is fine.
     *   E02..E09 -> step A hung there. That is the bug, named.
     *   device dark -> the watchdog does not work; trust nothing above.
     * One-shot: a recovered trace suppresses the self-test next boot. */
    if (pqf_dfu_trace_last == 0) {
        flash_wd_arm();
        flash_rom_op(PQF_STAGE_SLOT_OFF, NULL, 0);   /* step A */

        s_trace_sector = 0xFFFFu;                     /* step B */
        trace(PQF_TR_SELFTEST);
        flash_wd_arm();
        while (true) tight_loop_contents();
    }
#endif

#if defined(PQF_BOOT_FORCE_DFU)
    /* DIAGNOSTIC (never ship): skip the boot decision entirely and go
     * straight to DFU mode. Isolates "does the bootloader boot + bring
     * up USB on this board?" from the flash-read / bootsel-sample /
     * rom_chain_image path. If the device enumerates as the DFU device
     * with this set but hangs without it, the fault is in that path. */
    dfu_mode_run();
#endif

    /* Interrupted install first -- before any boot decision, so a
     * power cut mid-update can't strand a half-copied app slot. */
    recover_pending_install();

    bool want_dfu = dfu_requested_via_scratch();
    if (!want_dfu)
        want_dfu = pqf_bootsel_pressed();

    if (!want_dfu)
        try_boot_app();   /* no return on success */

    /* App missing/unverified, app asked for DFU, or button held. */
    dfu_mode_run();
}
