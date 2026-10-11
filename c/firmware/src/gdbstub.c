/* gdbstub.c -- GDB remote-serial-protocol stub on the token
 * itself, served over USB. Debug a cased/locked production-style unit
 * with nothing but the cable: no SWD probe, no opened enclosure, no
 * hardware debug assist on the host side.
 *
 *     (host)  arm-none-eabi-gdb build/bruce_c.elf
 *             (gdb) target remote /dev/cu.usbmodemXXXXXXXX3
 *             (gdb) break ctap2_dispatch
 *             (gdb) continue
 *
 * ## Architecture: monitor-mode debug
 *
 * A hardware probe halts the core from outside (halting debug, via the
 * DAP). We have no probe, so the core must debug itself: ARMv8-M
 * "monitor mode" debug. With DEMCR.MON_EN set, debug events --
 * breakpoints (FPB match or a BKPT instruction) and single-step
 * completion -- raise the DebugMonitor exception instead of halting.
 * Our DebugMonitor handler IS the debugger: it captures the interrupted
 * context, then sits in a packet loop servicing GDB until told to
 * resume. "Halted" therefore means "spinning inside the DebugMonitor
 * exception"; the target shares its CPU with the stub, and anything
 * running at higher priority than the halt keeps running (that's what
 * keeps USB alive -- and also what makes this weaker than SWD; see
 * Constraints).
 *
 * Key pieces:
 *
 *   - DebugMonitor priority 0 (the highest configurable level). So
 *     breakpoints work almost anywhere, including inside default-
 *     priority (0x80) IRQ handlers. The cost: while halted no interrupt
 *     can preempt the monitor, so the monitor services the USB
 *     controller BY POLLING -- tud_int_handler(0) + tud_task(), exactly
 *     the interrupt-free pump the pure-RISC-V port runs full-time (see
 *     pqf_usb_task in fido_hid.c). The pended USBCTRL IRQ is level-
 *     based; whatever the poll already handled deasserts, the rest is
 *     taken on resume.
 *
 *   - Breakpoints via the FPB (Flash Patch & Breakpoint) comparators,
 *     not BKPT patching. GDB's Z0 "software breakpoint" normally
 *     rewrites the instruction, but our .text lives in XIP flash (or a
 *     copy_to_ram image) -- patching flash is a sector-erase operation,
 *     a non-starter. The v8-M FPB comparators match ANY instruction
 *     address (XIP included), so both Z0 and Z1 map onto them. 8
 *     comparators on the RP2350's M33s (probed at init). GDB handles
 *     the step-over-breakpoint dance itself (z0 / s / Z0 / c).
 *
 *   - Single-step via DEMCR.MON_STEP: returning from the monitor with
 *     it set executes one instruction and re-enters. For the step's
 *     duration BASEPRI is raised to 0x20 so a pending default-priority
 *     IRQ can't hijack the step (you'd land on the first instruction
 *     of an ISR -- technically correct, never what you meant); the
 *     monitor's own re-entry at priority 0 is unaffected. BASEPRI is
 *     restored on re-entry.
 *
 *   - Async halt (Ctrl-C, and the halt GDB expects on attach) via
 *     DEMCR.MON_PEND, set from pqf_gdb_poll(). Poll runs at controlled
 *     thread-level sites only (main loop, long-op tick, UP gate), so
 *     the monitor never lands mid-way through a TinyUSB queue
 *     operation it is about to re-enter. A hard wedge that pumps
 *     nothing can't be broken into -- set the breakpoint first, or use
 *     it as the reason this stub exists and reflash with one.
 *
 *   - While the monitor is in control the FPB is master-disabled
 *     (FP_CTRL.ENABLE=0), so the stub can never hit its own
 *     breakpoints while pumping USB through the very stack the user
 *     is debugging. Comparators are re-armed on resume.
 *
 * ## The halted-inside-tud_task question
 *
 * The FIDO dispatch runs INSIDE a TinyUSB callback (tud_hid_set_report
 * cb -> ctaphid_recv_frame -> ctap2_dispatch), so a breakpoint there
 * halts under tud_task() -- and the monitor then calls tud_task() again
 * to talk to GDB. That nesting is not novel: this firmware already
 * re-enters tud_task() from inside dispatches as a matter of course
 * (fido_hid_send_frame's ready-wait, the KEEPALIVE long-op tick, the
 * user-presence gate), and the CTAPHID layer defends its state with
 * the s_dispatching CHANNEL_BUSY guard. The one place the pattern
 * genuinely breaks is a breakpoint inside TinyUSB/dcd internals
 * themselves (the queue and endpoint bookkeeping the monitor's own
 * pump needs) -- don't put breakpoints there; the transport can't
 * debug itself.
 *
 * ## Constraints (v1 -- documented in docs/GDB_DEBUG.md)
 *
 *   - Core 0 only. Core 1 (the signing worker) keeps running free;
 *     its own vector table is untouched. Halt core 0 during a core-1
 *     sign and the sign completes into the mailbox, harmlessly.
 *   - No halt-the-world: timers keep ticking, USB stays enumerated,
 *     hosts may time out FIDO transactions you sit on. That's
 *     inherent to monitor mode, not fixable from software.
 *   - Breakpoints do NOT fire inside PRIMASK-masked regions (the
 *     flash-commit park window, bootsel.c's QSPI-CS sampling): a
 *     debug event there escalates to HardFault. Same for anything at
 *     priority 0.
 *   - Regions readable/writable via m/M are whitelisted (ROM, XIP
 *     flash, SRAM). Peripheral pokes through GDB are refused (E01) --
 *     a stray bus fault inside the monitor would wedge the device.
 *   - A BKPT compiled into code (pico-sdk panics) now vectors here
 *     instead of wedging dark: the token parks itself halted and
 *     waits for GDB to attach and look around. `continue` from such a
 *     bkpt re-traps in place (by design -- it's a panic).
 *   - MUST be excluded from production-signed images. The stub is an
 *     unauthenticated read/write/execute primitive over USB --
 *     PQF_GDB_STUB is a developer build flag, default OFF, and the
 *     descriptor set only grows the debug CDC interface when it's on.
 *     (A future authenticated-unlock story could gate it at runtime;
 *     v1 keeps the line simple: debug build vs production build.)
 *   - If a real SWD probe holds C_DEBUGEN, halting debug wins and the
 *     monitor never fires (architectural); init logs a warning over
 *     the banner CDC.
 *
 * ## RSP subset
 *
 *   ?  g G  p P  m M  c s  Z0/z0 Z1/z1  D k  H  qSupported qAttached
 *   qXfer:features:read (target.xml, armv8-m.main m-profile)  qRcmd
 *   ("monitor help/reset/bootsel").  Unrecognised packets get the
 *   empty reply, per spec, and GDB falls back gracefully.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(PQF_GDB_STUB)

#if defined(__riscv)
#error "PQF_GDB_STUB is Arm-only (ARMv8-M DebugMonitor); the Hazard3 \
cores use a different debug architecture -- see docs/GDB_DEBUG.md."
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* Platform seam. The firmware build talks to real ARMv8-M debug
 * registers and real TinyUSB; the host test build (PQF_GDB_HOST,
 * test/Makefile) swaps in simulated MMIO, a simulated SRAM, and a pty
 * for the transport, so the entire RSP layer below -- framing,
 * checksums, escaping, register marshalling, the FPB slot allocator,
 * the halted session loop -- is driven by a REAL arm-none-eabi-gdb on
 * the host with no hardware in the loop (test/test_gdbstub.c). Only
 * the DebugMonitor entry trampoline and the FPB/DEMCR side effects
 * genuinely need silicon. Same pattern as resident_store.c's
 * PQF_RESIDENT_HOST / the flash + rand stubs. */
#if defined(PQF_GDB_HOST)
#include "gdbstub_host.h"
#else

#include "pico/stdlib.h"
#include "hardware/sync.h"      /* __dsb / __isb barriers */
#include "tusb.h"

#include "board.h"
#include "usb_descriptors.h"

/* ---- ARMv8-M debug registers (architectural addresses) --------- *
 *
 * Spelled out raw rather than through SDK structs: these five are the
 * entire register surface the stub touches, the addresses are fixed by
 * the architecture, and pico-sdk 2.1.1 has no monitor-mode API to
 * lean on (hardware_exception stops at SysTick).                     */

#define GDB_REG32(a)        (*(volatile uint32_t *)(uintptr_t)(a))

/* Target memory access. A plain volatile dereference on the device;
 * the host build routes these into a simulated SRAM/flash image. */
#define GDB_MEM_RD8(a)      (*(volatile const uint8_t *)(uintptr_t)(a))
#define GDB_MEM_WR8(a, v)   (*(volatile uint8_t *)(uintptr_t)(a) = (v))

#endif /* PQF_GDB_HOST */

#include "gdbstub.h"

#define SCB_VTOR            GDB_REG32(0xE000ED08u)   /* vector table base   */
#define SCB_SHPR3           GDB_REG32(0xE000ED20u)   /* sys handler prio 12-15 */
#define SCB_DFSR            GDB_REG32(0xE000ED30u)   /* debug fault status (W1C) */
#define SCB_DHCSR           GDB_REG32(0xE000EDF0u)   /* halting-debug ctrl  */
#define SCB_DEMCR           GDB_REG32(0xE000EDFCu)   /* debug exc + monitor ctrl */

#define DEMCR_MON_EN        (1u << 16)
#define DEMCR_MON_PEND      (1u << 17)
#define DEMCR_MON_STEP      (1u << 18)

#define DFSR_HALTED         (1u << 0)    /* step completed        */
#define DFSR_BKPT           (1u << 1)    /* FPB match or BKPT instr */

#define DHCSR_C_DEBUGEN     (1u << 0)    /* halting debug (SWD) live */

/* Flash Patch & Breakpoint unit (v8-M revision: full-address
 * comparators -- bit 0 enables, bits [31:1] hold address[31:1]). */
#define FP_CTRL             GDB_REG32(0xE0002000u)
#define FP_COMP(n)          GDB_REG32(0xE0002008u + 4u * (n))
#define FP_CTRL_KEY         (1u << 1)
#define FP_CTRL_ENABLE      (1u << 0)

#define FPB_MAX_COMP        8u           /* M33 configuration ceiling */

/* BASEPRI value masking every default-priority IRQ during a single
 * step while leaving priority-0 (the DebugMonitor) deliverable. Works
 * for any implemented-priority-bits >= 3. */
#define GDB_STEP_BASEPRI    0x20u

/* The GDB channel is the second CDC instance (see usb_descriptors.c);
 * instance 0 stays the banner/BOOTSEL port. */
#define GDB_CDC             PQF_GDB_CDC_ITF

/* RSP packet ceiling advertised in qSupported (hex 800 = 2048). Sized
 * so a g-response, a 1 KiB memory read, or a fat M-write all fit. */
#define GDB_PKT_MAX         2048u

/* ---- Stub state ------------------------------------------------- */

static bool     s_enabled;          /* init succeeded, MON_EN live     */
static bool     s_attached;         /* a GDB has spoken this session   */
static volatile bool s_halted;      /* monitor loop in control         */
static bool     s_in_monitor;       /* re-entry paranoia guard         */
static bool     s_halt_req;         /* halt was host-requested (SIGINT) */
static bool     s_halt_pending;     /* halt asked for; taken after the drain */
static bool     s_step_req;         /* resume with MON_STEP            */
static bool     s_stepping;         /* a MON_STEP resume is in flight  */

/* The interrupted code's own BASEPRI, preserved across the halt. The
 * stub raises BASEPRI for a single-step window, so it must put back
 * what the application had rather than assuming 0 -- otherwise a
 * breakpoint inside a BASEPRI-guarded critical section would silently
 * unmask interrupts on resume, which is exactly the kind of heisenbug
 * a debugger must not introduce. (Nothing in THIS firmware uses
 * BASEPRI -- pico-sdk masks with PRIMASK -- but downstream builds may.) */
static uint32_t s_app_basepri;

/* Register cache while halted. Index = GDB register number from our
 * target.xml: 0-12 = r0-r12, 13 = sp, 14 = lr, 15 = pc, 16 = xpsr. */
#define REG_SP  13
#define REG_LR  14
#define REG_PC  15
#define REG_PSR 16
#define REG_N   17
static uint32_t  s_regs[REG_N];
static uint32_t *s_frame;           /* stacked exception frame         */
static uint32_t *s_saved_r4_r11;    /* callee-saved block (handler stack) */

/* FPB comparator bookkeeping. */
static uint32_t s_fpb_num;
static uint32_t s_bp_addr[FPB_MAX_COMP];
static bool     s_bp_used[FPB_MAX_COMP];

/* RSP receive parser. */
enum rx_state { RX_IDLE, RX_BODY, RX_CK1, RX_CK2 };
static enum rx_state s_rx_state;
static bool     s_rx_escape;
static bool     s_rx_overrun;
static char     s_rx_buf[GDB_PKT_MAX + 1];
static size_t   s_rx_len;
static uint8_t  s_rx_sum;
static uint8_t  s_rx_ck;

/* Last transmitted packet, kept verbatim for '-' retransmission. */
static char     s_tx_buf[GDB_PKT_MAX + 8];
static size_t   s_tx_len;

/* Last stop reply ("S05"/"S02"), replayed for a repeated '?'. */
static char     s_stop_reply[4] = "S05";

/* ---- Small helpers ---------------------------------------------- */

static const char s_hex[] = "0123456789abcdef";

static int hex_nib(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse hex until a non-hex char; returns chars consumed (0 = none). */
static size_t hex_u32(const char *s, uint32_t *out)
{
    uint32_t v = 0;
    size_t   n = 0;
    int      d;
    while ((d = hex_nib(s[n])) >= 0) {
        v = (v << 4) | (uint32_t)d;
        n++;
    }
    *out = v;
    return n;
}

/* Courtesy note on the banner CDC (instance 0) so someone watching
 * `screen` sees the halt/resume narrative. Best-effort: while halted
 * the monitor's own pump flushes it. */
static void gdb_note(const char *msg)
{
    if (!tud_cdc_n_connected(0)) return;
    tud_cdc_n_write_str(0, msg);
    tud_cdc_n_write_flush(0);
}

/* ---- USB pump --------------------------------------------------- *
 *
 * Halted (inside the DebugMonitor, priority 0): the USBCTRL IRQ can't
 * preempt us, so poll the controller handler by hand, then run the
 * deferred task. Identical concurrency shape to the pure-RISC-V
 * port's pqf_usb_task() -- TinyUSB's rp2040 dcd handler is explicitly
 * safe to call from thread/poll context, and the real IRQ can't run
 * concurrently while we hold priority 0.
 *
 * Running (pqf_gdb_poll from thread level): the IRQ is live and does
 * the controller half; only the deferred task belongs here -- calling
 * tud_int_handler() as well would race the real ISR. */
static void gdb_pump(void)
{
    if (s_in_monitor) {
        tud_int_handler(0);
    }
    tud_task();
}

/* ---- Raw transmit ----------------------------------------------- */

static void gdb_tx_raw(const char *data, size_t len)
{
    size_t off = 0;
    while (off < len) {
        uint32_t n = tud_cdc_n_write(GDB_CDC, data + off, (uint32_t)(len - off));
        off += n;
        tud_cdc_n_write_flush(GDB_CDC);
        if (n == 0) {
            /* FIFO full -- let the stack move bytes. If the host never
             * drains us the loop spins here; GDB always reads its
             * replies, so in practice this clears in microseconds. */
            gdb_pump();
        }
    }
    tud_cdc_n_write_flush(GDB_CDC);
}

/* Frame `body` as $body#ck, remember it for retransmission, send. */
static void gdb_tx_packet(const char *body)
{
    size_t  blen = strlen(body);
    uint8_t sum  = 0;

    if (blen + 4 > sizeof(s_tx_buf)) {
        blen = sizeof(s_tx_buf) - 4;    /* never happens: callers bound */
    }
    s_tx_buf[0] = '$';
    memcpy(&s_tx_buf[1], body, blen);
    for (size_t i = 0; i < blen; i++) {
        sum = (uint8_t)(sum + (uint8_t)body[i]);
    }
    s_tx_buf[1 + blen]     = '#';
    s_tx_buf[2 + blen]     = s_hex[sum >> 4];
    s_tx_buf[3 + blen]     = s_hex[sum & 0xF];
    s_tx_len               = blen + 4;
    gdb_tx_raw(s_tx_buf, s_tx_len);
}

static void gdb_tx_retransmit(void)
{
    if (s_tx_len > 0) {
        gdb_tx_raw(s_tx_buf, s_tx_len);
    }
}

/* ---- Memory access ----------------------------------------------- *
 *
 * Whitelist of regions the monitor may touch. Everything else is
 * answered E01 rather than risking a BusFault: a fault raised at
 * monitor priority escalates to HardFault and wedges the device,
 * which is precisely what a debug stub must never do to you.
 *
 *   ROM   0x0000_0000 + 32 KiB   read-only
 *   XIP   0x1000_0000 + flash    read-only (patching flash needs the
 *                                programmer, not a debugger poke)
 *   SRAM  0x2000_0000 + 520 KiB  read/write (covers copy_to_ram .text,
 *                                so GDB's software-bkpt fallback works
 *                                there if the FPB ever runs out)
 */
static bool mem_ok(uint32_t addr, uint32_t len, bool write)
{
    uint32_t end = addr + len;
    if (end < addr) return false;                     /* wrap */
    if (addr >= 0x20000000u && end <= 0x20082000u) return true;
    if (write) return false;
    if (end <= 0x00008000u) return true;
    if (addr >= 0x10000000u
        && end <= 0x10000000u + PICO_FLASH_SIZE_BYTES) return true;
    return false;
}

/* ---- FPB driver -------------------------------------------------- */

static void fpb_init(void)
{
    uint32_t ctrl = FP_CTRL;
    s_fpb_num = ((ctrl >> 4) & 0xFu) | (((ctrl >> 12) & 0x7u) << 4);
    if (s_fpb_num > FPB_MAX_COMP) s_fpb_num = FPB_MAX_COMP;
    for (uint32_t i = 0; i < s_fpb_num; i++) {
        FP_COMP(i) = 0;
        s_bp_used[i] = false;
    }
    FP_CTRL = FP_CTRL_KEY | FP_CTRL_ENABLE;
}

static void fpb_master(bool enable)
{
    FP_CTRL = FP_CTRL_KEY | (enable ? FP_CTRL_ENABLE : 0u);
    __dsb();
    __isb();
}

static bool fpb_set(uint32_t addr)
{
    addr &= ~1u;                        /* thumb bit off */
    int free_slot = -1;
    for (uint32_t i = 0; i < s_fpb_num; i++) {
        if (s_bp_used[i] && s_bp_addr[i] == addr) return true;  /* idempotent */
        if (!s_bp_used[i] && free_slot < 0) free_slot = (int)i;
    }
    if (free_slot < 0) return false;    /* comparators exhausted */
    s_bp_addr[free_slot] = addr;
    s_bp_used[free_slot] = true;
    FP_COMP((uint32_t)free_slot) = addr | 1u;   /* BE=1, address[31:1] */
    __dsb();
    __isb();
    return true;
}

static bool fpb_clear(uint32_t addr)
{
    addr &= ~1u;
    for (uint32_t i = 0; i < s_fpb_num; i++) {
        if (s_bp_used[i] && s_bp_addr[i] == addr) {
            s_bp_used[i] = false;
            FP_COMP(i) = 0;
            __dsb();
            __isb();
            return true;
        }
    }
    return true;    /* clearing a bp we don't hold is not an error */
}

static void fpb_clear_all(void)
{
    for (uint32_t i = 0; i < s_fpb_num; i++) {
        s_bp_used[i] = false;
        FP_COMP(i) = 0;
    }
    __dsb();
    __isb();
}

/* ---- Packet handlers --------------------------------------------- */

/* Embedded target description: GDB reads this and knows the register
 * file without any `set architecture` incantation on the user's side. */
static const char s_target_xml[] =
    "<?xml version=\"1.0\"?>"
    "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
    "<target version=\"1.0\">"
    "<architecture>armv8-m.main</architecture>"
    "<feature name=\"org.gnu.gdb.arm.m-profile\">"
    "<reg name=\"r0\" bitsize=\"32\"/>"
    "<reg name=\"r1\" bitsize=\"32\"/>"
    "<reg name=\"r2\" bitsize=\"32\"/>"
    "<reg name=\"r3\" bitsize=\"32\"/>"
    "<reg name=\"r4\" bitsize=\"32\"/>"
    "<reg name=\"r5\" bitsize=\"32\"/>"
    "<reg name=\"r6\" bitsize=\"32\"/>"
    "<reg name=\"r7\" bitsize=\"32\"/>"
    "<reg name=\"r8\" bitsize=\"32\"/>"
    "<reg name=\"r9\" bitsize=\"32\"/>"
    "<reg name=\"r10\" bitsize=\"32\"/>"
    "<reg name=\"r11\" bitsize=\"32\"/>"
    "<reg name=\"r12\" bitsize=\"32\"/>"
    "<reg name=\"sp\" bitsize=\"32\" type=\"data_ptr\"/>"
    "<reg name=\"lr\" bitsize=\"32\"/>"
    "<reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\"/>"
    "<reg name=\"xpsr\" bitsize=\"32\"/>"
    "</feature>"
    "</target>";

static void gdb_request_halt(void);

/* Reply scratch shared by the handlers below (hex payloads). */
static char s_reply[GDB_PKT_MAX + 1];

static void reply_regs_one(uint32_t v, char *out)
{
    /* Little-endian byte order, per RSP. */
    for (int b = 0; b < 4; b++) {
        out[b * 2]     = s_hex[(v >> (b * 8 + 4)) & 0xF];
        out[b * 2 + 1] = s_hex[(v >> (b * 8)) & 0xF];
    }
}

static bool parse_regs_one(const char *in, uint32_t *out)
{
    uint32_t v = 0;
    for (int b = 0; b < 4; b++) {
        int hi = hex_nib(in[b * 2]);
        int lo = hex_nib(in[b * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        v |= (uint32_t)((hi << 4) | lo) << (b * 8);
    }
    *out = v;
    return true;
}

/* Map an incoming GDB register number onto s_regs[], tolerating the
 * legacy ARM numbering where xPSR sits at 25. */
static int reg_index(uint32_t n)
{
    if (n < REG_N) return (int)n;
    if (n == 25)   return REG_PSR;
    return -1;
}

static void handle_read_regs(void)
{
    for (int i = 0; i < REG_N; i++) {
        reply_regs_one(s_regs[i], &s_reply[i * 8]);
    }
    s_reply[REG_N * 8] = '\0';
    gdb_tx_packet(s_reply);
}

static void handle_write_regs(const char *p)
{
    for (int i = 0; i < REG_N; i++) {
        uint32_t v;
        if (!parse_regs_one(p + i * 8, &v)) {
            gdb_tx_packet("E01");
            return;
        }
        /* SP is derived from the exception frame and can't be moved
         * without relocating the frame itself -- accept and ignore
         * (documented v1 limitation). */
        if (i != REG_SP) s_regs[i] = v;
    }
    gdb_tx_packet("OK");
}

static void handle_read_reg(const char *p)
{
    uint32_t n;
    if (!hex_u32(p, &n)) { gdb_tx_packet("E01"); return; }
    int i = reg_index(n);
    if (i < 0) { gdb_tx_packet("E01"); return; }
    reply_regs_one(s_regs[i], s_reply);
    s_reply[8] = '\0';
    gdb_tx_packet(s_reply);
}

static void handle_write_reg(const char *p)
{
    uint32_t n, v;
    size_t   used = hex_u32(p, &n);
    if (used == 0 || p[used] != '=') { gdb_tx_packet("E01"); return; }
    int i = reg_index(n);
    if (i < 0 || !parse_regs_one(p + used + 1, &v)) {
        gdb_tx_packet("E01");
        return;
    }
    if (i != REG_SP) s_regs[i] = v;
    gdb_tx_packet("OK");
}

static void handle_read_mem(const char *p)
{
    uint32_t addr, len;
    size_t   used = hex_u32(p, &addr);
    if (used == 0 || p[used] != ',') { gdb_tx_packet("E01"); return; }
    if (!hex_u32(p + used + 1, &len)) { gdb_tx_packet("E01"); return; }

    /* Partial replies are legal; GDB re-requests the tail. */
    uint32_t max = (uint32_t)(sizeof(s_reply) - 1) / 2;
    if (len > max) len = max;

    if (len == 0 || !mem_ok(addr, len, false)) {
        gdb_tx_packet("E01");
        return;
    }
    for (uint32_t i = 0; i < len; i++) {
        uint8_t b = GDB_MEM_RD8(addr + i);
        s_reply[i * 2]     = s_hex[b >> 4];
        s_reply[i * 2 + 1] = s_hex[b & 0xF];
    }
    s_reply[len * 2] = '\0';
    gdb_tx_packet(s_reply);
}

static void handle_write_mem(const char *p)
{
    uint32_t addr, len;
    size_t   used = hex_u32(p, &addr);
    if (used == 0 || p[used] != ',') { gdb_tx_packet("E01"); return; }
    size_t used2 = hex_u32(p + used + 1, &len);
    const char *data = p + used + 1 + used2;
    if (used2 == 0 || *data != ':') { gdb_tx_packet("E01"); return; }
    data++;

    if (!mem_ok(addr, len, true)) { gdb_tx_packet("E01"); return; }

    for (uint32_t i = 0; i < len; i++) {
        int hi = hex_nib(data[i * 2]);
        int lo = hex_nib(data[i * 2 + 1]);
        if (hi < 0 || lo < 0) { gdb_tx_packet("E01"); return; }
        GDB_MEM_WR8(addr + i, (uint8_t)((hi << 4) | lo));
    }
    /* Writes may have touched code (copy_to_ram .text) -- make sure
     * the pipeline sees them. */
    __dsb();
    __isb();
    gdb_tx_packet("OK");
}

static void handle_breakpoint(char op, const char *p)
{
    /* Z<type>,<addr>,<kind>[;cond...] -- types 0 (sw) and 1 (hw) both
     * land on the FPB; everything else is unsupported (empty reply). */
    char type = p[0];
    if ((type != '0' && type != '1') || p[1] != ',') {
        gdb_tx_packet("");
        return;
    }
    uint32_t addr;
    if (!hex_u32(p + 2, &addr)) { gdb_tx_packet("E01"); return; }

    bool ok = (op == 'Z') ? fpb_set(addr) : fpb_clear(addr);
    gdb_tx_packet(ok ? "OK" : "E0E");
}

static void handle_qxfer_features(const char *p)
{
    /* qXfer:features:read:<annex>:<off>,<len> */
    const char *colon = strchr(p, ':');
    if (!colon) { gdb_tx_packet("E01"); return; }
    if (strncmp(p, "target.xml", (size_t)(colon - p)) != 0) {
        gdb_tx_packet("E00");
        return;
    }
    uint32_t off, len;
    size_t used = hex_u32(colon + 1, &off);
    if (used == 0 || colon[1 + used] != ',') { gdb_tx_packet("E01"); return; }
    if (!hex_u32(colon + 1 + used + 1, &len)) { gdb_tx_packet("E01"); return; }

    uint32_t xml_len = (uint32_t)(sizeof(s_target_xml) - 1);
    if (len > sizeof(s_reply) - 2) len = sizeof(s_reply) - 2;

    if (off >= xml_len) {
        gdb_tx_packet("l");
        return;
    }
    uint32_t n    = xml_len - off;
    bool     last = (n <= len);
    if (n > len) n = len;
    s_reply[0] = last ? 'l' : 'm';
    memcpy(&s_reply[1], s_target_xml + off, n);
    s_reply[1 + n] = '\0';
    gdb_tx_packet(s_reply);
}

static void handle_qrcmd(const char *p)
{
    /* qRcmd,<hex command>. Reply is hex-encoded console text. */
    char cmd[32];
    size_t n = 0;
    while (p[0] && p[1] && n < sizeof(cmd) - 1) {
        int hi = hex_nib(p[0]);
        int lo = hex_nib(p[1]);
        if (hi < 0 || lo < 0) break;
        cmd[n++] = (char)((hi << 4) | lo);
        p += 2;
    }
    cmd[n] = '\0';

    const char *text;
    if (strcmp(cmd, "reset") == 0) {
        gdb_tx_packet("OK");
        gdb_note("[gdb] monitor reset -- warm reboot\r\n");
        pqf_board_reboot(PQF_REBOOT_WARM);          /* noreturn */
        return;
    } else if (strcmp(cmd, "bootsel") == 0) {
        gdb_tx_packet("OK");
        gdb_note("[gdb] monitor bootsel -- rebooting to bootloader\r\n");
        pqf_board_reboot(PQF_REBOOT_BOOTSEL);       /* noreturn */
        return;
    } else if (strcmp(cmd, "help") == 0) {
        text = "monitor reset   -- warm reboot\n"
               "monitor bootsel -- reboot into BOOTSEL (reflash)\n";
    } else {
        text = "unknown command; try: monitor help\n";
    }
    size_t i = 0;
    for (; text[i] && i * 2 < sizeof(s_reply) - 2; i++) {
        s_reply[i * 2]     = s_hex[((uint8_t)text[i]) >> 4];
        s_reply[i * 2 + 1] = s_hex[((uint8_t)text[i]) & 0xF];
    }
    s_reply[i * 2] = '\0';
    gdb_tx_packet(s_reply);
}

static void handle_query(char *pkt)
{
    if (strncmp(pkt, "qSupported", 10) == 0) {
        snprintf(s_reply, sizeof(s_reply),
                 "PacketSize=%x;qXfer:features:read+", (unsigned)GDB_PKT_MAX);
        gdb_tx_packet(s_reply);
    } else if (strncmp(pkt, "qXfer:features:read:", 20) == 0) {
        handle_qxfer_features(pkt + 20);
    } else if (strcmp(pkt, "qAttached") == 0) {
        /* "Attached to an existing process" -- so GDB's `quit` offers
         * detach semantics rather than kill. */
        gdb_tx_packet("1");
    } else if (strncmp(pkt, "qRcmd,", 6) == 0) {
        handle_qrcmd(pkt + 6);
    } else {
        gdb_tx_packet("");
    }
}

static void gdb_detach_cleanup(const char *why)
{
    fpb_clear_all();
    s_attached = false;
    s_step_req = false;
    s_halted   = false;         /* exits the monitor loop -> resume */
    gdb_note("[gdb] ");
    gdb_note(why);
    gdb_note(" -- resuming free run\r\n");
}

/* One complete, checksum-verified packet. Runs from the monitor loop
 * when halted, or from pqf_gdb_poll() when the target is running (the
 * only packets that matter then are the attach probes and '?'). */
static void handle_packet(char *pkt)
{
    s_attached = true;

    switch (pkt[0]) {
    case '?':
        if (s_halted) {
            gdb_tx_packet(s_stop_reply);
        } else {
            /* Fresh attach to a running target: GDB expects a stopped
             * process. Halt now -- the monitor sends the stop reply as
             * the answer to this '?'. */
            gdb_request_halt();
        }
        break;

    case 'g':
        if (!s_halted) { gdb_tx_packet("E01"); break; }
        handle_read_regs();
        break;
    case 'G':
        if (!s_halted) { gdb_tx_packet("E01"); break; }
        handle_write_regs(pkt + 1);
        break;
    case 'p':
        if (!s_halted) { gdb_tx_packet("E01"); break; }
        handle_read_reg(pkt + 1);
        break;
    case 'P':
        if (!s_halted) { gdb_tx_packet("E01"); break; }
        handle_write_reg(pkt + 1);
        break;

    case 'm':
        handle_read_mem(pkt + 1);
        break;
    case 'M':
        handle_write_mem(pkt + 1);
        break;

    case 'Z':
    case 'z':
        handle_breakpoint(pkt[0], pkt + 1);
        break;

    case 'c':
        /* Optional resume address. No reply -- the next stop does. */
        if (pkt[1]) {
            uint32_t addr;
            if (hex_u32(pkt + 1, &addr)) s_regs[REG_PC] = addr;
        }
        s_step_req = false;
        s_halted   = false;
        break;

    case 's':
        if (pkt[1]) {
            uint32_t addr;
            if (hex_u32(pkt + 1, &addr)) s_regs[REG_PC] = addr;
        }
        s_step_req = true;
        s_halted   = false;
        break;

    case 'D':
        gdb_tx_packet("OK");
        gdb_detach_cleanup("detached");
        break;
    case 'k':
        /* No reply is expected for 'k'. Treat it as detach -- a `quit`
         * from GDB must not take the token down with it. */
        gdb_detach_cleanup("killed (treated as detach)");
        break;

    case 'H':
        gdb_tx_packet("OK");        /* single thread: any Hc/Hg is fine */
        break;
    case 'T':
        gdb_tx_packet("OK");        /* thread 1 is always alive */
        break;

    case 'q':
        handle_query(pkt);
        break;

    case 'v':
        if (strncmp(pkt, "vKill", 5) == 0) {
            gdb_tx_packet("OK");
            gdb_detach_cleanup("vKill (treated as detach)");
        } else {
            gdb_tx_packet("");      /* vMustReplyEmpty & friends */
        }
        break;

    default:
        gdb_tx_packet("");          /* unsupported -> empty, per spec */
        break;
    }
}

/* ---- Receive parser ---------------------------------------------- */

static void gdb_rx_byte(uint8_t b)
{
    switch (s_rx_state) {
    case RX_IDLE:
        if (b == '$') {
            s_rx_state   = RX_BODY;
            s_rx_len     = 0;
            s_rx_sum     = 0;
            s_rx_escape  = false;
            s_rx_overrun = false;
        } else if (b == 0x03) {
            /* Interrupt request (Ctrl-C in GDB). */
            if (!s_halted) {
                s_halt_req = true;
                gdb_request_halt();
            }
        } else if (b == '-') {
            gdb_tx_retransmit();
        }
        /* '+' acks and line noise are dropped on the floor. */
        break;

    case RX_BODY:
        if (b == '#') {
            s_rx_state = RX_CK1;
            break;
        }
        s_rx_sum = (uint8_t)(s_rx_sum + b);
        if (b == '}') {
            s_rx_escape = true;
            break;
        }
        if (s_rx_escape) {
            b ^= 0x20;
            s_rx_escape = false;
        }
        if (s_rx_len < GDB_PKT_MAX) {
            s_rx_buf[s_rx_len++] = (char)b;
        } else {
            s_rx_overrun = true;
        }
        break;

    case RX_CK1: {
        int d = hex_nib((char)b);
        if (d < 0) { s_rx_state = RX_IDLE; break; }
        s_rx_ck    = (uint8_t)(d << 4);
        s_rx_state = RX_CK2;
        break;
    }

    case RX_CK2: {
        int d = hex_nib((char)b);
        s_rx_state = RX_IDLE;
        if (d < 0) break;
        s_rx_ck |= (uint8_t)d;
        if (s_rx_ck != s_rx_sum || s_rx_overrun) {
            gdb_tx_raw("-", 1);
            break;
        }
        gdb_tx_raw("+", 1);
        s_rx_buf[s_rx_len] = '\0';
        handle_packet(s_rx_buf);
        break;
    }
    }
}

static void gdb_rx_drain(void)
{
    uint8_t chunk[64];
    uint32_t n;
    while ((n = tud_cdc_n_read(GDB_CDC, chunk, sizeof(chunk))) > 0) {
        for (uint32_t i = 0; i < n; i++) {
            gdb_rx_byte(chunk[i]);
            if (s_in_monitor && !s_halted) {
                /* A resume packet mid-chunk: stop consuming -- anything
                 * the host sends after `c`/`s` belongs to the next
                 * stop, and the FIFO keeps it until then. */
                return;
            }
        }
    }
}

/* ---- Halt / monitor session --------------------------------------- */

/* Ask for a halt. DEFERRED, not immediate: taking the exception here
 * would run the whole halted session nested inside packet processing,
 * while gdb_rx_drain still held unprocessed bytes in its local read
 * buffer -- the monitor's own drain reads from the CDC FIFO, so it could
 * never see them, and a resume packet stranded in that buffer would
 * wedge the session. Setting a flag instead lets the caller finish
 * consuming its buffer and take the halt at a clean top-level point
 * (pqf_gdb_poll). */
static void gdb_request_halt(void)
{
    if (s_in_monitor) return;
    s_halt_pending = true;
}

/* Take a deferred halt. Priority 0 + thread level => the DebugMonitor
 * is entered inside this call; by the time it returns the whole halted
 * session has played out and the target is running again. */
static void gdb_take_pending_halt(void)
{
    if (!s_halt_pending || s_in_monitor) return;
    s_halt_pending = false;
    SCB_DEMCR |= DEMCR_MON_PEND;
    __dsb();
    __isb();
}

/* Build the register cache from the stacked frame + the callee-saved
 * block the assembly trampoline pushed. */
static void regs_from_frame(uint32_t excret)
{
    uint32_t *f = s_frame;

    s_regs[0]  = f[0];
    s_regs[1]  = f[1];
    s_regs[2]  = f[2];
    s_regs[3]  = f[3];
    for (int i = 0; i < 8; i++) {
        s_regs[4 + i] = s_saved_r4_r11[i];
    }
    s_regs[12]      = f[4];
    s_regs[REG_LR]  = f[5];
    s_regs[REG_PC]  = f[6] & ~1u;
    s_regs[REG_PSR] = f[7];

    /* Reconstruct the pre-exception SP: frame base + frame size
     * (+ the aligner word if the hardware inserted one -- stacked
     * xPSR bit 9). Standard frame 0x20 bytes; FP-extended (EXC_RETURN
     * FType==0) 0x68. */
    uint32_t fsize = (excret & 0x10u) ? 0x20u : 0x68u;
    if (f[7] & (1u << 9)) fsize += 4u;
    s_regs[REG_SP] = (uint32_t)(uintptr_t)f + fsize;
}

static void regs_to_frame(void)
{
    uint32_t *f = s_frame;

    f[0] = s_regs[0];
    f[1] = s_regs[1];
    f[2] = s_regs[2];
    f[3] = s_regs[3];
    for (int i = 0; i < 8; i++) {
        s_saved_r4_r11[i] = s_regs[4 + i];
    }
    f[4] = s_regs[12];
    f[5] = s_regs[REG_LR];
    f[6] = s_regs[REG_PC] & ~1u;
    /* Preserve the hardware's aligner bit; force Thumb state (bit 24)
     * -- the M33 has no Arm state and a cleared T is an instant
     * INVSTATE UsageFault on return. */
    f[7] = (f[7] & (1u << 9))
         | (s_regs[REG_PSR] & ~(1u << 9))
         | (1u << 24);
}

static inline void set_basepri(uint32_t v)
{
#if defined(PQF_GDB_HOST)
    (void)v;                    /* no interrupt model in the host test */
#else
    __asm volatile ("msr basepri, %0" :: "r" (v) : "memory");
#endif
}

static inline uint32_t get_basepri(void)
{
#if defined(PQF_GDB_HOST)
    return 0;
#else
    uint32_t v;
    __asm volatile ("mrs %0, basepri" : "=r" (v));
    return v;
#endif
}

/* The C half of the DebugMonitor handler. Runs at exception priority
 * 0 on the main stack. `msp` is the stack pointer AT ENTRY (before the
 * trampoline's pushes) -- i.e. the exception frame, when the exception
 * came from MSP-using code. Pointer-typed (not uint32_t) so the host
 * test build can hand it a real 64-bit frame pointer; on Arm the
 * trampoline already has both stack pointers in r0/r1, so the ABI is
 * identical either way. */
void pqf_gdb_monitor_entry(uint32_t *msp, uint32_t *psp, uint32_t excret,
                           uint32_t *saved_r4_r11);
void pqf_gdb_monitor_entry(uint32_t *msp, uint32_t *psp, uint32_t excret,
                           uint32_t *saved_r4_r11)
{
    /* A step just completed (or was abandoned): stop stepping before
     * anything else so we can't re-trigger. */
    SCB_DEMCR &= ~DEMCR_MON_STEP;

    uint32_t dfsr = SCB_DFSR;
    SCB_DFSR = dfsr;                    /* W1C: clear what we consumed */

    /* Distinguish "re-entered because WE armed MON_STEP" from a fresh
     * stop: on a step re-entry BASEPRI holds the stub's step mask, not
     * the application's value, so it must not be resampled. */
    bool was_stepping = s_stepping;

    if (!s_enabled || s_in_monitor) {
        /* Re-entry can't happen by construction (FPB master-disabled,
         * MON_STEP cleared above, MON_PEND guarded) -- but if it ever
         * does, resuming beats recursing. */
        if (was_stepping) {
            s_stepping = false;
            set_basepri(s_app_basepri);
        }
        return;
    }

    bool stray_step = was_stepping && !s_attached;
    s_stepping = false;
    if (stray_step && !(dfsr & DFSR_BKPT)) {
        set_basepri(s_app_basepri);  /* drop our step-window mask */
        return;     /* leftover MON_STEP after a detach: just run */
    }

    if (!was_stepping) {
        s_app_basepri = get_basepri();
    }
    /* Priority 0 already blocks every interrupt for the duration of the
     * session, so BASEPRI plays no part while halted; clear it so the
     * value we restore on resume is the only one that matters. */
    set_basepri(0);

    s_in_monitor = true;
    fpb_master(false);      /* the monitor must never trap itself */

    s_frame         = (excret & 0x4u) ? psp : msp;
    s_saved_r4_r11  = saved_r4_r11;
    regs_from_frame(excret);

    /* Classify the stop for GDB: breakpoints and finished steps are
     * SIGTRAP; a host-requested halt reports as SIGINT. */
    uint8_t sig = 5;
    if (!(dfsr & (DFSR_BKPT | DFSR_HALTED)) && s_halt_req) {
        sig = 2;
    }
    s_halt_req = false;
    s_stop_reply[0] = 'S';
    s_stop_reply[1] = '0';
    s_stop_reply[2] = (char)('0' + sig);
    s_stop_reply[3] = '\0';

    {
        char note[64];
        snprintf(note, sizeof(note),
                 "[gdb] halted (%s) pc=0x%08lx\r\n",
                 (dfsr & DFSR_BKPT) ? "breakpoint" :
                 (dfsr & DFSR_HALTED) ? "step" : "interrupt",
                 (unsigned long)s_regs[REG_PC]);
        gdb_note(note);
    }

    gdb_tx_packet(s_stop_reply);

    /* ---- The halted session: serve GDB until told to resume ---- */
    s_halted   = true;
    s_step_req = false;
    while (s_halted) {
        gdb_pump();
        gdb_rx_drain();
    }

    regs_to_frame();

    if (s_step_req) {
        /* One instruction, interrupts (below priority 0) masked for
         * the step window so it lands on the NEXT app instruction,
         * not the first instruction of whatever IRQ is pending. If the
         * interrupted code was already masking MORE than that, keep
         * its stricter value -- we may only add masking for the step,
         * never relax what the application asked for. */
        uint32_t mask = GDB_STEP_BASEPRI;
        if (s_app_basepri != 0 && s_app_basepri < mask) {
            mask = s_app_basepri;
        }
        s_stepping = true;
        set_basepri(mask);
        SCB_DEMCR |= DEMCR_MON_STEP;
    } else {
        set_basepri(s_app_basepri);     /* hand the app its mask back */
    }

    fpb_master(true);
    s_in_monitor = false;
    __dsb();
    __isb();
    /* Return through the trampoline: pops (possibly rewritten)
     * r4-r11, then the exception return unstacks the (possibly
     * rewritten) frame. */
}

#if !defined(PQF_GDB_HOST)
/* DebugMonitor vector target. Captures what the hardware didn't stack
 * (r4-r11, the live EXC_RETURN, both stack pointers) and hands off to
 * the C monitor. The `sub sp, #4` keeps the stack 8-byte aligned at
 * the call boundary (9 pushed words otherwise = AAPCS violation). */
static void __attribute__((naked)) gdb_debugmon_trampoline(void)
{
    __asm volatile (
        "mrs   r0, msp            \n"
        "mrs   r1, psp            \n"
        "mov   r2, lr             \n"
        "push  {r4-r11, lr}       \n"
        "sub   sp, #4             \n"
        "add   r3, sp, #4         \n"
        "bl    pqf_gdb_monitor_entry \n"
        "add   sp, #4             \n"
        "pop   {r4-r11, pc}       \n"
    );
}
#endif /* !PQF_GDB_HOST -- the trampoline is the one Arm-only piece */

/* ---- Public API --------------------------------------------------- */

void pqf_gdb_poll(void)
{
    if (!s_enabled || s_in_monitor) return;
    if (tud_cdc_n_available(GDB_CDC)) {
        gdb_rx_drain();
    }
    /* Only now, with the read buffer fully consumed, is it safe to
     * enter the monitor (see gdb_request_halt). */
    gdb_take_pending_halt();
}

void pqf_gdb_init(void)
{
    /* The DebugMonitor slot (exception 12) is `isr_invalid` in the
     * pico-sdk flash vector table and hardware_exception has no
     * monitor API, so install straight into the RAM vector table the
     * SDK runtime already switched VTOR to. If VTOR still points at
     * flash (PICO_NO_RAM_VECTOR_TABLE build), we can't hook -- say so
     * and stay disabled rather than fault. */
    uint32_t vtor = SCB_VTOR;
    if (vtor < 0x20000000u || vtor >= 0x20082000u) {
        /* Explicitly disabled, not merely "not enabled": every entry
         * point (pqf_gdb_poll, the monitor) gates on s_enabled, so the
         * failure path must leave the stub inert even if init is
         * reached twice. */
        s_enabled = false;
        gdb_note("[gdb] init FAILED: no RAM vector table\r\n");
        return;
    }
#if !defined(PQF_GDB_HOST)
    ((volatile uint32_t *)(uintptr_t)vtor)[12] =
        (uint32_t)(uintptr_t)&gdb_debugmon_trampoline;
#endif
    __dsb();
    __isb();

    /* DebugMonitor at priority 0 -- see the header essay for why. */
    SCB_SHPR3 &= ~0xFFu;

    SCB_DFSR = SCB_DFSR;            /* clear stale W1C status */
    fpb_init();
    SCB_DEMCR |= DEMCR_MON_EN;
    __dsb();
    __isb();

    s_enabled = true;

    if (SCB_DHCSR & DHCSR_C_DEBUGEN) {
        /* A wire debugger owns the core: halting debug beats monitor
         * debug architecturally, so the stub will never fire. */
        gdb_note("[gdb] WARNING: C_DEBUGEN set (SWD probe attached) -- "
                 "monitor stub suppressed until it detaches\r\n");
    }
}

#endif /* PQF_GDB_STUB */
