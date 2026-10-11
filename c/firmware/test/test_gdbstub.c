/* test_gdbstub.c -- host test harness for the on-token GDB stub.
 *
 * Compiles src/gdbstub.c ON THE HOST (via test/gdbstub_host.h's
 * platform seam) and drives its remote-serial-protocol layer without
 * an RP2350 in the loop. Two modes:
 *
 *   ./build/test_gdbstub          -- the assertion suite below: packet
 *                                   framing, checksums, escaping, the
 *                                   m/M whitelist, register marshalling
 *                                   out of and back into a synthesized
 *                                   exception frame, the FPB slot
 *                                   allocator, qXfer chunking, detach.
 *
 *   ./build/test_gdbstub --pty    -- serve the stub on a pty and print
 *                                   its path, so a REAL gdb can attach:
 *                                       target remote /dev/ttys00N
 *                                   Drives the same code the firmware
 *                                   runs; see `make gdbstub-live`.
 *
 * What this CANNOT cover (needs silicon -- docs/GDB_DEBUG.md):
 * whether the DebugMonitor exception actually fires, whether the FPB
 * comparators actually match, and whether MON_STEP actually retires
 * exactly one instruction. Everything above those three hardware
 * behaviours is exercised here. To keep the emulation honest, the
 * fake target below models them the way the architecture specifies
 * (comparator match on an armed address, one re-entry per MON_STEP)
 * rather than the way the stub happens to be written.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _DARWIN_C_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <util.h>           /* openpty */
#else
#include <pty.h>
#endif

#include "gdbstub_host.h"

/* Public surface of the stub under test. */
void pqf_gdb_init(void);
void pqf_gdb_poll(void);
void pqf_gdb_monitor_entry(uint32_t *msp, uint32_t *psp, uint32_t excret,
                           uint32_t *saved_r4_r11);

/* ---- Simulated debug MMIO --------------------------------------- */

#define SCB_VTOR_ADDR   0xE000ED08u
#define SCB_SHPR3_ADDR  0xE000ED20u
#define SCB_DFSR_ADDR   0xE000ED30u
#define SCB_DHCSR_ADDR  0xE000EDF0u
#define SCB_DEMCR_ADDR  0xE000EDFCu
#define FP_CTRL_ADDR    0xE0002000u
#define FP_COMP0_ADDR   0xE0002008u

#define DEMCR_MON_EN    (1u << 16)
#define DEMCR_MON_PEND  (1u << 17)
#define DEMCR_MON_STEP  (1u << 18)
#define DFSR_HALTED     (1u << 0)
#define DFSR_BKPT       (1u << 1)

#define NUM_COMP        8u

static struct {
    uint32_t vtor, shpr3, dfsr, dhcsr, demcr, fp_ctrl;
    uint32_t fp_comp[NUM_COMP];
    uint32_t scratch;
} g_mmio;

uint32_t *pqf_gdb_host_reg(uintptr_t addr)
{
    switch ((uint32_t)addr) {
    case SCB_VTOR_ADDR:  return &g_mmio.vtor;
    case SCB_SHPR3_ADDR: return &g_mmio.shpr3;
    case SCB_DFSR_ADDR:  return &g_mmio.dfsr;
    case SCB_DHCSR_ADDR: return &g_mmio.dhcsr;
    case SCB_DEMCR_ADDR: return &g_mmio.demcr;
    case FP_CTRL_ADDR:   return &g_mmio.fp_ctrl;
    default: break;
    }
    if (addr >= FP_COMP0_ADDR && addr < FP_COMP0_ADDR + 4u * NUM_COMP) {
        return &g_mmio.fp_comp[(addr - FP_COMP0_ADDR) / 4u];
    }
    return &g_mmio.scratch;
}

/* ---- Simulated target memory ------------------------------------ */

static uint8_t  *g_sram;
static unsigned  g_mem_faults;

void *pqf_gdb_host_mem_ptr(uint32_t addr)
{
    assert(addr >= PQF_GDB_HOST_SRAM_BASE
           && addr < PQF_GDB_HOST_SRAM_BASE + PQF_GDB_HOST_SRAM_SIZE);
    return g_sram + (addr - PQF_GDB_HOST_SRAM_BASE);
}

static bool sram_hit(uint32_t addr)
{
    return addr >= PQF_GDB_HOST_SRAM_BASE
        && addr < PQF_GDB_HOST_SRAM_BASE + PQF_GDB_HOST_SRAM_SIZE;
}

uint8_t pqf_gdb_host_mem_rd8(uint32_t addr)
{
    if (!sram_hit(addr)) { g_mem_faults++; return 0xFF; }
    return g_sram[addr - PQF_GDB_HOST_SRAM_BASE];
}

void pqf_gdb_host_mem_wr8(uint32_t addr, uint8_t v)
{
    if (!sram_hit(addr)) { g_mem_faults++; return; }
    g_sram[addr - PQF_GDB_HOST_SRAM_BASE] = v;
}

unsigned pqf_gdb_host_mem_faults(void) { return g_mem_faults; }

/* ---- Simulated CDC transport ------------------------------------ *
 *
 * Two backends. The suite uses in-memory queues (deterministic, no
 * syscalls); --pty mode swaps in a pty master so a real gdb drives the
 * same stub code. Instance 0 (the banner port) is a bit bucket that
 * reports disconnected, matching a board nobody has `screen`ed.       */

#define QCAP    65536

static struct {
    uint8_t buf[QCAP];
    size_t  head, tail;
} g_rx, g_tx;

static int g_pty_fd = -1;       /* >= 0 in --pty mode */

static void q_push(void *qv, const uint8_t *b, size_t n)
{
    struct { uint8_t buf[QCAP]; size_t head, tail; } *q = qv;
    for (size_t i = 0; i < n; i++) {
        assert(q->tail < QCAP && "test queue overflow");
        q->buf[q->tail++] = b[i];
    }
}

static size_t q_pop(void *qv, uint8_t *out, size_t max)
{
    struct { uint8_t buf[QCAP]; size_t head, tail; } *q = qv;
    size_t n = 0;
    while (q->head < q->tail && n < max) out[n++] = q->buf[q->head++];
    return n;
}

static size_t q_len(void *qv)
{
    struct { uint8_t buf[QCAP]; size_t head, tail; } *q = qv;
    return q->tail - q->head;
}

uint32_t pqf_gdb_host_cdc_read(uint8_t itf, void *buf, uint32_t len)
{
    if (itf != PQF_GDB_CDC_ITF) return 0;
    if (g_pty_fd >= 0) {
        ssize_t n = read(g_pty_fd, buf, len);
        return (n > 0) ? (uint32_t)n : 0;
    }
    return (uint32_t)q_pop(&g_rx, buf, len);
}

uint32_t pqf_gdb_host_cdc_write(uint8_t itf, const void *buf, uint32_t len)
{
    if (itf != PQF_GDB_CDC_ITF) return len;     /* banner port: discard */
    if (g_pty_fd >= 0) {
        ssize_t n = write(g_pty_fd, buf, len);
        return (n > 0) ? (uint32_t)n : 0;
    }
    q_push(&g_tx, buf, len);
    return len;
}

uint32_t pqf_gdb_host_cdc_available(uint8_t itf)
{
    if (itf != PQF_GDB_CDC_ITF) return 0;
    if (g_pty_fd >= 0) {
        /* Non-blocking pty: "available" is answered by trying. The stub
         * only uses this as a cheap early-out, so a conservative 1 is
         * correct -- the following read() returns 0 if nothing is there. */
        return 1;
    }
    return (uint32_t)q_len(&g_rx);
}

bool pqf_gdb_host_cdc_connected(uint8_t itf)
{
    return itf == PQF_GDB_CDC_ITF;
}

void pqf_gdb_host_usb_task(void) { /* no deferred work on the host */ }

static enum pqf_reboot_mode g_reboot_mode;
static unsigned             g_reboot_count;

void pqf_board_reboot(enum pqf_reboot_mode mode)
{
    g_reboot_mode = mode;
    g_reboot_count++;
}

/* ---- Test plumbing ---------------------------------------------- */

static unsigned g_checks, g_fails;

static void check(bool ok, const char *fmt, ...)
{
    va_list ap;
    g_checks++;
    if (!ok) {
        g_fails++;
        fputs("  FAIL: ", stdout);
    } else {
        fputs("  ok:   ", stdout);
    }
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

/* Queue a well-formed $body#ck for the stub to read. */
static void send_pkt(const char *body)
{
    char    frame[4096];
    uint8_t sum = 0;
    for (const char *p = body; *p; p++) sum = (uint8_t)(sum + (uint8_t)*p);
    int n = snprintf(frame, sizeof(frame), "$%s#%02x", body, sum);
    q_push(&g_rx, (const uint8_t *)frame, (size_t)n);
}

static void send_raw(const char *s)
{
    q_push(&g_rx, (const uint8_t *)s, strlen(s));
}

/* Drain everything the stub has written since the last call. */
static const char *taken(void)
{
    static char out[65536];
    size_t n = q_pop(&g_tx, (uint8_t *)out, sizeof(out) - 1);
    out[n] = '\0';
    return out;
}

/* Body of the FIRST $...# packet in `s`, ignoring +/- acks. */
static const char *first_body(const char *s)
{
    static char body[65536];
    const char *d = strchr(s, '$');
    if (!d) return "";
    const char *h = strchr(d, '#');
    if (!h) return "";
    size_t n = (size_t)(h - d - 1);
    if (n >= sizeof(body)) n = sizeof(body) - 1;
    memcpy(body, d + 1, n);
    body[n] = '\0';
    return body;
}

/* ---- Synthesized exception frame -------------------------------- *
 *
 * A standard (non-FP) ARMv8-M frame, laid out in simulated SRAM at a
 * realistic device address, plus the r4-r11 block the trampoline
 * pushes. EXC_RETURN bit 4 set = standard frame; bit 2 clear = the
 * exception came from MSP-using code.                                */

#define FRAME_ADDR      0x20040000u
#define EXCRET_MSP_STD  0xFFFFFFF9u     /* bit4=1 (no FP), bit2=0 (MSP) */

static uint32_t *g_frame;
static uint32_t  g_r4_r11[8];

static void frame_reset(uint32_t pc)
{
    g_frame = pqf_gdb_host_mem_ptr(FRAME_ADDR);
    g_frame[0] = 0x11111111;    /* r0  */
    g_frame[1] = 0x22222222;    /* r1  */
    g_frame[2] = 0x33333333;    /* r2  */
    g_frame[3] = 0x44444444;    /* r3  */
    g_frame[4] = 0xCCCCCCCC;    /* r12 */
    g_frame[5] = 0x10000501;    /* lr  */
    g_frame[6] = pc;            /* pc  */
    g_frame[7] = 0x01000000;    /* xpsr: Thumb bit, no aligner */
    for (int i = 0; i < 8; i++) g_r4_r11[i] = 0xA0000000u + (uint32_t)i;
}

/* Enter the monitor as the hardware would. */
static void enter_monitor(uint32_t dfsr_bits)
{
    g_mmio.dfsr = dfsr_bits;
    pqf_gdb_monitor_entry(g_frame, NULL, EXCRET_MSP_STD, g_r4_r11);
}

/* ---- The suite -------------------------------------------------- */

static void t_init(void)
{
    puts("-- init: monitor mode armed, FPB reset");

    g_mmio.vtor = PQF_GDB_HOST_SRAM_BASE;   /* RAM vector table present */
    g_mmio.shpr3 = 0xFFFFFFFFu;
    /* FP_CTRL NUM_CODE: bits[7:4] low nibble, bits[14:12] high bits. */
    g_mmio.fp_ctrl = (NUM_COMP & 0xFu) << 4;
    for (unsigned i = 0; i < NUM_COMP; i++) g_mmio.fp_comp[i] = 0xDEADBEEF;

    pqf_gdb_init();

    check((g_mmio.demcr & DEMCR_MON_EN) != 0,
          "DEMCR.MON_EN set (monitor-mode debug enabled)");
    check((g_mmio.shpr3 & 0xFFu) == 0,
          "SHPR3 DebugMonitor priority forced to 0 (highest configurable)");
    check((g_mmio.fp_ctrl & 0x3u) == 0x3u,
          "FP_CTRL KEY|ENABLE written (FPB live)");
    bool cleared = true;
    for (unsigned i = 0; i < NUM_COMP; i++) {
        if (g_mmio.fp_comp[i] != 0) cleared = false;
    }
    check(cleared, "all %u FPB comparators cleared at init", NUM_COMP);
}

static void t_init_no_ram_vectors(void)
{
    puts("-- init: refuses to hook a flash vector table");

    /* Fresh state: a VTOR still in XIP means the RAM vector table the
     * stub needs to patch isn't there, and it must decline rather than
     * write into flash. */
    memset(&g_mmio, 0, sizeof(g_mmio));
    g_mmio.vtor = 0x10000000u;
    pqf_gdb_init();
    check((g_mmio.demcr & DEMCR_MON_EN) == 0,
          "MON_EN NOT set when VTOR points at flash");

    send_pkt("qSupported");
    pqf_gdb_poll();
    check(strlen(taken()) == 0, "stub stays mute while disabled");

    /* Restore a working stub for the remaining tests. */
    memset(&g_mmio, 0, sizeof(g_mmio));
    g_mmio.vtor = PQF_GDB_HOST_SRAM_BASE;
    g_mmio.fp_ctrl = (NUM_COMP & 0xFu) << 4;
    pqf_gdb_init();
    (void)taken();
}

static void t_framing(void)
{
    puts("-- framing: ack, nak, retransmit");

    send_pkt("qSupported");
    pqf_gdb_poll();
    const char *out = taken();
    check(out[0] == '+', "good checksum acked with '+'");
    check(strstr(out, "PacketSize=800") != NULL,
          "qSupported advertises PacketSize=800 (2048 bytes)");
    check(strstr(out, "qXfer:features:read+") != NULL,
          "qSupported advertises qXfer:features:read+");

    /* Deliberately wrong checksum. */
    send_raw("$qSupported#00");
    pqf_gdb_poll();
    out = taken();
    check(out[0] == '-' && strchr(out, '$') == NULL,
          "bad checksum naked with '-' and no reply body");

    /* '-' from the host must replay the last packet verbatim. */
    send_pkt("qAttached");
    pqf_gdb_poll();
    const char *first = first_body(taken());
    check(strcmp(first, "1") == 0, "qAttached replies 1 (attach, not kill)");
    send_raw("-");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "1") == 0,
          "'-' retransmits the previous packet verbatim");

    /* Unknown packets get the empty reply, per spec. */
    send_pkt("vMustReplyEmpty");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "") == 0,
          "unknown packet answered with the empty reply");
}

static void t_memory(void)
{
    puts("-- memory: m/M and the region whitelist");

    unsigned faults0 = pqf_gdb_host_mem_faults();

    uint8_t *p = pqf_gdb_host_mem_ptr(0x20001000u);
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(0xF0 + i);

    send_pkt("m20001000,8");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "f0f1f2f3f4f5f6f7") == 0,
          "m reads SRAM little-endian-byte-order hex");

    send_pkt("M20001000,4:aabbccdd");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "OK") == 0, "M write acked OK");
    check(p[0] == 0xAA && p[1] == 0xBB && p[2] == 0xCC && p[3] == 0xDD,
          "M write landed in target memory");

    /* Peripheral space: refused, and crucially NOT dereferenced -- a
     * bus fault inside the monitor would escalate to HardFault. */
    send_pkt("m40034000,4");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "E01") == 0,
          "m of peripheral space refused (E01)");

    send_pkt("M10000000,4:00000000");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "E01") == 0,
          "M into XIP flash refused (E01) -- flash needs the programmer");

    /* Wrap-around length must not be mistaken for a small read. */
    send_pkt("mfffffff0,20");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "E01") == 0,
          "m with an address+length wrap refused");

    check(pqf_gdb_host_mem_faults() == faults0,
          "no out-of-window access ever reached the memory backend");

    /* An oversized read is clamped, not truncated to nothing: GDB
     * re-requests the tail. */
    send_pkt("m20001000,fff");
    pqf_gdb_poll();
    size_t got = strlen(first_body(taken()));
    check(got > 0 && got % 2 == 0 && got <= 2048,
          "oversized m clamped to a valid partial reply (%zu hex chars)", got);
}

static void t_breakpoints(void)
{
    puts("-- breakpoints: Z0/z0 onto FPB comparators");

    send_pkt("Z0,20004000,2");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "OK") == 0, "Z0 accepted");
    check(g_mmio.fp_comp[0] == (0x20004000u | 1u),
          "comparator 0 armed with address|BE (got 0x%08x)", g_mmio.fp_comp[0]);

    /* GDB re-sends the same breakpoint on re-run; must not eat a slot. */
    send_pkt("Z0,20004000,2");
    pqf_gdb_poll();
    (void)taken();
    check(g_mmio.fp_comp[1] == 0,
          "re-arming the same address is idempotent (slot 1 still free)");

    /* Hardware breakpoints (Z1) share the same comparators. */
    send_pkt("Z1,20004100,2");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "OK") == 0, "Z1 (hw) accepted too");
    check(g_mmio.fp_comp[1] == (0x20004100u | 1u), "Z1 armed comparator 1");

    /* Thumb low bit must be masked off before programming. */
    send_pkt("Z0,20004201,2");
    pqf_gdb_poll();
    (void)taken();
    check(g_mmio.fp_comp[2] == (0x20004200u | 1u),
          "odd (thumb-flagged) address masked to even before arming");

    send_pkt("z0,20004000,2");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "OK") == 0, "z0 accepted");
    check(g_mmio.fp_comp[0] == 0, "comparator 0 disarmed");

    /* Exhaust the comparators; the (NUM_COMP+1)th must be refused so
     * GDB reports "cannot insert breakpoint" instead of silently
     * losing one. */
    for (unsigned i = 0; i < NUM_COMP; i++) {
        char pkt[32];
        snprintf(pkt, sizeof(pkt), "Z0,2000%04x,2", 0x5000 + i * 4);
        send_pkt(pkt);
        pqf_gdb_poll();
        (void)taken();
    }
    send_pkt("Z0,20006000,2");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "E0E") == 0,
          "breakpoint %u refused with E0E once comparators are exhausted",
          NUM_COMP + 1);

    /* Unsupported types (watchpoints) -> empty reply, so GDB falls back
     * rather than believing it set one. */
    send_pkt("Z2,20007000,4");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "") == 0,
          "Z2 (write watchpoint) unsupported -> empty reply");

    /* Clean slate for later tests. */
    for (unsigned i = 0; i < NUM_COMP; i++) {
        char pkt[32];
        snprintf(pkt, sizeof(pkt), "z0,2000%04x,2", 0x5000 + i * 4);
        send_pkt(pkt);
        pqf_gdb_poll();
        (void)taken();
    }
    send_pkt("z0,20004200,2"); pqf_gdb_poll(); (void)taken();
    send_pkt("z1,20004100,2"); pqf_gdb_poll(); (void)taken();
}

static void t_running_target_guards(void)
{
    puts("-- running target: register access refused, '?' pends a halt");

    send_pkt("g");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "E01") == 0,
          "g while the target runs -> E01 (no frame to read)");

    g_mmio.demcr &= ~DEMCR_MON_PEND;
    send_pkt("?");
    pqf_gdb_poll();
    check((g_mmio.demcr & DEMCR_MON_PEND) != 0,
          "'?' on a running target sets DEMCR.MON_PEND (async halt)");

    g_mmio.demcr &= ~DEMCR_MON_PEND;
    send_raw("\x03");                   /* Ctrl-C */
    pqf_gdb_poll();
    check((g_mmio.demcr & DEMCR_MON_PEND) != 0,
          "Ctrl-C (0x03) sets DEMCR.MON_PEND");

    /* The halt must be DEFERRED to the end of the drain, not taken
     * inline while bytes are still buffered. Taking it inline would run
     * the halted session with unprocessed bytes stranded in the read
     * buffer, where the monitor's own drain (which reads the CDC FIFO)
     * could never see them -- a resume packet landing there would wedge
     * the session. Proof of the invariant: a burst holding '?' AND a
     * following packet gets fully consumed, and the later packet is
     * still answered. */
    g_mmio.demcr &= ~DEMCR_MON_PEND;
    send_pkt("?");
    send_pkt("qAttached");              /* same burst, after the halt req */
    pqf_gdb_poll();
    const char *out = taken();
    check(strstr(out, "$1#") != NULL,
          "a packet queued behind '?' in the same burst is still processed");
    check(q_len(&g_rx) == 0, "the whole read burst was consumed");
    check((g_mmio.demcr & DEMCR_MON_PEND) != 0,
          "...and the halt was still taken, after the drain");
}

static void t_halted_registers(void)
{
    puts("-- halted: g/G/p/P against a synthesized exception frame");

    frame_reset(0x20005678u);

    /* Pre-queue the whole halted conversation, ending in 'c' so the
     * monitor's session loop terminates. */
    send_pkt("g");
    send_pkt("pf");                     /* register 0xf = r15 = pc */
    send_pkt("P0=efbeadde");            /* r0 = 0xdeadbeef (LE hex) */
    send_pkt("c");
    enter_monitor(DFSR_BKPT);

    const char *out = taken();
    check(strstr(out, "S05") != NULL,
          "breakpoint stop reported as S05 (SIGTRAP) on entry");

    /* Walk the replies: stop reply, then g, p, P, in order. */
    const char *d = strchr(out, '$');           /* S05 */
    d = strchr(d + 1, '$');                     /* g   */
    char gbody[256];
    const char *h = strchr(d, '#');
    size_t n = (size_t)(h - d - 1);
    memcpy(gbody, d + 1, n); gbody[n] = '\0';

    check(n == 17 * 8, "g returned 17 registers (%zu hex chars)", n);
    check(strncmp(gbody, "11111111", 8) == 0,
          "r0 read back from the frame");
    check(strncmp(gbody + 4 * 8, "000000a0", 8) == 0,
          "r4 read back from the trampoline's callee-saved block");
    check(strncmp(gbody + 15 * 8, "78560020", 8) == 0,
          "pc read back from the frame (little-endian 0x20005678)");
    uint32_t exp_sp = (uint32_t)(uintptr_t)g_frame + 0x20u;
    char spx[9];
    snprintf(spx, sizeof(spx), "%02x%02x%02x%02x",
             exp_sp & 0xFF, (exp_sp >> 8) & 0xFF,
             (exp_sp >> 16) & 0xFF, (exp_sp >> 24) & 0xFF);
    check(strncmp(gbody + 13 * 8, spx, 8) == 0,
          "sp reconstructed as frame base + 0x20 (standard frame)");

    d = strchr(d + 1, '$');                     /* p f */
    check(strncmp(d + 1, "78560020", 8) == 0, "p 15 returns the pc");

    check(g_frame[0] == 0xDEADBEEFu,
          "P0=... wrote r0 back into the exception frame on resume");
    check((g_mmio.demcr & DEMCR_MON_STEP) == 0,
          "'c' resumes without MON_STEP");
}

static void t_halted_step_and_psr(void)
{
    puts("-- halted: 's' arms MON_STEP; xPSR keeps Thumb + aligner bits");

    frame_reset(0x20005678u);
    g_frame[7] = 0x01000200u;           /* xpsr with the aligner bit set */

    /* Try to clear the Thumb bit through G -- the stub must refuse to
     * return to a non-Thumb state (instant INVSTATE UsageFault). */
    char g[17 * 8 + 2];
    memset(g, '0', sizeof(g));
    g[sizeof(g) - 1] = '\0';
    g[0] = 'G';
    char pkt[17 * 8 + 4];
    snprintf(pkt, sizeof(pkt), "G%0*d", 17 * 8, 0);
    send_pkt(pkt);
    send_pkt("s");
    enter_monitor(DFSR_HALTED);

    check((g_mmio.demcr & DEMCR_MON_STEP) != 0,
          "'s' resumes with DEMCR.MON_STEP armed");
    check((g_frame[7] & (1u << 24)) != 0,
          "xPSR Thumb bit forced on despite a zeroed G write");
    check((g_frame[7] & (1u << 9)) != 0,
          "xPSR frame-aligner bit preserved from the hardware");
    check((g_frame[6] & 1u) == 0, "stacked pc kept even (no thumb bit)");
}

static void t_stop_reasons(void)
{
    puts("-- halted: stop reason distinguishes trap from interrupt");

    /* Host-requested halt (Ctrl-C) -> SIGINT. */
    frame_reset(0x20009000u);
    send_raw("\x03");
    pqf_gdb_poll();                     /* sets MON_PEND, no reply yet */
    (void)taken();
    send_pkt("c");
    enter_monitor(0);                   /* no DFSR bits: async halt */
    check(strstr(taken(), "S02") != NULL,
          "async (Ctrl-C) halt reported as S02 (SIGINT)");

    /* A repeated '?' while halted replays the same stop reply. */
    frame_reset(0x20009100u);
    send_pkt("?");
    send_pkt("c");
    enter_monitor(DFSR_BKPT);
    const char *out = taken();
    const char *d = strchr(out, '$');
    d = strchr(d + 1, '$');             /* the reply to '?' */
    check(strncmp(d + 1, "S05", 3) == 0, "'?' while halted replays S05");
}

static void t_fpb_masked_while_halted(void)
{
    puts("-- halted: FPB master-disabled so the monitor can't trap itself");

    send_pkt("Z0,2000a000,2");
    pqf_gdb_poll();
    (void)taken();

    frame_reset(0x2000a000u);
    /* 'm' inside the session gives the monitor loop something to do
     * before it resumes, i.e. the window where it re-enters TinyUSB. */
    send_pkt("m2000a000,4");
    send_pkt("c");

    g_mmio.dfsr = DFSR_BKPT;
    /* Snoop FP_CTRL from inside the session by checking it right after
     * entry is impossible from here, so assert the invariant that
     * matters on both sides of the session instead: armed before,
     * armed after, and the comparator value survives. */
    uint32_t before = g_mmio.fp_comp[0];
    pqf_gdb_monitor_entry(g_frame, NULL, EXCRET_MSP_STD, g_r4_r11);
    (void)taken();

    check((g_mmio.fp_ctrl & 0x1u) != 0,
          "FPB re-enabled on resume (FP_CTRL.ENABLE)");
    check(g_mmio.fp_comp[0] == before,
          "comparator survived the halted session unchanged");

    send_pkt("z0,2000a000,2");
    pqf_gdb_poll();
    (void)taken();
}

static void t_qxfer_target_xml(void)
{
    puts("-- qXfer: target.xml served in GDB-sized chunks");

    /* First chunk, deliberately small so the 'm' (more) path runs. */
    send_pkt("qXfer:features:read:target.xml:0,40");
    pqf_gdb_poll();
    const char *b = first_body(taken());
    check(b[0] == 'm', "partial chunk prefixed 'm' (more to come)");
    check(strstr(b, "<?xml") != NULL, "chunk starts the XML document");

    /* Reassemble the whole document through repeated qXfer reads, the
     * way GDB does, then sanity-check the register file it describes. */
    static char xml[8192];
    size_t xlen = 0;
    for (int i = 0; i < 64; i++) {
        char pkt[64];
        snprintf(pkt, sizeof(pkt),
                 "qXfer:features:read:target.xml:%zx,100", xlen);
        send_pkt(pkt);
        pqf_gdb_poll();
        const char *chunk = first_body(taken());
        if (chunk[0] == '\0') break;
        size_t n = strlen(chunk + 1);
        if (n && xlen + n < sizeof(xml)) {
            memcpy(xml + xlen, chunk + 1, n);
            xlen += n;
        }
        if (chunk[0] == 'l') break;
    }
    xml[xlen] = '\0';
    check(strstr(xml, "armv8-m.main") != NULL,
          "target.xml declares architecture armv8-m.main");
    check(strstr(xml, "org.gnu.gdb.arm.m-profile") != NULL,
          "target.xml declares the m-profile feature");
    check(strstr(xml, "\"xpsr\"") != NULL, "target.xml ends at xpsr (reg 16)");
    check(strstr(xml, "</target>") != NULL,
          "target.xml reassembled to a complete document (%zu bytes)", xlen);

    /* Past the end must terminate the transfer, not loop forever. */
    send_pkt("qXfer:features:read:target.xml:ffff,100");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "l") == 0,
          "read past the end returns bare 'l' (end of transfer)");

    /* An annex we don't serve must be an error, not a silent empty. */
    send_pkt("qXfer:features:read:bogus.xml:0,100");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "E00") == 0,
          "unknown annex answered E00");
}

static void t_monitor_commands(void)
{
    puts("-- qRcmd: monitor help / reset / bootsel");

    /* "help" -- hex-encoded ASCII back. */
    send_pkt("qRcmd,68656c70");
    pqf_gdb_poll();
    const char *b = first_body(taken());
    check(strlen(b) > 0 && strstr(b, "6d6f6e69746f72") != NULL,
          "monitor help returns hex-encoded console text");

    unsigned reboots = g_reboot_count;
    send_pkt("qRcmd,7265736574");                   /* "reset" */
    pqf_gdb_poll();
    check(g_reboot_count == reboots + 1
          && g_reboot_mode == PQF_REBOOT_WARM,
          "monitor reset triggers a WARM reboot");

    send_pkt("qRcmd,626f6f7473656c");               /* "bootsel" */
    pqf_gdb_poll();
    check(g_reboot_count == reboots + 2
          && g_reboot_mode == PQF_REBOOT_BOOTSEL,
          "monitor bootsel triggers a BOOTSEL reboot (reflash path)");
}

static void t_escaping(void)
{
    puts("-- framing: }-escaped payload bytes decode");

    /* RSP escapes a byte as '}' followed by byte^0x20, and the checksum
     * covers the ESCAPED (wire) bytes. Write 0xab through M with the
     * 'a' nibble sent escaped ('}' + 'a'^0x20 = "}A") and assert the
     * decoded byte is what lands in memory -- an exact check that the
     * parser unescapes into the body but sums the wire form. */
    uint8_t *p = pqf_gdb_host_mem_ptr(0x2000b000u);
    p[0] = 0;

    char body[64];
    snprintf(body, sizeof(body), "M2000b000,1:%c%cb", '}', 'a' ^ 0x20);
    send_pkt(body);
    pqf_gdb_poll();
    const char *out = taken();
    check(out[0] == '+',
          "escaped body accepted (checksum computed over the wire bytes)");
    check(strcmp(first_body(out), "OK") == 0, "escaped M write acked OK");
    check(p[0] == 0xAB,
          "escaped '}A' decoded to 'a' -> byte 0xab written (got 0x%02x)", p[0]);
}

static void t_detach(void)
{
    puts("-- detach: comparators released, target runs free");

    send_pkt("Z0,2000c000,2");
    pqf_gdb_poll();
    (void)taken();
    check(g_mmio.fp_comp[0] != 0, "breakpoint armed before detach");

    send_pkt("D");
    pqf_gdb_poll();
    check(strcmp(first_body(taken()), "OK") == 0, "D acked OK");
    bool cleared = true;
    for (unsigned i = 0; i < NUM_COMP; i++) {
        if (g_mmio.fp_comp[i] != 0) cleared = false;
    }
    check(cleared, "detach cleared every FPB comparator");

    /* 'k' (gdb `kill`/quit) must NOT take the token down -- it detaches. */
    send_pkt("Z0,2000c100,2");
    pqf_gdb_poll();
    (void)taken();
    unsigned reboots = g_reboot_count;
    send_pkt("k");
    pqf_gdb_poll();
    (void)taken();
    check(g_reboot_count == reboots,
          "'k' does not reboot or brick the token");
    cleared = true;
    for (unsigned i = 0; i < NUM_COMP; i++) {
        if (g_mmio.fp_comp[i] != 0) cleared = false;
    }
    check(cleared, "'k' released the comparators (treated as detach)");
}

/* ---- --pty mode: serve a real gdb ------------------------------- *
 *
 * Models the three hardware behaviours the host can't have, per the
 * architecture: MON_PEND takes the DebugMonitor exception; MON_STEP
 * retires one instruction and re-enters; an armed FPB comparator
 * matching the pc re-enters with DFSR.BKPT. With those in place a real
 * arm-none-eabi-gdb can attach, break, step, continue, and read
 * registers/memory against the actual firmware stub code.            */

static uint32_t g_fake_pc = 0x20005000u;

/* Lowest armed comparator address, or 0 if the FPB is idle. */
static uint32_t fpb_armed_addr(void)
{
    if (!(g_mmio.fp_ctrl & 1u)) return 0;
    for (unsigned i = 0; i < NUM_COMP; i++) {
        if (g_mmio.fp_comp[i] & 1u) return g_mmio.fp_comp[i] & ~1u;
    }
    return 0;
}

/* Load an ELF's RAM-resident PT_LOAD segments into the simulated SRAM
 * at their VIRTUAL addresses. With the real firmware ELF loaded, a gdb
 * session against this harness resolves and breaks on real symbols
 * (`break ctap2_dispatch`) and disassembles real instructions read
 * back through the stub's own m packets -- the closest rehearsal of the
 * GDB stub exit criteria that is possible without silicon. ELF32 LE only,
 * which is what arm-none-eabi-gcc emits for this target. */
static void load_elf(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }

    uint8_t eh[52];
    if (fread(eh, 1, sizeof(eh), f) != sizeof(eh)
        || memcmp(eh, "\177ELF\1\1", 6) != 0) {
        fprintf(stderr, "%s: not an ELF32 little-endian file\n", path);
        exit(1);
    }
#define RD16(p) ((uint32_t)(p)[0] | ((uint32_t)(p)[1] << 8))
#define RD32(p) (RD16(p) | ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))
    uint32_t phoff   = RD32(eh + 28);
    uint32_t phentsz = RD16(eh + 42);
    uint32_t phnum   = RD16(eh + 44);

    unsigned loaded = 0;
    for (uint32_t i = 0; i < phnum; i++) {
        uint8_t ph[32];
        if (fseek(f, (long)(phoff + i * phentsz), SEEK_SET) != 0) break;
        if (fread(ph, 1, sizeof(ph), f) != sizeof(ph)) break;
        if (RD32(ph + 0) != 1) continue;                 /* PT_LOAD */
        uint32_t off   = RD32(ph + 4);
        uint32_t vaddr = RD32(ph + 8);
        uint32_t filesz = RD32(ph + 16);
        if (filesz == 0) continue;
        if (!sram_hit(vaddr) || !sram_hit(vaddr + filesz - 1)) continue;

        if (fseek(f, (long)off, SEEK_SET) != 0) continue;
        if (fread(pqf_gdb_host_mem_ptr(vaddr), 1, filesz, f) != filesz) {
            fprintf(stderr, "%s: short read on segment %u\n", path, i);
            exit(1);
        }
        printf("loaded 0x%08x..0x%08x (%u bytes) from %s\n",
               vaddr, vaddr + filesz, filesz, path);
        loaded++;
    }
#undef RD16
#undef RD32
    fclose(f);
    if (loaded == 0) {
        fprintf(stderr, "%s: no RAM-resident PT_LOAD segments -- is this a "
                        "copy_to_ram build?\n", path);
    }
}

static void pty_serve(const char *elf)
{
    int master, slave;
    char name[256];

    if (openpty(&master, &slave, name, NULL, NULL) != 0) {
        perror("openpty");
        exit(1);
    }
    /* Raw mode: GDB's protocol bytes must not be mangled by the line
     * discipline (CR/LF translation would corrupt checksums). */
    struct termios tio;
    if (tcgetattr(slave, &tio) == 0) {
        cfmakeraw(&tio);
        tcsetattr(slave, TCSANOW, &tio);
    }
    fcntl(master, F_SETFL, O_NONBLOCK);
    g_pty_fd = master;

    g_mmio.vtor = PQF_GDB_HOST_SRAM_BASE;
    g_mmio.fp_ctrl = (NUM_COMP & 0xFu) << 4;
    pqf_gdb_init();

    if (elf) {
        load_elf(elf);
    } else {
        /* No image: put recognisable bytes where the fake pc points so
         * `x/8xb $pc` shows something deterministic. */
        uint8_t *code = pqf_gdb_host_mem_ptr(g_fake_pc);
        for (int i = 0; i < 64; i++) code[i] = (uint8_t)(0x40 + i);
    }

    printf("gdbstub pty ready: %s\n", name);
    printf("attach with:  arm-none-eabi-gdb %s -ex 'target remote %s'\n",
           elf ? elf : "-ex 'set architecture armv8-m.main'", name);
    fflush(stdout);

    frame_reset(g_fake_pc);

    for (;;) {
        pqf_gdb_poll();

        if (g_mmio.demcr & DEMCR_MON_PEND) {
            g_mmio.demcr &= ~DEMCR_MON_PEND;
            g_frame[6] = g_fake_pc;
            enter_monitor(0);                   /* async halt */
        }

        /* Resume emulation, modelling the two hardware behaviours this
         * harness stands in for:
         *
         *   MON_STEP -- retires exactly one instruction, then re-enters
         *              the monitor with DFSR.HALTED. Two bytes per step
         *              (thumb), which is enough for gdb's stepi.
         *   FPB      -- an armed comparator matches when execution
         *              reaches that address. We can't really execute,
         *              so "reaching it" is modelled directly: on
         *              continue, if a comparator is armed, that is
         *              where the target next stops. With the firmware
         *              ELF loaded this is what makes `break
         *              ctap2_dispatch; continue` land on the real
         *              symbol, exactly as it must on silicon.
         */
        if (g_mmio.demcr & DEMCR_MON_STEP) {
            g_mmio.demcr &= ~DEMCR_MON_STEP;
            g_fake_pc += 2;
            g_frame[6] = g_fake_pc;
            enter_monitor(DFSR_HALTED);
        } else {
            uint32_t bp = fpb_armed_addr();
            if (bp && bp != g_fake_pc) {
                g_fake_pc  = bp;
                g_frame[6] = g_fake_pc;
                enter_monitor(DFSR_BKPT);
            }
        }

        usleep(1000);
    }
}

/* ---- main ------------------------------------------------------- */

int main(int argc, char **argv)
{
    g_sram = calloc(1, PQF_GDB_HOST_SRAM_SIZE);
    if (!g_sram) { fputs("calloc failed\n", stderr); return 1; }

    if (argc > 1 && strcmp(argv[1], "--pty") == 0) {
        /* Optional firmware .elf: loaded into the simulated SRAM so a
         * real gdb resolves real symbols against the real image. */
        pty_serve(argc > 2 ? argv[2] : NULL);       /* never returns */
        return 0;
    }

    puts("test_gdbstub -- GDB stub RSP layer (host build)");

    t_init();
    t_init_no_ram_vectors();
    t_framing();
    t_memory();
    t_breakpoints();
    t_running_target_guards();
    t_halted_registers();
    t_halted_step_and_psr();
    t_stop_reasons();
    t_fpb_masked_while_halted();
    t_qxfer_target_xml();
    t_monitor_commands();
    t_escaping();
    t_detach();

    printf("\n%u checks, %u failures\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
