/* pqf_align_str.c -- alignment-safe memcmp/strcmp for Hazard3 (RISC-V
 * builds only; empty translation unit elsewhere).
 *
 * WHY THIS FILE EXISTS (root cause of the 2026-07 RISC-V freezes):
 * the prebuilt newlib in Raspberry Pi's riscv-toolchain-15 is compiled
 * with GCC's default `__riscv_misaligned_slow` model -- "misaligned
 * scalar access is supported, just slow" -- so its optimised memcmp and
 * strcmp go straight to word-sized loads with NO alignment check
 * (strcmp additionally uses the Zbb orc.b word trick). The RP2350's
 * Hazard3 cores do NOT support misaligned access at all: any such load
 * traps with mcause=4 (LOAD_ALIGN). Whether a given CBOR string /
 * crypto buffer pointer happens to be 4-aligned is data-dependent, so
 * the traps looked like random freezes (silicon-confirmed 2026-07-14:
 * `!! CORE 0 TRAP mcause=4 mepc=<newlib memcmp+6>` during a browser
 * MakeCredential, caught by the trap reporter in core1_signer.c).
 *
 * Defining the functions here (strong symbols, in an object file)
 * means the linker never pulls newlib's archive copies. Word-at-a-time
 * fast paths are kept for the mutually-aligned case; everything else
 * runs bytewise. The toolchain's memcpy/memset/memmove/strlen variants
 * were audited by disassembly and DO align first -- they need no
 * replacement. The Arm builds keep plain newlib (the M33 supports
 * misaligned access in hardware; those builds are silicon-validated).
 *
 * The mixed-mode core-1 blob compiles this file too (build_blob.sh) --
 * its libc is the same newlib, and the same trap class is the leading
 * explanation for its previously-observed random signing failures.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(__riscv)

#include <stddef.h>
#include <stdint.h>

int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *a = (const unsigned char *)s1;
    const unsigned char *b = (const unsigned char *)s2;

    /* Word-at-a-time only when BOTH pointers are word-aligned. */
    if ((((uintptr_t)a | (uintptr_t)b) & 3u) == 0) {
        while (n >= 4) {
            uint32_t wa = *(const uint32_t *)(const void *)a;
            uint32_t wb = *(const uint32_t *)(const void *)b;
            if (wa != wb)
                break;              /* resolve the ordering bytewise */
            a += 4; b += 4; n -= 4;
        }
    }
    while (n--) {
        if (*a != *b)
            return (int)*a - (int)*b;
        a++; b++;
    }
    return 0;
}

int strcmp(const char *s1, const char *s2)
{
    const unsigned char *a = (const unsigned char *)s1;
    const unsigned char *b = (const unsigned char *)s2;
    while (*a && *a == *b) {
        a++; b++;
    }
    return (int)*a - (int)*b;
}

#endif /* __riscv */
