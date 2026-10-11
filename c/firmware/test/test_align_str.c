/* test_align_str.c -- the alignment-safe memcmp/strcmp.
 *
 * This file exists because of real silicon freezes. Raspberry Pi's
 * prebuilt newlib for riscv-toolchain-15 is built with GCC's default
 * `__riscv_misaligned_slow` model, so its optimised memcmp and strcmp go
 * straight to word-sized loads with no alignment check. The RP2350's
 * Hazard3 cores do not support misaligned access at all: such a load
 * traps with mcause=4. Whether a given CBOR string or crypto buffer
 * happens to be 4-aligned is data-dependent, so the traps presented as
 * random freezes -- silicon-confirmed 2026-07-14, caught mid-browser
 * MakeCredential.
 *
 * The replacements keep a word-at-a-time fast path for the mutually
 * aligned case and run bytewise otherwise. That is two code paths
 * through each function, and which one you get depends on the low two
 * bits of two pointers -- so the tests below sweep every alignment
 * combination rather than testing the aligned case and hoping.
 *
 * Compiled here with __riscv defined, since the file is an empty
 * translation unit on any other target.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* The implementations under test, renamed so they do not collide with
 * the host libc -- which is also the oracle they are checked against. */
#define memcmp pqf_memcmp
#define strcmp pqf_strcmp
#include "../src/pqf_align_str.c"
#undef memcmp
#undef strcmp

static int failures, checks;
#define CHECK(cond, ...) do {                                       \
        checks++;                                                   \
        if (!(cond)) {                                              \
            failures++;                                             \
            printf("  [FAIL] " __VA_ARGS__);                        \
            printf("\n         at %s:%d\n", __FILE__, __LINE__);    \
        }                                                           \
    } while (0)

/* Only the sign is defined by the standard, not the magnitude. */
static int sgn(int v) { return (v > 0) - (v < 0); }

/* A buffer with controllable alignment: allocate over-sized and hand
 * back a pointer at the requested offset from a 4-aligned base. */
static unsigned char pool_a[512] __attribute__((aligned(16)));
static unsigned char pool_b[512] __attribute__((aligned(16)));

static void t_memcmp_all_alignments(void)
{
    printf("--- memcmp, every alignment pair ---\n");

    /* The word fast path is taken only when BOTH pointers are word
     * aligned. Sixteen combinations, and the fifteen unaligned ones are
     * the ones newlib got wrong. */
    for (int oa = 0; oa < 4; oa++) {
        for (int ob = 0; ob < 4; ob++) {
            for (size_t n = 0; n <= 40; n++) {
                unsigned char *a = pool_a + oa;
                unsigned char *b = pool_b + ob;
                for (size_t i = 0; i < n; i++) {
                    a[i] = (unsigned char)(i * 7 + 1);
                    b[i] = a[i];
                }
                CHECK(pqf_memcmp(a, b, n) == 0,
                      "equal buffers differed at align %d/%d, n=%zu", oa, ob, n);

                if (n == 0) continue;
                /* Differ at every position in turn: the fast path breaks
                 * out on a word mismatch and resolves bytewise, so the
                 * byte that differs must still decide the ordering. */
                for (size_t d = 0; d < n; d++) {
                    unsigned char save = b[d];
                    b[d] = (unsigned char)(save ^ 0x80);
                    int want = sgn(memcmp(a, b, n));
                    int got  = sgn(pqf_memcmp(a, b, n));
                    CHECK(got == want,
                          "align %d/%d n=%zu differing at %zu: got %d want %d",
                          oa, ob, n, d, got, want);
                    b[d] = save;
                }
            }
        }
    }
}

static void t_memcmp_zero_length(void)
{
    printf("--- memcmp with n = 0 ---\n");
    /* Must not read either pointer. Passing distinct non-empty buffers
     * makes a read visible as a wrong answer. */
    pool_a[0] = 0xAA;
    pool_b[0] = 0x55;
    CHECK(pqf_memcmp(pool_a, pool_b, 0) == 0,
          "a zero-length compare looked at the buffers");
}

static void t_memcmp_sign_is_unsigned(void)
{
    printf("--- memcmp treats bytes as unsigned ---\n");
    /* The classic mistake: comparing as signed char makes 0x80 sort
     * below 0x00. On this device the bytes being compared are credential
     * ids and hashes, where that would make two different ids compare
     * equal-or-swapped depending on their high bit. */
    unsigned char hi[1] = { 0x80 };
    unsigned char lo[1] = { 0x01 };
    CHECK(sgn(pqf_memcmp(hi, lo, 1)) > 0,
          "0x80 did not compare above 0x01 -- bytes are being read as signed");
    CHECK(sgn(pqf_memcmp(lo, hi, 1)) < 0, "the reverse comparison disagrees");
}

static void t_memcmp_long_buffers(void)
{
    printf("--- memcmp over longer buffers ---\n");
    /* A credential id is 161 bytes and a hash is 32; the word loop runs
     * many iterations at those sizes. */
    for (int oa = 0; oa < 4; oa++) {
        for (int ob = 0; ob < 4; ob++) {
            unsigned char *a = pool_a + oa;
            unsigned char *b = pool_b + ob;
            size_t n = 161;
            for (size_t i = 0; i < n; i++) { a[i] = (unsigned char)i; b[i] = (unsigned char)i; }
            CHECK(pqf_memcmp(a, b, n) == 0, "161-byte equal compare failed at %d/%d", oa, ob);
            b[160] ^= 1;
            CHECK(sgn(pqf_memcmp(a, b, n)) == sgn(memcmp(a, b, n)),
                  "a difference in the last byte was missed at %d/%d", oa, ob);
            b[160] ^= 1;
            b[0] ^= 1;
            CHECK(sgn(pqf_memcmp(a, b, n)) == sgn(memcmp(a, b, n)),
                  "a difference in the first byte was wrong at %d/%d", oa, ob);
            b[0] ^= 1;
        }
    }
}

static void t_strcmp_all_alignments(void)
{
    printf("--- strcmp, every alignment pair ---\n");
    const char *words[] = {
        "", "a", "ab", "abc", "abcd", "abcde", "abcdefgh",
        "example.com", "example.co", "example.comm",
        "\x7f\x7f", "\x80\x80",
    };
    const int nw = (int)(sizeof words / sizeof words[0]);

    for (int oa = 0; oa < 4; oa++) {
        for (int ob = 0; ob < 4; ob++) {
            for (int i = 0; i < nw; i++) {
                for (int j = 0; j < nw; j++) {
                    char *a = (char *)pool_a + oa;
                    char *b = (char *)pool_b + ob;
                    strcpy(a, words[i]);
                    strcpy(b, words[j]);
                    int want = sgn(strcmp(a, b));
                    int got  = sgn(pqf_strcmp(a, b));
                    CHECK(got == want,
                          "align %d/%d %s vs %s: got %d want %d",
                          oa, ob, words[i], words[j], got, want);
                }
            }
        }
    }
}

static void t_strcmp_stops_at_the_terminator(void)
{
    printf("--- strcmp stops at NUL ---\n");
    /* The word fast path reads four bytes at a time; it must not run
     * past the terminator into whatever follows. Poison the tail so a
     * read past it changes the answer. */
    for (int oa = 0; oa < 4; oa++) {
        for (int ob = 0; ob < 4; ob++) {
            char *a = (char *)pool_a + oa;
            char *b = (char *)pool_b + ob;
            memset(a, 0xEE, 64);
            memset(b, 0x11, 64);
            strcpy(a, "rp.example");
            strcpy(b, "rp.example");
            CHECK(pqf_strcmp(a, b) == 0,
                  "equal strings differed at align %d/%d -- the compare ran "
                  "past the terminator into the poisoned tail", oa, ob);
        }
    }
}

static void t_strcmp_sign_is_unsigned(void)
{
    printf("--- strcmp treats bytes as unsigned ---\n");
    /* C requires the comparison be as unsigned char. An rpId with a
     * high-bit byte -- any non-ASCII domain -- would otherwise sort
     * wrongly, and rpId comparison is what scopes a credential. */
    char hi[2] = { (char)0x80, 0 };
    char lo[2] = { 0x01, 0 };
    CHECK(sgn(pqf_strcmp(hi, lo)) > 0,
          "0x80 did not compare above 0x01 -- bytes are being read as signed");
    CHECK(sgn(pqf_strcmp(lo, hi)) < 0, "the reverse comparison disagrees");
}

static void t_strcmp_prefixes(void)
{
    printf("--- strcmp on prefixes ---\n");
    /* The case that matters for rpId scoping: one string a prefix of the
     * other must never compare equal. "example.com" and
     * "example.com.evil" are different sites. */
    const char *pairs[][2] = {
        { "example.com", "example.com.evil" },
        { "example.co",  "example.com" },
        { "a",           "aa" },
        { "",            "a" },
    };
    for (size_t i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
        CHECK(pqf_strcmp(pairs[i][0], pairs[i][1]) != 0,
              "\"%s\" compared equal to \"%s\"", pairs[i][0], pairs[i][1]);
        CHECK(sgn(pqf_strcmp(pairs[i][0], pairs[i][1]))
              == sgn(strcmp(pairs[i][0], pairs[i][1])),
              "\"%s\" vs \"%s\" ordered differently from libc",
              pairs[i][0], pairs[i][1]);
    }
}

static void t_random_against_libc(void)
{
    printf("--- random buffers against libc ---\n");
    /* A sweep: the two implementations must agree on the sign for
     * arbitrary content at arbitrary alignments. This is where a subtle
     * word-loop error shows up that hand-picked cases miss. */
    unsigned seed = 12345;
    for (int iter = 0; iter < 20000; iter++) {
        seed = seed * 1103515245u + 12345u;
        int oa = (seed >> 16) & 3;
        int ob = (seed >> 18) & 3;
        size_t n = ((seed >> 20) % 48u) + 1u;
        unsigned char *a = pool_a + oa;
        unsigned char *b = pool_b + ob;
        for (size_t i = 0; i < n; i++) {
            seed = seed * 1103515245u + 12345u;
            a[i] = (unsigned char)(seed >> 24);
            seed = seed * 1103515245u + 12345u;
            /* Mostly equal, so the word loop actually runs. */
            b[i] = ((seed >> 8) & 7) ? a[i] : (unsigned char)(seed >> 24);
        }
        if (sgn(pqf_memcmp(a, b, n)) != sgn(memcmp(a, b, n))) {
            CHECK(0, "memcmp disagreed with libc at iteration %d "
                     "(align %d/%d, n=%zu)", iter, oa, ob, n);
            return;
        }
    }
    CHECK(1, "20000 random memcmp comparisons agree with libc");
}

int main(void)
{
    printf("alignment-safe memcmp/strcmp host test\n");
    t_memcmp_all_alignments();
    t_memcmp_zero_length();
    t_memcmp_sign_is_unsigned();
    t_memcmp_long_buffers();
    t_strcmp_all_alignments();
    t_strcmp_stops_at_the_terminator();
    t_strcmp_sign_is_unsigned();
    t_strcmp_prefixes();
    t_random_against_libc();
    printf("%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
