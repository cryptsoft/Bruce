/* Fuzzing the C CBOR decoder.
 *
 * c/cbor/pqcbor.c is linked into nine existing suites and tested by
 * none of them -- they all use it as a means to reach ctap2.c. It is
 * the first thing every byte from a host meets on the C port.
 *
 * Three things this does that a fixture list cannot:
 *
 * STRUCTURE-AWARE INPUT. Uniform random bytes are rejected at byte 0
 * almost always, so they only ever exercise the first branch. This
 * builds valid CBOR, then corrupts it -- truncation, bit flips,
 * rewritten length headers, spliced tails. That reaches the code that
 * runs after a header has parsed, which is where a declared length gets
 * trusted.
 *
 * A LEAK ORACLE THAT WORKS ON THIS PLATFORM. LeakSanitizer is
 * unsupported on macOS arm64 -- it answers "detect_leaks is not
 * supported on this platform" -- so a leak across a million iterations
 * would simply not be seen. pqcbor.c is instead compiled with
 * calloc/free redirected to the counting wrappers below (the same trick
 * test_blob_alloc uses), and the balance is checked after EVERY
 * iteration. That is a stronger check than LSan would give: it catches
 * the leak on the input that caused it, not at exit.
 *
 * A ONE-DIRECTIONAL AGREEMENT ORACLE. pqfido_cbor_decode and
 * pqfido_cbor_item_length walk the same grammar, but the walker does no
 * duplicate-key detection. So decode(x) == OK must imply walk(x) == OK,
 * and not the converse -- asserting both directions would report ~30k
 * false failures per 3M iterations.
 *
 * Deterministic: iteration N is the same input on every machine, so a
 * failure prints a number that reproduces it. argv[1] overrides the
 * count for a longer soak.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pqcbor.h"

/* ---- the allocation oracle ---------------------------------------
 *
 * pqcbor.c is compiled with -Dcalloc=pqfuzz_calloc -Dfree=pqfuzz_free.
 * This file is not, so the calls below are the real ones. */
long pqf_live = 0;
long pqf_total = 0;

void *pqfuzz_calloc(size_t n, size_t sz)
{
    void *p = calloc(n, sz);
    if (p) { pqf_live++; pqf_total++; }
    return p;
}

void pqfuzz_free(void *p)
{
    if (p) pqf_live--;
    free(p);
}

static int failures;
static long checks;
#define CHECK(cond, label) do {                                          \
    checks++;                                                            \
    if (!(cond)) { printf("  FAIL: %s\n", (label)); failures++; }         \
} while (0)

/* ---- deterministic PRNG (xorshift64*) ----------------------------- */

static uint64_t rng_state = 0x243F6A8885A308D3ull;

static uint64_t rnd(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}
static size_t below(size_t n) { return n ? (size_t)(rnd() % n) : 0; }
static unsigned char rbyte(void) { return (unsigned char)(rnd() >> 24); }

/* ---- structure-aware generation ------------------------------------ */

#define MAXBUF 512

struct buf { unsigned char b[MAXBUF]; size_t n; };

static void put(struct buf *o, unsigned char c)
{
    if (o->n < MAXBUF) o->b[o->n++] = c;
}

static void put_head(struct buf *o, int major, uint64_t arg)
{
    unsigned char m = (unsigned char)(major << 5);
    if (arg <= 23) { put(o, (unsigned char)(m | arg)); }
    else if (arg <= 0xFF) { put(o, (unsigned char)(m | 24)); put(o, (unsigned char)arg); }
    else if (arg <= 0xFFFF) {
        put(o, (unsigned char)(m | 25));
        put(o, (unsigned char)(arg >> 8)); put(o, (unsigned char)arg);
    } else if (arg <= 0xFFFFFFFFu) {
        put(o, (unsigned char)(m | 26));
        put(o, (unsigned char)(arg >> 24)); put(o, (unsigned char)(arg >> 16));
        put(o, (unsigned char)(arg >> 8));  put(o, (unsigned char)arg);
    } else {
        /* The 8-byte form. There was no branch for it at all, and the
         * generator never produced an argument big enough to reach the
         * 4-byte one either -- every uint was masked to 0xFFFF. So two
         * of the five header encodings had never been fuzzed, and they
         * are the two where a 32-bit truncation lives: a declared length
         * of 0x1_0000_0004 read as 4. That exact bug was found in the
         * Rust reader by hand, and this fuzzer could not have found it. */
        put(o, (unsigned char)(m | 27));
        put(o, (unsigned char)(arg >> 56)); put(o, (unsigned char)(arg >> 48));
        put(o, (unsigned char)(arg >> 40)); put(o, (unsigned char)(arg >> 32));
        put(o, (unsigned char)(arg >> 24)); put(o, (unsigned char)(arg >> 16));
        put(o, (unsigned char)(arg >> 8));  put(o, (unsigned char)arg);
    }
}

/* An argument that reaches every header encoding, not just the short
 * ones. Weighted so the ordinary small values still dominate -- the
 * point is to reach 0x1a and 0x1b sometimes, not to spend the whole
 * budget on them. */
static uint64_t wide_arg(void)
{
    switch (below(8)) {
    case 0: return (uint64_t)rnd() << 16 | rnd();          /* 4-byte form */
    case 1: return (uint64_t)rnd() << 40 | (uint64_t)rnd() << 8 | rnd();
    case 2: return 0x100000004ull;   /* truncates to 4 in 32 bits */
    case 3: return 0xFFFFFFFFull;    /* the 32-bit boundary */
    case 4: return 0x100000000ull;   /* one past it */
    default: return rnd() & 0xFFFF;  /* the common case */
    }
}

/* Emit one random well-formed item. Map keys are made distinct by
 * construction (a counter), because the decoder rejects duplicates by
 * design and a generated collision is not a finding. */
static void gen(struct buf *o, int depth, unsigned *keyctr)
{
    int pick = (int)below(depth > 0 ? 8 : 5);
    size_t i, n;
    switch (pick) {
    case 0: put_head(o, 0, wide_arg()); break;                  /* uint   */
    case 1: put_head(o, 1, wide_arg());     break;              /* negint */
    case 2:                                                      /* bytes  */
        n = below(24);
        put_head(o, 2, n);
        for (i = 0; i < n; i++) put(o, rbyte());
        break;
    case 3:                                                      /* text   */
        n = below(16);
        put_head(o, 3, n);
        for (i = 0; i < n; i++) put(o, (unsigned char)('a' + below(26)));
        break;
    case 4:                                                      /* simple */
        put(o, (unsigned char)(0xf4 + below(4)));   /* false/true/null/undef */
        break;
    case 5:                                                      /* array  */
        n = below(4);
        put_head(o, 4, n);
        for (i = 0; i < n; i++) gen(o, depth - 1, keyctr);
        break;
    case 6:                                                      /* map    */
        n = below(4);
        put_head(o, 5, n);
        for (i = 0; i < n; i++) {
            put_head(o, 0, (*keyctr)++);   /* distinct uint keys */
            gen(o, depth - 1, keyctr);
        }
        break;
    default:                                                     /* tag    */
        put_head(o, 6, below(64));
        gen(o, depth - 1, keyctr);
        break;
    }
}

static void mutate(struct buf *o)
{
    if (o->n == 0) return;
    switch (below(6)) {
    case 0: o->b[below(o->n)] ^= (unsigned char)(1u << below(8)); break;
    case 1: o->n = below(o->n); break;                    /* truncate */
    case 2: o->b[below(o->n)] = rbyte(); break;
    case 3: {                                             /* inflate a length */
        size_t i = below(o->n);
        o->b[i] = (unsigned char)((o->b[i] & 0xE0) | (24 + below(3)));
        break;
    }
    case 4: {                                             /* trailing junk */
        size_t k = below(6);
        while (k-- && o->n < MAXBUF) put(o, rbyte());
        break;
    }
    default: {                                            /* duplicate a slice */
        if (o->n > 2) {
            size_t a = below(o->n - 1);
            size_t b = a + 1 + below(o->n - a - 1);
            size_t k;
            unsigned char tmp[MAXBUF];
            memcpy(tmp, o->b + a, b - a);
            for (k = 0; k < b - a && o->n < MAXBUF; k++) put(o, tmp[k]);
        }
        break;
    }
    }
}

/* ---- oracles -------------------------------------------------------- */

static void one_iteration(unsigned long iter)
{
    struct buf o;
    pqfido_cbor_item_t *it = NULL;
    unsigned keyctr = 0;
    long live_before = pqf_live;
    int rc;
    size_t len_out = 0;
    int len_rc;
    char label[96];

    o.n = 0;
    gen(&o, 3, &keyctr);
    if (below(2) == 0) mutate(&o);
    if (below(4) == 0) mutate(&o);

    rc = pqfido_cbor_decode(o.b, o.n, &it);

    /* 1. A failed decode must leave nothing for the caller to free, and
     *    a successful one must be freed completely. Checked every
     *    iteration so a leak is attributed to the input that caused it
     *    rather than discovered at exit with no way back. */
    if (rc != PQFIDO_OK) {
        snprintf(label, sizeof label,
                 "iter %lu: a failed decode returned a non-NULL item", iter);
        CHECK(it == NULL, label);
    }
    pqfido_cbor_free(it);
    it = NULL;

    snprintf(label, sizeof label,
             "iter %lu: decode/free left %ld allocation(s) outstanding",
             iter, pqf_live - live_before);
    CHECK(pqf_live == live_before, label);

    /* 2. decode succeeding implies the non-allocating walker succeeds
     *    and agrees on the length. NOT the converse: the walker does no
     *    duplicate-key detection, so it legitimately accepts maps the
     *    tree decoder rejects. */
    len_rc = pqfido_cbor_item_length(o.b, o.n, &len_out);
    rc = pqfido_cbor_decode(o.b, o.n, &it);
    if (rc == PQFIDO_OK) {
        snprintf(label, sizeof label,
                 "iter %lu: decode accepted but item_length refused", iter);
        CHECK(len_rc == PQFIDO_OK, label);
        snprintf(label, sizeof label,
                 "iter %lu: item_length %zu exceeds the %zu bytes given",
                 iter, len_out, o.n);
        CHECK(len_out <= o.n, label);
    }
    pqfido_cbor_free(it);

    snprintf(label, sizeof label,
             "iter %lu: the second decode/free left %ld outstanding",
             iter, pqf_live - live_before);
    CHECK(pqf_live == live_before, label);
}

/* ---- targeted cases the generator will not reach ------------------- */

static void targeted(void)
{
    pqfido_cbor_item_t *it = NULL;
    long live = pqf_live;

    /* Nesting far past PQFIDO_CBOR_MAX_DEPTH must be refused without
     * recursing the stack away. 100k levels: if the bound were missing
     * this crashes rather than failing. */
    {
        static unsigned char deep[100000];
        size_t i;
        for (i = 0; i < sizeof deep - 1; i++) deep[i] = 0x81;  /* array(1) */
        deep[sizeof deep - 1] = 0x00;
        CHECK(pqfido_cbor_decode(deep, sizeof deep, &it) != PQFIDO_OK,
              "100k nested arrays were accepted");
        pqfido_cbor_free(it); it = NULL;
        CHECK(pqf_live == live, "deep-nesting refusal leaked");
    }

    /* A tag chain is a separate recursion path from arrays. */
    {
        static unsigned char tags[100000];
        size_t i;
        for (i = 0; i < sizeof tags - 1; i++) tags[i] = 0xc0;  /* tag(0) */
        tags[sizeof tags - 1] = 0x00;
        CHECK(pqfido_cbor_decode(tags, sizeof tags, &it) != PQFIDO_OK,
              "100k nested tags were accepted");
        pqfido_cbor_free(it); it = NULL;
        CHECK(pqf_live == live, "tag-chain refusal leaked");
    }

    /* An impossible declared length must not be allocated against. */
    {
        const unsigned char huge[] = { 0x5b, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                                       'e','i','g','h','t','!','!','!' };
        CHECK(pqfido_cbor_decode(huge, sizeof huge, &it) != PQFIDO_OK,
              "a byte string claiming 2^64-1 bytes was accepted");
        pqfido_cbor_free(it); it = NULL;
        CHECK(pqf_live == live, "huge-length refusal leaked");
    }

    /* Duplicate keys are refused, including when the two keys are
     * spelled differently. `f4` and `f8 14` are both `false`; the
     * comparison works on the decoded type and argument, so it catches
     * the pair rather than being fooled by the differing bytes. */
    {
        const unsigned char dup[]  = { 0xa2, 0xf4, 0x01, 0xf4, 0x02 };
        const unsigned char spel[] = { 0xa2, 0xf4, 0x01, 0xf8, 0x14, 0x02 };
        const unsigned char ok[]   = { 0xa2, 0xf4, 0x01, 0xf5, 0x02 };
        CHECK(pqfido_cbor_decode(dup, sizeof dup, &it) != PQFIDO_OK,
              "a map with a repeated key was accepted");
        pqfido_cbor_free(it); it = NULL;
        CHECK(pqfido_cbor_decode(spel, sizeof spel, &it) != PQFIDO_OK,
              "two spellings of false slipped past duplicate detection");
        pqfido_cbor_free(it); it = NULL;
        CHECK(pqfido_cbor_decode(ok, sizeof ok, &it) == PQFIDO_OK,
              "a map with false and true keys was wrongly refused");
        pqfido_cbor_free(it); it = NULL;
        CHECK(pqf_live == live, "duplicate-key handling leaked");
    }

    /* Empty and one-byte inputs: the degenerate cases every decoder
     * gets wrong once. */
    {
        const unsigned char one[] = { 0x00 };
        CHECK(pqfido_cbor_decode(NULL, 0, &it) != PQFIDO_OK, "NULL input accepted");
        pqfido_cbor_free(it); it = NULL;
        CHECK(pqfido_cbor_decode(one, 0, &it) != PQFIDO_OK, "zero length accepted");
        pqfido_cbor_free(it); it = NULL;
        CHECK(pqfido_cbor_decode(one, 1, &it) == PQFIDO_OK, "uint 0 was refused");
        pqfido_cbor_free(it); it = NULL;
        CHECK(pqf_live == live, "degenerate inputs leaked");
    }
}

int main(int argc, char **argv)
{
    unsigned long iters = 200000;
    unsigned long i;

    if (argc > 1) iters = strtoul(argv[1], NULL, 10);

    printf("== pqcbor fuzz (%lu iterations) ==\n", iters);
    targeted();
    for (i = 0; i < iters; i++) {
        /* Reseed per iteration so the input is a pure function of its
         * index: iteration N is the same everywhere, and a reported
         * failure is reproducible by running to N. */
        rng_state = (i + 1) * 0x9E3779B97F4A7C15ull;
        one_iteration(i);
        if (failures > 20) {
            printf("  (stopping early after %d failures)\n", failures);
            break;
        }
    }
    printf("\n%ld checks, %d failure(s)\n", checks, failures);
    printf("allocations: %ld total, %ld still live\n", pqf_total, pqf_live);
    if (pqf_live != 0) {
        printf("  FAIL: %ld allocation(s) leaked overall\n", pqf_live);
        failures++;
    }
    return failures != 0;
}
