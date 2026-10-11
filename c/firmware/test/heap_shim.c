/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* dyld-interpose malloc accounting: tracks live bytes + peak. */
#include <stdlib.h>
#include <malloc/malloc.h>

static size_t s_cur, s_peak;

size_t shim_peak(void) { return s_peak; }
void shim_reset(void) { s_peak = s_cur; }

static void add(void *p) {
    if (!p) return;
    s_cur += malloc_size(p);
    if (s_cur > s_peak) s_peak = s_cur;
}
static void sub(void *p) {
    if (!p) return;
    size_t n = malloc_size(p);
    s_cur = (s_cur > n) ? s_cur - n : 0;
}

static void *my_malloc(size_t n) { void *p = malloc(n); add(p); return p; }
static void *my_calloc(size_t c, size_t n) { void *p = calloc(c, n); add(p); return p; }
static void *my_realloc(void *p, size_t n) { sub(p); void *q = realloc(p, n); add(q); return q; }
static void  my_free(void *p) { sub(p); free(p); }

typedef struct { const void *repl, *orig; } interpose_t;
__attribute__((used)) static const interpose_t interposers[]
    __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)my_malloc,  (const void *)malloc },
    { (const void *)my_calloc,  (const void *)calloc },
    { (const void *)my_realloc, (const void *)realloc },
    { (const void *)my_free,    (const void *)free },
};
