/* blob_alloc.c -- two-ended arena allocator (see blob_alloc.h for the
 * rationale and the measured sizing). Freestanding: no libc calls
 * except memset/memcpy. Compiled into the RISC-V blob AND into the
 * host test (test/test_blob_alloc.c), so keep it ISA-neutral.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <string.h>

#include "blob_alloc.h"

#define BLOB_ALIGN     8u
#define BLOB_SMALL_MAX 512u
#define ALIGN_UP(n)    (((n) + (BLOB_ALIGN - 1)) & ~(size_t)(BLOB_ALIGN - 1))

typedef struct big_hdr {
    uint32_t size;               /* payload bytes (aligned)             */
    struct big_hdr *next_free;   /* on the free list only               */
} big_hdr_t;

static uint8_t   *s_lo, *s_hi;   /* arena bounds                        */
static uint8_t   *s_big_brk;     /* bottom-up bump limit (first unused) */
static uint8_t   *s_small_brk;   /* top-down bump limit (lowest used)   */
static big_hdr_t *s_free_list;   /* address-sorted free big chunks      */
static size_t     s_hw;          /* high-water, both ends combined      */

void blob_heap_init(void *lo, void *hi)
{
    s_lo = (uint8_t *)lo;
    s_hi = (uint8_t *)hi;
    s_hw = 0;
    blob_heap_reset();
}

void blob_heap_reset(void)
{
    s_big_brk   = s_lo;
    s_small_brk = s_hi;
    s_free_list = NULL;
}

size_t blob_heap_hw(void) { return s_hw; }

static void hw_note(void)
{
    size_t used = (size_t)(s_big_brk - s_lo) + (size_t)(s_hi - s_small_brk);
    if (used > s_hw)
        s_hw = used;
}

void *blob_malloc(size_t n)
{
    if (n == 0) n = 1;
    n = ALIGN_UP(n);

    if (n < BLOB_SMALL_MAX) {
        /* Small: top-down bump with an 8-byte size header (realloc /
         * free dispatch). Never reused within an op by design. */
        uint8_t *p = s_small_brk - (n + BLOB_ALIGN);
        if (p < s_big_brk) { blob_alloc_oom(n); return NULL; }
        s_small_brk = p;
        *(uint32_t *)p = (uint32_t)n;
        hw_note();
        return p + BLOB_ALIGN;
    }

    /* Big: first-fit over the address-sorted free list, splitting when
     * the remainder can hold another big chunk. */
    big_hdr_t **link = &s_free_list;
    for (big_hdr_t *c = s_free_list; c; link = &c->next_free, c = c->next_free) {
        if (c->size < n) continue;
        if (c->size >= n + sizeof(big_hdr_t) + BLOB_SMALL_MAX) {
            big_hdr_t *rest = (big_hdr_t *)((uint8_t *)(c + 1) + n);
            rest->size = c->size - (uint32_t)n - (uint32_t)sizeof(big_hdr_t);
            rest->next_free = c->next_free;
            *link = rest;
            c->size = (uint32_t)n;
        } else {
            *link = c->next_free;
        }
        c->next_free = NULL;
        return c + 1;
    }
    /* No fit: extend bottom-up. */
    uint8_t *p = s_big_brk;
    if (p + sizeof(big_hdr_t) + n > s_small_brk) { blob_alloc_oom(n); return NULL; }
    s_big_brk = p + sizeof(big_hdr_t) + n;
    big_hdr_t *h = (big_hdr_t *)p;
    h->size = (uint32_t)n;
    h->next_free = NULL;
    hw_note();
    return h + 1;
}

void blob_free(void *ptr)
{
    if (ptr == NULL) return;
    uint8_t *p = (uint8_t *)ptr;
    if (p >= s_small_brk && p < s_hi)
        return;                          /* small side: no reuse */

    /* Big side: insert address-sorted, coalesce with both neighbours,
     * then give a trailing chunk back to the bump limit. */
    big_hdr_t *h = (big_hdr_t *)p - 1;
    big_hdr_t **link = &s_free_list;
    while (*link && *link < h)
        link = &(*link)->next_free;
    h->next_free = *link;
    *link = h;
    /* coalesce h with its successor */
    if (h->next_free
        && (uint8_t *)(h + 1) + h->size == (uint8_t *)h->next_free) {
        h->size += (uint32_t)sizeof(big_hdr_t) + h->next_free->size;
        h->next_free = h->next_free->next_free;
    }
    /* coalesce predecessor with h */
    if (link != &s_free_list) {
        big_hdr_t *prev = (big_hdr_t *)((uint8_t *)link
                                        - offsetof(big_hdr_t, next_free));
        if ((uint8_t *)(prev + 1) + prev->size == (uint8_t *)h) {
            prev->size += (uint32_t)sizeof(big_hdr_t) + h->size;
            prev->next_free = h->next_free;
            h = prev;
        }
    }
    /* trailing free chunk: shrink the bump limit instead of listing it */
    if ((uint8_t *)(h + 1) + h->size == s_big_brk) {
        big_hdr_t **l2 = &s_free_list;
        while (*l2 && *l2 != h)
            l2 = &(*l2)->next_free;
        if (*l2 == h) {
            *l2 = h->next_free;
            s_big_brk = (uint8_t *)h;
        }
    }
}

void *blob_calloc(size_t nmemb, size_t size)
{
    if (size != 0 && nmemb > (size_t)-1 / size)
        return NULL;
    size_t n = nmemb * size;
    void *p = blob_malloc(n);
    if (p) memset(p, 0, n);
    return p;
}

void *blob_realloc(void *ptr, size_t n)
{
    if (ptr == NULL) return blob_malloc(n);
    if (n == 0) { blob_free(ptr); return NULL; }
    uint8_t *p = (uint8_t *)ptr;
    size_t old = (p >= s_small_brk && p < s_hi)
        ? *(uint32_t *)(p - BLOB_ALIGN)
        : ((big_hdr_t *)p - 1)->size;
    void *q = blob_malloc(n);
    if (q) {
        memcpy(q, ptr, old < n ? old : n);
        blob_free(ptr);
    }
    return q;
}
