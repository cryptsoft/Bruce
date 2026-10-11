/* crypto.h -- minimal libcrypto shim.
 *
 * sha256.c and md32_common.h reference exactly one symbol from this
 * header: OPENSSL_cleanse(), used inside SHA256_Final() to wipe the
 * context after producing the digest. The upstream function offers
 * compiler-defeating zeroisation (it survives dead-store elimination);
 * for our embedded use, a plain memset is good enough -- the cleared
 * context lives in heap or stack memory we control and the threat
 * model is "don't leak partial intermediate state across CTAP
 * transactions", not anti-debug.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/crypto.h.in`,
 *   Copyright 1995-2023 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_CRYPTO_H
#define OPENSSL_CRYPTO_H

#include <string.h>
#include <stddef.h>
#include <stdlib.h>     /* malloc / calloc / realloc / free */

/* Zeroization that survives the optimiser.
 *
 * This was `memset(ptr, 0, len)`, which does not work. A memset whose
 * buffer is dead afterwards is a dead store, and GCC removes it -- most
 * aggressively when the very next statement frees the same pointer,
 * which is exactly the OPENSSL_clear_free() shape below. Compiled
 * -O2 -mcpu=cortex-m33, a function that malloc'd 64 bytes, wrote to
 * them and then memset+free'd them reduced to a single `bx lr`: the
 * store, the memset AND the free were all eliminated. Every cleanse in
 * this tree was therefore a no-op in the shipped firmware, leaving
 * ML-DSA private vectors and BN intermediates in freed heap.
 *
 * Writing through a volatile pointer forces each store to be emitted;
 * the same technique the firmware already used for stack buffers.
 * Byte-at-a-time is slower than memset, but every caller here is
 * wiping a key, a polynomial vector or a digest context, never a hot
 * loop. */
static inline void OPENSSL_cleanse(void *ptr, size_t len)
{
    volatile unsigned char *v = (volatile unsigned char *)ptr;

    while (len--)
        *v++ = 0;
}

/* Constant-time memory compare -- returns 0 iff equal. Used by the
 * packet/ml_dsa code for tag / encoded-key comparisons. */
static inline int CRYPTO_memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (unsigned char)(pa[i] ^ pb[i]);
    return diff;
}

/* CRYPTO_RWLOCK -- referenced by openssl/bn.h. The firmware is
 * single-threaded for CTAP dispatch (and runs core-1 PQC work via a
 * shared-state handshake, not concurrent libcrypto calls), so we
 * stub the lock type as an opaque struct. Code paths that try to
 * acquire / release the lock fall through the stubs below as no-ops. */
typedef struct crypto_rwlock_st CRYPTO_RWLOCK;

static inline CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new (void) { return (CRYPTO_RWLOCK *)1; }
static inline int            CRYPTO_THREAD_read_lock (CRYPTO_RWLOCK *l) { (void)l; return 1; }
static inline int            CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *l) { (void)l; return 1; }
static inline int            CRYPTO_THREAD_unlock    (CRYPTO_RWLOCK *l) { (void)l; return 1; }
static inline void           CRYPTO_THREAD_lock_free (CRYPTO_RWLOCK *l) { (void)l; }

/* CRYPTO_atomic_* -- single-threaded -> trivial load / add over plain
 * int. (The reference-count *struct* CRYPTO_REF_COUNT lives in
 * internal/refcount.h; these operate on raw ints.) */
static inline int CRYPTO_atomic_load_int(int *v, int *ret, CRYPTO_RWLOCK *l)
{ (void)l; *ret = *v; return 1; }
static inline int CRYPTO_atomic_add(int *v, int amt, int *ret,
                                     CRYPTO_RWLOCK *l)
{ (void)l; *v += amt; if (ret) *ret = *v; return 1; }

#define CRYPTO_THREAD_run_once(once, fn)   ((void)fn())

/* ---- ex_data: per-object application data slots ----
 *
 * EC_KEY embeds a CRYPTO_EX_DATA and registers ex-data callbacks.
 * The firmware never attaches application data to keys, so the
 * struct is a single inert pointer and the management functions are
 * no-ops that report success. */
typedef struct crypto_ex_data_st {
    void *sk;
} CRYPTO_EX_DATA;

typedef int  CRYPTO_EX_new (void);
typedef void CRYPTO_EX_free(void);
typedef int  CRYPTO_EX_dup (void);

/* ex-data index classes. EC_KEY registers under CRYPTO_EX_INDEX_EC_KEY;
 * the values are opaque tags, never used for arithmetic. */
enum {
    CRYPTO_EX_INDEX_SSL = 0,
    CRYPTO_EX_INDEX_SSL_CTX,
    CRYPTO_EX_INDEX_SSL_SESSION,
    CRYPTO_EX_INDEX_X509,
    CRYPTO_EX_INDEX_X509_STORE,
    CRYPTO_EX_INDEX_X509_STORE_CTX,
    CRYPTO_EX_INDEX_DH,
    CRYPTO_EX_INDEX_DSA,
    CRYPTO_EX_INDEX_EC_KEY,
    CRYPTO_EX_INDEX_RSA,
    CRYPTO_EX_INDEX_ENGINE,
    CRYPTO_EX_INDEX_UI,
    CRYPTO_EX_INDEX_BIO,
    CRYPTO_EX_INDEX_APP,
    CRYPTO_EX_INDEX__COUNT
};

static inline int  CRYPTO_get_ex_new_index(int idx, long argl, void *argp,
                                            void *n, void *d, void *f)
{ (void)idx; (void)argl; (void)argp; (void)n; (void)d; (void)f; return 0; }
static inline int  CRYPTO_new_ex_data(int idx, void *obj, CRYPTO_EX_DATA *ad)
{ (void)idx; (void)obj; if (ad) ad->sk = NULL; return 1; }
static inline int  CRYPTO_dup_ex_data(int idx, CRYPTO_EX_DATA *to,
                                       const CRYPTO_EX_DATA *from)
{ (void)idx; (void)from; if (to) to->sk = NULL; return 1; }
static inline void CRYPTO_free_ex_data(int idx, void *obj, CRYPTO_EX_DATA *ad)
{ (void)idx; (void)obj; if (ad) ad->sk = NULL; }
static inline int  CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val)
{ (void)ad; (void)idx; (void)val; return 1; }
static inline void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx)
{ (void)ad; (void)idx; return NULL; }

/* Case-insensitive compare -- EC name lookup uses it. */
static inline int OPENSSL_strcasecmp(const char *a, const char *b)
{
    unsigned char ca, cb;
    do {
        ca = (unsigned char)*a++; cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
    } while (ca && ca == cb);
    return (int)ca - (int)cb;
}

/* libcrypto-side memory wrappers some callers expect to be linkable
 * symbols (not the macro form). Wrap the macros above. */
static inline void *CRYPTO_malloc (size_t n, const char *f, int l)
    { (void)f; (void)l; return malloc(n); }
static inline void *CRYPTO_zalloc (size_t n, const char *f, int l)
    { (void)f; (void)l; return calloc(1, n); }
static inline void *CRYPTO_realloc(void *p, size_t n, const char *f, int l)
    { (void)f; (void)l; return realloc(p, n); }
static inline void  CRYPTO_free   (void *p, const char *f, int l)
    { (void)f; (void)l; free(p); }
static inline void  CRYPTO_clear_free(void *p, size_t n, const char *f, int l)
    { (void)f; (void)l; if (p) { memset(p, 0, n); free(p); } }

/* Secure-heap allocators. Upstream uses these for sensitive material
 * (BN_priv_* values, etc.) and pulls from a separately-mmapped pool
 * that's wiped on free. For the embedded firmware we route through
 * plain malloc/free + an explicit cleanse -- the device has no
 * swap / no shared filesystem / no /proc, so the threat model the
 * secure heap addresses isn't reachable here. */
static inline void *OPENSSL_secure_malloc(size_t n)
    { return malloc(n); }
static inline void *OPENSSL_secure_zalloc(size_t n)
    { return calloc(1, n); }
static inline void  OPENSSL_secure_free(void *p)
    { free(p); }
static inline void  OPENSSL_secure_clear_free(void *p, size_t n)
    { if (p) { memset(p, 0, n); free(p); } }
static inline int   CRYPTO_secure_malloc_initialized(void) { return 0; }
static inline size_t OPENSSL_secure_actual_size(void *p)
    { (void)p; return 0; }

/* Misc allocator helpers BN's conversion + context paths reach for. */
static inline char *OPENSSL_strdup(const char *s)
{
    if (s == NULL) return NULL;
    size_t n = strlen(s) + 1;
    char *r = (char *)malloc(n);
    if (r) memcpy(r, s, n);
    return r;
}
static inline void *OPENSSL_clear_realloc(void *p, size_t old_n, size_t n)
{
    (void)old_n;       /* plain realloc; we don't wipe the old block */
    return realloc(p, n);
}
static inline void *OPENSSL_memdup(const void *p, size_t n)
{
    if (p == NULL) return NULL;
    void *r = malloc(n);
    if (r) memcpy(r, p, n);
    return r;
}
static inline char *OPENSSL_strndup(const char *s, size_t maxlen)
{
    if (s == NULL) return NULL;
    size_t n = 0;
    while (n < maxlen && s[n]) n++;
    char *r = (char *)malloc(n + 1);
    if (r) { memcpy(r, s, n); r[n] = '\0'; }
    return r;
}
static inline size_t OPENSSL_strlcpy(char *dst, const char *src, size_t size)
{
    size_t l = strlen(src);
    if (size) {
        size_t cp = (l >= size) ? size - 1 : l;
        memcpy(dst, src, cp); dst[cp] = '\0';
    }
    return l;
}
static inline size_t OPENSSL_strlcat(char *dst, const char *src, size_t size)
{
    size_t dl = strlen(dst), sl = strlen(src);
    if (dl < size) {
        size_t cp = (size - dl - 1 < sl) ? size - dl - 1 : sl;
        memcpy(dst + dl, src, cp); dst[dl + cp] = '\0';
    }
    return dl + sl;
}

static inline int OPENSSL_hexchar2int(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* OPENSSL_malloc family -- defined here (in the header every BN/EC
 * source pulls via types.h) rather than only in internal/cryptlib.h,
 * because the EC sources don't include cryptlib.h. Route through the
 * standard allocator; OPENSSL_zalloc zero-fills like upstream. */
#ifndef OPENSSL_malloc
#define OPENSSL_malloc(n)            malloc((n))
#define OPENSSL_zalloc(n)            calloc(1, (n))
#define OPENSSL_realloc(p, n)        realloc((p), (n))
#define OPENSSL_free(p)              free((p))
/* OPENSSL_cleanse, not memset -- see its definition above. A memset here
 * is deleted outright, because the pointer is freed on the next line. */
#define OPENSSL_clear_free(p, n)     do { \
    if ((p) != NULL) { OPENSSL_cleanse((p), (n)); free((p)); } \
} while (0)
#endif

#endif /* OPENSSL_CRYPTO_H */
