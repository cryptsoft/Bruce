/* pqf_cleanse.h -- guaranteed secret-buffer zeroization.
 *
 * Plain memset(p, 0, n) on a function-local buffer that is never read
 * again is a dead store: a conforming optimiser may legally elide it,
 * leaving cleartext PIN/PIN-hash/shared-secret/key material resident on
 * the stack after a function returns. pqf_cleanse() writes through a
 * volatile pointer so the compiler must treat each byte store as an
 * observable side effect and cannot remove it.
 *
 * Use this -- not memset(...,0,...) -- for every buffer that has held a
 * secret (decrypted PIN, SHA-256(PIN), HKDF PRK/Z, HMAC key-pads,
 * decrypted credential plaintext, etc.).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CLEANSE_H
#define PQF_CLEANSE_H

#include <stddef.h>
#include <stdint.h>

/* Overwrite n bytes at p with zero, guaranteed not to be optimised
 * away. The volatile pointer forces each store to be emitted. */
static inline void pqf_cleanse(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

#endif /* PQF_CLEANSE_H */
