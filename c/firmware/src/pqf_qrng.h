/* pqf_qrng.h -- external quantum RNG, read over I2C.
 *
 * An optional external entropy source. When a chip answers on the bus at
 * boot it becomes the FIRST source pqf_rand.c draws from; when nothing
 * answers, or the chip stops answering, pqf_rand.c falls back to the
 * source the port used before (pico_rand over the on-die TRNG). The
 * device keeps working either way -- the QRNG is preferred, not required.
 *
 * Register map (the same numbers the
 * qrngBridge bring-up firmware validated on silicon):
 *   7-bit address 0x37
 *   0x10  status: 0x00 = calibrated and ready
 *   0x12  packet, burst read of 18 bytes: header (always 0xA2), health
 *         byte (low nibble must be 0), then 16 bytes of entropy. Reading
 *         0x12 latches a fresh packet; new entropy every ~500 us.
 *
 * CONDITIONING. The part has no DRBG inside and its maker claims only
 * >= 7.0 bits of min-entropy per byte, not 8. Its
 * raw stream is measurably biased (ones ratio 0.4973 over 170 KB on
 * this part). So nothing here hands raw bytes to a caller: every 32
 * bytes out are SHA-256 over 64 raw bytes in -- 448 bits of claimed
 * min-entropy for 256 out, comfortably past what SP 800-90B asks of a
 * vetted conditioner. Header and health bytes are framing and are
 * dropped before hashing; a packet with a bad header or a set health
 * bit is discarded whole.
 *
 * The bus access is behind pqf_qrng_hw.h so this file has no pico-sdk
 * dependency and the framing / conditioning / fallback logic runs on
 * the host (test/test_qrng.c).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_QRNG_H
#define PQF_QRNG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PQF_QRNG_I2C_ADDR        0x37
#define PQF_QRNG_REG_STATUS      0x10
#define PQF_QRNG_REG_PACKET      0x12
#define PQF_QRNG_PACKET_LEN      18
#define PQF_QRNG_HEADER_BYTE     0xA2
#define PQF_QRNG_HEALTH_MASK     0x0F
#define PQF_QRNG_ENTROPY_PER_PKT 16
/* 64 raw bytes -> 32 conditioned. */
#define PQF_QRNG_RAW_PER_HASH    64
#define PQF_QRNG_HASH_OUT        32

struct pqf_qrng_stats {
    uint32_t packets;        /* packets read off the chip                */
    uint32_t header_err;     /* packets dropped: header != 0xA2          */
    uint32_t health_err;     /* packets dropped: health nibble set       */
    uint32_t bus_err;        /* I2C transactions that failed or timed out */
    uint32_t served;         /* conditioned bytes handed to callers      */
    uint32_t short_requests; /* requests this source could not complete  */
    uint8_t  bus_stuck;      /* 1: SDA/SCL held low at boot, bus unusable */
    uint8_t  not_ready;      /* 1: chip ACKed at boot but never readied  */
    uint8_t  lost;           /* 1: was present, then failed repeatedly   */
};

/* Probe for the chip. Claims the bus pins, recovers a stuck bus, checks
 * whether anything ACKs at 0x37, power-cycles the part through PD (a
 * no-op when PD is not wired) and waits for the status register to
 * read ready. Bounded: every bus operation has a timeout, and an absent
 * chip is decided by a NAK in microseconds. Returns true if the QRNG is
 * present and ready; false leaves the pins released. */
bool pqf_qrng_init(void);

/* True while a chip that answered at boot is still believed healthy. */
bool pqf_qrng_present(void);

/* The three states a host can be told about (CTAPHID_CMD_RNG_STATUS):
 * nothing answered at boot; answered and serving; answered at boot but
 * written off since (unplugged, or failed repeatedly). */
enum pqf_qrng_state {
    PQF_QRNG_ABSENT = 0,
    PQF_QRNG_LIVE   = 1,
    PQF_QRNG_LOST   = 2,
};
enum pqf_qrng_state pqf_qrng_state(void);

/* Fill `out` with up to `len` conditioned bytes. Returns the number
 * written -- `len` on success, less if the chip failed mid-request (the
 * caller supplies the rest from its fallback source). Every byte is
 * handed out exactly once; served bytes are wiped from the buffer. */
size_t pqf_qrng_bytes(uint8_t *out, size_t len);

const struct pqf_qrng_stats *pqf_qrng_stats(void);

#endif /* PQF_QRNG_H */
