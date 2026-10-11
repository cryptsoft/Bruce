/* pqf_qrng_hw.h -- the bus underneath pqf_qrng.c.
 *
 * pqf_qrng.c owns the protocol (framing, health, conditioning, fallback
 * policy); this is the handful of primitives it needs from the board.
 * The firmware implements them over pico-sdk hardware_i2c + GPIO in
 * pqf_qrng_hw.c; test/test_qrng.c implements them as a scripted model
 * so the protocol logic is exercised with no board.
 *
 * Every call must be BOUNDED. An I2C slave interrupted mid-byte holds
 * SDA low waiting for clocks that never come, and a driver that blocks
 * on it produces a firmware that is simply dark -- indistinguishable
 * from a brick. So reads carry a timeout and init checks the idle
 * levels before the I2C block ever claims the pins.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_QRNG_HW_H
#define PQF_QRNG_HW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Claim SDA/SCL (and PD if configured), clock out a stuck bus, bring
 * the I2C controller up. false = the bus is held low and could not be
 * recovered; nothing was left claimed. */
bool pqf_qrng_hw_init(void);

/* Undo init: controller off, pins back to their reset state. Called
 * when no chip answered, so an unpopulated bus is left exactly as the
 * board profile found it. */
void pqf_qrng_hw_release(void);

/* Register read: write the one-byte register address (repeated start),
 * then read `len` bytes. 0 on success, -1 on NAK / timeout / any bus
 * error. Never blocks past the configured timeout. */
int pqf_qrng_hw_read_regs(uint8_t reg, uint8_t *buf, size_t len);

/* Drive the chip's PD (power-down, active low) line. No-op when PD is
 * not wired to a GPIO (PQF_QRNG_PD < 0). */
void pqf_qrng_hw_pd(bool high);

/* Busy-wait. Used only during init and error recovery. */
void pqf_qrng_hw_delay_us(uint32_t us);

/* Human-readable wiring, for the CDC banner: "i2c1 GP26/GP27 pd=GP2". */
const char *pqf_qrng_hw_describe(void);

#endif /* PQF_QRNG_HW_H */
