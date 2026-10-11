/* pqf_qrng_hw.c -- pqf_qrng_hw.h over pico-sdk hardware_i2c + GPIO.
 *
 * Instruction-set neutral: hardware_i2c and the GPIO block are the same
 * peripherals on the Cortex-M33 and Hazard3 cores, the timeout variants
 * of the I2C calls poll the timer rather than arming an alarm (so they
 * also suit the interrupt-free pure-RISC-V build), and the only wait is
 * a busy-wait. Compiled into the firmware only; the host test supplies
 * its own implementation of this header.
 *
 * Default wiring is the Pimoroni Tiny 2350's QW/ST (Qwiic / STEMMA QT)
 * connector: SDA = GP12, SCL = GP13, which are I2C0. The 4-pin QW/ST
 * cable carries 3V3/GND/SDA/SCL only, so PD is not wired by default and
 * the breakout idles it high through its own pull-up. The breakout's
 * header works too -- A0/A1 = GP26/GP27, which are I2C1, with PD on any
 * free GPIO -- through the CMake cache variables PQF_QRNG_I2C / _SDA /
 * _SCL / _PD / _BAUD. Naming the wrong controller for a pin pair scans
 * an empty bus and reports nothing found. The Spotpear profile drives
 * its LCD reset from GP12, so PQF_QRNG defaults OFF for that board.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pqf_qrng_hw.h"
#include "pqf_qrng.h"

#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "pico/time.h"

#ifndef PQF_QRNG_I2C_INDEX
#define PQF_QRNG_I2C_INDEX 0
#endif
#ifndef PQF_QRNG_SDA
#define PQF_QRNG_SDA 12
#endif
#ifndef PQF_QRNG_SCL
#define PQF_QRNG_SCL 13
#endif
/* < 0: PD is not wired to a GPIO (the QW/ST cable has no line for it). */
#ifndef PQF_QRNG_PD
#define PQF_QRNG_PD -1
#endif
/* The part allows 50-400 kHz; 100 kHz is the rate the source was
 * qualified at (qrngBridge), and the bus is not the bottleneck: a
 * 64-byte draw is four packets, ~7 ms, against a ~1 s hybrid sign. */
#ifndef PQF_QRNG_BAUD
#define PQF_QRNG_BAUD 100000
#endif
/* Per transaction. A healthy 18-byte read takes ~1.7 ms at 100 kHz. */
#ifndef PQF_QRNG_TIMEOUT_US
#define PQF_QRNG_TIMEOUT_US 20000
#endif

#define STR_(x) #x
#define STR(x)  STR_(x)

static bool s_claimed;

static i2c_inst_t *bus(void)
{
    return i2c_get_instance(PQF_QRNG_I2C_INDEX);
}

/* Both lines as plain inputs with pull-ups, so their idle level can be
 * read before the I2C block claims them. A line stuck low is the one
 * fault that looks identical to "no chip" from inside a transaction. */
static void pins_as_inputs(void)
{
    gpio_init(PQF_QRNG_SDA);
    gpio_init(PQF_QRNG_SCL);
    gpio_set_dir(PQF_QRNG_SDA, GPIO_IN);
    gpio_set_dir(PQF_QRNG_SCL, GPIO_IN);
    gpio_pull_up(PQF_QRNG_SDA);
    gpio_pull_up(PQF_QRNG_SCL);
}

static bool bus_idle(void)
{
    busy_wait_us(100);
    return gpio_get(PQF_QRNG_SDA) && gpio_get(PQF_QRNG_SCL);
}

/* Standard stuck-bus recovery: a slave interrupted mid-byte keeps SDA
 * low waiting for clocks it will never get. Drive up to nine manual SCL
 * pulses to let it finish the byte, then a STOP to resynchronise
 * everyone. Harmless when the bus is already idle. */
static void bus_recover(void)
{
    gpio_set_dir(PQF_QRNG_SCL, GPIO_OUT);
    gpio_put(PQF_QRNG_SCL, 1);
    busy_wait_us(10);
    for (int i = 0; i < 9 && gpio_get(PQF_QRNG_SDA) == 0; i++) {
        gpio_put(PQF_QRNG_SCL, 0);
        busy_wait_us(10);
        gpio_put(PQF_QRNG_SCL, 1);
        busy_wait_us(10);
    }
    /* STOP: SDA rises while SCL is high. */
    gpio_set_dir(PQF_QRNG_SDA, GPIO_OUT);
    gpio_put(PQF_QRNG_SDA, 0);
    busy_wait_us(10);
    gpio_put(PQF_QRNG_SCL, 1);
    busy_wait_us(10);
    gpio_set_dir(PQF_QRNG_SDA, GPIO_IN);
    busy_wait_us(10);
}

bool pqf_qrng_hw_init(void)
{
    pins_as_inputs();
    if (!bus_idle()) {
        bus_recover();
        pins_as_inputs();
        if (!bus_idle()) {
            /* Held low by something that will not let go: never hand
             * these pins to the controller, it would wait forever. */
            gpio_deinit(PQF_QRNG_SDA);
            gpio_deinit(PQF_QRNG_SCL);
            return false;
        }
    }

    i2c_init(bus(), PQF_QRNG_BAUD);
    gpio_set_function(PQF_QRNG_SDA, GPIO_FUNC_I2C);
    gpio_set_function(PQF_QRNG_SCL, GPIO_FUNC_I2C);
    /* The breakout carries its own 2.2k pull-ups; the internal ones add
     * no harm and let a two-wire hookup without them still work. */
    gpio_pull_up(PQF_QRNG_SDA);
    gpio_pull_up(PQF_QRNG_SCL);

#if PQF_QRNG_PD >= 0
    /* Idle high = running. pqf_qrng.c pulses it low for a clean start. */
    gpio_init(PQF_QRNG_PD);
    gpio_put(PQF_QRNG_PD, 1);
    gpio_set_dir(PQF_QRNG_PD, GPIO_OUT);
#endif
    s_claimed = true;
    return true;
}

void pqf_qrng_hw_release(void)
{
    if (!s_claimed)
        return;
    i2c_deinit(bus());
    /* Back to the reset state (NULL function, no pulls), so a board
     * with nothing on these pads is left exactly as it was found. */
    gpio_deinit(PQF_QRNG_SDA);
    gpio_deinit(PQF_QRNG_SCL);
#if PQF_QRNG_PD >= 0
    gpio_deinit(PQF_QRNG_PD);
#endif
    s_claimed = false;
}

int pqf_qrng_hw_read_regs(uint8_t reg, uint8_t *buf, size_t len)
{
    int rc;

    if (!s_claimed)
        return -1;
    /* nostop=true: repeated START between the register write and the
     * read, which is how the part expects a register read framed. */
    rc = i2c_write_timeout_us(bus(), PQF_QRNG_I2C_ADDR, &reg, 1, true,
                              PQF_QRNG_TIMEOUT_US);
    if (rc != 1)
        return -1;
    rc = i2c_read_timeout_us(bus(), PQF_QRNG_I2C_ADDR, buf, len, false,
                             PQF_QRNG_TIMEOUT_US);
    return rc == (int)len ? 0 : -1;
}

void pqf_qrng_hw_pd(bool high)
{
#if PQF_QRNG_PD >= 0
    if (s_claimed)
        gpio_put(PQF_QRNG_PD, high);
#else
    (void)high;
#endif
}

void pqf_qrng_hw_delay_us(uint32_t us)
{
    busy_wait_us(us);
}

const char *pqf_qrng_hw_describe(void)
{
    return "i2c" STR(PQF_QRNG_I2C_INDEX)
           " GP" STR(PQF_QRNG_SDA) "/GP" STR(PQF_QRNG_SCL)
#if PQF_QRNG_PD >= 0
           " pd=GP" STR(PQF_QRNG_PD)
#else
           " pd=none"
#endif
           ;
}
