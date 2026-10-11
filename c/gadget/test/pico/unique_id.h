/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Stand-in for the pico-sdk's board-id API.
 *
 * The status page reports the RP2350's unique id. Fixed here so the page
 * is byte-identical between runs.
 */
#ifndef PQF_GADGET_TEST_PICO_UNIQUE_ID_H
#define PQF_GADGET_TEST_PICO_UNIQUE_ID_H
#include <stdint.h>
#include <string.h>

#define PICO_UNIQUE_BOARD_ID_SIZE_BYTES 8

typedef struct { uint8_t id[PICO_UNIQUE_BOARD_ID_SIZE_BYTES]; } pico_unique_board_id_t;

static inline void pico_get_unique_board_id(pico_unique_board_id_t *out)
{
    static const uint8_t fixed[PICO_UNIQUE_BOARD_ID_SIZE_BYTES] =
        { 0xE6, 0x60, 0x38, 0xB7, 0x13, 0x57, 0x2A, 0x24 };
    memcpy(out->id, fixed, sizeof fixed);
}

static inline void pico_get_unique_board_id_string(char *buf, uint32_t len)
{
    static const char s[] = "E66038B713572A24";
    if (len == 0) return;
    uint32_t n = (uint32_t)(sizeof s - 1);
    if (n > len - 1) n = len - 1;
    memcpy(buf, s, n);
    buf[n] = '\0';
}

#endif
