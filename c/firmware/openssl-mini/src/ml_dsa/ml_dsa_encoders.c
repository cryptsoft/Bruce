/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Modified by Cryptsoft Pty Ltd for Bruce (2026). This file is not the
 * OpenSSL 3.5 original: the low-memory ML-DSA changes it carries are
 * listed, with their reasons, in ../../ML-DSA-LOWMEM.md.
 */

#include <openssl/byteorder.h>
#include <openssl/evp.h>
#include "ml_dsa_hash.h"
#include "ml_dsa_key.h"
#include "internal/packet.h"

#define POLY_COEFF_NUM_BYTES(bits)  ((bits) * (ML_DSA_NUM_POLY_COEFFICIENTS / 8))
/* Cast mod_sub result in support of left-shifts that create 64-bit values. */
#define mod_sub_64(a, b) ((uint64_t) mod_sub(a, b))

typedef int (ENCODE_FN)(const POLY *s, WPACKET *pkt);
typedef int (DECODE_FN)(POLY *s, PACKET *pkt);

static ENCODE_FN poly_encode_signed_2;
static ENCODE_FN poly_encode_signed_4;
static ENCODE_FN poly_encode_signed_two_to_power_17;
static ENCODE_FN poly_encode_signed_two_to_power_19;
static DECODE_FN poly_decode_signed_2;
static DECODE_FN poly_decode_signed_4;
static DECODE_FN poly_decode_signed_two_to_power_17;
static DECODE_FN poly_decode_signed_two_to_power_19;

/* Bit packing Algorithms */

/*
 * Encodes a polynomial into a byte string, assuming that all coefficients are
 * in the range 0..15 (4 bits).
 *
 * See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 4 bits
 *
 * i.e. Use 4 bits from each coefficient and pack them into bytes
 * So every 2 coefficients fit into 1 byte.
 *
 * This is used to encode w1 when signing with ML-DSA-65 and ML-DSA-87
 *
 * @param p A polynomial with coefficients all in the range (0..15)
 * @param pkt A packet object to write 128 bytes to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_4_bits(const POLY *p, WPACKET *pkt)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    if (!WPACKET_allocate_bytes(pkt, POLY_COEFF_NUM_BYTES(4), &out))
        return 0;

    do {
        uint32_t z0 = *in++;
        uint32_t z1 = *in++;

        *out++ = z0 | (z1 << 4);
    } while (in < end);
    return 1;
}

/*
 * Encodes a polynomial into a byte string, assuming that all coefficients are
 * in the range 0..43 (6 bits).
 *
 * See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 43
 *
 * i.e. Use 6 bits from each coefficient and pack them into bytes
 * So every 4 coefficients fit into 3 bytes.
 *
 *  |c0||c1||c2||c3|
 *   |  /|  /\  /
 *  |6 2|4 4|2 6|
 *
 * This is used to encode w1 when signing with ML-DSA-44
 *
 * @param p A polynomial with coefficients all in the range (0..43)
 * @param pkt A packet object to write 96 bytes to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_6_bits(const POLY *p, WPACKET *pkt)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    if (!WPACKET_allocate_bytes(pkt, POLY_COEFF_NUM_BYTES(6), &out))
        return 0;

    do {
        uint32_t c0 = *in++;
        uint32_t c1 = *in++;
        uint32_t c2 = *in++;
        uint32_t c3 = *in++;

        *out++ = c0 | (c1 << 6);
        *out++ = (c1 >> 2) | (c2 << 4);
        *out++ = (c2 >> 4) | (c3 << 2);
    } while (in < end);
    return 1;
}

/*
 * Encodes a polynomial into a byte string, assuming that all coefficients are
 * unsigned 10 bit values.
 *
 * See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 10 bits
 *
 * i.e. Use 10 bits from each coefficient and pack them into bytes
 * So every 4 coefficients (c0..c3) fit into 5 bytes.
 *  |c0||c1||c2||c3|
 *   |\  |\  |\  |\
 *  |8|2 6|4 4|6 2|8|
 *
 * This is used to save t1 (the high part of public key polynomial t)
 *
 * @param p A polynomial with coefficients all in the range (0..1023)
 * @param pkt A packet object to write 320 bytes to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_10_bits(const POLY *p, WPACKET *pkt)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    if (!WPACKET_allocate_bytes(pkt, POLY_COEFF_NUM_BYTES(10), &out))
        return 0;

    do {
        uint32_t c0 = *in++;
        uint32_t c1 = *in++;
        uint32_t c2 = *in++;
        uint32_t c3 = *in++;

        *out++ = (uint8_t)c0;
        *out++ = (uint8_t)((c0 >> 8) | (c1 << 2));
        *out++ = (uint8_t)((c1 >> 6) | (c2 << 4));
        *out++ = (uint8_t)((c2 >> 4) | (c3 << 6));
        *out++ = (uint8_t)(c3 >> 2);
    } while (in < end);
    return 1;
}

/*
 * @brief Reverses the procedure of poly_encode_10_bits().
 * See FIPS 204, Algorithm 18, SimpleBitUnpack(v, b) where b = 10.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 320 bytes from.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_decode_10_bits(POLY *p, PACKET *pkt)
{
    const uint8_t *in = NULL;
    uint32_t v, w, mask = 0x3ff; /* 10 bits */
    uint32_t *out = p->coeff, *end = out + ML_DSA_NUM_POLY_COEFFICIENTS;

    do {
        if (!PACKET_get_bytes(pkt, &in, 5))
            return 0;

        in = OPENSSL_load_u32_le(&v, in);
        w = *in;

        *out++ = v & mask;
        *out++ = (v >> 10) & mask;
        *out++ = (v >> 20) & mask;
        *out++ = (v >> 30) | (w << 2);
    } while (out < end);
    return 1;
}

/*
 * @brief Encodes a polynomial into a byte string, assuming that all
 * coefficients are in the range -4..4.
 * See FIPS 204, Algorithm 17, BitPack(w, a, b). (a = 4, b = 4)
 *
 * It uses a nibble from each coefficient and packs them into bytes
 * So every 2 coefficients fit into 1 byte.
 *
 * This is used to encode the private key polynomial elements of s1 and s2
 * for ML-DSA-65 (i.e. eta = 4)
 *
 * @param p An array of 256 coefficients all in the range -4..4
 * @param pkt A packet to write 128 bytes of encoded polynomial coefficients to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_signed_4(const POLY *p, WPACKET *pkt)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    if (!WPACKET_allocate_bytes(pkt, 32 * 4, &out))
        return 0;

    do {
        uint32_t z = mod_sub(4, *in++);

        *out++ = z | (mod_sub(4, *in++) << 4);
    } while (in < end);
    return 1;
}

/*
 * @brief Reverses the procedure of poly_encode_signed_4().
 * See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = b = 4.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 128 bytes from.
 *
 * @returns 1 on success, or 0 on error. An error will occur if any of the
 *          coefficients are not in the correct range.
 */
static int poly_decode_signed_4(POLY *p, PACKET *pkt)
{
    int i, ret = 0;
    uint32_t v, *out = p->coeff;
    const uint8_t *in;
    uint32_t msbs, mask;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 8); i++) {
        if (!PACKET_get_bytes(pkt, &in, 4))
            goto err;
        in = OPENSSL_load_u32_le(&v, in);

        /*
         * None of the nibbles may be >= 9. So if the MSB of any nibble is set,
         * none of the other bits may be set. First, select all the MSBs.
         */
        msbs = v & 0x88888888u;
        /* For each nibble where the MSB is set, form a mask of all the other bits. */
        mask = (msbs >> 1) | (msbs >> 2) | (msbs >> 3);
        /*
         * A nibble is only out of range in the case of invalid input, in which case
         * it is okay to leak the value.
         */
        if (value_barrier_32((mask & v) != 0))
            goto err;

        *out++ = mod_sub(4, v & 15);
        *out++ = mod_sub(4, (v >> 4) & 15);
        *out++ = mod_sub(4, (v >> 8) & 15);
        *out++ = mod_sub(4, (v >> 12) & 15);
        *out++ = mod_sub(4, (v >> 16) & 15);
        *out++ = mod_sub(4, (v >> 20) & 15);
        *out++ = mod_sub(4, (v >> 24) & 15);
        *out++ = mod_sub(4, v >> 28);
    }
    ret = 1;
 err:
    return ret;
}

/*
 * @brief Encodes a polynomial into a byte string, assuming that all
 * coefficients are in the range -2..2.
 * See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = b = 2.
 *
 * This is used to encode the private key polynomial elements of s1 and s2
 * for ML-DSA-44 and ML-DSA-87 (i.e. eta = 2)
 *
 * @param pkt A packet to write 128 bytes of encoded polynomial coefficients to.
 * @param p An array of 256 coefficients all in the range -2..2
 *
 * Use 3 bits from each coefficient and pack them into bytes
 * So every 8 coefficients fit into 3 bytes.
 *  |c0 c1 c2 c3 c4 c5 c6 c7|
 *   | /  / | |  / / | |  /
 *  |3 3 2| 1 3 3 1| 2 3 3|
 *
 * @param p An array of 256 coefficients all in the range -2..2
 * @param pkt A packet to write 64 bytes of encoded polynomial coefficients to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_signed_2(const POLY *p, WPACKET *pkt)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    if (!WPACKET_allocate_bytes(pkt, POLY_COEFF_NUM_BYTES(3), &out))
        return 0;

    do {
        uint32_t z;

        z = mod_sub(2, *in++);
        z |= mod_sub(2, *in++) << 3;
        z |= mod_sub(2, *in++) << 6;
        z |= mod_sub(2, *in++) << 9;
        z |= mod_sub(2, *in++) << 12;
        z |= mod_sub(2, *in++) << 15;
        z |= mod_sub(2, *in++) << 18;
        z |= mod_sub(2, *in++) << 21;

        out = OPENSSL_store_u16_le(out, (uint16_t) z);
        *out++ = (uint8_t) (z >> 16);
    } while (in < end);
    return 1;
}

/*
 * @brief Reverses the procedure of poly_encode_signed_2().
 * See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = b = 2.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 64 encoded bytes from.
 *
 * @returns 1 on success, or 0 on error. An error will occur if any of the
 *          coefficients are not in the correct range.
 */
static int poly_decode_signed_2(POLY *p, PACKET *pkt)
{
    int i, ret = 0;
    uint32_t u = 0, v = 0, *out = p->coeff;
    uint32_t msbs, mask;
    const uint8_t *in;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 8); i++) {
        if (!PACKET_get_bytes(pkt, &in, 3))
            goto err;
        memcpy(&u, in, 3);
        OPENSSL_load_u32_le(&v, (uint8_t *)&u);

        /*
         * Each octal value (3 bits) must be <= 4, So if the MSB is set then the
         * bottom 2 bits must not be set.
         * First, select all the MSBs (Use octal representation for the mask)
         */
        msbs = v & 044444444;
        /* For each octal value where the MSB is set, form a mask of the 2 other bits. */
        mask = (msbs >> 1) | (msbs >> 2);
        /*
         * A nibble is only out of range in the case of invalid input, in which
         * case it is okay to leak the value.
         */
        if (value_barrier_32((mask & v) != 0))
            goto err;

        *out++ = mod_sub(2, v & 7);
        *out++ = mod_sub(2, (v >> 3) & 7);
        *out++ = mod_sub(2, (v >> 6) & 7);
        *out++ = mod_sub(2, (v >> 9) & 7);
        *out++ = mod_sub(2, (v >> 12) & 7);
        *out++ = mod_sub(2, (v >> 15) & 7);
        *out++ = mod_sub(2, (v >> 18) & 7);
        *out++ = mod_sub(2, (v >> 21) & 7);
    }
    ret = 1;
 err:
    return ret;
}

/*
 * @brief Encodes a polynomial into a byte string, assuming that all
 * coefficients are in the range (-2^12 + 1)..2^12.
 * See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = 2^12 - 1, b = 2^12.
 *
 * This is used to encode the LSB of the public key polynomial elements of t0
 * (which are encoded as part of the encoded private key).
 *
 * Use 13 bits from each coefficient and pack them into bytes
 *
 * The code below packs them into 2 64 bits blocks by doing..
 *  z0 z1 z2 z3  z4  z5 z6  z7 0
 *  |   |  | |   / \  |  |  |  |
 * |13 13 13 13 12 |1 13 13 13 24
 *
 * @param p An array of 256 coefficients all in the range -2^12+1..2^12
 * @param pkt A packet to write 416 (13 * 256 / 8) bytes of encoded polynomial
 *            coefficients to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_signed_two_to_power_12(const POLY *p, WPACKET *pkt)
{
    static const uint32_t range = 1u << 12;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    do {
        uint8_t *out;
        uint64_t a1, a2;

        if (!WPACKET_allocate_bytes(pkt, 13, &out))
            return 0;

        a1 = mod_sub_64(range, *in++);
        a1 |= mod_sub_64(range, *in++) << 13;
        a1 |= mod_sub_64(range, *in++) << 26;
        a1 |= mod_sub_64(range, *in++) << 39;
        a1 |= (a2 = mod_sub_64(range, *in++)) << 52;
        a2 = (a2 >> 12) | (mod_sub_64(range, *in++) << 1);
        a2 |= mod_sub_64(range, *in++) << 14;
        a2 |= mod_sub_64(range, *in++) << 27;

        out = OPENSSL_store_u64_le(out, a1);
        out = OPENSSL_store_u32_le(out, (uint32_t) a2);
        *out = (uint8_t) (a2 >> 32);
    } while (in < end);
    return 1;
}

/*
 * @brief Reverses the procedure of poly_encode_signed_two_to_power_12().
 * See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = 2^12 - 1, b = 2^12.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 416 encoded bytes from.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_decode_signed_two_to_power_12(POLY *p, PACKET *pkt)
{
    int i, ret = 0;
    uint32_t *out = p->coeff;
    const uint8_t *in;
    static const uint32_t range = 1u << 12;
    static const uint32_t mask_13_bits = (1u << 13) - 1;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 8); i++) {
        uint64_t a1;
        uint32_t a2, b13;

        if (!PACKET_get_bytes(pkt, &in, 13))
            goto err;
        in = OPENSSL_load_u64_le(&a1, in);
        in = OPENSSL_load_u32_le(&a2, in);
        b13 = (uint32_t) *in;

        *out++ = mod_sub(range, a1 & mask_13_bits);
        *out++ = mod_sub(range, (a1 >> 13) & mask_13_bits);
        *out++ = mod_sub(range, (a1 >> 26) & mask_13_bits);
        *out++ = mod_sub(range, (a1 >> 39) & mask_13_bits);
        *out++ = mod_sub(range, (a1 >> 52) | ((a2 << 12) & mask_13_bits));
        *out++ = mod_sub(range, (a2 >> 1) & mask_13_bits);
        *out++ = mod_sub(range, (a2 >> 14) & mask_13_bits);
        *out++ = mod_sub(range, (a2 >> 27) | (b13 << 5));
    }
    ret = 1;
 err:
    return ret;
}

/*
 * @brief Encodes a polynomial into a byte string, assuming that all
 * coefficients are in the range (-2^19 + 1)..2^19.
 * See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = 2^19 - 1, b = 2^19.
 *
 * This is used to encode signatures for ML-DSA-65 & ML-DSA-87 (gamma1 = 2^19)
 *
 * Use 20 bits from each coefficient and pack them into bytes
 *
 * The code below packs every 4 (20 bit) coefficients into 10 bytes
 *  z0  z1  z2 z3
 *  |   |\  |  | \
 * |20 12|8 20 4|16
 *
 * @param p An array of 256 coefficients all in the range -2^19+1..2^19
 * @param pkt A packet to write 640 (20 * 256 / 8) bytes of encoded polynomial
 *            coefficients to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_signed_two_to_power_19(const POLY *p, WPACKET *pkt)
{
    static const uint32_t range = 1u << 19;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    do {
        uint32_t z0, z1, z2;
        uint8_t *out;

        if (!WPACKET_allocate_bytes(pkt, 10, &out))
            return 0;

        z0 = mod_sub(range, *in++);
        z0 |= (z1 = mod_sub(range, *in++)) << 20;
        z1 = (z1 >> 12) | (mod_sub(range, *in++) << 8);
        z1 |= (z2 = mod_sub(range, *in++)) << 28;

        out = OPENSSL_store_u32_le(out, z0);
        out = OPENSSL_store_u32_le(out, z1);
        out = OPENSSL_store_u16_le(out, (uint16_t) (z2 >> 4));
    } while (in < end);
    return 1;
}

/*
 * @brief Reverses the procedure of poly_encode_signed_two_to_power_19().
 * See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = 2^19 - 1, b = 2^19.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 640 encoded bytes from.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_decode_signed_two_to_power_19(POLY *p, PACKET *pkt)
{
    int i, ret = 0;
    uint32_t *out = p->coeff;
    const uint8_t *in;
    static const uint32_t range = 1u << 19;
    static const uint32_t mask_20_bits = (1u << 20) - 1;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 4); i++) {
        uint32_t a1, a2;
        uint16_t a3;

        if (!PACKET_get_bytes(pkt, &in, 10))
            goto err;
        in = OPENSSL_load_u32_le(&a1, in);
        in = OPENSSL_load_u32_le(&a2, in);
        in = OPENSSL_load_u16_le(&a3, in);

        *out++ = mod_sub(range, a1 & mask_20_bits);
        *out++ = mod_sub(range, (a1 >> 20) | ((a2 & 0xFF) << 12));
        *out++ = mod_sub(range, (a2 >> 8) & mask_20_bits);
        *out++ = mod_sub(range, (a2 >> 28) | (a3 << 4));
    }
    ret = 1;
 err:
    return ret;
}

/*
 * @brief Encodes a polynomial into a byte string, assuming that all
 * coefficients are in the range (-2^17 + 1)..2^17.
 * See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = 2^17 - 1, b = 2^17.
 *
 * This is used to encode signatures for ML-DSA-44 (where gamma1 = 2^17)
 *
 * Use 18 bits from each coefficient and pack them into bytes
 *
 * The code below packs every 4 (18 bit) coefficients into 9 bytes
 *  z0  z1  z2 z3
 *  |   |\  |  | \
 * |18 14|4 18 10| 8
 *
 * @param p An array of 256 coefficients all in the range -2^17+1..2^17
 * @param pkt A packet to write 576 (18 * 256 / 8) bytes of encoded polynomial
 *            coefficients to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_signed_two_to_power_17(const POLY *p, WPACKET *pkt)
{
    static const uint32_t range = 1u << 17;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    do {
        uint8_t *out;
        uint32_t z0, z1, z2;

        if (!WPACKET_allocate_bytes(pkt, 9, &out))
            return 0;

        z0 = mod_sub(range, *in++);
        z0 |= (z1 = mod_sub(range, *in++)) << 18;
        z1 = (z1 >> 14) | (mod_sub(range, *in++) << 4);
        z1 |= (z2 = mod_sub(range, *in++)) << 22;

        out = OPENSSL_store_u32_le(out, z0);
        out = OPENSSL_store_u32_le(out, z1);
        *out = z2 >> 10;
    } while (in < end);
    return 1;
}

/*
 * @brief Reverses the procedure of poly_encode_signed_two_to_power_17().
 * See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = 2^17 - 1, b = 2^17.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 576 encoded bytes from.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_decode_signed_two_to_power_17(POLY *p, PACKET *pkt)
{
    uint32_t *out = p->coeff;
    const uint32_t *end = out + ML_DSA_NUM_POLY_COEFFICIENTS;
    const uint8_t *in;
    static const uint32_t range = 1u << 17;
    static const uint32_t mask_18_bits = (1u << 18) - 1;

    do {
        uint32_t a1, a2, a3;

        if (!PACKET_get_bytes(pkt, &in, 9))
            return 0;
        in = OPENSSL_load_u32_le(&a1, in);
        in = OPENSSL_load_u32_le(&a2, in);
        a3 = (uint32_t) *in;

        *out++ = mod_sub(range, a1 & mask_18_bits);
        *out++ = mod_sub(range, (a1 >> 18) | ((a2 & 0xF) << 14));
        *out++ = mod_sub(range, (a2 >> 4) & mask_18_bits);
        *out++ = mod_sub(range, (a2 >> 22) | (a3 << 10));
    } while (out < end);
    return 1;
}

/*
 * @brief pkEncode() streamed a polynomial at a time into a caller's buffer.
 *
 * ossl_ml_dsa_pk_encode() needs the whole t1 vector to exist first, and
 * allocates the encoding itself. Public-key generation produces t1 one row
 * at a time and has nowhere to keep the rest, so it writes each row out as
 * Power2Round yields it. rho goes in first, exactly as pkEncode() specifies,
 * so the byte stream is identical either way.
 *
 * The caller owns |pkt| and must WPACKET_finish() it on every path.
 */
int ossl_ml_dsa_pk_encode_begin(const ML_DSA_KEY *key, WPACKET *pkt,
                                uint8_t *out, size_t out_len)
{
    if (out_len != key->params->pk_len)
        return 0;
    return WPACKET_init_static_len(pkt, out, out_len, 0)
           && WPACKET_memcpy(pkt, key->rho, sizeof(key->rho));
}

int ossl_ml_dsa_pk_encode_poly(WPACKET *pkt, const POLY *t1)
{
    return poly_encode_10_bits(t1, pkt);
}

int ossl_ml_dsa_pk_encode_done(const ML_DSA_KEY *key, WPACKET *pkt)
{
    size_t written = 0;

    return WPACKET_get_total_written(pkt, &written)
           && written == key->params->pk_len;
}

/*
 * @brief Encode the public key as an array of bytes.
 * See FIPS 204, Algorithm 22, pkEncode().
 *
 * @param key A key object containing public key values. The encoded public
 *            key data is stored in this key.
 * @returns 1 if the public key was encoded successfully or 0 otherwise.
 */
int ossl_ml_dsa_pk_encode(ML_DSA_KEY *key)
{
    int ret = 0;
    size_t i, written = 0;
    const POLY *t1 = key->t1.poly;
    size_t t1_len = key->t1.num_poly;
    size_t enc_len = key->params->pk_len;
    uint8_t *enc = OPENSSL_malloc(enc_len);
    WPACKET pkt;

    if (enc == NULL)
        return 0;

    if (!WPACKET_init_static_len(&pkt, enc, enc_len, 0)
            || !WPACKET_memcpy(&pkt, key->rho, sizeof(key->rho)))
        goto err;
    for (i = 0; i < t1_len; i++)
        if (!poly_encode_10_bits(t1 + i, &pkt))
            goto err;
    if (!WPACKET_get_total_written(&pkt, &written)
            || written != enc_len)
        goto err;
    OPENSSL_free(key->pub_encoding);
    key->pub_encoding = enc;
    ret = 1;
err:
    WPACKET_finish(&pkt);
    if (ret == 0)
        OPENSSL_free(enc);
    return ret;
}

/*
 * @brief Start hashing the encoded public key without materialising the
 * encoding.
 *
 * Computes tr = H(pkEncode(rho, t1), 64), See FIPS 204, Algorithm 6,
 * KeyGen_internal() step 8, by absorbing the same byte stream
 * ossl_ml_dsa_pk_encode() would produce. A key that is only going to sign
 * never has to hold the encoded public key, and - since the rows of t1 are
 * absorbed one at a time by ossl_ml_dsa_pk_hash_poly() as Power2Round
 * produces them - never has to hold t1 either. Signing uses tr and reads
 * neither.
 *
 * @param key A key object containing rho.
 * @param md_ctx A EVP_MD_CTX to hash with.
 * @returns 1 on success or 0 otherwise.
 */
int ossl_ml_dsa_pk_hash_init(const ML_DSA_KEY *key, EVP_MD_CTX *md_ctx)
{
    return EVP_DigestInit_ex2(md_ctx, key->shake256_md, NULL)
        && EVP_DigestUpdate(md_ctx, key->rho, sizeof(key->rho));
}

/*
 * @brief Absorb one polynomial of t1 into a hash started by
 * ossl_ml_dsa_pk_hash_init().
 *
 * The 320 bytes pkEncode() would write for this polynomial are formed on the
 * stack and absorbed. The caller squeezes tr once all k have been passed in.
 *
 * @param md_ctx A EVP_MD_CTX part way through hashing a public key encoding.
 * @param t1 The polynomial to absorb, with coefficients in the range 0..1023.
 * @returns 1 on success or 0 otherwise.
 */
int ossl_ml_dsa_pk_hash_poly(EVP_MD_CTX *md_ctx, const POLY *t1)
{
    int ret;
    size_t written;
    uint8_t buf[POLY_COEFF_NUM_BYTES(10)];
    WPACKET pkt;

    if (!WPACKET_init_static_len(&pkt, buf, sizeof(buf), 0))
        return 0;
    ret = poly_encode_10_bits(t1, &pkt)
        && WPACKET_get_total_written(&pkt, &written)
        && written == sizeof(buf)
        && EVP_DigestUpdate(md_ctx, buf, sizeof(buf));
    WPACKET_finish(&pkt);
    return ret;
}

/*
 * @brief The reverse of ossl_ml_dsa_pk_encode().
 * See FIPS 204, Algorithm 23, pkDecode().
 *
 * @param in An encoded public key.
 * @param in_len The size of |in|
 * @param key A key object to store the decoded public key into.
 *
 * @returns 1 if the public key was decoded successfully or 0 otherwise.
 */
int ossl_ml_dsa_pk_decode(ML_DSA_KEY *key, const uint8_t *in, size_t in_len)
{
    int ret = 0;
    size_t i;
    PACKET pkt;
    EVP_MD_CTX *ctx;

    if (key->priv_encoding != NULL || key->pub_encoding != NULL)
        return 0; /* Do not allow key mutation */
    if (in_len != key->params->pk_len)
        return 0;

    if (!ossl_ml_dsa_key_pub_alloc(key))
        return 0;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto err;
    if (!PACKET_buf_init(&pkt, in, in_len)
            || !PACKET_copy_bytes(&pkt, key->rho, sizeof(key->rho)))
        goto err;
    for (i = 0; i < key->t1.num_poly; i++)
        if (!poly_decode_10_bits(key->t1.poly + i, &pkt))
            goto err;

    /* cache the hash of the encoded public key */
    if (!shake_xof(ctx, key->shake256_md, in, in_len, key->tr, sizeof(key->tr)))
        goto err;

    key->pub_encoding = OPENSSL_memdup(in, in_len);
    ret = (key->pub_encoding != NULL);
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * @brief Encode the private key as an array of bytes.
 * See FIPS 204, Algorithm 24, skEncode().
 *
 * @param key A key object containing private key values. The encoded private
 *            key data is stored in this key.
 * @returns 1 if the private key was encoded successfully or 0 otherwise.
 */
int ossl_ml_dsa_sk_encode(ML_DSA_KEY *key)
{
    int ret = 0;
    const ML_DSA_PARAMS *params = key->params;
    size_t i, written = 0, k = params->k, l = params->l;
    ENCODE_FN *encode_fn;
    size_t enc_len = params->sk_len;
    const POLY *t0 = key->t0.poly;
    WPACKET pkt;
    uint8_t *enc = OPENSSL_malloc(enc_len);

    if (enc == NULL)
        return 0;

    /* eta is the range of private key coefficients (-eta...eta) */
    if (params->eta == ML_DSA_ETA_4)
        encode_fn = poly_encode_signed_4;
    else
        encode_fn = poly_encode_signed_2;

    if (!WPACKET_init_static_len(&pkt, enc, enc_len, 0)
            || !WPACKET_memcpy(&pkt, key->rho, sizeof(key->rho))
            || !WPACKET_memcpy(&pkt, key->K, sizeof(key->K))
            || !WPACKET_memcpy(&pkt, key->tr, sizeof(key->tr)))
        goto err;
    for (i = 0; i < l; ++i)
        if (!encode_fn(key->s1.poly + i, &pkt))
            goto err;
    for (i = 0; i < k; ++i)
        if (!encode_fn(key->s2.poly + i, &pkt))
            goto err;
    for (i = 0; i < k; ++i)
        if (!poly_encode_signed_two_to_power_12(t0++, &pkt))
            goto err;
    if (!WPACKET_get_total_written(&pkt, &written)
            || written != enc_len)
        goto err;
    OPENSSL_clear_free(key->priv_encoding, enc_len);
    key->priv_encoding = enc;
    ret = 1;
err:
    WPACKET_finish(&pkt);
    if (ret == 0)
        OPENSSL_clear_free(enc, enc_len);
    return ret;
}

/*
 * @brief The size of the bit-packed form of s1, s2 and t0.
 *
 * That is the tail of skEncode() - everything after rho || K || tr:
 * (l + k) polynomials at bitlen(2 * eta) bits per coefficient followed by
 * k at 13 bits. 2432 / 3904 / 4768 bytes at ML-DSA-44/65/87.
 */
size_t ossl_ml_dsa_priv_packed_len(const ML_DSA_PARAMS *params)
{
    size_t s_len = (params->eta == ML_DSA_ETA_4) ? POLY_COEFF_NUM_BYTES(4)
                                                 : POLY_COEFF_NUM_BYTES(3);

    return (params->l + params->k) * s_len
           + params->k * POLY_COEFF_NUM_BYTES(13);
}

/*
 * @brief Locate one polynomial's slot within the bit-packed private form.
 *
 * Every polynomial there occupies a fixed width, so any one of them is
 * independently addressable in either direction.
 *
 * @param params contains constants for an ML-DSA algorithm (such as eta)
 * @param which ML_DSA_PRIV_S1, ML_DSA_PRIV_S2 or ML_DSA_PRIV_T0.
 * @param idx The index of the polynomial within that vector.
 * @param off The returned byte offset of the slot.
 * @param len The returned size of the slot.
 * @returns 1 on success, or 0 if |which| or |idx| is out of range.
 */
static int priv_packed_slot(const ML_DSA_PARAMS *params, int which, size_t idx,
                            size_t *off, size_t *len)
{
    size_t s_len = (params->eta == ML_DSA_ETA_4) ? POLY_COEFF_NUM_BYTES(4)
                                                 : POLY_COEFF_NUM_BYTES(3);

    switch (which) {
    case ML_DSA_PRIV_S1:
        if (idx >= params->l)
            return 0;
        *off = idx * s_len;
        *len = s_len;
        return 1;
    case ML_DSA_PRIV_S2:
        if (idx >= params->k)
            return 0;
        *off = (params->l + idx) * s_len;
        *len = s_len;
        return 1;
    case ML_DSA_PRIV_T0:
        if (idx >= params->k)
            return 0;
        *len = POLY_COEFF_NUM_BYTES(13);
        *off = (params->l + params->k) * s_len + idx * *len;
        return 1;
    }
    return 0;
}

/*
 * @brief Reserve a key's bit-packed s1, s2 and t0 block.
 *
 * The unpacked vectors are 12288 / 17408 / 23552 bytes; packed they are
 * 2432 / 3904 / 4768. A key that is only going to sign holds them this way
 * for the life of the signature and unpacks a polynomial at a time. Key
 * generation fills the block slot by slot with ossl_ml_dsa_priv_pack_poly()
 * as it samples s1 and s2 and rounds t, so the unpacked form is never
 * assembled at all.
 *
 * @param key A key with no packed form yet.
 * @returns 1 on success or 0 on failure.
 */
int ossl_ml_dsa_priv_pack_alloc(ML_DSA_KEY *key)
{
    if (key->s_packed != NULL)
        return 0;
    key->s_packed = OPENSSL_malloc(ossl_ml_dsa_priv_packed_len(key->params));
    return key->s_packed != NULL;
}

/*
 * @brief Bit-pack one polynomial of s1, s2 or t0 into its slot.
 *
 * The packing is the tail of skEncode(): fixed-width bit manipulation over
 * every coefficient, so it does not branch on the secret it is packing.
 *
 * @param key A key holding a packed private block.
 * @param which ML_DSA_PRIV_S1, ML_DSA_PRIV_S2 or ML_DSA_PRIV_T0.
 * @param idx The index of the polynomial within that vector.
 * @param in The polynomial to encode.
 * @returns 1 on success or 0 on failure.
 */
int ossl_ml_dsa_priv_pack_poly(ML_DSA_KEY *key, int which, size_t idx,
                               const POLY *in)
{
    const ML_DSA_PARAMS *params = key->params;
    size_t off, len, written = 0;
    WPACKET pkt;
    int ret;

    if (key->s_packed == NULL
            || !priv_packed_slot(params, which, idx, &off, &len))
        return 0;
    if (!WPACKET_init_static_len(&pkt, key->s_packed + off, len, 0))
        return 0;
    if (which == ML_DSA_PRIV_T0)
        ret = poly_encode_signed_two_to_power_12(in, &pkt);
    else if (params->eta == ML_DSA_ETA_4)
        ret = poly_encode_signed_4(in, &pkt);
    else
        ret = poly_encode_signed_2(in, &pkt);
    ret = ret && WPACKET_get_total_written(&pkt, &written) && written == len;
    WPACKET_finish(&pkt);
    return ret;
}

/*
 * @brief The reverse of ossl_ml_dsa_priv_pack_poly().
 *
 * Signing decodes just the polynomial it is about to consume, which is what
 * lets s1, s2 and t0 be scratch rather than three resident vectors.
 *
 * @param key A key holding a packed private form.
 * @param which ML_DSA_PRIV_S1, ML_DSA_PRIV_S2 or ML_DSA_PRIV_T0.
 * @param idx The index of the polynomial within that vector.
 * @param out The polynomial to decode into.
 * @returns 1 on success or 0 on failure.
 */
int ossl_ml_dsa_priv_unpack_poly(const ML_DSA_KEY *key, int which, size_t idx,
                                 POLY *out)
{
    const ML_DSA_PARAMS *params = key->params;
    size_t off, len;
    PACKET pkt;

    if (key->s_packed == NULL
            || !priv_packed_slot(params, which, idx, &off, &len)
            || !PACKET_buf_init(&pkt, key->s_packed + off, len))
        return 0;
    if (which == ML_DSA_PRIV_T0)
        return poly_decode_signed_two_to_power_12(out, &pkt);
    if (params->eta == ML_DSA_ETA_4)
        return poly_decode_signed_4(out, &pkt);
    return poly_decode_signed_2(out, &pkt);
}

/*
 * @brief The reverse of ossl_ml_dsa_sk_encode().
 * See FIPS 204, Algorithm 24, skDecode().
 *
 * @param in An encoded private key.
 * @param in_len The size of |in|
 * @param key A key object to store the decoded private key into.
 *
 * @returns 1 if the private key was decoded successfully or 0 otherwise.
 */
int ossl_ml_dsa_sk_decode(ML_DSA_KEY *key, const uint8_t *in, size_t in_len)
{
    DECODE_FN *decode_fn;
    const ML_DSA_PARAMS *params = key->params;
    size_t i, k = params->k, l = params->l;
    uint8_t input_tr[ML_DSA_TR_BYTES];
    PACKET pkt;

    /* When loading from an explicit key, drop the seed. */
    OPENSSL_clear_free(key->seed, ML_DSA_SEED_BYTES);
    key->seed = NULL;

    /* Allow the key encoding to be already set to the provided pointer */
    if ((key->priv_encoding != NULL && key->priv_encoding != in)
        || key->pub_encoding != NULL)
        return 0; /* Do not allow key mutation */
    if (in_len != key->params->sk_len)
        return 0;
    if (!ossl_ml_dsa_key_priv_alloc(key))
        return 0;

    /* eta is the range of private key coefficients (-eta...eta) */
    if (params->eta == ML_DSA_ETA_4)
        decode_fn = poly_decode_signed_4;
    else
        decode_fn = poly_decode_signed_2;

    if (!PACKET_buf_init(&pkt, in, in_len)
            || !PACKET_copy_bytes(&pkt, key->rho, sizeof(key->rho))
            || !PACKET_copy_bytes(&pkt, key->K, sizeof(key->K))
            || !PACKET_copy_bytes(&pkt, input_tr, sizeof(input_tr)))
        return 0;

    for (i = 0; i < l; ++i)
        if (!decode_fn(key->s1.poly + i, &pkt))
            goto err;
    for (i = 0; i < k; ++i)
        if (!decode_fn(key->s2.poly + i, &pkt))
            goto err;
    for (i = 0; i < k; ++i)
        if (!poly_decode_signed_two_to_power_12(key->t0.poly + i, &pkt))
            goto err;
    if (PACKET_remaining(&pkt) != 0)
        goto err;
    if (key->priv_encoding == NULL
        && (key->priv_encoding = OPENSSL_memdup(in, in_len)) == NULL)
        goto err;
    /*
     * Computing the public key also computes its hash, which must be equal to
     * the |tr| value in the private key, else the key was corrupted.
     */
    if (!ossl_ml_dsa_key_public_from_private(key)
            || memcmp(input_tr, key->tr, sizeof(input_tr)) != 0)
        goto err;

    return 1;
 err:
    return 0;
}

/*
 * @brief The size of one bit-packed z polynomial in an encoded signature.
 *
 * See FIPS 204, Algorithm 26, sigEncode() - 20 bits per coefficient when
 * gamma1 is 2^19, 18 when it is 2^17.
 */
size_t ossl_ml_dsa_sig_z_packed_len(const ML_DSA_PARAMS *params)
{
    return params->gamma1 == ML_DSA_GAMMA1_TWO_POWER_19
           ? POLY_COEFF_NUM_BYTES(20) : POLY_COEFF_NUM_BYTES(18);
}

/*
 * @brief Bit-pack one z polynomial straight into an encoded signature.
 *
 * See FIPS 204, Algorithm 26, sigEncode(). Every z polynomial occupies a
 * fixed width slot, so signing writes each one to its slot as it is formed
 * instead of collecting an l polynomial vector for a second pass to encode.
 *
 * @param z A polynomial with coefficients in the range -gamma1+1..gamma1
 * @param params contains constants for an ML-DSA algorithm (such as gamma1)
 * @param idx Which column of z the polynomial is
 * @param out A signature buffer of at least params->sig_len bytes
 * @returns 1 on success, or 0 on error.
 */
int ossl_ml_dsa_sig_encode_z(const POLY *z, const ML_DSA_PARAMS *params,
                             size_t idx, uint8_t *out)
{
    size_t z_len = ossl_ml_dsa_sig_z_packed_len(params);
    ENCODE_FN *encode_fn;
    WPACKET pkt;
    int ret;

    if (idx >= params->l)
        return 0;
    if (params->gamma1 == ML_DSA_GAMMA1_TWO_POWER_19)
        encode_fn = poly_encode_signed_two_to_power_19;
    else
        encode_fn = poly_encode_signed_two_to_power_17;

    if (!WPACKET_init_static_len(&pkt,
                                 out + (params->bit_strength >> 2)
                                 + idx * z_len, z_len, 0))
        return 0;
    ret = encode_fn(z, &pkt);
    WPACKET_finish(&pkt);
    return ret;
}

/*
 * @brief Compute one polynomial's hint bits and append them to an encoded
 * signature's hint region.
 *
 * See FIPS 204, Algorithm 39, MakeHint() feeding Algorithm 20, HintBitPack().
 * The hint is encoded as the coefficient indices of the set bits, followed by
 * k running totals, so the indices can be written as they are found: signing
 * needs neither the k polynomials of 0/1 coefficients FIPS 204 describes nor
 * the k * 32 byte bitmap that replaced them.
 *
 * |out| must be the zeroed omega + k byte hint region of the signature. A
 * rejected attempt can produce more than omega hint bits; index writes are
 * clamped so they cannot run past |omega| into the running totals, and the
 * caller weighs |index| against omega before keeping the signature.
 *
 * @param ct0 c * t0 for this row
 * @param cs2 c * s2 for this row
 * @param w A * y for this row
 * @param gamma2 either ML_DSA_GAMMA2_Q_MINUS1_DIV32 or ML_DSA_GAMMA2_Q_MINUS1_DIV88
 * @param omega The most hint bits a signature may carry
 * @param row Which row of the hint the polynomial is
 * @param out The omega + k byte hint region of a signature
 * @param index In: hint bits set by rows 0..row-1. Out: including this row.
 */
void ossl_ml_dsa_sig_make_hint(const POLY *ct0, const POLY *cs2, const POLY *w,
                               uint32_t gamma2, uint32_t omega, size_t row,
                               uint8_t *out, size_t *index)
{
    int i;
    size_t idx = *index;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++) {
        if (ossl_ml_dsa_key_compress_make_hint(ct0->coeff[i], cs2->coeff[i],
                                               gamma2, w->coeff[i]) != 0) {
            if (idx < omega)
                out[idx] = (uint8_t)i;
            idx++;
        }
    }
    out[omega + row] = (uint8_t)(idx < omega ? idx : omega);
    *index = idx;
}

/*
 * @brief Decode one z polynomial from an encoded signature.
 *
 * The reverse of ossl_ml_dsa_sig_encode_z(). See FIPS 204, Algorithm 27,
 * sigDecode().
 *
 * @param z The polynomial to decode into
 * @param params contains constants for an ML-DSA algorithm (such as gamma1)
 * @param idx Which column of z to decode
 * @param in An encoded signature of params->sig_len bytes
 * @returns 1 on success, or 0 on error.
 */
int ossl_ml_dsa_sig_decode_z(POLY *z, const ML_DSA_PARAMS *params, size_t idx,
                             const uint8_t *in)
{
    size_t z_len = ossl_ml_dsa_sig_z_packed_len(params);
    PACKET pkt;

    if (idx >= params->l
            || !PACKET_buf_init(&pkt,
                                in + (params->bit_strength >> 2) + idx * z_len,
                                z_len))
        return 0;
    if (params->gamma1 == ML_DSA_GAMMA1_TWO_POWER_19)
        return poly_decode_signed_two_to_power_19(z, &pkt);
    return poly_decode_signed_two_to_power_17(z, &pkt);
}

/*
 * @brief Decode one row of the hint from an encoded signature.
 *
 * The reverse of ossl_ml_dsa_sig_make_hint(). See FIPS 204, Algorithm 21,
 * HintBitUnpack(). Each row's run of coefficient indices ends where the
 * encoding's running total for that row says, so a row can be unpacked on its
 * own: row i covers y[omega + i - 1] .. y[omega + i] - 1, and row 0 starts at
 * 0. Verification therefore never holds the whole k * 32 byte bitmap.
 *
 * Both of the malformed-input rejections in Algorithm 21 are kept. The
 * padding check has to see the last row's running total, so - like the row
 * bounds - it is only meaningful once row k - 1 is reached, and is done there.
 * Every row is decoded before the signature is accepted, so a malformed
 * encoding is still always rejected.
 *
 * @param out A 32 byte bitmap for this row's hint bits. See poly_use_hint().
 * @param params contains constants for an ML-DSA algorithm (such as omega)
 * @param row Which row of the hint to decode
 * @param in An encoded signature of params->sig_len bytes
 * @returns 1 on success, or 0 if |in| is malformed.
 */
int ossl_ml_dsa_sig_decode_h_row(uint8_t *out, const ML_DSA_PARAMS *params,
                                 size_t row, const uint8_t *in)
{
    size_t omega = (size_t)params->omega, i, first, limit;
    const uint8_t *y;

    if (row >= params->k)
        return 0;
    y = in + (params->bit_strength >> 2)
        + params->l * ossl_ml_dsa_sig_z_packed_len(params);

    first = (row == 0) ? 0 : y[omega + row - 1];
    limit = y[omega + row];
    if (limit < first || limit > omega)
        return 0;

    memset(out, 0, ML_DSA_HINT_POLY_BYTES);
    for (i = first; i < limit; i++) {
        if (i > first && y[i - 1] >= y[i])
            return 0;   /* the indices in a row must strictly increase */
        out[y[i] >> 3] |= (uint8_t)(1u << (y[i] & 7));
    }
    if (row + 1 == params->k)
        for (i = limit; i < omega; i++)
            if (y[i] != 0)
                return 0;   /* the unused index bytes must be zero */
    return 1;
}

int ossl_ml_dsa_poly_decode_expand_mask(POLY *out,
                                        const uint8_t *in, size_t in_len,
                                        uint32_t gamma1)
{
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, in, in_len))
        return 0;
    if (gamma1 == ML_DSA_GAMMA1_TWO_POWER_19)
        return poly_decode_signed_two_to_power_19(out, &pkt);
    else
        return poly_decode_signed_two_to_power_17(out, &pkt);
}

/*
 * @brief Take the high bits of a polynomial vector and encode them, without
 * materialising the intermediate vector.
 *
 * See FIPS 204, Algorithm 37, HighBits() feeding Algorithm 28, w1Encode().
 * Signing produces w1 only to encode it and hash the encoding, so each
 * polynomial is reduced in |tmp| and written out as it is reached: k - 1
 * polynomials less than building the vector, 7 KiB at ML-DSA-87.
 *
 * @param w The vector to take the high bits of
 * @param gamma2 either ML_DSA_GAMMA2_Q_MINUS1_DIV32 or ML_DSA_GAMMA2_Q_MINUS1_DIV88
 * @param tmp A scratch polynomial
 * @param out The buffer to encode into
 * @param out_len The size of |out|
 * @returns 1 if the vector was encoded successfully or 0 otherwise.
 */
int ossl_ml_dsa_w1_encode_high_bits(const VECTOR *w, uint32_t gamma2,
                                    POLY *tmp, uint8_t *out, size_t out_len)
{
    WPACKET pkt;
    ENCODE_FN *encode_fn;
    int ret = 0;
    size_t i;

    if (!WPACKET_init_static_len(&pkt, out, out_len, 0))
        return 0;
    if (gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV32)
        encode_fn = poly_encode_4_bits;
    else
        encode_fn = poly_encode_6_bits;
    for (i = 0; i < w->num_poly; ++i) {
        poly_high_bits(w->poly + i, gamma2, tmp);
        if (!encode_fn(tmp, &pkt))
            goto err;
    }
    ret = 1;
err:
    WPACKET_finish(&pkt);
    return ret;
}

/*
 * @brief Encode one polynomial of w1 into the slot it occupies in the w1
 * encoding.
 *
 * See FIPS 204, Algorithm 28, w1Encode(). Verification derives w1 a row at a
 * time, so each row is written where it belongs rather than the vector being
 * assembled for a second pass to encode.
 *
 * @param w1 A polynomial with coefficients in the range 0..15 or 0..43,
 *           depending on gamma2
 * @param gamma2 either ML_DSA_GAMMA2_Q_MINUS1_DIV32 or ML_DSA_GAMMA2_Q_MINUS1_DIV88
 * @param idx Which row of w1 the polynomial is
 * @param out The buffer to encode into
 * @param out_len The size of |out|
 * @returns 1 on success, or 0 on error.
 */
int ossl_ml_dsa_w1_encode_poly(const POLY *w1, uint32_t gamma2, size_t idx,
                               uint8_t *out, size_t out_len)
{
    WPACKET pkt;
    ENCODE_FN *encode_fn;
    size_t poly_len;
    int ret;

    if (gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV32) {
        encode_fn = poly_encode_4_bits;
        poly_len = POLY_COEFF_NUM_BYTES(4);
    } else {
        encode_fn = poly_encode_6_bits;
        poly_len = POLY_COEFF_NUM_BYTES(6);
    }
    if ((idx + 1) * poly_len > out_len
            || !WPACKET_init_static_len(&pkt, out + idx * poly_len, poly_len,
                                        0))
        return 0;
    ret = encode_fn(w1, &pkt);
    WPACKET_finish(&pkt);
    return ret;
}
