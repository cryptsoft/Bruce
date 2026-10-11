/* Host shim: flash geometry. These MUST match pico-sdk
 * hardware/flash.h, because flash_store.c has _Static_asserts that
 * validate its whole sector layout against them -- wrong values here
 * would make those asserts certify a layout the device does not have.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_HOST_HARDWARE_FLASH_H
#define PQF_HOST_HARDWARE_FLASH_H
#define FLASH_PAGE_SIZE   (1u << 8)    /* 256  */
#define FLASH_SECTOR_SIZE (1u << 12)   /* 4096 */
#define FLASH_BLOCK_SIZE  (1u << 16)   /* 64K  */
#endif
