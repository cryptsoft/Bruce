/* Host shim for the QMI window registers.
 *
 * Modelled rather than stubbed, because this is where a real
 * regression lived: the flash-op path once left QMI window 0 in slow
 * 03h serial mode after every write, turning a 1-second ML-DSA
 * signature into 13 and timing the host out. flash_store.c saves and
 * restores the window around the XIP-off sequence; a test can only see
 * that if the registers exist and hold what was written.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PQF_HOST_HARDWARE_STRUCTS_QMI_H
#define PQF_HOST_HARDWARE_STRUCTS_QMI_H
#include <stdint.h>

typedef struct {
    uint32_t timing;
    uint32_t rfmt;
    uint32_t rcmd;
    uint32_t wfmt;
    uint32_t wcmd;
} qmi_mem_hw_t;

typedef struct {
    qmi_mem_hw_t m[2];
} pqf_host_qmi_t;

extern pqf_host_qmi_t pqf_host_qmi;
#define qmi_hw (&pqf_host_qmi)
#endif
