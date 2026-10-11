/* encoder.h -- shim (empty).
 *
 * Upstream internal/encoder.h declares ossl_bio_print_ffc_params and
 * pulls internal/ffc.h. The ml_dsa sources include it transitively
 * but use nothing from it. Empty so the include resolves without the
 * FFC (finite-field DH) machinery.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from upstream include/internal/encoder.h, Apache-2.0.
 */
#ifndef OSSL_INTERNAL_ENCODER_H
#define OSSL_INTERNAL_ENCODER_H
#endif
