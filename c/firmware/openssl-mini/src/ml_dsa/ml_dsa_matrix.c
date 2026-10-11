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

#include "ml_dsa_local.h"
#include "ml_dsa_vector.h"
#include "ml_dsa_matrix.h"

/*
 * Matrix multiply of a k*l matrix of polynomials by a 1 * l vector of
 * polynomials to produce a 1 * k vector of polynomial results.
 * i.e. t = a * s
 *
 * The matrix is walked strictly row by row, so an |a| initialised by
 * matrix_init_stream() can re-derive each element as it is reached rather
 * than holding all k * l of them.
 *
 * @param a A k * l matrix of polynomials in NTT form
 * @param s A 1 * l vector of polynomials in NTT form
 * @param t 1 * k vector of polynomial results in NTT form
 * @returns 1 on success, or 0 if expanding an element of |a| failed.
 */
int ossl_ml_dsa_matrix_mult_vector(const MATRIX *a, const VECTOR *s,
                                   VECTOR *t)
{
    size_t i, j;
    POLY *poly = a->m_poly;

    vector_zero(t);

    if (a->rho == NULL) {
        for (i = 0; i < a->k; i++) {
            for (j = 0; j < a->l; j++)
                ossl_ml_dsa_poly_ntt_mult_add(poly++, &s->poly[j], &t->poly[i]);
        }
        return 1;
    }

    for (i = 0; i < a->k; i++) {
        for (j = 0; j < a->l; j++) {
            if (!ossl_ml_dsa_matrix_expand_A_elem(a->md_ctx, a->md, a->rho,
                                                  i, j, poly))
                return 0;
            ossl_ml_dsa_poly_ntt_mult_add(poly, &s->poly[j], &t->poly[i]);
        }
    }
    return 1;
}
