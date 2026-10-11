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

/*
 * A 'k' by 'l' Matrix object ('k' rows and 'l' columns) containing polynomial
 * scalars.
 *
 * The matrix is either materialised - |m_poly| holds all k * l polynomials -
 * or expanded on demand, in which case |rho| is non-NULL, |m_poly| is a single
 * scratch block, and each element is re-derived from |rho| as it is consumed.
 * ExpandA() samples every element independently, so the two forms produce
 * identical results; they trade k * l - 1 polynomials of storage against one
 * rejection sample per element per use.
 */
struct matrix_st {
    POLY *m_poly;
    size_t k, l;
    const uint8_t *rho;     /* NULL when the matrix is materialised */
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;
};

/**
 * @brief Initialize a materialised Matrix object.
 *
 * @param m The matrix object.
 * @param polys A preallocated array of k * l polynomial blocks. |m| does not
 *              own/free this.
 * @param k The number of rows
 * @param l The number of columns
 */
static ossl_inline ossl_unused void
matrix_init(MATRIX *m, POLY *polys, size_t k, size_t l)
{
    m->k = k;
    m->l = l;
    m->m_poly = polys;
    m->rho = NULL;
    m->md_ctx = NULL;
    m->md = NULL;
}

/**
 * @brief Initialize a Matrix object that expands its elements on demand.
 *
 * @param m The matrix object.
 * @param scratch A single preallocated polynomial block used to hold each
 *                element in turn. |m| does not own/free this.
 * @param k The number of rows
 * @param l The number of columns
 * @param md_ctx A EVP_MD_CTX used for sampling
 * @param md A pre-fetched SHAKE128 object
 * @param rho The 32 byte seed the matrix is derived from. It must stay valid
 *            for the lifetime of |m|.
 */
static ossl_inline ossl_unused void
matrix_init_stream(MATRIX *m, POLY *scratch, size_t k, size_t l,
                   EVP_MD_CTX *md_ctx, const EVP_MD *md, const uint8_t *rho)
{
    m->k = k;
    m->l = l;
    m->m_poly = scratch;
    m->rho = rho;
    m->md_ctx = md_ctx;
    m->md = md;
}

/**
 * @brief Return element (i, j) of a matrix.
 *
 * For a materialised matrix this is a pointer into |m_poly|. For a streaming
 * one the element is re-derived into the scratch block, so the result is only
 * valid until the next call. ExpandA() samples every element from
 * |rho| || j || i independently, so elements may be asked for in any order.
 *
 * @param m The matrix object
 * @param i The row
 * @param j The column
 * @returns the element, or NULL if expanding it failed.
 */
static ossl_inline ossl_unused const POLY *
matrix_get_elem(const MATRIX *m, size_t i, size_t j)
{
    if (m->rho == NULL)
        return m->m_poly + i * m->l + j;
    if (!ossl_ml_dsa_matrix_expand_A_elem(m->md_ctx, m->md, m->rho, i, j,
                                          m->m_poly))
        return NULL;
    return m->m_poly;
}

static ossl_inline ossl_unused int
matrix_mult_vector(const MATRIX *a, const VECTOR *s, VECTOR *t)
{
    return ossl_ml_dsa_matrix_mult_vector(a, s, t);
}

static ossl_inline ossl_unused int
matrix_expand_A(EVP_MD_CTX *g_ctx, const EVP_MD *md, const uint8_t *rho,
                MATRIX *out)
{
    return ossl_ml_dsa_matrix_expand_A(g_ctx, md, rho, out);
}
