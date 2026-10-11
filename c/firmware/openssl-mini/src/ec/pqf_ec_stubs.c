/* pqf_ec_stubs.c -- inert implementations of the OpenSSL provider /
 * OSSL_PARAM key-serialisation surface the vendored EC sources
 * reference but the firmware never invokes.
 *
 * OpenSSL 3.x routes EC key import/export through the provider
 * `keymgmt` interface and the OSSL_PARAM array machinery
 * (ec_backend.c + the OSSL_PARAM / OSSL_PARAM_BLD APIs). The
 * firmware does none of that -- it builds EC_KEYs directly from raw
 * scalars / coordinates (see pqf_p256.c) and signs / verifies /
 * does ECDH with them. But because ec_lib.c / ec_key.c carry the
 * todata / fromdata / dup-via-params code paths, those symbols must
 * resolve at link time even though they're never called.
 *
 * Every function here is a no-op / failure stub. If any is ever
 * actually reached at runtime it returns an error (0 / NULL) rather
 * than silently misbehaving -- a loud failure is the right outcome
 * for a code path we've asserted is dead.
 *
 * This file is project-original; it implements
 * the upstream prototypes from <openssl/params.h>,
 * <openssl/param_build.h>, and <crypto/ec.h> without copying their
 * bodies.
 *
 * Copyright 2026 Cryptsoft Pty Ltd
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "crypto/ec.h"

/* ---- OSSL_PARAM_BLD (param array builder) --------------------- */

OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void)                 { return NULL; }
void            OSSL_PARAM_BLD_free(OSSL_PARAM_BLD *b)   { (void)b; }
OSSL_PARAM     *OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *b){ (void)b; return NULL; }

/* ---- OSSL_PARAM accessors ------------------------------------- */

const OSSL_PARAM *OSSL_PARAM_locate_const(const OSSL_PARAM *p, const char *key)
{ (void)p; (void)key; return NULL; }
int OSSL_PARAM_get_int(const OSSL_PARAM *p, int *val)
{ (void)p; (void)val; return 0; }
int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **val)
{ (void)p; (void)val; return 0; }
int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM *p, const char **val)
{ (void)p; (void)val; return 0; }

/* ---- ec_backend.c provider bridge ----------------------------- */

EC_KEY *ossl_ec_key_dup(const EC_KEY *key, int selection)
{ (void)key; (void)selection; return NULL; }

int ossl_ec_curve_name2nid(const char *name)
{ (void)name; return 0; }
const char *ossl_ec_curve_nid2nist_int(int nid)
{ (void)nid; return NULL; }
int ossl_ec_curve_nist2nid_int(const char *name)
{ (void)name; return 0; }

int ossl_ec_group_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl,
                         OSSL_PARAM params[], OSSL_LIB_CTX *libctx,
                         const char *propq,
                         BN_CTX *bnctx, unsigned char **genbuf)
{
    (void)group; (void)tmpl; (void)params; (void)libctx;
    (void)propq; (void)bnctx; (void)genbuf;
    return 0;
}

int ossl_ec_encoding_param2id(const OSSL_PARAM *p, int *id)
{ (void)p; (void)id; return 0; }
int ossl_ec_pt_format_param2id(const OSSL_PARAM *p, int *id)
{ (void)p; (void)id; return 0; }

/* ---- ASN1_OBJECT_free ----------------------------------------- *
 * Declared in our asn1.h shim. OBJ_nid2obj returns a non-NULL
 * sentinel (never a heap object), so freeing it is a no-op. */
#include <openssl/asn1.h>
void ASN1_OBJECT_free(ASN1_OBJECT *a) { (void)a; }

/* ---- pqf_yield ---------------------------------------------------- *
 * The cooperative yield point ec_mult.c calls per ladder step
 * (pqf_yield.h). Weak no-op default; the single-core firmware defines
 * the real one. ml_dsa/pqf_mldsa.c carries an identical weak default so
 * a link that takes only one of the two directories still resolves. */
#include "pqf_yield.h"
void __attribute__((weak)) pqf_yield(void) { }
