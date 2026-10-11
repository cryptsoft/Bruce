/* asn1.h -- ASN.1 type shim.
 *
 * Upstream `openssl/asn1.h` is enormous (the entire ASN.1 template
 * + STACK_OF machinery). The EC code we vendor for ECDSA / ECDH
 * touches exactly ONE ASN.1 symbol: `ASN1_OBJECT` (an opaque curve
 * OID pointer stored in EC_GROUP) and `ASN1_OBJECT_free`. No
 * i2d_/d2i_ serialization is reached on the ECDSA/ECDH paths.
 *
 * This shim provides the opaque type + the free function so the EC
 * sources compile. If a future change actually serialises EC params
 * to ASN.1 (ECPKPARAMETERS), vendor the real asn1.h subset then.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from upstream `include/openssl/asn1.h.in`,
 *   Copyright 1995-2024 The OpenSSL Project Authors.
 *   Licensed under the Apache License 2.0. See `LICENSE-APACHE-OPENSSL`.
 */

#ifndef OPENSSL_ASN1_H
#define OPENSSL_ASN1_H

#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ASN1_OBJECT is opaque to all our EC code -- it only ever holds /
 * frees a pointer. ASN1_OBJECT_free on a NULL is a no-op (matches
 * upstream). The EC group's OID is never populated on the paths we
 * use (we build groups from explicit curve parameters, not from an
 * OID lookup that allocates an ASN1_OBJECT). */
void ASN1_OBJECT_free(ASN1_OBJECT *a);

/* DECLARE_ASN1_* macro family.
 *
 * The vendored `openssl/ec.h` carries `DECLARE_ASN1_ITEM`,
 * `DECLARE_ASN1_ALLOC_FUNCTIONS`, and `DECLARE_ASN1_ENCODE_FUNCTIONS_only`
 * for ECPKPARAMETERS / ECPARAMETERS / ECDSA_SIG. Those expand (in
 * the real asn1.h) to `extern const ASN1_ITEM`, `X_new`/`X_free`,
 * and `i2d_X`/`d2i_X` declarations backed by OpenSSL's ASN.1
 * template engine -- which we deliberately don't vendor.
 *
 * We expand them to nothing. The EC params ASN.1 codec is never
 * exercised on the ECDSA/ECDH path (we construct groups from
 * explicit curve parameters). ECDSA_SIG DER encode/decode -- which
 * FIDO genuinely needs -- is hand-written in `src/pqf_p256.c` from
 * the trivial `SEQUENCE { INTEGER r, INTEGER s }` shape rather than
 * routed through this engine. */
#define DECLARE_ASN1_ITEM(name)
#define DECLARE_ASN1_ALLOC_FUNCTIONS(name)
#define DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name)

/* The ENCODE_FUNCTIONS macros MUST still emit the i2d_/d2i_
 * prototypes -- unlike the ITEM/ALLOC macros, these have real
 * hand-written implementations (see src/ec/pqf_ecdsa_sig.c for
 * ECDSA_SIG). Expanding them to nothing would delete the
 * prototype and break the callers in ecdsa_ossl.c / ecdsa_vrf.c. */
#define DECLARE_ASN1_ENCODE_FUNCTIONS_only(type, name)                  \
    type *d2i_##name(type **a, const unsigned char **in, long len);     \
    int   i2d_##name(const type *a, unsigned char **out);
#define DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)               \
    DECLARE_ASN1_ENCODE_FUNCTIONS_only(type, name)
#define DECLARE_ASN1_FUNCTIONS(name)                                    \
    DECLARE_ASN1_ENCODE_FUNCTIONS_only(name, name)

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_ASN1_H */
