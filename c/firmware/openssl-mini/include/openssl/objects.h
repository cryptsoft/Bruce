/* objects.h -- OBJECT-identifier registry shim.
 *
 * ec_curve.c calls OBJ_nid2obj / OBJ_nid2sn / OBJ_length to attach a
 * curve's OID + short name to the EC_GROUP it builds. None of that
 * metadata is consulted on the ECDSA / ECDH paths -- the group works
 * purely from its explicit field + generator parameters. So the
 * stubs return "no OID" (NULL / empty) and the group is anonymous
 * but fully functional.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from upstream include/openssl/objects.h,
 *   Copyright 1995-2024 The OpenSSL Project Authors. Apache-2.0.
 */
#ifndef OPENSSL_OBJECTS_H
#define OPENSSL_OBJECTS_H
#include <openssl/types.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
/* OBJ_nid2obj MUST return non-NULL: ec_group_new_from_data treats a
 * NULL return as a hard error rather than "this curve has no OID".
 * Return a non-NULL sentinel + OBJ_length()==0, which steers that
 * code into OPENSSL_EC_EXPLICIT_CURVE -- right for our anonymous
 * P-256 group. The sentinel is never dereferenced; ASN1_OBJECT_free
 * (pqf_ec_stubs.c) ignores it. */
#define PQF_OBJ_SENTINEL  ((ASN1_OBJECT *)1)
static inline ASN1_OBJECT *OBJ_nid2obj(int n) { (void)n; return PQF_OBJ_SENTINEL; }
static inline const char  *OBJ_nid2sn (int n) { (void)n; return ""; }
static inline const char  *OBJ_nid2ln (int n) { (void)n; return ""; }
static inline int          OBJ_length (const ASN1_OBJECT *o) { (void)o; return 0; }
static inline int          OBJ_obj2nid(const ASN1_OBJECT *o) { (void)o; return 0; }
static inline int          OBJ_sn2nid (const char *s) { (void)s; return 0; }
#endif
