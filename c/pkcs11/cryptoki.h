/* cryptoki.h -- platform bindings for the OASIS PKCS#11 headers.
 *
 * The OASIS headers (vendored verbatim under oasis/) require the
 * including project to define five platform macros before pulling in
 * pkcs11.h -- see the long comment at the top of oasis/pkcs11.h.
 * These are the standard "generic UNIX" definitions from that
 * comment; they are equally correct for Windows builds of a DLL that
 * uses the default C calling convention.
 *
 * Include THIS header, never oasis/pkcs11.h directly.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PQF_CRYPTOKI_H
#define PQF_CRYPTOKI_H

#define CK_PTR *

#define CK_DECLARE_FUNCTION(returnType, name) \
	returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
	returnType (* name)

#ifndef NULL_PTR
#include <stddef.h>   /* NULL */
#define NULL_PTR NULL
#endif

#include "oasis/pkcs11.h"

#endif /* PQF_CRYPTOKI_H */
