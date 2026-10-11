/* smoke.c -- sanity-check program for the pqf-pkcs11 module.
 *
 * dlopens the module the way a Cryptoki application would and
 * exercises everything that works without a token attached: the
 * function list (fully populated, correct version), init/finalize
 * lifecycle, C_GetInfo contents, slot listing (zero slots is fine),
 * argument validation, and the not-supported / not-parallel answers
 * of the faked surface. End-to-end C_GenerateRandom needs a real
 * device -- that's `pkcs11-tool --generate-random`, not this program.
 *
 * Usage: smoke <path-to-module>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <dlfcn.h>

#include "cryptoki.h"

static int fail(const char *msg)
{
	fprintf(stderr, "smoke: FAIL: %s\n", msg);
	return 1;
}

int main(int argc, char **argv)
{
	void *dso;
	CK_C_GetFunctionList getfl;
	CK_FUNCTION_LIST_PTR fl;
	CK_INFO info;
	CK_ULONG count;
	CK_RV rv;

	if (argc != 2) return fail("usage: smoke <module>");

	dso = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (dso == NULL) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return fail("dlopen");
	}
	/* ISO C leaves object-to-function pointer conversion undefined;
	 * POSIX dlsym guarantees it. Silence the pedantic warning with
	 * the classic double cast. */
	*(void **)&getfl = dlsym(dso, "C_GetFunctionList");
	if (getfl == NULL) return fail("dlsym C_GetFunctionList");

	if (getfl(NULL_PTR) != CKR_ARGUMENTS_BAD)
		return fail("C_GetFunctionList(NULL) must be ARGUMENTS_BAD");
	if (getfl(&fl) != CKR_OK || fl == NULL_PTR)
		return fail("C_GetFunctionList");
	printf("  function list: ok (cryptoki %u.%u)\n",
	  (unsigned)fl->version.major, (unsigned)fl->version.minor);
	if (fl->version.major != 2 || fl->version.minor != 40)
		return fail("expected version 2.40");

	/* Every slot in the vector must be populated -- walk it as an
	 * array of pointers past the version header. */
	{
		void **p = (void **)((char *)fl + sizeof(CK_VERSION));
		size_t n = (sizeof(CK_FUNCTION_LIST) - sizeof(CK_VERSION))
		  / sizeof(void *);
		size_t i;
		for (i = 0; i < n; i++)
			if (p[i] == NULL) return fail("NULL function pointer");
		printf("  %u entry points, none NULL: ok\n", (unsigned)n);
	}

	if (fl->C_GetInfo(&info) != CKR_CRYPTOKI_NOT_INITIALIZED)
		return fail("C_GetInfo before init must fail");
	if (fl->C_Initialize(NULL_PTR) != CKR_OK)
		return fail("C_Initialize");
	if (fl->C_Initialize(NULL_PTR) != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return fail("double C_Initialize must fail");
	printf("  init lifecycle: ok\n");

	if (fl->C_GetInfo(&info) != CKR_OK)
		return fail("C_GetInfo");
	printf("  C_GetInfo: '%.32s' / '%.32s'\n",
	  info.manufacturerID, info.libraryDescription);

	rv = fl->C_GetSlotList(CK_TRUE, NULL_PTR, &count);
	if (rv != CKR_OK) return fail("C_GetSlotList");
	printf("  C_GetSlotList: %lu token(s)\n", (unsigned long)count);

	if (fl->C_Login(1, CKU_USER, NULL_PTR, 0)
	  != CKR_FUNCTION_NOT_SUPPORTED)
		return fail("C_Login must be NOT_SUPPORTED");
	if (fl->C_GetFunctionStatus(1) != CKR_FUNCTION_NOT_PARALLEL)
		return fail("C_GetFunctionStatus must be NOT_PARALLEL");
	printf("  faked surface: ok\n");

	if (fl->C_Finalize(NULL_PTR) != CKR_OK)
		return fail("C_Finalize");

	printf("all fixtures pass\n");
	return 0;
}
