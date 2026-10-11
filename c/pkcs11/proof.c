/* proof.c -- demonstrate that PKCS#11 entropy really comes from the
 * pico token.
 *
 * Loads the pqf-pkcs11 module with dlopen the way any Cryptoki
 * application would (no link-time dependency on it whatsoever) and
 * builds a chain of evidence:
 *
 *   1. Identity -- C_GetTokenInfo's serial number is the token's USB
 *      iSerialNumber (the firmware randomizes it per boot; compare
 *      against `ioreg -p IOUSB -l` / `lsusb -v` yourself).
 *   2. Liveness -- two back-to-back C_GenerateRandom calls return
 *      different bytes: it's a live generator, not a canned buffer.
 *   3. Quality -- a larger draw has ~8 bits/byte Shannon entropy.
 *   4. Physical dependence (`-i`, interactive) -- unplug the token
 *      mid-run and C_GenerateRandom fails with CKR_DEVICE_REMOVED
 *      while the slot list drops to zero; replug and entropy flows
 *      again. Software RNGs don't do that.
 *
 * Usage:  proof [-i] [path/to/pqf-pkcs11.dylib]
 *
 * Build via `make proof` in this directory.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <dlfcn.h>

#include "cryptoki.h"

#define DRAW_SMALL   32
#define DRAW_BIG     4096

static int fail(const char *what, CK_RV rv)
{
	fprintf(stderr, "proof: FAIL: %s (CKR 0x%02lx)\n",
	  what, (unsigned long)rv);
	return 1;
}

/* Cryptoki strings are space-padded, not NUL-terminated. */
static void print_padded(const char *tag, const CK_UTF8CHAR *s, size_t n)
{
	while (n > 0 && s[n - 1] == ' ') n--;
	printf("  %-14s %.*s\n", tag, (int)n, s);
}

static void print_hex(const char *tag, const unsigned char *b, size_t n)
{
	size_t i;
	printf("  %-14s ", tag);
	for (i = 0; i < n; i++) printf("%02x", b[i]);
	printf("\n");
}

static double shannon(const unsigned char *b, size_t n)
{
	double h = 0.0, p;
	size_t hist[256];
	size_t i;
	memset(hist, 0, sizeof hist);
	for (i = 0; i < n; i++) hist[b[i]]++;
	for (i = 0; i < 256; i++) {
		if (hist[i] == 0) continue;
		p = (double)hist[i] / (double)n;
		h -= p * log(p) / log(2.0);
	}
	return h;
}

static void wait_enter(const char *prompt)
{
	int c;
	printf("\n>>> %s (press Enter) ", prompt);
	fflush(stdout);
	while ((c = getchar()) != '\n' && c != EOF) ;
}

int main(int argc, char **argv)
{
	const char *path = "./pqf-pkcs11.dylib";
	int interactive = 0;
	void *dso;
	CK_C_GetFunctionList getfl;
	CK_FUNCTION_LIST_PTR f;
	CK_SLOT_ID slot;
	CK_ULONG nslots;
	CK_TOKEN_INFO tok;
	CK_SESSION_HANDLE ses;
	unsigned char a[DRAW_SMALL], b[DRAW_SMALL], big[DRAW_BIG];
	CK_RV rv;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-i") == 0) interactive = 1;
		else path = argv[i];
	}

	printf("[1] loading module (as any Cryptoki app would)\n");
	printf("  %-14s %s\n", "module", path);
	dso = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (dso == NULL) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return 1;
	}
	*(void **)&getfl = dlsym(dso, "C_GetFunctionList");
	if (getfl == NULL) return fail("dlsym", 0);
	if ((rv = getfl(&f)) != CKR_OK) return fail("C_GetFunctionList", rv);
	if ((rv = f->C_Initialize(NULL_PTR)) != CKR_OK)
		return fail("C_Initialize", rv);

	printf("\n[2] identity: the slot IS the USB token\n");
	nslots = 1;
	rv = f->C_GetSlotList(CK_TRUE, &slot, &nslots);
	if (rv != CKR_OK || nslots == 0) {
		fprintf(stderr,
		  "proof: no token on the USB bus -- plug it in and rerun.\n"
		  "       (That in itself is half the proof: no token, no"
		  " slot, no entropy.)\n");
		return 1;
	}
	if ((rv = f->C_GetTokenInfo(slot, &tok)) != CKR_OK)
		return fail("C_GetTokenInfo", rv);
	print_padded("label", tok.label, sizeof tok.label);
	print_padded("manufacturer", tok.manufacturerID,
	  sizeof tok.manufacturerID);
	print_padded("serial", tok.serialNumber, sizeof tok.serialNumber);
	printf("  %-14s cross-check: ioreg -p IOUSB -l | grep -B9 SerialNumber\n", "");
	printf("  %-14s (serial is the USB iSerialNumber, randomized per boot)\n", "");

	if ((rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR,
	  NULL_PTR, &ses)) != CKR_OK)
		return fail("C_OpenSession", rv);

	printf("\n[3] liveness: consecutive draws differ\n");
	if ((rv = f->C_GenerateRandom(ses, a, sizeof a)) != CKR_OK)
		return fail("C_GenerateRandom #1", rv);
	if ((rv = f->C_GenerateRandom(ses, b, sizeof b)) != CKR_OK)
		return fail("C_GenerateRandom #2", rv);
	print_hex("draw #1", a, sizeof a);
	print_hex("draw #2", b, sizeof b);
	if (memcmp(a, b, sizeof a) == 0)
		return fail("draws identical -- not a live source", 0);

	printf("\n[4] quality: %u-byte draw\n", (unsigned)DRAW_BIG);
	if ((rv = f->C_GenerateRandom(ses, big, sizeof big)) != CKR_OK)
		return fail("C_GenerateRandom (big)", rv);
	printf("  %-14s %.4f bits/byte (ideal 8, expect >7.9)\n",
	  "entropy", shannon(big, sizeof big));

	if (interactive) {
		printf("\n[5] physical dependence: the entropy dies with"
		  " the cable\n");
		wait_enter("UNPLUG the token now");
		rv = f->C_GenerateRandom(ses, a, sizeof a);
		printf("  %-14s CKR 0x%02lx %s\n", "unplugged draw",
		  (unsigned long)rv,
		  rv == CKR_OK ? "(!!! still worked -- NOT the token?)"
		               : "(refused, as it must be)");
		if (rv == CKR_OK) return fail("entropy survived unplug", 0);
		f->C_CloseSession(ses);
		nslots = 1;
		if (f->C_GetSlotList(CK_TRUE, &slot, &nslots) == CKR_OK)
			printf("  %-14s %lu\n", "slots now",
			  (unsigned long)nslots);

		wait_enter("REPLUG the token");
		nslots = 1;
		rv = f->C_GetSlotList(CK_TRUE, &slot, &nslots);
		if (rv != CKR_OK || nslots == 0)
			return fail("token did not come back", rv);
		if ((rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION,
		  NULL_PTR, NULL_PTR, &ses)) != CKR_OK)
			return fail("re-open session", rv);
		if ((rv = f->C_GenerateRandom(ses, a, sizeof a)) != CKR_OK)
			return fail("draw after replug", rv);
		print_hex("replugged draw", a, sizeof a);
		if ((rv = f->C_GetTokenInfo(slot, &tok)) != CKR_OK)
			return fail("C_GetTokenInfo after replug", rv);
		print_padded("serial now", tok.serialNumber,
		  sizeof tok.serialNumber);
		printf("  %-14s (fresh serial after a reboot = fresh USB"
		  " enumeration)\n", "");
	} else {
		printf("\n[5] (skipped -- rerun with -i for the unplug/replug"
		  " proof)\n");
	}

	f->C_CloseSession(ses);
	f->C_Finalize(NULL_PTR);
	printf("\nPASS: every byte above arrived via C_GenerateRandom from"
	  " the token above.\n");
	return 0;
}
