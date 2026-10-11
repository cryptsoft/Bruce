/* smoke.c -- sanity-check program for the pqhid transport.
 *
 * Exercises the entry points that don't require a live device:
 * version reporting and NULL-argument rejection. End-to-end
 * INIT / PING / WINK / CBOR / MSG tests need a real authenticator,
 * so they live outside this smoke step (see reboot.c and rng.c).
 *
 * Build via `make smoke` or `make test` in this directory.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "pqhid.h"

static int
fail(const char *msg)
{
	fprintf(stderr, "smoke: FAIL: %s\n", msg);
	return 1;
}

int
main(void)
{
	printf("pqhid version: %s\n", pqhid_version());

	/* Fixture 1: version string is the compile-time macro. */
	if(strcmp(pqhid_version(), PQHID_VERSION_STRING) != 0)
		return fail("version string mismatch");
	printf("  version string: ok\n");

	/* Fixture 2: pqhid_open() rejects NULL path / NULL out. */
	{
		pqhid_dev_t *dev = NULL;
		if(pqhid_open(NULL, &dev) != PQFIDO_ERR_INVAL)
			return fail("open NULL path");
		if(pqhid_open("/dev/null", NULL) != PQFIDO_ERR_INVAL)
			return fail("open NULL out");
		printf("  open NULL args: ok\n");
	}

	/* Fixture 3: pqhid_close(NULL) is safe (no segfault, no return value). */
	pqhid_close(NULL);
	printf("  close NULL: ok\n");

	/* Fixture 3b: pqhid_enumerate() argument checking. A zero-capacity
	 * array is success-with-zero-devices by contract, and never
	 * reaches the OS backend. */
	{
		pqhid_devinfo_t infos[2];
		size_t n = 99;

		if(pqhid_enumerate(NULL, 2, &n) != PQFIDO_ERR_INVAL)
			return fail("enumerate NULL infos");
		if(pqhid_enumerate(infos, 2, NULL) != PQFIDO_ERR_INVAL)
			return fail("enumerate NULL count");
		if(pqhid_enumerate(infos, 0, &n) != PQFIDO_OK || n != 0)
			return fail("enumerate zero cap");
		printf("  enumerate args: ok\n");
	}

	/* Fixture 4: pqhid_get_info() rejects NULL args. */
	{
		pqhid_info_t info;
		if(pqhid_get_info(NULL, &info) != PQFIDO_ERR_INVAL)
			return fail("get_info NULL dev");
		if(pqhid_get_info((const pqhid_dev_t *)0x1, NULL)
		    != PQFIDO_ERR_INVAL)
			return fail("get_info NULL out");
		printf("  get_info NULL args: ok\n");
	}

	/* Fixture 5: command entry points reject NULL dev / NULL buffers. */
	{
		unsigned char buf[8] = {0};
		size_t n = 0;

		if(pqhid_ping(NULL, buf, sizeof buf) != PQFIDO_ERR_INVAL)
			return fail("ping NULL dev");
		if(pqhid_ping((pqhid_dev_t *)0x1, NULL, 0) != PQFIDO_ERR_INVAL)
			return fail("ping NULL data");

		if(pqhid_wink(NULL) != PQFIDO_ERR_INVAL)
			return fail("wink NULL dev");

		if(pqhid_cbor(NULL, buf, sizeof buf, buf, sizeof buf, &n)
		    != PQFIDO_ERR_INVAL)
			return fail("cbor NULL dev");
		if(pqhid_cbor((pqhid_dev_t *)0x1, NULL, 0, buf, sizeof buf, &n)
		    != PQFIDO_ERR_INVAL)
			return fail("cbor NULL data");
		if(pqhid_cbor((pqhid_dev_t *)0x1, buf, sizeof buf, NULL,
		    sizeof buf, &n) != PQFIDO_ERR_INVAL)
			return fail("cbor NULL resp");
		if(pqhid_cbor((pqhid_dev_t *)0x1, buf, sizeof buf, buf,
		    sizeof buf, NULL) != PQFIDO_ERR_INVAL)
			return fail("cbor NULL respLen");

		if(pqhid_msg(NULL, buf, sizeof buf, buf, sizeof buf, &n)
		    != PQFIDO_ERR_INVAL)
			return fail("msg NULL dev");
		if(pqhid_msg((pqhid_dev_t *)0x1, NULL, 0, buf, sizeof buf, &n)
		    != PQFIDO_ERR_INVAL)
			return fail("msg NULL apdu");

		printf("  command NULL args: ok\n");
	}

	/* Fixture 5b: pqhid_reboot() rejects NULL dev and out-of-range
	 * mode bytes (only WARM / BOOTSEL are valid). */
	{
		if(pqhid_reboot(NULL, PQHID_REBOOT_BOOTSEL) != PQFIDO_ERR_INVAL)
			return fail("reboot NULL dev");
		if(pqhid_reboot((pqhid_dev_t *)0x1, 99) != PQFIDO_ERR_INVAL)
			return fail("reboot bad mode");
		printf("  reboot arg validation: ok\n");
	}

	/* Fixture 6: capability flags match the wire constants. */
	if(PQHID_CAP_WINK != 0x01 || PQHID_CAP_CBOR != 0x04
	    || PQHID_CAP_NMSG != 0x08)
		return fail("capability flag values");
	printf("  capability flags: ok\n");

	printf("all fixtures pass\n");
	return 0;
}
