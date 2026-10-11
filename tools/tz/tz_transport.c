/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* Multi-frame transport check for the TrustZone NS image (M4a). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pqhid.h"

int main(void)
{
	pqhid_devinfo_t infos[16];
	size_t n = 0, i;
	pqhid_dev_t *dev = NULL;
	const char *path = NULL;
	static const size_t sizes[] = {1, 32, 57, 58, 64, 116, 117, 200, 500, 1000, 2048};
	int fails = 0;

	if (pqhid_enumerate(infos, 16, &n) != 0) { puts("enumerate failed"); return 1; }
	for (i = 0; i < n; i++)
		if (strstr(infos[i].product, "TZ-NS")) path = infos[i].path;
	if (!path) { puts("no TZ-NS device"); return 1; }
	if (pqhid_open(path, &dev) != 0) { puts("open failed"); return 1; }

	for (i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
		size_t len = sizes[i];
		unsigned char *buf = malloc(len);
		size_t j;
		int rc;
		for (j = 0; j < len; j++) buf[j] = (unsigned char)(j * 31 + 7);
		rc = pqhid_ping(dev, buf, len);
		printf("  ping %4zu bytes: %s\n", len, rc == 0 ? "ok" : "FAIL");
		if (rc != 0) fails++;
		free(buf);
	}
	{
		unsigned char req[1] = {0x04}; /* authenticatorGetInfo */
		unsigned char resp[512];
		size_t rlen = 0;
		int rc = pqhid_cbor(dev, req, 1, resp, sizeof(resp), &rlen);
		printf("  getInfo: %s (%zu bytes, status 0x%02x)\n",
		       rc == 0 ? "ok" : "FAIL", rlen, rlen ? resp[0] : 0xff);
		if (rc != 0 || rlen == 0 || resp[0] != 0x00) fails++;
	}

	pqhid_close(dev);
	printf("  %s\n", fails ? "MULTI-FRAME FAILURES" : "all sizes echoed verbatim");
	return fails ? 1 : 0;
}
