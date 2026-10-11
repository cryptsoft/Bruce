/* Copyright 2026 Cryptsoft Pty Ltd
 * SPDX-License-Identifier: Apache-2.0 */

/* reboot.c -- CLI to reboot a Bruce token via the vendor command
 * CTAPHID_CMD_REBOOT (0x51). Sibling of smoke.c; links libpqhid.
 *
 *   make reboot
 *   ./reboot --list              # list the Bruce tokens found; sends nothing
 *   ./reboot                     # into BOOTSEL (USB mass storage / DFU)
 *   ./reboot bootsel
 *   ./reboot warm                # warm reboot back into the firmware
 *   ./reboot bootsel Bruce    # pick a token by product-string substring
 *   ./reboot warm  Tiny          # (needed when several tokens are attached)
 *
 * --list (or -l) only enumerates. It prints one line per Bruce token,
 *
 *   found: <product> (vid=xxxx pid=xxxx) path=<platform path, or n/a>
 *
 * and exits 0; with none it prints "no Bruce token found" and exits 1.
 * It never opens a device, let alone sends anything, so a script can
 * poll it to learn whether a token is present -- tools/flash-usbc.sh
 * does, before and after every reboot it asks for.
 *
 * IMPORTANT -- user presence. On a build whose board enforces a test of
 * user presence (Feitian BOOTSEL button; Tiny 2350 GP0 capacitive pad),
 * you must physically PRESS/TOUCH the token within ~10 s of running
 * this, or the reboot is declined. Buttonless / PQF_TEST_NO_USER_BUTTON
 * builds reboot immediately with no gesture.
 *
 * The token disappears from the bus on success, so this is
 * fire-and-forget: it sends the request and exits. Confirm by polling
 * for the device to re-appear (as an RP-series BOOTSEL mass-storage
 * device, e.g. `picotool info`, or as the FIDO device again after a
 * warm reboot).
 */
#include <stdio.h>
#include <string.h>
#include "pqhid.h"

/* A Bruce token: the FIDO product id 0xF1D0 -- or 0xF1DC, the
 * TrustZone Non-secure image, which takes a distinct pid so it cannot
 * be mistaken for production firmware -- and either the Bruce
 * manufacturer string or the placeholder vendor id 0xcafe both
 * firmware ports use. */
static int is_pqf(const pqhid_devinfo_t *d)
{
	return (d->product_id == 0xF1D0 || d->product_id == 0xF1DC)
	    && (strstr(d->manufacturer, "Bruce") != NULL
	        || d->vendor_id == 0xcafe);
}

int main(int argc, char **argv)
{
	int mode = PQHID_REBOOT_BOOTSEL;
	const char *label = "BOOTSEL (USB mass storage / DFU)";
	const char *match = NULL;
	size_t n = 0;
	size_t i;
	size_t hits = 0;
	const char *path = NULL;
	pqhid_devinfo_t infos[16];
	pqhid_dev_t *dev = NULL;
	int rc;
	int list = 0;

	if(argc > 1){
		if(strcmp(argv[1], "--list") == 0 || strcmp(argv[1], "-l") == 0){
			list = 1;
		} else if(strcmp(argv[1], "warm") == 0){
			mode = PQHID_REBOOT_WARM;
			label = "warm (back into firmware)";
		} else if(strcmp(argv[1], "bootsel") == 0){
			mode = PQHID_REBOOT_BOOTSEL;
		} else {
			fprintf(stderr,
			  "usage: %s [bootsel|warm] [product-substring]\n"
			  "       %s --list | -l\n", argv[0], argv[0]);
			return 2;
		}
	}
	if(argc > 2){
		if(list){
			fprintf(stderr, "usage: %s --list | -l   (takes no other "
			  "argument)\n", argv[0]);
			return 2;
		}
		match = argv[2];
	}

	if(pqhid_enumerate(infos, 16, &n) != PQFIDO_OK){
		fprintf(stderr, "enumerate failed\n");
		return 2;
	}

	/* --list: report every Bruce token and stop. Nothing is opened,
	 * so nothing can be sent; the exit code says whether one is here. */
	if(list){
		for(i = 0; i < n; i++){
			if(!is_pqf(&infos[i]))
				continue;
			printf("found: %s (vid=%04x pid=%04x) path=%s\n",
			  infos[i].product, infos[i].vendor_id, infos[i].product_id,
			  infos[i].path[0] != '\0' ? infos[i].path : "n/a");
			hits++;
		}
		if(hits == 0){
			printf("no Bruce token found\n");
			return 1;
		}
		return 0;
	}

	/* Select the target token. With several attached (a flash station),
	 * pass a product-substring to disambiguate; refuse to guess. */
	for(i = 0; i < n; i++){
		if(!is_pqf(&infos[i]))
			continue;
		if(match != NULL && strstr(infos[i].product, match) == NULL)
			continue;
		printf("candidate: %s (vid=%04x pid=%04x)\n",
		  infos[i].product, infos[i].vendor_id, infos[i].product_id);
		path = infos[i].path;
		hits++;
	}
	if(hits == 0){
		fprintf(stderr, "no matching Bruce token found "
		  "(plugged in and in application mode?)\n");
		return 2;
	}
	if(hits > 1){
		fprintf(stderr, "%zu tokens match -- pass a product-substring "
		  "to pick one\n", hits);
		return 2;
	}

	if(pqhid_open(path, &dev) != PQFIDO_OK){
		fprintf(stderr, "open failed\n");
		return 2;
	}

	printf("sending CMD_REBOOT: %s\n", label);
	rc = pqhid_reboot(dev, mode);
	pqhid_close(dev);
	if(rc != PQFIDO_OK){
		fprintf(stderr, "pqhid_reboot failed (rc=%d)\n", rc);
		return 1;
	}

	printf("sent. If this build enforces user presence, PRESS/TOUCH the "
	  "token NOW (within ~10s); otherwise it reboots immediately.\n");
	return 0;
}
