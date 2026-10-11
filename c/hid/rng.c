/* rng.c -- ask a token which entropy source it is serving from, then pull
 * bytes from its vendor RNG command and time them.
 *
 *   ./rng                # 1024 bytes from the only attached token
 *   ./rng 256            # a different count (1..1024)
 *   ./rng 1024 Tiny      # pick a token by product-string substring
 *
 * The bytes cannot tell you the source -- SHA-256-conditioned QRNG
 * output and on-die TRNG output both pass any test you point at them --
 * so the first thing this does is ASK, with CTAPHID_CMD_RNG_STATUS: the
 * token reports whether a QRNG answered at boot, whether it is still
 * live or has since been written off (cable pulled, chip failed), and
 * how many bytes each source has served with the QRNG's error counters.
 * The transfer time is printed as corroboration: the QRNG path is bound
 * by a 100 kHz I2C bus reading four 18-byte packets per 32 bytes out
 * (~330 ms per KiB), the TRNG answers a KiB in a few milliseconds.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pqhid.h"

static double
now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

int
main(int argc, char **argv)
{
	size_t want = 1024;
	const char *match = NULL;
	pqhid_devinfo_t infos[16];
	size_t n = 0, i, hits = 0;
	const char *path = NULL;
	const char *product = "";
	pqhid_dev_t *dev = NULL;
	pqhid_rng_status_t st;
	int have_status = 0;
	unsigned char buf[PQHID_RNG_MAX_XACT];
	unsigned long ones = 0;
	int seen[256] = {0}, distinct = 0;
	double t0, dt, per_kib;
	int rc;

	if(argc > 1){
		long v = strtol(argv[1], NULL, 10);
		if(v < 1 || v > (long)PQHID_RNG_MAX_XACT){
			fprintf(stderr, "usage: %s [bytes 1..%d] [product-substring]\n",
			  argv[0], PQHID_RNG_MAX_XACT);
			return 2;
		}
		want = (size_t)v;
	}
	if(argc > 2)
		match = argv[2];

	if(pqhid_enumerate(infos, 16, &n) != PQFIDO_OK){
		fprintf(stderr, "enumerate failed\n");
		return 2;
	}
	for(i = 0; i < n; i++){
		if(match != NULL && strstr(infos[i].product, match) == NULL)
			continue;
		if(hits++ == 0){
			path = infos[i].path;
			product = infos[i].product;
		}
	}
	if(hits == 0){
		fprintf(stderr, "no matching token (plugged in and running?)\n");
		return 1;
	}
	if(hits > 1){
		fprintf(stderr, "%zu tokens match; pass a product-substring\n", hits);
		return 1;
	}
	if(pqhid_open(path, &dev) != PQFIDO_OK){
		fprintf(stderr, "open failed\n");
		return 1;
	}

	/* Draw first, then ask: the report then covers this very request,
	 * so an unplug is visible on the run that discovered it. */
	t0 = now_ms();
	rc = pqhid_rng(dev, buf, want);
	dt = now_ms() - t0;
	if(rc != PQFIDO_OK){
		fprintf(stderr, "CMD_RNG failed: rc=%d\n", rc);
		pqhid_close(dev);
		return 1;
	}
	if(pqhid_rng_status(dev, &st) == PQFIDO_OK)
		have_status = 1;
	pqhid_close(dev);

	for(i = 0; i < want; i++){
		unsigned v = buf[i];
		if(!seen[v]){ seen[v] = 1; distinct++; }
		while(v){ ones += v & 1u; v >>= 1; }
	}
	per_kib = dt * 1024.0 / (double)want;

	printf("token:    %s\n", product);
	printf("bytes:    %zu in %.1f ms (%.0f ms per KiB)\n", want, dt, per_kib);
	printf("first:    ");
	for(i = 0; i < 16 && i < want; i++)
		printf("%02x", buf[i]);
	printf("\n");
	printf("sanity:   ones ratio %.4f, %d/256 distinct byte values\n",
	  (double)ones / (double)(want * 8), distinct);

	if(!have_status){
		/* Older firmware without CMD_RNG_STATUS: the clock is all there is. */
		printf("source:   unknown (this firmware has no RNG status command)\n");
		printf("verdict:  %s\n", per_kib > 150.0
		  ? "QRNG-paced (I2C-bound), by timing alone"
		  : "TRNG-paced, by timing alone");
		return 0;
	}

	printf("served:   qrng=%u fallback=%u | pkts=%u hdr=%u hlth=%u bus=%u short=%u\n",
	  st.qrng_bytes, st.fallback_bytes, st.packets, st.header_err,
	  st.health_err, st.bus_err, st.short_requests);
	switch(st.source){
	case PQHID_RNG_SRC_QRNG:
		printf("source:   QRNG -- the external quantum RNG is live and serving\n");
		if(per_kib < 150.0)
			printf("          (but the transfer was TRNG-fast -- worth a look)\n");
		else if(per_kib > 600.0)
			printf("          (slow transfer: the bus is struggling, see the counters)\n");
		break;
	case PQHID_RNG_SRC_QRNG_LOST:
		printf("source:   TRNG -- the QRNG answered at boot but has since been LOST\n"
		       "          (unplugged or failed); reconnect it and reboot the token\n");
		break;
	case PQHID_RNG_SRC_TRNG:
		printf("source:   TRNG -- no QRNG answered at boot\n");
		break;
	case PQHID_RNG_SRC_NO_QRNG:
		printf("source:   TRNG -- this firmware was built without QRNG support\n");
		break;
	default:
		printf("source:   unknown code %u\n", st.source);
		break;
	}
	return 0;
}
