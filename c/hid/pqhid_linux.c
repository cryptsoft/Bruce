/* pqhid_linux.c
 *
 * Linux backend for the CTAP-over-USB-HID transport: /dev/hidraw
 * character devices plus poll() for read timeouts. Implements the
 * pqhid_os.h contract consumed by the platform-independent core
 * (pqhid.c).
 *
 * Written against:
 *   - the Linux kernel hidraw interface (Documentation/hid/hidraw.rst
 *     and the <linux/hidraw.h> uapi header): per-device /dev/hidrawN
 *     nodes, read()/write() of whole reports, and the HIDIOCG* ioctls
 *     for device info, the report descriptor and the name string;
 *   - USB Device Class Definition for HID 1.11 sec. 6.2.2: report
 *     descriptor item format, used to spot the FIDO usage page;
 *   - FIDO CTAP sec. 8.1.8.2: an authenticator's HID interface sits on
 *     usage page 0xf1d0 with usage 0x0001.
 *
 * Report-ID plumbing (Documentation/hid/hidraw.rst): on write() the
 * first byte is the report ID and the report follows; FIDO devices
 * use unnumbered reports, so every write is 65 bytes with a leading
 * 0x00. On read() the ID byte is omitted for devices without numbered
 * reports, so a whole report is the bare 64-byte frame.
 *
 * Copyright (C) 2010-2026 Cryptsoft Pty Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* poll(2), clock_gettime(2), getrandom(2), the dirent API and the
 * hidraw ioctls all sit outside plain ISO C; ask the libc for its
 * default (POSIX.1-2008 plus common Unix) namespace before any
 * header is pulled in. */
#define _DEFAULT_SOURCE 1

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include <linux/hid.h>
#include <linux/hidraw.h>

/* getrandom(3) arrived in glibc 2.25; older toolchains simply take
 * the /dev/urandom path in pqhid_os_random(). */
#if defined(__has_include)
# if __has_include(<sys/random.h>)
#  include <sys/random.h>
#  define PQHID_HAVE_GETRANDOM 1
# endif
#endif

#include "pqhid.h"
#include "pqhid_os.h"

/* ---- Device handle ---------------------------------------------- */

struct pqhid_os_dev {
	int fd;                       /* open /dev/hidrawN descriptor */
};

/* ---- Report descriptor scan -------------------------------------- */

/* Short-item fields (HID 1.11 sec. 6.2.2.2): the prefix byte carries
 * bTag[7:4] bType[3:2] bSize[1:0], where a bSize of 3 means four data
 * bytes. A prefix of 0xfe is a long item (sec. 6.2.2.3): one data-size
 * byte and one tag byte follow, then that many data bytes. */
#define PQHID_ITEM_LONG             0xfe

#define PQHID_ITEM_TYPE_MAIN        0
#define PQHID_ITEM_TYPE_GLOBAL      1
#define PQHID_ITEM_TYPE_LOCAL       2

#define PQHID_TAG_MAIN_COLLECTION   0x0a  /* Main:   Collection */
#define PQHID_TAG_GLOBAL_USAGE_PAGE 0x00  /* Global: Usage Page */
#define PQHID_TAG_LOCAL_USAGE       0x00  /* Local:  Usage      */

#define PQHID_FIDO_USAGE_PAGE       0xf1d0u  /* CTAP sec. 8.1.8.2 */
#define PQHID_FIDO_USAGE_CTAP       0x0001u

/* Walk a HID report descriptor and decide whether its first
 * Collection is the FIDO one (usage page 0xf1d0, usage 0x0001 --
 * CTAP sec. 8.1.8.2).
 *
 * Item scan per HID 1.11 sec. 6.2.2: track the current Global 'Usage
 * Page' and the most recent Local 'Usage'; both are in force when a
 * Main item is reached. A four-byte Usage is an "extended" usage
 * carrying its own page in the high 16 bits (sec. 6.2.2.8), overriding
 * the global page. Item data is little-endian and unsigned for these
 * items. The first Collection settles the question either way, so
 * parsing stops there.
 *
 * Returns 1 for a FIDO descriptor, 0 for anything else (including a
 * truncated or malformed descriptor). */
static int pqhid_desc_is_fido(const unsigned char *desc, size_t descLen)
{
	size_t i = 0;
	size_t dSize;
	size_t k;
	unsigned char prefix;
	unsigned char bTag;
	unsigned char bType;
	uint32_t data;
	uint32_t usagePage = 0;
	uint32_t usage = 0;
	size_t usageSize = 0;
	int haveUsage = 0;
	uint32_t page;

	while(i < descLen){
		prefix = desc[i];

		if(prefix == PQHID_ITEM_LONG){
			/* [0xfe][bDataSize][bLongItemTag][data...] --
			 * HID 1.11 defines no long items; skip whole. */
			if(descLen - i < 3) return 0;
			dSize = desc[i + 1];
			i += 3;
			if(dSize > descLen - i) return 0;
			i += dSize;
			continue;
		}

		bTag  = (unsigned char)(prefix >> 4);
		bType = (unsigned char)((prefix >> 2) & 0x03);
		dSize = prefix & 0x03;
		if(dSize == 3) dSize = 4;
		i++;
		if(dSize > descLen - i) return 0;

		data = 0;
		for(k = 0; k < dSize; k++)
			data |= (uint32_t)desc[i + k] << (8 * k);
		i += dSize;

		switch(bType){
		case PQHID_ITEM_TYPE_MAIN:
			if(bTag == PQHID_TAG_MAIN_COLLECTION){
				if(!haveUsage) return 0;
				page = (usageSize == 4)
				  ? (usage >> 16) : usagePage;
				return page == PQHID_FIDO_USAGE_PAGE
				  && (usage & 0xffffu) == PQHID_FIDO_USAGE_CTAP;
			}
			/* Any other Main item consumes the Local state
			 * (HID 1.11 sec. 6.2.2.8). */
			usage = 0;
			usageSize = 0;
			haveUsage = 0;
			break;
		case PQHID_ITEM_TYPE_GLOBAL:
			if(bTag == PQHID_TAG_GLOBAL_USAGE_PAGE)
				usagePage = data;
			break;
		case PQHID_ITEM_TYPE_LOCAL:
			if(bTag == PQHID_TAG_LOCAL_USAGE){
				usage = data;
				usageSize = dSize;
				haveUsage = 1;
			}
			break;
		default:                  /* reserved type -- ignore */
			break;
		}
	}

	return 0;                         /* no Collection at all */
}

/* Probe one open hidraw node: query VID/PID and the report
 * descriptor, and if the descriptor is FIDO fill `info`. `path` is
 * the "/dev/hidrawN" string the node was opened by (NUL-terminated,
 * caller guarantees it fits info->path). Returns 1 when `info` was
 * filled, 0 to skip the device (not FIDO, or the kernel refused one
 * of the queries). */
static int pqhid_probe(int fd, const char *path, pqhid_devinfo_t *info)
{
	struct hidraw_devinfo di;
	struct hidraw_report_descriptor rd;
	int descSize = 0;
	int n;

	if(ioctl(fd, HIDIOCGRAWINFO, &di) < 0)
		return 0;
	if(ioctl(fd, HIDIOCGRDESCSIZE, &descSize) < 0)
		return 0;
	if(descSize <= 0 || (size_t)descSize > sizeof rd.value)
		return 0;
	rd.size = (uint32_t)descSize;
	if(ioctl(fd, HIDIOCGRDESC, &rd) < 0)
		return 0;
	if(!pqhid_desc_is_fido(rd.value, rd.size))
		return 0;

	memset(info, 0, sizeof *info);
	memcpy(info->path, path, strlen(path) + 1);
	info->vendor_id  = (uint16_t)di.vendor;
	info->product_id = (uint16_t)di.product;

	/* hidraw exposes a single combined name string; report it as
	 * the product and leave manufacturer/serial empty (the memset
	 * above). HIDIOCGRAWNAME returns the number of bytes copied,
	 * which includes the NUL only when the whole string fit. */
	n = ioctl(fd, HIDIOCGRAWNAME(sizeof info->product - 1),
	  info->product);
	if(n < 0)
		n = 0;
	if((size_t)n > sizeof info->product - 1)
		n = (int)(sizeof info->product - 1);
	info->product[n] = '\0';

	return 1;
}

/* ---- Deadline helper --------------------------------------------- */

/* Monotonic milliseconds. Used to hold the read deadline steady when
 * poll() is interrupted by a signal -- restarting the wait must not
 * extend it. */
static int64_t pqhid_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- pqhid_os contract ------------------------------------------- */

int pqhid_os_enumerate(pqhid_devinfo_t *infos, size_t cap, size_t *count)
{
	DIR *dir;
	struct dirent *ent;
	char path[PQHID_MAX_PATH];
	size_t nameLen;
	size_t found = 0;
	int fd;

	if(infos == NULL || count == NULL) return PQFIDO_ERR_INVAL;
	*count = 0;

	dir = opendir("/dev");
	if(dir == NULL) return PQFIDO_ERR_IO;

	while(found < cap && (ent = readdir(dir)) != NULL){
		if(strncmp(ent->d_name, "hidraw", 6) != 0)
			continue;
		nameLen = strlen(ent->d_name);
		if(nameLen + 6 > sizeof path)  /* "/dev/" + name + NUL */
			continue;
		memcpy(path, "/dev/", 5);
		memcpy(path + 5, ent->d_name, nameLen + 1);

		/* Skipping silently on open failure is the contract:
		 * enumeration reports what this process can use. */
		fd = open(path, O_RDWR);
		if(fd < 0)
			continue;
		if(pqhid_probe(fd, path, &infos[found]))
			found++;
		close(fd);
	}

	closedir(dir);
	*count = found;
	return PQFIDO_OK;
}

int pqhid_os_open(const char *path, pqhid_os_dev_t **out)
{
	pqhid_os_dev_t *dev;
	int fd;

	if(path == NULL || out == NULL) return PQFIDO_ERR_INVAL;
	*out = NULL;

	do {
		fd = open(path, O_RDWR);
	} while(fd < 0 && errno == EINTR);
	if(fd < 0)
		return PQFIDO_ERR_IO;

	dev = (pqhid_os_dev_t *)calloc(1, sizeof(*dev));
	if(dev == NULL){ close(fd); return PQFIDO_ERR_NOMEM; }
	dev->fd = fd;

	*out = dev;
	return PQFIDO_OK;
}

void pqhid_os_close(pqhid_os_dev_t *dev)
{
	if(dev == NULL) return;
	close(dev->fd);
	free(dev);
}

int pqhid_os_write(pqhid_os_dev_t *dev,
  const unsigned char frame[PQHID_OS_FRAME_SIZE])
{
	unsigned char buf[PQHID_OS_FRAME_SIZE + 1];
	ssize_t n;

	if(dev == NULL || frame == NULL) return PQFIDO_ERR_INVAL;

	/* hidraw write format: report ID first, then the report. FIDO
	 * devices use unnumbered reports, so the ID byte is 0x00. */
	buf[0] = 0x00;
	memcpy(buf + 1, frame, PQHID_OS_FRAME_SIZE);

	for(;;){
		n = write(dev->fd, buf, sizeof buf);
		if(n == (ssize_t)sizeof buf)
			return PQFIDO_OK;
		if(n < 0 && errno == EINTR)
			continue;
		return PQFIDO_ERR_IO;
	}
}

int pqhid_os_read(pqhid_os_dev_t *dev,
  unsigned char frame[PQHID_OS_FRAME_SIZE], int timeoutMs)
{
	struct pollfd pfd;
	int64_t deadline;
	int64_t remain;
	ssize_t n;
	int rc;

	if(dev == NULL || frame == NULL) return PQFIDO_ERR_INVAL;

	pfd.fd = dev->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	deadline = pqhid_now_ms() + timeoutMs;

	for(;;){
		if(timeoutMs < 0){
			remain = -1;  /* poll(2): negative = no timeout */
		} else {
			remain = deadline - pqhid_now_ms();
			if(remain < 0) remain = 0;
		}
		rc = poll(&pfd, 1, (int)remain);
		if(rc == 0)
			return PQFIDO_ERR_TIMEOUT;
		if(rc < 0){
			if(errno == EINTR)
				continue;         /* deadline unmoved */
			return PQFIDO_ERR_IO;
		}
		if(pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			return PQFIDO_ERR_IO;     /* device went away */
		break;
	}

	for(;;){
		/* Devices without numbered reports -- all FIDO
		 * authenticators -- deliver the bare 64-byte frame;
		 * hidraw omits the report-ID byte on read. */
		n = read(dev->fd, frame, PQHID_OS_FRAME_SIZE);
		if(n == PQHID_OS_FRAME_SIZE)
			return PQFIDO_OK;
		if(n < 0 && errno == EINTR)
			continue;
		return PQFIDO_ERR_IO;
	}
}

int pqhid_os_random(unsigned char *buf, size_t len)
{
	size_t got;
	ssize_t n;
	int fd;

	if(buf == NULL && len > 0) return PQFIDO_ERR_INVAL;

#ifdef PQHID_HAVE_GETRANDOM
	got = 0;
	while(got < len){
		n = getrandom(buf + got, len - got, 0);
		if(n < 0){
			if(errno == EINTR)
				continue;
			break;  /* e.g. ENOSYS pre-3.17 kernel -- fall
			         * back to /dev/urandom below */
		}
		got += (size_t)n;
	}
	if(got == len)
		return PQFIDO_OK;
#endif

	/* No silent degradation past this point: if /dev/urandom is
	 * unusable too, the caller gets PQFIDO_ERR_IO, never a weak
	 * nonce. */
	fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0)
		return PQFIDO_ERR_IO;
	got = 0;
	while(got < len){
		n = read(fd, buf + got, len - got);
		if(n > 0){ got += (size_t)n; continue; }
		if(n < 0 && errno == EINTR)
			continue;
		break;
	}
	close(fd);
	return (got == len) ? PQFIDO_OK : PQFIDO_ERR_IO;
}
