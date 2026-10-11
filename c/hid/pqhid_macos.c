/* pqhid_macos.c
 *
 * macOS backend for the CTAP-HID transport -- the pqhid_os.h contract
 * implemented directly on the IOKit HID Manager (IOHIDManager /
 * IOHIDDevice) and CoreFoundation. All CTAP framing lives in the
 * platform-independent core (pqhid.c); this file only enumerates
 * devices, moves raw 64-byte reports, and sources random bytes.
 *
 * Platform notes (Apple IOKit HID Manager / CoreFoundation docs):
 *
 *   - Discovery: an IOHIDManager with a matching dictionary on the
 *     primary usage page/usage restricts enumeration to devices
 *     advertising the FIDO usage page 0xf1d0, usage 0x0001
 *     (CTAP sec. 8.1.8.2). Reading device properties requires neither
 *     the manager nor the devices to be opened.
 *
 *   - Addressing: a device is named by its IORegistry entry ID,
 *     carried in the pqhid path string as "ioreg:<decimal-id>". The
 *     entry ID is unique for the life of the boot and re-resolvable
 *     via IORegistryEntryIDMatching() for as long as the device
 *     stays attached.
 *
 *   - Input: IOKit delivers input reports by callback from a run
 *     loop, never through a blocking read call. Each handle owns a
 *     small FIFO of received frames; pqhid_os_read() schedules the
 *     device on the *calling* thread's run loop, spins that run
 *     loop until a frame arrives or the deadline passes, then
 *     unschedules again so the handle is never pinned to the thread
 *     that opened it.
 *
 *   - Report IDs: on this platform the report ID travels out-of-band
 *     (a separate IOHIDDeviceSetReport argument / input-callback
 *     parameter), so the bare 64-byte CTAP frame crosses this API
 *     unchanged -- no leading report-ID byte as on the hidraw and
 *     Windows backends (see pqhid_os.h).
 *
 * Copyright (C) 2010-2026 Cryptsoft Pty Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hid/IOHIDDevice.h>
#include <IOKit/hid/IOHIDManager.h>

#include "pqhid.h"
#include "pqhid_os.h"

/* ---- Constants ---------------------------------------------------- */

/* FIDO HID usage page / usage (CTAP sec. 8.1.8.2). */
#define FIDO_USAGE_PAGE 0xf1d0
#define FIDO_USAGE_CTAP 0x0001

/* Received-frame FIFO depth. The core drains frames far faster than
 * a full-speed interrupt endpoint delivers them, so 16 slots only
 * ever fill if the caller stops reading; the oldest frame is then
 * dropped and the transaction fails cleanly in the core instead of
 * wedging the run loop. */
#define PQHID_FIFO_SLOTS 16

/* Run-loop slice while waiting for input, in seconds. */
#define PQHID_RUNLOOP_SLICE 0.05

/* ---- Device handle ------------------------------------------------ */

struct pqhid_os_dev {
	IOHIDDeviceRef  dev;
	/* Buffer registered with the input-report callback; IOKit
	 * writes each incoming report here before invoking the
	 * callback. Must stay valid until the callback is unregistered
	 * in pqhid_os_close(). */
	unsigned char   report[PQHID_OS_FRAME_SIZE];
	/* FIFO of received frames -- fixed slots, no allocation per
	 * report. head is the next slot to pop; pushes land at
	 * (head + count) % PQHID_FIFO_SLOTS. */
	unsigned char   fifo[PQHID_FIFO_SLOTS][PQHID_OS_FRAME_SIZE];
	size_t          head;
	size_t          count;
	/* Set by the removal callback when the device is unplugged. */
	int             removed;
};

/* ---- IOKit callbacks ---------------------------------------------- */

/* Input-report callback (IOHIDReportCallback). Runs on whichever
 * thread's run loop the device is currently scheduled on -- with this
 * backend that is always the thread sitting inside pqhid_os_read(),
 * so no locking is needed around the FIFO. Appends the report,
 * dropping the oldest frame on overflow. */
static void pqhid_input_cb(void *context, IOReturn result, void *sender,
                           IOHIDReportType type, uint32_t reportID,
                           uint8_t *report, CFIndex reportLength)
{
	pqhid_os_dev_t *dev = (pqhid_os_dev_t *)context;
	size_t slot, n;

	(void)sender;
	(void)reportID;   /* report ID is out-of-band and always 0 here */

	if(dev == NULL || result != kIOReturnSuccess)
		return;
	if(type != kIOHIDReportTypeInput)
		return;
	if(report == NULL || reportLength <= 0)
		return;

	if(dev->count == PQHID_FIFO_SLOTS){
		/* Full: drop the oldest frame. */
		dev->head = (dev->head + 1) % PQHID_FIFO_SLOTS;
		dev->count--;
	}
	slot = (dev->head + dev->count) % PQHID_FIFO_SLOTS;
	n = (size_t)reportLength;
	if(n > PQHID_OS_FRAME_SIZE) n = PQHID_OS_FRAME_SIZE;
	memset(dev->fifo[slot], 0, PQHID_OS_FRAME_SIZE);
	memcpy(dev->fifo[slot], report, n);
	dev->count++;
}

/* Removal callback (IOHIDCallback): flags the handle so a read in
 * progress reports PQFIDO_ERR_IO instead of idling to its timeout
 * against a device that no longer exists. */
static void pqhid_removal_cb(void *context, IOReturn result, void *sender)
{
	pqhid_os_dev_t *dev = (pqhid_os_dev_t *)context;

	(void)result;
	(void)sender;
	if(dev != NULL)
		dev->removed = 1;
}

/* ---- Property helpers --------------------------------------------- */

/* Read a numeric IOHIDDevice property. Properties returned by
 * IOHIDDeviceGetProperty follow the CoreFoundation Get rule -- the
 * reference is not owned by the caller and must not be released.
 * Returns 0 when the property is absent or not a number. */
static uint32_t pqhid_prop_u32(IOHIDDeviceRef dev, CFStringRef key)
{
	CFTypeRef ref;
	int32_t v = 0;

	ref = IOHIDDeviceGetProperty(dev, key);
	if(ref != NULL && CFGetTypeID(ref) == CFNumberGetTypeID())
		CFNumberGetValue((CFNumberRef)ref, kCFNumberSInt32Type, &v);
	return (uint32_t)v;
}

/* Read a string IOHIDDevice property as UTF-8 into out (Get rule
 * again -- nothing to release). Writes the empty string when the
 * property is absent, not a string, or does not fit. */
static void pqhid_prop_str(IOHIDDeviceRef dev, CFStringRef key,
                           char *out, size_t outLen)
{
	CFTypeRef ref;

	out[0] = '\0';
	ref = IOHIDDeviceGetProperty(dev, key);
	if(ref != NULL && CFGetTypeID(ref) == CFStringGetTypeID()){
		if(!CFStringGetCString((CFStringRef)ref, out, (CFIndex)outLen,
		    kCFStringEncodingUTF8))
			out[0] = '\0';
	}
}

/* ---- Enumeration --------------------------------------------------- */

/* Build the IOHIDManager matching dictionary selecting the FIDO
 * usage page / usage. The returned dictionary (and the CFNumbers it
 * retains) is owned by the caller -- CFRelease it after handing it
 * to IOHIDManagerSetDeviceMatching, which takes its own retain. */
static CFDictionaryRef pqhid_match_fido(void)
{
	int32_t usagePage = FIDO_USAGE_PAGE;
	int32_t usage = FIDO_USAGE_CTAP;
	CFNumberRef pageNum, usageNum;
	CFDictionaryRef dict;
	const void *keys[2];
	const void *vals[2];

	pageNum  = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type,
	  &usagePage);
	usageNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type,
	  &usage);
	if(pageNum == NULL || usageNum == NULL){
		if(pageNum != NULL) CFRelease(pageNum);
		if(usageNum != NULL) CFRelease(usageNum);
		return NULL;
	}

	keys[0] = CFSTR(kIOHIDPrimaryUsagePageKey);
	keys[1] = CFSTR(kIOHIDPrimaryUsageKey);
	vals[0] = pageNum;
	vals[1] = usageNum;
	dict = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 2,
	  &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

	/* The dictionary retains its values; drop our references. */
	CFRelease(pageNum);
	CFRelease(usageNum);
	return dict;
}

/* Fill one pqhid_devinfo_t from an (unopened) IOHIDDeviceRef.
 * Returns PQFIDO_OK, or an error to make the caller skip the device. */
static int pqhid_fill_devinfo(IOHIDDeviceRef dev, pqhid_devinfo_t *info)
{
	io_service_t svc;
	uint64_t eid = 0;

	/* Path: the device's IORegistry entry ID. Per the note in
	 * Apple's IOHIDDevice.h, IOHIDDeviceGetService returns a
	 * service reference borrowed from the IOHIDDevice (valid only
	 * as long as the device object is) -- the caller must NOT
	 * IOObjectRelease it. */
	svc = IOHIDDeviceGetService(dev);
	if(svc == IO_OBJECT_NULL)
		return PQFIDO_ERR_IO;
	if(IORegistryEntryGetRegistryEntryID(svc, &eid) != KERN_SUCCESS)
		return PQFIDO_ERR_IO;

	memset(info, 0, sizeof *info);
	snprintf(info->path, sizeof info->path, "ioreg:%llu",
	  (unsigned long long)eid);

	info->vendor_id  = (uint16_t)pqhid_prop_u32(dev,
	  CFSTR(kIOHIDVendorIDKey));
	info->product_id = (uint16_t)pqhid_prop_u32(dev,
	  CFSTR(kIOHIDProductIDKey));
	pqhid_prop_str(dev, CFSTR(kIOHIDManufacturerKey),
	  info->manufacturer, sizeof info->manufacturer);
	pqhid_prop_str(dev, CFSTR(kIOHIDProductKey),
	  info->product, sizeof info->product);
	pqhid_prop_str(dev, CFSTR(kIOHIDSerialNumberKey),
	  info->serial, sizeof info->serial);
	return PQFIDO_OK;
}

int pqhid_os_enumerate(pqhid_devinfo_t *infos, size_t cap, size_t *count)
{
	IOHIDManagerRef mgr;
	CFDictionaryRef match;
	CFSetRef devSet;
	const void **refs;
	CFIndex n, i;
	size_t filled;

	*count = 0;

	mgr = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
	if(mgr == NULL)
		return PQFIDO_ERR_IO;

	match = pqhid_match_fido();
	if(match == NULL){
		CFRelease(mgr);
		return PQFIDO_ERR_NOMEM;
	}

	/* The manager retains the dictionary; release our reference.
	 * Property reads below need neither IOHIDManagerOpen nor
	 * IOHIDDeviceOpen. */
	IOHIDManagerSetDeviceMatching(mgr, match);
	CFRelease(match);

	devSet = IOHIDManagerCopyDevices(mgr);
	if(devSet == NULL){
		/* No matching devices attached -- still success. */
		CFRelease(mgr);
		return PQFIDO_OK;
	}

	filled = 0;
	n = CFSetGetCount(devSet);
	if(n > 0){
		refs = (const void **)calloc((size_t)n, sizeof *refs);
		if(refs == NULL){
			CFRelease(devSet);
			CFRelease(mgr);
			return PQFIDO_ERR_NOMEM;
		}
		CFSetGetValues(devSet, refs);
		for(i = 0; i < n && filled < cap; i++){
			/* Devices that cannot be probed are skipped. */
			if(pqhid_fill_devinfo((IOHIDDeviceRef)refs[i],
			    &infos[filled]) == PQFIDO_OK)
				filled++;
		}
		free(refs);
	}

	/* The copied set holds the only references we own to the
	 * device objects; releasing it releases them too. */
	CFRelease(devSet);
	CFRelease(mgr);

	*count = filled;
	return PQFIDO_OK;
}

/* ---- Open / close -------------------------------------------------- */

int pqhid_os_open(const char *path, pqhid_os_dev_t **out)
{
	pqhid_os_dev_t *h;
	unsigned long long eid;
	char *end;
	CFMutableDictionaryRef match;
	io_service_t svc;
	IOHIDDeviceRef dev;

	if(path == NULL || out == NULL) return PQFIDO_ERR_INVAL;
	*out = NULL;

	if(strncmp(path, "ioreg:", 6) != 0) return PQFIDO_ERR_INVAL;
	/* Base 0: accepts the decimal form pqhid_os_enumerate emits and
	 * a 0x-prefixed hex spelling of the same entry ID. */
	eid = strtoull(path + 6, &end, 0);
	if(end == path + 6 || *end != '\0') return PQFIDO_ERR_INVAL;

	match = IORegistryEntryIDMatching((uint64_t)eid);
	if(match == NULL) return PQFIDO_ERR_NOMEM;

	/* Master port 0 is accepted by every SDK generation as "the
	 * default port" -- it sidesteps the kIOMainPortDefault (macOS 12+)
	 * vs kIOMasterPortDefault (older SDKs) naming split. Note that
	 * IOServiceGetMatchingService CONSUMES one reference to the
	 * matching dictionary, so it is not released here. */
	svc = IOServiceGetMatchingService(0, match);
	if(svc == IO_OBJECT_NULL)
		return PQFIDO_ERR_IO;   /* stale path: device unplugged */

	dev = IOHIDDeviceCreate(kCFAllocatorDefault, svc);
	IOObjectRelease(svc);   /* this reference IS ours to release */
	if(dev == NULL)
		return PQFIDO_ERR_IO;

	/* Shared open -- kIOHIDOptionsTypeNone, not the seizing kind. */
	if(IOHIDDeviceOpen(dev, kIOHIDOptionsTypeNone) != kIOReturnSuccess){
		CFRelease(dev);
		return PQFIDO_ERR_IO;
	}

	h = (pqhid_os_dev_t *)calloc(1, sizeof(*h));
	if(h == NULL){
		IOHIDDeviceClose(dev, kIOHIDOptionsTypeNone);
		CFRelease(dev);
		return PQFIDO_ERR_NOMEM;
	}
	h->dev = dev;

	/* The callbacks only fire while the device is scheduled on a
	 * run loop, which pqhid_os_read() does per call. */
	IOHIDDeviceRegisterInputReportCallback(dev, h->report,
	  (CFIndex)sizeof h->report, pqhid_input_cb, h);
	IOHIDDeviceRegisterRemovalCallback(dev, pqhid_removal_cb, h);

	*out = h;
	return PQFIDO_OK;
}

void pqhid_os_close(pqhid_os_dev_t *dev)
{
	if(dev == NULL) return;

	/* Unregister callbacks (NULL callback removes the registration)
	 * before tearing the device down. */
	IOHIDDeviceRegisterInputReportCallback(dev->dev, dev->report,
	  (CFIndex)sizeof dev->report, NULL, NULL);
	IOHIDDeviceRegisterRemovalCallback(dev->dev, NULL, NULL);
	IOHIDDeviceClose(dev->dev, kIOHIDOptionsTypeNone);
	CFRelease(dev->dev);
	free(dev);
}

/* ---- Report I/O ----------------------------------------------------- */

int pqhid_os_write(pqhid_os_dev_t *dev,
  const unsigned char frame[PQHID_OS_FRAME_SIZE])
{
	IOReturn r;

	if(dev == NULL || frame == NULL) return PQFIDO_ERR_INVAL;

	/* Report ID 0 travels out-of-band on this platform (the CFIndex
	 * argument), so the 64-byte frame is sent bare. */
	r = IOHIDDeviceSetReport(dev->dev, kIOHIDReportTypeOutput, 0,
	  frame, PQHID_OS_FRAME_SIZE);
	return (r == kIOReturnSuccess) ? PQFIDO_OK : PQFIDO_ERR_IO;
}

int pqhid_os_read(pqhid_os_dev_t *dev,
  unsigned char frame[PQHID_OS_FRAME_SIZE], int timeoutMs)
{
	CFAbsoluteTime deadline;
	int rc;

	if(dev == NULL || frame == NULL) return PQFIDO_ERR_INVAL;

	/* Schedule on the CURRENT thread's run loop for the duration of
	 * this call only, so the handle may be used from any thread --
	 * not just the one that opened it. */
	IOHIDDeviceScheduleWithRunLoop(dev->dev, CFRunLoopGetCurrent(),
	  kCFRunLoopDefaultMode);

	/* Negative timeoutMs = wait indefinitely, matching the Linux
	 * (poll(-1)) and Windows (INFINITE) backends. */
	deadline = CFAbsoluteTimeGetCurrent()
	  + (CFAbsoluteTime)timeoutMs / 1000.0;
	for(;;){
		if(dev->count > 0){
			memcpy(frame, dev->fifo[dev->head],
			  PQHID_OS_FRAME_SIZE);
			dev->head = (dev->head + 1) % PQHID_FIFO_SLOTS;
			dev->count--;
			rc = PQFIDO_OK;
			break;
		}
		if(dev->removed){
			rc = PQFIDO_ERR_IO;
			break;
		}
		if(timeoutMs >= 0
		  && CFAbsoluteTimeGetCurrent() >= deadline){
			rc = PQFIDO_ERR_TIMEOUT;
			break;
		}
		/* Spin the run loop so IOKit can deliver report and
		 * removal callbacks; returns early on activity. */
		(void)CFRunLoopRunInMode(kCFRunLoopDefaultMode,
		  PQHID_RUNLOOP_SLICE, true);
	}

	IOHIDDeviceUnscheduleFromRunLoop(dev->dev, CFRunLoopGetCurrent(),
	  kCFRunLoopDefaultMode);
	return rc;
}

/* ---- CSPRNG --------------------------------------------------------- */

int pqhid_os_random(unsigned char *buf, size_t len)
{
	if(buf == NULL && len > 0) return PQFIDO_ERR_INVAL;

	/* arc4random_buf(3) never fails and never blocks; it is seeded
	 * by the kernel entropy source. */
	arc4random_buf(buf, len);
	return PQFIDO_OK;
}
