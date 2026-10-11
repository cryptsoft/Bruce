/* pqhid_windows.c
 *
 * Windows backend for the CTAP-over-USB-HID transport. Implements
 * the pqhid_os.h contract directly on the documented Win32 device
 * stack -- no third-party HID layer:
 *
 *   enumeration   SetupAPI device-interface walking (SetupDiGetClassDevsA,
 *                 SetupDiEnumDeviceInterfaces,
 *                 SetupDiGetDeviceInterfaceDetailA) against the HID
 *                 class GUID from HidD_GetHidGuid
 *   metadata      hid.dll queries: HidD_GetAttributes for VID/PID,
 *                 HidD_GetPreparsedData + HidP_GetCaps for usage page /
 *                 usage / report lengths, HidD_Get*String for the USB
 *                 descriptor strings
 *   report I/O    overlapped ReadFile/WriteFile on the device interface
 *                 path; WaitForSingleObject + CancelIoEx provide the
 *                 read timeout
 *   CSPRNG        CNG BCryptGenRandom (system-preferred RNG)
 *
 * Report-ID quirk (see pqhid_os.h): the HID class driver frames every
 * report buffer with the report ID in byte 0 and expects the buffer to
 * be exactly the Input/OutputReportByteLength from HIDP_CAPS. CTAP
 * devices use unnumbered reports (report ID 0x00) with a 64-byte
 * payload (CTAP sec. 8.1.4), so both lengths are 65: writes prepend a
 * 0x00 byte, reads strip byte 0 before handing the core its bare
 * 64-byte frame.
 *
 * Elevation note: since Windows 10 1903 the OS reserves HID devices on
 * the FIDO usage page (0xf1d0 -- CTAP sec. 8.1.8.2) for its own WebAuthn
 * service; opening one for read/write requires an elevated process.
 * Metadata queries do not, so enumeration keeps working unprivileged
 * (see pqhid_os_enumerate below).
 *
 * Copyright (C) 2010-2026 Cryptsoft Pty Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* CancelIoEx needs the Vista-and-later API surface; ask for Windows 7
 * explicitly rather than trusting the toolchain default. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <bcrypt.h>

#include <stdlib.h>
#include <string.h>

#include "pqhid.h"
#include "pqhid_os.h"

/* ---- Constants -------------------------------------------------- */

/* FIDO authenticators advertise this usage page / usage as the first
 * usage in their HID report descriptor (CTAP sec. 8.1.8.2). */
#define HID_FIDO_USAGE_PAGE     0xf1d0
#define HID_FIDO_USAGE          0x0001

/* CTAP devices use unnumbered reports; the class driver represents
 * those as report ID zero in byte 0 of every report buffer. */
#define HID_REPORT_ID           0x00

/* ---- Device handle ---------------------------------------------- */

struct pqhid_os_dev {
	HANDLE h;               /* opened FILE_FLAG_OVERLAPPED */
	USHORT in_len;          /* HIDP_CAPS InputReportByteLength  (65) */
	USHORT out_len;         /* HIDP_CAPS OutputReportByteLength (65) */
};

/* ---- Helpers ----------------------------------------------------- */

/* Bounded string copy; always NUL-terminates, truncates silently. */
static void pqhid_win_copystr(char *dst, size_t dstLen, const char *src)
{
	size_t n;

	n = strlen(src);
	if(n >= dstLen) n = dstLen - 1;
	memcpy(dst, src, n);
	dst[n] = '\0';
}

/* Fetch the top-level collection capabilities of an open HID handle.
 * Wraps the preparsed-data dance: HidD_GetPreparsedData allocates a
 * parse of the report descriptor, HidP_GetCaps extracts the summary,
 * HidD_FreePreparsedData releases the parse. */
static int pqhid_win_caps(HANDLE h, HIDP_CAPS *caps)
{
	PHIDP_PREPARSED_DATA pp;
	NTSTATUS st;

	if(!HidD_GetPreparsedData(h, &pp))
		return PQFIDO_ERR_IO;
	st = HidP_GetCaps(pp, caps);
	HidD_FreePreparsedData(pp);
	return (st == HIDP_STATUS_SUCCESS) ? PQFIDO_OK : PQFIDO_ERR_IO;
}

/* Signature shared by HidD_GetManufacturerString /
 * HidD_GetProductString / HidD_GetSerialNumberString: fill a WCHAR
 * buffer of BufferLength *bytes* with a NUL-terminated UTF-16 string. */
typedef BOOLEAN (NTAPI *pqhid_win_strfn_t)(HANDLE, PVOID, ULONG);

/* Query one USB descriptor string and store it as UTF-8. The contract
 * (pqhid.h) wants an empty string whenever the device doesn't provide
 * one or the query/conversion fails. */
static void pqhid_win_string(HANDLE h, pqhid_win_strfn_t query,
                             char *dst, size_t dstLen)
{
	WCHAR wstr[PQHID_MAX_STR];

	dst[0] = '\0';
	memset(wstr, 0, sizeof wstr);
	if(!query(h, wstr, (ULONG)(sizeof wstr - sizeof(WCHAR))))
		return;
	wstr[PQHID_MAX_STR - 1] = L'\0';
	if(WideCharToMultiByte(CP_UTF8, 0, wstr, -1,
	    dst, (int)dstLen, NULL, NULL) <= 0)
		dst[0] = '\0';
}

/* ---- Enumeration ------------------------------------------------- */

/* Walk every present HID device interface and keep the ones whose
 * top-level collection is FIDO (usage page 0xf1d0, usage 0x0001).
 *
 * Each candidate is probed with dwDesiredAccess = 0: Windows permits
 * attribute/caps/string queries on a handle opened without read or
 * write access, so enumeration works from a non-elevated process even
 * though opening a FIDO device for traffic would not. Devices that
 * refuse even the query-only open are skipped silently, per the
 * pqhid_os.h contract. */
int pqhid_os_enumerate(pqhid_devinfo_t *infos, size_t cap, size_t *count)
{
	GUID hidGuid;
	HDEVINFO devs;
	SP_DEVICE_INTERFACE_DATA iface;
	SP_DEVICE_INTERFACE_DETAIL_DATA_A *detail;
	HANDLE h;
	HIDD_ATTRIBUTES attr;
	HIDP_CAPS caps;
	pqhid_devinfo_t *info;
	DWORD idx;
	DWORD need;
	size_t found;

	if(infos == NULL || count == NULL) return PQFIDO_ERR_INVAL;
	*count = 0;

	HidD_GetHidGuid(&hidGuid);
	devs = SetupDiGetClassDevsA(&hidGuid, NULL, NULL,
	  DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if(devs == INVALID_HANDLE_VALUE) return PQFIDO_ERR_IO;

	found = 0;
	for(idx = 0; found < cap; idx++){
		memset(&iface, 0, sizeof iface);
		iface.cbSize = sizeof iface;
		if(!SetupDiEnumDeviceInterfaces(devs, NULL, &hidGuid,
		    idx, &iface))
			break;   /* ERROR_NO_MORE_ITEMS ends the walk */

		/* Two-call dance: first call reports the required buffer
		 * size (and fails with ERROR_INSUFFICIENT_BUFFER), second
		 * call fills it. cbSize must be the size of the fixed
		 * struct -- NOT the buffer size -- or the call rejects the
		 * buffer with ERROR_INVALID_USER_BUFFER. */
		need = 0;
		SetupDiGetDeviceInterfaceDetailA(devs, &iface, NULL, 0,
		  &need, NULL);
		if(need == 0) continue;
		detail = (SP_DEVICE_INTERFACE_DETAIL_DATA_A *)malloc(need);
		if(detail == NULL){
			SetupDiDestroyDeviceInfoList(devs);
			return PQFIDO_ERR_NOMEM;
		}
		detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);
		if(!SetupDiGetDeviceInterfaceDetailA(devs, &iface, detail,
		    need, NULL, NULL)){
			free(detail);
			continue;
		}

		/* Query-only probe (no read/write access requested). */
		h = CreateFileA(detail->DevicePath, 0,
		  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		  OPEN_EXISTING, 0, NULL);
		if(h == INVALID_HANDLE_VALUE){
			free(detail);
			continue;
		}

		memset(&attr, 0, sizeof attr);
		attr.Size = sizeof attr;
		if(!HidD_GetAttributes(h, &attr)
		  || pqhid_win_caps(h, &caps) != PQFIDO_OK
		  || caps.UsagePage != HID_FIDO_USAGE_PAGE
		  || caps.Usage != HID_FIDO_USAGE){
			CloseHandle(h);
			free(detail);
			continue;
		}

		info = &infos[found];
		memset(info, 0, sizeof *info);
		pqhid_win_copystr(info->path, sizeof info->path,
		  detail->DevicePath);
		info->vendor_id = attr.VendorID;
		info->product_id = attr.ProductID;
		pqhid_win_string(h, &HidD_GetManufacturerString,
		  info->manufacturer, sizeof info->manufacturer);
		pqhid_win_string(h, &HidD_GetProductString,
		  info->product, sizeof info->product);
		pqhid_win_string(h, &HidD_GetSerialNumberString,
		  info->serial, sizeof info->serial);

		CloseHandle(h);
		free(detail);
		found++;
	}

	SetupDiDestroyDeviceInfoList(devs);
	*count = found;
	return PQFIDO_OK;
}

/* ---- Open / close ------------------------------------------------ */

/* Open the device interface path for overlapped read/write and cache
 * the report buffer lengths from HIDP_CAPS.
 *
 * A failed open is reported as PQFIDO_ERR_IO: since Windows 10 1903
 * opening a FIDO-usage device for traffic needs an elevated process
 * (only the query-only probes used during enumeration are exempt) --
 * that is platform policy, not a device fault. */
int pqhid_os_open(const char *path, pqhid_os_dev_t **out)
{
	HANDLE h;
	HIDP_CAPS caps;
	pqhid_os_dev_t *dev;

	if(path == NULL || out == NULL) return PQFIDO_ERR_INVAL;
	*out = NULL;

	h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
	  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
	  FILE_FLAG_OVERLAPPED, NULL);
	if(h == INVALID_HANDLE_VALUE) return PQFIDO_ERR_IO;

	/* A CTAP report buffer is 1 report-ID byte + 64 payload bytes;
	 * anything shorter cannot carry a full frame. */
	if(pqhid_win_caps(h, &caps) != PQFIDO_OK
	  || caps.InputReportByteLength < PQHID_OS_FRAME_SIZE + 1
	  || caps.OutputReportByteLength < PQHID_OS_FRAME_SIZE + 1){
		CloseHandle(h);
		return PQFIDO_ERR_IO;
	}

	dev = (pqhid_os_dev_t *)calloc(1, sizeof(*dev));
	if(dev == NULL){
		CloseHandle(h);
		return PQFIDO_ERR_NOMEM;
	}
	dev->h = h;
	dev->in_len = caps.InputReportByteLength;
	dev->out_len = caps.OutputReportByteLength;

	*out = dev;
	return PQFIDO_OK;
}

void pqhid_os_close(pqhid_os_dev_t *dev)
{
	if(dev == NULL) return;
	if(dev->h != INVALID_HANDLE_VALUE)
		CloseHandle(dev->h);
	free(dev);
}

/* ---- Report I/O -------------------------------------------------- */

/* Write one report. The class driver wants a buffer of exactly
 * OutputReportByteLength bytes with the report ID in byte 0, so the
 * 64-byte frame is staged at offset 1 and the remainder zero-padded.
 * The handle is overlapped-only, so even a "blocking" write goes
 * through an OVERLAPPED and is reaped with GetOverlappedResult. */
int pqhid_os_write(pqhid_os_dev_t *dev,
  const unsigned char frame[PQHID_OS_FRAME_SIZE])
{
	unsigned char *buf;
	OVERLAPPED ov;
	DWORD wrote;
	BOOL ok;
	int rc;

	if(dev == NULL || frame == NULL) return PQFIDO_ERR_INVAL;

	buf = (unsigned char *)calloc(1, dev->out_len);
	if(buf == NULL) return PQFIDO_ERR_NOMEM;
	buf[0] = HID_REPORT_ID;
	memcpy(buf + 1, frame, PQHID_OS_FRAME_SIZE);

	memset(&ov, 0, sizeof ov);
	ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
	if(ov.hEvent == NULL){
		free(buf);
		return PQFIDO_ERR_IO;
	}

	ok = WriteFile(dev->h, buf, dev->out_len, NULL, &ov);
	if(!ok && GetLastError() != ERROR_IO_PENDING){
		rc = PQFIDO_ERR_IO;
		goto out;
	}

	wrote = 0;
	if(!GetOverlappedResult(dev->h, &ov, &wrote, TRUE)){
		rc = PQFIDO_ERR_IO;
		goto out;
	}
	rc = (wrote == (DWORD)dev->out_len) ? PQFIDO_OK : PQFIDO_ERR_IO;

out:
	CloseHandle(ov.hEvent);
	free(buf);
	return rc;
}

/* Read one report, waiting at most timeoutMs milliseconds (negative
 * means wait forever). The class driver always delivers the report-ID
 * byte first, so byte 0 is stripped and bytes 1..64 become the
 * caller's frame. On timeout the pending read MUST be cancelled and
 * reaped before the OVERLAPPED (and buffer) go out of scope --
 * CancelIoEx followed by a blocking GetOverlappedResult guarantees the
 * kernel is done with both. A short read is a protocol-impossible
 * condition for an interrupt-IN report and is surfaced as I/O error. */
int pqhid_os_read(pqhid_os_dev_t *dev,
  unsigned char frame[PQHID_OS_FRAME_SIZE], int timeoutMs)
{
	unsigned char *buf;
	OVERLAPPED ov;
	DWORD got;
	DWORD wait;
	BOOL ok;
	int rc;

	if(dev == NULL || frame == NULL) return PQFIDO_ERR_INVAL;

	buf = (unsigned char *)malloc(dev->in_len);
	if(buf == NULL) return PQFIDO_ERR_NOMEM;

	memset(&ov, 0, sizeof ov);
	ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
	if(ov.hEvent == NULL){
		free(buf);
		return PQFIDO_ERR_IO;
	}

	ok = ReadFile(dev->h, buf, dev->in_len, NULL, &ov);
	if(!ok && GetLastError() != ERROR_IO_PENDING){
		rc = PQFIDO_ERR_IO;
		goto out;
	}

	if(!ok){
		wait = WaitForSingleObject(ov.hEvent,
		  (timeoutMs < 0) ? INFINITE : (DWORD)timeoutMs);
		if(wait != WAIT_OBJECT_0){
			/* Cancel, then reap (blocking) so the kernel is done
			 * with buf/ov before they go away. The cancel can lose
			 * the race: if the report landed between the wait
			 * expiring and CancelIoEx taking effect, the reap
			 * reports success with real bytes -- deliver that frame
			 * rather than dropping it, or the message it belongs
			 * to could never reassemble. */
			CancelIoEx(dev->h, &ov);
			got = 0;
			if(GetOverlappedResult(dev->h, &ov, &got, TRUE)
			  && got >= (DWORD)dev->in_len){
				memcpy(frame, buf + 1, PQHID_OS_FRAME_SIZE);
				rc = PQFIDO_OK;
				goto out;
			}
			rc = (wait == WAIT_TIMEOUT)
			  ? PQFIDO_ERR_TIMEOUT : PQFIDO_ERR_IO;
			goto out;
		}
	}

	got = 0;
	if(!GetOverlappedResult(dev->h, &ov, &got, TRUE)){
		rc = PQFIDO_ERR_IO;
		goto out;
	}
	if(got < (DWORD)dev->in_len){
		rc = PQFIDO_ERR_IO;
		goto out;
	}

	memcpy(frame, buf + 1, PQHID_OS_FRAME_SIZE);
	rc = PQFIDO_OK;

out:
	CloseHandle(ov.hEvent);
	free(buf);
	return rc;
}

/* ---- CSPRNG ------------------------------------------------------ */

/* CNG system-preferred RNG; used by the core for the 8-byte INIT
 * nonce (CTAP sec. 8.1.9.1.3). */
int pqhid_os_random(unsigned char *buf, size_t len)
{
	NTSTATUS st;

	if(buf == NULL && len > 0) return PQFIDO_ERR_INVAL;
	if(len == 0) return PQFIDO_OK;

	st = BCryptGenRandom(NULL, buf, (ULONG)len,
	  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	return (st == 0) ? PQFIDO_OK : PQFIDO_ERR_IO;
}
