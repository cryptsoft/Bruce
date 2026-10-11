/* pqf_pkcs11.c -- PKCS#11 module exposing the Bruce token as a
 * random number source.
 *
 * A Cryptoki (PKCS#11 v2.40-compatible, built against the OASIS v3.01
 * headers) shared library whose only real capability is
 * C_GenerateRandom: bytes are pulled from the token's ring-oscillator
 * TRNG over USB via the vendor CTAPHID_CMD_RNG command (see
 * c/firmware/src/ctaphid.h for the wire contract and c/hid/pqhid.h
 * for the transport). No authentication, no objects, no mechanisms --
 * the entire remaining API surface is present in the function list
 * but answers CKR_FUNCTION_NOT_SUPPORTED.
 *
 * Intended consumers: `pkcs11-tool --generate-random`, the OpenSSL
 * pkcs11 provider (`openssl rand -provider pkcs11 ...`), or anything
 * else that can drink entropy through Cryptoki.
 *
 * Model:
 *   - One slot per FIDO authenticator found on the USB bus
 *     (pqhid_enumerate). C_GetSlotList rescans on every call, so
 *     hot-plug is picked up by applications that re-list slots.
 *     Slot IDs are indices into the most recent scan -- they are NOT
 *     stable across replug (v1 simplification).
 *   - C_OpenSession opens the HID device (CTAPHID INIT handshake);
 *     C_CloseSession closes it. Every session holds its own device
 *     handle, so concurrent sessions to one token multiplex on the
 *     device's per-channel CIDs.
 *   - C_SeedRandom is accepted and ignored (CKR_OK): the token's
 *     TRNG takes no external seed material.
 *
 * Threading: this module performs no locking of its own and is
 * intended for single-threaded use (pkcs11-tool, openssl rand). It
 * accepts any CK_C_INITIALIZE_ARGS locking flags without acting on
 * them -- a v1 limitation, documented in README.md.
 *
 * C90, single file. Link with libpqhid.a (c/hid) and, on macOS, the
 * IOKit + CoreFoundation frameworks.
 *
 * Copyright (C) 2010-2026 Cryptsoft Pty Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "cryptoki.h"
#include "pqhid.h"

/* ---- Module constants ------------------------------------------- */

#define PQF_P11_VERSION_MAJOR   0
#define PQF_P11_VERSION_MINOR   1

#define PQF_MAX_SLOTS           8
#define PQF_MAX_SESSIONS        16

#define PQF_MANUFACTURER        "Bruce"
#define PQF_LIB_DESCRIPTION     "Bruce token RNG bridge"
#define PQF_SLOT_DESCRIPTION    "Bruce USB CTAP HID slot"
#define PQF_TOKEN_MODEL         "Bruce"

/* ---- Module state ------------------------------------------------ */

static CK_BBOOL s_initialized = CK_FALSE;

/* Most recent USB scan. Slot ID n == s_devs[n]. */
static pqhid_devinfo_t s_devs[PQF_MAX_SLOTS];
static CK_ULONG        s_ndevs = 0;

/* Session table. Handle n == s_sessions[n-1] (0 is never a valid
 * Cryptoki handle). */
typedef struct pqf_session {
	CK_BBOOL      in_use;
	CK_SLOT_ID    slot;
	CK_FLAGS      flags;
	pqhid_dev_t  *dev;
} pqf_session_t;

static pqf_session_t s_sessions[PQF_MAX_SESSIONS];

/* ---- Helpers ------------------------------------------------------ */

/* Cryptoki string fields are fixed-width, space-padded, and NOT
 * NUL-terminated (PKCS#11 v3.0 base sec. 4.1). */
static void pad_str(CK_UTF8CHAR *dst, size_t dstLen, const char *src)
{
	size_t n = strlen(src);
	if (n > dstLen) n = dstLen;
	memcpy(dst, src, n);
	memset(dst + n, ' ', dstLen - n);
}

static int rescan(void)
{
	size_t count = 0;
	int rc = pqhid_enumerate(s_devs,
	  sizeof s_devs / sizeof s_devs[0], &count);
	if (rc != PQFIDO_OK) return rc;
	s_ndevs = (CK_ULONG)count;
	return PQFIDO_OK;
}

static pqf_session_t *session_from_handle(CK_SESSION_HANDLE h)
{
	if (h == 0 || h > PQF_MAX_SESSIONS) return NULL_PTR;
	if (!s_sessions[h - 1].in_use) return NULL_PTR;
	return &s_sessions[h - 1];
}

/* ---- General-purpose ---------------------------------------------- */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_C_INITIALIZE_ARGS_PTR args;

	if (s_initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (pInitArgs != NULL_PTR) {
		args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
		if (args->pReserved != NULL_PTR)
			return CKR_ARGUMENTS_BAD;
		/* Locking arguments are accepted but not acted upon --
		 * this module does no locking (header comment). */
	}

	memset(s_sessions, 0, sizeof s_sessions);
	s_ndevs = 0;
	s_initialized = CK_TRUE;
	return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	CK_ULONG i;

	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pReserved != NULL_PTR) return CKR_ARGUMENTS_BAD;

	for (i = 0; i < PQF_MAX_SESSIONS; i++) {
		if (s_sessions[i].in_use)
			pqhid_close(s_sessions[i].dev);
	}
	memset(s_sessions, 0, sizeof s_sessions);
	s_initialized = CK_FALSE;
	return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	memset(pInfo, 0, sizeof *pInfo);
	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 40;
	pad_str(pInfo->manufacturerID, sizeof pInfo->manufacturerID,
	  PQF_MANUFACTURER);
	pInfo->flags = 0;
	pad_str(pInfo->libraryDescription,
	  sizeof pInfo->libraryDescription, PQF_LIB_DESCRIPTION);
	pInfo->libraryVersion.major = PQF_P11_VERSION_MAJOR;
	pInfo->libraryVersion.minor = PQF_P11_VERSION_MINOR;
	return CKR_OK;
}

/* ---- Slot and token management ------------------------------------ */

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
  CK_ULONG_PTR pulCount)
{
	CK_ULONG i;

	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pulCount == NULL_PTR) return CKR_ARGUMENTS_BAD;

	/* Hot-plug: rescan the bus on every list. A slot exists only
	 * where a token is enumerated, so tokenPresent doesn't change
	 * the answer. */
	(void)tokenPresent;
	if (rescan() != PQFIDO_OK) return CKR_DEVICE_ERROR;

	if (pSlotList == NULL_PTR) {
		*pulCount = s_ndevs;
		return CKR_OK;
	}
	if (*pulCount < s_ndevs) {
		*pulCount = s_ndevs;
		return CKR_BUFFER_TOO_SMALL;
	}
	for (i = 0; i < s_ndevs; i++)
		pSlotList[i] = (CK_SLOT_ID)i;
	*pulCount = s_ndevs;
	return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (slotID >= s_ndevs) return CKR_SLOT_ID_INVALID;

	memset(pInfo, 0, sizeof *pInfo);
	pad_str(pInfo->slotDescription, sizeof pInfo->slotDescription,
	  PQF_SLOT_DESCRIPTION);
	pad_str(pInfo->manufacturerID, sizeof pInfo->manufacturerID,
	  s_devs[slotID].manufacturer[0] != '\0'
	    ? s_devs[slotID].manufacturer : PQF_MANUFACTURER);
	pInfo->flags = CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE
	  | CKF_HW_SLOT;
	return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (slotID >= s_ndevs) return CKR_SLOT_ID_INVALID;

	memset(pInfo, 0, sizeof *pInfo);
	pad_str(pInfo->label, sizeof pInfo->label,
	  s_devs[slotID].product[0] != '\0'
	    ? s_devs[slotID].product : PQF_TOKEN_MODEL);
	pad_str(pInfo->manufacturerID, sizeof pInfo->manufacturerID,
	  s_devs[slotID].manufacturer[0] != '\0'
	    ? s_devs[slotID].manufacturer : PQF_MANUFACTURER);
	pad_str(pInfo->model, sizeof pInfo->model, PQF_TOKEN_MODEL);
	pad_str(pInfo->serialNumber, sizeof pInfo->serialNumber,
	  s_devs[slotID].serial);

	/* CKF_RNG is the whole point. No CKF_LOGIN_REQUIRED: sessions
	 * need no PIN. CKF_WRITE_PROTECTED: nothing here writes. */
	pInfo->flags = CKF_RNG | CKF_TOKEN_INITIALIZED
	  | CKF_WRITE_PROTECTED;

	pInfo->ulMaxSessionCount = PQF_MAX_SESSIONS;
	pInfo->ulMaxRwSessionCount = 0;
	pInfo->ulMaxPinLen = 0;
	pInfo->ulMinPinLen = 0;
	pInfo->ulTotalPublicMemory  = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory   = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory  = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = PQF_P11_VERSION_MAJOR;
	pInfo->firmwareVersion.minor = PQF_P11_VERSION_MINOR;
	return CKR_OK;
}

/* ---- Session management ------------------------------------------- */

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
  CK_VOID_PTR pApplication, CK_NOTIFY Notify,
  CK_SESSION_HANDLE_PTR phSession)
{
	CK_ULONG i;
	int rc;

	(void)pApplication;
	(void)Notify;

	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (phSession == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	/* Sessions may be opened before any C_GetSlotList call --
	 * populate the slot table on demand. */
	if (s_ndevs == 0 && rescan() != PQFIDO_OK)
		return CKR_DEVICE_ERROR;
	if (slotID >= s_ndevs) return CKR_SLOT_ID_INVALID;

	for (i = 0; i < PQF_MAX_SESSIONS; i++) {
		if (!s_sessions[i].in_use) break;
	}
	if (i == PQF_MAX_SESSIONS) return CKR_SESSION_COUNT;

	rc = pqhid_open(s_devs[slotID].path, &s_sessions[i].dev);
	if (rc == PQFIDO_ERR_IO) return CKR_TOKEN_NOT_PRESENT;
	if (rc != PQFIDO_OK) return CKR_DEVICE_ERROR;

	s_sessions[i].in_use = CK_TRUE;
	s_sessions[i].slot = slotID;
	s_sessions[i].flags = flags;
	*phSession = (CK_SESSION_HANDLE)(i + 1);
	return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	pqf_session_t *s;

	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	s = session_from_handle(hSession);
	if (s == NULL_PTR) return CKR_SESSION_HANDLE_INVALID;

	pqhid_close(s->dev);
	memset(s, 0, sizeof *s);
	return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	CK_ULONG i;

	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID >= s_ndevs) return CKR_SLOT_ID_INVALID;

	for (i = 0; i < PQF_MAX_SESSIONS; i++) {
		if (s_sessions[i].in_use && s_sessions[i].slot == slotID) {
			pqhid_close(s_sessions[i].dev);
			memset(&s_sessions[i], 0, sizeof s_sessions[i]);
		}
	}
	return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo)
{
	pqf_session_t *s;

	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;
	s = session_from_handle(hSession);
	if (s == NULL_PTR) return CKR_SESSION_HANDLE_INVALID;

	memset(pInfo, 0, sizeof *pInfo);
	pInfo->slotID = s->slot;
	/* No login concept: a session is always in the public state. */
	pInfo->state = (s->flags & CKF_RW_SESSION)
	  ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	pInfo->flags = s->flags;
	pInfo->ulDeviceError = 0;
	return CKR_OK;
}

/* ---- Random numbers (the whole point) ----------------------------- */

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
  CK_ULONG ulSeedLen)
{
	pqf_session_t *s;

	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	s = session_from_handle(hSession);
	if (s == NULL_PTR) return CKR_SESSION_HANDLE_INVALID;
	if (pSeed == NULL_PTR && ulSeedLen != 0)
		return CKR_ARGUMENTS_BAD;

	/* Accepted and ignored: the token's ring-oscillator TRNG takes
	 * no external seed material. */
	return CKR_OK;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	pqf_session_t *s;
	int rc;

	if (!s_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
	s = session_from_handle(hSession);
	if (s == NULL_PTR) return CKR_SESSION_HANDLE_INVALID;
	if (ulRandomLen == 0) return CKR_OK;
	if (RandomData == NULL_PTR) return CKR_ARGUMENTS_BAD;

	rc = pqhid_rng(s->dev, RandomData, (size_t)ulRandomLen);
	if (rc == PQFIDO_OK) return CKR_OK;
	if (rc == PQFIDO_ERR_IO) return CKR_DEVICE_REMOVED;
	/* PQFIDO_ERR_PROTO here usually means the token's firmware
	 * predates the vendor RNG command. */
	return CKR_DEVICE_ERROR;
}

/* ---- Parallel-execution legacy stubs (PKCS#11 v3.0 base sec. 5.16) ----
 *
 * These two must return CKR_FUNCTION_NOT_PARALLEL (not
 * CKR_FUNCTION_NOT_SUPPORTED) per the spec. */

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_PARALLEL;
}

/* ---- Everything else: present but unsupported ---------------------
 *
 * "Fake the entire API surface": every remaining v2.40 entry point
 * exists (the function list below must be fully populated) and
 * answers CKR_FUNCTION_NOT_SUPPORTED. Signatures generated from the
 * OASIS pkcs11f.h, in its order. */

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	(void)slotID; (void)pMechanismList; (void)pulCount;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
  CK_MECHANISM_INFO_PTR pInfo)
{
	(void)slotID; (void)type; (void)pInfo;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	(void)slotID; (void)pPin; (void)ulPinLen; (void)pLabel;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen)
{
	(void)hSession; (void)pPin; (void)ulPinLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
  CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	(void)hSession; (void)pOldPin; (void)ulOldLen;
	(void)pNewPin; (void)ulNewLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	(void)hSession; (void)pOperationState; (void)pulOperationStateLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
  CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	(void)hSession; (void)pOperationState; (void)ulOperationStateLen;
	(void)hEncryptionKey; (void)hAuthenticationKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	(void)hSession; (void)userType; (void)pPin; (void)ulPinLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phObject)
{
	(void)hSession; (void)pTemplate; (void)ulCount; (void)phObject;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phNewObject)
{
	(void)hSession; (void)hObject; (void)pTemplate; (void)ulCount;
	(void)phNewObject;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject)
{
	(void)hSession; (void)hObject;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	(void)hSession; (void)hObject; (void)pulSize;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount)
{
	(void)hSession; (void)hObject; (void)pTemplate; (void)ulCount;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount)
{
	(void)hSession; (void)hObject; (void)pTemplate; (void)ulCount;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	(void)hSession; (void)pTemplate; (void)ulCount;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
  CK_ULONG_PTR pulObjectCount)
{
	(void)hSession; (void)phObject; (void)ulMaxObjectCount;
	(void)pulObjectCount;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	(void)hSession; (void)pMechanism; (void)hKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
  CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen)
{
	(void)hSession; (void)pData; (void)ulDataLen; (void)pEncryptedData;
	(void)pulEncryptedDataLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart;
	(void)pulEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	(void)hSession; (void)pLastEncryptedPart;
	(void)pulLastEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	(void)hSession; (void)pMechanism; (void)hKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
  CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen)
{
	(void)hSession; (void)pEncryptedData; (void)ulEncryptedDataLen;
	(void)pData; (void)pulDataLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	(void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen;
	(void)pPart; (void)pulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
  CK_ULONG_PTR pulLastPartLen)
{
	(void)hSession; (void)pLastPart; (void)pulLastPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism)
{
	(void)hSession; (void)pMechanism;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
  CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	(void)hSession; (void)pData; (void)ulDataLen; (void)pDigest;
	(void)pulDigestLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen)
{
	(void)hSession; (void)pPart; (void)ulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	(void)hSession; (void)hKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen)
{
	(void)hSession; (void)pDigest; (void)pulDigestLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey)
{
	(void)hSession; (void)pMechanism; (void)hKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession; (void)pData; (void)ulDataLen; (void)pSignature;
	(void)pulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen)
{
	(void)hSession; (void)pPart; (void)ulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession; (void)pSignature; (void)pulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	(void)hSession; (void)pMechanism; (void)hKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession; (void)pData; (void)ulDataLen; (void)pSignature;
	(void)pulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	(void)hSession; (void)pMechanism; (void)hKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	(void)hSession; (void)pData; (void)ulDataLen; (void)pSignature;
	(void)ulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen)
{
	(void)hSession; (void)pPart; (void)ulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen)
{
	(void)hSession; (void)pSignature; (void)ulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	(void)hSession; (void)pMechanism; (void)hKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	(void)hSession; (void)pSignature; (void)ulSignatureLen; (void)pData;
	(void)pulDataLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart;
	(void)pulEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	(void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen;
	(void)pPart; (void)pulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart;
	(void)pulEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	(void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen;
	(void)pPart; (void)pulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession; (void)pMechanism; (void)pTemplate; (void)ulCount;
	(void)phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
  CK_ULONG ulPublicKeyAttributeCount,
  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
  CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
  CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	(void)hSession; (void)pMechanism; (void)pPublicKeyTemplate;
	(void)ulPublicKeyAttributeCount; (void)pPrivateKeyTemplate;
	(void)ulPrivateKeyAttributeCount; (void)phPublicKey;
	(void)phPrivateKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
  CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	(void)hSession; (void)pMechanism; (void)hWrappingKey; (void)hKey;
	(void)pWrappedKey; (void)pulWrappedKeyLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
  CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession; (void)pMechanism; (void)hUnwrappingKey;
	(void)pWrappedKey; (void)ulWrappedKeyLen; (void)pTemplate;
	(void)ulAttributeCount; (void)phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession; (void)pMechanism; (void)hBaseKey; (void)pTemplate;
	(void)ulAttributeCount; (void)phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
  CK_VOID_PTR pReserved)
{
	(void)flags; (void)pSlot; (void)pReserved;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ---- The function list --------------------------------------------
 *
 * Built by the OASIS headers' own iteration macro so the pointer
 * order can never drift from the CK_FUNCTION_LIST struct definition
 * (both expand pkcs11f.h with CK_PKCS11_2_0_ONLY set). */

static CK_FUNCTION_LIST s_function_list = {
	{ 2, 40 },
#define CK_PKCS11_FUNCTION_INFO(name) name,
#define CK_PKCS11_2_0_ONLY 1
#include "oasis/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
#undef CK_PKCS11_2_0_ONLY
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (ppFunctionList == NULL_PTR) return CKR_ARGUMENTS_BAD;
	*ppFunctionList = &s_function_list;
	return CKR_OK;
}
