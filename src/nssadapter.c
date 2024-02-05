// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "nssadapter.h"
#include "dbg_trace.h"
#include "p11_util.h"
#include <memory.h>
#include <stdbool.h>
#include <stdint.h>
#include <nss3/pkcs11.h>

/* ****************************************************************************
 * Internal/Private functions
 * ****************************************************************************/
#pragma GCC visibility push(hidden)

// Saved non-decorated original function list from NSS, for this wrapper's use.
// NOTE: the PKCS #11 v3.0 standard states 'CK_FUNCTION_LIST_3_0 is a structure
// which contains the same function pointers as in CK_FUNCTION_LIST and
// additional functions added to the end of the structure that were defined in
// Cryptoki version 3.0'. This implies that we can safely use CK_FUNCTION_LIST
// regardless of the version, as long as it contains all the functions we need.
CK_FUNCTION_LIST_PTR o = NULL;

// Copy for the decorated versions of the CK_INTERFACE and CK_FUNCTION_LIST/_3_0
// structures. We use CK_FUNCTION_LIST_3_0 since it has enough space to hold all
// the CK_FUNCTION_LIST data, in runtime, one or the other can be present.
CK_INTERFACE decoratedInterface = { 0 } ;
CK_FUNCTION_LIST_3_0 decoratedFunctionList = { 0 };

// Import/Export session, key, initialization vector (IV) and mechanism. The
// IV was randomly generated once: there is no point in trying to generate it
// at run time, since the encryption is temporary, and we are receiving or
// going to return the sensitive attributes in plain.
static CK_SESSION_HANDLE ieKeySession = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE ieKey = CK_INVALID_HANDLE;
static CK_BYTE iv[] = { 0xa1, 0xe9, 0xe1, 0x95, 0xbf, 0x11, 0x6c, 0xca,
                        0xef, 0xa5, 0x56, 0x5e, 0xdd, 0xfc, 0xdc, 0x8c  };
static CK_MECHANISM ieKeyMech = { .mechanism = CKM_AES_CBC_PAD,
                                  .pParameter = &iv,
                                  .ulParameterLen = sizeof(iv) };

CK_RV C_CreateObject(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phObject
) {
    CK_RV ret = o->C_CreateObject(hSession, pTemplate, ulCount, phObject);
    dbg_trace("Forwarded to original function (returned " GREPABLE(CKR) "), "
              "parameters:\nhSession = " HEX32 ", pTemplate = " HEX64
              ", ulCount = %lu, phObject = " HEX64, ret, hSession,
              (uintptr_t)pTemplate, ulCount, (uintptr_t)phObject);
    return ret;
}

CK_RV C_GetAttributeValue(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
) {
    CK_RV ret = o->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
    dbg_trace("Forwarded to original function (returned " GREPABLE(CKR) "), "
              "parameters:\nhSession = " HEX32 ", hObject = %lu, pTemplate = "
              HEX64 ", ulCount = %lu", ret, hSession, hObject,
              (uintptr_t)pTemplate, ulCount);
    if (ret == CKR_OK && ulCount >= 3) {
        CK_BBOOL* token = NULL;
        CK_BBOOL* sensitive = NULL;
        CK_BBOOL* extractable = NULL;
        FOREACH_ATTRIBUTE_START(attribute)
            getBBoolAttr(attribute, CKA_TOKEN, &token);
            getBBoolAttr(attribute, CKA_SENSITIVE, &sensitive);
            getBBoolAttr(attribute, CKA_EXTRACTABLE, &extractable);
            if (token != NULL && *token == CK_TRUE) {
                dbg_trace("Without an NSS DB, CKA_TOKEN should always be "
                          "CK_FALSE");
                return CKR_GENERAL_ERROR;
            }
            if (// For non-sensitive keys, the exporter isn't necessary:
                (sensitive != NULL && *sensitive == CK_FALSE) ||
                // For non-extractable keys, the exporter doesn't work:
                (extractable != NULL && *extractable == CK_FALSE)) {
                break;
            }
            if (token != NULL && sensitive != NULL && extractable != NULL) {
                // Non-token, sensitive and extractable key:
                if (!isKeyType(o, hSession, hObject, CKO_PRIVATE_KEY, CKK_DH)) {
                    // See OPENJDK-824 for reasons behind skipping DH keys
                    dbg_trace("Forcing extractable key to be non-sensitive, "
                              "to prevent an opaque Java key object, which "
                              "does not get certain attributes");
                    *sensitive = CK_FALSE;
                }
                break;
            }
        FOREACH_ATTRIBUTE_END
    } else if (ret == CKR_ATTRIBUTE_SENSITIVE) {
        FOREACH_ATTRIBUTE_START(attribute)
            if (isUnavailableInformation(attribute)) {
                dbg_trace("TODO: exportKey();");  // TODO: exportKey();
                break;
            }
        FOREACH_ATTRIBUTE_END
    }
    return ret;
}

CK_RV initializeImporterExporter() {
    if (ieKey != CK_INVALID_HANDLE) {
        // Already initialized
        return CKR_OK;
    }

    // NSS realizes that no DB was configured and FIPS level is 2 after the
    // C_GetTokenInfo() call, and stops requiring login on each operation
    CK_TOKEN_INFO info;
    CK_RV ret = o->C_GetTokenInfo(FIPS_SLOT_ID, &info);
    dbg_trace("Called C_GetTokenInfo() to remove the login requirement "
              "(returned " GREPABLE(CKR) ")", ret);
    if (ret != CKR_OK) {
        return ret;
    }

    ret = o->C_OpenSession(FIPS_SLOT_ID, CKF_SERIAL_SESSION, NULL, NULL,
                           &ieKeySession);
    dbg_trace("Called C_OpenSession() to create the session for the "
              "import/export key (returned " GREPABLE(CKR) ")", ret);
    if (ret != CKR_OK) {
        return ret;
    }

    CK_OBJECT_CLASS kClass = CKO_SECRET_KEY;
    CK_ULONG kLen = 256 >> 3;
    CK_MECHANISM mechanisms[] = {
        { .mechanism=CKM_AES_KEY_GEN, .pParameter=NULL, .ulParameterLen=0 },
    };
    CK_ATTRIBUTE attributes[] = {
        { .type=CKA_CLASS,     .pValue=&kClass, .ulValueLen=sizeof(kClass) },
        { .type=CKA_VALUE_LEN, .pValue=&kLen,   .ulValueLen=sizeof(kLen)   },
    };
    ret = o->C_GenerateKey(ieKeySession, mechanisms, attributes,
                           sizeof(attributes) / sizeof(CK_ATTRIBUTE), &ieKey);
    dbg_trace("Called C_GenerateKey() to create the import/export key "
              "(returned " GREPABLE(CKR) ")", ret);
    return ret;
}

CK_RV C_Initialize(
  CK_VOID_PTR pInitArgs
) {
    CK_RV ret = o->C_Initialize(pInitArgs);
    dbg_trace("Forwarded to original function (returned " GREPABLE(CKR) "), "
              "pInitArgs = " HEX64, ret, (uintptr_t)pInitArgs);
    if (ret == CKR_OK) {
        // After loading this native library, the SunPKCS11 constructor calls
        // PKCS11::getInstance(), which is a synchronized method. This method
        // invokes C_Initialize(), so by calling initializeImporterExporter()
        // at this point (inside the C_Initialize() implementation), we are
        // guaranteed that the importer/exporter initialization will not be
        // concurrently executed.
        if (initializeImporterExporter(o) != CKR_OK) {
            ret = CKR_GENERAL_ERROR;
        }
    }
    return ret;
}

#pragma GCC visibility pop

/* ****************************************************************************
 * Exported/Public functions
 * ****************************************************************************/

WITH_FIPS_PROTOTYPE(CK_RV, C_GetInterface,
  CK_UTF8CHAR_PTR pInterfaceName,
  CK_VERSION_PTR pVersion,
  CK_INTERFACE_PTR_PTR ppInterface,
  CK_FLAGS flags
) {
    dbg_trace("Parameters:\npInterfaceName = \"%s\", pVersion = " HEX64
              ", ppInterface = " HEX64 ", flags = %lu", pInterfaceName,
              (uintptr_t)pVersion, (uintptr_t)ppInterface, flags);
    if (pInterfaceName != NULL) {
        dbg_trace("Only the default interface is supported by this adapter");
        return CKR_GENERAL_ERROR;
    }
    if (decoratedInterface.pFunctionList == &decoratedFunctionList) {
        // Already initialized
        *ppInterface = &decoratedInterface;
        return CKR_OK;
    }

    CK_RV ret = FC_GetInterface(pInterfaceName, pVersion, ppInterface, flags);
    if (ret == CKR_OK) {
        // Save non-decorated original function list, for this wrapper's use
        o = (*ppInterface)->pFunctionList;

        // Clone returned structures
        memcpy(&decoratedInterface, *ppInterface, sizeof(decoratedInterface));
        memcpy(&decoratedFunctionList, o, o->version.major == 3 ?
               sizeof(CK_FUNCTION_LIST_3_0) : sizeof(CK_FUNCTION_LIST));

        // Decorate functions
        decoratedFunctionList.C_CreateObject = C_CreateObject;
        decoratedFunctionList.C_GetAttributeValue = C_GetAttributeValue;
        decoratedFunctionList.C_Initialize = C_Initialize;

        // Update pointers
        decoratedInterface.pFunctionList = &decoratedFunctionList;
        *ppInterface = &decoratedInterface;
        dbg_trace("NSS PKCS #11 v%d.%d, software token successfully "
                  "adapted", o->version.major, o->version.minor);
    }
    return ret;
}

WITH_FIPS_PROTOTYPE(CK_RV, C_GetFunctionList,
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList
) {
    dbg_trace("Only the C_GetInterface() API is supported by this adapter "
              "(ppFunctionList = " HEX64 ")", (uintptr_t)ppFunctionList);
    *ppFunctionList = NULL;
    return CKR_GENERAL_ERROR;
}

/* ****************************************************************************
 * Library constructor/destructor
 * ****************************************************************************/

static void CONSTRUCTOR_FUNCTION library_constructor(void) {
    dbg_initialize();
}

static void DESTRUCTOR_FUNCTION library_destructor(void) {
    // Destroy import/export key, if created
    if (ieKeySession != CK_INVALID_HANDLE) {
        o->C_CloseSession(ieKeySession);
    }
}
