// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "nssadapter.h"
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
 * Library constructor and destructor
 * ****************************************************************************/

void CONSTRUCTOR_FUNCTION library_constructor(void) {
    // TODO: create wrapper keys for import/export workaround
}

void DESTRUCTOR_FUNCTION library_destructor(void) {
    // TODO: destroy wrapper keys
}
