// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "nssadapter.h"
#include "decorator.h"
#include "p11_util.h"
#include <stdint.h>
#include <nss3/pkcs11.h>

/* ****************************************************************************
 * Internal/Private functions
 * ****************************************************************************/
#pragma GCC visibility push(hidden)

DECLARE_DECORATOR(CK_RV, C_CreateObject,
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phObject
) {
    CK_RV ret = ORIGINAL(C_CreateObject)(hSession, pTemplate,
                                         ulCount, phObject);
    dbg_trace("Forwarded to original function (returned " HEX32 "), parameters:"
              "\nhSession = " HEX32 ", pTemplate = " HEX64 ", ulCount = %lu"
              ", phObject = " HEX64, ret, hSession, (uintptr_t)pTemplate,
              ulCount, (uintptr_t)phObject);
    return ret;
}

DECLARE_DECORATOR(CK_RV, C_GetAttributeValue,
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
) {
    CK_RV ret = ORIGINAL(C_GetAttributeValue)(hSession, hObject,
                                              pTemplate, ulCount);
    dbg_trace("Forwarded to original function (returned " HEX32 "), parameters:"
              "\nhSession = " HEX32 ", hObject = %lu, pTemplate = " HEX64
              ", ulCount = %lu", ret, hSession, hObject, (uintptr_t)pTemplate,
              ulCount);
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
                if (!IS_KEY_TYPE(CKO_PRIVATE_KEY, CKK_DH)) {
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

DECLARE_DECORATOR(CK_RV, FC_GetInterface,
  CK_UTF8CHAR_PTR pInterfaceName,
  CK_VERSION_PTR pVersion,
  CK_INTERFACE_PTR_PTR ppInterface,
  CK_FLAGS flags
) {
    dbg_trace("Parameters:\npInterfaceName = \"%s\", pVersion = " HEX64
              ", ppInterface = " HEX64 ", flags = %lu", pInterfaceName,
              (uintptr_t)pVersion, (uintptr_t)ppInterface, flags);
    CK_RV ret = ORIGINAL(FC_GetInterface)(pInterfaceName, pVersion,
                                          ppInterface, flags);
    if (ret == CKR_OK) {
        // NOTE: the PKCS #11 v3.0 standard states 'CK_FUNCTION_LIST_3_0
        // is a structure which contains the same function pointers as in
        // CK_FUNCTION_LIST and additional functions added to the end of
        // the structure that were defined in Cryptoki version 3.0'. This
        // implies that we can safely use CK_FUNCTION_LIST regardless of
        // the version, as long as it contains all the functions we need
        // to decorate, which is our case.
        CK_FUNCTION_LIST_PTR pFunctionList = (*ppInterface)->pFunctionList;
        DECORATE_FUNCTION_LIST(C_CreateObject, pFunctionList);
        DECORATE_FUNCTION_LIST(C_GetAttributeValue, pFunctionList);
        dbg_trace("NSS PKCS #11 v%d.%d, software token successfully adapted",
                  pFunctionList->version.major, pFunctionList->version.minor);
    }
    return ret;
}

DECLARE_DECORATOR(CK_RV, FC_GetFunctionList,
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList
) {
    dbg_trace("Parameters: ppFunctionList = " HEX64, (uintptr_t)ppFunctionList);
    CK_RV ret = ORIGINAL(FC_GetFunctionList)(ppFunctionList);
    if (ret == CKR_OK) {
        DECORATE_FUNCTION_LIST(C_CreateObject, *ppFunctionList);
        DECORATE_FUNCTION_LIST(C_GetAttributeValue, *ppFunctionList);
        dbg_trace("NSS PKCS #11, software token successfully adapted");
    }
    return ret;
}

// Force FIPS setup
CK_RV C_GetInterface(
  CK_UTF8CHAR_PTR pInterfaceName,
  CK_VERSION_PTR pVersion,
  CK_INTERFACE_PTR_PTR ppInterface,
  CK_FLAGS flags
) {
    return FC_GetInterface(pInterfaceName, pVersion, ppInterface, flags);
}

CK_RV C_GetFunctionList(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList
) {
    return FC_GetFunctionList(ppFunctionList);
}

/* ****************************************************************************
 * Library constructor and destructor
 * ****************************************************************************/

void CONSTRUCTOR_FUNCTION library_constructor(void) {
    SAVE_ORIGINAL_SYMBOL(softokn3, FC_GetInterface);
    SAVE_ORIGINAL_SYMBOL(softokn3, FC_GetFunctionList);
    // TODO: create wrapper keys for import/export workaround
}

void DESTRUCTOR_FUNCTION library_destructor(void) {
    // TODO: destroy wrapper keys
}
