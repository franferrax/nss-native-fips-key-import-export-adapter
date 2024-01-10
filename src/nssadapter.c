// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "nssadapter.h"
#include <stdint.h>
#include <nss3/pkcs11.h>

/* ****************************************************************************
 * PKCS #11 Decorator macros
 * ****************************************************************************/

// Get the name of the saved original wrapped/decorated function
#define ORIGINAL(name)  name ## _Original

// Get the name of the wrapper/decorator function
#define DECORATOR(name) name ## _Decorator

// Declare a function wrapper/decorator, along with a function pointer
// to keep a reference to the original wrapped/decorated function
#define DECLARE_DECORATOR(ret_type, name, ...)                                 \
    static ret_type (*ORIGINAL(name))(__VA_ARGS__) = NULL;                     \
    ret_type DECORATOR(name)(__VA_ARGS__)

// Apply a declared function wrapper/decorator to a function list
#define DECORATE(name, pFunctionList) do {                                     \
    ORIGINAL(name) = (pFunctionList)->name;                                    \
    dbg_trace("Decorating " #name " (replacing " HEX64 " by " HEX64 ")",       \
              (uintptr_t)ORIGINAL(name), (uintptr_t)DECORATOR(name));          \
    (pFunctionList)->name = DECORATOR(name);                                   \
} while(0)

// Define a function having its NSS FIPS prototype (FC_... proto + C_... func)
#define WITH_FIPS_PROTOTYPE(ret_type, name, ...)                               \
    ret_type F ## name(__VA_ARGS__);                                           \
    ret_type name(__VA_ARGS__)


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
    dbg_trace("Forwarding to original function, parameters:"
              "\n   hSession = " HEX32
              "\n  pTemplate = " HEX64
              "\n    ulCount = %lu"
              "\n   phObject = " HEX64,
              hSession, (uintptr_t)pTemplate, ulCount, (uintptr_t)phObject);
    return ORIGINAL(C_CreateObject)(hSession, pTemplate, ulCount, phObject);
}

DECLARE_DECORATOR(CK_RV, C_GetAttributeValue,
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
) {
    dbg_trace("Forwarding to original function, parameters:"
              "\n   hSession = " HEX32
              "\n    hObject = %lu"
              "\n  pTemplate = " HEX64
              "\n    ulCount = %lu",
              hSession, hObject, (uintptr_t)pTemplate, ulCount);
    return ORIGINAL(C_GetAttributeValue)(hSession, hObject, pTemplate, ulCount);
}

#pragma GCC visibility pop


/* ****************************************************************************
 * Exported/Public functions
 * ****************************************************************************/

/*
void CONSTRUCTOR_FUNCTION library_constructor(void) {
    // TODO: create wrapper keys for import/export workaround
    dbg_trace();
}

void DESTRUCTOR_FUNCTION library_destructor(void) {
    // TODO: destroy wrapper keys
    dbg_trace();
}
*/

// Call FIPS implementation of C_GetFunctionList and apply decorations
WITH_FIPS_PROTOTYPE(CK_RV, C_GetFunctionList,
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList
) {
    CK_RV ret = FC_GetFunctionList(ppFunctionList);
    if (ret == CKR_OK) {
        DECORATE(C_CreateObject, *ppFunctionList);
        DECORATE(C_GetAttributeValue, *ppFunctionList);
        dbg_trace("NSS PKCS #11, libsoftokn3.so successfully adapted");
    }
    return ret;
}
