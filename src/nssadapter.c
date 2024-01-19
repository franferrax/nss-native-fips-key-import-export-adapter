// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "nssadapter.h"
#include <stdint.h>
#include <dlfcn.h>
#include <nss3/pkcs11.h>

/* ****************************************************************************
 * PKCS #11 and symbol decorator macros
 * ****************************************************************************/

// Define a name for a pointer type that corresponds with a function
#define FUNC_TYPE(name) name ## _PTR

// Get the name of the saved original wrapped/decorated function
#define ORIGINAL(name)  name ## _Original

// Declare a function wrapper/decorator, along with a function pointer
// to keep a reference to the original wrapped/decorated function
#define DECLARE_DECORATOR(ret_type, name, ...)                                 \
    typedef ret_type (*FUNC_TYPE(name))(__VA_ARGS__);                          \
    static FUNC_TYPE(name) ORIGINAL(name) = NULL;                              \
    ret_type name(__VA_ARGS__)

// Apply a declared function wrapper/decorator to a function list
#define DECORATE_FUNCTION_LIST(name, pFunctionList) do {                       \
    ORIGINAL(name) = (pFunctionList)->name;                                    \
    (pFunctionList)->name = name;                                              \
    dbg_trace("Decorated " #name " (" HEX64 ", replaced by " HEX64 ")",        \
              (uintptr_t)ORIGINAL(name), (uintptr_t)name);                     \
} while(0)

// Save the original wrapped/decorated imported symbol (to be called at load)
#define SAVE_ORIGINAL_SYMBOL(lib, name) do {                                   \
    ORIGINAL(name) = (FUNC_TYPE(name)) __resolve("lib" #lib ".so", #name);     \
    dbg_trace("Saved original " #name " (" HEX64 ", replaced by " HEX64 ")",   \
              (uintptr_t)ORIGINAL(name), (uintptr_t)name);                     \
} while(0)

// Do not call directly, use SAVE_ORIGINAL_SYMBOL(lib, name) instead
static void (*  __resolve(const char *lib_name, const char *symbol)  )(void) {
    void *handle = dlopen(lib_name, RTLD_NOLOAD | RTLD_LAZY | RTLD_LOCAL);
    void *func = NULL;
    if (handle) {
        func = dlsym(handle, symbol);
        dlclose(handle);
    }
    dbg_trace(handle ? ( func ? "Opened %s, and successfully resolved %s" :
              "Opened %s, but could not resolve %s, " WILL_CRASH ) :
              "Could not open %s, " WILL_CRASH, lib_name, symbol);
    // Temporarily allow casting a data pointer to a function pointer.
    // By returning a generic void(*f)(void) function pointer, we make
    // sure a later cast to another function pointer will not fail.
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wpedantic"
    return func;
    #pragma GCC diagnostic pop
}

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

DECLARE_DECORATOR(CK_RV, FC_GetInterface,
  CK_UTF8CHAR_PTR pInterfaceName,
  CK_VERSION_PTR pVersion,
  CK_INTERFACE_PTR_PTR ppInterface,
  CK_FLAGS flags
) {
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
