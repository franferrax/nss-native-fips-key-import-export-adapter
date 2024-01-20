// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef DECORATOR_H
#define DECORATOR_H

#include "nssadapter.h"
#include <dlfcn.h>

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

#endif // DECORATOR_H
