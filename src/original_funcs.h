// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef ORIGINAL_FUNCS_H
#define ORIGINAL_FUNCS_H

#include <nss3/pkcs11.h>

#define SAVED(func_name)               CK_ ## func_name func_name
#define SAVED_AND_DECORATED(func_name) SAVED(func_name)

typedef struct {
    #include "original_funcs_list.h"
} original_funcs_t;

#undef SAVED
#undef SAVED_AND_DECORATED
#endif // ORIGINAL_FUNCS_H


#ifdef SAVE_AND_DECORATE_P11_FUNCTIONS

#define SAVED(func_name)               o.func_name = pFunctionList->func_name
#define SAVED_AND_DECORATED(func_name) do {                                    \
    SAVED(func_name);                                                          \
    pFunctionList->func_name = func_name;                                      \
    dbg_trace("Decorated " #func_name " (" HEX64 ", replaced by " HEX64 ")",   \
              (uintptr_t)o.func_name, (uintptr_t)func_name);                   \
} while(0)

#include "original_funcs_list.h"

#undef SAVED
#undef SAVED_AND_DECORATED
#endif // SAVE_AND_DECORATE_P11_FUNCTIONS