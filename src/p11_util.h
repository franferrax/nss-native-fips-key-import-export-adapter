// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef P11_UTIL_H
#define P11_UTIL_H

#include "nssadapter.h"
#include <lowkeyi.h>
#include <memory.h>
#include <pkcs11.h>
#include <stdbool.h>
#include <stdlib.h>

#define FIPS_SLOT_ID 3

// Qualifies a value with a prefix such that the final text we can be copied to
// the clipboard and used for the following command:
//   grep -irE "^\s*#define\s+$(xclip -sel clip)" /usr/include
// This is used to match CK constants to their definition.
#define __greppable(prefix) #prefix "_.*0x%08lx"
#define CKA_FMT             __greppable(CKA) // CK_ATTRIBUTE_TYPE
#define CKK_FMT             __greppable(CKK) // CK_KEY_TYPE
#define CKO_FMT             __greppable(CKO) // CK_OBJECT_CLASS
#define CKR_FMT             __greppable(CKR) // CK_RV (return value)

// Gets the length of a fixed-size (stack / global) attributes array.
#define attrs_count(attributes) (sizeof(attributes) / sizeof(CK_ATTRIBUTE))

// Loads the return value in the 'ret' variable and jump to the 'cleanup' label.
#define return_with_cleanup(return_value)                                      \
    do {                                                                       \
        ret = (return_value);                                                  \
        goto cleanup;                                                          \
    } while (0)

// Implements the "Conventions for functions returning output
// in a variable-length buffer" (PKCS #11 v3.0 Section 5.2).
#define p11_call_with_allocation(P11_Func, data, data_len, ...)                \
    do {                                                                       \
        ret = P11_Func(__VA_ARGS__, NULL, &(data_len));                        \
        if (ret != CKR_OK) {                                                   \
            dbg_trace(#P11_Func "() has failed with ret = " CKR_FMT, ret);     \
            return_with_cleanup(CKR_GENERAL_ERROR);                            \
        }                                                                      \
        (data) = malloc(data_len);                                             \
        if ((data) == NULL) {                                                  \
            dbg_trace("Ran out of memory for the " #P11_Func "() call");       \
            return_with_cleanup(CKR_HOST_MEMORY);                              \
        }                                                                      \
        ret = P11_Func(__VA_ARGS__, (data), &(data_len));                      \
    } while (0)

static inline bool
allocate_PrivateKeyInfo_and_PrivateKey(PLArenaPool *arena,
                                       NSSLOWKEYPrivateKeyInfo **pki,
                                       NSSLOWKEYPrivateKey **lpk) {
    *pki = PORT_ArenaZAlloc(arena, sizeof(NSSLOWKEYPrivateKeyInfo));
    if (*pki == NULL) {
        dbg_trace("Failed to allocate NSSLOWKEYPrivateKeyInfo");
        return false;
    }
    *lpk = PORT_ArenaZAlloc(arena, sizeof(NSSLOWKEYPrivateKey));
    if (*lpk == NULL) {
        dbg_trace("Failed to allocate NSSLOWKEYPrivateKey");
        return false;
    }
    (*lpk)->arena = arena;

    return true;
}

static inline void zeroize_and_free(void *ptr, size_t len) {
    memset(ptr, 0, len);
    free(ptr);
}

#endif // P11_UTIL_H
