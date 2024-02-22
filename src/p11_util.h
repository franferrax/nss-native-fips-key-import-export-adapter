// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef P11_UTIL_H
#define P11_UTIL_H

#include "nssadapter.h"
#include <memory.h>
#include <nss3/lowkeyi.h>
#include <nss3/pkcs11.h>
#include <stdbool.h>
#include <stdlib.h>

#define FIPS_SLOT_ID 3

// Qualify the printed value with its macro prefix, so we can copy the printed
// REGEX and execute `grep -irE "^\s*#define\s+$(xclip -sel clip)" /usr/include`
// to know the defined value
#define __grep_able(prefix) #prefix "_.*0x%08lx"
#define CKA_FMT             __grep_able(CKA)
#define CKK_FMT             __grep_able(CKK)
#define CKO_FMT             __grep_able(CKO)
#define CKR_FMT             __grep_able(CKR)

// Get the length of a fixed-size (stack / global) attributes array
#define attrs_count(attributes) (sizeof(attributes) / sizeof(CK_ATTRIBUTE))

// Load the return value in the 'ret' variable and jump to the 'cleanup' label
#define return_with_cleanup(return_value)                                      \
    do {                                                                       \
        ret = (return_value);                                                  \
        goto cleanup;                                                          \
    } while (0)

// Handle convention described in PKCS #11 v3.0 Section 5.2 on producing output
#define p11_allocation_idiom(P11_Func, data, data_len, ...)                    \
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

// Log a CK_ATTRIBUTE with all its fields and data
#define dbg_trace_attr(message, attr)                                          \
    do {                                                                       \
        if (dbg_is_enabled()) {                                                \
            if ((attr).ulValueLen == CK_UNAVAILABLE_INFORMATION) {             \
                dbg_trace("%s:\n  type = " CKA_FMT ", pValue = %p, "           \
                          "ulValueLen = CK_UNAVAILABLE_INFORMATION",           \
                          (message), (attr).type, (attr).pValue);              \
            } else {                                                           \
                dbg_trace("%s:\n  type = " CKA_FMT ", pValue = %p, "           \
                          "ulValueLen = %lu",                                  \
                          (message), (attr).type, (attr).pValue,               \
                          (attr).ulValueLen);                                  \
                if (should_dump_attr_value((attr).type)) {                     \
                    dbg_trace_hex((attr).pValue, (attr).ulValueLen);           \
                }                                                              \
            }                                                                  \
        }                                                                      \
    } while (0)

static inline bool should_dump_attr_value(UNUSED CK_ATTRIBUTE_TYPE type) {
    return true
#ifndef DEBUG
// Do not dump attribute value if sensitive
#define for_each_sensitive_attr(idx, sensitive_attr_type)                      \
    &&type != sensitive_attr_type
#include "sensitive_attributes.h"
#undef for_each_sensitive_attr
#endif
        ;
}

static inline bool
allocate_PrivateKeyInfo_and_PrivateKey(PLArenaPool *arena,
                                       NSSLOWKEYPrivateKeyInfo **pki,
                                       NSSLOWKEYPrivateKey **lpk) {
    *pki = PORT_ArenaZAlloc(arena, sizeof(NSSLOWKEYPrivateKeyInfo));
    if (*pki == NULL) {
        return false;
    }
    *lpk = PORT_ArenaZAlloc(arena, sizeof(NSSLOWKEYPrivateKey));
    if (*lpk == NULL) {
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
