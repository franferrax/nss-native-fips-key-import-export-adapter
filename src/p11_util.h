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
                dbg_trace_hex((attr).pValue, (attr).ulValueLen);               \
            }                                                                  \
        }                                                                      \
    } while (0)

static inline bool get_key_type_from_object(CK_SESSION_HANDLE session,
                                            CK_OBJECT_HANDLE key_id,
                                            CK_OBJECT_CLASS *key_class,
                                            CK_KEY_TYPE *key_type) {
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS,    key_class, sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE, key_type,  sizeof(CK_KEY_TYPE)    },
    };
    CK_RV ret = P11.C_GetAttributeValue(session, key_id, attributes,
                                        attrs_count(attributes));
    if (ret == CKR_OK) {
        dbg_trace("key: id = %lu, class = " CKO_FMT ", type = " CKK_FMT, key_id,
                  *key_class, *key_type);
        return true;
    } else {
        dbg_trace("C_GetAttributeValue call failed with ret = " CKR_FMT, ret);
        return false;
    }
}

static inline bool get_key_type_from_attrs(CK_OBJECT_CLASS *key_class,
                                           CK_KEY_TYPE *key_type,
                                           CK_ATTRIBUTE_PTR attributes,
                                           CK_ULONG n_attributes) {
    bool has_key_class = false;
    bool has_key_type = false;
    for (size_t n = 0; n < n_attributes; n++) {
        if (attributes[n].pValue != NULL) {
            if (attributes[n].type == CKA_CLASS &&
                attributes[n].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
                *key_class = *((CK_OBJECT_CLASS *)attributes[n].pValue);
                has_key_class = true;
                if (has_key_type) {
                    break;
                }
            } else if (attributes[n].type == CKA_KEY_TYPE &&
                       attributes[n].ulValueLen == sizeof(CK_KEY_TYPE)) {
                *key_type = *((CK_KEY_TYPE *)attributes[n].pValue);
                has_key_type = true;
                if (has_key_class) {
                    break;
                }
            }
        }
    }
    if (dbg_is_enabled()) {
        if (has_key_class && has_key_type) {
            dbg_trace("key: class = " CKO_FMT ", type = " CKK_FMT, *key_class,
                      *key_type);
        } else if (has_key_class) {
            dbg_trace("key: class = " CKO_FMT ", type = NONE", *key_class);
        } else if (has_key_type) {
            dbg_trace("key: class = NONE, type = " CKK_FMT, *key_type);
        } else {
            dbg_trace("key: class = NONE, type = NONE");
        }
    }
    return has_key_class && has_key_type;
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
