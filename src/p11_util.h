// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef P11_UTIL_H
#define P11_UTIL_H

#include <nss3/pkcs11.h>

#define FIPS_SLOT_ID 3

// Qualify the printed value with its macro prefix, so we can copy the printed
// REGEX and execute `grep -irE "^\s*#define\s+$(xclip -sel clip)" /usr/include`
// to know the defined value
#define __grep_able(prefix) #prefix "_.*0x%08lx"
#define CKA_FMT             __grep_able(CKA)
#define CKK_FMT             __grep_able(CKK)
#define CKO_FMT             __grep_able(CKO)
#define CKR_FMT             __grep_able(CKR)

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

// Handle the convention described in PKCS #11 Section 5.2 on producing output
#define ALLOCATION_IDIOM(api, pData, dataLen, ...)                             \
    do {                                                                       \
        ret = api(__VA_ARGS__, NULL, &dataLen);                                \
        if (ret != CKR_OK) {                                                   \
            dbg_trace(#api "() has failed with " CKR_FMT, ret);                \
            goto end;                                                          \
        }                                                                      \
        pData = malloc(dataLen);                                               \
        if (pData == NULL) {                                                   \
            dbg_trace("Ran out of memory for the " #api "() call");            \
            goto end;                                                          \
        }                                                                      \
        ret = api(__VA_ARGS__, pData, &dataLen);                               \
    } while (0)

static inline CK_RV getKeyType(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject,
                               CK_OBJECT_CLASS *pKeyClass,
                               CK_KEY_TYPE *pKeyType) {
    CK_ATTRIBUTE attrs[] = {
        {
         .type = CKA_CLASS,
         .pValue = pKeyClass,
         .ulValueLen = sizeof(CK_OBJECT_CLASS),
         },
        {
         .type = CKA_KEY_TYPE,
         .pValue = pKeyType,
         .ulValueLen = sizeof(CK_KEY_TYPE),
         },
    };
    CK_RV ret = P11.C_GetAttributeValue(hSession, hObject, attrs,
                                        sizeof(attrs) / sizeof(CK_ATTRIBUTE));
    if (ret == CKR_OK) {
        dbg_trace("key ID = %lu, key class = " CKO_FMT ", key type = " CKK_FMT,
                  hObject, *pKeyClass, *pKeyType);
    } else {
        dbg_trace("C_GetAttributeValue call failed with " CKR_FMT, ret);
    }
    return ret;
}

static inline CK_BBOOL isKeyType(CK_SESSION_HANDLE hSession,
                                 CK_OBJECT_HANDLE hObject,
                                 CK_OBJECT_CLASS expectedClass,
                                 CK_KEY_TYPE expectedType) {
    CK_OBJECT_CLASS kClass;
    CK_KEY_TYPE kType;
    return getKeyType(hSession, hObject, &kClass, &kType) == CKR_OK &&
           kClass == expectedClass && kType == expectedType;
}

static inline void getBBoolAttr(CK_ATTRIBUTE_PTR attr,
                                CK_ATTRIBUTE_TYPE expected_type,
                                CK_BBOOL **out) {
    if (attr != NULL && attr->type == expected_type &&
        attr->ulValueLen == sizeof(CK_BBOOL) && attr->pValue != NULL) {
        *out = attr->pValue;
    }
}

static inline CK_BBOOL isUnavailableInformation(CK_ATTRIBUTE_PTR attr) {
    return attr != NULL && attr->ulValueLen == CK_UNAVAILABLE_INFORMATION;
}

#endif // P11_UTIL_H
