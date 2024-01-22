// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef P11_UTIL_H
#define P11_UTIL_H

#include <nss3/pkcs11.h>

// (pTemplate, ulCount) attributes iterator, with automatic debug traces
#define FOREACH_ATTRIBUTE_START(attr)                                          \
    CK_ATTRIBUTE_PTR attr = NULL;                                              \
    for (CK_ULONG i = 0; i < ulCount; i++) {                                   \
        attr = &pTemplate[i];                                                  \
        dbg_trace(#attr ": type = " HEX32 ", pValue = " HEX64                  \
                  ", ulValueLen = %lu",                                        \
                  attr != NULL ? attr->type              : 0,                  \
                  attr != NULL ? (uintptr_t)attr->pValue : (uintptr_t)0,       \
                  attr != NULL ? attr->ulValueLen        : 0);                 \

#define FOREACH_ATTRIBUTE_END }

#define IS_KEY_TYPE(expectedClass, expectedType)                               \
    isKeyType(hSession, hObject, ORIGINAL(C_GetAttributeValue),                \
              expectedClass, expectedType)

static inline CK_BBOOL isKeyType(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_C_GetAttributeValue C_GetAttributeValue,
  CK_OBJECT_CLASS expectedClass,
  CK_KEY_TYPE expectedType
) {
    CK_OBJECT_CLASS kClass;
    CK_KEY_TYPE kType;
    CK_ATTRIBUTE attrs[] = {
        { .type=CKA_CLASS,    .pValue=&kClass, .ulValueLen=sizeof(kClass) },
        { .type=CKA_KEY_TYPE, .pValue=&kType,  .ulValueLen=sizeof(kType)  },
    };
    CK_RV ret = C_GetAttributeValue(hSession, hObject, attrs,
                                    sizeof(attrs) / sizeof(CK_ATTRIBUTE));
    dbg_trace("kClass = " HEX32 " (expected: " HEX32 "), kType = " HEX32
              " (expected: " HEX32 ")", kClass, expectedClass, kType,
              expectedType);
    return ret == CKR_OK && kClass == expectedClass && kType == expectedType;
}

static inline void getBBoolAttr(
  CK_ATTRIBUTE_PTR attr,
  CK_ATTRIBUTE_TYPE expected_type,
  CK_BBOOL** out
) {
    if (attr != NULL && attr->type == expected_type &&
        attr->ulValueLen == sizeof(CK_BBOOL) && attr->pValue != NULL) {
        *out = attr->pValue;
    }
}

static inline CK_BBOOL isUnavailableInformation(CK_ATTRIBUTE_PTR attr) {
    return attr != NULL && attr->ulValueLen == CK_UNAVAILABLE_INFORMATION;
}

#endif // P11_UTIL_H
