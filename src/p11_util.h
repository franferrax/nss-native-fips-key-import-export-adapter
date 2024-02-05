// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef P11_UTIL_H
#define P11_UTIL_H

#include <nss3/pkcs11.h>

#define FIPS_SLOT_ID 3

// Define a function having its NSS FIPS prototype (FC_... proto + C_... func)
#define WITH_FIPS_PROTOTYPE(ret_type, name, ...)                               \
    ret_type F ## name(__VA_ARGS__);                                           \
    ret_type name(__VA_ARGS__)

// Qualify the printed value with its macro prefix, so we can copy the printed
// REGEX and execute `grep -rE "^\s*#define\s+$(xclip -sel clip)" /usr/include`
// to know the defined value
#define GREPABLE(prefix) #prefix "_.*" HEX32

#define dbg_trace_attr(attr) do {                                              \
    dbg_trace((attr) == NULL ? "ATTR: NULL" : (                                \
                (attr)->ulValueLen == CK_UNAVAILABLE_INFORMATION ?             \
                  "ATTR: type = " GREPABLE(CKA) ", pValue = " HEX64            \
                  ", ulValueLen = CK_UNAVAILABLE_INFORMATION" :                \
                  "ATTR: type = " GREPABLE(CKA) ", pValue = " HEX64            \
                  ", ulValueLen = %lu"                                         \
                ),                                                             \
              (attr) == NULL ? 0 : (attr)->type,                               \
              (attr) == NULL ? 0 : (uintptr_t)(attr)->pValue,                  \
              (attr) == NULL ? 0 : (attr)->ulValueLen);                        \
} while(0)

static inline CK_BBOOL isKeyType(
  CK_FUNCTION_LIST_PTR o,
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_OBJECT_CLASS expectedClass,
  CK_KEY_TYPE expectedType
) {
    CK_OBJECT_CLASS kClass;
    CK_KEY_TYPE kType;
    CK_ATTRIBUTE attrs[] = {
        { .type=CKA_CLASS,    .pValue=&kClass, .ulValueLen=sizeof(kClass) },
        { .type=CKA_KEY_TYPE, .pValue=&kType,  .ulValueLen=sizeof(kType)  },
    };
    CK_RV ret = o->C_GetAttributeValue(hSession, hObject, attrs,
                                       sizeof(attrs) / sizeof(CK_ATTRIBUTE));
    dbg_trace("kClass = " GREPABLE(CKO) " (expected: " GREPABLE(CKO) "), "
              "kType = " GREPABLE(CKK) " (expected: " GREPABLE(CKK) ")",
              kClass, expectedClass, kType, expectedType);
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
