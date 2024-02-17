// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "exporter.h"
#include "dbg_trace.h"
#include "p11_util.h"
#include <limits.h>
#include <nss3/lowkeyi.h>
#include <nss3/secasn1.h>
#include <nss3/secoid.h>

// Thread-local stored exported attributes, to keep them
// from one call (querying the buffer sizes) to the other
// (passing the allocated buffers to get the attributes).
static __thread CK_ATTRIBUTE cached_sensitive_attrs[] = {
    {.type = CKA_VALUE,            .pValue = NULL, .ulValueLen = 0},
    {.type = CKA_PRIVATE_EXPONENT, .pValue = NULL, .ulValueLen = 0},
    {.type = CKA_PRIME_1,          .pValue = NULL, .ulValueLen = 0},
    {.type = CKA_PRIME_2,          .pValue = NULL, .ulValueLen = 0},
    {.type = CKA_EXPONENT_1,       .pValue = NULL, .ulValueLen = 0},
    {.type = CKA_EXPONENT_2,       .pValue = NULL, .ulValueLen = 0},
    {.type = CKA_COEFFICIENT,      .pValue = NULL, .ulValueLen = 0},
};

static CK_ATTRIBUTE_PTR get_sensitive_cached_attr(CK_ATTRIBUTE_TYPE type) {
    switch (type) {
    case CKA_VALUE:
        return &cached_sensitive_attrs[0];
    case CKA_PRIVATE_EXPONENT:
        return &cached_sensitive_attrs[1];
    case CKA_PRIME_1:
        return &cached_sensitive_attrs[2];
    case CKA_PRIME_2:
        return &cached_sensitive_attrs[3];
    case CKA_EXPONENT_1:
        return &cached_sensitive_attrs[4];
    case CKA_EXPONENT_2:
        return &cached_sensitive_attrs[5];
    case CKA_COEFFICIENT:
        return &cached_sensitive_attrs[6];
    default:
        return NULL;
    }
}

static CK_RV exportSecretKey(CK_BYTE_PTR *ppEncodedKey,
                             CK_ULONG encodedKeyLen) {
    CK_ATTRIBUTE_PTR cached_attr = get_sensitive_cached_attr(CKA_VALUE);
    cached_attr->ulValueLen = encodedKeyLen;
    cached_attr->pValue = *ppEncodedKey;
    // Transfer ownership to the above assignation to cached_attr->pValue:
    *ppEncodedKey = NULL;
    return CKR_OK;
}

static CK_RV exportRSAPrivateKey(CK_BYTE_PTR pEncodedKey,
                                 CK_ULONG encodedKeyLen,
                                 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    dbg_trace("pEncodedKey = %p, encodedKeyLen = %lu, pTemplate = %p, "
              "ulCount = %lu",
              (void *)pEncodedKey, encodedKeyLen, (void *)pTemplate, ulCount);
    // TODO: implement
    return CKR_GENERAL_ERROR;
}

static CK_RV exportDSAPrivateKey(CK_BYTE_PTR pEncodedKey,
                                 CK_ULONG encodedKeyLen,
                                 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    dbg_trace("pEncodedKey = %p, encodedKeyLen = %lu, pTemplate = %p, "
              "ulCount = %lu",
              (void *)pEncodedKey, encodedKeyLen, (void *)pTemplate, ulCount);
    // TODO: implement
    return CKR_GENERAL_ERROR;
}

static CK_RV exportECPrivateKey(CK_BYTE_PTR pEncodedKey, CK_ULONG encodedKeyLen,
                                CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    dbg_trace("pEncodedKey = %p, encodedKeyLen = %lu, pTemplate = %p, "
              "ulCount = %lu",
              (void *)pEncodedKey, encodedKeyLen, (void *)pTemplate, ulCount);
    // TODO: implement
    return CKR_GENERAL_ERROR;
}

static CK_RV exportAndStoreKeyInTLS(CK_OBJECT_CLASS keyClass,
                                    CK_KEY_TYPE keyType,
                                    CK_OBJECT_HANDLE hObject,
                                    CK_ATTRIBUTE_PTR pTemplate,
                                    CK_ULONG ulCount) {
    CK_RV ret = CKR_OK;
    CK_BYTE_PTR pEncodedKey = NULL;
    CK_ULONG encodedKeyLen = 0;
    CK_BYTE_PTR pEncryptedKey = NULL;
    CK_ULONG encryptedKeyLen = 0;

    // Wrap
    ALLOCATION_IDIOM(P11.C_WrapKey, pEncryptedKey, encryptedKeyLen, IE.session,
                     &IE.mech, IE.key_id, hObject);
    dbg_trace("Called C_WrapKey() to export the key (returned " CKR_FMT
              "), wrapped key len = %lu",
              ret, encryptedKeyLen);
    if (ret != CKR_OK) {
        goto end;
    }

    // Decrypt
    ret = P11.C_DecryptInit(IE.session, &IE.mech, IE.key_id);
    if (ret != CKR_OK) {
        dbg_trace("C_DecryptInit has failed with " CKR_FMT, ret);
        goto end;
    }
    ALLOCATION_IDIOM(P11.C_Decrypt, pEncodedKey, encodedKeyLen, IE.session,
                     pEncryptedKey, encryptedKeyLen);
    dbg_trace("Called C_Decrypt() to export the key (returned " CKR_FMT
              "), encoded key len = %lu",
              ret, encodedKeyLen);
    if (ret != CKR_OK) {
        goto end;
    }

    // Decode and fix attributes template
    switch (keyClass) {
    case CKO_SECRET_KEY:
        ret = exportSecretKey(&pEncodedKey, encodedKeyLen);
        break;
    case CKO_PRIVATE_KEY:
        switch (keyType) {
        case CKK_RSA:
            ret = exportRSAPrivateKey(pEncodedKey, encodedKeyLen, pTemplate,
                                      ulCount);
            break;
        case CKK_DSA:
            ret = exportDSAPrivateKey(pEncodedKey, encodedKeyLen, pTemplate,
                                      ulCount);
            break;
        case CKK_EC:
            ret = exportECPrivateKey(pEncodedKey, encodedKeyLen, pTemplate,
                                     ulCount);
            break;
        default:
            dbg_trace("Unknown key type");
            ret = CKR_GENERAL_ERROR;
            break;
        }
        break;
    default:
        dbg_trace("Unknown key class");
        ret = CKR_GENERAL_ERROR;
        break;
    }
end:
    if (pEncryptedKey != NULL) {
        free(pEncryptedKey);
    }
    if (pEncodedKey != NULL) {
        free(pEncodedKey);
    }
    return ret;
}

CK_RV export_key(CK_OBJECT_CLASS keyClass, CK_KEY_TYPE keyType,
                 CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    CK_RV ret = P11.C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
    dbg_trace("Forwarded to original function (returned " CKR_FMT "), "
              "parameters:\nhSession = 0x%08lx, hObject = %lu, "
              "pTemplate = %p, ulCount = %lu",
              ret, hSession, hObject, (void *)pTemplate, ulCount);
    if (dbg_is_enabled()) {
        for (CK_ULONG i = 0; i < ulCount; i++) {
            dbg_trace_attr("Attribute returned by NSS C_GetAttributeValue()",
                           pTemplate[i]);
        }
    }
    if (ret == CKR_OK && ulCount >= 3) {
        CK_BBOOL *token = NULL;
        CK_BBOOL *sensitive = NULL;
        CK_BBOOL *extractable = NULL;
        for (CK_ULONG i = 0; i < ulCount; i++) {
            getBBoolAttr(&pTemplate[i], CKA_TOKEN, &token);
            getBBoolAttr(&pTemplate[i], CKA_SENSITIVE, &sensitive);
            getBBoolAttr(&pTemplate[i], CKA_EXTRACTABLE, &extractable);
            if (token != NULL && *token == CK_TRUE) {
                dbg_trace("Without an NSS DB, CKA_TOKEN should always be "
                          "CK_FALSE");
                return CKR_GENERAL_ERROR;
            }
            if ( // For non-sensitive keys, the exporter isn't necessary:
                (sensitive != NULL && *sensitive == CK_FALSE) ||
                // For non-extractable keys, the exporter doesn't work:
                (extractable != NULL && *extractable == CK_FALSE)) {
                break;
            }
            if (token != NULL && sensitive != NULL && extractable != NULL) {
                // Non-token, sensitive and extractable key:
                if (!(keyClass == CKO_PRIVATE_KEY && keyType == CKK_DH)) {
                    // See OPENJDK-824 for reasons behind skipping DH keys
                    dbg_trace("Forcing extractable key to be non-sensitive, "
                              "to prevent an opaque Java key object, which "
                              "does not get certain attributes");
                    *sensitive = CK_FALSE;
                }
                break;
            }
        }
    } else if (ret == CKR_ATTRIBUTE_SENSITIVE) {
        CK_ATTRIBUTE_PTR cached_attr = NULL;
        for (CK_ULONG i = 0; i < ulCount; i++) {
            if (isUnavailableInformation(&pTemplate[i])) {
                cached_attr = get_sensitive_cached_attr(pTemplate[i].type);
                if (cached_attr == NULL) {
                    dbg_trace("Unknown sensitive attribute");
                    return CKR_GENERAL_ERROR;
                }
                if (pTemplate[i].pValue == NULL) {
                    // First call, Java is querying the buffer sizes
                    if (cached_attr->pValue == NULL) {
                        ret = exportAndStoreKeyInTLS(keyClass, keyType, hObject,
                                                     pTemplate, ulCount);
                        if (ret != CKR_OK) {
                            return CKR_GENERAL_ERROR;
                        }
                    }
                    dbg_trace("Changing ulValueLen = CK_UNAVAILABLE_INFORMATION"
                              " to ulValueLen = %lu",
                              cached_attr->ulValueLen);
                    pTemplate[i].ulValueLen = cached_attr->ulValueLen;
                } else {
                    // Second call, Java has allocated the buffers and
                    // is trying to retrieve the attribute values
                    if (cached_attr->pValue == NULL) {
                        dbg_trace("No exported key is available to return");
                        return CKR_GENERAL_ERROR;
                    }
                    dbg_trace("Copying pValue %p -> %p",
                              (void *)cached_attr->pValue,
                              (void *)pTemplate[i].pValue);
                    // NOTE: here we trust that the Java layer only called
                    // us if it managed to allocate pTemplate[i].pValue with
                    // the length we returned in pTemplate[i].ulValueLen, in
                    // the previous call. Otherwise, we should check
                    // pTemplate[i].ulValueLen before forwarding the call to
                    // NSS' FC_GetAttributeValue(), which overwrites the
                    // received value with CK_UNAVAILABLE_INFORMATION.
                    pTemplate[i].ulValueLen = cached_attr->ulValueLen;
                    memcpy(pTemplate[i].pValue, cached_attr->pValue,
                           pTemplate[i].ulValueLen);
                    free(cached_attr->pValue);
                    cached_attr->pValue = NULL;
                    cached_attr->ulValueLen = 0;
                }
            }
        }
        ret = CKR_OK;
    }
    return ret;
}
