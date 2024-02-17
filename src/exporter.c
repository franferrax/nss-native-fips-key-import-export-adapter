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
    {CKA_VALUE,            NULL, 0},
    {CKA_PRIVATE_EXPONENT, NULL, 0},
    {CKA_PRIME_1,          NULL, 0},
    {CKA_PRIME_2,          NULL, 0},
    {CKA_EXPONENT_1,       NULL, 0},
    {CKA_EXPONENT_2,       NULL, 0},
    {CKA_COEFFICIENT,      NULL, 0},
};

static inline CK_ATTRIBUTE_PTR
get_sensitive_cached_attr(CK_ATTRIBUTE_TYPE type) {
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

static CK_RV decode_and_store_secret_key(CK_BYTE_PTR *encoded_key,
                                         CK_ULONG encoded_key_len) {
    CK_ATTRIBUTE_PTR cached_attr = get_sensitive_cached_attr(CKA_VALUE);
    cached_attr->ulValueLen = encoded_key_len;
    cached_attr->pValue = *encoded_key;
    // Transfer ownership to the above assignation to cached_attr->pValue:
    *encoded_key = NULL;
    return CKR_OK;
}

static CK_RV decode_and_store_private_key(CK_KEY_TYPE key_type,
                                          CK_BYTE_PTR *encoded_key,
                                          CK_ULONG encoded_key_len) {
    switch (key_type) {
    case CKK_RSA:
        // TODO: implement
        return CKR_GENERAL_ERROR;
    case CKK_DSA:
        // TODO: implement
        return CKR_GENERAL_ERROR;
    case CKK_EC:
        // TODO: implement
        return CKR_GENERAL_ERROR;
    default:
        dbg_trace("Unknown key type: " CKK_FMT, key_type);
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

static CK_RV export_and_store_key_in_tls(CK_OBJECT_CLASS key_class,
                                         CK_KEY_TYPE key_type,
                                         CK_OBJECT_HANDLE key_id) {
    CK_RV ret = CKR_OK;
    CK_BYTE_PTR encoded_key = NULL;
    CK_ULONG encoded_key_len = 0;
    CK_BYTE_PTR encrypted_key = NULL;
    CK_ULONG encrypted_key_len = 0;

    // Wrap
    p11_allocation_idiom(P11.C_WrapKey, encrypted_key, encrypted_key_len,
                         IE.session, &IE.mech, IE.key_id, key_id);
    dbg_trace("Called C_WrapKey() to export the key (returned " CKR_FMT
              "), wrapped key len = %lu",
              ret, encrypted_key_len);
    if (ret != CKR_OK) {
        goto cleanup;
    }

    // Decrypt
    ret = P11.C_DecryptInit(IE.session, &IE.mech, IE.key_id);
    if (ret != CKR_OK) {
        dbg_trace("C_DecryptInit has failed with " CKR_FMT, ret);
        goto cleanup;
    }
    p11_allocation_idiom(P11.C_Decrypt, encoded_key, encoded_key_len,
                         IE.session, encrypted_key, encrypted_key_len);
    dbg_trace("Called C_Decrypt() to export the key (returned " CKR_FMT
              "), encoded key len = %lu",
              ret, encoded_key_len);
    if (ret != CKR_OK) {
        goto cleanup;
    }

    // Decode and fix attributes template
    switch (key_class) {
    case CKO_SECRET_KEY:
        ret = decode_and_store_secret_key(&encoded_key, encoded_key_len);
        break;
    case CKO_PRIVATE_KEY:
        ret = decode_and_store_private_key(key_type, &encoded_key,
                                           encoded_key_len);
        break;
    default:
        dbg_trace("Unknown key class");
        ret = CKR_GENERAL_ERROR;
        break;
    }
cleanup:
    if (encrypted_key != NULL) {
        free(encrypted_key);
    }
    if (encoded_key != NULL) {
        free(encoded_key);
    }
    return ret;
}

CK_RV export_key(CK_OBJECT_CLASS key_class, CK_KEY_TYPE key_type,
                 CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key_id,
                 CK_ATTRIBUTE_PTR attributes, CK_ULONG n_attributes) {
    CK_RV ret =
        P11.C_GetAttributeValue(session, key_id, attributes, n_attributes);
    dbg_trace("Forwarded to original function (returned " CKR_FMT "), "
              "parameters:\nsession = 0x%08lx, key_id = %lu, "
              "attributes = %p, n_attributes = %lu",
              ret, session, key_id, (void *)attributes, n_attributes);
    if (dbg_is_enabled()) {
        for (size_t n = 0; n < n_attributes; n++) {
            dbg_trace_attr("Attribute returned by NSS C_GetAttributeValue()",
                           attributes[n]);
        }
    }
    if (ret == CKR_OK && n_attributes >= 3) {
        CK_BBOOL *token = NULL;
        CK_BBOOL *sensitive = NULL;
        CK_BBOOL *extractable = NULL;
        for (size_t n = 0; n < n_attributes; n++) {
            get_matching_bool(attributes[n], CKA_TOKEN, token);
            get_matching_bool(attributes[n], CKA_SENSITIVE, sensitive);
            get_matching_bool(attributes[n], CKA_EXTRACTABLE, extractable);
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
                if (!(key_class == CKO_PRIVATE_KEY && key_type == CKK_DH)) {
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
        for (size_t n = 0; n < n_attributes; n++) {
            if (attributes[n].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                cached_attr = get_sensitive_cached_attr(attributes[n].type);
                if (cached_attr == NULL) {
                    dbg_trace("Unknown sensitive attribute");
                    return CKR_GENERAL_ERROR;
                }
                if (attributes[n].pValue == NULL) {
                    // First call, Java is querying the buffer sizes
                    if (cached_attr->pValue == NULL) {
                        ret = export_and_store_key_in_tls(key_class, key_type,
                                                          key_id);
                        if (ret != CKR_OK) {
                            return CKR_GENERAL_ERROR;
                        }
                    }
                    dbg_trace("Changing ulValueLen = CK_UNAVAILABLE_INFORMATION"
                              " to ulValueLen = %lu",
                              cached_attr->ulValueLen);
                    attributes[n].ulValueLen = cached_attr->ulValueLen;
                } else {
                    // Second call, Java has allocated the buffers and
                    // is trying to retrieve the attribute values
                    if (cached_attr->pValue == NULL) {
                        dbg_trace("No exported key is available to return");
                        return CKR_GENERAL_ERROR;
                    }
                    dbg_trace("Copying pValue %p -> %p",
                              (void *)cached_attr->pValue,
                              (void *)attributes[n].pValue);
                    // NOTE: here we trust that the Java layer only called
                    // us if it managed to allocate attributes[n].pValue with
                    // the length we returned in attributes[n].ulValueLen, in
                    // the previous call. Otherwise, we should check
                    // attributes[n].ulValueLen before forwarding the call to
                    // NSS' FC_GetAttributeValue(), which overwrites the
                    // received value with CK_UNAVAILABLE_INFORMATION.
                    attributes[n].ulValueLen = cached_attr->ulValueLen;
                    memcpy(attributes[n].pValue, cached_attr->pValue,
                           attributes[n].ulValueLen);
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
