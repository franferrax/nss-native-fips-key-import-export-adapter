// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "exporter.h"
#include "dbg_trace.h"
#include "p11_util.h"
#include <limits.h>
#include <lowkeyi.h>
#include <secasn1.h>
#include <secoid.h>

// OpenJDK's libj2pkcs11 follows the "Conventions for functions returning output
// in a variable-length buffer" (PKCS #11 v3.0 Section 5.2). Keep state between
// querying the buffer sizes and executing the actual call in thread-local
// variables.
static __thread bool cached_attrs_initialized = false;
static __thread CK_ATTRIBUTE cached_sensitive_attrs[] = {
#define for_each_sensitive_attr(idx, sensitive_attr_type)                      \
    {.type = sensitive_attr_type, .pValue = NULL, .ulValueLen = 0},
#include "sensitive_attributes.h"
#undef for_each_sensitive_attr
};

static inline CK_ATTRIBUTE_PTR
get_sensitive_cached_attr(CK_ATTRIBUTE_TYPE type) {
    switch (type) {
#define for_each_sensitive_attr(idx, sensitive_attr_type)                      \
    case sensitive_attr_type:                                                  \
        return &cached_sensitive_attrs[idx];
#include "sensitive_attributes.h"
#undef for_each_sensitive_attr
    default:
        return NULL;
    }
}

static inline void clear_sensitive_cached_attrs(void) {
    for (size_t n = 0; n < attrs_count(cached_sensitive_attrs); n++) {
        if (cached_sensitive_attrs[n].pValue != NULL) {
            zeroize_and_free(cached_sensitive_attrs[n].pValue,
                             cached_sensitive_attrs[n].ulValueLen);
            cached_sensitive_attrs[n].pValue = NULL;
        }
        cached_sensitive_attrs[n].ulValueLen = 0;
    }
    cached_attrs_initialized = false;
}

#define __store_cached_attr(attr_type, sec_item_attr)                          \
    do {                                                                       \
        CK_ATTRIBUTE_PTR cached_attr = get_sensitive_cached_attr(attr_type);   \
        if (cached_attr == NULL) {                                             \
            dbg_trace("Cannot store unknown sensitive attribute " #attr_type); \
            return CKR_GENERAL_ERROR;                                          \
        }                                                                      \
        cached_attr->pValue = malloc((sec_item_attr).len);                     \
        if (cached_attr->pValue == NULL) {                                     \
            dbg_trace("Ran out of memory while exporting " #attr_type);        \
            return CKR_HOST_MEMORY;                                            \
        }                                                                      \
        memcpy(cached_attr->pValue, (sec_item_attr).data,                      \
               (sec_item_attr).len);                                           \
        cached_attr->ulValueLen = (sec_item_attr).len;                         \
    } while (0)

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
                                          CK_BYTE_PTR encoded_key,
                                          CK_ULONG encoded_key_len) {
    CK_RV ret = CKR_OK;
    PLArenaPool *arena = NULL;
    NSSLOWKEYPrivateKeyInfo *pki;
    NSSLOWKEYPrivateKey *lpk;

    if (encoded_key_len > UINT_MAX) {
        dbg_trace("Too big encoded key (%lu bytes)", encoded_key_len);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    SECItem encoded_key_item = {.type = siBuffer,
                                .data = encoded_key,
                                .len = (unsigned int)encoded_key_len};

    arena = PORT_NewArena(2048);
    if (arena == NULL) {
        return_with_cleanup(CKR_HOST_MEMORY);
    }
    if (!allocate_PrivateKeyInfo_and_PrivateKey(arena, &pki, &lpk)) {
        return_with_cleanup(CKR_HOST_MEMORY);
    }

    if (SEC_QuickDERDecodeItem(arena, pki, nsslowkey_PrivateKeyInfoTemplate,
                               &encoded_key_item) != SECSuccess) {
        dbg_trace("Failed to decode PKCS #8 private key");
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    SECOidTag alg_tag = SECOID_GetAlgorithmTag(&pki->algorithm);
    switch (key_type) {
    case CKK_RSA:
        // We only care about sensitive attributes. For this reason,
        // SEC_OID_PKCS1_RSA_PSS_SIGNATURE does not need algorithm
        // parameters handling to extract the CKA_PUBLIC_KEY_INFO
        // value: P11.C_GetAttributeValue() already did so.
        if (alg_tag != SEC_OID_PKCS1_RSA_ENCRYPTION &&
            alg_tag != SEC_OID_PKCS1_RSA_PSS_SIGNATURE) {
            dbg_trace("Unexpected key algorithm tag: %u", alg_tag);
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        lpk->keyType = NSSLOWKEYRSAKey;
        prepare_low_rsa_priv_key_for_asn1(lpk);
        if (SEC_QuickDERDecodeItem(arena, lpk, nsslowkey_RSAPrivateKeyTemplate,
                                   &pki->privateKey) != SECSuccess) {
            dbg_trace("Failed to decode PKCS #8 RSA private key");
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        __store_cached_attr(CKA_PRIVATE_EXPONENT, lpk->u.rsa.privateExponent);
        __store_cached_attr(CKA_PRIME_1, lpk->u.rsa.prime1);
        __store_cached_attr(CKA_PRIME_2, lpk->u.rsa.prime2);
        __store_cached_attr(CKA_EXPONENT_1, lpk->u.rsa.exponent1);
        __store_cached_attr(CKA_EXPONENT_2, lpk->u.rsa.exponent2);
        __store_cached_attr(CKA_COEFFICIENT, lpk->u.rsa.coefficient);
        dbg_trace("Successfully decoded RSA private key");
        break;
    case CKK_DSA:
        // We only care about sensitive attributes. For this reason,
        // we don't need to decode the PQG parameters to extract the
        // CKA_PRIME, CKA_SUBPRIME and CKA_BASE attribute values:
        // P11.C_GetAttributeValue() already did so.
        if (alg_tag != SEC_OID_ANSIX9_DSA_SIGNATURE) {
            dbg_trace("Unexpected key algorithm tag: %u", alg_tag);
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        lpk->keyType = NSSLOWKEYDSAKey;
        prepare_low_dsa_priv_key_export_for_asn1(lpk);
        if (SEC_QuickDERDecodeItem(arena, lpk,
                                   nsslowkey_DSAPrivateKeyExportTemplate,
                                   &pki->privateKey) != SECSuccess) {
            dbg_trace("Failed to decode PKCS #8 DSA private key");
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        __store_cached_attr(CKA_VALUE, lpk->u.dsa.privateValue);
        dbg_trace("Successfully decoded DSA private key");
        break;
    case CKK_EC:
        // We only care about sensitive attributes. For this reason, we don't
        // need to copy lpk->u.ec.ecParams.DEREncoding to set the CKA_EC_PARAMS
        // attribute value: P11.C_GetAttributeValue() already did so.
        if (alg_tag != SEC_OID_ANSIX962_EC_PUBLIC_KEY) {
            dbg_trace("Unexpected key algorithm tag: %u", alg_tag);
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        lpk->keyType = NSSLOWKEYECKey;
        prepare_low_ec_priv_key_for_asn1(lpk);
        if (SEC_QuickDERDecodeItem(arena, lpk, nsslowkey_ECPrivateKeyTemplate,
                                   &pki->privateKey) != SECSuccess) {
            dbg_trace("Failed to decode PKCS #8 EC private key");
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        __store_cached_attr(CKA_VALUE, lpk->u.ec.privateValue);
        dbg_trace("Successfully decoded EC private key");
        break;
    default:
        dbg_trace("This should never happen, given is_importable_exportable() "
                  "was previously called\n  key_type = " CKK_FMT,
                  key_type);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }

cleanup:
    if (arena != NULL) {
        PORT_FreeArena(arena, /* zero = */ PR_TRUE);
    }
    return ret;
}

static CK_RV export_and_store_key(CK_OBJECT_CLASS key_class,
                                  CK_KEY_TYPE key_type,
                                  CK_OBJECT_HANDLE key_id) {
    CK_RV ret = CKR_OK;
    CK_BYTE_PTR encoded_key = NULL;
    CK_ULONG encoded_key_len = 0;
    CK_BYTE_PTR encrypted_key = NULL;
    CK_ULONG encrypted_key_len = 0;

    // Wrap.
    p11_call_with_allocation(P11.C_WrapKey, encrypted_key, encrypted_key_len,
                             IEK.session, &IEK.mech, IEK.id, key_id);
    dbg_trace("Called C_WrapKey() to export the key\n  "
              "encrypted_key_len = %lu, ret = " CKR_FMT,
              encrypted_key_len, ret);
    if (ret != CKR_OK) {
        return_with_cleanup(CKR_GENERAL_ERROR);
    }

    // Decrypt.
    ret = P11.C_DecryptInit(IEK.session, &IEK.mech, IEK.id);
    if (ret != CKR_OK) {
        dbg_trace("C_DecryptInit has failed with ret = " CKR_FMT, ret);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    p11_call_with_allocation(P11.C_Decrypt, encoded_key, encoded_key_len,
                             IEK.session, encrypted_key, encrypted_key_len);
    dbg_trace("Called C_Decrypt() to export the key\n  encoded_key_len = %lu, "
              "ret = " CKR_FMT,
              encoded_key_len, ret);
    if (ret != CKR_OK) {
        return_with_cleanup(CKR_GENERAL_ERROR);
    }

    // Decode and store.
    if (key_class == CKO_SECRET_KEY) {
        ret = decode_and_store_secret_key(&encoded_key, encoded_key_len);
    } else if (key_class == CKO_PRIVATE_KEY) {
        ret = decode_and_store_private_key(key_type, encoded_key,
                                           encoded_key_len);
    } else {
        dbg_trace("This should never happen, given is_importable_exportable() "
                  "was previously called\n  key_class = " CKO_FMT,
                  key_class);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    if (ret == CKR_OK) {
        cached_attrs_initialized = true;
    }

cleanup:
    if (encrypted_key != NULL) {
        zeroize_and_free(encrypted_key, encrypted_key_len);
    }
    if (encoded_key != NULL) {
        zeroize_and_free(encoded_key, encoded_key_len);
    }
    return ret;
}

CK_RV export_key(CK_OBJECT_CLASS key_class, CK_KEY_TYPE key_type,
                 CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key_id,
                 CK_ATTRIBUTE_PTR attributes, CK_ULONG n_attributes) {
    CK_RV ret = CKR_OK;

    // Consistency checks for convention described in PKCS #11 v3.0 Section 5.2.
    for (size_t n = 0; n < n_attributes; n++) {
        CK_ATTRIBUTE_PTR cached_attr =
            get_sensitive_cached_attr(attributes[n].type);
        if (cached_attr == NULL) {
            // Skip non-sensitive attribute.
            continue;
        }
        if (!cached_attrs_initialized && attributes[n].pValue != NULL) {
            dbg_trace_attr("First call should query the buffer sizes, "
                           "unexpected attribute",
                           attributes[n]);
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        if (cached_attrs_initialized) {
            if (attributes[n].pValue == NULL) {
                dbg_trace_attr("Second call should have allocated the buffers, "
                               "unexpected attribute",
                               attributes[n]);
                return_with_cleanup(CKR_GENERAL_ERROR);
            }
            if (cached_attr->pValue == NULL ||
                cached_attr->ulValueLen != attributes[n].ulValueLen) {
                dbg_trace_attr("Cached attribute and destination attribute "
                               "data mismatch, unexpected attribute",
                               attributes[n]);
                dbg_trace_attr("Cached attribute counterpart", *cached_attr);
                return_with_cleanup(CKR_GENERAL_ERROR);
            }
        }
    }

    ret = P11.C_GetAttributeValue(session, key_id, attributes, n_attributes);
    dbg_trace("Forwarded to NSS C_GetAttributeValue()\n  session = 0x%08lx, "
              "key_id = %lu, attributes = %p, n_attributes = %lu, "
              "ret = " CKR_FMT,
              session, key_id, (void *)attributes, n_attributes, ret);

    if (dbg_is_enabled() && ret != CKR_ATTRIBUTE_SENSITIVE) {
        // For CKR_ATTRIBUTE_SENSITIVE we have more detailed logging.
        for (size_t n = 0; n < n_attributes; n++) {
            dbg_trace_attr("Attribute returned by NSS C_GetAttributeValue()",
                           attributes[n]);
        }
    }

    if (ret == CKR_OK) {
        // All the attributes are non-sensitive
        if (cached_attrs_initialized) {
            dbg_trace("Sensitive attributes were expected");
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        if (n_attributes >= 3) {
            // OpenJDK may query these three attributes to determine if
            // the key is opaque. Based on our FIPS configuration (FIPS
            // enabled and no-DB), these attribute values (if present)
            // must be token == CK_FALSE and sensitive == CK_TRUE.
            CK_BBOOL *token = NULL;
            CK_BBOOL *sensitive = NULL;
            CK_BBOOL *extractable = NULL;
            for (size_t n = 0; n < n_attributes; n++) {
                if (attributes[n].pValue != NULL &&
                    attributes[n].ulValueLen == sizeof(CK_BBOOL)) {
                    if (attributes[n].type == CKA_TOKEN) {
                        token = attributes[n].pValue;
                        if (*token == CK_TRUE) {
                            dbg_trace("Without an NSS DB, CKA_TOKEN should "
                                      "always be CK_FALSE");
                            return_with_cleanup(CKR_GENERAL_ERROR);
                        }
                    } else if (attributes[n].type == CKA_SENSITIVE) {
                        sensitive = attributes[n].pValue;
                        if (*sensitive == CK_FALSE) {
                            // This should never happen in FIPS mode given that
                            // is_importable_exportable() returned true, so the
                            // key is secret or private.
                            dbg_trace("Non-sensitive key, this is unexpected "
                                      "in FIPS mode");
                            return_with_cleanup(CKR_GENERAL_ERROR);
                        }
                    } else if (attributes[n].type == CKA_EXTRACTABLE) {
                        extractable = attributes[n].pValue;
                    }
                }
            }
            if (token != NULL && sensitive != NULL && extractable != NULL) {
                // We know that *token == CK_FALSE && *sensitive == CK_TRUE.
                if (*extractable == CK_TRUE) {
                    // Make the key look as non-sensitive so OpenJDK does not
                    // consider it opaque and gets the sensitive attribute
                    // values that the exporter will handle.
                    dbg_trace("Extractable key, forcing CKA_SENSITIVE=CK_FALSE "
                              "to avoid an opaque P11Key object");
                    *sensitive = CK_FALSE;
                } else {
                    dbg_trace("Let non-extractable key be handled as opaque");
                }
            }
        }
    } else if (ret == CKR_ATTRIBUTE_SENSITIVE) {
        bool first_call = !cached_attrs_initialized;
        if (first_call) {
            ret = export_and_store_key(key_class, key_type, key_id);
            if (ret != CKR_OK) {
                return_with_cleanup(ret);
            }
        }
        CK_ATTRIBUTE_PTR cached_attr = NULL;
        for (size_t n = 0; n < n_attributes; n++) {
            dbg_trace_attr("Attribute returned by NSS C_GetAttributeValue()",
                           attributes[n]);
            if (attributes[n].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                cached_attr = get_sensitive_cached_attr(attributes[n].type);
                if (cached_attr == NULL) {
                    dbg_trace("Unknown sensitive attribute");
                    return_with_cleanup(CKR_GENERAL_ERROR);
                }
                if (first_call) {
                    // First call, libj2pkcs11 is querying the buffer sizes.
                    attributes[n].ulValueLen = cached_attr->ulValueLen;
                    dbg_trace_attr("First call, replaced ulValueLen",
                                   attributes[n]);
                } else {
                    // Second call, libj2pkcs11 has allocated the buffers and
                    // is trying to retrieve the attribute values.
                    attributes[n].ulValueLen = cached_attr->ulValueLen;
                    memcpy(attributes[n].pValue, cached_attr->pValue,
                           attributes[n].ulValueLen);
                    dbg_trace_attr("Second call, copied previously exported "
                                   "attribute",
                                   attributes[n]);
                }
            }
        }
        ret = CKR_OK;
        if (!first_call) {
            clear_sensitive_cached_attrs();
        }
    }

cleanup:
    if (ret != CKR_OK) {
        clear_sensitive_cached_attrs();
    }
    return ret;
}
