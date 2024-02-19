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
static __thread bool cached_attrs_initialized = false;
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

#define __store_cached_attr(attr_type, source)                                 \
    do {                                                                       \
        CK_ATTRIBUTE_PTR cached_attr = get_sensitive_cached_attr(attr_type);   \
        if (cached_attr == NULL) {                                             \
            dbg_trace("Trying to store unknown sensitive attribute");          \
            return CKR_GENERAL_ERROR;                                          \
        }                                                                      \
        cached_attr->pValue = malloc((source).len);                            \
        if (cached_attr->pValue == NULL) {                                     \
            dbg_trace("Ran out of memory while exporting " #attr_type);        \
            return CKR_HOST_MEMORY;                                            \
        }                                                                      \
        memcpy(cached_attr->pValue, (source).data, (source).len);              \
        cached_attr->ulValueLen = (source).len;                                \
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
                                          PLArenaPool *arena,
                                          SECItem *encoded_key_item) {
    NSSLOWKEYPrivateKeyInfo *pki;
    NSSLOWKEYPrivateKey *lpk;
    if (!allocate_PrivateKeyInfo_and_PrivateKey(arena, &pki, &lpk)) {
        return CKR_HOST_MEMORY;
    }

    if (SEC_QuickDERDecodeItem(arena, pki, nsslowkey_PrivateKeyInfoTemplate,
                               encoded_key_item) != SECSuccess) {
        dbg_trace("Failed to decode PKCS #8 private key");
        return CKR_GENERAL_ERROR;
    }
    SECOidTag alg_tag = SECOID_GetAlgorithmTag(&pki->algorithm);
    switch (key_type) {
    case CKK_RSA:
        if (alg_tag != SEC_OID_PKCS1_RSA_ENCRYPTION &&
            alg_tag != SEC_OID_PKCS1_RSA_PSS_SIGNATURE) {
            dbg_trace("Unexpected key algorithm tag: %u", alg_tag);
            return CKR_GENERAL_ERROR;
        }
        lpk->keyType = NSSLOWKEYRSAKey;
        prepare_low_rsa_priv_key_for_asn1(lpk);
        if (SEC_QuickDERDecodeItem(arena, lpk, nsslowkey_RSAPrivateKeyTemplate,
                                   &pki->privateKey) != SECSuccess) {
            dbg_trace("Failed to decode PKCS #8 RSA private key");
            return CKR_GENERAL_ERROR;
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
        if (alg_tag != SEC_OID_ANSIX9_DSA_SIGNATURE) {
            dbg_trace("Unexpected key algorithm tag: %u", alg_tag);
            return CKR_GENERAL_ERROR;
        }
        lpk->keyType = NSSLOWKEYDSAKey;
        prepare_low_dsa_priv_key_export_for_asn1(lpk);

        lpk->keyType = NSSLOWKEYDSAKey;
        prepare_low_dsa_priv_key_export_for_asn1(lpk);
        if (SEC_QuickDERDecodeItem(arena, lpk,
                                   nsslowkey_DSAPrivateKeyExportTemplate,
                                   &pki->privateKey) != SECSuccess) {
            dbg_trace("Failed to decode PKCS #8 DSA private key");
            return CKR_GENERAL_ERROR;
        }
        __store_cached_attr(CKA_VALUE, lpk->u.dsa.privateValue);
        dbg_trace("Successfully decoded DSA private key");
        break;
    case CKK_EC:
        if (alg_tag != SEC_OID_ANSIX962_EC_PUBLIC_KEY) {
            dbg_trace("Unexpected key algorithm tag: %u", alg_tag);
            return CKR_GENERAL_ERROR;
        }
        lpk->keyType = NSSLOWKEYECKey;
        prepare_low_ec_priv_key_for_asn1(lpk);
        if (SEC_QuickDERDecodeItem(arena, lpk, nsslowkey_ECPrivateKeyTemplate,
                                   &pki->privateKey) != SECSuccess) {
            dbg_trace("Failed to decode PKCS #8 EC private key");
            return CKR_GENERAL_ERROR;
        }
        __store_cached_attr(CKA_VALUE, lpk->u.ec.privateValue);
        dbg_trace("Successfully decoded EC private key");
        break;
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
    PLArenaPool *arena = NULL;
    CK_BYTE_PTR encoded_key = NULL;
    CK_ULONG encoded_key_len = 0;
    CK_BYTE_PTR encrypted_key = NULL;
    CK_ULONG encrypted_key_len = 0;

    // Wrap
    p11_allocation_idiom(P11.C_WrapKey, encrypted_key, encrypted_key_len,
                         IE.session, &IE.mech, IE.key_id, key_id);
    dbg_trace("Called C_WrapKey() to export the key\n  "
              "encrypted_key_len = %lu, ret = " CKR_FMT,
              encrypted_key_len, ret);
    if (ret != CKR_OK) {
        return_with_cleanup(CKR_GENERAL_ERROR);
    }

    // Decrypt
    ret = P11.C_DecryptInit(IE.session, &IE.mech, IE.key_id);
    if (ret != CKR_OK) {
        dbg_trace("C_DecryptInit has failed with ret = " CKR_FMT, ret);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    p11_allocation_idiom(P11.C_Decrypt, encoded_key, encoded_key_len,
                         IE.session, encrypted_key, encrypted_key_len);
    dbg_trace("Called C_Decrypt() to export the key\n  encoded_key_len = %lu, "
              "ret = " CKR_FMT,
              encoded_key_len, ret);
    if (ret != CKR_OK) {
        return_with_cleanup(CKR_GENERAL_ERROR);
    }

    // Decode and fix attributes template
    switch (key_class) {
    case CKO_SECRET_KEY:
        ret = decode_and_store_secret_key(&encoded_key, encoded_key_len);
        break;
    case CKO_PRIVATE_KEY:
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
        ret = decode_and_store_private_key(key_type, arena, &encoded_key_item);
        break;
    default:
        dbg_trace("Unknown key class: " CKO_FMT, key_class);
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
    if (arena != NULL) {
        PORT_FreeArena(arena, /* zero = */ PR_TRUE);
    }
    return ret;
}

CK_RV export_key(CK_OBJECT_CLASS key_class, CK_KEY_TYPE key_type,
                 CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key_id,
                 CK_ATTRIBUTE_PTR attributes, CK_ULONG n_attributes) {
    CK_RV ret = CKR_OK;

    // Check convention described in PKCS #11 v3.0 Section 5.2 on producing
    // output. We know libj2pkcs11 OpenJDK native library uses this convention.
    for (size_t n = 0; n < n_attributes; n++) {
        CK_ATTRIBUTE_PTR cached_attr =
            get_sensitive_cached_attr(attributes[n].type);
        if (cached_attr == NULL) {
            // Skip known non-sensitive attribute
            continue;
        }
        if (!cached_attrs_initialized && attributes[n].pValue != NULL) {
            dbg_trace_attr("First call should query the buffer sizes, "
                           "offending attribute",
                           attributes[n]);
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        if (cached_attrs_initialized) {
            if (attributes[n].pValue == NULL) {
                dbg_trace_attr("Second call should have allocated the buffers, "
                               "offending attribute",
                               attributes[n]);
                return_with_cleanup(CKR_GENERAL_ERROR);
            }
            if (cached_attr->pValue == NULL ||
                cached_attr->ulValueLen != attributes[n].ulValueLen) {
                dbg_trace_attr("Cached attribute and destination attribute "
                               "data mismatch, offending attribute",
                               attributes[n]);
                dbg_trace_attr("Corresponding cached attribute", *cached_attr);
                return_with_cleanup(CKR_GENERAL_ERROR);
            }
        }
    }

    ret = P11.C_GetAttributeValue(session, key_id, attributes, n_attributes);
    dbg_trace("Forwarded to NSS C_GetAttributeValue()\n  session = 0x%08lx, "
              "key_id = %lu, attributes = %p, n_attributes = %lu, "
              "ret = " CKR_FMT,
              session, key_id, (void *)attributes, n_attributes, ret);
    if (dbg_is_enabled()) {
        for (size_t n = 0; n < n_attributes; n++) {
            dbg_trace_attr("Attribute returned by NSS C_GetAttributeValue()",
                           attributes[n]);
        }
    }
    if (ret == CKR_OK) {
        if (cached_attrs_initialized) {
            dbg_trace("Sensitive attributes were expected");
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        if (n_attributes >= 3) {
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
                    return_with_cleanup(CKR_GENERAL_ERROR);
                }
                if ((sensitive != NULL && *sensitive == CK_FALSE) ||
                    (extractable != NULL && *extractable == CK_FALSE)) {
                    // For non-sensitive keys the exporter isn't necessary,
                    // for non-extractable keys the exporter doesn't work.
                    break;
                }
                if (token != NULL && sensitive != NULL && extractable != NULL) {
                    // Non-token, sensitive and extractable key, we need
                    // to prevent an opaque SunPKCS11 P11Key object, which
                    // refrains from obtaining the sensitive attributes.
                    dbg_trace("Extractable key, forcing CKA_SENSITIVE=CK_FALSE "
                              "to avoid opaque P11Key objects");
                    *sensitive = CK_FALSE;
                    break;
                }
            }
        }
    } else if (ret == CKR_ATTRIBUTE_SENSITIVE) {
        bool first_call = !cached_attrs_initialized;
        if (first_call && export_and_store_key_in_tls(key_class, key_type,
                                                      key_id) != CKR_OK) {
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        CK_ATTRIBUTE_PTR cached_attr = NULL;
        for (size_t n = 0; n < n_attributes; n++) {
            if (attributes[n].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                cached_attr = get_sensitive_cached_attr(attributes[n].type);
                if (cached_attr == NULL) {
                    dbg_trace("Unknown sensitive attribute");
                    return_with_cleanup(CKR_GENERAL_ERROR);
                }
                if (first_call) {
                    // First call, libj2pkcs11 is querying the buffer sizes
                    dbg_trace("First call, replacing ulValueLen = CK_"
                              "UNAVAILABLE_INFORMATION with ulValueLen = %lu",
                              cached_attr->ulValueLen);
                    attributes[n].ulValueLen = cached_attr->ulValueLen;
                } else {
                    // Second call, libj2pkcs11 has allocated the buffers and
                    // is trying to retrieve the attribute values
                    dbg_trace_attr("Second call, copying previously exported "
                                   "attribute",
                                   *cached_attr);
                    attributes[n].ulValueLen = cached_attr->ulValueLen;
                    memcpy(attributes[n].pValue, cached_attr->pValue,
                           attributes[n].ulValueLen);
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
