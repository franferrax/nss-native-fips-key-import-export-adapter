// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "importer.h"
#include "dbg_trace.h"
#include "p11_util.h"
#include <limits.h>
#include <nss3/lowkeyi.h>
#include <nss3/secasn1.h>
#include <nss3/secder.h>
#include <nss3/secoid.h>

#define __nth_attr_to_SECItem(attr_type, sec_item)                             \
    do {                                                                       \
        if (attributes[n].ulValueLen > UINT_MAX) {                             \
            dbg_trace_attr(#attr_type " is too big", attributes[n]);           \
            return CKR_GENERAL_ERROR;                                          \
        }                                                                      \
        (sec_item).data = attributes[n].pValue;                                \
        (sec_item).len = (unsigned int)attributes[n].ulValueLen;               \
    } while (0)

#define __attr_case(attr_type, sec_item)                                       \
    case (attr_type):                                                          \
        found_attrs++;                                                         \
        if (attributes[n].pValue == NULL) {                                    \
            dbg_trace_attr(#attr_type " has no data", attributes[n]);          \
            return CKR_GENERAL_ERROR;                                          \
        }                                                                      \
        __nth_attr_to_SECItem(attr_type, (sec_item));                          \
        break

static CK_RV encode_secret_key(CK_ATTRIBUTE_PTR attributes,
                               CK_ULONG n_attributes,
                               SECItem *encoded_key_item) {
    for (size_t n = 0; n < n_attributes; n++) {
        if (attributes[n].type == CKA_VALUE && attributes[n].pValue != NULL) {
            __nth_attr_to_SECItem(CKA_VALUE, *encoded_key_item);
            return CKR_OK;
        }
    }
    dbg_trace("Unavailable attribute: CKA_VALUE");
    return CKR_TEMPLATE_INCOMPLETE;
}

static CK_RV encode_private_key(CK_ATTRIBUTE_PTR attributes,
                                CK_ULONG n_attributes, CK_KEY_TYPE key_type,
                                PLArenaPool *arena, SECItem *encoded_key_item,
                                bool *nss_db_attr_present) {
    SECItem *params = NULL;
    CK_ULONG found_attrs = 0;
    SECOidTag alg_tag = SEC_OID_UNKNOWN;
    NSSLOWKEYPrivateKeyInfo *pki;
    NSSLOWKEYPrivateKey *lpk;
    if (!allocate_PrivateKeyInfo_and_PrivateKey(arena, &pki, &lpk)) {
        return CKR_HOST_MEMORY;
    }

    switch (key_type) {
    case CKK_RSA:
        alg_tag = SEC_OID_PKCS1_RSA_ENCRYPTION;
        lpk->keyType = NSSLOWKEYRSAKey;
        lpk->u.rsa.arena = arena;
        if (DER_SetUInteger(arena, &lpk->u.rsa.version,
                            NSSLOWKEY_PRIVATE_KEY_INFO_VERSION) != SECSuccess) {
            dbg_trace("Failed to encode the RSA private key version");
            return CKR_GENERAL_ERROR;
        }
        prepare_low_rsa_priv_key_for_asn1(lpk);
        found_attrs = 0;
        for (size_t n = 0; n < n_attributes; n++) {
            switch (attributes[n].type) {
                __attr_case(CKA_MODULUS, lpk->u.rsa.modulus);
                __attr_case(CKA_PUBLIC_EXPONENT, lpk->u.rsa.publicExponent);
                __attr_case(CKA_PRIVATE_EXPONENT, lpk->u.rsa.privateExponent);
                __attr_case(CKA_PRIME_1, lpk->u.rsa.prime1);
                __attr_case(CKA_PRIME_2, lpk->u.rsa.prime2);
                __attr_case(CKA_EXPONENT_1, lpk->u.rsa.exponent1);
                __attr_case(CKA_EXPONENT_2, lpk->u.rsa.exponent2);
                __attr_case(CKA_COEFFICIENT, lpk->u.rsa.coefficient);
            default:
                break;
            }
        }
        if (found_attrs < 8) {
            dbg_trace("Too few attributes for an RSA private key");
            return CKR_TEMPLATE_INCOMPLETE;
        }
        if (SEC_ASN1EncodeItem(arena, &pki->privateKey, lpk,
                               nsslowkey_RSAPrivateKeyTemplate) == NULL) {
            dbg_trace("Failed to encode the RSA private key");
            return CKR_GENERAL_ERROR;
        }
        dbg_trace("Successfully encoded RSA private key");
        break;
    case CKK_DSA:
        alg_tag = SEC_OID_ANSIX9_DSA_SIGNATURE;
        lpk->keyType = NSSLOWKEYDSAKey;
        lpk->u.dsa.params.arena = arena;
        prepare_low_dsa_priv_key_export_for_asn1(lpk);
        prepare_low_pqg_params_for_asn1(&lpk->u.dsa.params);
        found_attrs = 0;
        for (size_t n = 0; n < n_attributes; n++) {
            switch (attributes[n].type) {
                __attr_case(CKA_PRIME, lpk->u.dsa.params.prime);
                __attr_case(CKA_SUBPRIME, lpk->u.dsa.params.subPrime);
                __attr_case(CKA_BASE, lpk->u.dsa.params.base);
                __attr_case(CKA_VALUE, lpk->u.dsa.privateValue);
            case CKA_NSS_DB:
                *nss_db_attr_present = true;
                break;
            default:
                break;
            }
        }
        if (found_attrs < 4) {
            dbg_trace("Too few attributes for a DSA private key");
            return CKR_TEMPLATE_INCOMPLETE;
        }
        params = SEC_ASN1EncodeItem(arena, NULL, &lpk->u.dsa.params,
                                    nsslowkey_PQGParamsTemplate);
        if (params == NULL) {
            dbg_trace("Failed to encode the DSA private key PQG params");
            return CKR_GENERAL_ERROR;
        }
        if (SEC_ASN1EncodeItem(arena, &pki->privateKey, lpk,
                               nsslowkey_DSAPrivateKeyExportTemplate) == NULL) {
            dbg_trace("Failed to encode the DSA private key");
            return CKR_GENERAL_ERROR;
        }
        dbg_trace("Successfully encoded DSA private key");
        break;
    case CKK_EC:
        alg_tag = SEC_OID_ANSIX962_EC_PUBLIC_KEY;
        lpk->keyType = NSSLOWKEYECKey;
        lpk->u.ec.ecParams.arena = arena;
        if (DER_SetUInteger(arena, &lpk->u.ec.version,
                            NSSLOWKEY_EC_PRIVATE_KEY_VERSION) != SECSuccess) {
            dbg_trace("Failed to encode the EC private key version");
            return CKR_GENERAL_ERROR;
        }
        prepare_low_ec_priv_key_for_asn1(lpk);
        found_attrs = 0;
        for (size_t n = 0; n < n_attributes; n++) {
            switch (attributes[n].type) {
                __attr_case(CKA_EC_PARAMS, lpk->u.ec.ecParams.DEREncoding);
                __attr_case(CKA_VALUE, lpk->u.ec.privateValue);
            case CKA_NSS_DB:
                *nss_db_attr_present = true;
                break;
            default:
                break;
            }
        }
        if (found_attrs < 2) {
            dbg_trace("Too few attributes for an EC private key");
            return CKR_TEMPLATE_INCOMPLETE;
        }
        params = SECITEM_ArenaDupItem(arena, &lpk->u.ec.ecParams.DEREncoding);
        if (SEC_ASN1EncodeItem(arena, &pki->privateKey, lpk,
                               nsslowkey_ECPrivateKeyTemplate) == NULL) {
            dbg_trace("Failed to encode the EC private key");
            return CKR_GENERAL_ERROR;
        }
        dbg_trace("Successfully encoded EC private key");
        break;
    default:
        dbg_trace("Unknown key type: " CKK_FMT, key_type);
        return CKR_GENERAL_ERROR;
    }

    if (SECOID_SetAlgorithmID(arena, &pki->algorithm, alg_tag, params) !=
        SECSuccess) {
        dbg_trace("Failed to encode the private key algorithm");
        return CKR_GENERAL_ERROR;
    }
    if (SEC_ASN1EncodeInteger(arena, &pki->version,
                              NSSLOWKEY_PRIVATE_KEY_INFO_VERSION) == NULL) {
        dbg_trace("Failed to encode the private key version");
        return CKR_GENERAL_ERROR;
    }
    if (SEC_ASN1EncodeItem(arena, encoded_key_item, pki,
                           nsslowkey_PrivateKeyInfoTemplate) == NULL) {
        dbg_trace("Failed to encode the private key");
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

CK_RV import_key(CK_OBJECT_CLASS key_class, CK_KEY_TYPE key_type,
                 CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes,
                 CK_ULONG n_attributes, CK_OBJECT_HANDLE_PTR key_id) {
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE_PTR modified_attrs = NULL;
    bool nss_db_attr_present = false;
    PLArenaPool *arena = NULL;
    SECItem encoded_key_item = {0};
    CK_BYTE_PTR encrypted_key = NULL;
    CK_ULONG encrypted_key_len = 0;

    if (dbg_is_enabled()) {
        for (size_t n = 0; n < n_attributes; n++) {
            dbg_trace_attr("Attribute received by our C_CreateObject()",
                           attributes[n]);
        }
    }

    // Encode
    if (key_class == CKO_SECRET_KEY) {
        ret = encode_secret_key(attributes, n_attributes, &encoded_key_item);
    } else { // CKO_PRIVATE_KEY, guaranteed by is_importable_exportable()
        arena = PORT_NewArena(2048);
        if (arena == NULL) {
            return_with_cleanup(CKR_HOST_MEMORY);
        }
        ret = encode_private_key(attributes, n_attributes, key_type, arena,
                                 &encoded_key_item, &nss_db_attr_present);
    }
    if (ret != CKR_OK) {
        goto cleanup;
    }

    // Encrypt
    ret = P11.C_EncryptInit(IE.session, &IE.mech, IE.key_id);
    if (ret != CKR_OK) {
        dbg_trace("C_EncryptInit has failed with ret = " CKR_FMT, ret);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    p11_allocation_idiom(P11.C_Encrypt, encrypted_key, encrypted_key_len,
                         IE.session, encoded_key_item.data,
                         encoded_key_item.len);
    dbg_trace("Called C_Encrypt() to import the key\n  "
              "encoded_key_item.len = %u, encrypted_key_len = %lu, "
              "ret = " CKR_FMT,
              encoded_key_item.len, encrypted_key_len, ret);
    if (ret != CKR_OK) {
        return_with_cleanup(CKR_GENERAL_ERROR);
    }

    // Unwrap
    CK_BYTE zero = 0;
    if (!nss_db_attr_present && key_class == CKO_PRIVATE_KEY &&
        (key_type == CKK_DSA || key_type == CKK_EC)) {
        dbg_trace("Adding CKA_NSS_DB (a.k.a. CKA_NETSCAPE_DB) attribute");
        modified_attrs = malloc((n_attributes + 1) * sizeof(CK_ATTRIBUTE));
        if (modified_attrs == NULL) {
            return_with_cleanup(CKR_HOST_MEMORY);
        }
        memcpy(modified_attrs, attributes, n_attributes * sizeof(CK_ATTRIBUTE));
        modified_attrs[n_attributes].type = CKA_NSS_DB;
        modified_attrs[n_attributes].pValue = &zero;
        modified_attrs[n_attributes].ulValueLen = sizeof(zero);
        attributes = modified_attrs;
        n_attributes++;
    }
    ret = P11.C_UnwrapKey(session, &IE.mech, IE.key_id, encrypted_key,
                          encrypted_key_len, attributes, n_attributes, key_id);
    dbg_trace("Called C_UnwrapKey() to import the key\n  "
              "imported key_id = %lu, ret = " CKR_FMT,
              *key_id, ret);

cleanup:
    if (modified_attrs != NULL) {
        free(modified_attrs);
    }
    if (encrypted_key != NULL) {
        zeroize_and_free(encrypted_key, encrypted_key_len);
    }
    if (arena != NULL) {
        PORT_FreeArena(arena, /* zero = */ PR_TRUE);
    }
    return ret;
}
