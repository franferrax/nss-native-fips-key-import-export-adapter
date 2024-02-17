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
                                PLArenaPool *arena, SECItem *encoded_key_item) {
    NSSLOWKEYPrivateKeyInfo *pki;
    NSSLOWKEYPrivateKey *lpk;
    if (!allocate_PrivateKeyInfo_and_PrivateKey(arena, &pki, &lpk)) {
        return CKR_HOST_MEMORY;
    }

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
        dbg_trace("Unknown key type");
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV import_key(CK_OBJECT_CLASS key_class, CK_KEY_TYPE key_type,
                 CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes,
                 CK_ULONG n_attributes, CK_OBJECT_HANDLE_PTR key_id) {
    CK_RV ret = CKR_OK;
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

    switch (key_class) {
    case CKO_SECRET_KEY:
        ret = encode_secret_key(attributes, n_attributes, &encoded_key_item);
        if (ret != CKR_OK) {
            goto cleanup;
        }
        break;
    case CKO_PRIVATE_KEY:
        arena = PORT_NewArena(2048);
        if (arena == NULL) {
            return_with_cleanup(CKR_HOST_MEMORY);
        }
        ret = encode_private_key(attributes, n_attributes, key_type, arena,
                                 &encoded_key_item);
        if (ret != CKR_OK) {
            goto cleanup;
        }
        break;
    default:
        dbg_trace("Unknown key class");
        return_with_cleanup(CKR_GENERAL_ERROR);
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
    ret = P11.C_UnwrapKey(session, &IE.mech, IE.key_id, encrypted_key,
                          encrypted_key_len, attributes, n_attributes, key_id);
    dbg_trace("Called C_UnwrapKey() to import the key\n  "
              "imported key_id = %lu, ret = " CKR_FMT,
              *key_id, ret);

cleanup:
    if (encrypted_key != NULL) {
        zeroize_and_free(encrypted_key, encrypted_key_len);
    }
    if (arena != NULL) {
        PORT_FreeArena(arena, /* zero = */ PR_TRUE);
    }
    return ret;
}
