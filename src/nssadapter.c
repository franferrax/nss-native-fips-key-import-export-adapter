// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "nssadapter.h"
#include "dbg_trace.h"
#include "exporter.h"
#include "importer.h"
#include "p11_util.h"
#include <nss3/pkcs11.h>

/* ****************************************************************************
 * Global importer / exporter data
 * ****************************************************************************
   .orig_funcs_list            [aliased &P11]        (CK_FUNCTION_LIST_PTR)
     Saved non-decorated original function list from NSS, for this wrapper's
     use. NOTE: the PKCS #11 v3.0 standard states 'CK_FUNCTION_LIST_3_0 is a
     structure which contains the same function pointers as in CK_FUNCTION_LIST
     and additional functions added to the end of the structure that were
     defined in Cryptoki version 3.0'. This implies that we can safely use
     CK_FUNCTION_LIST regardless of the version, as long as it contains all the
     functions we need.

   .importer_exporter.session  [aliased IE.session]  (CK_SESSION_HANDLE)
   .importer_exporter.key_id   [aliased IE.key_id]   (CK_OBJECT_HANDLE)
   .importer_exporter.mech     [aliased IE.mech]     (CK_MECHANISM, has the IV)
     Import / Export session, key, initialization vector (IV) and mechanism. The
     IV was randomly generated once: there is no point in trying to generate it
     at run time, since the encryption is temporary, and we are receiving or
     going to return the sensitive attributes in plain.

*/
static CK_BYTE iv[] = {0xa1, 0xe9, 0xe1, 0x95, 0xbf, 0x11, 0x6c, 0xca,
                       0xef, 0xa5, 0x56, 0x5e, 0xdd, 0xfc, 0xdc, 0x8c};
static global_data_t global_data = {
    .orig_funcs_list = NULL,
    .importer_exporter = {.session = CK_INVALID_HANDLE,
                          .key_id = CK_INVALID_HANDLE,
                          .mech = {CKM_AES_CBC_PAD, &iv, sizeof(iv)}},
};

// Copy for the decorated versions of the CK_INTERFACE and CK_FUNCTION_LIST/_3_0
// structures. We use CK_FUNCTION_LIST_3_0 since it has enough space to hold all
// the CK_FUNCTION_LIST data, in runtime, one or the other can be present.
static CK_INTERFACE decorated_interface = {0};
static CK_FUNCTION_LIST_3_0 decorated_func_list = {0};

inline global_data_t *__get_global_data() {
    return &global_data;
}

/* ****************************************************************************
 * Common code for importer / exporter entry points
 * ****************************************************************************/

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

static inline bool is_importable_exportable(CK_OBJECT_CLASS key_class,
                                            CK_KEY_TYPE key_type) {
    // NOTE: see OPENJDK-824 for reasons behind skipping DH keys
    return key_class == CKO_SECRET_KEY ||
           (key_class == CKO_PRIVATE_KEY &&
            (key_type == CKK_RSA || key_type == CKK_DSA || key_type == CKK_EC));
}

/* ****************************************************************************
 * Importer entry point
 * ****************************************************************************/

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
    CK_OBJECT_CLASS keyClass = (CK_OBJECT_CLASS)-1;
    CK_KEY_TYPE keyType = (CK_KEY_TYPE)-1;
    if (!get_key_type_from_attrs(&keyClass, &keyType, pTemplate, ulCount) ||
        !is_importable_exportable(keyClass, keyType)) {
        dbg_trace("There is no support for importing this key, forwarding to "
                  "NSS\n  hSession = 0x%08lx, pTemplate = %p, ulCount = %lu, "
                  "phObject = %p",
                  hSession, (void *)pTemplate, ulCount, (void *)phObject);
        return P11.C_CreateObject(hSession, pTemplate, ulCount, phObject);
    }
    return import_key(keyClass, keyType, hSession, pTemplate, ulCount,
                      phObject);
}

/* ****************************************************************************
 * Exporter entry point
 * ****************************************************************************/

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    CK_OBJECT_CLASS keyClass = (CK_OBJECT_CLASS)-1;
    CK_KEY_TYPE keyType = (CK_KEY_TYPE)-1;
    if (!get_key_type_from_object(hSession, hObject, &keyClass, &keyType) ||
        !is_importable_exportable(keyClass, keyType)) {
        dbg_trace("There is no support for exporting this key, forwarding to "
                  "NSS\n  hSession = 0x%08lx, hObject = %lu, pTemplate = %p, "
                  "ulCount = %lu",
                  hSession, hObject, (void *)pTemplate, ulCount);
        return P11.C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
    }
    return export_key(keyClass, keyType, hSession, hObject, pTemplate, ulCount);
}

/* ****************************************************************************
 * Initialization
 * ****************************************************************************/

static CK_RV initialize_importer_exporter() {
    if (IE.key_id != CK_INVALID_HANDLE) {
        // Already initialized
        return CKR_OK;
    }

    // NSS realizes that no DB was configured and FIPS level is 2 after the
    // C_GetTokenInfo() call, and stops requiring login on each operation
    CK_TOKEN_INFO info;
    CK_RV ret = P11.C_GetTokenInfo(FIPS_SLOT_ID, &info);
    dbg_trace("Called C_GetTokenInfo() to remove the login requirement\n  "
              "ret = " CKR_FMT,
              ret);
    if (ret != CKR_OK) {
        return ret;
    }

    // Create importer / exporter session
    ret = P11.C_OpenSession(FIPS_SLOT_ID, CKF_SERIAL_SESSION, NULL, NULL,
                            &IE.session);
    dbg_trace("Called C_OpenSession() to create the session for the "
              "import / export key\n  ret = " CKR_FMT,
              ret);
    if (ret != CKR_OK) {
        return ret;
    }

    // Create importer / exporter key
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG keyLen = 256 >> 3;
    CK_MECHANISM mechanisms[] = {
        {CKM_AES_KEY_GEN, NULL, 0},
    };
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS,     &keyClass, sizeof(keyClass)},
        {CKA_VALUE_LEN, &keyLen,   sizeof(keyLen)  },
    };
    ret = P11.C_GenerateKey(IE.session, mechanisms, attributes,
                            attrs_count(attributes), &IE.key_id);
    dbg_trace("Called C_GenerateKey() to create the import / export key\n  "
              "ret = " CKR_FMT,
              ret);
    return ret;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    CK_RV ret = P11.C_Initialize(pInitArgs);
    dbg_trace("Forwarded to NSS function\n  pInitArgs = %p, ret = " CKR_FMT,
              pInitArgs, ret);
    if (ret == CKR_OK) {
        // After loading this native library, the SunPKCS11 constructor calls
        // PKCS11::getInstance(), which is a synchronized method. This method
        // invokes C_Initialize(), so by calling initialize_importer_exporter()
        // at this point (inside the C_Initialize() implementation), we are
        // guaranteed that the importer / exporter initialization will not be
        // concurrently executed.
        if (initialize_importer_exporter() != CKR_OK) {
            ret = CKR_GENERAL_ERROR;
        }
    }
    return ret;
}

/* ****************************************************************************
 * Decorated exported functions
 * ****************************************************************************/

// Prototype for the FIPS version in NSS' libsoftokn3.so
CK_RV FC_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                      CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags);

EXPORTED_FUNCTION CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName,
                                       CK_VERSION_PTR pVersion,
                                       CK_INTERFACE_PTR_PTR ppInterface,
                                       CK_FLAGS flags) {
    dbg_trace("Adapting NSS interface\n  pInterfaceName = \"%s\", "
              "pVersion = %p, ppInterface = %p, flags = %lu",
              pInterfaceName, (void *)pVersion, (void *)ppInterface, flags);
    if (pInterfaceName != NULL) {
        dbg_trace("Only the default interface is supported by this adapter");
        return CKR_GENERAL_ERROR;
    }
    if (decorated_interface.pFunctionList == &decorated_func_list) {
        // Already initialized
        *ppInterface = &decorated_interface;
        return CKR_OK;
    }

    CK_RV ret = FC_GetInterface(pInterfaceName, pVersion, ppInterface, flags);
    if (ret == CKR_OK) {
        // Save non-decorated original function list, for this wrapper's use
        global_data.orig_funcs_list = (*ppInterface)->pFunctionList;
        CK_VERSION_PTR version = (*ppInterface)->pFunctionList;

        // Clone returned structures
        memcpy(&decorated_interface, *ppInterface, sizeof(decorated_interface));
        memcpy(&decorated_func_list, global_data.orig_funcs_list,
               version->major == 3 ? sizeof(CK_FUNCTION_LIST_3_0)
                                   : sizeof(CK_FUNCTION_LIST));

        // Decorate functions
        decorated_func_list.C_CreateObject = C_CreateObject;
        decorated_func_list.C_GetAttributeValue = C_GetAttributeValue;
        decorated_func_list.C_Initialize = C_Initialize;

        // Update pointers
        decorated_interface.pFunctionList = &decorated_func_list;
        *ppInterface = &decorated_interface;
        dbg_trace("NSS PKCS #11 v%d.%d, software token successfully adapted",
                  version->major, version->minor);
    }
    return ret;
}

EXPORTED_FUNCTION CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    dbg_trace("Only the C_GetInterface() API is supported by this adapter\n  "
              "ppFunctionList = %p",
              (void *)ppFunctionList);
    *ppFunctionList = NULL;
    return CKR_GENERAL_ERROR;
}

/* ****************************************************************************
 * Library constructor/destructor
 * ****************************************************************************/

static void CONSTRUCTOR_FUNCTION library_constructor(void) {
    dbg_initialize();
}

static void DESTRUCTOR_FUNCTION library_destructor(void) {
    // Destroy import / export key, if created
    if (IE.session != CK_INVALID_HANDLE) {
        P11.C_CloseSession(IE.session);
    }
    dbg_finalize();
}
