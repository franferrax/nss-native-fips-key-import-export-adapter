// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef NSS_ADAPTER_H
#define NSS_ADAPTER_H

#include <nss3/pkcs11.h>

// Shared library constructor/initializer and destructor/finalizer
#define CONSTRUCTOR_FUNCTION __attribute__((constructor))
#define DESTRUCTOR_FUNCTION  __attribute__((destructor))
#define EXPORTED_FUNCTION    __attribute__((visibility("default")))

// Global data, see members description in nssadapter.c initialization
typedef struct {
    CK_FUNCTION_LIST_PTR orig_funcs_list;
    struct {
        CK_SESSION_HANDLE session;
        CK_OBJECT_HANDLE key_id;
        CK_MECHANISM mech;
    } importer_exporter;
} global_data_t;

// Global data accessor and facilities
global_data_t *__get_global_data();
#define IE  (__get_global_data()->importer_exporter)
#define P11 (*(__get_global_data()->orig_funcs_list))

#endif // NSS_ADAPTER_H
