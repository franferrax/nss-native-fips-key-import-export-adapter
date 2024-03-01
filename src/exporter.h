// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef EXPORTER_H
#define EXPORTER_H

#include "nssadapter.h"
#include <pkcs11.h>

typedef struct {
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE type;
    CK_BBOOL token;
    CK_BBOOL sensitive;
    CK_BBOOL extractable;
} key_data_t;

CK_RV export_key(key_data_t *key_data, CK_SESSION_HANDLE session,
                 CK_OBJECT_HANDLE key_id, CK_ATTRIBUTE_PTR attributes,
                 CK_ULONG n_attributes);

#endif // EXPORTER_H
