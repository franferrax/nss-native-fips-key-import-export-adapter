// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef IMPORTER_H
#define IMPORTER_H

#include "nssadapter.h"
#include <pkcs11.h>

CK_RV import_key(CK_OBJECT_CLASS key_class, CK_KEY_TYPE key_type,
                 CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes,
                 CK_ULONG n_attributes, CK_OBJECT_HANDLE_PTR key_id);

#endif // IMPORTER_H
