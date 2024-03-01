// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef EXPORTER_H
#define EXPORTER_H

#include "nssadapter.h"
#include <pkcs11.h>

CK_RV export_key(CK_OBJECT_CLASS key_class, CK_KEY_TYPE key_type,
                 CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key_id,
                 CK_ATTRIBUTE_PTR attributes, CK_ULONG n_attributes);

#endif // EXPORTER_H
