// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef EXPORTER_H
#define EXPORTER_H

#include "nssadapter.h"
#include <nss3/pkcs11.h>

CK_RV export_key(CK_OBJECT_CLASS keyClass, CK_KEY_TYPE keyType,
                 CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

#endif // EXPORTER_H
