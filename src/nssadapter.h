// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef NSS_ADAPTER_H
#define NSS_ADAPTER_H

// Shared library constructor/initializer and destructor/finalizer
#define CONSTRUCTOR_FUNCTION __attribute__((constructor))
#define DESTRUCTOR_FUNCTION __attribute__((destructor))

#endif // NSS_ADAPTER_H