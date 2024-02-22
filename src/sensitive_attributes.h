// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

// Use:
// #define for_each_sensitive_attr(idx, sensitive_attr_type) YOUR_ACTION
// #include "sensitive_attributes.h"

for_each_sensitive_attr(0, CKA_VALUE)
for_each_sensitive_attr(1, CKA_PRIVATE_EXPONENT)
for_each_sensitive_attr(2, CKA_PRIME_1)
for_each_sensitive_attr(3, CKA_PRIME_2)
for_each_sensitive_attr(4, CKA_EXPONENT_1)
for_each_sensitive_attr(5, CKA_EXPONENT_2)
for_each_sensitive_attr(6, CKA_COEFFICIENT)
