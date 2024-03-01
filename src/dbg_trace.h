// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef DBG_TRACE_H
#define DBG_TRACE_H

#include <pkcs11.h>
#include <stdbool.h>
#include <stdio.h>

// Internal for dbg_ macros, do not use directly
FILE *__dbg_file();
void __dbg_lock();
void __dbg_unlock();
void __dbg_trace_header(const char *file, const unsigned int line,
                        const char *func);
void __dbg_trace_footer();
bool __dbg_should_dump_attr_value(CK_ATTRIBUTE_TYPE type);
void __dbg_trace_hex(const unsigned char *const buf, size_t len);

// Public
void dbg_initialize();
bool dbg_is_enabled();
void dbg_finalize();

#define dbg_trace(...)                                                         \
    do {                                                                       \
        if (dbg_is_enabled()) {                                                \
            __dbg_lock();                                                      \
            __dbg_trace_header(__FILE__, __LINE__, __func__);                  \
            fprintf(__dbg_file(), ##__VA_ARGS__);                              \
            __dbg_trace_footer();                                              \
            __dbg_unlock();                                                    \
        }                                                                      \
    } while (0)

// Logs a CK_ATTRIBUTE with all its fields and data.
#define dbg_trace_attr(message, attr)                                          \
    do {                                                                       \
        if (dbg_is_enabled()) {                                                \
            __dbg_lock();                                                      \
            __dbg_trace_header(__FILE__, __LINE__, __func__);                  \
            if ((attr).ulValueLen == CK_UNAVAILABLE_INFORMATION) {             \
                fprintf(__dbg_file(),                                          \
                        "%s:\n  type = " CKA_FMT ", pValue = %p, "             \
                        "ulValueLen = CK_UNAVAILABLE_INFORMATION",             \
                        (message), (attr).type, (attr).pValue);                \
            } else {                                                           \
                fprintf(__dbg_file(),                                          \
                        "%s:\n  type = " CKA_FMT ", pValue = %p, "             \
                        "ulValueLen = %lu",                                    \
                        (message), (attr).type, (attr).pValue,                 \
                        (attr).ulValueLen);                                    \
                if (__dbg_should_dump_attr_value((attr).type)) {               \
                    __dbg_trace_hex((attr).pValue, (attr).ulValueLen);         \
                }                                                              \
            }                                                                  \
            __dbg_trace_footer();                                              \
            __dbg_unlock();                                                    \
        }                                                                      \
    } while (0)

#endif // DBG_TRACE_H
