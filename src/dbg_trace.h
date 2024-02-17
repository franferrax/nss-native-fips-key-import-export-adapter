// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef DBG_TRACE_H
#define DBG_TRACE_H

#include <stdbool.h>
#include <stdio.h>

// Internal for dbg_ macros, do not use directly
FILE *__dbg_file();
void __dbg_new_line_and_flush();
void __dbg_trace_header(const char *file, const unsigned int line,
                        const char *func);

// Public
void dbg_initialize();
bool dbg_is_enabled();
void dbg_finalize();

#define dbg_trace(...)                                                         \
    do {                                                                       \
        if (dbg_is_enabled()) {                                                \
            __dbg_trace_header(__FILE__, __LINE__, __func__);                  \
            fprintf(__dbg_file(), ##__VA_ARGS__);                              \
            __dbg_new_line_and_flush();                                        \
        }                                                                      \
    } while (0)

#endif // DBG_TRACE_H
