// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef DBG_TRACE_H
#define DBG_TRACE_H

#include <stdio.h>

// Internal
unsigned char dbg_is_enabled();
void __dbg_trace_header(const char *file, const unsigned int line,
                        const char *func);

// Public
void dbg_initialize();

#define HEX32 "0x%08lx"
#define HEX64 "0x%016lx"

#define dbg_trace(...)                                                         \
    do {                                                                       \
        if (dbg_is_enabled()) {                                                \
            __dbg_trace_header(__FILE__, __LINE__, __func__);                  \
            fprintf(stderr, ##__VA_ARGS__);                                    \
            fputc('\n', stderr);                                               \
            fflush(stderr);                                                    \
        }                                                                      \
    } while (0)

#endif // DBG_TRACE_H
