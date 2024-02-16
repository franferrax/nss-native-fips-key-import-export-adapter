// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "dbg_trace.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define ansi_attrs(attrs) "\033[" attrs "m"

#define STATUS_ENABLED    (1 << 0)
#define STATUS_COLOR      (1 << 1)
#ifdef DEBUG
#define DEFAULT_STATUS (STATUS_ENABLED | STATUS_COLOR)
#else
#define DEFAULT_STATUS 0
#endif // DEBUG

static unsigned char dbg_status = 0;

void dbg_initialize() {
    const char *var = getenv("NSS_ADAPTER_DEBUG");
    if (var == NULL) {
        dbg_status = DEFAULT_STATUS;
    } else {
        if (strcmp(var, "YES") == 0 || strcmp(var, "yes") == 0) {
            dbg_status = STATUS_ENABLED;
        } else if (strcmp(var, "COLOR") == 0 || strcmp(var, "color") == 0) {
            dbg_status = STATUS_ENABLED | STATUS_COLOR;
        } else if (strcmp(var, "NO") == 0 || strcmp(var, "no") == 0) {
            dbg_status = 0;
        }
    }
}

inline unsigned char dbg_is_enabled() {
    return dbg_status & STATUS_ENABLED ? true : false;
}

inline void __dbg_trace_header(const char *file, const unsigned int line,
                               const char *func) {
    struct timeval tv;
    char dt[24];
    const char *ansi_end;
    const char *b_cyan;
    const char *italic;
    const char *i_green;
    const char *i_magenta;
    const char *i_yellow;

    if (dbg_status & STATUS_COLOR) {
        ansi_end = ansi_attrs();
        b_cyan = ansi_attrs("1;36");
        italic = ansi_attrs("3");
        i_green = ansi_attrs("3;32");
        i_magenta = ansi_attrs("3;35");
        i_yellow = ansi_attrs("3;33");
    } else {
        ansi_end = b_cyan = italic = i_green = i_magenta = i_yellow = "";
    }
    gettimeofday(&tv, NULL);
    strftime(dt, sizeof(dt), "%F %T", gmtime(&tv.tv_sec));
    fprintf(stderr,
            "%s%s.%06ld UTC%s \u2014 %s%s%s%s:%s%s%d%s %sin%s %s%s()%s "
            "\u2014 ",
            b_cyan, dt, tv.tv_usec, ansi_end, i_green, file, ansi_end, italic,
            ansi_end, i_magenta, line, ansi_end, italic, ansi_end, i_yellow,
            func, ansi_end);
}
