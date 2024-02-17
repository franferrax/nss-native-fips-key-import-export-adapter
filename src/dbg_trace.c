// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "dbg_trace.h"
#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define VAR_NAME          "NSS_ADAPTER_DEBUG"
#define DISABLED_OPT      "no"
#define ENABLED_OPT       "yes"
#define ENABLED_COLOR_OPT "color"

#define STATUS_DISABLED   (0)
#define STATUS_ENABLED    (1 << 0)
#define STATUS_COLOR      (1 << 1)

#ifdef DEBUG
#define STATUS_DEFAULT (STATUS_ENABLED | STATUS_COLOR)
#else
#define STATUS_DEFAULT (STATUS_DISABLED)
#endif

static FILE *dbg_file = NULL;
static unsigned char dbg_status = STATUS_DEFAULT;

// If 'text' startswith 'other', returns the length of 'other', otherwise zero
#define __case_starts_with(text, other)                                        \
    (strncasecmp((text), (other), sizeof(other) - 1) ? 0 : (sizeof(other) - 1))

void dbg_initialize() {
    const char *var = getenv(VAR_NAME);
    if (var != NULL) {
        size_t offset = 0;
        if (__case_starts_with(var, DISABLED_OPT)) {
            dbg_status = STATUS_DISABLED;
        } else if ((offset = __case_starts_with(var, ENABLED_OPT))) {
            dbg_status = STATUS_ENABLED;
        } else if ((offset = __case_starts_with(var, ENABLED_COLOR_OPT))) {
            dbg_status = STATUS_ENABLED | STATUS_COLOR;
        }
        if (offset > 0 && strlen(var + offset) > 0 && var[offset] == ':') {
            const char *file_path = var + offset + 1;
            dbg_file = fopen(file_path, "a");
            if (dbg_file == NULL) {
                dbg_status = STATUS_DISABLED;
                warn(VAR_NAME " file '%s'", file_path);
            }
        }
    }
    if (dbg_file == NULL) {
        dbg_file = stderr;
    }
}
inline bool dbg_is_enabled() {
    return dbg_status & STATUS_ENABLED;
}

void dbg_finalize() {
    if (dbg_file != NULL && dbg_file != stderr) {
        fclose(dbg_file);
    }
}

FILE *__dbg_file() {
    return dbg_file;
}

void __dbg_new_line_and_flush() {
    if (dbg_is_enabled()) {
        fputc('\n', dbg_file);
        fflush(dbg_file);
    }
}

// Generates an ANSI terminal escape sequence
#define __ansi_attrs(attrs) "\033[" attrs "m"

inline void __dbg_trace_header(const char *file, const unsigned int line,
                               const char *func) {
    struct timeval tv;
    char datetime[24];
    const char *cyan;
    const char *green;
    const char *magenta;
    const char *yellow;
    const char *reset;
    if (dbg_status & STATUS_COLOR) {
        cyan = __ansi_attrs("36");
        green = __ansi_attrs("32");
        magenta = __ansi_attrs("35");
        yellow = __ansi_attrs("33");
        reset = __ansi_attrs();
    } else {
        cyan = green = magenta = yellow = reset = "";
    }
    gettimeofday(&tv, NULL);
    strftime(datetime, sizeof(datetime), "%F %T", gmtime(&tv.tv_sec));
    fprintf(dbg_file, "%s%s.%06ld%s: %s%s%s:%s%d%s, %s%s()%s: ", cyan, datetime,
            tv.tv_usec, reset, green, file, reset, magenta, line, reset, yellow,
            func, reset);
}
