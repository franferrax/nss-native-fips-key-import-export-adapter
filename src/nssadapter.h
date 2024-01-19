// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef NSS_ADAPTER_H
#define NSS_ADAPTER_H

#include <stdio.h>

// Shared library constructor/initializer and destructor/finalizer
#define CONSTRUCTOR_FUNCTION __attribute__((constructor))
#define DESTRUCTOR_FUNCTION __attribute__((destructor))

// Compile-time debug utility (when building with `make debug`)
#ifdef DEBUG
  #include <time.h>
  #include <sys/time.h>

  // To disable colors, change _ansi_ to:
  // #define _ansi_(text, ansi_attrs)    text
  #define _ansi_(text, ansi_attrs)    "\033[" #ansi_attrs "m" text "\033[m"

  #define dbg_trace(...) do {                                                  \
      char dt[24]; struct timeval tv; gettimeofday(&tv, NULL);                 \
      strftime(dt, sizeof(dt), "%F %T", gmtime(&tv.tv_sec));                   \
      fprintf(stderr, _ansi_("%s.%06ld UTC", 1;36) " \u2014 "                  \
              _ansi_("%s", 3;32) _ansi_(":", 3) _ansi_("%d", 3;35)             \
              _ansi_(" in ", 3) _ansi_("%s()", 3;33) " \u2014 ",               \
              dt, tv.tv_usec, __FILE__, __LINE__, __func__);                   \
      fprintf(stderr, ##__VA_ARGS__); fputc('\n', stderr); fflush(stderr);     \
  } while(0)

  #define HEX32 "0x%08lx"
  #define HEX64 "0x%016lx"
#else
  #define dbg_trace(format, ...)
#endif // DEBUG

#endif // NSS_ADAPTER_H