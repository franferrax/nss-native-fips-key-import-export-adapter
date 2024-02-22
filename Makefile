# SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

NAME         := nssadapter
SRC_DIR      := src
TST_DIR      := test
BIN_DIR      := bin
OUTPUT       := $(BIN_DIR)/lib$(NAME).so
DBG_SENTINEL := $(BIN_DIR)/_built_in_debug_mode_

JAVA          = java
CC            = gcc
LIBS          = softokn3 nss3
INCLUDES      = /usr/include/nspr4
CFLAGS        = -shared -fPIC $(addprefix -l,$(LIBS)) $(addprefix -I,$(INCLUDES)) \
                -Wpedantic -Wall -Wextra -Wconversion -Werror -fvisibility=hidden
REL_CFLAGS    = -O3
DBG_CFLAGS    = -Wno-error=unused-variable -Wno-error=unused-parameter -O0 -g -DDEBUG

# https://clang.llvm.org/docs/ClangFormatStyleOptions.html
CLANG_FORMAT_STYLE = {                                                         \
    BasedOnStyle: LLVM,                                                        \
    IndentWidth: 4,                                                            \
    AlignArrayOfStructures: Left,                                              \
    AlignConsecutiveMacros: AcrossEmptyLines,                                  \
    AllowShortFunctionsOnASingleLine: Inline,                                  \
    InsertNewlineAtEOF: true,                                                  \
}
CLANG_FORMAT_IGNORED_FILES = $(SRC_DIR)/nss_lowkey_imported.c                  \
                             $(SRC_DIR)/sensitive_attributes.h
# Reasons for exclusion:
#   nss_lowkey_imported.c  <- copy and pasted content from NSS
#   sensitive_attributes.h <- this file is wrongly formatted


#
# Build
#
SRC_FILES = $(wildcard $(SRC_DIR)/*.h) $(wildcard $(SRC_DIR)/*.c)
ifeq ($(wildcard $(DBG_SENTINEL)),$(DBG_SENTINEL))
  BUILT_MODE = debug
  CLEAN_IF_BUILT_MODE_IS_DEBUG = clean
else
  BUILT_MODE = release
  CLEAN_IF_BUILT_MODE_IS_RELEASE = clean
endif

.PHONY: release
release: CFLAGS += $(REL_CFLAGS)
release: $(CLEAN_IF_BUILT_MODE_IS_DEBUG) $(OUTPUT)  ## Build in RELEASE mode (default)

.PHONY: debug
debug: CFLAGS += $(DBG_CFLAGS)
debug: CREATE_DBG_SENTINEL_IF_NEEDED = touch $(DBG_SENTINEL)
debug: $(CLEAN_IF_BUILT_MODE_IS_RELEASE) $(OUTPUT)  ## Build in DEBUG mode

.PHONY: rebuild
rebuild: clean $(BUILT_MODE)                        ## Force a rebuild in the previous mode (RELEASE if not built)

.PHONY: clean
clean:                                              ## Remove binaries and artifacts
	rm -rf $(BIN_DIR)


$(BIN_DIR):
	@mkdir $(BIN_DIR)

$(OUTPUT): $(BIN_DIR) $(SRC_FILES)
	@$(CREATE_DBG_SENTINEL_IF_NEEDED)
	$(CC) $(CFLAGS) $(filter %.c, $+) -o $@


#
# Utilities
#
.PHONY: format
format:                                             ## Automatically format the source code (requires 'clang-format')
	@clang-format --verbose -i --style='$(CLANG_FORMAT_STYLE)' \
	    $(filter-out $(CLANG_FORMAT_IGNORED_FILES),$(SRC_FILES)) || \
	    echo "In RHEL/Fedora, 'clang-format' is provided by the 'clang-tools-extra' package"

.PHONY: info
info: $(BUILT_MODE)                                 ## Show built binary information (build mode, linkage and symbols)
	@echo
	@test -f $(DBG_SENTINEL) && echo "Built in DEBUG mode" || echo "Built in RELEASE mode"
	@echo
	ldd $(OUTPUT)
	@echo
	nm --dynamic --radix=x $(OUTPUT)
	@echo

.PHONY: test
test: $(BUILT_MODE)                                 ## Run the test suite, usage: make test [JAVA=/path/to/java]
	$(JAVA)c -d $(BIN_DIR) $(TST_DIR)/Main.java && $(JAVA) -cp $(BIN_DIR) Main $(OUTPUT)

.PHONY: help
help:                                               ## Display this message
	@echo '$(shell tput bold)Available make targets:$(shell tput sgr0)'
	@sed -ne 's/^\([a-zA-Z0-9_\-]*\):.*##\s*\(.*\)/  $(shell tput setaf 6)\1$(shell tput sgr0)\2/p' \
	    $(MAKEFILE_LIST) | column -c2 -t -s
