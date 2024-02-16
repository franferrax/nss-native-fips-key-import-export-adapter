# SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

NAME         := nssadapter
SRC_DIR      := src
BIN_DIR      := bin
OUTPUT       := $(BIN_DIR)/lib$(NAME).so
DBG_SENTINEL := $(BIN_DIR)/_built_in_debug_mode_

CC            = gcc
LIBS          = softokn3
INCLUDES      = /usr/include/nspr4
CFLAGS        = -shared -fPIC $(addprefix -l,$(LIBS)) $(addprefix -I,$(INCLUDES)) \
                -Wpedantic -Wall -Wextra -Wconversion -Werror -fvisibility=hidden
REL_CFLAGS    = -O3
DBG_CFLAGS    = -Wno-error=unused-variable -Wno-error=unused-parameter -O0 -g -DDEBUG


#
# Build
#
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

$(OUTPUT): $(BIN_DIR) $(wildcard $(SRC_DIR)/*.h) $(wildcard $(SRC_DIR)/*.c)
	@$(CREATE_DBG_SENTINEL_IF_NEEDED)
	$(CC) $(CFLAGS) $(filter %.c, $+) -o $@


#
# Utilities
#
.PHONY: info
info: $(BUILT_MODE)                                 ## Show built binary information (build mode, linkage and symbols)
	@echo
	@test -f $(DBG_SENTINEL) && echo "Built in DEBUG mode" || echo "Built in RELEASE mode"
	@echo
	ldd $(OUTPUT)
	@echo
	nm --dynamic --radix=x $(OUTPUT)
	@echo

.PHONY: help
help:                                               ## Display this message
	@echo '$(shell tput bold)Available make targets:$(shell tput sgr0)'
	@sed -ne 's/^\([a-zA-Z0-9_\-]*\):.*##\s*\(.*\)/  $(shell tput setaf 6)\1$(shell tput sgr0):\2/p' \
	    $(MAKEFILE_LIST) | column -c2 -t -s:
