# Builds and tests the C core without Xcode.
#
#   make test     unit tests
#   make ubsan    unit tests under UndefinedBehaviorSanitizer
#   make asan     unit tests under AddressSanitizer + UBSan (needs a working ASan
#                 runtime; Xcode 16.4's traps at startup on macOS 26)
#   make rules    regenerate the extension's rule files from Blocklists/
#   make bench    replay Bench/sample-corpus.txt through the engine
#   make clean

CC      ?= cc
CFLAGS  ?= -O2
WARN    := -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion -Werror
INC     := -ICore/include -ICore/src
CORE    := $(wildcard Core/src/*.c)
BUILD   := build

TRACKERS := Blocklists/trackers.txt
PARAMS   := Blocklists/tracking-params.txt
RULES    := Extension/Resources/rules

.PHONY: all test ubsan asan rules bench clean check-rules

all: $(BUILD)/swk-tool

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/swk-tool: Tools/swk_tool.c $(CORE) Core/include/swk.h Core/src/swk_internal.h | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) $(INC) Tools/swk_tool.c $(CORE) -o $@

$(BUILD)/test_core: Tests/test_core.c $(CORE) Core/include/swk.h Core/src/swk_internal.h | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) $(INC) Tests/test_core.c $(CORE) -o $@

$(BUILD)/test_core_ubsan: Tests/test_core.c $(CORE) Core/include/swk.h Core/src/swk_internal.h | $(BUILD)
	$(CC) -O1 -g -fsanitize=undefined -fno-sanitize-recover=undefined $(WARN) $(INC) Tests/test_core.c $(CORE) -o $@

$(BUILD)/test_core_asan: Tests/test_core.c $(CORE) Core/include/swk.h Core/src/swk_internal.h | $(BUILD)
	$(CC) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer $(WARN) $(INC) Tests/test_core.c $(CORE) -o $@

test: $(BUILD)/test_core
	./$(BUILD)/test_core

ubsan: $(BUILD)/test_core_ubsan
	./$(BUILD)/test_core_ubsan

asan: $(BUILD)/test_core_asan
	./$(BUILD)/test_core_asan

rules: $(BUILD)/swk-tool
	mkdir -p $(RULES)
	./$(BUILD)/swk-tool compile --trackers $(TRACKERS) --params $(PARAMS) --out $(RULES)

# Fails if the committed rule files are stale relative to Blocklists/.
check-rules: $(BUILD)/swk-tool
	mkdir -p $(BUILD)/rules-check
	./$(BUILD)/swk-tool compile --trackers $(TRACKERS) --params $(PARAMS) --out $(BUILD)/rules-check >/dev/null
	diff -r $(BUILD)/rules-check $(RULES)

bench: $(BUILD)/swk-tool
	./$(BUILD)/swk-tool bench --trackers $(TRACKERS) --params $(PARAMS) --corpus Bench/sample-corpus.txt

clean:
	rm -rf $(BUILD)
