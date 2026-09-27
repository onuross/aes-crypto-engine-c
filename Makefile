# ============================================================================ #
#                  AES Cryptographic Engine - Build System                     #
# ============================================================================ #

CC       ?= clang
CFLAGS   := -Wall -Wextra -Werror -pedantic -std=c99 -O2 -Iinclude

SRC_DIR  := src
INC_DIR  := include
TEST_DIR := tests
OBJ_DIR  := build

LIB_SRC  := $(SRC_DIR)/aes.c
MAIN_SRC := $(SRC_DIR)/main.c
TEST_SRC := $(TEST_DIR)/test_aes.c

LIB_OBJ  := $(OBJ_DIR)/aes.o
MAIN_OBJ := $(OBJ_DIR)/main.o
TEST_OBJ := $(OBJ_DIR)/test_aes.o

DEMO_BIN := aes_demo
TEST_BIN := test_runner

.PHONY: all demo test run clean

# Default target: builds both the CLI demo and the NIST verification suite
all: $(DEMO_BIN) $(TEST_BIN)

# Build the CLI demonstration binary
$(DEMO_BIN): $(LIB_OBJ) $(MAIN_OBJ)
	$(CC) $(CFLAGS) $^ -o $@

# Build the NIST unit test binary
$(TEST_BIN): $(LIB_OBJ) $(TEST_OBJ)
	$(CC) $(CFLAGS) $^ -o $@

# Compile library and application source files into object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/aes.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile test source files into object files
$(OBJ_DIR)/%.o: $(TEST_DIR)/%.c $(INC_DIR)/aes.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create build directory for object files
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Build and execute the NIST test suite
test: $(TEST_BIN)
	./$(TEST_BIN)

# Build and execute the CLI demonstration
run: $(DEMO_BIN)
	./$(DEMO_BIN)

# Remove all compiled binaries and build artifacts
clean:
	rm -rf $(OBJ_DIR) $(DEMO_BIN) $(TEST_BIN) *.dSYM