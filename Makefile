# HGS Attestation Path Analyzer — user-mode Makefile.
#
# Targets the MinGW-w64 / clang toolchain on Windows. The kernel side
# is built separately via `makefile.kernel`. Source list is explicit;
# do NOT wildcard $(SRC_DIR)/*.c because that would pull the
# hgs_kernel_*.c files into a user-mode link and break the build.

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c99 -O2 -g -I$(INC_DIR)
LDFLAGS = -ladvapi32 -lcrypt32 -lole32 -loleaut32 -lwbemuuid \
          -lpsapi -lntdll -lkernel32 -luser32 -ltbs -lrpcrt4

SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

# User-mode sources (must stay in sync with build.bat SOURCES).
SOURCES = \
    $(SRC_DIR)/main.c \
    $(SRC_DIR)/hgs_framework.c \
    $(SRC_DIR)/hgs_rpc_observer.c \
    $(SRC_DIR)/hgs_attestation_fuzzer.c \
    $(SRC_DIR)/hgs_key_protector_model.c \
    $(SRC_DIR)/hgs_vm_policy_sampler.c \
    $(SRC_DIR)/hgs_utils.c \
    $(SRC_DIR)/getopt_compat.c

OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET  = $(BIN_DIR)/hgs_manipulator.exe

all: $(TARGET)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)

release: CFLAGS += -DNDEBUG -O3
release: clean $(TARGET)

run: $(TARGET)
	./$(TARGET) --help

help:
	@echo "Targets:"
	@echo "  all     - build $(TARGET) (default)"
	@echo "  clean   - remove obj/ bin/"
	@echo "  debug   - build with -DDEBUG -g3"
	@echo "  release - clean rebuild with -O3"
	@echo "  run     - build and run --help"

.PHONY: all clean debug release run help
