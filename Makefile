# Makefile for SHA-256 Checker with C and Rust

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lraylib -lm -lpthread -ldl

# Rust library details
RUST_LIB_DIR = target/release
RUST_LIB = $(RUST_LIB_DIR)/libsha256_rust.a

# Source files
C_SOURCES = raylib_gui.c sha256.c
HEADERS = sha256.h

# Output binary
OUTPUT = sha256_checker

.PHONY: all clean rust

all: rust $(OUTPUT)

# Build Rust static library
rust:
	@echo "Building Rust SHA-256 library..."
	cargo build --release

# Build C program and link with Rust library
$(OUTPUT): $(C_SOURCES) $(HEADERS) $(RUST_LIB)
	@echo "Compiling C program and linking with Rust library..."
	$(CC) $(CFLAGS) $(C_SOURCES) $(RUST_LIB) -o $(OUTPUT) $(LDFLAGS)
	@echo "Build complete! Run with: ./$(OUTPUT)"

clean:
	rm -f $(OUTPUT)
	cargo clean
	@echo "Clean complete!"

run: all
	./$(OUTPUT)