# SHA-256 Implementation: C and Rust Comparison

A graphical application that implements SHA-256 hashing in both C and Rust, comparing the results against OpenSSL to verify correctness.

## Project Structure

```
sha256-checker/
├── Cargo.toml              # Rust project configuration
├── Makefile                # Build automation script
├── README.md               # This file
│
├── src/
│   └── lib.rs             # Rust SHA-256 implementation (bare-metal, no std)
│
├── sha256.h                # C SHA-256 header file
├── sha256.c                # C SHA-256 implementation
└── raylib_gui.c            # Main GUI application with Raylib
```

After building, the following will be generated:

```
sha256-checker/
├── target/
│   └── release/
│       └── libsha256_rust.a    # Compiled Rust static library
└── sha256_checker              # Final executable
```

## Architecture Overview

This project demonstrates Foreign Function Interface (FFI) between C and Rust. The architecture consists of three main components:

### 1. C SHA-256 Implementation (sha256.c)
A bare-metal implementation of the SHA-256 algorithm in C, following the FIPS 180-4 specification.

### 2. Rust SHA-256 Implementation (src/lib.rs)
An equivalent bare-metal implementation in Rust using `#![no_std]` (no standard library). Functions are exported with C-compatible interfaces for FFI.

### 3. GUI Application (raylib_gui.c)
The main application built with Raylib that:
- Provides user interface for text input
- Calls both C and Rust SHA-256 implementations
- Executes OpenSSL via system command for verification
- Displays and compares all three results

## How the Components Connect

### Data Flow

```
User Input (Text)
       |
       v
┌──────────────────┐
│  raylib_gui.c    │  Main Application
│  (C Code)        │
└──────────────────┘
       |
       |-----> sha256_init(&c_ctx)
       |       sha256_update(&c_ctx, text, len)
       |       sha256_final(&c_ctx, digest)
       |       [C Implementation]
       |
       |-----> rust_sha256_init(&rust_ctx)
       |       rust_sha256_update(&rust_ctx, text, len)
       |       rust_sha256_final(&rust_ctx, digest)
       |       [Rust Implementation via FFI]
       |
       |-----> popen("openssl dgst -sha256")
       |       [OpenSSL System Command]
       |
       v
Compare Results & Display
```

### Foreign Function Interface (FFI)

The Rust code exports C-compatible functions that the C code can call directly.

**Rust Side (src/lib.rs):**

```rust
#[repr(C)]                           // Use C memory layout
pub struct Sha256Ctx {
    h: [u32; 8],
    buffer: [u8; 64],
    buflen: u32,
    bitlen: u64,
}

#[no_mangle]                         // Prevent name mangling
pub extern "C" fn rust_sha256_init(ctx: *mut Sha256Ctx) {
    // Implementation
}
```

**C Side (raylib_gui.c):**

```c
// Declare the Rust struct (must match memory layout)
typedef struct {
    unsigned int h[8];
    unsigned char buffer[64];
    unsigned int buflen;
    unsigned long long bitlen;
} RustSha256Ctx;

// Declare external Rust functions
extern void rust_sha256_init(RustSha256Ctx *ctx);

// Call Rust function from C
RustSha256Ctx ctx;
rust_sha256_init(&ctx);              // This calls into Rust code
```

### Key FFI Concepts

1. **#[no_mangle]**: Prevents Rust compiler from changing function names, allowing C linker to find them
2. **extern "C"**: Uses C calling convention for function calls
3. **#[repr(C)]**: Ensures Rust struct has same memory layout as C struct
4. **Raw pointers**: `*mut T` in Rust corresponds to `T*` in C

## Build Process

### Step 1: Compile Rust to Static Library

```bash
cargo build --release
```

This produces `target/release/libsha256_rust.a`, a static library containing compiled Rust code.

### Step 2: Compile C Code and Link Everything

```bash
gcc -Wall -O2 raylib_gui.c sha256.c \
    target/release/libsha256_rust.a \
    -o sha256_checker \
    -lraylib -lm -lpthread -ldl
```

This:
- Compiles `raylib_gui.c` (main application)
- Compiles `sha256.c` (C implementation)
- Links the Rust static library
- Links required system libraries
- Produces the final executable `sha256_checker`

### Libraries Linked

| Library | Purpose |
|---------|---------|
| raylib | GUI rendering and input handling |
| m | Standard math library |
| pthread | POSIX threads (required by Rust runtime) |
| dl | Dynamic linking (required by Rust runtime) |

## Building and Running

### Quick Build

```bash
make
```

### Run Application

```bash
./sha256_checker
```

### Clean Build Artifacts

```bash
make clean
```

## Usage

1. Launch the application: `./sha256_checker`
2. Type text into the input field
3. Press Enter or click "Check Hash"
4. View the results:
   - C SHA-256 hash
   - Rust SHA-256 hash
   - OpenSSL reference hash
   - Verification status for each implementation

## How Text is Passed and Processed

### 1. User Input Collection

The Raylib GUI captures keyboard input character by character:

```c
char inputText[MAX_INPUT] = {0};
int letterCount = 0;

int key = GetCharPressed();
while (key > 0) {
    if ((key >= 32) && (key <= 125)) {
        inputText[letterCount] = (char)key;
        inputText[letterCount + 1] = '\0';
        letterCount++;
    }
    key = GetCharPressed();
}
```

### 2. Text Processing in C Implementation

When user presses Enter, the text is passed to the C SHA-256 function:

```c
struct sha256_ctx c_ctx;
unsigned char c_digest[32];
char c_hash[65];

sha256_init(&c_ctx);
sha256_update(&c_ctx, (const u8 *)inputText, strlen(inputText));
sha256_final(&c_ctx, c_digest);
sha256_to_hex(c_digest, c_hash);
```

### 3. Text Processing in Rust Implementation

The same text is passed to Rust via FFI:

```c
RustSha256Ctx rust_ctx;
unsigned char rust_digest[32];
char rust_hash[65];

rust_sha256_init(&rust_ctx);
rust_sha256_update(&rust_ctx, 
                   (const unsigned char *)inputText, 
                   strlen(inputText));
rust_sha256_final(&rust_ctx, rust_digest);
rust_sha256_to_hex(rust_digest, rust_hash);
```

The Rust function receives:
- A pointer to the text buffer
- The length of the text
- Processes it identically to the C implementation

### 4. OpenSSL Verification

The text is passed to OpenSSL via system command:

```c
void run_openssl_sha256(const char *input, char *openssl_output) {
    char command[2048];
    snprintf(command, sizeof(command), 
             "echo -n '%s' | openssl dgst -sha256", input);
    
    FILE *fp = popen(command, "r");
    fgets(openssl_output, 65, fp);
    pclose(fp);
}
```

### 5. Result Comparison

All three hashes are compared:

```c
if (strcmp(cHash, opensslHash) == 0) {
    strcpy(cVsOpensslMsg, "C matches OpenSSL [PASS]");
}

if (strcmp(rustHash, opensslHash) == 0) {
    strcpy(rustVsOpensslMsg, "Rust matches OpenSSL [PASS]");
}
```

## Memory Layout Compatibility

For FFI to work correctly, the Rust and C structures must have identical memory layouts:

**C Structure:**
```c
struct sha256_ctx {
    u32 h[8];           // 32 bytes
    u8  buffer[64];     // 64 bytes
    u32 buflen;         // 4 bytes
    u64 bitlen;         // 8 bytes
};                      // Total: 108 bytes
```

**Rust Structure:**
```rust
#[repr(C)]
pub struct Sha256Ctx {
    h: [u32; 8],        // 32 bytes
    buffer: [u8; 64],   // 64 bytes
    buflen: u32,        // 4 bytes
    bitlen: u64,        // 8 bytes
}                       // Total: 108 bytes
```

The `#[repr(C)]` attribute ensures Rust uses the same memory layout as C.

## Execution Flow

```
1. Application Start
   └─> InitWindow() - Raylib creates GUI window

2. Main Loop (60 FPS)
   ├─> GetCharPressed() - Capture user input
   ├─> Store input in inputText buffer
   └─> Display input on screen

3. User Presses Enter
   ├─> Call sha256_init/update/final (C)
   │   └─> Process text, produce hash
   │
   ├─> Call rust_sha256_init/update/final (Rust via FFI)
   │   └─> Process same text, produce hash
   │
   └─> Call run_openssl_sha256 (System command)
       └─> Execute OpenSSL, capture output

4. Display Results
   ├─> Show all three hashes
   ├─> Compare C hash with OpenSSL
   ├─> Compare Rust hash with OpenSSL
   └─> Display verification status

5. Loop continues until window closed
```

## Testing

The application can be tested with known SHA-256 test vectors:

| Input | Expected SHA-256 |
|-------|------------------|
| (empty) | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| hello | 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 |
| abc | ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad |

All three implementations should produce identical results for any input.

## Technical Details

### SHA-256 Algorithm Implementation

Both C and Rust implementations follow the FIPS 180-4 specification:

1. Initialize hash values (8 words)
2. Process input in 512-bit (64-byte) blocks
3. Apply compression function (64 rounds per block)
4. Output final 256-bit (32-byte) hash

### No Standard Library in Rust

The Rust implementation uses `#![no_std]`, meaning:
- No heap allocation
- No standard collections (Vec, HashMap, etc.)
- No file I/O
- Only stack-allocated arrays and primitives
- Demonstrates bare-metal compatibility

This makes the Rust code directly comparable to the C implementation in terms of resource usage and portability.

## References

- SHA-256 Specification: FIPS 180-4
- Raylib Documentation: https://www.raylib.com/
- Rust FFI Guide: https://doc.rust-lang.org/nomicon/ffi.html
- Cargo Book: https://doc.rust-lang.org/cargo/
