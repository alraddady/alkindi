# Alkindi Architecture

Technical overview for developers who want to understand how Alkindi works internally, contribute to the project, or extend its functionality.

## Table of Contents

1. [Overview](#overview)
2. [Project Structure](#project-structure)
3. [Core Components](#core-components)
4. [Build System](#build-system)
5. [Memory & Error Handling](#memory--error-handling)
6. [Thread Safety](#thread-safety)
7. [Testing Strategy](#testing-strategy)
8. [Design Decisions](#design-decisions)

## Overview

Alkindi provides Python bindings to OpenSSL's post-quantum cryptography via a layered architecture:

```
┌─────────────────────────────────────────┐
│        Python Application Code          │
├─────────────────────────────────────────┤
│    High-Level API (KEM, Signature)     │  ← src/alkindi/kem.py, signatures.py
├─────────────────────────────────────────┤
│   Validation & Error Handling Layer     │  ← src/alkindi/exceptions.py, _utils.py
├─────────────────────────────────────────┤
│     CFFI-Generated Bindings (_alkindi_) │  ← src/alkindi/bindings.py
├─────────────────────────────────────────┤
│          OpenSSL EVP API (C)            │  ← libcrypto.a (bundled)
├─────────────────────────────────────────┤
│    PQC Algorithms (ML-KEM, ML-DSA, SLH-DSA) │
└─────────────────────────────────────────┘
```

**Layer Responsibilities:**
- **OpenSSL (C)**: FIPS-standardized PQC implementations, EVP API, memory management
- **CFFI Bindings**: Low-level Python-to-C interface, automatic type conversion
- **Error Handling**: Custom exception hierarchy, OpenSSL error extraction
- **High-Level API**: Pythonic interfaces, parameter validation, type hints

## Project Structure

```
alkindi-openssl/
├── src/alkindi/              # Main package source
│   ├── __init__.py           # Package exports and public API
│   ├── bindings.py           # CFFI bindings generator
│   ├── kem.py                # ML-KEM implementation
│   ├── signatures.py         # ML-DSA/SLH-DSA implementation
│   ├── exceptions.py         # Exception hierarchy
│   ├── _utils.py             # Internal utilities (error checking)
│   ├── _params.py            # Algorithm parameters (immutable)
│   └── utilities.py          # Public utility functions
│
├── tests/                    # Test suite
│   ├── correctness/          # Functional tests
│   ├── property/             # Property-based tests
│   ├── fuzzing/              # Fuzz tests
│   └── NIST/                 # NIST ACVP test vectors
│
├── scripts/                  # Build and utility scripts
│   └── build_openssl.sh      # OpenSSL build script
│
├── pyproject.toml            # Project metadata and configuration
├── setup.py                  # Custom build logic
├── .env                      # OpenSSL version configuration
└── README.md                 # User documentation
```

## Core Components

### 1. CFFI Bindings (`src/alkindi/bindings.py`)

Generates low-level Python bindings to OpenSSL's C API. Runs at build time to create the `_alkindi_` extension module with OpenSSL function declarations, compilation settings, and platform-specific linking.

### 2. Key Encapsulation (`src/alkindi/kem.py`)

Provides ML-KEM operations via static methods: `generate_keypair()`, `encapsulate()`, `decapsulate()`. Each operation validates inputs, creates OpenSSL contexts, performs crypto operations, and cleans up resources in try/finally blocks.

**Operation Flow**: Validation → Context creation → OpenSSL EVP API calls → Export raw bytes → Cleanup → Return results

### 3. Digital Signatures (`src/alkindi/signatures.py`)

Provides ML-DSA and SLH-DSA operations: `generate_keypair()`, `sign()`, `verify()`. Supports optional context strings (max 255 bytes) per FIPS 204/205.

**Sign Flow**: Validate → Import key → Create digest context → Sign → Cleanup → Return signature

**Verify Flow**: Validate → Import key → Create digest context → Verify → Return boolean

### 4. Parameters (`src/alkindi/_params.py`)

Immutable algorithm parameters using `MappingProxyType` and `frozenset`:
- Prevents accidental modifications
- Thread-safe by design
- Stores key/ciphertext/signature sizes for all supported algorithms

### 5. Error Handling (`src/alkindi/exceptions.py`, `src/alkindi/_utils.py`)

**Exception Hierarchy**: `AlkindiError` → `OpenSSLError` (OpenSSL failures) / `AlkindiAPIError` (API usage errors)

The `check_openssl_errors()` utility validates OpenSSL return values (NULL pointers, error codes) and extracts error strings from OpenSSL's error queue.

### 6. Utilities (`src/alkindi/utilities.py`)

Public helper functions including `guide()` for displaying supported algorithms, security levels, and metadata.

## Build System

**Build Flow**: `pip install` → setuptools reads `pyproject.toml` → invokes `setup.py` → CFFI generates C extension from `bindings.py` → `BuildPyWithLibs` bundles OpenSSL libs to `alkindi.libs/` → package installation

### OpenSSL Build (`scripts/build_openssl.sh`)

Builds minimal PQC-only OpenSSL 3.5.0+ with static linking, disabled legacy features (TLS/SSL, classical crypto), and size optimization (`-Os`, `-flto`). Outputs `libcrypto.a`, headers, and binary to `openssl-build/install/`.

### Runtime Library Loading

Uses platform-specific rpath for bundled libraries:
- **macOS**: `-Wl,-rpath,@loader_path/../alkindi.libs`
- **Linux**: `-Wl,-rpath,$ORIGIN/../alkindi.libs`
- **Windows**: Loaded from same directory or PATH

## Memory & Error Handling

### Resource Management Pattern

**Create → Use → Free in try/finally blocks**

Key principles:
1. Initialize OpenSSL objects to `ffi.NULL` for safe cleanup checks
2. Always free resources in `finally` blocks (prevents memory leaks)
3. Copy data to Python bytes before returning: `bytes(ffi.buffer(...))`
4. No dangling references to C objects

**Memory Model**:
- **C-side**: OpenSSL objects (e.g., `EVP_PKEY`) must be explicitly freed
- **Python-side**: CFFI buffers (e.g., `ffi.new("unsigned char[]", size)`) are garbage collected

### Error Handling Strategy

**Three-layer approach**:
1. **Input Validation** (Python): Check algorithm names, parameter limits → raises `AlkindiAPIError`
2. **OpenSSL Checks** (CFFI): Validate return values and pointers → raises `OpenSSLError` with error queue details
3. **Resource Cleanup** (always): Use try/finally blocks to prevent leaks

## Thread Safety

**Stateless design**:
- All methods are static with no shared state or class variables
- Each operation creates its own OpenSSL contexts
- Operations clean up before returning
- OpenSSL contexts never shared between threads
- CFFI releases the GIL during C calls for parallelism

**Guarantees**: Safe for concurrent calls to any KEM/Signature methods. No synchronization required.

## Testing Strategy

**Four-layer approach**:
1. **Correctness** (`tests/correctness/`): Basic functionality, round-trip operations, error cases, thread safety
2. **Property-Based** (`tests/property/`): Hypothesis-generated cases, invariants, size consistency
3. **Fuzzing** (`tests/fuzzing/`): Random inputs, edge cases, graceful error handling
4. **NIST ACVP** (`tests/NIST/`): Official test vectors, byte-for-byte validation, standards compliance

**Coverage goals**: >95% line coverage, >90% branch coverage, 100% algorithm coverage

## Design Decisions

**Why CFFI over ctypes?**

CFFI provides better type safety, automatic header parsing, cleaner code generation, and is the industry standard for C bindings. It generates more efficient code and provides better error messages during compilation. While ctypes is part of the Python standard library, it's more verbose, error-prone, and lacks compile-time type checking.

**Why bundle OpenSSL?**

Bundling ensures PQC support (not all system OpenSSL versions have it), provides version consistency across platforms, enables minimal builds for smaller size, and gives full control over configuration and security. This approach guarantees that users get the same cryptographic functionality regardless of their system's OpenSSL installation. System OpenSSL has inconsistent PQC support and version fragmentation, which would make the library unreliable across different environments.

## Contributing

Read this document, follow existing patterns, add tests for all new functionality, update documentation for user-facing changes, and run the full test suite before submitting. See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## References

- [OpenSSL EVP Documentation](https://www.openssl.org/docs/manmaster/man7/evp.html) | [CFFI Documentation](https://cffi.readthedocs.io/)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) | [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) | [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [PEP 517/518: Build System](https://peps.python.org/pep-0517/)
