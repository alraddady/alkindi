# Alkindi Architecture

Technical overview for developers who want to understand how Alkindi works internally, contribute to the project, or
extend its functionality.

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
│    High-Level API (KEM, Signature)      │  ← src/alkindi/kem.py, signatures.py
├─────────────────────────────────────────┤
│   Validation & Error Handling Layer     │  ← src/alkindi/_internal/exceptions.py, utils.py
├─────────────────────────────────────────┤
│     CFFI-Generated Bindings (_alkindi_) │  ← src/alkindi/_internal/bindings.py
├─────────────────────────────────────────┤
│          OpenSSL EVP API (C)            │  ← libcrypto.a (statically linked)
├─────────────────────────────────────────┤
│             PQC Algorithms              │
└─────────────────────────────────────────┘
```

**Layer Responsibilities:**

- **OpenSSL (C)**: FIPS-standardized PQC implementations, EVP API, memory management
- **CFFI Bindings**: Low-level Python-to-C interface, automatic type conversion
- **Error Handling**: Custom exception hierarchy, OpenSSL error extraction
- **High-Level API**: Pythonic interfaces, parameter validation, type hints

## Project Structure

```
alkindi/
├── src/alkindi/              # Main package source
│   ├── __init__.py           # Package exports and public API
│   ├── kem.py                # ML-KEM implementation
│   ├── signatures.py         # ML-DSA/SLH-DSA implementation
│   ├── serialization.py      # DER/PEM key serialization
│   ├── utilities.py          # Public utility functions
│   └── _internal/            # Internal implementation details
│       ├── bindings.py       # CFFI bindings generator
│       ├── exceptions.py     # Exception hierarchy
│       ├── utils.py          # Internal utilities (error checking)
│       └── params.py         # Algorithm parameters (immutable)
│
├── tests/                    # Test suite
│   ├── correctness/          # Functional and round-trip tests
│   ├── security/             # Security property tests
│   └── validation/           # Standards validation tests
│
├── scripts/                  # Build and utility scripts
│   └── build_openssl.sh      # OpenSSL build script
│
├── pyproject.toml            # Project metadata and configuration
├── setup.py                  # Custom build logic
├── build.env                 # OpenSSL version configuration
└── README.md                 # User documentation
```

## Core Components

### 1. CFFI Bindings (`src/alkindi/_internal/bindings.py`)

Generates low-level Python bindings to OpenSSL's C API. Runs at build time to create the `_alkindi_` extension module
with OpenSSL function declarations, compilation settings, and platform-specific linking.

### 2. Key Encapsulation (`src/alkindi/kem.py`)

Provides ML-KEM operations via static methods: `generate_keypair()`, `encapsulate()`, `decapsulate()`. Each operation
validates inputs, creates OpenSSL contexts, performs crypto operations, and cleans up resources in try/finally blocks.

**Operation Flow**: Validation → Context creation → OpenSSL EVP API calls → Export raw bytes → Cleanup → Return results

### 3. Digital Signatures (`src/alkindi/signatures.py`)

Provides ML-DSA and SLH-DSA operations: `generate_keypair()`, `sign()`, `verify()`. Supports optional context strings
(max 255 bytes) per FIPS 204/205.

**Sign Flow**: Validate → Import key → Create digest context → Sign → Cleanup → Return signature

**Verify Flow**: Validate → Import key → Create digest context → Verify → Return boolean

### 4. Parameters (`src/alkindi/_internal/params.py`)

Immutable algorithm parameters using `MappingProxyType` and `frozenset`:

- Prevents accidental modifications
- Thread-safe by design
- Stores key/ciphertext/signature sizes for all supported algorithms

### 5. Error Handling (`src/alkindi/_internal/exceptions.py`, `src/alkindi/_internal/utils.py`)

**Exception Hierarchy**: `AlkindiError` → `OpenSSLError` (OpenSSL failures) / `AlkindiAPIError` (API usage errors)

The `check_openssl_errors()` utility validates OpenSSL return values (NULL pointers, error codes) and extracts error
strings from OpenSSL's error queue.

### 6. Utilities (`src/alkindi/utilities.py`)

Public helper functions including `guide()` for displaying supported algorithms, security levels, and metadata.

## Build System

**Build Flow**: `pip install` → setuptools reads `pyproject.toml` → invokes `setup.py` → CFFI builds `_alkindi_`
extension with OpenSSL statically linked → package installation

### OpenSSL Build (`scripts/build_openssl.sh`)

Builds minimal PQC-only OpenSSL 3.6.2 with static linking, disabled legacy features (TLS/SSL, classical crypto), and
size optimization (`-Os`, `-flto`). Outputs `libcrypto.a` and headers to `scripts/openssl-build/install/`.

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

**Three-layer approach**:

1. **Correctness** (`tests/correctness/`): Basic functionality, round-trip operations, error cases, thread safety
2. **Security** (`tests/security/`): Security property tests for KEM, signatures, and serialization
3. **Validation** (`tests/validation/`): Standards compliance, interoperability, and NIST ACVP test vectors *(NIST ACVP planned)*

## Design Decisions

**Why CFFI over ctypes?**

CFFI provides better type safety, automatic header parsing, and cleaner code generation. ctypes is more verbose,
error-prone, and lacks compile-time type checking.

**Why bundle OpenSSL?**

System OpenSSL has inconsistent PQC support across platforms and versions. Bundling a minimal static build guarantees
the same cryptographic functionality everywhere.

## References

- [OpenSSL EVP Documentation](https://www.openssl.org/docs/manmaster/man7/evp.html) | [CFFI Documentation](https://cffi.readthedocs.io/)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) | [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) | [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [PEP 517/518: Build System](https://peps.python.org/pep-0517/)
