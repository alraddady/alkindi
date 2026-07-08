# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.4] — 2026-07-08

### Added
- `bytearray` and `memoryview` inputs are now accepted (and actually work)
  across KEM, signature, and serialization APIs
- Python 3.14 wheels (`cp314`) added to the CI build matrix
- Test suite coverage for bytes-like inputs, including non-`bytes` memoryviews

### Changed
- Upgraded OpenSSL to 3.6.3 (security patch release, June 2026)
- Build now requires `setuptools>=77` (needed for the SPDX license metadata);
  removed the redundant `wheel` build requirement

### Fixed
- Passing a `bytearray` or `memoryview` raised `TypeError` from CFFI instead
  of performing the operation; all bytes-like inputs are now routed through
  `ffi.from_buffer`
- Length validation for `seed` and `context` now measures bytes, so
  memoryviews with itemsize > 1 (e.g. over an `array.array`) are handled
  correctly
- Shared-secret buffers in encapsulate/decapsulate and encoder output buffers
  holding PKCS#8 private keys are now zeroed with `OPENSSL_cleanse` before
  release
- Corrected type hints for optional parameters (`seed`, `context`) and stale
  thread-safety/memory-safety docstrings

## [0.0.3] — 2026-04-16

### Added
- DER and PEM key serialization via `OSSL_ENCODER`/`OSSL_DECODER`
- Deterministic key generation for ML-KEM using a 64-byte seed (`d||z`)
- Context string support for ML-DSA and SLH-DSA signatures
- CFFI bindings for `OSSL_ENCODER`, `OSSL_DECODER`, and `OSSL_PARAM` families
- Test suite organized into `correctness/`, `security/`, and `validation/` suites

### Changed
- Upgraded OpenSSL to 3.6.2
- Switched to static-only OpenSSL linking; removed shared library bundling
- Moved internal modules into `alkindi._internal` subpackage

### Fixed
- Hardened error handling; `OPENSSL_cleanse` now runs on private-key buffers before release
- OpenSSL install path in CI environment variables
- Retry logic added to OpenSSL source downloads in CI
- Workflow actions pinned to specific commit SHAs

## [0.0.2] — 2025-12-30

### Added
- GitHub Actions workflow for building and publishing wheels
- Windows wheel build support with static OpenSSL linking
- `build.env` file for pinning build dependency versions

### Fixed
- OpenSSL library path detection for CFFI bindings on Linux (`lib` vs `lib64`)
- Deprecated license identifier format in `pyproject.toml`

## [0.0.1] — 2025-12-03

### Added
- ML-KEM (FIPS 203) key encapsulation: `Keys`, `KEM`
- ML-DSA (FIPS 204) digital signatures: `Signature`
- SLH-DSA (FIPS 205) digital signatures: `Signature`
- CFFI bindings over OpenSSL 3.x `EVP_PKEY` API
- Type-safe Python API with context managers for resource cleanup
- Algorithm selection guide (`alkindi.guide()`)
- Static OpenSSL build script (`scripts/build_openssl.sh`)

[0.0.4]: https://github.com/alraddady/alkindi/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/alraddady/alkindi/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/alraddady/alkindi/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/alraddady/alkindi/releases/tag/v0.0.1
