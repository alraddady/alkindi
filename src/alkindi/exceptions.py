"""
Exception hierarchy for alkindi cryptographic operations.

Two-layer exception hierarchy:
    AlkindiError (base)
    ├── OpenSSLError (OpenSSL layer - internal operations)
    └── AlkindiAPIError (Alkindi layer - API usage)
"""

from __future__ import annotations

from typing import Optional


class AlkindiError(Exception):
    """
    Base exception for all alkindi errors.

    Attributes:
        openssl_error: OpenSSL error string if available, None otherwise.
    """

    def __init__(self, message: str, *, openssl_error: Optional[str] = None) -> None:
        self.openssl_error: Optional[str] = openssl_error

        if openssl_error:
            full_message = f"{message} (OpenSSL error: {openssl_error})"
        else:
            full_message = message

        super().__init__(full_message)


class OpenSSLError(AlkindiError):
    """
    Raised for OpenSSL layer errors (internal operations).

    This covers all low-level OpenSSL library failures:
        - Key generation/import/export failures
        - Signing/verification failures
        - KEM encapsulation/decapsulation failures
        - Context initialization failures
        - Memory allocation failures
    """

    pass


class AlkindiAPIError(AlkindiError):
    """
    Raised for Alkindi layer errors (API usage).

    This covers all high-level alkindi API usage errors:
        - Invalid parameters or arguments
        - Invalid key formats or types
        - Unsupported algorithms
        - Invalid encoding formats
    """

    pass
