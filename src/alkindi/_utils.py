"""
Internal utility for OpenSSL error handling.
"""

from __future__ import annotations

from typing import Any, Type

from _alkindi_ import ffi, lib

from alkindi.exceptions import AlkindiError, OpenSSLError


def check_openssl_errors(
    result: Any, operation: str, error_class: Type[AlkindiError] = OpenSSLError
) -> None:
    """
    Check an OpenSSL operation for errors and raise an exception if it failed.

    Handles all OpenSSL return patterns:
        - Integer: 1 = success, 0 or negative = failure
        - Pointer: NULL = failure

    Args:
        result: The return value from an OpenSSL function (int or pointer)
        operation: Description of the operation for error messages
        error_class: Exception class to raise on failure (default: OpenSSLError)

    Raises:
        error_class: If the operation failed, with OpenSSL error details if available
    """
    failed = False

    if result == ffi.NULL:
        failed = True
    # Check for integer failure (1 = success, 0 or negative = failure)
    elif isinstance(result, int) and result <= 0:
        failed = True

    if failed:
        openssl_error = None
        error_code = lib.ERR_get_error()
        if error_code != 0:
            error_str_ptr = lib.ERR_error_string(error_code, ffi.NULL)
            if error_str_ptr != ffi.NULL:
                openssl_error = ffi.string(error_str_ptr).decode(
                    "utf-8", errors="replace"
                )

        raise error_class(f"{operation} failed", openssl_error=openssl_error)
