"""
Post-Quantum Digital Signature Algorithms

This module provides a high-level Python interface for the NIST-standardized
post-quantum digital signature schemes ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
These algorithms are designed to remain secure against both classical and
quantum-capable adversaries. They support digital authentication, integrity
verification, and non-repudiation with long-term cryptographic resilience.

Implementation Notes
--------------------

Thread Safety
    All signature operations are thread-safe. Each operation creates and
    disposes its own cryptographic context. No shared state is used.

Memory Safety
    Every operation releases its native resources in a ``finally`` block,
    and private-key buffers are zeroed with ``OPENSSL_cleanse`` before release.
"""

from _alkindi_ import ffi, lib
from typing import NamedTuple, Optional

from alkindi._internal.params import SUPPORTED_SIGNATURE_ALGORITHMS
from alkindi._internal.utils import check_openssl_errors, to_c_buffer
from alkindi._internal.exceptions import AlkindiAPIError, OpenSSLError


class KeyPair(NamedTuple):
    public_key: bytes
    private_key: bytes


class Signature:
    @staticmethod
    def generate_keypair(algorithm: str) -> KeyPair:
        """
        Generate a new signature keypair.

        Generates a fresh public/private keypair for the specified signature
        algorithm. Keys are returned as immutable bytes objects for maximum
        compatibility with Python's crypto ecosystem.

        Args:
            algorithm:
                Signature algorithm name (e.g., 'ML-DSA-87', 'SLH-DSA-SHA2-128s').

        Returns:
            KeyPair(public_key: bytes, private_key: bytes)

        Raises:
            AlkindiAPIError:
                If the algorithm name is not supported.
            OpenSSLError:
                If OpenSSL key generation fails.
        """

        algorithm = algorithm.upper()

        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise AlkindiAPIError(
                f"Invalid input: {algorithm}. "
                "See the Alkindi documentation for valid options."
            )

        algorithm_name_in_bytes: bytes = algorithm.encode("ascii")

        ctx = ffi.NULL
        pkey = ffi.NULL
        priv_buf = None
        priv_buf_size = 0

        try:
            lib.ERR_clear_error()
            ctx = lib.EVP_PKEY_CTX_new_from_name(
                ffi.NULL,
                algorithm_name_in_bytes,
                ffi.NULL,
            )
            if ctx == ffi.NULL:
                raise OpenSSLError(f"Failed to create key context for {algorithm}")

            result: int = lib.EVP_PKEY_keygen_init(ctx)
            check_openssl_errors(result, "Key generation init", OpenSSLError)

            pkey_ptr = ffi.new("EVP_PKEY **")
            result = lib.EVP_PKEY_keygen(ctx, pkey_ptr)
            check_openssl_errors(result, "Key generation", OpenSSLError)
            pkey = pkey_ptr[0]

            pub_len = ffi.new("size_t *")
            result = lib.EVP_PKEY_get_raw_public_key(pkey, ffi.NULL, pub_len)
            check_openssl_errors(result, "Public key size query", OpenSSLError)
            pub_buf = ffi.new("unsigned char[]", pub_len[0])
            result = lib.EVP_PKEY_get_raw_public_key(pkey, pub_buf, pub_len)
            check_openssl_errors(result, "Public key export", OpenSSLError)
            public_key: bytes = bytes(ffi.buffer(pub_buf, pub_len[0]))

            priv_len = ffi.new("size_t *")
            result = lib.EVP_PKEY_get_raw_private_key(pkey, ffi.NULL, priv_len)
            check_openssl_errors(result, "Private key size query", OpenSSLError)
            priv_buf = ffi.new("unsigned char[]", priv_len[0])
            priv_buf_size = priv_len[0]
            result = lib.EVP_PKEY_get_raw_private_key(pkey, priv_buf, priv_len)
            check_openssl_errors(result, "Private key export", OpenSSLError)
            private_key: bytes = bytes(ffi.buffer(priv_buf, priv_len[0]))

            return KeyPair(public_key=public_key, private_key=private_key)

        finally:
            if priv_buf is not None and priv_buf_size > 0:
                lib.OPENSSL_cleanse(priv_buf, priv_buf_size)
            if pkey != ffi.NULL:
                lib.EVP_PKEY_free(pkey)
            if ctx != ffi.NULL:
                lib.EVP_PKEY_CTX_free(ctx)

    @staticmethod
    def sign(
            algorithm: str, private_key: bytes, message: bytes,
            context: Optional[bytes] = None,
    ) -> bytes:
        """
        Sign a message with a private key.

        Creates a digital signature for the given message using the private key.
        The signature can be verified by anyone with the corresponding public key.

        Args:
            algorithm:
                Signature algorithm name (e.g., 'ML-DSA-87').
            private_key:
                Signer's private key as raw bytes (as returned by generate_keypair()).
            message:
                Message to sign, as raw bytes.
            context:
                Optional context string (up to 255 bytes). Supported by ML-DSA and
                SLH-DSA. The same context must be supplied during verification.
                Defaults to empty (no context).

        Returns:
            Digital signature as bytes.

        Raises:
            AlkindiAPIError:
                If the algorithm name is not supported or context exceeds 255 bytes.
            OpenSSLError:
                If key import or signing fails at the OpenSSL layer.
        """
        algorithm = algorithm.upper()

        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise AlkindiAPIError(
                f"Invalid input: {algorithm}. "
                "See the Alkindi documentation for valid options."
            )

        if not isinstance(private_key, (bytes, bytearray, memoryview)):
            raise AlkindiAPIError(
                f"private_key must be a bytes-like object, got {type(private_key).__name__}"
            )

        if not isinstance(message, (bytes, bytearray, memoryview)):
            raise AlkindiAPIError(
                f"message must be a bytes-like object, got {type(message).__name__}"
            )

        ctx_buf = None
        if context is not None:
            if not isinstance(context, (bytes, bytearray, memoryview)):
                raise AlkindiAPIError(
                    f"context must be a bytes-like object, got {type(context).__name__}"
                )
            ctx_buf = to_c_buffer(context, "context")
            if len(ctx_buf) > 255:
                raise AlkindiAPIError(
                    f"context must be at most 255 bytes, got {len(ctx_buf)}"
                )

        algorithm_name_in_bytes: bytes = algorithm.encode("ascii")
        priv_buf = to_c_buffer(private_key, "private_key")
        msg_buf = to_c_buffer(message, "message")

        pkey = ffi.NULL
        md_ctx = ffi.NULL

        try:
            lib.ERR_clear_error()
            pkey = lib.EVP_PKEY_new_raw_private_key_ex(
                ffi.NULL,
                algorithm_name_in_bytes,
                ffi.NULL,
                priv_buf,
                len(priv_buf),
            )
            if pkey == ffi.NULL:
                raise OpenSSLError(
                    f"Failed to import private key for {algorithm}. "
                    "The key material may have an invalid length or format."
                )

            md_ctx = lib.EVP_MD_CTX_new()
            if md_ctx == ffi.NULL:
                raise OpenSSLError("Failed to create message digest context")

            if ctx_buf is not None:
                pctx_ptr = ffi.new("EVP_PKEY_CTX **")
            else:
                pctx_ptr = ffi.NULL

            result: int = lib.EVP_DigestSignInit_ex(
                md_ctx,
                pctx_ptr,
                ffi.NULL,
                ffi.NULL,
                ffi.NULL,
                pkey,
                ffi.NULL,
            )
            check_openssl_errors(result, "Signature initialization", OpenSSLError)

            if ctx_buf is not None:
                params = ffi.new("OSSL_PARAM[2]")
                params[0] = lib.OSSL_PARAM_construct_octet_string(
                    b"context-string", ctx_buf, len(ctx_buf)
                )
                params[1] = lib.OSSL_PARAM_construct_end()
                result = lib.EVP_PKEY_CTX_set_params(pctx_ptr[0], params)
                check_openssl_errors(result, "Setting context parameter", OpenSSLError)

            sig_len = ffi.new("size_t *")
            result = lib.EVP_DigestSign(
                md_ctx,
                ffi.NULL,
                sig_len,
                msg_buf,
                len(msg_buf),
            )
            check_openssl_errors(result, "Signature size query", OpenSSLError)

            sig_buf = ffi.new("unsigned char[]", sig_len[0])
            result = lib.EVP_DigestSign(
                md_ctx,
                sig_buf,
                sig_len,
                msg_buf,
                len(msg_buf),
            )
            check_openssl_errors(result, "Signature generation", OpenSSLError)

            return bytes(ffi.buffer(sig_buf, sig_len[0]))

        finally:
            if md_ctx != ffi.NULL:
                lib.EVP_MD_CTX_free(md_ctx)
            if pkey != ffi.NULL:
                lib.EVP_PKEY_free(pkey)

    @staticmethod
    def verify(
            algorithm: str, public_key: bytes, message: bytes, signature: bytes,
            context: Optional[bytes] = None,
    ) -> bool:
        """
        Verify a digital signature.

        Checks whether the provided signature is valid for the given message and
        public key under the specified algorithm.

        Args:
            algorithm:
                Signature algorithm name (e.g., 'ML-DSA-87').
            public_key:
                Signer's public key as raw bytes (as returned by generate_keypair()).
            message:
                Original message bytes.
            signature:
                Signature bytes produced by sign().
            context:
                Optional context string (up to 255 bytes). Must match the context
                used during signing exactly.

        Returns:
            True if the signature is valid, False if invalid.

        Raises:
            AlkindiAPIError:
                If the algorithm name is not supported or context exceeds 255 bytes.
            OpenSSLError:
                If verification fails due to an OpenSSL error (as opposed to
                a simple "invalid signature" result).
        """

        algorithm = algorithm.upper()

        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise AlkindiAPIError(
                f"Invalid input: {algorithm}. "
                "See the Alkindi documentation for valid options."
            )

        if not isinstance(public_key, (bytes, bytearray, memoryview)):
            raise AlkindiAPIError(
                f"public_key must be a bytes-like object, got {type(public_key).__name__}"
            )

        if not isinstance(message, (bytes, bytearray, memoryview)):
            raise AlkindiAPIError(
                f"message must be a bytes-like object, got {type(message).__name__}"
            )

        if not isinstance(signature, (bytes, bytearray, memoryview)):
            raise AlkindiAPIError(
                f"signature must be a bytes-like object, got {type(signature).__name__}"
            )

        ctx_buf = None
        if context is not None:
            if not isinstance(context, (bytes, bytearray, memoryview)):
                raise AlkindiAPIError(
                    f"context must be a bytes-like object, got {type(context).__name__}"
                )
            ctx_buf = to_c_buffer(context, "context")
            if len(ctx_buf) > 255:
                raise AlkindiAPIError(
                    f"context must be at most 255 bytes, got {len(ctx_buf)}"
                )

        algorithm_name_in_bytes: bytes = algorithm.encode("ascii")
        pub_buf = to_c_buffer(public_key, "public_key")
        msg_buf = to_c_buffer(message, "message")
        sig_buf = to_c_buffer(signature, "signature")

        pkey = ffi.NULL
        md_ctx = ffi.NULL

        try:
            lib.ERR_clear_error()
            pkey = lib.EVP_PKEY_new_raw_public_key_ex(
                ffi.NULL,
                algorithm_name_in_bytes,
                ffi.NULL,
                pub_buf,
                len(pub_buf),
            )
            if pkey == ffi.NULL:
                raise OpenSSLError(
                    f"Failed to import public key for {algorithm}. "
                    "The key material may have an invalid length or format."
                )

            md_ctx = lib.EVP_MD_CTX_new()
            if md_ctx == ffi.NULL:
                raise OpenSSLError("Failed to create message digest context")

            if ctx_buf is not None:
                pctx_ptr = ffi.new("EVP_PKEY_CTX **")
            else:
                pctx_ptr = ffi.NULL

            result: int = lib.EVP_DigestVerifyInit_ex(
                md_ctx,
                pctx_ptr,
                ffi.NULL,
                ffi.NULL,
                ffi.NULL,
                pkey,
                ffi.NULL,
            )
            check_openssl_errors(
                result,
                "Signature verification initialization",
                OpenSSLError,
            )

            if ctx_buf is not None:
                params = ffi.new("OSSL_PARAM[2]")
                params[0] = lib.OSSL_PARAM_construct_octet_string(
                    b"context-string", ctx_buf, len(ctx_buf)
                )
                params[1] = lib.OSSL_PARAM_construct_end()
                result = lib.EVP_PKEY_CTX_set_params(pctx_ptr[0], params)
                check_openssl_errors(result, "Setting context parameter", OpenSSLError)

            result = lib.EVP_DigestVerify(
                md_ctx,
                sig_buf,
                len(sig_buf),
                msg_buf,
                len(msg_buf),
            )

            if result == 1:
                return True
            elif result == 0:
                return False
            else:
                raise OpenSSLError(
                    "OpenSSL error occurred during signature verification"
                )

        finally:
            if md_ctx != ffi.NULL:
                lib.EVP_MD_CTX_free(md_ctx)
            if pkey != ffi.NULL:
                lib.EVP_PKEY_free(pkey)
