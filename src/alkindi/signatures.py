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
    Context managers and automatic finalizers ensure proper cleanup of native
    resources. Use 'with' blocks where appropriate to ensure timely release.
"""

from typing import NamedTuple

from _alkindi_ import ffi, lib

from alkindi._params import SUPPORTED_SIGNATURE_ALGORITHMS
from alkindi._utils import check_openssl_errors
from alkindi.exceptions import AlkindiAPIError, OpenSSLError


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

        try:
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
            result = lib.EVP_PKEY_get_raw_private_key(pkey, priv_buf, priv_len)
            check_openssl_errors(result, "Private key export", OpenSSLError)
            private_key: bytes = bytes(ffi.buffer(priv_buf, priv_len[0]))

            return KeyPair(public_key=public_key, private_key=private_key)

        finally:
            if pkey != ffi.NULL:
                lib.EVP_PKEY_free(pkey)
            if ctx != ffi.NULL:
                lib.EVP_PKEY_CTX_free(ctx)

    @staticmethod
    def sign(algorithm: str, private_key: bytes, message: bytes) -> bytes:
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

        Returns:
            Digital signature as bytes.

        Raises:
            AlkindiAPIError:
                If the algorithm name is not supported.
            OpenSSLError:
                If key import or signing fails at the OpenSSL layer.
        """
        algorithm = algorithm.upper()

        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise AlkindiAPIError(
                f"Invalid input: {algorithm}. "
                "See the Alkindi documentation for valid options."
            )

        algorithm_name_in_bytes: bytes = algorithm.encode("ascii")

        pkey = ffi.NULL
        md_ctx = ffi.NULL

        try:
            pkey = lib.EVP_PKEY_new_raw_private_key_ex(
                ffi.NULL,
                algorithm_name_in_bytes,
                ffi.NULL,
                private_key,
                len(private_key),
            )
            if pkey == ffi.NULL:
                raise OpenSSLError(
                    f"Failed to import private key for {algorithm}. "
                    "The key material may have an invalid length or format."
                )

            md_ctx = lib.EVP_MD_CTX_new()
            if md_ctx == ffi.NULL:
                raise OpenSSLError("Failed to create message digest context")

            result: int = lib.EVP_DigestSignInit_ex(
                md_ctx,
                ffi.NULL,
                ffi.NULL,
                ffi.NULL,
                ffi.NULL,
                pkey,
                ffi.NULL,
            )
            check_openssl_errors(result, "Signature initialization", OpenSSLError)

            sig_len = ffi.new("size_t *")
            result = lib.EVP_DigestSign(
                md_ctx,
                ffi.NULL,
                sig_len,
                message,
                len(message),
            )
            check_openssl_errors(result, "Signature size query", OpenSSLError)

            sig_buf = ffi.new("unsigned char[]", sig_len[0])
            result = lib.EVP_DigestSign(
                md_ctx,
                sig_buf,
                sig_len,
                message,
                len(message),
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
        algorithm: str, public_key: bytes, message: bytes, signature: bytes
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

        Returns:
            True if the signature is valid, False if invalid.

        Raises:
            AlkindiAPIError:
                If the algorithm name is not supported.
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

        algorithm_name_in_bytes: bytes = algorithm.encode("ascii")

        pkey = ffi.NULL
        md_ctx = ffi.NULL

        try:
            pkey = lib.EVP_PKEY_new_raw_public_key_ex(
                ffi.NULL,
                algorithm_name_in_bytes,
                ffi.NULL,
                public_key,
                len(public_key),
            )
            if pkey == ffi.NULL:
                raise OpenSSLError(
                    f"Failed to import public key for {algorithm}. "
                    "The key material may have an invalid length or format."
                )

            md_ctx = lib.EVP_MD_CTX_new()
            if md_ctx == ffi.NULL:
                raise OpenSSLError("Failed to create message digest context")

            result: int = lib.EVP_DigestVerifyInit_ex(
                md_ctx,
                ffi.NULL,
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

            result = lib.EVP_DigestVerify(
                md_ctx,
                signature,
                len(signature),
                message,
                len(message),
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
