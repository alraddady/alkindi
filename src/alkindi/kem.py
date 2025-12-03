"""ML-KEM (FIPS 203) - Key Encapsulation Mechanism.

This module provides a high-level Python interface for ML-KEM (Module
Lattice-Based Key Encapsulation Mechanism), formerly known as Kyber, which is
a post-quantum cryptographic algorithm standardized in FIPS 203.

Implementation Notes
--------------------

Thread Safety
    All signature operations are thread-safe. Each operation creates and
    disposes its own cryptographic context. No shared state is used.

Memory Safety
    Context managers and automatic finalizers ensure proper cleanup of native
    resources. Use 'with' blocks where appropriate to ensure timely release.
"""

from typing import NamedTuple, Tuple

from _alkindi_ import ffi, lib

from alkindi._params import SUPPORTED_KEM_ALGORITHMS
from alkindi._utils import check_openssl_errors
from alkindi.exceptions import AlkindiAPIError, OpenSSLError


class KeyPair(NamedTuple):
    public_key: bytes
    private_key: bytes


class KEM:
    """
    This class provides post-quantum secure key exchange using the ML-KEM
    (Module Lattice-Based KEM) family of algorithms standardized in FIPS 203.
    """

    @staticmethod
    def generate_keypair(algorithm: str) -> KeyPair:
        """
        Generate a new ML-KEM keypair.

        Generates a fresh public/private keypair for the specified ML-KEM algorithm.
        Keys are returned as raw bytes for maximum performance and flexibility.

        Args:
            algorithm: ML-KEM algorithm name ('ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024')

        Returns:
            KeyPair(public_key: bytes, private_key: bytes)

        Raises:
            AlkindiAPIError: If algorithm is not supported
            OpenSSLError: If OpenSSL key generation fails

        Security Note:
            Private keys should be stored securely and never transmitted.
            Consider encrypting private keys at rest using PKCS#8 format.

        Example:
            >>> keypair = KEM.generate_keypair('ML-KEM-1024')
            >>> len(keypair.public_key)
            1568
            >>> len(keypair.private_key)
            3168
        """

        algorithm = algorithm.upper()

        if algorithm not in SUPPORTED_KEM_ALGORITHMS:
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
    def encapsulate(algorithm: str, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate to generate a shared secret and ciphertext.

        The sender uses the recipient's public key to generate a random shared
        secret and its encapsulation (ciphertext). The ciphertext is sent to
        the recipient, who can decapsulate it to recover the same shared secret.

        Args:
            algorithm: ML-KEM algorithm name
            public_key: Recipient's public key as raw bytes

        Returns:
            Tuple of (ciphertext, shared_secret) as raw bytes

        Raises:
            AlkindiAPIError: If algorithm is not supported
            OpenSSLError: If key import or encapsulation fails

        Security Note:
            The shared secret should be used with a Key Derivation Function (KDF)
            before use in encryption. Never reuse the same shared secret.

        Example:
            >>> keypair = KEM.generate_keypair('ML-KEM-1024')
            >>> ciphertext, shared_secret = KEM.encapsulate('ML-KEM-1024', keypair.public_key)
            >>> len(ciphertext)
            1568
            >>> len(shared_secret)
            32
        """

        algorithm = algorithm.upper()

        if algorithm not in SUPPORTED_KEM_ALGORITHMS:
            raise AlkindiAPIError(
                f"Invalid input: {algorithm}. "
                "See the Alkindi documentation for valid options."
            )

        algorithm_name_in_bytes: bytes = algorithm.encode("ascii")

        pkey = ffi.NULL
        ctx = ffi.NULL

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

            ctx = lib.EVP_PKEY_CTX_new_from_pkey(ffi.NULL, pkey, ffi.NULL)
            if ctx == ffi.NULL:
                raise OpenSSLError("Failed to create key context")

            result: int = lib.EVP_PKEY_encapsulate_init(ctx, ffi.NULL)
            check_openssl_errors(result, "Encapsulation initialization", OpenSSLError)

            ciphertext_len = ffi.new("size_t *")
            secret_len = ffi.new("size_t *")
            result = lib.EVP_PKEY_encapsulate(
                ctx,
                ffi.NULL,
                ciphertext_len,
                ffi.NULL,
                secret_len,
            )
            check_openssl_errors(result, "Encapsulation size query", OpenSSLError)

            ciphertext_buf = ffi.new("unsigned char[]", ciphertext_len[0])
            secret_buf = ffi.new("unsigned char[]", secret_len[0])
            result = lib.EVP_PKEY_encapsulate(
                ctx,
                ciphertext_buf,
                ciphertext_len,
                secret_buf,
                secret_len,
            )
            check_openssl_errors(result, "Encapsulation", OpenSSLError)

            ciphertext: bytes = bytes(ffi.buffer(ciphertext_buf, ciphertext_len[0]))
            shared_secret: bytes = bytes(ffi.buffer(secret_buf, secret_len[0]))

            return (ciphertext, shared_secret)

        finally:
            if ctx != ffi.NULL:
                lib.EVP_PKEY_CTX_free(ctx)
            if pkey != ffi.NULL:
                lib.EVP_PKEY_free(pkey)

    @staticmethod
    def decapsulate(algorithm: str, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate ciphertext to recover the shared secret.

        The recipient uses their private key to decapsulate the ciphertext
        and recover the shared secret that was generated during encapsulation.

        Args:
            algorithm: ML-KEM algorithm name
            private_key: Recipient's private key as raw bytes
            ciphertext: Encapsulated secret from sender

        Returns:
            Shared secret as raw bytes

        Raises:
            AlkindiAPIError: If algorithm is not supported
            OpenSSLError: If key import or decapsulation fails

        Security Note:
            Decapsulation failure may indicate a corrupted or malicious ciphertext.
            The shared secret should be used with a KDF before use in encryption.

        Example:
            >>> keypair = KEM.generate_keypair('ML-KEM-1024')
            >>> ciphertext, secret_sender = KEM.encapsulate('ML-KEM-1024', keypair.public_key)
            >>> secret_receiver = KEM.decapsulate('ML-KEM-1024', keypair.private_key, ciphertext)
            >>> assert secret_sender == secret_receiver
        """

        algorithm = algorithm.upper()

        if algorithm not in SUPPORTED_KEM_ALGORITHMS:
            raise AlkindiAPIError(
                f"Invalid input: {algorithm}. "
                "See the Alkindi documentation for valid options."
            )

        algorithm_name_in_bytes: bytes = algorithm.encode("ascii")

        pkey = ffi.NULL
        ctx = ffi.NULL

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

            ctx = lib.EVP_PKEY_CTX_new_from_pkey(ffi.NULL, pkey, ffi.NULL)
            if ctx == ffi.NULL:
                raise OpenSSLError("Failed to create key context")

            result: int = lib.EVP_PKEY_decapsulate_init(ctx, ffi.NULL)
            check_openssl_errors(result, "Decapsulation initialization", OpenSSLError)

            secret_len = ffi.new("size_t *")
            result = lib.EVP_PKEY_decapsulate(
                ctx,
                ffi.NULL,
                secret_len,
                ciphertext,
                len(ciphertext),
            )
            check_openssl_errors(result, "Decapsulation size query", OpenSSLError)

            secret_buf = ffi.new("unsigned char[]", secret_len[0])
            result = lib.EVP_PKEY_decapsulate(
                ctx,
                secret_buf,
                secret_len,
                ciphertext,
                len(ciphertext),
            )
            check_openssl_errors(result, "Decapsulation", OpenSSLError)

            shared_secret: bytes = bytes(ffi.buffer(secret_buf, secret_len[0]))

            return shared_secret

        finally:
            if ctx != ffi.NULL:
                lib.EVP_PKEY_CTX_free(ctx)
            if pkey != ffi.NULL:
                lib.EVP_PKEY_free(pkey)
