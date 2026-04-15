"""
Key Serialization — DER and PEM formats.

This module provides import/export of post-quantum keys in standard ASN.1
wire formats:

  * Public keys  ==> SubjectPublicKeyInfo (SPKI), as defined in RFC 5480 / X.509
  * Private keys ==> PKCS#8 PrivateKeyInfo, as defined in RFC 5958

Both DER (binary) and PEM (base64-armored) encodings are supported.
Serialization is implemented via the OpenSSL 3.x OSSL_ENCODER / OSSL_DECODER
provider-based API — no legacy i2d_*/d2i_* functions are used.

Implementation Notes
--------------------

Thread Safety
    All operations are thread-safe. Each call creates its own encoder/decoder
    context and frees it before returning. No shared state is used.

Memory Safety
    Buffers allocated by OSSL_ENCODER_to_data are freed with OPENSSL_free
    before the function returns. Decoded EVP_PKEY objects are freed in the
    finally block if an error occurs after the key is created.
"""

from _alkindi_ import ffi, lib

from alkindi._internal.params import ALL_SUPPORTED_ALGORITHMS
from alkindi._internal.utils import check_openssl_errors
from alkindi._internal.exceptions import AlkindiAPIError, OpenSSLError

# EVP_PKEY selection constants (openssl/evp.h)
# EVP_PKEY_PUBLIC_KEY = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS (0x04)
#                     | OSSL_KEYMGMT_SELECT_PUBLIC_KEY (0x02) = 0x06
# EVP_PKEY_KEYPAIR    = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS (0x04)
#                     | OSSL_KEYMGMT_SELECT_PRIVATE_KEY (0x01)
#                     | OSSL_KEYMGMT_SELECT_PUBLIC_KEY (0x02) = 0x07
_EVP_PKEY_PUBLIC_KEY = 0x06
_EVP_PKEY_KEYPAIR    = 0x07

_DER = b"DER"
_PEM = b"PEM"
_SPKI = b"SubjectPublicKeyInfo"
_PKCS8 = b"PrivateKeyInfo"


def _encode(pkey, selection: int, output_type: bytes, output_struct: bytes) -> bytes:
    """Encode *pkey* to DER or PEM bytes using OSSL_ENCODER."""
    enc_ctx = ffi.NULL
    pdata_ptr = ffi.new("unsigned char *[1]", [ffi.NULL])
    pdata_len = ffi.new("size_t *", 0)

    try:
        enc_ctx = lib.OSSL_ENCODER_CTX_new_for_pkey(
            pkey, selection, output_type, output_struct, ffi.NULL
        )
        if enc_ctx == ffi.NULL:
            raise OpenSSLError(
                f"Failed to create encoder context "
                f"(type={output_type.decode()}, struct={output_struct.decode()})"
            )

        result = lib.OSSL_ENCODER_to_data(enc_ctx, pdata_ptr, pdata_len)
        check_openssl_errors(result, "Key encoding", OpenSSLError)

        return bytes(ffi.buffer(pdata_ptr[0], pdata_len[0]))

    finally:
        if pdata_ptr[0] != ffi.NULL:
            lib.OPENSSL_free(pdata_ptr[0])
        if enc_ctx != ffi.NULL:
            lib.OSSL_ENCODER_CTX_free(enc_ctx)


def _load_pkey(
    algorithm: bytes,
    data: bytes,
    input_type: bytes,
    input_struct: bytes,
    selection: int,
):
    """Decode DER or PEM *data* into an EVP_PKEY using OSSL_DECODER.

    Returns the raw CFFI EVP_PKEY pointer. The caller is responsible for
    calling ``lib.EVP_PKEY_free`` on it.
    """
    pkey_ptr = ffi.new("EVP_PKEY *[1]", [ffi.NULL])
    dec_ctx = ffi.NULL

    try:
        dec_ctx = lib.OSSL_DECODER_CTX_new_for_pkey(
            pkey_ptr,
            input_type,
            input_struct,
            algorithm,
            selection,
            ffi.NULL,
            ffi.NULL,
        )
        if dec_ctx == ffi.NULL:
            raise OpenSSLError(
                f"Failed to create decoder context "
                f"(type={input_type.decode()}, struct={input_struct.decode()})"
            )

        c_data = ffi.from_buffer("unsigned char[]", data)
        pdata_ptr = ffi.new("const unsigned char *[1]", [c_data])
        pdata_len = ffi.new("size_t *", len(data))

        result = lib.OSSL_DECODER_from_data(dec_ctx, pdata_ptr, pdata_len)
        check_openssl_errors(result, "Key decoding", OpenSSLError)

        pkey = pkey_ptr[0]
        if pkey == ffi.NULL:
            raise OpenSSLError("Decoder succeeded but produced no key")

        pkey_ptr[0] = ffi.NULL
        return pkey

    finally:
        if dec_ctx != ffi.NULL:
            lib.OSSL_DECODER_CTX_free(dec_ctx)
        if pkey_ptr[0] != ffi.NULL:
            lib.EVP_PKEY_free(pkey_ptr[0])


def _get_raw_public(pkey) -> bytes:
    """Extract raw public key bytes from an EVP_PKEY."""
    pub_len = ffi.new("size_t *")
    result = lib.EVP_PKEY_get_raw_public_key(pkey, ffi.NULL, pub_len)
    check_openssl_errors(result, "Public key size query", OpenSSLError)
    pub_buf = ffi.new("unsigned char[]", pub_len[0])
    result = lib.EVP_PKEY_get_raw_public_key(pkey, pub_buf, pub_len)
    check_openssl_errors(result, "Public key export", OpenSSLError)
    return bytes(ffi.buffer(pub_buf, pub_len[0]))


def _get_raw_private(pkey) -> bytes:
    """Extract raw private key bytes from an EVP_PKEY, zeroing the buffer."""
    priv_len = ffi.new("size_t *")
    result = lib.EVP_PKEY_get_raw_private_key(pkey, ffi.NULL, priv_len)
    check_openssl_errors(result, "Private key size query", OpenSSLError)
    priv_buf = ffi.new("unsigned char[]", priv_len[0])
    size = priv_len[0]
    try:
        result = lib.EVP_PKEY_get_raw_private_key(pkey, priv_buf, priv_len)
        check_openssl_errors(result, "Private key export", OpenSSLError)
        return bytes(ffi.buffer(priv_buf, priv_len[0]))
    finally:
        lib.OPENSSL_cleanse(priv_buf, size)


class Keys:
    """
    DER and PEM serialization for post-quantum keys.

    Bind once to an algorithm, then encode or decode keys without repeating
    the algorithm name on every call.

    All algorithms supported by ``KEM`` and ``Signature`` are accepted.
    Algorithm names are case-insensitive.

    Public keys are encoded as SubjectPublicKeyInfo (SPKI / X.509).
    Private keys are encoded as PKCS#8 PrivateKeyInfo (unencrypted).

    Example::

        keys = Keys('ML-KEM-1024')

        der = keys.public_key_to_der(keypair.public_key)
        pem = keys.private_key_to_pem(keypair.private_key)

        pub = keys.public_key_from_pem(pem)
        priv = keys.private_key_from_der(der)
    """

    def __init__(self, algorithm: str) -> None:
        algorithm = algorithm.upper()
        if algorithm not in ALL_SUPPORTED_ALGORITHMS:
            raise AlkindiAPIError(
                f"Invalid input: {algorithm}. "
                "See the Alkindi documentation for valid options."
            )
        self._algorithm = algorithm
        self._algorithm_b = algorithm.encode("ascii")

    def public_key_to_der(self, public_key: bytes) -> bytes:
        """
        Encode a raw public key to SubjectPublicKeyInfo DER.

        Args:
            public_key: Raw public key bytes as returned by
                        ``KEM.generate_keypair()`` or
                        ``Signature.generate_keypair()``.

        Returns:
            DER-encoded SubjectPublicKeyInfo as bytes.

        Raises:
            AlkindiAPIError: If the input is not bytes.
            OpenSSLError:    If the OpenSSL encoder fails.
        """
        _check_bytes(public_key, "public_key")
        pkey = ffi.NULL
        try:
            lib.ERR_clear_error()
            pkey = lib.EVP_PKEY_new_raw_public_key_ex(
                ffi.NULL, self._algorithm_b, ffi.NULL, public_key, len(public_key)
            )
            if pkey == ffi.NULL:
                raise OpenSSLError(f"Failed to import public key for {self._algorithm}")
            return _encode(pkey, _EVP_PKEY_PUBLIC_KEY, _DER, _SPKI)
        finally:
            if pkey != ffi.NULL:
                lib.EVP_PKEY_free(pkey)

    def public_key_to_pem(self, public_key: bytes) -> bytes:
        """
        Encode a raw public key to SubjectPublicKeyInfo PEM.

        Args:
            public_key: Raw public key bytes.

        Returns:
            PEM-encoded SubjectPublicKeyInfo as bytes (includes header/footer).

        Raises:
            AlkindiAPIError: If the input is not bytes.
            OpenSSLError:    If the OpenSSL encoder fails.
        """
        _check_bytes(public_key, "public_key")
        pkey = ffi.NULL
        try:
            lib.ERR_clear_error()
            pkey = lib.EVP_PKEY_new_raw_public_key_ex(
                ffi.NULL, self._algorithm_b, ffi.NULL, public_key, len(public_key)
            )
            if pkey == ffi.NULL:
                raise OpenSSLError(f"Failed to import public key for {self._algorithm}")
            return _encode(pkey, _EVP_PKEY_PUBLIC_KEY, _PEM, _SPKI)
        finally:
            if pkey != ffi.NULL:
                lib.EVP_PKEY_free(pkey)

    def private_key_to_der(self, private_key: bytes) -> bytes:
        """
        Encode a raw private key to PKCS#8 PrivateKeyInfo DER.

        Args:
            private_key: Raw private key bytes as returned by
                         ``KEM.generate_keypair()`` or
                         ``Signature.generate_keypair()``.

        Returns:
            DER-encoded PKCS#8 PrivateKeyInfo as bytes.

        Raises:
            AlkindiAPIError: If the input is not bytes.
            OpenSSLError:    If the OpenSSL encoder fails.
        """
        _check_bytes(private_key, "private_key")
        pkey = ffi.NULL
        try:
            lib.ERR_clear_error()
            pkey = lib.EVP_PKEY_new_raw_private_key_ex(
                ffi.NULL, self._algorithm_b, ffi.NULL, private_key, len(private_key)
            )
            if pkey == ffi.NULL:
                raise OpenSSLError(f"Failed to import private key for {self._algorithm}")
            return _encode(pkey, _EVP_PKEY_KEYPAIR, _DER, _PKCS8)
        finally:
            if pkey != ffi.NULL:
                lib.EVP_PKEY_free(pkey)

    def private_key_to_pem(self, private_key: bytes) -> bytes:
        """
        Encode a raw private key to PKCS#8 PrivateKeyInfo PEM.

        Args:
            private_key: Raw private key bytes.

        Returns:
            PEM-encoded PKCS#8 PrivateKeyInfo as bytes (includes header/footer).

        Raises:
            AlkindiAPIError: If the input is not bytes.
            OpenSSLError:    If the OpenSSL encoder fails.
        """
        _check_bytes(private_key, "private_key")
        pkey = ffi.NULL
        try:
            lib.ERR_clear_error()
            pkey = lib.EVP_PKEY_new_raw_private_key_ex(
                ffi.NULL, self._algorithm_b, ffi.NULL, private_key, len(private_key)
            )
            if pkey == ffi.NULL:
                raise OpenSSLError(f"Failed to import private key for {self._algorithm}")
            return _encode(pkey, _EVP_PKEY_KEYPAIR, _PEM, _PKCS8)
        finally:
            if pkey != ffi.NULL:
                lib.EVP_PKEY_free(pkey)

    def public_key_from_der(self, der: bytes) -> bytes:
        """
        Decode a SubjectPublicKeyInfo DER blob to raw public key bytes.

        Args:
            der: DER-encoded SubjectPublicKeyInfo.

        Returns:
            Raw public key bytes.

        Raises:
            AlkindiAPIError: If the input is not bytes.
            OpenSSLError:    If the OpenSSL decoder fails.
        """
        _check_bytes(der, "der")
        lib.ERR_clear_error()
        pkey = _load_pkey(self._algorithm_b, der, _DER, _SPKI, _EVP_PKEY_PUBLIC_KEY)
        try:
            return _get_raw_public(pkey)
        finally:
            lib.EVP_PKEY_free(pkey)

    def public_key_from_pem(self, pem: bytes) -> bytes:
        """
        Decode a SubjectPublicKeyInfo PEM blob to raw public key bytes.

        Args:
            pem: PEM-encoded SubjectPublicKeyInfo.

        Returns:
            Raw public key bytes.

        Raises:
            AlkindiAPIError: If the input is not bytes.
            OpenSSLError:    If the OpenSSL decoder fails.
        """
        _check_bytes(pem, "pem")
        lib.ERR_clear_error()
        pkey = _load_pkey(self._algorithm_b, pem, _PEM, _SPKI, _EVP_PKEY_PUBLIC_KEY)
        try:
            return _get_raw_public(pkey)
        finally:
            lib.EVP_PKEY_free(pkey)

    def private_key_from_der(self, der: bytes) -> bytes:
        """
        Decode a PKCS#8 PrivateKeyInfo DER blob to raw private key bytes.

        Args:
            der: DER-encoded PKCS#8 PrivateKeyInfo.

        Returns:
            Raw private key bytes.

        Raises:
            AlkindiAPIError: If the input is not bytes.
            OpenSSLError:    If the OpenSSL decoder fails.
        """
        _check_bytes(der, "der")
        lib.ERR_clear_error()
        pkey = _load_pkey(self._algorithm_b, der, _DER, _PKCS8, _EVP_PKEY_KEYPAIR)
        try:
            return _get_raw_private(pkey)
        finally:
            lib.EVP_PKEY_free(pkey)

    def private_key_from_pem(self, pem: bytes) -> bytes:
        """
        Decode a PKCS#8 PrivateKeyInfo PEM blob to raw private key bytes.

        Args:
            pem: PEM-encoded PKCS#8 PrivateKeyInfo.

        Returns:
            Raw private key bytes.

        Raises:
            AlkindiAPIError: If the input is not bytes.
            OpenSSLError:    If the OpenSSL decoder fails.
        """
        _check_bytes(pem, "pem")
        lib.ERR_clear_error()
        pkey = _load_pkey(self._algorithm_b, pem, _PEM, _PKCS8, _EVP_PKEY_KEYPAIR)
        try:
            return _get_raw_private(pkey)
        finally:
            lib.EVP_PKEY_free(pkey)


def _check_bytes(value: bytes, param_name: str) -> None:
    if not isinstance(value, bytes):
        raise AlkindiAPIError(
            f"{param_name} must be bytes, got {type(value).__name__}"
        )
