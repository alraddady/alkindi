"""CFFI builder for OpenSSL post-quantum cryptography bindings.

This module defines the CFFI (C Foreign Function Interface) builder that compiles
the _alkindi_ C extension module at build time. It provides Python bindings
to OpenSSL's EVP_PKEY API for post-quantum cryptographic algorithms.


NOTE:
    For Thread Safety: Contexts MUST NOT be shared between threads.
    It is not permissible to use the same context simultaneously in two threads.

References:
    OpenSSL Documentation: https://www.openssl.org/docs/

Build Process:
    This module is referenced in setup.py via cffi_modules parameter.
    When setuptools builds the package, it:
    1. Imports this module
    2. Finds the 'ffibuilder' object
    3. Calls ffibuilder.compile() to generate the C extension
    4. The result is the _alkindi_ module that can be imported at runtime
"""

import os
import platform

from cffi import FFI

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, "..", "..")

OPENSSL_INSTALL = os.environ.get(
    "OPENSSL_DIR",
    os.path.join(PROJECT_ROOT, "scripts/openssl-build/install"),
)

if platform.system() != "Windows" and os.path.exists(
        os.path.join(OPENSSL_INSTALL, "lib64")
):
    OPENSSL_LIB = os.path.join(OPENSSL_INSTALL, "lib64")
else:
    OPENSSL_LIB = os.path.join(OPENSSL_INSTALL, "lib")

OPENSSL_INCLUDE = os.path.join(OPENSSL_INSTALL, "include")

ffibuilder = FFI()

# Define the C function signatures and types that we want to expose to Python
# These declarations tell CFFI what functions and types are available in OpenSSL
# The syntax is similar to C header files
ffibuilder.cdef("""
    /******************************************************************
     *                                                                *
     *                    Opaque Structure Types                      *
     *                                                                *
     ******************************************************************/

    /**
     * EVP_PKEY: Generic structure for public/private keys
     */
    typedef struct evp_pkey_st EVP_PKEY;

    /**
     * EVP_PKEY_CTX: Context for key operations
     * Used for key generation, signing, encryption, KEM operations
     */
    typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

    /**
     * EVP_MD_CTX: Context for message digest and signature operations
     */
    typedef struct evp_md_ctx_st EVP_MD_CTX;


    /******************************************************************
     *                                                                *
     *                      Key Context Management                    *
     *                                                                *
     ******************************************************************/

    /**
     * Creates a new key context by algorithm name.
     * Used for key generation when you know the algorithm name.
     *
     * @param libctx Library context (NULL for default)
     * @param name Algorithm name (e.g., "ML-KEM-768")
     * @param propquery Property query string (NULL for default)
     * @return New context or NULL on error
     */
    EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(void *libctx, const char *name,
                                              const char *propquery);

    /**
     * Creates a new key context from an existing key.
     * Used for operations on existing keys (sign, verify, encapsulate, etc.)
     *
     * @param libctx Library context (NULL for default)
     * @param pkey Existing key
     * @param propq Property query string (NULL for default)
     * @return New context or NULL on error
     */
    EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(void *libctx, EVP_PKEY *pkey,
                                             const char *propq);

    /**
     * Frees a key context and all associated resources.
     * Must be called to prevent memory leaks.
     *
     * @param ctx Context to free
     */
    void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);


    /******************************************************************
     *                                                                *
     *                 Key Generation Operations                      *
     *                                                                *
     ******************************************************************/

    /**
     * Initializes a context for key generation.
     * Must be called before EVP_PKEY_keygen().
     *
     * @param ctx Key context created with EVP_PKEY_CTX_new_from_name
     * @return
     *   @retval 1   Success
     *   @retval 0   Failure
     *   @retval -2  Operation not supported by this key type/algorithm
     *   @retval <0  Other internal error (check ERR_get_error())
     */
    int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);

    /**
     * Generates a new key pair.
     * Creates both public and private key for the configured algorithm.
     *
     * @param ctx Initialized key generation context
     * @param ppkey Output parameter for the generated key
     * @return
     *   @retval 1   Success
     *   @retval 0   Failure
     *   @retval -2  Operation not supported by this key type/algorithm
     *   @retval <0  Other internal error (check ERR_get_error())
     */
    int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);

    /**
     * Frees a key and all associated resources.
     * Must be called to prevent memory leaks.
     *
     * @param pkey Key to free
     */
    void EVP_PKEY_free(EVP_PKEY *pkey);


    /******************************************************************
     *                                                                *
     *                  Digital Signature Operations                  *
     *                                                                *
     ******************************************************************/

    /**
     * Creates a new message digest context for signature operations.
     *
     * @return New context or NULL on error
     */
    EVP_MD_CTX *EVP_MD_CTX_new(void);

    /**
     * Frees a message digest context.
     *
     * @param ctx Context to free
     */
    void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

    /**
     * Initializes a context for signature generation.
     * For post-quantum algorithms, mdname should be NULL (they handle hashing internally).
     *
     * @param ctx Message digest context
     * @param pctx Optional output for EVP_PKEY_CTX (can be NULL)
     * @param mdname Digest name (NULL for PQC algorithms)
     * @param propq Property query string (NULL for default)
     * @param pkey Private key for signing
     * @param params Additional parameters (NULL for defaults)
     * @return 1 on success, 0 or negative on error
     */
    int EVP_DigestSignInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                             const char *mdname, void *libctx, const char *propq,
                             EVP_PKEY *pkey, const void *params);

    /**
     * Generates a digital signature in one operation.
     * Call twice: first with sigret=NULL to get size, then with buffer to generate.
     *
     * @param ctx Initialized signature context
     * @param sigret Output buffer for signature (NULL to query size)
     * @param siglen Input/output: buffer size / actual signature size
     * @param tbs Data to be signed
     * @param tbslen Length of data in bytes
     * @return 1 on success, 0 or negative on error
     */
    int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
                       size_t *siglen, const unsigned char *tbs, size_t tbslen);

    /**
     * Initializes a context for signature verification.
     * For post-quantum algorithms, mdname should be NULL.
     *
     * @param ctx Message digest context
     * @param pctx Optional output for EVP_PKEY_CTX (can be NULL)
     * @param mdname Digest name (NULL for PQC algorithms)
     * @param propq Property query string (NULL for default)
     * @param pkey Public key for verification
     * @param params Additional parameters (NULL for defaults)
     * @return 1 on success, 0 or negative on error
     */
    int EVP_DigestVerifyInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                               const char *mdname, void *libctx, const char *propq,
                               EVP_PKEY *pkey, const void *params);

    /**
     * Verifies a digital signature in one operation.
     *
     * @param ctx Initialized verification context
     * @param sigret Signature to verify
     * @param siglen Signature length in bytes
     * @param tbs Original data that was signed
     * @param tbslen Length of original data
     * @return 1 if valid, 0 if invalid, negative on error
     */
    int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
                        size_t siglen, const unsigned char *tbs, size_t tbslen);


    /******************************************************************
     *                                                                *
     *           Key Encapsulation Mechanism Operations               *
     *                                                                *
     ******************************************************************/

    /**
     * Initializes a context for key encapsulation (sender side).
     * Used to generate a shared secret and ciphertext.
     *
     * @param ctx Context created from recipient's public key
     * @param params Optional parameters (NULL for defaults)
     * @return 1 on success, 0 or negative on error
     */
    int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const void *params);

    /**
     * Performs key encapsulation to generate shared secret and ciphertext.
     * Call twice: first with NULL buffers to get sizes, then with buffers.
     *
     * @param ctx Initialized encapsulation context
     * @param wrappedkey Output buffer for ciphertext (NULL to query size)
     * @param wrappedkeylen Input/output: buffer size / actual ciphertext size
     * @param secret Output buffer for shared secret (NULL to query size)
     * @param secretlen Input/output: buffer size / actual secret size
     * @return 1 on success, 0 or negative on error
     */
    int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx,
                             unsigned char *wrappedkey, size_t *wrappedkeylen,
                             unsigned char *secret, size_t *secretlen);

    /**
     * Initializes a context for key decapsulation (receiver side).
     * Used to recover the shared secret from ciphertext.
     *
     * @param ctx Context created from recipient's private key
     * @param params Optional parameters (NULL for defaults)
     * @return 1 on success, 0 or negative on error
     */
    int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx, const void *params);

    /**
     * Performs key decapsulation to recover shared secret from ciphertext.
     *
     * @param ctx Initialized decapsulation context
     * @param secret Output buffer for recovered shared secret
     * @param secretlen Input/output: buffer size / actual secret size
     * @param wrappedkey Input ciphertext
     * @param wrappedkeylen Ciphertext length in bytes
     * @return 1 on success, 0 or negative on error
     */
    int EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx,
                             unsigned char *secret, size_t *secretlen,
                             const unsigned char *wrappedkey, size_t wrappedkeylen);


    /******************************************************************
     *                                                                *
     *                     Key Serialization                          *
     *                                                                *
     ******************************************************************/

    /**
     * Exports a public key to raw bytes.
     * Call twice: first with pub=NULL to get size, then with buffer.
     *
     * @param pkey Key to export
     * @param pub Output buffer (NULL to query size)
     * @param len Input/output: buffer size / actual key size
     * @return 1 on success, 0 or negative on error
     */
    int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub,
                                    size_t *len);

    /**
     * Exports a private key to raw bytes.
     * Call twice: first with priv=NULL to get size, then with buffer.
     *
     * @param pkey Key to export
     * @param priv Output buffer (NULL to query size)
     * @param len Input/output: buffer size / actual key size
     * @return 1 on success, 0 or negative on error
     */
    int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv,
                                     size_t *len);

    /**
     * Imports a public key from raw bytes.
     *
     * @param libctx Library context (NULL for default)
     * @param keytype Algorithm name (e.g., "ML-KEM-768")
     * @param propq Property query (NULL for default)
     * @param pub Raw public key bytes
     * @param len Length of public key
     * @return New EVP_PKEY or NULL on error
     */
    EVP_PKEY *EVP_PKEY_new_raw_public_key_ex(void *libctx, const char *keytype,
                                             const char *propq,
                                             const unsigned char *pub, size_t len);

    /**
     * Imports a private key from raw bytes.
     *
     * @param libctx Library context (NULL for default)
     * @param keytype Algorithm name (e.g., "ML-KEM-768")
     * @param propq Property query (NULL for default)
     * @param priv Raw private key bytes
     * @param len Length of private key
     * @return New EVP_PKEY or NULL on error
     */
    EVP_PKEY *EVP_PKEY_new_raw_private_key_ex(void *libctx, const char *keytype,
                                              const char *propq,
                                              const unsigned char *priv, size_t len);


    /******************************************************************
     *                                                                *
     *                        Error Handling                          *
     *                                                                *
     ******************************************************************/

    /**
     * Retrieves the earliest error code from OpenSSL's error queue.
     * Returns 0 if no errors are queued.
     *
     * @return Error code or 0 if no error
     */
    unsigned long ERR_get_error(void);

    /**
     * Converts an error code to a human-readable string.
     *
     * @param e Error code from ERR_get_error()
     * @param buf Buffer for error string (256+ bytes recommended, NULL for static buffer)
     * @return Pointer to error string
     */
    char *ERR_error_string(unsigned long e, char *buf);

    /**
     * Clears all errors from OpenSSL's error queue.
     * Should be called before operations for clean error state.
     */
    void ERR_clear_error(void);

    /**
     * Securely erases a memory buffer.
     *
     * Unlike memset, this call is guaranteed not to be optimized away by the
     * compiler. Use for zeroing sensitive material (private keys, shared secrets)
     * before buffers go out of scope.
     *
     * @param ptr Buffer to erase
     * @param len Number of bytes to overwrite
     */
    void OPENSSL_cleanse(void *ptr, size_t len);


""")

# OpenSSL is built as a static library, so libcrypto is linked
# directly into the extension at compile time.

extra_link_args = []

if platform.system() == "Windows":
    # Windows requires explicit linking against system support libraries.
    extra_link_args.extend(
        [
            "ws2_32.lib",  # Winsock
            "advapi32.lib",  # Advanced Windows API
            "crypt32.lib",  # Cryptography API
            "user32.lib",  # User interface functions
        ]
    )

if platform.system() == "Windows":
    crypto_lib = ["libcrypto"]  # libcrypto.lib — no-shared build produces this name
else:
    crypto_lib = ["crypto"]  # libcrypto.a on Unix

ffibuilder.set_source(
    "_alkindi_",
    """
    #include <openssl/opensslv.h>
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/crypto.h>
    #include <openssl/provider.h>
    #include <openssl/params.h>
    #include <openssl/core_names.h>
    """,
    include_dirs=[OPENSSL_INCLUDE],
    library_dirs=[OPENSSL_LIB],
    libraries=crypto_lib,
    extra_link_args=extra_link_args,
)
