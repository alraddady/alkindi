"""Utility functions for alkindi cryptographic algorithms.

This module provides helper functions to query information about supported
post-quantum algorithms across both KEM and signature schemes.
"""

from alkindi._params import MLKEM_PARAMS, MLDSA_PARAMS, SLHDSA_PARAMS

_SECURITY_LEVELS = {
    "ML-KEM-512": (1, 128),
    "ML-KEM-768": (3, 192),
    "ML-KEM-1024": (5, 256),
    "ML-DSA-44": (2, 128),
    "ML-DSA-65": (3, 192),
    "ML-DSA-87": (5, 256),
    "SLH-DSA-SHA2-128S": (1, 128),
    "SLH-DSA-SHA2-128F": (1, 128),
    "SLH-DSA-SHA2-192S": (3, 192),
    "SLH-DSA-SHA2-192F": (3, 192),
    "SLH-DSA-SHA2-256S": (5, 256),
    "SLH-DSA-SHA2-256F": (5, 256),
    "SLH-DSA-SHAKE-128S": (1, 128),
    "SLH-DSA-SHAKE-128F": (1, 128),
    "SLH-DSA-SHAKE-192S": (3, 192),
    "SLH-DSA-SHAKE-192F": (3, 192),
    "SLH-DSA-SHAKE-256S": (5, 256),
    "SLH-DSA-SHAKE-256F": (5, 256),
}

# Pre-computed algorithm lists for efficient lookup (immutable static data)
_KEM_ALGORITHMS = [
    {
        "name": name,
        "type": "kem",
        "security_category": _SECURITY_LEVELS[name][0],
        "security_level": _SECURITY_LEVELS[name][1],
        **params,
    }
    for name, params in MLKEM_PARAMS.items()
]

_MLDSA_ALGORITHMS = [
    {
        "name": name,
        "type": "signature",
        "security_category": _SECURITY_LEVELS[name][0],
        "security_level": _SECURITY_LEVELS[name][1],
        **params,
    }
    for name, params in MLDSA_PARAMS.items()
]

_SLHDSA_ALGORITHMS = [
    {
        "name": name,
        "type": "signature",
        "security_category": _SECURITY_LEVELS[name][0],
        "security_level": _SECURITY_LEVELS[name][1],
        **params,
    }
    for name, params in SLHDSA_PARAMS.items()
]

_SIGNATURE_ALGORITHMS = _MLDSA_ALGORITHMS + _SLHDSA_ALGORITHMS
_ALL_ALGORITHMS = _KEM_ALGORITHMS + _SIGNATURE_ALGORITHMS


def guide() -> None:
    """
    Display comprehensive guide for post-quantum cryptographic algorithms.

    Prints detailed information about algorithm types, NIST security categories,
    and specifications for all supported algorithms.

    Example:
        >>> import alkindi
        >>> alkindi.guide()
    """

    print(f"""
{"=" * 80}
POST-QUANTUM CRYPTOGRAPHIC ALGORITHMS GUIDE
{"=" * 80}

ALGORITHM TYPES:
{"-" * 80}

ML-KEM (Module Lattice-Based Key Encapsulation Mechanism):
  Standardized in FIPS 203, ML-KEM is designed for secure key exchange
  in post-quantum cryptography. It offers excellent performance with
  compact key sizes and ciphertexts, making it ideal for establishing
  shared secrets in hybrid encryption schemes. Based on the hardness
  of module lattice problems.

ML-DSA (Module Lattice-Based Digital Signature Algorithm):
  Standardized in FIPS 204, ML-DSA provides fast signing and verification
  with relatively compact signatures. It offers a good balance between
  security, performance, and signature size. Based on the hardness of
  module lattice problems, similar to ML-KEM.

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm):
  Standardized in FIPS 205, SLH-DSA offers conservative security based
  solely on the strength of hash functions. While it produces larger
  signatures than ML-DSA, it provides an alternative security foundation
  that doesn't rely on structured mathematical problems. Available in
  'small' (s) variants for smaller signatures or 'fast' (f) variants
  for faster signing.

{"-" * 80}
NIST SECURITY CATEGORIES:
{"-" * 80}

Category 0:
    Not considered quantum safe. Algorithms with this category do not
    provide sufficient security against quantum attacks.

Category 1 (128-bit security):
    Key search on a block cipher with a 128-bit key (AES-128 equivalent).
    Sufficient for most commercial applications. Provides protection
    against quantum attacks requiring approximately 2^128 operations.

Category 2 (128-bit security):
    Collision search on a 256-bit hash function (SHA-256 equivalent).
    Similar strength to Category 1 but measured against collision
    resistance rather than key search.

Category 3 (192-bit security):
    Key search on a block cipher with a 192-bit key (AES-192 equivalent).
    Recommended for applications requiring higher security margins.
    Provides protection against attacks requiring approximately 2^192
    operations.

Category 4 (224-bit security):
    Collision search on a 384-bit hash function (SHA3-384 equivalent).
    Provides protection against attacks requiring approximately 2^224
    operations. Not used by any algorithms in this library.

Category 5 (256-bit security):
    Key search on a block cipher with a 256-bit key (AES-256 equivalent).
    Highest standardized security level, suitable for long-term protection
    of highly sensitive data. Provides protection against attacks requiring
    approximately 2^256 operations.
""")

    print(f"""
{"=" * 80}
SUPPORTED ALGORITHMS
{"=" * 80}""")

    for alg in _ALL_ALGORITHMS:
        if alg["type"] == "kem":
            type_specific = f"""  Ciphertext Size: {alg["ciphertext_size"]} bytes
  Shared Secret Size: {alg["shared_secret_size"]} bytes"""
        else:
            type_specific = f"""  Signature Size: {alg["signature_size"]} bytes"""

        print(f"""
Algorithm: {alg["name"]}
  Type: {alg["type"]}
  Security Category: {alg["security_category"]}
  Security Level: {alg["security_level"]} bits
  Public Key Size: {alg["public_key_size"]} bytes
  Private Key Size: {alg["private_key_size"]} bytes
{type_specific}""")

    print(f"\n{'=' * 80}")
