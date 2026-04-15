"""
Hardcoded parameters for post-quantum cryptographic algorithms.

These parameters are verified against OpenSSL at runtime during testing.
"""

from types import MappingProxyType

# MappingProxyType provides a read-only view of dictionaries, preventing accidental
# modification of cryptographic parameters at runtime.

# ML-KEM (FIPS 203): Key Encapsulation Mechanism
MLKEM_PARAMS = MappingProxyType(
    {
        "ML-KEM-512": {
            "public_key_size": 800,
            "private_key_size": 1632,
            "ciphertext_size": 768,
            "shared_secret_size": 32,
        },
        "ML-KEM-768": {
            "public_key_size": 1184,
            "private_key_size": 2400,
            "ciphertext_size": 1088,
            "shared_secret_size": 32,
        },
        "ML-KEM-1024": {
            "public_key_size": 1568,
            "private_key_size": 3168,
            "ciphertext_size": 1568,
            "shared_secret_size": 32,
        },
    }
)

# ML-DSA (FIPS 204): Lattice-based Digital Signature Algorithm
MLDSA_PARAMS = MappingProxyType(
    {
        "ML-DSA-44": {
            "public_key_size": 1312,
            "private_key_size": 2560,
            "signature_size": 2420,
        },
        "ML-DSA-65": {
            "public_key_size": 1952,
            "private_key_size": 4032,
            "signature_size": 3309,
        },
        "ML-DSA-87": {
            "public_key_size": 2592,
            "private_key_size": 4896,
            "signature_size": 4627,
        },
    }
)

# SLH-DSA (FIPS 205): Hash-based Digital Signature Algorithm
SLHDSA_PARAMS = MappingProxyType(
    {
        "SLH-DSA-SHA2-128S": {
            "public_key_size": 32,
            "private_key_size": 64,
            "signature_size": 7856,
        },
        "SLH-DSA-SHA2-128F": {
            "public_key_size": 32,
            "private_key_size": 64,
            "signature_size": 17088,
        },
        "SLH-DSA-SHA2-192S": {
            "public_key_size": 48,
            "private_key_size": 96,
            "signature_size": 16224,
        },
        "SLH-DSA-SHA2-192F": {
            "public_key_size": 48,
            "private_key_size": 96,
            "signature_size": 35664,
        },
        "SLH-DSA-SHA2-256S": {
            "public_key_size": 64,
            "private_key_size": 128,
            "signature_size": 29792,
        },
        "SLH-DSA-SHA2-256F": {
            "public_key_size": 64,
            "private_key_size": 128,
            "signature_size": 49856,
        },
        "SLH-DSA-SHAKE-128S": {
            "public_key_size": 32,
            "private_key_size": 64,
            "signature_size": 7856,
        },
        "SLH-DSA-SHAKE-128F": {
            "public_key_size": 32,
            "private_key_size": 64,
            "signature_size": 17088,
        },
        "SLH-DSA-SHAKE-192S": {
            "public_key_size": 48,
            "private_key_size": 96,
            "signature_size": 16224,
        },
        "SLH-DSA-SHAKE-192F": {
            "public_key_size": 48,
            "private_key_size": 96,
            "signature_size": 35664,
        },
        "SLH-DSA-SHAKE-256S": {
            "public_key_size": 64,
            "private_key_size": 128,
            "signature_size": 29792,
        },
        "SLH-DSA-SHAKE-256F": {
            "public_key_size": 64,
            "private_key_size": 128,
            "signature_size": 49856,
        },
    }
)

# frozenset provides:
#   1. Immutability: Cannot be modified after creation, preventing bugs
#   2. O(1) average-case membership testing for fast algorithm validation
#   3. Hashability: Can be used as dict keys or in other sets (unlike regular sets)
#   4. Memory efficiency: More compact than regular sets since no mutation support needed
#
# Aggregation patterns:
#   - The * operator unpacks dictionary keys from MappingProxyType objects
#   - The | operator creates set unions to combine multiple algorithm families
#   - This approach maintains a single source of truth while enabling efficient lookups

SUPPORTED_KEM_ALGORITHMS = frozenset(MLKEM_PARAMS)

SUPPORTED_SIGNATURE_ALGORITHMS = frozenset(
    {
        *MLDSA_PARAMS,
        *SLHDSA_PARAMS,
    }
)

ALL_SUPPORTED_ALGORITHMS = frozenset(
    SUPPORTED_KEM_ALGORITHMS | SUPPORTED_SIGNATURE_ALGORITHMS
)
