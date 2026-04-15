"""Shared fixtures and constants for the alkindi test suite."""

import pytest

from alkindi import KEM, Signature
from alkindi._internal.params import MLDSA_PARAMS, MLKEM_PARAMS

MESSAGE = b"the quick brown fox jumps over the lazy dog"

# Only fast SLH-DSA variants — full SLH-DSA keygen is slow.
_SLHDSA_FAST = ["SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F"]

SIG_ALGORITHMS = list(MLDSA_PARAMS) + _SLHDSA_FAST


@pytest.fixture(scope="session", params=list(MLKEM_PARAMS))
def kem_algorithm(request):
    return request.param


@pytest.fixture(scope="session")
def kem_keypair(kem_algorithm):
    return KEM.generate_keypair(kem_algorithm)


@pytest.fixture(scope="session", params=list(MLDSA_PARAMS))
def mldsa_algorithm(request):
    return request.param


@pytest.fixture(scope="session")
def mldsa_keypair(mldsa_algorithm):
    return Signature.generate_keypair(mldsa_algorithm)


@pytest.fixture(scope="session", params=SIG_ALGORITHMS)
def sig_algorithm(request):
    return request.param


@pytest.fixture(scope="session")
def sig_keypair(sig_algorithm):
    return Signature.generate_keypair(sig_algorithm)
