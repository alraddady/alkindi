"""Security tests for key serialization — structural key confusion prevention."""

import pytest

from alkindi import KEM
from alkindi.serialization import Keys

KEM_ALG = "ML-KEM-768"


def test_public_key_der_cannot_decode_as_private():
    keypair = KEM.generate_keypair(KEM_ALG)
    keys = Keys(KEM_ALG)
    der = keys.public_key_to_der(keypair.public_key)
    with pytest.raises(Exception):
        keys.private_key_from_der(der)
