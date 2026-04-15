"""Correctness tests for key serialization — DER/PEM round trips and integration."""

import pytest

from alkindi import KEM, Signature
from alkindi.serialization import Keys

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"


@pytest.fixture(scope="module")
def kem_keypair():
    return KEM.generate_keypair(KEM_ALG)


@pytest.fixture(scope="module")
def sig_keypair():
    return Signature.generate_keypair(SIG_ALG)


@pytest.fixture(scope="module")
def kem_keys():
    return Keys(KEM_ALG)


@pytest.fixture(scope="module")
def sig_keys():
    return Keys(SIG_ALG)


def test_public_key_der_round_trip(kem_keys, kem_keypair):
    assert kem_keys.public_key_from_der(kem_keys.public_key_to_der(kem_keypair.public_key)) == kem_keypair.public_key


def test_public_key_pem_round_trip(kem_keys, kem_keypair):
    assert kem_keys.public_key_from_pem(kem_keys.public_key_to_pem(kem_keypair.public_key)) == kem_keypair.public_key


def test_private_key_der_round_trip(kem_keys, kem_keypair):
    assert kem_keys.private_key_from_der(kem_keys.private_key_to_der(kem_keypair.private_key)) == kem_keypair.private_key


def test_private_key_pem_round_trip(kem_keys, kem_keypair):
    assert kem_keys.private_key_from_pem(kem_keys.private_key_to_pem(kem_keypair.private_key)) == kem_keypair.private_key


def test_der_and_pem_decode_to_same_public_key(kem_keys, kem_keypair):
    assert kem_keys.public_key_from_der(kem_keys.public_key_to_der(kem_keypair.public_key)) == \
           kem_keys.public_key_from_pem(kem_keys.public_key_to_pem(kem_keypair.public_key))


def test_der_and_pem_decode_to_same_private_key(kem_keys, kem_keypair):
    assert kem_keys.private_key_from_der(kem_keys.private_key_to_der(kem_keypair.private_key)) == \
           kem_keys.private_key_from_pem(kem_keys.private_key_to_pem(kem_keypair.private_key))


def test_pem_has_header_and_footer(kem_keys, kem_keypair):
    for pem in [
        kem_keys.public_key_to_pem(kem_keypair.public_key),
        kem_keys.private_key_to_pem(kem_keypair.private_key),
    ]:
        assert pem.startswith(b"-----BEGIN")
        assert b"-----END" in pem


def test_der_is_binary_not_pem(kem_keys, kem_keypair):
    assert not kem_keys.public_key_to_der(kem_keypair.public_key).startswith(b"-----")
    assert not kem_keys.private_key_to_der(kem_keypair.private_key).startswith(b"-----")


def test_output_is_bytes(kem_keys, kem_keypair):
    assert isinstance(kem_keys.public_key_to_der(kem_keypair.public_key), bytes)
    assert isinstance(kem_keys.public_key_to_pem(kem_keypair.public_key), bytes)
    assert isinstance(kem_keys.private_key_to_der(kem_keypair.private_key), bytes)
    assert isinstance(kem_keys.private_key_to_pem(kem_keypair.private_key), bytes)


def test_serialized_public_key_works_with_kem(kem_keys, kem_keypair):
    pub = kem_keys.public_key_from_pem(kem_keys.public_key_to_pem(kem_keypair.public_key))
    ciphertext, secret_sender = KEM.encapsulate(KEM_ALG, pub)
    assert KEM.decapsulate(KEM_ALG, kem_keypair.private_key, ciphertext) == secret_sender


def test_serialized_private_key_works_with_signature(sig_keys, sig_keypair):
    message = b"hello world"
    priv = sig_keys.private_key_from_pem(sig_keys.private_key_to_pem(sig_keypair.private_key))
    sig = Signature.sign(SIG_ALG, priv, message)
    assert Signature.verify(SIG_ALG, sig_keypair.public_key, message, sig)
