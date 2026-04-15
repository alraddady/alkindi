"""Validation tests for ML-KEM — invalid inputs are rejected."""

import pytest

from alkindi import KEM, AlkindiAPIError


def test_invalid_algorithm_on_generate():
    with pytest.raises(AlkindiAPIError):
        KEM.generate_keypair("ML-KEM-9999")


def test_invalid_algorithm_on_encapsulate():
    with pytest.raises(AlkindiAPIError):
        KEM.encapsulate("ML-KEM-9999", b"\x00" * 100)


def test_invalid_algorithm_on_decapsulate():
    with pytest.raises(AlkindiAPIError):
        KEM.decapsulate("ML-KEM-9999", b"\x00" * 100, b"\x00" * 100)


def test_public_key_not_bytes(kem_algorithm):
    with pytest.raises(AlkindiAPIError):
        KEM.encapsulate(kem_algorithm, "not bytes")


def test_ciphertext_not_bytes(kem_algorithm, kem_keypair):
    with pytest.raises(AlkindiAPIError):
        KEM.decapsulate(kem_algorithm, kem_keypair.private_key, "not bytes")


def test_invalid_public_key_bytes(kem_algorithm):
    with pytest.raises(Exception):
        KEM.encapsulate(kem_algorithm, b"\x00" * 10)


def test_seed_wrong_length(kem_algorithm):
    with pytest.raises(AlkindiAPIError):
        KEM.generate_keypair(kem_algorithm, seed=bytes(32))


def test_seed_not_bytes(kem_algorithm):
    with pytest.raises(AlkindiAPIError):
        KEM.generate_keypair(kem_algorithm, seed="a" * 64)


def test_algorithm_name_is_case_insensitive():
    from alkindi._params import MLKEM_PARAMS
    kp = KEM.generate_keypair("ml-kem-768")
    assert len(kp.public_key) == MLKEM_PARAMS["ML-KEM-768"]["public_key_size"]
