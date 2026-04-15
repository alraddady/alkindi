"""Validation tests for key serialization — invalid inputs are rejected."""

import pytest

from alkindi import AlkindiAPIError
from alkindi.serialization import Keys


def test_invalid_algorithm():
    with pytest.raises(AlkindiAPIError):
        Keys("ML-KEM-9999")


def test_public_key_not_bytes():
    keys = Keys("ML-KEM-768")
    with pytest.raises(AlkindiAPIError):
        keys.public_key_to_der("not bytes")


def test_private_key_not_bytes():
    keys = Keys("ML-KEM-768")
    with pytest.raises(AlkindiAPIError):
        keys.private_key_to_der("not bytes")


def test_invalid_der_raises():
    keys = Keys("ML-KEM-768")
    with pytest.raises(Exception):
        keys.public_key_from_der(b"\x00" * 64)


def test_algorithm_name_is_case_insensitive():
    assert Keys("ml-kem-768")._algorithm == "ML-KEM-768"
