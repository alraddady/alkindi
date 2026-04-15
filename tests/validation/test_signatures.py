"""Validation tests for ML-DSA and SLH-DSA — invalid inputs are rejected."""

import pytest

from alkindi import AlkindiAPIError, Signature

MESSAGE = b"the quick brown fox jumps over the lazy dog"


def test_invalid_algorithm_on_generate():
    with pytest.raises(AlkindiAPIError):
        Signature.generate_keypair("ML-DSA-999")


def test_invalid_algorithm_on_sign():
    with pytest.raises(AlkindiAPIError):
        Signature.sign("ML-DSA-999", b"\x00" * 100, MESSAGE)


def test_private_key_not_bytes(sig_algorithm):
    with pytest.raises(AlkindiAPIError):
        Signature.sign(sig_algorithm, "not bytes", MESSAGE)


def test_message_not_bytes(sig_algorithm, sig_keypair):
    with pytest.raises(AlkindiAPIError):
        Signature.sign(sig_algorithm, sig_keypair.private_key, "not bytes")


def test_public_key_not_bytes_on_verify(sig_algorithm, sig_keypair):
    sig = Signature.sign(sig_algorithm, sig_keypair.private_key, MESSAGE)
    with pytest.raises(AlkindiAPIError):
        Signature.verify(sig_algorithm, "not bytes", MESSAGE, sig)


def test_context_too_long(mldsa_algorithm, mldsa_keypair):
    with pytest.raises(AlkindiAPIError):
        Signature.sign(mldsa_algorithm, mldsa_keypair.private_key, MESSAGE, context=b"x" * 256)


def test_context_not_bytes(mldsa_algorithm, mldsa_keypair):
    with pytest.raises(AlkindiAPIError):
        Signature.sign(mldsa_algorithm, mldsa_keypair.private_key, MESSAGE, context="string")


def test_algorithm_name_is_case_insensitive():
    from alkindi._internal.params import MLDSA_PARAMS
    kp = Signature.generate_keypair("ml-dsa-44")
    assert len(kp.public_key) == MLDSA_PARAMS["ML-DSA-44"]["public_key_size"]
