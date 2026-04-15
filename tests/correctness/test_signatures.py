"""Correctness tests for ML-DSA and SLH-DSA — key sizes, sign/verify round trips, context."""

from alkindi import Signature
from alkindi._internal.params import MLDSA_PARAMS

MESSAGE = b"the quick brown fox jumps over the lazy dog"


def test_public_key_size(mldsa_algorithm, mldsa_keypair):
    assert len(mldsa_keypair.public_key) == MLDSA_PARAMS[mldsa_algorithm]["public_key_size"]


def test_private_key_size(mldsa_algorithm, mldsa_keypair):
    assert len(mldsa_keypair.private_key) == MLDSA_PARAMS[mldsa_algorithm]["private_key_size"]


def test_signature_size(mldsa_algorithm, mldsa_keypair):
    sig = Signature.sign(mldsa_algorithm, mldsa_keypair.private_key, MESSAGE)
    assert len(sig) == MLDSA_PARAMS[mldsa_algorithm]["signature_size"]


def test_sign_verify_round_trip(sig_algorithm, sig_keypair):
    sig = Signature.sign(sig_algorithm, sig_keypair.private_key, MESSAGE)
    assert Signature.verify(sig_algorithm, sig_keypair.public_key, MESSAGE, sig)


def test_sign_verify_empty_message(sig_algorithm, sig_keypair):
    sig = Signature.sign(sig_algorithm, sig_keypair.private_key, b"")
    assert Signature.verify(sig_algorithm, sig_keypair.public_key, b"", sig)


def test_context_round_trip(mldsa_algorithm, mldsa_keypair):
    ctx = b"my-application-v1"
    sig = Signature.sign(mldsa_algorithm, mldsa_keypair.private_key, MESSAGE, context=ctx)
    assert Signature.verify(mldsa_algorithm, mldsa_keypair.public_key, MESSAGE, sig, context=ctx)


def test_empty_context(mldsa_algorithm, mldsa_keypair):
    sig = Signature.sign(mldsa_algorithm, mldsa_keypair.private_key, MESSAGE, context=b"")
    assert Signature.verify(mldsa_algorithm, mldsa_keypair.public_key, MESSAGE, sig, context=b"")


def test_max_context_length(mldsa_algorithm, mldsa_keypair):
    ctx = b"x" * 255
    sig = Signature.sign(mldsa_algorithm, mldsa_keypair.private_key, MESSAGE, context=ctx)
    assert Signature.verify(mldsa_algorithm, mldsa_keypair.public_key, MESSAGE, sig, context=ctx)


def test_output_types_are_bytes(sig_algorithm, sig_keypair):
    assert isinstance(sig_keypair.public_key, bytes)
    assert isinstance(sig_keypair.private_key, bytes)
    assert isinstance(Signature.sign(sig_algorithm, sig_keypair.private_key, MESSAGE), bytes)


