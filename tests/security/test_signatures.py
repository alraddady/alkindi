"""Security tests for ML-DSA and SLH-DSA — forgery and context binding."""

from alkindi import Signature

MESSAGE = b"the quick brown fox jumps over the lazy dog"


def test_keypairs_are_random(sig_algorithm):
    kp1 = Signature.generate_keypair(sig_algorithm)
    kp2 = Signature.generate_keypair(sig_algorithm)
    assert kp1.public_key != kp2.public_key


def test_wrong_public_key_fails(sig_algorithm, sig_keypair):
    other = Signature.generate_keypair(sig_algorithm)
    sig = Signature.sign(sig_algorithm, sig_keypair.private_key, MESSAGE)
    assert not Signature.verify(sig_algorithm, other.public_key, MESSAGE, sig)


def test_tampered_message_fails(sig_algorithm, sig_keypair):
    sig = Signature.sign(sig_algorithm, sig_keypair.private_key, MESSAGE)
    assert not Signature.verify(sig_algorithm, sig_keypair.public_key, b"tampered", sig)


def test_tampered_signature_fails(sig_algorithm, sig_keypair):
    sig = Signature.sign(sig_algorithm, sig_keypair.private_key, MESSAGE)
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    assert not Signature.verify(sig_algorithm, sig_keypair.public_key, MESSAGE, bad_sig)


def test_wrong_context_fails(mldsa_algorithm, mldsa_keypair):
    sig = Signature.sign(mldsa_algorithm, mldsa_keypair.private_key, MESSAGE, context=b"ctx-a")
    assert not Signature.verify(mldsa_algorithm, mldsa_keypair.public_key, MESSAGE, sig, context=b"ctx-b")


def test_context_vs_no_context_fails(mldsa_algorithm, mldsa_keypair):
    sig_with_ctx = Signature.sign(mldsa_algorithm, mldsa_keypair.private_key, MESSAGE, context=b"ctx")
    sig_no_ctx = Signature.sign(mldsa_algorithm, mldsa_keypair.private_key, MESSAGE)
    assert not Signature.verify(mldsa_algorithm, mldsa_keypair.public_key, MESSAGE, sig_with_ctx)
    assert not Signature.verify(mldsa_algorithm, mldsa_keypair.public_key, MESSAGE, sig_no_ctx, context=b"ctx")
