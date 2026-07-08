"""Correctness tests for bytes-like inputs — bytearray and memoryview everywhere."""

import array

import pytest

from alkindi import KEM, AlkindiAPIError, Signature
from alkindi.serialization import Keys

KEM_ALG = "ML-KEM-512"
SIG_ALG = "ML-DSA-44"
MESSAGE = b"the quick brown fox jumps over the lazy dog"


@pytest.fixture(scope="module")
def kem_kp():
    return KEM.generate_keypair(KEM_ALG)


@pytest.fixture(scope="module")
def sig_kp():
    return Signature.generate_keypair(SIG_ALG)


# --- ML-KEM ---

def test_encapsulate_accepts_bytearray_and_memoryview(kem_kp):
    for public_key in [bytearray(kem_kp.public_key), memoryview(kem_kp.public_key)]:
        ciphertext, secret = KEM.encapsulate(KEM_ALG, public_key)
        assert KEM.decapsulate(KEM_ALG, kem_kp.private_key, ciphertext) == secret


def test_decapsulate_accepts_bytearray_and_memoryview(kem_kp):
    ciphertext, secret = KEM.encapsulate(KEM_ALG, kem_kp.public_key)
    for private_key, ct in [
        (bytearray(kem_kp.private_key), bytearray(ciphertext)),
        (memoryview(kem_kp.private_key), memoryview(ciphertext)),
    ]:
        assert KEM.decapsulate(KEM_ALG, private_key, ct) == secret


def test_seed_accepts_bytearray_and_memoryview():
    seed = bytes(range(64))
    kp_bytes = KEM.generate_keypair(KEM_ALG, seed=seed)
    assert KEM.generate_keypair(KEM_ALG, seed=bytearray(seed)) == kp_bytes
    assert KEM.generate_keypair(KEM_ALG, seed=memoryview(seed)) == kp_bytes


def test_seed_length_is_measured_in_bytes():
    # 16 uint32 items == 64 bytes, but len(memoryview) == 16.
    seed_items = array.array("I", range(16))
    assert seed_items.itemsize * len(seed_items) == 64
    kp = KEM.generate_keypair(KEM_ALG, seed=memoryview(seed_items))
    assert kp == KEM.generate_keypair(KEM_ALG, seed=seed_items.tobytes())


def test_non_contiguous_memoryview_rejected(kem_kp):
    with pytest.raises(AlkindiAPIError):
        KEM.encapsulate(KEM_ALG, memoryview(kem_kp.public_key)[::2])


# --- Signatures ---

def test_sign_verify_accepts_bytearray(sig_kp):
    sig = Signature.sign(SIG_ALG, bytearray(sig_kp.private_key), bytearray(MESSAGE))
    assert Signature.verify(
        SIG_ALG, bytearray(sig_kp.public_key), bytearray(MESSAGE), bytearray(sig)
    )


def test_sign_verify_accepts_memoryview(sig_kp):
    sig = Signature.sign(SIG_ALG, memoryview(sig_kp.private_key), memoryview(MESSAGE))
    assert Signature.verify(
        SIG_ALG, memoryview(sig_kp.public_key), memoryview(MESSAGE), memoryview(sig)
    )


def test_context_accepts_bytearray_and_memoryview(sig_kp):
    ctx = b"my-application-v1"
    sig = Signature.sign(SIG_ALG, sig_kp.private_key, MESSAGE, context=bytearray(ctx))
    assert Signature.verify(
        SIG_ALG, sig_kp.public_key, MESSAGE, sig, context=memoryview(ctx)
    )
    assert Signature.verify(SIG_ALG, sig_kp.public_key, MESSAGE, sig, context=ctx)


# --- Serialization ---

def test_keys_encode_accepts_bytearray_and_memoryview(kem_kp):
    keys = Keys(KEM_ALG)
    der = keys.public_key_to_der(kem_kp.public_key)
    assert keys.public_key_to_der(bytearray(kem_kp.public_key)) == der
    assert keys.public_key_to_der(memoryview(kem_kp.public_key)) == der
    pem = keys.private_key_to_pem(kem_kp.private_key)
    assert keys.private_key_to_pem(bytearray(kem_kp.private_key)) == pem
    assert keys.private_key_to_pem(memoryview(kem_kp.private_key)) == pem


def test_keys_decode_accepts_bytearray_and_memoryview(kem_kp):
    keys = Keys(KEM_ALG)
    der = keys.public_key_to_der(kem_kp.public_key)
    pem = keys.private_key_to_pem(kem_kp.private_key)
    assert keys.public_key_from_der(bytearray(der)) == kem_kp.public_key
    assert keys.public_key_from_der(memoryview(der)) == kem_kp.public_key
    assert keys.private_key_from_pem(bytearray(pem)) == kem_kp.private_key
    assert keys.private_key_from_pem(memoryview(pem)) == kem_kp.private_key
