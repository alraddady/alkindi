"""Correctness tests for ML-KEM — key sizes, round trips, seed determinism."""

from alkindi import KEM
from alkindi._internal.params import MLKEM_PARAMS


def test_public_key_size(kem_algorithm, kem_keypair):
    assert len(kem_keypair.public_key) == MLKEM_PARAMS[kem_algorithm]["public_key_size"]


def test_private_key_size(kem_algorithm, kem_keypair):
    assert len(kem_keypair.private_key) == MLKEM_PARAMS[kem_algorithm]["private_key_size"]


def test_ciphertext_size(kem_algorithm, kem_keypair):
    ciphertext, _ = KEM.encapsulate(kem_algorithm, kem_keypair.public_key)
    assert len(ciphertext) == MLKEM_PARAMS[kem_algorithm]["ciphertext_size"]


def test_shared_secret_size(kem_algorithm, kem_keypair):
    _, shared_secret = KEM.encapsulate(kem_algorithm, kem_keypair.public_key)
    assert len(shared_secret) == MLKEM_PARAMS[kem_algorithm]["shared_secret_size"]


def test_encapsulate_decapsulate_secrets_match(kem_algorithm, kem_keypair):
    ciphertext, secret_sender = KEM.encapsulate(kem_algorithm, kem_keypair.public_key)
    secret_receiver = KEM.decapsulate(kem_algorithm, kem_keypair.private_key, ciphertext)
    assert secret_sender == secret_receiver


def test_seed_produces_same_keypair(kem_algorithm):
    seed = bytes(range(64))
    kp1 = KEM.generate_keypair(kem_algorithm, seed=seed)
    kp2 = KEM.generate_keypair(kem_algorithm, seed=seed)
    assert kp1.public_key == kp2.public_key
    assert kp1.private_key == kp2.private_key


def test_different_seeds_produce_different_keypairs(kem_algorithm):
    kp1 = KEM.generate_keypair(kem_algorithm, seed=bytes(64))
    kp2 = KEM.generate_keypair(kem_algorithm, seed=bytes([1] * 64))
    assert kp1.public_key != kp2.public_key


def test_output_types_are_bytes(kem_algorithm, kem_keypair):
    assert isinstance(kem_keypair.public_key, bytes)
    assert isinstance(kem_keypair.private_key, bytes)
    ciphertext, shared_secret = KEM.encapsulate(kem_algorithm, kem_keypair.public_key)
    assert isinstance(ciphertext, bytes)
    assert isinstance(shared_secret, bytes)


