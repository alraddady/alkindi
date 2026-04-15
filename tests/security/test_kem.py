"""Security tests for ML-KEM — randomness and key isolation."""

from alkindi import KEM


def test_keypairs_are_random(kem_algorithm):
    kp1 = KEM.generate_keypair(kem_algorithm)
    kp2 = KEM.generate_keypair(kem_algorithm)
    assert kp1.public_key != kp2.public_key
    assert kp1.private_key != kp2.private_key


def test_encapsulation_is_random(kem_algorithm, kem_keypair):
    _, secret1 = KEM.encapsulate(kem_algorithm, kem_keypair.public_key)
    _, secret2 = KEM.encapsulate(kem_algorithm, kem_keypair.public_key)
    assert secret1 != secret2


def test_wrong_private_key_gives_different_secret(kem_algorithm, kem_keypair):
    other = KEM.generate_keypair(kem_algorithm)
    ciphertext, secret_sender = KEM.encapsulate(kem_algorithm, kem_keypair.public_key)
    assert KEM.decapsulate(kem_algorithm, other.private_key, ciphertext) != secret_sender
