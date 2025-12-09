<div align="center">

# Alkindi

In honor of Alkindi (الكِندي), the 9th-century pioneer of cryptography*

[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)](https://github.com/alraddady/alkindi)
[![License: Apache-2.0](https://img.shields.io/github/license/alraddady/alkindi)](LICENSE)

**High-performance Python bindings for NIST-standardized post-quantum cryptography, powered by OpenSSL.**

---

</div>

## Table of Contents

- [About](#about)
- [Why Alkindi?](#why-alkindi)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Key Encapsulation (ML-KEM)](#key-encapsulation-ml-kem)
  - [Digital Signatures (ML-DSA)](#digital-signatures-ml-dsa)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## About

The project is named after [**Alkindi**](https://www.britannica.com/biography/al-kindi) (الكِنْدي), the 9th-century Arab Muslim polymath who pioneered cryptanalysis and frequency analysis, laying the foundations for modern cryptography.

**Alkindi** makes quantum-resistant cryptography straightforward and accessible in Python by providing clean, type-safe bindings to OpenSSL's implementations of NIST-standardized post-quantum algorithms. As quantum computers advance, traditional public-key systems like RSA and elliptic curves become vulnerable. Alkindi provides the cryptographic primitives needed to protect against both classical and quantum attacks.

### Supported Algorithms

- **ML-KEM** (formerly Kyber) — Key encapsulation mechanisms for secure key exchange  
  Based on lattice cryptography, ML-KEM enables two parties to establish a shared secret over an insecure channel. Available in three security levels (ML-KEM-512, ML-KEM-768, ML-KEM-1024) corresponding to AES-128, AES-192, and AES-256 equivalent security.

- **ML-DSA** (formerly Dilithium) — Digital signatures for authentication and integrity  
  Lattice-based signatures that provide quantum-resistant authentication. Three parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87) offer balanced trade-offs between signature size and security strength.

- **SLH-DSA** (formerly SPHINCS+) — Hash-based signatures for conservative security guarantees  
  Unlike lattice-based schemes, SLH-DSA relies only on hash function security, making it ideal for long-term signatures and applications requiring minimal cryptographic assumptions. Available in multiple variants optimized for either speed or size.


Alkindi uses **CFFI** to interface directly with OpenSSL's C implementations, achieving high performance with minimal overhead. The library provides a stateless, thread-safe API with full type annotations for enhanced developer experience. 


> **Status:** Alpha — Alkindi is under active development with the explicit goal of becoming a production-grade, thoroughly reviewed PQC library for Python. APIs may change before version 1.0.0.

---

## Why Alkindi?

Alkindi bridges the gap between enterprise-grade cryptography and Python developer ergonomics, bringing NIST-standardized post-quantum algorithms to your applications with production readiness in mind:

| Feature                    | Description                                                                                                                             |
|----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| **Battle-tested backend**  | Built on OpenSSL, leveraging decades of cryptographic engineering and security audits rather than implementing algorithms from scratch. |
| **Standards-first**        | Uses NIST-standardized post-quantum algorithms exclusively and avoids experimental or pre-standard variants.                            |
| **High performance**       | CFFI-based bindings call OpenSSL directly, achieving near-native C performance with minimal Python overhead.                            |
| **Type-safe, simple API**  | Full type hints and a stateless, thread-safe design for safer concurrent usage and superior developer experience.                       |
| **Minimal attack surface** | A deliberately focused API that is easier to reason about, audit, and review than a sprawling cryptographic toolkit.                    |

---

## Installation

### From PyPI *(Coming Soon)*

```bash
pip install alkindi
```

### From Source

**Requirements:** Python 3.10+ and C compiler

```bash
# Clone the repository
git clone https://github.com/alraddady/alkindi.git
cd alkindi

# Build OpenSSL with PQC support
./scripts/build_openssl.sh

# Install Alkindi
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

---

## Quick Start

### Key Encapsulation (ML-KEM)

ML-KEM enables two parties to establish a shared secret over an insecure channel. The sender encapsulates a secret into a ciphertext using the receiver's public key, and the receiver decapsulates it to recover the same secret.

```python
from alkindi import KEM

# Generate a keypair for the receiver
keypair = KEM.generate_keypair("ML-KEM-768")

# Sender: encapsulate a shared secret
ciphertext, shared_secret_sender = KEM.encapsulate("ML-KEM-768", keypair.public_key)

# Receiver: decapsulate to recover the shared secret
shared_secret_receiver = KEM.decapsulate("ML-KEM-768", keypair.private_key, ciphertext)

# Both parties now share the same secret
assert shared_secret_sender == shared_secret_receiver
```

---

### Digital Signatures (ML-DSA)

ML-DSA provides digital signatures for authentication and message integrity. A signer uses their private key to sign messages, and verifiers use the corresponding public key to confirm authenticity.

```python
from alkindi import Signature

# Generate a keypair for the signer
keypair = Signature.generate_keypair("ML-DSA-65")

# Sign a message
message = b"Hello, quantum world!"
signature = Signature.sign("ML-DSA-65", keypair.private_key, message)

# Verify the signature
is_valid = Signature.verify("ML-DSA-65", keypair.public_key, message, signature)
print(f"Signature valid: {is_valid}")  # True

# Tampering detection
is_valid = Signature.verify("ML-DSA-65", keypair.public_key, b"Tampered message", signature)
print(f"Tampered signature valid: {is_valid}")  # False
```

---

## Documentation

### Algorithm Selection Guide

Choosing the right algorithm and parameter set depends on your security requirements, performance constraints, and use case. For detailed guidance on selecting appropriate algorithms, see the [Algorithm Selection Guide](docs/algorithm-selection-guide.md).

### NIST Standards

- [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/205/final)

### Additional Resources

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## Contributing

Contributions are welcome! Please review our [Contributing Guidelines](docs/CONTRIBUTING.md) before submitting pull requests or opening issues.

---

## License

Licensed under the **Apache License 2.0**. See [`LICENSE`](LICENSE) for complete terms.

---

## Acknowledgments

Alkindi stands on the shoulders of giants. I would like to thank the following organizations and teams for their foundational work:

- **National Institute of Standards and Technology (NIST)**: for standardizing post-quantum cryptography
- **OpenSSL Project**: for providing the cryptographic foundation
- **Algorithm Development Teams:**
  - Kyber developers
  - Dilithium developers
  - SPHINCS+ developers
- **Open Quantum Safe (OQS)**: for their pioneering work in making post-quantum cryptography practical and for fostering a welcoming community

My sincere gratitude also extends to the broader open-source community, whose collaborative spirit and tireless contributions make projects like this possible.
