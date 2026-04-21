### Algorithm Selection Guide

This section is a high-level orientation for choosing among the NIST PQC algorithms
that Alkindi exposes. It explains what each family is for, how the parameter sets differ,
and the main trade-offs.

It is background material only. It does not override your own security policy, threat
model, or compliance requirements.

---

### 1. Algorithm families by purpose

At a high level you will typically need:

| Goal                                                                                   | Algorithm family  |
|----------------------------------------------------------------------------------------|-------------------|
| Establish a shared secret key over an untrusted network                                | ML-KEM            |
| Create and verify digital signatures on data (code, documents, messages, certificates) | ML-DSA or SLH-DSA |

- Use **ML-KEM** to derive symmetric keys (for example, for AES or ChaCha20-Poly1305).
- Use **ML-DSA** or **SLH-DSA** for signatures (for example, for code signing, document signing, or certificate chains).

---

### 2. ML-KEM parameter sets (key establishment)

ML-KEM defines three parameter sets that trade off security level against bandwidth, memory,
and CPU cost.

- `ML-KEM-512`
    - NIST security category: 1
    - Approximate classical security: about 128 bits

- `ML-KEM-768`
    - NIST security category: 3
    - Approximate classical security: about 192 bits

- `ML-KEM-1024`
    - NIST security category: 5
    - Approximate classical security: about 256 bits

NIST recommends using `ML-KEM-768` as the default parameter set, as it provides a large
security margin at a reasonable performance cost. In cases where this is impractical or
even higher security is required, other parameter sets may be used.

Very roughly:

- Choose `ML-KEM-512` if you are constrained by bandwidth or storage and a category 1 level
  of security is acceptable.
- Choose `ML-KEM-768` as a general purpose default for new designs.
- Choose `ML-KEM-1024` if your threat model or policy calls for the highest standardized
  security level and you can afford the larger key and ciphertext sizes.

---

### 3. Signature families: ML-DSA vs SLH-DSA

Both ML-DSA and SLH-DSA are standardized post-quantum digital signature schemes. They differ
in internal design, assumptions, and performance.

#### ML-DSA (FIPS 204)

- Based on module lattice assumptions.
- Provides several parameter sets with different security levels.
- Typically offers smaller signatures and faster signing and verification than SLH-DSA
  at comparable security levels.
- Good fit for most general purpose applications that are comfortable with lattice-based
  assumptions.

#### SLH-DSA (FIPS 205)

- Stateless hash-based scheme derived from SPHINCS+.
- Security relies only on the properties of cryptographic hash functions.
- Signatures are larger and operations are typically slower than ML-DSA at comparable
  security levels.
- Attractive when you want very conservative assumptions that reduce to the security of
  standard hash functions, or when your policy specifically prefers hash-based signatures.

A common pattern is:

- Start with **ML-DSA** unless you have a specific requirement that favors hash-based
  signatures.
- Consider **SLH-DSA** when hash-only assumptions or long-term robustness against new
  algebraic attacks are more important than signature size and speed.

---

### 4. ML-DSA parameter sets (lattice-based signatures)

ML-DSA defines three parameter sets. They increase in security level, key size, and
signature size.

- `ML-DSA-44`
    - NIST security category: 2
    - Approximate classical security: about 128 bits

- `ML-DSA-65`
    - NIST security category: 3
    - Approximate classical security: about 192 bits

- `ML-DSA-87`
    - NIST security category: 5
    - Approximate classical security: about 256 bits

Very roughly:

- `ML-DSA-44`: smallest sizes in the family, suitable when a category 2 level of security
  meets your requirements.
- `ML-DSA-65`: natural default for many applications that want a higher security margin.
- `ML-DSA-87`: highest security level, at the cost of larger keys and signatures and
  higher computational cost.

---

### 5. SLH-DSA variants (hash-based signatures)

SLH-DSA variants are named along three axes:

1. Security level: `128`, `192`, `256`
2. Hash family: `SHA2` vs `SHAKE`
3. Size vs speed: `s` ("small") vs `f` ("fast")

You will see names like:

- `SLH-DSA-SHA2-128s`
- `SLH-DSA-SHAKE-192f`
- `SLH-DSA-SHA2-256f`

Interpretation:

- **Security level**
    - `128`, `192`, `256` roughly correspond to NIST categories 1, 3, and 5.
    - Higher numbers mean higher security and increased costs.

- **Hash family: SHA2 vs SHAKE**
    - `SHA2` variants use SHA-2 style hash functions.
    - `SHAKE` variants use SHAKE (Keccak-based extendable-output functions).
    - The choice often follows your existing hash policies, available implementations,
      and ecosystem constraints.

- **Size vs speed: "s" vs "f"**
    - `s` ("small") variants optimize for smaller signatures and keys, at the cost of more
      computation per operation.
    - `f` ("fast") variants optimize for faster signing and verification, at the cost of
      larger signatures and higher bandwidth and storage usage.

In practice:

- Pick the security level that matches your key exchange and symmetric cipher choices.
- Pick the hash family that aligns with your existing standards and implementations.
- Choose `s` variants if bandwidth or storage is tight (smaller signatures, more computation) and `f` variants if CPU
  time is the main constraint (larger signatures, less computation). 