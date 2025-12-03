# Contributing to Alkindi

Thanks for your interest in contributing! This guide will help you get started.

> **Legal Notice**: By contributing, you agree that you have authored 100% of the content, have the necessary rights, and that your contribution may be provided under the Apache 2.0 license.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Questions & Support](#questions--support)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Style Guidelines](#style-guidelines)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

Be respectful, professional, and constructive in all interactions. We're building secure cryptographic software together.

## Questions & Support

Before asking a question:
1. Read the [README](../README.md) and [ARCHITECTURE](ARCHITECTURE.md) documentation
2. Search existing [Issues](../../issues) for similar questions
3. Search the internet for answers

If you still need help:
- Open an [Issue](../../issues/new) with context about your problem
- Include environment details: Python version, OS, OpenSSL version
- Provide relevant code examples

## Reporting Bugs

### Before Submitting

- Use the latest version
- Verify it's a bug and not a usage error (check [documentation](../README.md))
- Search [existing bug reports](../../issues?q=label%3Abug)
- Collect information:
  - Full traceback
  - Environment: OS, Python version, OpenSSL version (`./openssl-build/install/bin/openssl version`)
  - Minimal code to reproduce
  - Reproducibility with different versions

### Submitting Bug Reports

> **Security Issues**: Never report security vulnerabilities publicly. Email maintainers directly.

Create an [Issue](../../issues/new) with:

**Example Bug Report:**
```markdown
**Environment**
- Python 3.11 | macOS 14.0 | OpenSSL 3.5.0

**Code to Reproduce**
```python
from alkindi import KEM
keypair = KEM.generate_keypair('ML-KEM-1024')
```

**Expected**: Valid keypair generation
**Actual**: OpenSSLError: Failed to create key context

**Traceback**
[Full error traceback]
```

The team will label, reproduce, and prioritize accordingly.

## Suggesting Enhancements

### Before Submitting

- Use the latest version
- Check if the feature already exists in [documentation](../README.md)
- Search [existing suggestions](../../issues)
- Ensure it fits the project scope (useful for most users, not a niche use case)

### Creating Enhancement Requests

Use a [GitHub Issue](../../issues/new) with:
- **Clear title** identifying the enhancement
- **Detailed description** of the proposed functionality
- **Current vs. expected behavior**
- **Why it's useful** to most Alkindi users
- **Relation to PQC standards** (FIPS 203/204/205) if applicable

## Development Setup

**1. Fork and Clone**
```bash
git clone https://github.com/yourusername/alkindi.git
cd alkindi
```

**2. Build OpenSSL**
```bash
./scripts/build_openssl.sh
```

**3. Setup Environment**
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

**4. Verify Installation**
```bash
pytest tests/correctness/ -v
```

## Making Changes

**1. Create Branch**
```bash
git checkout -b feature/your-feature-name
```

**2. Develop**
- Follow [Style Guidelines](#style-guidelines)
- Add tests (correctness, property-based, fuzzing)
- Ensure code quality: `ruff check src/`

**3. Test**
```bash
pytest                    # Run all tests
pytest --cov=src/alkindi  # With coverage
```

**4. Commit & Push**
```bash
git add .
git commit -m "Add feature: brief description"
git push origin feature/your-feature-name
```

**5. Open Pull Request**

## Style Guidelines

### Code Style

- **PEP 8** compliant
- **Line length**: 100 characters max
- **Type hints**: Required for all function signatures
- **Docstrings**: Google style with Args, Returns, Raises

**Example:**
```python
def generate_keypair(algorithm: str) -> KeyPair:
    """
    Generate a keypair for the specified algorithm.

    Args:
        algorithm: ML-KEM algorithm name (e.g., 'ML-KEM-1024')

    Returns:
        KeyPair containing public and private keys as bytes

    Raises:
        AlkindiAPIError: If algorithm is not supported
        OpenSSLError: If key generation fails
    """
    ...
```

**Linting:**
```bash
ruff check src/   # Check for issues
ruff format src/  # Auto-format
```

### Testing Requirements

All contributions must include tests:

1. **Correctness**: Basic functionality (`tests/correctness/`)
2. **Property-Based**: Hypothesis tests for invariants (`tests/property/`)
3. **Fuzzing**: Robustness tests (`tests/fuzzing/`)
4. **NIST**: Only when adding new algorithms (`tests/NIST/`)

**Requirements**:
- All tests must pass
- New features need >90% coverage
- Include positive and negative test cases

**Test Structure:**
```python
@pytest.mark.parametrize("algorithm", sorted(SUPPORTED_KEM_ALGORITHMS))
def test_feature(algorithm):
    """Test description."""
    # Arrange
    keypair = KEM.generate_keypair(algorithm)

    # Act
    result = perform_operation(keypair)

    # Assert
    assert expected_condition(result)
```

### Commit Messages

**Format:**
- Start with verb in present tense
- First line <72 characters
- Reference issues when applicable

**Good Examples:**
```
Add support for ML-KEM-512 parameter validation
Fix memory leak in signature verification
Update README with installation instructions
```

**Bad Examples:**
```
Fixed stuff
Update
WIP
```

**Larger Changes (include body):**
```
Add property-based tests for ML-DSA

Implement Hypothesis-based tests to verify mathematical invariants
of ML-DSA signature operations including determinism, correctness,
and size consistency across all parameter sets.

Closes #123
```

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. Follow the PR template
4. Address review comments
5. Wait for maintainer approval
6. PR will be merged once approved

### Documentation Improvements

Documentation contributions are welcome:
- Fix typos or clarify existing docs
- Add examples to README
- Improve API documentation (docstrings)
- Add guides or tutorials

**Key Files:**
- `README.md`: User-facing docs and quick start
- `ARCHITECTURE.md`: Internal architecture and design
- `tests/README.md`: Testing methodology
- Source code docstrings: API documentation

## Becoming a Maintainer

Interested in joining the team? We look for contributors who:
- Have made several quality contributions
- Understand post-quantum cryptography concepts
- Are familiar with the codebase
- Can commit time to reviewing PRs and addressing issues

Reach out via GitHub Discussions or email (see repository).

---

**Thank you for contributing to Alkindi and helping advance post-quantum cryptography in Python!**