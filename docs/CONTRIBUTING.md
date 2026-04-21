# Contributing to Alkindi

Thanks for your interest in contributing!

> **Legal Notice**: By contributing, you agree that you have authored 100% of the content, have the necessary rights,
> and that your contribution may be provided under the Apache 2.0 license.

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

Be respectful and constructive in all interactions.

## Questions & Support

Before asking a question:

1. Read the [README](../README.md) and [ARCHITECTURE](ARCHITECTURE.md) documentation
2. Search existing [Issues](../../issues) for similar questions

If you still need help, open an [Issue](../../issues/new) with your Python version, OS, and a minimal code example.

## Reporting Bugs

> **Security Issues**: Never report security vulnerabilities through public issues. See [SECURITY.md](../SECURITY.md) for the disclosure process.

Before submitting:

- Confirm you are on the latest version
- Verify it is a bug and not a usage error
- Search [existing bug reports](../../issues?q=label%3Abug)

When filing an issue, include:

- OS, Python version, and alkindi version (`python -c "import alkindi; print(alkindi.__version__)"`)
- Full traceback
- Minimal code to reproduce

## Suggesting Enhancements

Open a [GitHub Issue](../../issues/new) with a clear description of the proposed functionality, the problem it solves,
and why it would be useful. Note any relation to FIPS 203/204/205 if applicable.

## Development Setup

**1. Fork and Clone**
```bash
git clone https://github.com/alraddady/alkindi.git
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
- Add tests for all new functionality
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

**Linting:**

```bash
ruff check src/   # Check for issues
ruff format src/  # Auto-format
```

### Testing Requirements

All contributions must include tests:

1. **Correctness**: Basic functionality (`tests/correctness/`)
2. **Security**: Security property tests (`tests/security/`)
3. **Validation**: Standards compliance and NIST ACVP test vectors (`tests/validation/`) *(NIST ACVP planned)*

Requirements: all tests must pass, new features need >90% coverage, include both positive and negative cases.

### Commit Messages

- Start with a verb in the present tense: `Add`, `Fix`, `Update`, `Remove`
- Keep the first line under 72 characters
- Reference issues when applicable: `Closes #123`

## Pull Request Process

1. Ensure all tests pass
2. Update documentation for any user-facing changes
3. I'll review and merge once everything looks good

---

**Thank you for contributing to Alkindi!**
