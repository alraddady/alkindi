"""Setup script for alkindi - Post-Quantum Cryptography Library.

This setup.py provides custom build logic for bundling OpenSSL libraries.
Project metadata is defined in pyproject.toml (PEP 517/518).

Build Process:
    1. CFFI compiles the C extension from src/alkindi/bindings.py
    2. Custom build_py command copies OpenSSL libraries to alkindi.libs/
    3. Wheel packages everything together
    4. At runtime, the extension finds OpenSSL via rpath (macOS/Linux) or PATH (Windows)

For wheel building:
    python -m build

For local development:
    pip install -e .
"""

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.dist import Distribution


class BinaryDistribution(Distribution):
    """Mark this distribution as containing platform-specific binary extensions.

    This ensures that setuptools creates platform-specific wheels rather than
    pure Python wheels.
    """

    def has_ext_modules(self):
        return True


class BuildPyWithLibs(build_py):
    """Custom build command that bundles OpenSSL libraries into the wheel.

    This command extends the standard build_py to copy OpenSSL shared libraries
    into an alkindi.libs directory that will be included in the wheel. The CFFI
    extension is configured (via rpath) to find these libraries at runtime.
    """

    def run(self):
        super().run()

        if not self.dry_run:
            openssl_lib_dir = Path("scripts/openssl-build/install/lib")

            if openssl_lib_dir.exists():
                libs_dir = Path(self.build_lib) / "alkindi.libs"
                libs_dir.mkdir(parents=True, exist_ok=True)

                lib_patterns = ["*.so*", "*.dylib", "*.dll"]
                copied_count = 0

                for pattern in lib_patterns:
                    for lib_file in openssl_lib_dir.glob(pattern):
                        if lib_file.is_file():
                            dest = libs_dir / lib_file.name
                            shutil.copy2(lib_file, dest)
                            print(f"Bundled OpenSSL library: {lib_file.name}")
                            copied_count += 1

                if copied_count > 0:
                    print(f"Successfully bundled {copied_count} OpenSSL libraries")
                else:
                    print("Warning: No OpenSSL libraries found to bundle")
            else:
                print(f"Warning: OpenSSL library directory not found: {openssl_lib_dir}")


setup(
    cffi_modules=["src/alkindi/bindings.py:ffibuilder"],

    cmdclass={
        "build_py": BuildPyWithLibs,
    },

    distclass=BinaryDistribution,
)
