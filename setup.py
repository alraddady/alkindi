"""Setup script for alkindi project"""

from setuptools import setup
from setuptools.dist import Distribution


class BinaryDistribution(Distribution):
    """Force platform-specific wheels; required when using CFFI ffibuilder."""

    def has_ext_modules(self):
        return True


setup(
    cffi_modules=["src/alkindi/_internal/bindings.py:ffibuilder"],
    distclass=BinaryDistribution,
)
