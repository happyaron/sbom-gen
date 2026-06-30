import os

from setuptools import setup

# ``os.getenv(...)`` returns None when unset, so ``X or "lit"`` picks the literal.
setup(
    name=os.getenv("OR_PKG_NAME") or "orpkg",
    version=os.getenv("OR_PKG_VERSION") or "5.5.5",
)
