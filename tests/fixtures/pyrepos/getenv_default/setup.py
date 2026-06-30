import os

from setuptools import setup

setup(
    name=os.environ.get("GETENV_PKG_NAME", "getenvpkg"),
    version=os.getenv("GETENV_PKG_VERSION", "2.0.0"),
)
