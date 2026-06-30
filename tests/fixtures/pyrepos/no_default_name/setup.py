import os

from setuptools import setup

# Mirrors mindspore: name comes from an env var with NO default, so it cannot be
# resolved statically and must fall back to the directory basename + warning.
package_name = os.getenv("MS_PACKAGE_NAME").replace("\n", "")

setup(
    name=package_name,
    version="2.10.0",
)
