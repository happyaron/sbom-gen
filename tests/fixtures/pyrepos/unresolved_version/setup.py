import os

from setuptools import setup

# Both pulled from env with no default and no version file anywhere — neither
# name nor version can be resolved statically.
setup(
    name="unresolvedverpkg",
    version=os.environ["UNRESOLVED_PKG_VERSION"],
)
