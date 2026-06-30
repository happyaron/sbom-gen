import os

from setuptools import setup

# Mirrors pyasc: the wheel name ('colocatedwheel') differs from the co-located
# CMake project name (project(ColocatedNative)); the wheel identity must win.
DEFAULT_VERSION = "1.1.1"

setup(
    name=os.environ.get("COLOCATED_PKG_NAME", "colocatedwheel"),
    version=DEFAULT_VERSION,
)
