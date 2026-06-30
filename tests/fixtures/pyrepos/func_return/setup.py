import os

from setuptools import setup


def get_name():
    return "funcpkg"


def get_version():
    # Mirrors MindIE-LLM: a local var assigned from os.getenv with a default.
    version = os.getenv("FUNC_PKG_VERSION_OVERRIDE", "7.0.0")
    return version


setup(
    name=get_name(),
    version=get_version(),
)
