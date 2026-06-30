from pathlib import Path

from setuptools import setup

setup(
    name="openreadpkg",
    version=open("VERSION").read().strip(),
    long_description=Path("README.md").read_text() if Path("README.md").is_file() else "",
)
