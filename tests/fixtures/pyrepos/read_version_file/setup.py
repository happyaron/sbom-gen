import os

from setuptools import setup

pwd = os.path.dirname(os.path.realpath(__file__))


def _read_file(filename):
    with open(os.path.join(pwd, filename), encoding="UTF-8") as f:
        return f.read()


version = _read_file("version.txt").replace("\n", "")

setup(
    name="readfilepkg",
    version=version,
)
