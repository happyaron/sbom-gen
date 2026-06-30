"""Unit tests for sbom.collectors.py_metadata — the static metadata resolver.

Two layers:
  • table-driven coverage of every supported name/version pattern against the
    synthetic mini-packages in tests/fixtures/pyrepos/ (literal, module const,
    os.getenv-default, ``X or "lit"`` fallback, single-return helper, file reads,
    no-default → dir-basename + warning, pyproject [project], pyproject dynamic
    attr/file, setup.cfg);
  • targeted in-memory AST cases for the chained-strip/replace and scm-fallback
    helper shapes;
  • a smoke pass over the REAL sibling repos (pyasc/mindspore/MindIE-LLM/shmem/
    pypto), skipped when absent, so the resolver stays general — not pyasc-shaped.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sbom.collectors.py_metadata import PkgMetadata, resolve_package_metadata

FIXTURES = Path(__file__).parent / "fixtures" / "pyrepos"
CANN = Path("/home/aron/testing/cann")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure env vars the fixtures reference are unset (defaults must win)."""
    for var in (
        "MS_PACKAGE_NAME",
        "UNRESOLVED_PKG_VERSION",
        "GETENV_PKG_NAME",
        "GETENV_PKG_VERSION",
        "OR_PKG_NAME",
        "OR_PKG_VERSION",
        "FUNC_PKG_VERSION_OVERRIDE",
        "COLOCATED_PKG_NAME",
    ):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# Table-driven: every pattern resolves to the expected name+version+source.
# ---------------------------------------------------------------------------

# (fixture dir, name, name_source, version, version_source)
CASES = [
    ("literal", "literalpkg", "setup_py:literal", "3.2.1", "setup_py:literal"),
    ("module_const", "constpkg", "setup_py:module_const", "1.4.0", "setup_py:module_const"),
    ("getenv_default", "getenvpkg", "setup_py:os.getenv_default", "2.0.0", "setup_py:os.getenv_default"),
    ("or_fallback", "orpkg", "setup_py:or_fallback", "5.5.5", "setup_py:or_fallback"),
    ("func_return", "funcpkg", "setup_py:function_return", "7.0.0", "setup_py:function_return"),
    ("read_version_file", "readfilepkg", "setup_py:literal", "4.5.6", "setup_py:version_file"),
    ("open_read", "openreadpkg", "setup_py:literal", "8.1.0", "setup_py:version_file"),
    ("setup_cfg", "cfgpkg", "setup_cfg", "2.2.2", "setup_cfg"),
    ("pyproject_static", "pep621pkg", "pyproject_project", "0.2.1", "pyproject_project"),
    ("pyproject_dynamic_attr", "dynamicattrpkg", "pyproject_project", "6.7.8", "pyproject_dynamic:attr"),
    ("pyproject_dynamic_file", "dynamicfilepkg", "pyproject_project", "3.1.4", "pyproject_dynamic:file"),
]


@pytest.mark.parametrize("fixture,name,name_src,version,ver_src", CASES)
def test_resolver_patterns(fixture, name, name_src, version, ver_src):
    meta = resolve_package_metadata(FIXTURES / fixture)
    assert isinstance(meta, PkgMetadata)
    assert meta.name == name
    assert meta.name_source == name_src
    assert meta.version == version
    assert meta.version_source == ver_src
    assert meta.warnings == []


# ---------------------------------------------------------------------------
# Honesty: unresolved name → dir basename + warning; unresolved version → None.
# ---------------------------------------------------------------------------


def test_no_default_name_falls_back_to_dir_basename():
    meta = resolve_package_metadata(FIXTURES / "no_default_name")
    # name unresolved (os.getenv with NO default) → directory basename.
    assert meta.name == "no_default_name"
    assert meta.name_source == "dir_basename"
    codes = [w.code for w in meta.warnings]
    assert "subject_name_unresolved" in codes
    # version is a literal, so it still resolves and is NOT warned about.
    assert meta.version == "2.10.0"
    assert "subject_version_unresolved" not in codes


def test_unresolved_version_is_none_with_warning():
    meta = resolve_package_metadata(FIXTURES / "unresolved_version")
    assert meta.name == "unresolvedverpkg"
    assert meta.version is None
    codes = [w.code for w in meta.warnings]
    assert "subject_version_unresolved" in codes
    assert "subject_name_unresolved" not in codes


def test_env_override_does_not_change_static_default(monkeypatch):
    # The resolver never executes code, so a set env var must NOT leak into the
    # resolved value — the static default literal is what we report.
    monkeypatch.setenv("GETENV_PKG_VERSION", "999.0.0")
    monkeypatch.setenv("GETENV_PKG_NAME", "leaked")
    meta = resolve_package_metadata(FIXTURES / "getenv_default")
    assert meta.version == "2.0.0"
    assert meta.name == "getenvpkg"


# ---------------------------------------------------------------------------
# Co-located fixture: the wheel name (≠ CMake project) resolves from setup.py.
# ---------------------------------------------------------------------------


def test_colocated_wheel_name_resolves_independent_of_cmake():
    meta = resolve_package_metadata(FIXTURES / "colocated_wheel_cmake")
    # name comes from os.getenv default; version from the module const.
    assert meta.name == "colocatedwheel"
    assert meta.version == "1.1.1"
    assert meta.warnings == []


# ---------------------------------------------------------------------------
# In-memory AST cases (chained transforms, scm/except-const fallback helper).
# ---------------------------------------------------------------------------


def _resolve_setup(tmp_path: Path, body: str, **extra_files: str) -> PkgMetadata:
    (tmp_path / "setup.py").write_text(body, encoding="utf-8")
    for rel, content in extra_files.items():
        (tmp_path / rel).write_text(content, encoding="utf-8")
    return resolve_package_metadata(tmp_path)


def test_chained_strip_and_replace(tmp_path):
    body = (
        "from setuptools import setup\n"
        "RAW = '  9.9.9\\n'\n"
        "setup(name='chainpkg', version=RAW.strip().replace('x', 'y'))\n"
    )
    meta = _resolve_setup(tmp_path, body)
    assert meta.name == "chainpkg"
    assert meta.version == "9.9.9"


def test_function_with_scm_then_const_fallback(tmp_path):
    # Mirrors pyasc get_project_version(): a build-only scm call that cannot be
    # statically resolved, plus a constant fallback in the except branch. The
    # static const must win (the scm return resolves to nothing).
    body = (
        "import setuptools_scm\n"
        "from setuptools import setup\n"
        "DEFAULT_VERSION = '1.1.1'\n"
        "def get_project_version():\n"
        "    try:\n"
        "        return setuptools_scm.get_version(root='.')\n"
        "    except Exception:\n"
        "        return DEFAULT_VERSION\n"
        "setup(name='scmpkg', version=get_project_version())\n"
    )
    meta = _resolve_setup(tmp_path, body)
    assert meta.name == "scmpkg"
    assert meta.version == "1.1.1"
    assert meta.version_source == "setup_py:function_return"


def test_path_read_text_version_file(tmp_path):
    body = (
        "from pathlib import Path\n"
        "from setuptools import setup\n"
        "setup(name='pathpkg', version=Path('version.txt').read_text().strip())\n"
    )
    meta = _resolve_setup(tmp_path, body, **{"version.txt": "0.9.1\n"})
    assert meta.version == "0.9.1"
    assert meta.version_source == "setup_py:version_file"


def test_attribute_setup_call(tmp_path):
    # ``setuptools.setup(...)`` (attribute form) is recognized too.
    body = (
        "import setuptools\n"
        "setuptools.setup(name='attrpkg', version='1.2.3')\n"
    )
    meta = _resolve_setup(tmp_path, body)
    assert meta.name == "attrpkg"
    assert meta.version == "1.2.3"


def test_dunder_version_fallback(tmp_path):
    # No name/version in setup(); version falls back to <pkg>/__init__ __version__.
    (tmp_path / "fallpkg").mkdir()
    (tmp_path / "fallpkg" / "__init__.py").write_text(
        "__version__ = '4.0.0'\n", encoding="utf-8"
    )
    body = "from setuptools import setup\nsetup(name='fallpkg')\n"
    meta = _resolve_setup(tmp_path, body)
    assert meta.name == "fallpkg"
    assert meta.version == "4.0.0"
    assert meta.version_source == "dunder_version"


def test_huge_version_file_is_ignored(tmp_path):
    # A version-file read that points at a giant blob is refused (returns None),
    # so we never embed megabytes as a "version".
    big = "x" * (200 * 1024)
    body = (
        "from setuptools import setup\n"
        "setup(name='bigpkg', version=open('VERSION').read().strip())\n"
    )
    meta = _resolve_setup(tmp_path, body, VERSION=big)
    assert meta.version is None
    assert any(w.code == "subject_version_unresolved" for w in meta.warnings)


# ---------------------------------------------------------------------------
# Real sibling repos: the resolver must generalize beyond the fixtures.
# ---------------------------------------------------------------------------

REAL_CASES = [
    # repo, expected name (or None ⇒ dir-basename fallback), expected version
    ("pyasc", "pyasc", "1.1.1"),
    ("mindspore", None, "2.10.0"),  # name unresolved (os.getenv no default)
    ("MindIE-LLM", "mindie_llm", "1.0.0"),
    ("shmem", "shmem", "1.0.0"),
    ("pypto", "pypto", "0.2.1"),
]


@pytest.mark.parametrize("repo,name,version", REAL_CASES)
def test_real_sibling_repos(repo, name, version):
    root = CANN / repo
    if not (root / "setup.py").is_file() and not (root / "pyproject.toml").is_file():
        pytest.skip(f"{repo} not present")
    meta = resolve_package_metadata(root)
    if name is None:
        # mindspore: name cannot be resolved statically → basename + warning.
        assert meta.name == root.name
        assert any(w.code == "subject_name_unresolved" for w in meta.warnings)
    else:
        assert meta.name == name
    assert meta.version == version


# ---------------------------------------------------------------------------
# Review round-2 regressions: version-file confinement (M3) + scm subdir tag (M4)
# ---------------------------------------------------------------------------


def test_version_file_directive_confined_to_pkg_root(tmp_path):
    # A 'file:' directive that points outside the package (absolute or ../) must
    # NOT read an arbitrary host file into the emitted version (M3).
    secret = tmp_path / "secret.txt"
    secret.write_text("99.99.99-pwned\n")
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "pyproject.toml").write_text(
        '[project]\nname = "pkg"\ndynamic = ["version"]\n'
        '[tool.setuptools.dynamic]\nversion = {file = ["../secret.txt"]}\n'
    )
    meta = resolve_package_metadata(pkg)
    assert meta.version != "99.99.99-pwned"  # the escape was rejected
    # an in-tree version file still resolves
    (pkg / "VERSION").write_text("1.2.3\n")
    assert resolve_package_metadata(pkg).version == "1.2.3"


def test_setuptools_scm_subdir_does_not_inherit_parent_tag(tmp_path):
    # A subdir package in a git tree must NOT report the PARENT repo's top-level
    # git tag as its own version (M4) -> stays unresolved.
    import subprocess

    repo = tmp_path / "repo"
    (repo / "subpkg").mkdir(parents=True)
    for args in (["init", "-q"], ["config", "user.email", "t@t"],
                 ["config", "user.name", "t"]):
        subprocess.run(["git", *args], cwd=repo, capture_output=True)
    (repo / "README").write_text("x")
    subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, capture_output=True)
    subprocess.run(["git", "tag", "v9.9.9"], cwd=repo, capture_output=True)
    # subpkg declares setuptools_scm but is NOT the git root
    (repo / "subpkg" / "pyproject.toml").write_text(
        '[project]\nname = "subpkg"\ndynamic = ["version"]\n'
        '[build-system]\nrequires = ["setuptools_scm"]\n'
    )
    meta = resolve_package_metadata(repo / "subpkg")
    assert meta.version != "9.9.9"  # did not inherit the parent's tag
