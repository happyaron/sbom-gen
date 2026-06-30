"""Unit tests for the pip/packaging-faithful Python collector.

Table-driven where practical, plus targeted assertions against the real
CANN/ops-math fixtures the task calls out.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from sbom.collectors import python as pc
from sbom.collectors import CollectResult
from sbom.models import (
    DeclarationReachability,
    Identity,
    RelationType,
    SourceKind,
    Subject,
    SubjectKind,
    SubjectRole,
    UsageScope,
)

OPS_MATH = Path("/home/aron/testing/cann/ops-math")


def _cfg(repo_root, **extra):
    return SimpleNamespace(repo_root=str(repo_root), scope="all",
                           collector_mode="static", exclude_scopes=[], **extra)


def _profile():
    return SimpleNamespace()


def _primary(repo_root, sid="ops_math"):
    return Subject(
        id=sid,
        identity=Identity(kind=SubjectKind.CANN_PACKAGE, name=sid),
        role=SubjectRole.PRIMARY,
        source_path=str(repo_root),
    )


def _run(tmp_path, files: dict[str, str], subjects=None):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    if subjects is None:
        subjects = [_primary(tmp_path)]
    return pc.collect(_cfg(tmp_path), _profile(), subjects)


def _comp(res: CollectResult, name: str):
    for c in res.components:
        if c.name == name or name in c.aliases:
            return c
    return None


def _scopes(res, name):
    c = _comp(res, name)
    return set() if c is None else {s.value for s in c.scopes}


# ---------------------------------------------------------------------------
# requirements.txt — basics & PEP 503 canonicalization
# ---------------------------------------------------------------------------


def test_editable_local_path_self_install_skipped(tmp_path):
    # '-e .' / '-e ./vendored' are local self/sibling installs, not external deps:
    # they must NOT register a phantom component (e.g. '.' -> '-') — review B7.
    res = _run(tmp_path, {"requirements.txt": "-e .\n-e ./vendored\nattrs==1.0\n"})
    names = {c.name for c in res.components}
    assert names == {"attrs"}
    assert "-" not in names and "." not in names and "vendored" not in names
    assert any(w.code == "python_local_path_install_skipped" for w in res.warnings)


def test_basic_requirements_runtime(tmp_path):
    res = _run(tmp_path, {"requirements.txt": "pyyaml\nsetuptools>=59.0.0\ndecorator\n"})
    assert _scopes(res, "pyyaml") == {"runtime"}
    assert _scopes(res, "decorator") == {"runtime"}
    comp = _comp(res, "setuptools")
    assert comp is not None
    obs = comp.observations[0]
    assert obs.source_kind is SourceKind.PYTHON_REQUIREMENT
    assert obs.version_constraint == ">=59.0.0"


@pytest.mark.parametrize(
    "raw,canon",
    [
        ("PyYAML", "pyyaml"),
        ("torch_npu", "torch-npu"),
        ("zope.interface", "zope-interface"),
        ("A.B-C_d", "a-b-c-d"),
    ],
)
def test_name_canonicalization(tmp_path, raw, canon):
    res = _run(tmp_path, {"requirements.txt": raw + "\n"})
    assert _comp(res, canon) is not None
    assert _comp(res, canon).name == canon


def test_completeness_unresolved_static(tmp_path):
    res = _run(tmp_path, {"requirements.txt": "numpy\n"})
    assert _comp(res, "numpy").completeness == {"python_transitives": "unresolved"}


# ---------------------------------------------------------------------------
# Concrete-version detection (static-mode pin policy)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("==24.2.0", "24.2.0"),
        ("===1.2", "1.2"),
        ("<2", None),
        ("==1.4.*", None),
        ("~=1.2", None),
        (">=3.20,<4.0", None),
        ("==1.0,!=1.0.1", None),
        (">=8.5", None),
        ("", None),
    ],
)
def test_concrete_version_helper(spec, expected):
    from packaging.specifiers import SpecifierSet

    assert pc.concrete_version(SpecifierSet(spec)) == expected


@pytest.mark.parametrize(
    "name,spec,expected",
    [
        # EXACT pins -> concrete version.
        ("attrs", "attrs==24.2.0", "24.2.0"),
        ("x", "x===1.2", "1.2"),
        # Ranges / wildcards / compatible-release / multi-clause / bare -> None.
        ("numpy", "numpy<2", None),
        ("foo", "foo==1.4.*", None),
        ("bar", "bar~=1.2", None),
        ("baz", "baz>=3.20,<4.0", None),
        ("qux", "qux==1.0,!=1.0.1", None),
        ("dep", "dep>=8.5", None),
        ("bare", "bare", None),
    ],
)
def test_concrete_version_sets_component_version(tmp_path, name, spec, expected):
    from packaging.requirements import Requirement

    res = _run(tmp_path, {"requirements.txt": spec + "\n"})
    comp = _comp(res, pc._canonical(name))
    assert comp is not None, [c.name for c in res.components]
    # An exact pin sets BOTH source and effective version; a range/bare leaves None.
    assert comp.source_version == expected
    assert comp.effective_version == expected
    # The full specifier is always recorded as the observation constraint.
    obs_spec = str(Requirement(spec).specifier) or None
    assert comp.observations[0].version_constraint == obs_spec


def test_bare_dep_with_extras_records_no_version(tmp_path):
    # A bare-with-extras dep: extras preserved, but no concrete version.
    res = _run(tmp_path, {"requirements.txt": "requests[socks]\n"})
    comp = _comp(res, "requests")
    assert comp.source_version is None and comp.effective_version is None
    assert comp.observations[0].version_constraint is None
    assert comp.observations[0].ecosystem_data["extras"] == ["socks"]


def test_concrete_version_in_setup_py_and_pyproject(tmp_path):
    setup = 'from setuptools import setup\nsetup(name="x", install_requires=["attrs==24.2.0", "numpy<2"])\n'
    res = _run(tmp_path, {"setup.py": setup})
    assert _comp(res, "attrs").effective_version == "24.2.0"
    assert _comp(res, "numpy").source_version is None

    pyproj = '[project]\nname="d"\ndependencies=["scipy==1.13.1", "click>=8"]\n'
    res2 = _run(tmp_path / "p", {"pyproject.toml": pyproj})
    assert _comp(res2, "scipy").effective_version == "1.13.1"
    assert _comp(res2, "click").source_version is None


def test_concrete_version_extras_and_markers_preserved(tmp_path):
    content = 'attrs[tests]==24.2.0 ; python_version >= "3.8"\n'
    res = _run(tmp_path, {"requirements.txt": content})
    comp = _comp(res, "attrs")
    assert comp.effective_version == "24.2.0"
    eco = comp.observations[0].ecosystem_data
    assert eco["extras"] == ["tests"]
    assert 'python_version >= "3.8"' in eco["marker"]


# ---------------------------------------------------------------------------
# -r recursion / -c constraints
# ---------------------------------------------------------------------------


def test_requirement_recursion(tmp_path):
    res = _run(
        tmp_path,
        {
            "requirements.txt": "-r base.txt\nattrs\n",
            "base.txt": "numpy\nscipy\n",
        },
    )
    for n in ("numpy", "scipy", "attrs"):
        assert _comp(res, n) is not None


def test_constraint_applied_not_emitted(tmp_path):
    res = _run(
        tmp_path,
        {
            "requirements.txt": "-c constraints.txt\nnumpy\n",
            "constraints.txt": "numpy==1.26.0\n",
        },
    )
    numpy = _comp(res, "numpy")
    assert numpy is not None
    # The constraint file itself must NOT spawn a second observation/component.
    assert len(numpy.observations) == 1
    assert numpy.observations[0].ecosystem_data.get("applied_constraint") == "==1.26.0"


def test_recursion_cycle_breaks(tmp_path):
    res = _run(
        tmp_path,
        {"requirements.txt": "-r other.txt\n", "other.txt": "-r requirements.txt\nnumpy\n"},
    )
    assert _comp(res, "numpy") is not None


# ---------------------------------------------------------------------------
# index options are file-level metadata, not packages
# ---------------------------------------------------------------------------


def test_index_options_not_packages(tmp_path):
    res = _run(
        tmp_path,
        {"requirements.txt": "--extra-index-url https://download.pytorch.org/whl/cpu\n\nbuild\nninja\n"},
    )
    names = {c.name for c in res.components}
    assert "build" in names and "ninja" in names
    assert not any("pytorch.org" in n for n in names)
    assert not any(n.startswith("--") or n.startswith("https") for n in names)
    # The index option is retained as file-level metadata on a requirement obs.
    build = _comp(res, "build")
    assert any(
        any("extra-index-url" in opt for opt in o.ecosystem_data.get("index_options", []))
        for o in build.observations
    )


# ---------------------------------------------------------------------------
# extras / markers / --hash
# ---------------------------------------------------------------------------


def test_extras_markers_hashes(tmp_path):
    content = (
        'requests[security,socks]>=2.0 ; python_version >= "3.8" '
        "--hash=sha256:abc123 --hash=sha256:def456\n"
    )
    res = _run(tmp_path, {"requirements.txt": content})
    comp = _comp(res, "requests")
    eco = comp.observations[0].ecosystem_data
    assert eco["extras"] == ["security", "socks"]
    assert 'python_version >= "3.8"' in eco["marker"]
    assert eco["hashes"] == ["sha256:abc123", "sha256:def456"]
    assert comp.observations[0].version_constraint == ">=2.0"


def test_comments_and_continuations(tmp_path):
    content = "# a comment line\nnumpy  # inline comment\nscipy \\\n  >=1.0\n"
    res = _run(tmp_path, {"requirements.txt": content})
    assert _comp(res, "numpy") is not None
    scipy = _comp(res, "scipy")
    assert scipy is not None
    assert scipy.observations[0].version_constraint == ">=1.0"


# ---------------------------------------------------------------------------
# -e / direct URL / VCS
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line,expect_name,expect_vcs",
    [
        ("-e git+https://github.com/pallets/flask.git#egg=flask", "flask", "git"),
        ("git+https://github.com/psf/requests.git@v2.0#egg=requests", "requests", "git"),
        ("mypkg @ https://example.com/mypkg-1.0.tar.gz", "mypkg", None),
        ("https://example.com/wheelhouse/foo-1.0-py3-none-any.whl", "foo-1.0-py3-none-any", None),
    ],
)
def test_direct_url_and_vcs(tmp_path, line, expect_name, expect_vcs):
    res = _run(tmp_path, {"requirements.txt": line + "\n"})
    comp = _comp(res, pc._canonical(expect_name))
    assert comp is not None, [c.name for c in res.components]
    obs = comp.observations[0]
    assert obs.resolved_url_or_path
    if expect_vcs:
        assert obs.ecosystem_data.get("vcs") == expect_vcs
    if line.startswith("-e"):
        assert obs.ecosystem_data.get("editable") is True


# ---------------------------------------------------------------------------
# setup.py — install_requires (AST) + build-scope import scanning
# ---------------------------------------------------------------------------


def test_setup_py_install_requires_and_cmdclass_imports(tmp_path):
    setup = '''
from setuptools import setup, Command
PACKAGE_NAME = "x"
class CMakeBuild(Command):
    def run(self):
        import torch
        import torch_npu
        subprocess.check_call(["cmake", "-S", "."])
setup(name=PACKAGE_NAME, version="1.0.0", install_requires=["torch", "numpy>=1.0"])
'''
    res = _run(tmp_path, {"setup.py": setup})
    # runtime from install_requires
    assert "runtime" in _scopes(res, "numpy")
    # torch present in BOTH runtime (install_requires) and build (cmdclass import)
    assert _scopes(res, "torch") == {"runtime", "build"}
    # torch_npu build-only (only imported in run())
    assert _scopes(res, "torch-npu") == {"build"}
    # cmake invocation -> build tool component
    assert "build" in _scopes(res, "cmake")
    # setuptools setup-time import -> build scope
    assert "build" in _scopes(res, "setuptools")


def test_setup_py_install_requires_constant_list(tmp_path):
    setup = '''
from setuptools import setup
DEPS = ["a", "b>=2"]
setup(name="x", version="1", install_requires=DEPS)
'''
    res = _run(tmp_path, {"setup.py": setup})
    assert _comp(res, "a") is not None
    assert _comp(res, "b").observations[0].version_constraint == ">=2"


def test_build_edge_relation_type(tmp_path):
    setup = '''
from setuptools import setup
class C:
    def run(self):
        subprocess.check_call(["ninja"])
setup(name="x", install_requires=[])
'''
    res = _run(tmp_path, {"setup.py": setup})
    build_edges = [e for e in res.edges if e.to_ref.id == "ninja"]
    assert build_edges
    assert all(e.relation_type is RelationType.BUILD_DEPENDENCY_OF for e in build_edges)
    assert all(e.usage_scope is UsageScope.BUILD for e in build_edges)


# ---------------------------------------------------------------------------
# pyproject.toml — [project].dependencies + [build-system].requires
# ---------------------------------------------------------------------------


def test_pyproject(tmp_path):
    content = """
[build-system]
requires = ["setuptools>=61", "wheel"]

[project]
name = "demo"
dependencies = ["numpy>=1.20", "click"]
"""
    res = _run(tmp_path, {"pyproject.toml": content})
    assert "runtime" in _scopes(res, "numpy")
    assert "runtime" in _scopes(res, "click")
    assert "build" in _scopes(res, "setuptools")
    assert "build" in _scopes(res, "wheel")
    setuptools = _comp(res, "setuptools")
    assert setuptools.observations[0].source_kind is SourceKind.PYTHON_BUILD


# ---------------------------------------------------------------------------
# scope assignment by path (default policy) + profile override hook
# ---------------------------------------------------------------------------


def test_file_scope_defaults_by_path(tmp_path):
    res = _run(
        tmp_path,
        {
            "requirements.txt": "runtime_pkg\n",
            "tests/requirements.txt": "test_pkg\n",
            "examples/foo/requirements.txt": "example_pkg\n",
        },
    )
    assert _scopes(res, "runtime_pkg") == {"runtime"}
    assert _scopes(res, "test_pkg") == {"test"}
    assert _scopes(res, "example_pkg") == {"example"}


def test_profile_scope_hook_overrides(tmp_path):
    prof = SimpleNamespace(python_file_scope=lambda p: UsageScope.EXPERIMENTAL)
    (tmp_path / "requirements.txt").write_text("pkg\n")
    res = pc.collect(_cfg(tmp_path), prof, [_primary(tmp_path)])
    assert _scopes(res, "pkg") == {"experimental"}


# ---------------------------------------------------------------------------
# Filename-derived usage scope: requirements-build/runtime/test.txt
# ---------------------------------------------------------------------------


def test_requirements_filename_scope_build_runtime_test(tmp_path):
    """requirements-build.txt -> BUILD, requirements-runtime.txt -> RUNTIME,
    requirements-test.txt -> TEST (the split-requirements layout)."""
    res = _run(
        tmp_path,
        {
            "requirements-build.txt": "build_pkg\n",
            "requirements-runtime.txt": "runtime_pkg\n",
            "requirements-test.txt": "test_pkg\n",
        },
    )
    assert _scopes(res, "build_pkg") == {"build"}
    assert _scopes(res, "runtime_pkg") == {"runtime"}
    assert _scopes(res, "test_pkg") == {"test"}


@pytest.mark.parametrize(
    "rel,expected",
    [
        ("requirements-build.txt", "build"),
        ("build-requirements.txt", "build"),
        ("requirements/build.txt", "build"),
        ("requirements-runtime.txt", "runtime"),
        ("requirements/runtime.txt", "runtime"),
        ("requirements.txt", "runtime"),  # bare, at repo root -> runtime
        ("requirements-test.txt", "test"),
        ("test-requirements.txt", "test"),
        ("requirements/test.txt", "test"),
    ],
)
def test_requirements_filename_scope_variants(tmp_path, rel, expected):
    res = _run(tmp_path, {rel: "pkg\n"})
    assert _scopes(res, "pkg") == {expected}, rel


def test_explicit_build_tag_beats_directory(tmp_path):
    """An explicit -build tag is authoritative even under an examples/ dir,
    but a bare requirements.txt still defers to the directory heuristic."""
    res = _run(
        tmp_path,
        {
            "examples/foo/requirements-build.txt": "tagged_build\n",
            "examples/foo/requirements.txt": "bare_example\n",
        },
    )
    assert _scopes(res, "tagged_build") == {"build"}
    assert _scopes(res, "bare_example") == {"example"}


# ---------------------------------------------------------------------------
# subject attribution & edges
# ---------------------------------------------------------------------------


def test_edges_attributed_to_owning_subject(tmp_path):
    primary = _primary(tmp_path, "ops_math")
    sibling = Subject(
        id="ascend_ops",
        identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="ascend_ops"),
        role=SubjectRole.SIBLING_ARTIFACT,
        source_path=str(tmp_path / "examples" / "fke"),
    )
    setup = 'from setuptools import setup\nsetup(name="ascend_ops", install_requires=["torch"])\n'
    res = _run(
        tmp_path,
        {"requirements.txt": "numpy\n", "examples/fke/setup.py": setup},
        subjects=[primary, sibling],
    )
    numpy_edges = [e for e in res.edges if e.to_ref.id == "numpy"]
    torch_edges = [e for e in res.edges if e.to_ref.id == "torch"]
    assert numpy_edges and all(e.root_artifact_id == "ops_math" for e in numpy_edges)
    assert torch_edges and all(e.root_artifact_id == "ascend_ops" for e in torch_edges)
    # observations carry root_artifact_id too
    torch = _comp(res, "torch")
    assert any(o.root_artifact_id == "ascend_ops" for o in torch.observations)


def test_invalid_requirement_warns(tmp_path):
    res = _run(tmp_path, {"requirements.txt": "==not a valid req==\n"})
    assert any(w.code == "python_requirement_invalid" for w in res.warnings)


# ---------------------------------------------------------------------------
# Real CANN/ops-math fixtures called out by the task
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not OPS_MATH.exists(), reason="ops-math tree not present")
def test_ops_math_real_tree():
    primary = _primary(OPS_MATH, "ops_math")
    res = pc.collect(_cfg(OPS_MATH), _profile(), [primary])
    names = {c.name for c in res.components}
    # runtime requirements.txt
    for n in ("pyyaml", "decorator", "sympy", "attrs"):
        assert n in names
    # multi-scope: appears in runtime AND tests/requirements.txt
    assert _scopes(res, "decorator") == {"runtime", "test"}
    assert _scopes(res, "attrs") == {"runtime", "test"}
    assert _scopes(res, "sympy") == {"runtime", "test"}
    # tests-only
    assert _scopes(res, "tensorflow") == {"test"}
    assert _comp(res, "tensorflow").observations[0].version_constraint == "==2.20.0"
    # torch carries {runtime, build, example}: scripts/torch_extension
    # install_requires (runtime sibling) + cmdclass import (build) + the
    # fast_kernel_launch_example wheel's install_requires (EXAMPLE-scoped, since an
    # example wheel's deps are not the distributable's runtime closure).
    assert _scopes(res, "torch") == {"runtime", "build", "example"}
    # torch-npu's only runtime source was the example wheel, so it is now
    # example/build-scoped (and correctly DROPPED from the release view).
    assert _scopes(res, "torch-npu") == {"build", "example"}
    # index option not a package
    assert not any("pytorch.org" in n for n in names)
    # no crash warnings on the real tree
    assert not any(w.code == "python_setup_unparsable" for w in res.warnings)


@pytest.mark.skipif(not OPS_MATH.exists(), reason="ops-math tree not present")
def test_torch_extension_setup_build_only_torch():
    """scripts/torch_extension/setup.py: CMakeBuild.run invokes cmake (no torch
    import), install_requires=["torch"] -> torch runtime; cmake build tool."""
    setup_path = OPS_MATH / "scripts" / "torch_extension"
    sib = Subject(
        id="npu_math_extension",
        identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="npu_math_extension"),
        role=SubjectRole.SIBLING_ARTIFACT,
        source_path=str(setup_path),
    )
    cfg = _cfg(setup_path)
    res = pc.collect(cfg, _profile(), [sib])
    assert "runtime" in _scopes(res, "torch")
    assert "build" in _scopes(res, "cmake")


def test_relative_source_path_attributes_to_repo_root(tmp_path, monkeypatch):
    """``source_path`` is relative to repo_root (empty == primary == repo_root).

    A deeper sibling (examples/scripts) must win over the primary by
    most-specific match, regardless of CWD. Deps declared in the sibling's
    setup.py/requirements carry the sibling root_artifact_id; only true
    root-level requirements carry the primary (ops_math).
    """
    # Resolve against repo_root, NOT cwd: run from an unrelated directory.
    monkeypatch.chdir(tmp_path / "..")

    primary = Subject(
        id="ops_math",
        identity=Identity(kind=SubjectKind.CANN_PACKAGE, name="ops_math"),
        role=SubjectRole.PRIMARY,
        source_path="",  # repo root itself
    )
    example_sib = Subject(
        id="ascend_ops",
        identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="ascend_ops"),
        role=SubjectRole.SIBLING_ARTIFACT,
        source_path="examples/fast_kernel_launch_example",  # relative to repo_root
    )
    script_sib = Subject(
        id="npu_math_extension",
        identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="npu_math_extension"),
        role=SubjectRole.SIBLING_ARTIFACT,
        source_path="scripts/torch_extension",
    )

    fke_setup = (
        'from setuptools import setup\n'
        'setup(name="ascend_ops", install_requires=["torch", "numpy"])\n'
    )
    ext_setup = (
        'from setuptools import setup\n'
        'setup(name="npu_math_extension", install_requires=["torch_npu"])\n'
    )
    res = _run(
        tmp_path,
        {
            "requirements.txt": "ninja\n",
            "examples/fast_kernel_launch_example/setup.py": fke_setup,
            "examples/fast_kernel_launch_example/requirements.txt": "numpy\n",
            "scripts/torch_extension/setup.py": ext_setup,
        },
        subjects=[primary, example_sib, script_sib],
    )

    def owners(name):
        return {e.root_artifact_id for e in res.edges if e.to_ref.id == name}

    # Only the true root-level requirement is attributed to the primary.
    assert owners("ninja") == {"ops_math"}
    # Sibling deps win by most-specific match, NOT the primary.
    assert owners("torch") == {"ascend_ops"}
    assert owners("numpy") == {"ascend_ops"}
    assert owners("torch-npu") == {"npu_math_extension"}
    assert "ops_math" not in owners("torch")
    assert "ops_math" not in owners("torch-npu")

    # Observations carry the sibling root_artifact_id too.
    torch = _comp(res, "torch")
    assert all(o.root_artifact_id == "ascend_ops" for o in torch.observations)
