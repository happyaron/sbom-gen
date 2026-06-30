"""Release-default view regression for the live ops-math + cmake trees.

The ``release`` scope is the DEFAULT view (``--scope release``): distributable
subjects plus their RUNTIME dependency closure only. This module runs the full
pipeline in-process against the REAL ``/home/aron/testing/cann/ops-math`` +
``/home/aron/testing/cann/cmake`` trees with NO scope flag (the default) and
asserts the release preset's net effect, plus that ``--scope all`` restores the
full view.

Release preset (the additive expansion verified here):
* excluded subject roles = {example, experimental, st_test, manual_example,
  non_distributable_test} → only distributable subjects survive;
* excluded usage scopes = ALL − {runtime} → only the runtime dependency closure
  survives (test deps, build tools, example/experimental/environment deps gone);
* no environment tools.

Skips cleanly when the live trees are absent. Name lookups resolve through the
CANN alias map + every component's recorded ``aliases`` (so ``OPBASE``/``opbase``
etc. still match).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sbom.cli import run
from sbom.config import Config
from sbom.models import UsageScope
from sbom.reconcile import build_alias_resolver
from sbom_profile_cann import CannProfile

CANN_ROOT = Path("/home/aron/testing/cann")
OPS_MATH = CANN_ROOT / "ops-math"
CMAKE_ROOT = CANN_ROOT / "cmake"
PYASC = CANN_ROOT / "pyasc"

requires_tree = pytest.mark.skipif(
    not OPS_MATH.is_dir() or not CMAKE_ROOT.is_dir(),
    reason="live CANN tree not present",
)

requires_pyasc = pytest.mark.skipif(
    not PYASC.is_dir(), reason="live pyasc tree not present"
)

pytestmark = requires_tree


# ---------------------------------------------------------------------------
# Build the release-default (no scope flag) and the full (--scope all) Documents
# once for the whole module; every assertion is read-only.
# ---------------------------------------------------------------------------


def _run(out_dir, scope=None):
    kw = {} if scope is None else {"scope": scope}
    config = Config(
        repo_root=OPS_MATH,
        repo_profile="cann",
        cmake_root=CMAKE_ROOT,
        collector_mode="static",
        formats=["cyclonedx", "spdx"],
        network="off",
        reproducible=True,
        out_dir=out_dir,
        **kw,
    )
    return run(config)


@pytest.fixture(scope="module")
def release_doc(tmp_path_factory):
    # NO scope flag → the release preset is the default.
    return _run(tmp_path_factory.mktemp("release_default"))


@pytest.fixture(scope="module")
def all_doc(tmp_path_factory):
    return _run(tmp_path_factory.mktemp("release_all"), scope="all")


@pytest.fixture(scope="module")
def resolver():
    return build_alias_resolver(CannProfile())


def _find(document, resolver, *spellings):
    wanted = {resolver.canonical(s) for s in spellings} | set(spellings)
    for comp in document.components:
        names = {comp.name, resolver.canonical(comp.name), *comp.aliases}
        names |= {resolver.canonical(a) for a in comp.aliases}
        if names & wanted:
            return comp
    return None


def _component_names(document, resolver):
    names: set[str] = set()
    for comp in document.components:
        names.add(comp.name)
        names.add(resolver.canonical(comp.name))
        for alias in comp.aliases:
            names.add(alias)
            names.add(resolver.canonical(alias))
    return names


# ---------------------------------------------------------------------------
# The release default IS the default (no scope flag selects it).
# ---------------------------------------------------------------------------


def test_default_scope_is_release():
    cfg = Config(repo_root=OPS_MATH)
    assert cfg.scope == "release"


# ---------------------------------------------------------------------------
# Distributable subjects only: example/experimental/ST/manual roots dropped.
# ---------------------------------------------------------------------------


def test_release_keeps_only_distributable_subjects(release_doc):
    # ascend_ops is built by examples/fast_kernel_launch_example -> a manual
    # example, NOT a distributable. The CANN profile classes that dir
    # MANUAL_EXAMPLE; the wheel now inherits that role instead of leaking as a
    # sibling_artifact, so only the genuinely distributable pair survives.
    subject_ids = {s.id for s in release_doc.subjects}
    assert subject_ids == {"ops_math", "npu_math_extension"}, (
        f"release view must keep only the distributable subjects; saw {subject_ids}"
    )


def test_release_drops_experimental_and_example_roots(release_doc, resolver):
    names = _component_names(release_doc, resolver)
    subject_ids = {s.id for s in release_doc.subjects}
    leaked = sorted(
        n
        for n in (names | subject_ids)
        if "example" in n.lower() or "bitwise" in n.lower()
    )
    assert not leaked, f"experimental/example roots leaked into release view: {leaked}"


# ---------------------------------------------------------------------------
# Runtime-only closure: test deps + pure build tools dropped, runtime kept.
# ---------------------------------------------------------------------------


def test_release_drops_gtest(release_doc, resolver):
    assert _find(release_doc, resolver, "gtest", "googletest") is None, (
        "release view must drop the purely test-scoped gtest"
    )


@pytest.mark.parametrize("tool", ["makeself", "protoc", "cmake", "ninja"])
def test_release_drops_pure_build_tooling(release_doc, resolver, tool):
    assert _find(release_doc, resolver, tool) is None, (
        f"release view must drop the build-only tool {tool!r}"
    )


@pytest.mark.parametrize("dep", ["eigen", "protobuf", "json", "opbase"])
def test_release_keeps_runtime_deps(release_doc, resolver, dep):
    assert _find(release_doc, resolver, dep) is not None, (
        f"release view must keep the runtime dep {dep!r}"
    )


def test_release_keeps_multiscope_dep_via_runtime(release_doc, resolver):
    # torch carries {runtime, build}; the build observation is dropped but torch
    # survives via its runtime observation (owned by the sibling wheels).
    torch = _find(release_doc, resolver, "torch")
    assert torch is not None, "release view must keep torch (it has a runtime obs)"
    surviving = {o.usage_scope for o in torch.observations if o.usage_scope}
    assert surviving == {UsageScope.RUNTIME}, (
        f"torch must keep only its runtime observation; saw {surviving}"
    )


def test_release_every_surviving_observation_is_runtime(release_doc):
    """THE INVARIANT: under release, every surviving observation across every
    component carries usage_scope == RUNTIME — none None, none test/build/
    example/st_test/manual_example/experimental/environment. This is the
    keep-only-RUNTIME guarantee and the strongest catch for the leak class
    (unclassified usage_scope=None observations such as gtest_shared_build and
    the cann-cmake FetchContent fragments used to survive here)."""
    leaked = [
        (c.name, o.source_kind.value, None if o.usage_scope is None else o.usage_scope.value)
        for c in release_doc.components
        for o in c.observations
        if o.usage_scope is not UsageScope.RUNTIME
    ]
    assert not leaked, (
        "every surviving observation must be usage_scope=runtime; leaked: "
        f"{leaked}"
    )


def test_release_every_surviving_edge_is_runtime(release_doc):
    """The edge counterpart: no surviving dependency edge may carry a
    non-runtime usage_scope (a None or test/build edge would be a leak)."""
    leaked = [
        (e.from_ref.id, e.to_ref.id, None if e.usage_scope is None else e.usage_scope.value)
        for e in release_doc.edges
        if e.usage_scope is not UsageScope.RUNTIME
    ]
    assert not leaked, f"non-runtime edges leaked into release view: {leaked}"


def test_release_component_scope_summaries_are_runtime_only(release_doc):
    """Each surviving component's recomputed scope summary is runtime-only."""
    bad = [
        (c.name, [s.value for s in c.scopes])
        for c in release_doc.components
        if any(s is not UsageScope.RUNTIME for s in c.scopes)
    ]
    assert not bad, f"components retained non-runtime scope summaries: {bad}"


def test_release_drops_the_specific_leak_class(release_doc, resolver):
    """Explicit roll-call of the adversarial-audit leaks (absent) and the
    runtime deps that must survive (present)."""
    for absent in ("gtest", "gtest_shared_build", "cann-cmake", "makeself", "protoc"):
        assert _find(release_doc, resolver, absent) is None, (
            f"release view must drop non-runtime component {absent!r}"
        )
    for present in ("eigen", "protobuf", "json", "opbase"):
        assert _find(release_doc, resolver, present) is not None, (
            f"release view must keep runtime dep {present!r}"
        )


# ---------------------------------------------------------------------------
# No environment tools in the release view.
# ---------------------------------------------------------------------------


def test_release_has_no_environment_tools(release_doc):
    assert release_doc.environment_tools == [], (
        "release view must omit every EnvironmentTool record"
    )


def test_release_emits_no_env_tool_markers(release_doc):
    from sbom.emit import EmitOptions
    from sbom.emit import cyclonedx as cdx_emit
    from sbom.emit import spdx as spdx_emit

    options = EmitOptions(reproducible=True, tool_version="test")
    cdx_text = cdx_emit.emit(release_doc, options)
    spdx_text = spdx_emit.emit(release_doc, options)
    assert "sbomgen:envtool" not in cdx_text
    assert "sbomgen:envtool" not in spdx_text


# ---------------------------------------------------------------------------
# Both validators pass on the release view; it is reproducible.
# ---------------------------------------------------------------------------


def test_release_sboms_pass_validators(release_doc):
    from sbom.emit import EmitOptions
    from sbom.emit import cyclonedx as cdx_emit
    from sbom.emit import spdx as spdx_emit
    from sbom.emit.validate import validate_cyclonedx, validate_spdx

    options = EmitOptions(reproducible=True, tool_version="test")

    cdx_text = cdx_emit.emit(release_doc, options)
    cdx_warnings = validate_cyclonedx(cdx_text)
    assert cdx_warnings == [], (
        "CycloneDX validation failed: "
        + repr([(w.code, w.detail) for w in cdx_warnings])
    )
    assert not any(
        w.code == "cyclonedx_validation_unavailable" for w in cdx_warnings
    )

    spdx_text = spdx_emit.emit(release_doc, options)
    spdx_warnings = validate_spdx(spdx_text)
    assert spdx_warnings == [], (
        "SPDX validation failed: "
        + repr([(w.code, w.detail) for w in spdx_warnings])
    )


def test_release_is_reproducible(tmp_path_factory):
    from sbom.emit import EmitOptions
    from sbom.emit import cyclonedx as cdx_emit
    from sbom.emit import spdx as spdx_emit

    a = _run(tmp_path_factory.mktemp("release_repro_a"))
    b = _run(tmp_path_factory.mktemp("release_repro_b"))
    options = EmitOptions(reproducible=True, tool_version="test")
    assert cdx_emit.emit(a, options) == cdx_emit.emit(b, options)
    assert spdx_emit.emit(a, options) == spdx_emit.emit(b, options)


# ---------------------------------------------------------------------------
# --scope all restores the full view (the escape hatch).
# ---------------------------------------------------------------------------


def test_scope_all_restores_full_view(all_doc, release_doc):
    # The full view is strictly larger on every axis.
    assert len(all_doc.subjects) == 11, (
        f"--scope all must restore all 11 subjects; saw {len(all_doc.subjects)}"
    )
    assert len(all_doc.components) > len(release_doc.components)
    assert len(all_doc.environment_tools) > 0, (
        "--scope all must restore the environment tools"
    )


def test_scope_all_restores_gtest(all_doc, resolver):
    assert _find(all_doc, resolver, "gtest", "googletest") is not None, (
        "--scope all must restore the test-scoped gtest"
    )


def test_scope_all_restores_experimental_roots(all_doc, resolver):
    subject_ids = {s.id for s in all_doc.subjects}
    names = _component_names(all_doc, resolver)
    found = sorted(
        n
        for n in (names | subject_ids)
        if "example" in n.lower() or "bitwise" in n.lower()
    )
    assert found, "--scope all must restore the experimental/example roots"


def test_scope_all_restores_build_tooling(all_doc, resolver):
    # At least one of the pure build tools the release view dropped is back.
    restored = [
        t for t in ("makeself", "protoc", "cmake", "ninja")
        if _find(all_doc, resolver, t) is not None
    ]
    assert restored, (
        "--scope all must restore build tooling dropped by the release view"
    )


def test_scope_all_restores_newly_scoped_leaks(all_doc, resolver):
    """The components the release filter drops because they are now correctly
    scoped non-runtime (gtest_shared_build -> test, cann-cmake -> build) must
    still be PRESENT in the full view — the fix re-scopes, it does not delete."""
    assert _find(all_doc, resolver, "gtest_shared_build") is not None, (
        "--scope all must restore the test-scoped gtest_shared_build"
    )
    assert _find(all_doc, resolver, "cann-cmake") is not None, (
        "--scope all must restore the build-scoped cann-cmake"
    )


# ---------------------------------------------------------------------------
# pyasc: a second real repo (LLVM/MLIR + split requirements) exercises the
# release filter end-to-end. The wheel is the primary; requirements-build.txt
# deps are BUILD (dropped); requirements-runtime.txt deps are RUNTIME (kept).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pyasc_release_doc(tmp_path_factory):
    config = Config(
        repo_root=PYASC,
        repo_profile="cann",
        collector_mode="static",
        formats=["cyclonedx", "spdx"],
        network="off",
        reproducible=True,
        out_dir=tmp_path_factory.mktemp("pyasc_release"),
        # NO scope flag -> release preset is the default.
    )
    return run(config)


@requires_pyasc
def test_pyasc_release_primary_and_runtime_deps(pyasc_release_doc, resolver):
    # Primary subject is the pyasc wheel 1.1.1.
    primary = pyasc_release_doc.subjects[0]
    assert primary.identity.name == "pyasc"
    assert primary.identity.version == "1.1.1"

    names = _component_names(pyasc_release_doc, resolver)
    # requirements-runtime.txt deps survive (RUNTIME).
    for dep in ("attrs", "scipy", "decorator", "psutil", "pyyaml", "importlib-metadata"):
        assert dep in names, f"pyasc release must keep runtime dep {dep!r}"


@requires_pyasc
def test_pyasc_release_drops_pure_build_tooling(pyasc_release_doc, resolver):
    # requirements-build.txt deps that are NOT also runtime install_requires are
    # BUILD-scoped and dropped: cmake/ninja/setuptools/setuptools-scm/wheel.
    names = _component_names(pyasc_release_doc, resolver)
    for tool in ("cmake", "ninja", "setuptools", "setuptools-scm", "wheel"):
        assert tool not in names, (
            f"pyasc release must drop the build-only tool {tool!r}"
        )


@requires_pyasc
def test_pyasc_release_every_observation_is_runtime(pyasc_release_doc):
    # THE INVARIANT on the second repo: no surviving observation is non-runtime
    # (this is what drops MLIR's would-be None find_package leak class and every
    # BUILD requirement).
    leaked = [
        (c.name, o.source_kind.value, None if o.usage_scope is None else o.usage_scope.value)
        for c in pyasc_release_doc.components
        for o in c.observations
        if o.usage_scope is not UsageScope.RUNTIME
    ]
    assert not leaked, f"pyasc release leaked non-runtime observations: {leaked}"


@requires_pyasc
def test_pyasc_release_no_env_tools(pyasc_release_doc):
    assert pyasc_release_doc.environment_tools == []


@requires_pyasc
def test_pyasc_release_sboms_valid(pyasc_release_doc):
    from sbom.emit import EmitOptions
    from sbom.emit import cyclonedx as cdx_emit
    from sbom.emit import spdx as spdx_emit
    from sbom.emit.validate import validate_cyclonedx, validate_spdx

    options = EmitOptions(reproducible=True, tool_version="test")
    assert validate_cyclonedx(cdx_emit.emit(pyasc_release_doc, options)) == []
    assert validate_spdx(spdx_emit.emit(pyasc_release_doc, options)) == []


# ---------------------------------------------------------------------------
# pyasc version handling: EXACT pins carry the version (and no unpinned marker);
# range/bare deps carry version=None + completeness['version']='unpinned'.
# requirements-runtime.txt: attrs/scipy/decorator/psutil/pytest/pytest-xdist are
# == pins; pyyaml/importlib-metadata are bare. requirements-build.txt:
# pybind11==2.13.1 (pin), numpy range, typing_extensions bare (BUILD-scoped, so
# the full --scope all view is needed to observe them).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pyasc_all_doc(tmp_path_factory):
    config = Config(
        repo_root=PYASC,
        repo_profile="cann",
        collector_mode="static",
        formats=["cyclonedx", "spdx"],
        network="off",
        reproducible=True,
        out_dir=tmp_path_factory.mktemp("pyasc_all"),
        scope="all",
    )
    return run(config)


def _by_name(document, resolver, name):
    canon = resolver.canonical(name)
    for comp in document.components:
        if name in {comp.name, *comp.aliases} or canon in {
            comp.name,
            resolver.canonical(comp.name),
        }:
            return comp
    return None


@requires_pyasc
@pytest.mark.parametrize(
    "name,version",
    [
        ("attrs", "24.2.0"),
        ("scipy", "1.13.1"),
        ("decorator", "5.1.1"),
        ("psutil", "6.0.0"),
        ("pytest", "8.3.2"),
        ("pytest-xdist", "3.6.1"),
    ],
)
def test_pyasc_runtime_exact_pins_carry_version(
    pyasc_release_doc, resolver, name, version
):
    comp = _by_name(pyasc_release_doc, resolver, name)
    assert comp is not None, f"{name} missing from release view"
    # An exact pin sets a concrete version and is NOT marked unpinned.
    assert (comp.effective_version or comp.source_version) == version
    assert comp.completeness.get("version") != "unpinned"


@requires_pyasc
@pytest.mark.parametrize("name", ["pyyaml", "importlib-metadata"])
def test_pyasc_runtime_bare_deps_unpinned(pyasc_release_doc, resolver, name):
    comp = _by_name(pyasc_release_doc, resolver, name)
    assert comp is not None, f"{name} missing from release view"
    assert comp.effective_version is None and comp.source_version is None
    assert comp.completeness.get("version") == "unpinned"


@requires_pyasc
def test_pyasc_build_pin_carries_version(pyasc_all_doc, resolver):
    # pybind11==2.13.1 from requirements-build.txt is an exact pin (BUILD scope,
    # so only visible under --scope all).
    pybind11 = _by_name(pyasc_all_doc, resolver, "pybind11")
    assert pybind11 is not None
    assert (pybind11.effective_version or pybind11.source_version) == "2.13.1"
    assert pybind11.completeness.get("version") != "unpinned"


@requires_pyasc
def test_pyasc_build_range_and_bare_unpinned(pyasc_all_doc, resolver):
    # numpy>=1.24.4,<=1.26.4 (range) and typing_extensions (bare) carry no
    # concrete version + the unpinned marker.
    numpy = _by_name(pyasc_all_doc, resolver, "numpy")
    assert numpy is not None
    assert numpy.effective_version is None and numpy.source_version is None
    assert numpy.completeness.get("version") == "unpinned"

    typing_ext = _by_name(pyasc_all_doc, resolver, "typing-extensions")
    assert typing_ext is not None
    assert typing_ext.effective_version is None
    assert typing_ext.completeness.get("version") == "unpinned"


@requires_pyasc
def test_pyasc_cyclonedx_purl_versionless_for_unpinned(pyasc_all_doc):
    import json

    from sbom.emit import EmitOptions
    from sbom.emit import cyclonedx as cdx_emit

    options = EmitOptions(reproducible=True, tool_version="test")
    bom = json.loads(cdx_emit.emit(pyasc_all_doc, options))
    by_name = {c["name"]: c for c in bom["components"]}
    # A concrete pin -> purl carries @version + component.version is set.
    attrs = by_name["attrs"]
    assert attrs.get("version") == "24.2.0"
    assert attrs["purl"] == "pkg:pypi/attrs@24.2.0"
    # An unpinned dep -> version omitted + a version-less purl.
    numpy = by_name["numpy"]
    assert "version" not in numpy
    assert numpy["purl"] == "pkg:pypi/numpy"
    props = {p["name"]: p["value"] for p in numpy.get("properties", [])}
    assert props.get("sbomgen:completeness:version") == "unpinned"


@requires_pyasc
def test_pyasc_spdx_versioninfo_omitted_for_unpinned(pyasc_all_doc):
    import json

    from sbom.emit import EmitOptions
    from sbom.emit import spdx as spdx_emit

    options = EmitOptions(reproducible=True, tool_version="test")
    spd = json.loads(spdx_emit.emit(pyasc_all_doc, options))
    pkgs = {p["name"]: p for p in spd["packages"]}
    # Concrete pin -> versionInfo present.
    assert pkgs["attrs"].get("versionInfo") == "24.2.0"
    # Unpinned -> versionInfo omitted (spdx-tools drops a None version).
    assert "versionInfo" not in pkgs["numpy"]


@requires_pyasc
def test_pyasc_all_sboms_valid(pyasc_all_doc):
    from sbom.emit import EmitOptions
    from sbom.emit import cyclonedx as cdx_emit
    from sbom.emit import spdx as spdx_emit
    from sbom.emit.validate import validate_cyclonedx, validate_spdx

    options = EmitOptions(reproducible=True, tool_version="test")
    assert validate_cyclonedx(cdx_emit.emit(pyasc_all_doc, options)) == []
    assert validate_spdx(spdx_emit.emit(pyasc_all_doc, options)) == []
