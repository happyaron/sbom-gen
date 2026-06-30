"""Locked-in drift regression for the live ops-math + cmake trees.

This is the integration-tier *live drift* check from ``SBOM_DESIGN.md``
(§"Integration tier — ops-math drift fixture"). It runs the full pipeline
in-process against the REAL ``/home/aron/testing/cann/ops-math`` +
``/home/aron/testing/cann/cmake`` trees and asserts the expectations the audit
locked in, so they can never silently regress.

The test skips cleanly when the live trees are absent (e.g. a snapshot
checkout). Name lookups resolve through the CANN alias map + every component's
recorded ``aliases`` so a future spelling change (``torch_npu`` vs ``torch-npu``,
``OPBASE`` vs ``opbase``) does not break the assertions.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sbom.cli import run
from sbom.config import Config
from sbom.models import (
    DeclarationReachability,
    RefKind,
    SourceKind,
    UsageScope,
)
from sbom.reconcile import build_alias_resolver
from sbom_profile_cann import CannProfile

CANN_ROOT = Path("/home/aron/testing/cann")
OPS_MATH = CANN_ROOT / "ops-math"
CMAKE_ROOT = CANN_ROOT / "cmake"

requires_tree = pytest.mark.skipif(
    not OPS_MATH.is_dir() or not CMAKE_ROOT.is_dir(),
    reason="live CANN tree not present",
)

pytestmark = requires_tree


# ---------------------------------------------------------------------------
# Build the Document once for the whole module (the pipeline run is the slow
# part; every assertion is read-only).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def document(tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("drift_out")
    config = Config(
        repo_root=OPS_MATH,
        repo_profile="cann",
        cmake_root=CMAKE_ROOT,
        collector_mode="static",
        formats=["cyclonedx", "spdx"],
        network="off",
        reproducible=True,
        out_dir=out_dir,
        # Pin the FULL view: every assertion in this module (gtest's two axes,
        # environment tools, build deps, the experimental roots, subjects=11)
        # was written against the unfiltered output. The release preset (now the
        # default) is covered separately in tests/test_release_default.py.
        scope="all",
    )
    return run(config)


@pytest.fixture(scope="module")
def resolver():
    return build_alias_resolver(CannProfile())


# ---------------------------------------------------------------------------
# Robust name resolution: through the CANN alias map AND recorded aliases.
# ---------------------------------------------------------------------------


def _find_component(document, resolver, *spellings):
    """Return the component matching any of ``spellings`` (alias-aware)."""
    wanted = {resolver.canonical(s) for s in spellings} | set(spellings)
    for comp in document.components:
        names = {comp.name, resolver.canonical(comp.name), *comp.aliases}
        names |= {resolver.canonical(a) for a in comp.aliases}
        if names & wanted:
            return comp
    return None


def _component_names(document, resolver):
    """Every canonical name + alias every component is known by."""
    names: set[str] = set()
    for comp in document.components:
        names.add(comp.name)
        names.add(resolver.canonical(comp.name))
        for alias in comp.aliases:
            names.add(alias)
            names.add(resolver.canonical(alias))
    return names


def _edge_to_ids(document, resolver, owner_id):
    """Canonical ids of components ``owner_id`` depends on."""
    ids: set[str] = set()
    for edge in document.edges:
        if edge.from_ref.id == owner_id:
            ids.add(resolver.canonical(edge.to_ref.id))
    return ids


def _has_cann_package_obs(comp):
    return any(
        o.source_kind is SourceKind.CANN_PACKAGE for o in comp.observations
    )


def _has_find_package_obs(comp):
    return any(
        o.source_kind is SourceKind.CMAKE_FIND_PACKAGE for o in comp.observations
    )


# ---------------------------------------------------------------------------
# 1. version.cmake CANN package deps (all 9) + opbase constraint
# ---------------------------------------------------------------------------

VERSION_CMAKE_PACKAGES = [
    "runtime",
    "opbase",
    "metadef",
    "ge-compiler",
    "bisheng-compiler",
    "asc-devkit",
    "ge-executor",
    "asc-tools",
    "ops-legacy",
]


@pytest.mark.parametrize("pkg", VERSION_CMAKE_PACKAGES)
def test_version_cmake_package_present(document, resolver, pkg):
    comp = _find_component(document, resolver, pkg)
    assert comp is not None, f"version.cmake package {pkg!r} missing"
    assert _has_cann_package_obs(comp), (
        f"{pkg!r} present but carries no cann_package observation"
    )


def test_opbase_carries_version_constraint(document, resolver):
    opbase = _find_component(document, resolver, "opbase", "OPBASE")
    assert opbase is not None
    constraints = {
        o.version_constraint
        for o in opbase.observations
        if o.source_kind is SourceKind.CANN_PACKAGE
    }
    assert ">=8.5" in constraints, (
        f"opbase missing '>=8.5' version_constraint; saw {constraints}"
    )


def test_cann_package_deps_carry_unpinned_marker(document, resolver):
    # A CANN package dep declared only with a '>=8.5' constraint is NOT a
    # concrete pin -> it carries no source/effective version and the version axis
    # is marked unpinned.
    for pkg in ("opbase", "metadef", "ge-compiler", "bisheng-compiler"):
        comp = _find_component(document, resolver, pkg)
        assert comp is not None, f"{pkg} missing"
        assert comp.source_version is None and comp.effective_version is None, (
            f"{pkg} unexpectedly has a concrete version"
        )
        assert comp.completeness.get("version") == "unpinned", (
            f"{pkg} missing the unpinned version marker; "
            f"completeness={comp.completeness}"
        )


def test_concrete_version_components_not_marked_unpinned(document, resolver):
    # eigen (curated 5.0.0) and protobuf (cmake/curated 25.1 -> 3.13.0) carry a
    # concrete version, so they are NEVER marked unpinned.
    for pkg in ("eigen", "protobuf"):
        comp = _find_component(document, resolver, pkg)
        assert comp is not None, f"{pkg} missing"
        assert (comp.effective_version or comp.source_version) is not None
        assert comp.completeness.get("version") != "unpinned", (
            f"{pkg} wrongly marked unpinned despite a concrete version"
        )


# ---------------------------------------------------------------------------
# 2. find_package deps incl conditional ones + requiredness
# ---------------------------------------------------------------------------

FIND_PACKAGE_DEPS = ["platform", "aicpu", "ASC", "GenerateEsPackage"]


@pytest.mark.parametrize("dep", FIND_PACKAGE_DEPS)
def test_find_package_dep_present(document, resolver, dep):
    comp = _find_component(document, resolver, dep)
    assert comp is not None, f"find_package dep {dep!r} missing"
    assert _has_find_package_obs(comp), (
        f"{dep!r} present but carries no cmake_find_package observation"
    )


def test_securec_find_package_not_required(document, resolver):
    securec = _find_component(document, resolver, "securec", "c_sec")
    assert securec is not None
    fp_required = [
        o.find_package.required
        for o in securec.observations
        if o.source_kind is SourceKind.CMAKE_FIND_PACKAGE and o.find_package
    ]
    assert fp_required, "securec has no find_package observation"
    assert all(req is False for req in fp_required), (
        f"securec find_package should be non-REQUIRED; saw {fp_required}"
    )


def test_a_required_find_package_is_required(document, resolver):
    # opbase's find_package(OPBASE ... REQUIRED) is the locked-in REQUIRED one.
    opbase = _find_component(document, resolver, "opbase", "OPBASE")
    assert opbase is not None
    fp_required = [
        o.find_package.required
        for o in opbase.observations
        if o.source_kind is SourceKind.CMAKE_FIND_PACKAGE and o.find_package
    ]
    assert any(req is True for req in fp_required), (
        f"expected a REQUIRED find_package on opbase; saw {fp_required}"
    )


_UNEXPANDED_VAR_RE = re.compile(r"\$\{[^}]*\}")


def test_no_unexpanded_cmake_variable_components(document, resolver):
    """No component name may carry an unexpanded CMake variable reference.

    ``find_package(${ARGN})`` (and ``target_link_libraries(... ${ARGN})``) inside
    cann-cmake's wrapper macros once leaked a component literally named
    ``${ARGN}`` into the --scope all SBOM. The link/program classifiers now drop
    any ``${...}`` token and the collector guards component names, so the full
    view must contain no such artifact while legit deps survive.
    """
    leaked = [c.name for c in document.components if _UNEXPANDED_VAR_RE.search(c.name)]
    assert not leaked, f"unexpanded CMake variable leaked as component(s): {leaked}"

    names = {c.name for c in document.components}
    assert "${ARGN}" not in names

    # Legit third-party deps are unaffected by the filter.
    for dep in ("eigen", "protobuf", "json"):
        assert _find_component(document, resolver, dep) is not None, (
            f"legit dependency {dep!r} missing after ${{...}} filter"
        )


# ---------------------------------------------------------------------------
# 3. gtest two-axis: reached + test + non-empty activation
# ---------------------------------------------------------------------------


def test_gtest_two_axis(document, resolver):
    gtest = _find_component(document, resolver, "gtest", "googletest")
    assert gtest is not None, "gtest component missing"
    # A single observation must carry ALL THREE facts together (the two axes are
    # never collapsed, and the gate must survive).
    match = [
        o
        for o in gtest.observations
        if o.declaration_reachability is DeclarationReachability.REACHED
        and o.usage_scope is UsageScope.TEST
        and o.activation_condition
    ]
    assert match, (
        "gtest must have an observation with reachability=reached, "
        "usage_scope=test AND a non-empty activation_condition; "
        f"observations: "
        + repr(
            [
                (
                    o.declaration_reachability.value,
                    o.usage_scope.value if o.usage_scope else None,
                    [a.expr for a in o.activation_condition],
                )
                for o in gtest.observations
            ]
        )
    )
    # The gate is the macro's TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD condition.
    exprs = " ".join(a.expr for o in match for a in o.activation_condition)
    assert "TOPLEVEL_PROJECT" in exprs, (
        f"gtest activation_condition lost its gate; saw {exprs!r}"
    )


# ---------------------------------------------------------------------------
# 4. No self-loop edges; edges de-duplicated
# ---------------------------------------------------------------------------


def test_no_self_loop_edges(document):
    loops = [
        edge
        for edge in document.edges
        if edge.from_ref.kind is edge.to_ref.kind
        and edge.from_ref.id == edge.to_ref.id
    ]
    assert not loops, f"found {len(loops)} self-loop edge(s): {loops[:3]}"


def test_edges_deduplicated(document):
    def identity(edge):
        return (
            edge.root_artifact_id,
            edge.from_ref.kind,
            edge.from_ref.id,
            edge.to_ref.kind,
            edge.to_ref.id,
            edge.relation_type,
            edge.usage_scope,
            edge.declaration_reachability,
            edge.source_file,
            edge.source_revision,
        )

    identities = [identity(e) for e in document.edges]
    assert len(identities) == len(set(identities)), (
        f"duplicate edges present: {len(identities)} total, "
        f"{len(set(identities))} unique"
    )


# ---------------------------------------------------------------------------
# 5. torch / torch_npu ownership (siblings, NOT ops_math)
# ---------------------------------------------------------------------------


def _canonical_torch(resolver):
    return resolver.canonical("torch")


def _canonical_torch_npu(resolver):
    return resolver.canonical("torch_npu")


def test_torch_owned_by_siblings_not_ops_math(document, resolver):
    torch_id = _canonical_torch(resolver)
    npu_id = _canonical_torch_npu(resolver)

    torch_owners = {
        edge.from_ref.id
        for edge in document.edges
        if resolver.canonical(edge.to_ref.id) in {torch_id, npu_id}
    }
    assert torch_owners, "no torch/torch_npu edges found at all"
    # Every torch/torch_npu edge belongs to a sibling subject, never ops_math.
    assert "ops_math" not in torch_owners, (
        f"ops_math must not own torch/torch_npu; owners={torch_owners}"
    )
    assert torch_owners <= {"ascend_ops", "npu_math_extension"}, (
        f"torch deps owned by unexpected roots: {torch_owners}"
    )


def test_torch_npu_canonicalized_single_component(document, resolver):
    # torch_npu (CMake link) and the wheel's torch-npu reconcile onto ONE
    # component, so there must be no raw, un-canonicalized torch_npu endpoint.
    npu_id = _canonical_torch_npu(resolver)
    raw = [
        edge
        for edge in document.edges
        if edge.to_ref.kind is RefKind.COMPONENT
        and edge.to_ref.id != npu_id
        and resolver.canonical(edge.to_ref.id) == npu_id
    ]
    assert not raw, (
        f"torch_npu edge endpoints not canonicalized to {npu_id!r}: "
        f"{[e.to_ref.id for e in raw]}"
    )


def test_ops_math_keeps_its_root_level_deps(document, resolver):
    # The root-level C++ deps stay attributed to ops_math (they are not lost to a
    # sibling root by the ownership split).
    ops_math_deps = _edge_to_ids(document, resolver, "ops_math")
    for dep in ("eigen", "protobuf", "json", "opbase"):
        assert resolver.canonical(dep) in ops_math_deps, (
            f"ops_math lost its root-level dep {dep!r}; "
            f"deps={sorted(ops_math_deps)}"
        )
    # ...but ops_math must NOT pick up the example/script torch deps.
    assert _canonical_torch(resolver) not in ops_math_deps
    assert _canonical_torch_npu(resolver) not in ops_math_deps


# ---------------------------------------------------------------------------
# 6. protobuf / abseil patched-build identity + opbase integrity
# ---------------------------------------------------------------------------


def test_protobuf_patched_identity(document, resolver):
    protobuf = _find_component(document, resolver, "protobuf")
    assert protobuf is not None
    assert protobuf.source_version == "25.1", (
        f"protobuf source_version={protobuf.source_version!r}, expected 25.1"
    )
    assert protobuf.effective_version == "3.13.0", (
        f"protobuf effective_version={protobuf.effective_version!r}, "
        "expected 3.13.0"
    )
    assert protobuf.patches, "protobuf must carry the version patch"
    patch_files = {p.file for p in protobuf.patches}
    assert any("version" in f.lower() for f in patch_files), (
        f"protobuf missing its version patch; saw {patch_files}"
    )


def test_abseil_carries_hide_symbols_patch(document, resolver):
    abseil = _find_component(document, resolver, "abseil-cpp", "abseil_build")
    assert abseil is not None, "abseil-cpp component missing"
    patch_files = {p.file for p in abseil.patches}
    assert "protobuf-hide_absl_symbols.patch" in patch_files, (
        f"abseil-cpp missing the hide-symbols patch; saw {patch_files}"
    )


def test_opbase_local_source_unverified(document, resolver):
    from sbom.models import IntegrityFinding

    opbase = _find_component(document, resolver, "opbase", "OPBASE")
    assert opbase is not None
    assert IntegrityFinding.LOCAL_SOURCE_UNVERIFIED in opbase.integrity_findings, (
        f"opbase missing local_source_unverified; "
        f"saw {[f.value for f in opbase.integrity_findings]}"
    )


# ---------------------------------------------------------------------------
# 7. environment tools vs components: ccache, protoc, no garbage
# ---------------------------------------------------------------------------


def test_ccache_is_environment_tool(document):
    tool_names = {t.name for t in document.environment_tools}
    assert "ccache" in tool_names, (
        f"ccache must be an EnvironmentTool; tools={sorted(tool_names)}"
    )
    # ...and never a component.
    comp_names = {c.name for c in document.components}
    assert "ccache" not in comp_names, "ccache must not be a component"


def test_protoc_is_protobuf_tooling_not_env_tool(document, resolver):
    tool_names = {t.name for t in document.environment_tools}
    assert "protoc" not in tool_names, (
        "protoc is domain tooling, not a generic env tool"
    )
    protoc = _find_component(document, resolver, "protoc")
    assert protoc is not None, "protoc must be present as protobuf tooling"
    # It is recorded through a program/imported-executable observation, i.e.
    # tooling, not an ordinary library dependency.
    tooling_kinds = {
        SourceKind.CMAKE_FIND_PROGRAM,
        SourceKind.CMAKE_IMPORTED_EXECUTABLE,
    }
    assert any(o.source_kind in tooling_kinds for o in protoc.observations), (
        "protoc must carry a find_program/imported_executable (tooling) "
        f"observation; saw {[o.source_kind.value for o in protoc.observations]}"
    )


GARBAGE_ENV_TOOLS = [
    "cmake_ar",
    "cmake_c_compiler",
    "arm_cxx_compiler",
    "ascend_python_executable",
    "protobuf_protoc_executable",
]


@pytest.mark.parametrize("name", GARBAGE_ENV_TOOLS)
def test_no_garbage_env_tools(document, name):
    tool_names = {t.name for t in document.environment_tools}
    assert name not in tool_names, (
        f"garbage env tool {name!r} leaked into environment_tools"
    )


# ---------------------------------------------------------------------------
# 8. Both emitted SBOMs pass their official validators (no degradation)
# ---------------------------------------------------------------------------


def test_emitted_sboms_pass_validators(document):
    from sbom.emit import EmitOptions
    from sbom.emit import cyclonedx as cdx_emit
    from sbom.emit import spdx as spdx_emit
    from sbom.emit.validate import validate_cyclonedx, validate_spdx

    options = EmitOptions(reproducible=True, tool_version="test")

    cdx_text = cdx_emit.emit(document, options)
    cdx_warnings = validate_cyclonedx(cdx_text)
    assert cdx_warnings == [], (
        "CycloneDX validation failed: "
        + repr([(w.code, w.detail) for w in cdx_warnings])
    )
    # The validation must NOT degrade to "unavailable" (jsonschema must be real).
    assert not any(
        w.code == "cyclonedx_validation_unavailable" for w in cdx_warnings
    )

    spdx_text = spdx_emit.emit(document, options)
    spdx_warnings = validate_spdx(spdx_text)
    assert spdx_warnings == [], (
        "SPDX validation failed: "
        + repr([(w.code, w.detail) for w in spdx_warnings])
    )


# ---------------------------------------------------------------------------
# 8b. Supply-chain provenance (Component.origin) on the real tree.
# ---------------------------------------------------------------------------

# CANN-internal libs + sibling packages -> first-party. bisheng-compiler is
# first-party too (CANN tool) even though closed-source / NOASSERTION-licensed.
_FIRST_PARTY = [
    "platform",
    "opbase",
    "metadef",
    "ge-compiler",
    "graph",
    "dlog",
    "bisheng-compiler",
]
# Fetched OSS (cann-3rd OBS mirror / cann-src-third-party) + a published Ascend
# wheel -> third-party. The mirrors share the 'cann' substring but are NOT the
# gitcode.com/cann/ org namespace, so they must NOT be misread as first-party.
_THIRD_PARTY = ["eigen", "protobuf", "abseil-cpp", "gtest", "securec", "torch-npu"]


@pytest.mark.parametrize("name", _FIRST_PARTY)
def test_provenance_first_party_components(document, resolver, name):
    comp = _find_component(document, resolver, name)
    assert comp is not None and comp.origin == "first-party", name


@pytest.mark.parametrize("name", _THIRD_PARTY)
def test_provenance_third_party_components(document, resolver, name):
    comp = _find_component(document, resolver, name)
    assert comp is not None and comp.origin == "third-party", name


def test_cpp_component_purls(document, resolver):
    # Well-known OSS -> true upstream purl (registered host); first-party -> generic
    # + vcs_url to the CANN repo; system/no-locator -> none.
    def purl_of(*spellings):
        c = _find_component(document, resolver, *spellings)
        return c.purl if c else "MISSING"

    assert purl_of("protobuf") == "pkg:github/protocolbuffers/protobuf@3.13.0"
    assert purl_of("eigen") == "pkg:gitlab/libeigen/eigen@5.0.0"
    assert purl_of("gtest", "googletest").startswith("pkg:github/google/googletest@")
    # first-party CANN libs: pkg:generic with a vcs_url qualifier to gitcode.com/cann
    plat = _find_component(document, resolver, "platform")
    assert plat.purl.startswith("pkg:generic/platform?") and "vcs_url=" in plat.purl
    assert "gitcode.com" in plat.purl


def test_every_component_is_classified(document):
    # The classifier covers every component; nothing is left origin=None.
    unclassified = [c.name for c in document.components if c.origin is None]
    assert unclassified == [], unclassified
    assert {c.origin for c in document.components} <= {
        "first-party",
        "third-party",
        "unknown",
    }


def test_bisheng_first_party_but_license_not_asserted(document, resolver):
    # Closed-source first-party: provenance is first-party, but the license is NOT
    # the CANN Open License — it stays unasserted (NOASSERTION) and carries no
    # profile-default license marker.
    bisheng = _find_component(document, resolver, "bisheng-compiler")
    assert bisheng is not None and bisheng.origin == "first-party"
    assert bisheng.license in (None, "NOASSERTION")
    assert bisheng.completeness.get("license") != "profile-default"


# ---------------------------------------------------------------------------
# 9. Config-driven filters (usage-scope exclusion, --subjects closure,
#    --no-env-tools) — the regression lock for the filtering features.
#
# Each filtered Document is built by re-running the in-process pipeline with the
# relevant Config flags; the unfiltered ``document`` fixture above is the
# baseline these are diffed against.
# ---------------------------------------------------------------------------


def _run_filtered(out_dir, **overrides):
    # Base on the FULL view (scope="all") so each fixture exercises ONLY the
    # explicit filter it passes (exclude_scopes / subjects / no_env_tools),
    # diffed against the unfiltered `document` baseline. The release preset is
    # tested in tests/test_release_default.py.
    config = Config(
        repo_root=OPS_MATH,
        repo_profile="cann",
        cmake_root=CMAKE_ROOT,
        collector_mode="static",
        formats=["cyclonedx", "spdx"],
        network="off",
        reproducible=True,
        out_dir=out_dir,
        scope="all",
        **overrides,
    )
    return run(config)


@pytest.fixture(scope="module")
def doc_exclude_test(tmp_path_factory):
    return _run_filtered(
        tmp_path_factory.mktemp("drift_exclude_test"),
        exclude_scopes=["test"],
    )


@pytest.fixture(scope="module")
def doc_exclude_build(tmp_path_factory):
    return _run_filtered(
        tmp_path_factory.mktemp("drift_exclude_build"),
        exclude_scopes=["build"],
    )


@pytest.fixture(scope="module")
def doc_subjects_ops_math(tmp_path_factory):
    return _run_filtered(
        tmp_path_factory.mktemp("drift_subjects"),
        subjects=["ops_math"],
    )


@pytest.fixture(scope="module")
def doc_no_env_tools(tmp_path_factory):
    return _run_filtered(
        tmp_path_factory.mktemp("drift_no_env_tools"),
        no_env_tools=True,
    )


def test_exclude_scope_test_drops_gtest(document, doc_exclude_test, resolver):
    # gtest is purely test-scoped, so usage-scope exclusion removes the whole
    # component; the baseline must still have it (guards against a no-op filter).
    assert _find_component(document, resolver, "gtest", "googletest") is not None, (
        "baseline must contain gtest"
    )
    assert _find_component(doc_exclude_test, resolver, "gtest", "googletest") is None, (
        "--exclude-scope test must drop the purely test-scoped gtest component"
    )
    # The filter is real, not a wholesale wipe: a non-test component survives.
    assert _find_component(doc_exclude_test, resolver, "eigen") is not None, (
        "--exclude-scope test must not drop non-test components like eigen"
    )
    # No surviving observation may carry usage_scope=test.
    leaked = [
        (c.name, o.source_kind.value)
        for c in doc_exclude_test.components
        for o in c.observations
        if o.usage_scope is UsageScope.TEST
    ]
    assert not leaked, f"test-scoped observations leaked past the filter: {leaked}"


def test_exclude_scope_build_survives_torch(
    document, doc_exclude_build, resolver
):
    # torch carries BOTH runtime and build observations; excluding build must
    # keep torch (its runtime observation survives), only stripping build obs.
    base_torch = _find_component(document, resolver, "torch")
    assert base_torch is not None, "baseline must contain torch"
    base_scopes = {o.usage_scope for o in base_torch.observations}
    assert UsageScope.BUILD in base_scopes and UsageScope.RUNTIME in base_scopes, (
        f"baseline torch must have both build and runtime; saw {base_scopes}"
    )

    torch = _find_component(doc_exclude_build, resolver, "torch")
    assert torch is not None, (
        "--exclude-scope build must NOT drop torch (it has a runtime observation)"
    )
    surviving = {o.usage_scope for o in torch.observations}
    assert UsageScope.BUILD not in surviving, (
        f"torch must lose its build observation(s); saw {surviving}"
    )
    assert UsageScope.RUNTIME in surviving, (
        f"torch must keep its runtime observation; saw {surviving}"
    )

    # Runtime/test-only python deps survive untouched.
    for dep in ("decorator", "sympy", "attrs"):
        assert _find_component(doc_exclude_build, resolver, dep) is not None, (
            f"--exclude-scope build must not drop runtime/test dep {dep!r}"
        )

    # No surviving observation anywhere may carry usage_scope=build.
    leaked = [
        (c.name, o.source_kind.value)
        for c in doc_exclude_build.components
        for o in c.observations
        if o.usage_scope is UsageScope.BUILD
    ]
    assert not leaked, f"build-scoped observations leaked past the filter: {leaked}"


def test_subjects_ops_math_closure(document, doc_subjects_ops_math, resolver):
    # The subject set collapses to ops_math alone (was 11 in the baseline).
    assert len(document.subjects) > 1, "baseline must have multiple subjects"
    subject_ids = {s.id for s in doc_subjects_ops_math.subjects}
    assert subject_ids == {"ops_math"}, (
        f"--subjects ops_math must keep only ops_math; saw {subject_ids}"
    )

    names = _component_names(doc_subjects_ops_math, resolver)

    # Sibling roots, their wheels, and the experimental example roots are NOT in
    # ops_math's dependency closure.
    for absent in ("ascend_ops", "npu_math_extension"):
        assert absent not in names, (
            f"--subjects ops_math must exclude sibling root {absent!r}"
        )
    assert _canonical_torch(resolver) not in names, "torch must be absent"
    assert _canonical_torch_npu(resolver) not in names, "torch_npu must be absent"
    # The experimental/example roots (bitwise_not_examples & friends) are gone.
    leaked_examples = sorted(
        n for n in names if "example" in n.lower() or "bitwise" in n.lower()
    )
    assert not leaked_examples, (
        f"experimental/example roots leaked into the closure: {leaked_examples}"
    )

    # ops_math's own dependency closure IS retained.
    for present in ("eigen", "protobuf", "json", "opbase"):
        assert resolver.canonical(present) in names, (
            f"--subjects ops_math must keep ops_math dep {present!r}"
        )


def test_no_env_tools_clears_environment_tools(document, doc_no_env_tools):
    # The baseline carries environment tools; --no-env-tools clears them all
    # while leaving subjects/components/edges identical in count.
    assert document.environment_tools, "baseline must carry environment tools"
    assert doc_no_env_tools.environment_tools == [], (
        "--no-env-tools must clear every EnvironmentTool record"
    )
    assert len(doc_no_env_tools.subjects) == len(document.subjects)
    assert len(doc_no_env_tools.components) == len(document.components)
    assert len(doc_no_env_tools.edges) == len(document.edges)


def test_no_env_tools_emits_no_env_tool_markers(doc_no_env_tools):
    # The emitted SBOMs must carry zero env-tool properties/annotations.
    from sbom.emit import EmitOptions
    from sbom.emit import cyclonedx as cdx_emit
    from sbom.emit import spdx as spdx_emit

    options = EmitOptions(reproducible=True, tool_version="test")
    cdx_text = cdx_emit.emit(doc_no_env_tools, options)
    spdx_text = spdx_emit.emit(doc_no_env_tools, options)
    assert "sbomgen:envtool" not in cdx_text, (
        "--no-env-tools left sbomgen:envtool:* properties in CycloneDX"
    )
    assert "sbomgen:envtool" not in spdx_text, (
        "--no-env-tools left sbomgen:envtool:* annotations in SPDX"
    )
