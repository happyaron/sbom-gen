"""Unit tests for sbom.reconcile: alias de-dup, observation union, version
mismatch flags, typed-edge ownership, and the layered license resolver."""

from __future__ import annotations

import pytest

from sbom.collectors import CollectResult
from sbom.models import (
    Component,
    DependencyEdge,
    DeclarationReachability,
    Observation,
    Patch,
    Provenance,
    Ref,
    RefKind,
    RelationType,
    SourceKind,
    Subject,
    SubjectKind,
    SubjectRole,
    Identity,
    UsageScope,
)
from sbom.profile import GenericProfile, Profile
from sbom.reconcile import AliasResolver, build_alias_resolver, reconcile


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


class _CannishProfile(Profile):
    """A profile supplying the CANN-style alias map used in the design tests."""

    name = "cannish"

    def alias_map(self) -> dict[str, dict]:
        return {
            "OPBASE": {"canonical": "opbase", "relation": RelationType.LINK.value},
            "tilingapi": {
                "canonical": "tiling_api",
                "relation": RelationType.DEPENDS_ON.value,
            },
            "tiling_api": {
                "canonical": "tiling_api",
                "relation": RelationType.LINK.value,
            },
        }

    def dependency_license_default(self, component):  # CANN deps stay NOASSERTION
        return None


from pathlib import Path as _Path

#: The OSS known-license content moved out of the core (now empty) into profiles;
#: tests that exercise the known-map layer supply it via this fixture.
_KNOWN_FIXTURE = _Path(__file__).parent / "data" / "known_licenses_fixture.yaml"


def _known_licenses_sources():
    from sbom.data_sources import CURATED, DataSource

    return [DataSource("known-licenses", CURATED, _KNOWN_FIXTURE, "yaml")]


class _KnownProfile(Profile):
    """A profile that supplies the OSS known-license map (the content the core no
    longer ships), so known-map layer tests resolve as before."""

    name = "known"

    def data_sources(self):
        return _known_licenses_sources()


def _component(name, **kw):
    return Component(name=name, **kw)


def _obs(source_kind, name, scope=None, **eco):
    data = {"name": name, **eco}
    return Observation(source_kind=source_kind, usage_scope=scope, ecosystem_data=data)


def _subj(sid, name):
    return Subject(
        id=sid, identity=Identity(kind=SubjectKind.CANN_PACKAGE, name=name, version="9.0.0")
    )


def _run(components=None, observations=None, edges=None, profile=None, config=None):
    res = CollectResult(
        components=components or [],
        observations=observations or [],
        edges=edges or [],
    )
    return reconcile([res], [], config, profile or GenericProfile())


# ---------------------------------------------------------------------------
# AliasResolver / build_alias_resolver
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spelling,expected_canonical,expected_relation",
    [
        ("googletest", "gtest", None),
        ("GOOGLETEST", "gtest", None),
        ("makeself-fetch", "makeself", None),
        ("nlohmann-json", "json", None),
        ("unknown-thing", "unknown-thing", None),
    ],
)
def test_oss_aliases(spelling, expected_canonical, expected_relation):
    resolver = build_alias_resolver(GenericProfile())
    assert resolver.canonical(spelling) == expected_canonical
    assert resolver.relation(spelling) == expected_relation


def test_profile_alias_union_with_relation():
    resolver = build_alias_resolver(_CannishProfile())
    # OSS aliases survive alongside profile aliases.
    assert resolver.canonical("googletest") == "gtest"
    # Profile alias map: OPBASE -> opbase, tilingapi/tiling_api -> tiling_api.
    # Lookup is case-insensitive, so OPBASE also covers the lowercase spelling.
    assert resolver.canonical("OPBASE") == "opbase"
    assert resolver.canonical("opbase") == "opbase"
    assert resolver.relation("OPBASE") == RelationType.LINK.value
    assert resolver.canonical("tilingapi") == "tiling_api"
    assert resolver.canonical("tiling_api") == "tiling_api"
    # tiling_api overwrites tilingapi? No -- distinct lowercased keys, both kept.
    assert resolver.relation("tiling_api") == RelationType.LINK.value
    assert resolver.is_known("OPBASE")
    assert not resolver.is_known("c_sec")


# ---------------------------------------------------------------------------
# On-the-fly alias derivation + config [aliases] overrides
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://x/cann-src-third-party/eigen/releases/download/5.0.0/eigen-5.0.0.tar.gz", "eigen"),
        ("https://x/abseil-cpp-20230802.1.tar.gz", "abseil-cpp"),
        ("https://x/protobuf-25.1.tar.gz", "protobuf"),
        ("https://x/json-3.11.3.tar.gz", "json"),
        ("https://x/eigen-5.0.0.tgz", "eigen"),
        ("https://x/foo-v1.2.3.zip", "foo"),
        # Archive-tag URLs: the filename is a BARE version, so the repo name must
        # come from the path (owner/repo), not the version-shaped filename.
        ("https://github.com/madler/zlib/archive/refs/tags/v1.3.1.tar.gz", "zlib"),
        ("https://gitcode.com/openeuler/libboundscheck/repository/archive/v1.1.16.tar.gz", "libboundscheck"),
        # A noisy asset filename ('makeself-release-2.5.0-patch1') must reduce to
        # the repo name 'makeself', not 'makeself-release'.
        ("https://gitcode.com/x/makeself/releases/download/2.5.0/makeself-release-2.5.0-patch1.tar.gz", "makeself"),
        ("https://example.com/owner/repo.git", None),  # not an archive
        ("https://x/v1.3.1.tar.gz", None),  # bare version, no repo path -> unknown
        ("${CANN_3RD_LIB_PATH}/eigen-5.0.0.tar.gz", None),  # unexpanded template
        (None, None),
    ],
)
def test_upstream_from_url(url, expected):
    from sbom.reconcile import _upstream_from_url

    assert _upstream_from_url(url) == expected


def test_derivation_collision_preserves_both_and_warns():
    # Two DISTINCT libraries whose asset filenames both reduce to 'json' (flat
    # URLs, no disambiguating repo path) must NOT silently merge: both are
    # preserved under their own names and a warning fires.
    a = _ext_project("external_nlohmann", "https://h/pkg/json-3.11.3.tar.gz")
    b = _ext_project("external_jsoncpp", "https://h/pkg/json-1.9.5.tar.gz")
    doc = _run(components=[a, b])
    names = {c.name for c in doc.components}
    assert {"external_nlohmann", "external_jsoncpp"} <= names  # both kept
    assert "json" not in names  # neither was renamed onto the colliding name
    assert any(w.code == "derived_alias_collision" and w.subject == "json" for w in doc.warnings)


def test_derivation_does_not_rename_clean_fetchcontent_name():
    # A FetchContent target already named after the upstream ('makeself') whose
    # asset is 'makeself-release-...' must KEEP its name, not become 'makeself-release'.
    c = _ext_project(
        "makeself",
        "https://h/x/makeself/releases/download/2.5.0/makeself-release-2.5.0-patch1.tar.gz",
    )
    doc = _run(components=[c])
    names = {comp.name for comp in doc.components}
    assert "makeself" in names and "makeself-release" not in names


def _ext_project(name, url):
    """A component named after its CMake target, carrying its download URL."""
    c = Component(name=name)
    c.observations.append(
        Observation(
            source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
            usage_scope=UsageScope.RUNTIME,
            canonical_url=url,
            ecosystem_data={"name": name},
        )
    )
    return c


def test_derivation_folds_external_target_into_upstream():
    # external_eigen_nn's own download URL says 'eigen'; it must rename to eigen
    # and keep the target name as an alias — no hand-written map entry.
    c = _ext_project("external_eigen_nn", "https://x/eigen/download/5.0.0/eigen-5.0.0.tar.gz")
    doc = _run(components=[c])
    names = {comp.name for comp in doc.components}
    assert "eigen" in names and "external_eigen_nn" not in names
    eigen = next(comp for comp in doc.components if comp.name == "eigen")
    assert "external_eigen_nn" in eigen.aliases


def test_derived_name_resolved_through_curated_aliases():
    # tarball 'googletest-1.14.0.tar.gz' derives 'googletest', which OSS folds to
    # 'gtest' — the derived canonical is itself resolved through curated layers.
    c = _ext_project("gtest_build_x", "https://x/googletest-1.14.0.tar.gz")
    doc = _run(components=[c])
    names = {comp.name for comp in doc.components}
    assert "gtest" in names and "googletest" not in names


def test_config_alias_overrides_derivation():
    # An explicit [aliases] entry wins over the on-the-fly guess.
    c = _ext_project("external_eigen_nn", "https://x/eigen-5.0.0.tar.gz")
    doc = _run(components=[c], config=_cfg(aliases={"external_eigen_nn": "my-eigen"}))
    names = {comp.name for comp in doc.components}
    assert "my-eigen" in names and "eigen" not in names


def test_config_alias_resolves_link_token_and_suppresses_warning():
    # A bare link token with no download URL can't be derived; a config alias maps
    # it onto the eigen component, attaching the edge and clearing the warning.
    eigen = _ext_project("eigen", "https://x/eigen-5.0.0.tar.gz")
    link = Observation(
        source_kind=SourceKind.CMAKE_LINK_LIBRARY,
        usage_scope=UsageScope.RUNTIME,
        ecosystem_data={"name": "Eigen3::EigenNn"},
    )
    # Without the alias: the token is unmapped.
    bare = _run(components=[_ext_project("eigen", "https://x/eigen-5.0.0.tar.gz")],
                observations=[Observation(source_kind=SourceKind.CMAKE_LINK_LIBRARY,
                                          usage_scope=UsageScope.RUNTIME,
                                          ecosystem_data={"name": "Eigen3::EigenNn"})])
    assert any(w.code == "unmapped_link_library" for w in bare.warnings)
    # With the alias: resolved, no warning.
    doc = _run(components=[eigen], observations=[link],
               config=_cfg(aliases={"Eigen3::EigenNn": "eigen"}))
    assert not any(w.code == "unmapped_link_library" for w in doc.warnings)


# ---------------------------------------------------------------------------
# Multi-scope merge (decorator/sympy/attrs)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pkg", ["decorator", "sympy", "attrs"])
def test_multi_scope_runtime_test_merge(pkg):
    runtime = _component(pkg, scopes=[UsageScope.RUNTIME])
    runtime.observations.append(_obs(SourceKind.PYTHON_REQUIREMENT, pkg, UsageScope.RUNTIME))
    test = _component(pkg, scopes=[UsageScope.TEST])
    test.observations.append(_obs(SourceKind.PYTHON_REQUIREMENT, pkg, UsageScope.TEST))

    doc = _run(components=[runtime, test])
    assert len(doc.components) == 1
    comp = doc.components[0]
    assert comp.name == pkg
    assert set(comp.scopes) == {UsageScope.RUNTIME, UsageScope.TEST}
    assert len(comp.observations) == 2


# ---------------------------------------------------------------------------
# torch runtime + build merge -> one component, {runtime, build}
# ---------------------------------------------------------------------------


def test_torch_runtime_build_merge_one_component():
    runtime = _component("torch", scopes=[UsageScope.RUNTIME], languages=["python"])
    runtime.observations.append(_obs(SourceKind.PYTHON_SETUP, "torch", UsageScope.RUNTIME))
    build = _component("torch", scopes=[UsageScope.BUILD], languages=["python"])
    build.observations.append(_obs(SourceKind.PYTHON_BUILD, "torch", UsageScope.BUILD))

    doc = _run(components=[runtime, build])
    assert len(doc.components) == 1
    comp = doc.components[0]
    assert set(comp.scopes) == {UsageScope.RUNTIME, UsageScope.BUILD}
    assert comp.languages == ["python"]
    assert len(comp.observations) == 2


# ---------------------------------------------------------------------------
# protobuf patched: source 25.1 vs effective 3.13.0
# ---------------------------------------------------------------------------


def test_protobuf_patched_version_mismatch_flagged():
    comp = _component(
        "protobuf",
        source_version="25.1",
        effective_version="3.13.0",
        patches=[Patch(file="protobuf.patch", sha256="abc")],
    )
    doc = _run(components=[comp])
    out = doc.components[0]
    # Kept SEPARATE, not collapsed.
    assert out.source_version == "25.1"
    assert out.effective_version == "3.13.0"
    codes = [w.code for w in doc.warnings]
    assert "patched_build" in codes
    pb = next(w for w in doc.warnings if w.code == "patched_build")
    assert pb.subject == "protobuf"


def test_no_mismatch_when_versions_equal_or_missing():
    same = _component("a", source_version="1.0", effective_version="1.0")
    onlysrc = _component("b", source_version="2.0")
    doc = _run(components=[same, onlysrc])
    assert "patched_build" not in [w.code for w in doc.warnings]


# ---------------------------------------------------------------------------
# Unpinned version marker + concrete-pin propagation + pin-vs-range merge
# ---------------------------------------------------------------------------


def _pyobs(name, constraint, scope=UsageScope.RUNTIME):
    return Observation(
        source_kind=SourceKind.PYTHON_REQUIREMENT,
        usage_scope=scope,
        version_constraint=constraint,
        ecosystem_data={"name": name},
    )


def test_unpinned_marker_for_range_and_cann_constraint_deps():
    # A Python range dep (numpy<2) and a CANN package dep (>=8.5) carry no
    # concrete version -> completeness['version']='unpinned'.
    numpy = _component("numpy", languages=["Python"])
    numpy.observations.append(_pyobs("numpy", "<2"))
    opbase = _component("opbase")
    opbase.observations.append(
        Observation(
            source_kind=SourceKind.CANN_PACKAGE,
            usage_scope=UsageScope.BUILD,
            version_constraint=">=8.5",
            ecosystem_data={"name": "opbase"},
        )
    )
    doc = _run(components=[numpy, opbase])
    out = {c.name: c for c in doc.components}
    assert out["numpy"].completeness.get("version") == "unpinned"
    assert out["opbase"].completeness.get("version") == "unpinned"


def test_unpinned_marker_for_bare_dep():
    pyyaml = _component("pyyaml", languages=["Python"])
    pyyaml.observations.append(_pyobs("pyyaml", None))
    doc = _run(components=[pyyaml])
    assert doc.components[0].completeness.get("version") == "unpinned"


def test_unexpanded_variable_version_is_unresolved_not_literal():
    # A version captured as an unexpanded CMake template (cann-cmake's
    # ${CANN_VERSION_${component}_VERSION}) is not a real version: it must be
    # nulled and marked 'unresolved' (distinct from 'unpinned'), never emitted.
    dev = _component(
        "cann_device",
        source_version="${CANN_VERSION_${component}_VERSION}",
    )
    dev.observations.append(
        Observation(
            source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
            usage_scope=UsageScope.RUNTIME,
            version_constraint="${SOME_VAR}",
            ecosystem_data={"name": "cann_device"},
        )
    )
    doc = _run(components=[dev])
    out = doc.components[0]
    assert out.source_version is None and out.effective_version is None
    assert out.completeness.get("version") == "unresolved"
    # the garbage constraint is dropped too
    assert all(o.version_constraint is None for o in out.observations)


def test_cann_first_party_license_default_applied_end_to_end():
    # Through the full reconcile, a first-party CANN dep (opbase) gets the CANN
    # LicenseRef + a 'profile-default' completeness marker, while a third-party dep
    # (eigen) resolves to its real license from the known-license map, NOT CANN.
    from sbom_profile_cann import CannProfile

    opbase = _component("opbase")
    opbase.observations.append(
        Observation(
            source_kind=SourceKind.CANN_PACKAGE,
            usage_scope=UsageScope.RUNTIME,
            ecosystem_data={"name": "opbase"},
        )
    )
    eigen = _component("eigen")
    doc = _run(components=[opbase, eigen], profile=CannProfile())
    out = {c.name: c for c in doc.components}
    assert out["opbase"].license == "LicenseRef-CANN-Open-Software-License-2.0"
    assert out["opbase"].completeness.get("license") == "profile-default"
    assert "CANN" not in (out["eigen"].license or "")  # eigen -> known map, not CANN


def test_concrete_version_component_not_marked_unpinned():
    # eigen/protobuf with a concrete source/effective version are NEVER marked.
    eigen = _component("eigen", source_version="5.0.0", effective_version="5.0.0")
    protobuf = _component(
        "protobuf", source_version="25.1", effective_version="3.13.0"
    )
    attrs = _component("attrs", languages=["Python"], source_version="24.2.0",
                       effective_version="24.2.0")
    attrs.observations.append(_pyobs("attrs", "==24.2.0"))
    doc = _run(components=[eigen, protobuf, attrs])
    for comp in doc.components:
        assert "version" not in comp.completeness, comp.name


def test_pin_vs_range_merge_keeps_pin():
    # Two collectors observe the same dep: one ==1.4.0 pin, one >=1.0 range.
    pinned = _component("attrs", languages=["Python"], source_version="1.4.0",
                        effective_version="1.4.0")
    pinned.observations.append(_pyobs("attrs", "==1.4.0"))
    ranged = _component("attrs", languages=["Python"])
    ranged.observations.append(_pyobs("attrs", ">=1.0"))
    doc = _run(components=[pinned, ranged])
    out = doc.components[0]
    # The concrete pin wins; no conflict (the range is not a competing pin).
    assert out.source_version == "1.4.0"
    assert out.effective_version == "1.4.0"
    assert "version" not in out.completeness
    assert "version_pin_conflict" not in [w.code for w in doc.warnings]


def test_version_pin_conflict_keeps_lowest_and_warns():
    # Two DIFFERENT concrete pins for the same component: keep the lowest, warn.
    a = _component("attrs", languages=["Python"], source_version="2.0.0",
                   effective_version="2.0.0")
    a.observations.append(_pyobs("attrs", "==2.0.0"))
    b = _component("attrs", languages=["Python"], source_version="1.5.0",
                   effective_version="1.5.0")
    b.observations.append(_pyobs("attrs", "==1.5.0"))
    doc = _run(components=[a, b])
    out = doc.components[0]
    assert out.source_version == "1.5.0"   # deterministic lowest
    assert out.effective_version == "1.5.0"
    codes = [w.code for w in doc.warnings]
    assert "version_pin_conflict" in codes
    w = next(w for w in doc.warnings if w.code == "version_pin_conflict")
    assert w.subject == "attrs"
    assert "1.5.0" in w.detail and "2.0.0" in w.detail
    # A resolved pin is concrete -> never marked unpinned.
    assert "version" not in out.completeness


def test_scope_filter_prunes_stale_depends_on():
    # When the usage-scope filter drops a component, no survivor may keep a
    # depends_on pointing at it (dangling internal reference) — review minor.
    a = _component("a")
    a.observations.append(_attached_obs(SourceKind.CMAKE_LINK_LIBRARY, "a", UsageScope.RUNTIME))
    btest = _component("btest")
    btest.observations.append(_attached_obs(SourceKind.CMAKE_LINK_LIBRARY, "btest", UsageScope.TEST))
    edge = DependencyEdge(
        root_artifact_id="r",
        from_ref=Ref(kind=RefKind.COMPONENT, id="a"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="btest"),
        relation_type=RelationType.DEPENDS_ON,
    )
    doc = _run(components=[a, btest], edges=[edge], config=_cfg(exclude_scopes=["test"]))
    out = {c.name: c for c in doc.components}
    assert "btest" not in out  # dropped by the test-scope filter
    assert "btest" not in out["a"].depends_on  # pruned, not dangling


def test_version_pin_conflict_preserves_curated_patched_pair():
    # A curated patched-build pair (protobuf source 25.1 / effective 3.13.0) plus
    # two conflicting requirements pins must KEEP the curated versions (not be
    # clobbered to a pin, which would also silence patched_build) — review B5.
    base = _component("protobuf", source_version="25.1", effective_version="3.13.0")
    a = _component("protobuf", languages=["Python"])
    a.observations.append(_pyobs("protobuf", "==4.0.0"))
    b = _component("protobuf", languages=["Python"])
    b.observations.append(_pyobs("protobuf", "==5.0.0"))
    doc = _run(components=[base, a, b])
    out = doc.components[0]
    assert out.source_version == "25.1" and out.effective_version == "3.13.0"
    assert "version_pin_conflict" in [w.code for w in doc.warnings]


# ---------------------------------------------------------------------------
# OPBASE/opbase + tilingapi/tiling_api alias union
# ---------------------------------------------------------------------------


def test_cann_alias_union_opbase_and_tiling():
    # find_package(OPBASE) seen as link, package dep opbase, link tiling_api,
    # find_package(tilingapi) -> two canonical components: opbase + tiling_api.
    fp_opbase = _component("OPBASE")
    pkg_opbase = _component("opbase", scopes=[UsageScope.RUNTIME])
    link_tiling = _component("tiling_api")
    fp_tiling = _component("tilingapi")

    doc = _run(
        components=[fp_opbase, pkg_opbase, link_tiling, fp_tiling],
        profile=_CannishProfile(),
    )
    names = sorted(c.name for c in doc.components)
    assert names == ["opbase", "tiling_api"]
    opbase = next(c for c in doc.components if c.name == "opbase")
    assert "OPBASE" in opbase.aliases
    tiling = next(c for c in doc.components if c.name == "tiling_api")
    assert "tilingapi" in tiling.aliases


# ---------------------------------------------------------------------------
# Typed edge ownership: per-root preserved; subject->component NOT in depends_on
# ---------------------------------------------------------------------------


def test_typed_edge_ownership_and_depends_on_rollup():
    protobuf = _component("protobuf")
    abseil = _component("abseil-cpp")
    eigen = _component("eigen")

    # subject -> component: ops_math -> eigen (ownership on edge, NOT a rollup)
    e1 = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ops_math"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="eigen"),
        relation_type=RelationType.DEPENDS_ON,
    )
    # component -> component: protobuf -> abseil-cpp (contributes to depends_on)
    e2 = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.COMPONENT, id="protobuf"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="abseil-cpp"),
        relation_type=RelationType.DEPENDS_ON,
    )
    # subject -> component for a sibling root: ascend_ops -> torch
    e3 = DependencyEdge(
        root_artifact_id="ascend_ops",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ascend_ops"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="torch"),
        relation_type=RelationType.DEPENDS_ON,
    )

    doc = _run(
        components=[protobuf, abseil, eigen, _component("torch")],
        edges=[e1, e2, e3],
    )
    # Edge ownership preserved unchanged.
    assert {e.root_artifact_id for e in doc.edges} == {"ops_math", "ascend_ops"}
    # depends_on rollup only from component->component edge.
    pb = next(c for c in doc.components if c.name == "protobuf")
    assert pb.depends_on == ["abseil-cpp"]
    # eigen/torch (subjects of subject->component edges) are NOT rolled up.
    for comp in doc.components:
        if comp.name in ("eigen", "torch"):
            assert comp.depends_on == []


def test_edges_alias_normalized_endpoints_preserve_root():
    comp_opbase = _component("opbase")
    edge = DependencyEdge(
        root_artifact_id=" st-root ".strip(),
        from_ref=Ref(kind=RefKind.COMPONENT, id="OPBASE"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="tilingapi"),
        relation_type=RelationType.LINK,
    )
    doc = _run(components=[comp_opbase], edges=[edge], profile=_CannishProfile())
    out_edge = doc.edges[0]
    assert out_edge.from_ref.id == "opbase"
    assert out_edge.to_ref.id == "tiling_api"
    assert out_edge.root_artifact_id == "st-root"


# ---------------------------------------------------------------------------
# Observation attachment + unmapped_link_library
# ---------------------------------------------------------------------------


def test_unattached_observation_attaches_to_component():
    comp = _component("eigen")
    obs = _obs(SourceKind.CMAKE_EXTERNAL_PROJECT, "eigen", UsageScope.RUNTIME)
    doc = _run(components=[comp], observations=[obs])
    assert len(doc.components) == 1
    assert doc.components[0].observations == [obs]
    assert UsageScope.RUNTIME in doc.components[0].scopes


def test_unmapped_link_library_warns():
    obs = _obs(SourceKind.CMAKE_LINK_LIBRARY, "c_sec")
    doc = _run(components=[], observations=[obs], profile=_CannishProfile())
    codes = [w.code for w in doc.warnings]
    assert "unmapped_link_library" in codes
    w = next(w for w in doc.warnings if w.code == "unmapped_link_library")
    assert w.subject == "c_sec"
    # No spurious component materialized for the unmapped token.
    assert all(c.name != "c_sec" for c in doc.components)


def test_known_link_library_observation_attaches():
    # googletest is an OSS alias of canonical gtest -> attaches, no unmapped warning.
    comp = _component("googletest")
    obs = _obs(SourceKind.CMAKE_LINK_LIBRARY, "gtest", UsageScope.TEST)
    doc = _run(components=[comp], observations=[obs])
    assert "unmapped_link_library" not in [w.code for w in doc.warnings]
    assert doc.components[0].observations == [obs]


# ---------------------------------------------------------------------------
# SHARED NAMING CONVENTION: legacy ecosystem_data keys resolve (cluster-A drop)
# ---------------------------------------------------------------------------


def test_cann_package_observation_attaches_with_constraint():
    # version.cmake set_cann_* obs carry the name under 'cann_package', NOT 'name',
    # plus a >= version constraint. They must attach (not drop) and keep the
    # constraint on the observation, preserved onto the component.
    comp = _component("bisheng-compiler")
    obs = Observation(
        source_kind=SourceKind.CANN_PACKAGE,
        usage_scope=UsageScope.BUILD,
        version_constraint=">=8.5",
        ecosystem_data={"cann_package": "bisheng-compiler"},
    )
    doc = _run(components=[comp], observations=[obs])
    assert "unattached_observation" not in [w.code for w in doc.warnings]
    out = doc.components[0]
    assert out.name == "bisheng-compiler"
    assert out.observations == [obs]
    # version_constraint survives reconcile onto the component's observation.
    assert out.observations[0].version_constraint == ">=8.5"
    assert UsageScope.BUILD in out.scopes


def test_cann_package_observation_materializes_component_when_unseen():
    # A cann_package obs for an otherwise-unseen component (asc-tools, ops-legacy)
    # still attaches by materializing the component rather than dropping.
    obs = Observation(
        source_kind=SourceKind.CANN_PACKAGE,
        usage_scope=UsageScope.RUNTIME,
        version_constraint=">=8.5",
        ecosystem_data={"cann_package": "ops-legacy"},
    )
    doc = _run(components=[], observations=[obs])
    assert "unattached_observation" not in [w.code for w in doc.warnings]
    names = [c.name for c in doc.components]
    assert "ops-legacy" in names
    comp = next(c for c in doc.components if c.name == "ops-legacy")
    assert comp.observations[0].version_constraint == ">=8.5"


def test_find_package_observation_attaches_with_requiredness():
    from sbom.models import FindPackageInfo

    # find_package obs carry their name under 'name' (the producer convention) and
    # the requiredness on obs.find_package. Both must survive reconcile.
    comp = _component("aicpu")
    obs = Observation(
        source_kind=SourceKind.CMAKE_FIND_PACKAGE,
        find_package=FindPackageInfo(required=True, quiet=False),
        ecosystem_data={"name": "aicpu"},
    )
    doc = _run(components=[comp], observations=[obs])
    assert "unattached_observation" not in [w.code for w in doc.warnings]
    out = doc.components[0]
    assert out.observations == [obs]
    assert out.observations[0].find_package.required is True


def test_find_package_name_resolved_from_find_package_attribute():
    # Last-resort convention fallback: an obs with neither a name attr nor an
    # ecosystem_data name resolves via obs.find_package.name.
    from sbom.models import FindPackageInfo

    info = FindPackageInfo(required=False)
    info.name = "securec"  # the convention's last-resort name carrier
    comp = _component("securec")
    obs = Observation(
        source_kind=SourceKind.CMAKE_FIND_PACKAGE,
        find_package=info,
    )
    doc = _run(components=[comp], observations=[obs])
    assert "unattached_observation" not in [w.code for w in doc.warnings]
    assert doc.components[0].observations[0].find_package.required is False


def test_program_observation_attaches_via_program_key():
    # program/tool obs carry the name under 'program' (protoc, host_protoc).
    comp = _component("protoc")
    obs = Observation(
        source_kind=SourceKind.CMAKE_FIND_PROGRAM,
        ecosystem_data={"program": "protoc", "path": "/usr/bin/protoc"},
    )
    doc = _run(components=[comp], observations=[obs])
    assert "unattached_observation" not in [w.code for w in doc.warnings]
    assert doc.components[0].observations == [obs]


# ---------------------------------------------------------------------------
# Curated Notice wiring: protobuf source_version != effective_version
# ---------------------------------------------------------------------------


class _CuratedConfig:
    """Minimal config carrying just the repo_root reconcile reads for curated."""

    def __init__(self, repo_root="."):
        self.repo_root = repo_root
        self.network = "off"
        # Pin the full view: these curated-version tests predate the release
        # default and assert on a component with no runtime observation, which
        # the release preset would drop.
        self.scope = "all"


class _NoticeProfile(Profile):
    """Profile whose curated Notice gives protobuf v25.1 source / v3.13.0 effective."""

    name = "notice"

    def dependency_license_default(self, component):
        return None

    def curated_records(self, repo_root):
        from sbom_profile_cann import CuratedRecord

        return [
            CuratedRecord(
                name="protobuf", version="v25.1", effective_version="v3.13.0"
            )
        ]


def test_protobuf_source_vs_effective_from_curated_notice():
    # cmake supplies source_version=25.1; the curated Notice supplies the patched
    # effective_version=3.13.0. Reconcile must keep them separate and flag it.
    comp = _component("protobuf", source_version="25.1")
    doc = _run(
        components=[comp],
        profile=_NoticeProfile(),
        config=_CuratedConfig(),
    )
    out = doc.components[0]
    assert out.source_version == "25.1"
    assert out.effective_version == "3.13.0"  # v-prefix normalized to bare form
    codes = [w.code for w in doc.warnings]
    assert "patched_build" in codes
    pb = next(w for w in doc.warnings if w.code == "patched_build")
    assert pb.subject == "protobuf"


def test_curated_records_noop_without_profile_hook():
    # GenericProfile has no curated_records hook -> silent no-op, no crash.
    comp = _component("protobuf", source_version="25.1")
    doc = _run(components=[comp], config=_CuratedConfig())
    out = doc.components[0]
    assert out.source_version == "25.1"
    assert out.effective_version is None
    assert "patched_build" not in [w.code for w in doc.warnings]


# ---------------------------------------------------------------------------
# Union of integrity_findings / provenance / languages
# ---------------------------------------------------------------------------


def test_integrity_and_provenance_union():
    from sbom.models import IntegrityFinding

    a = _component("zlib", languages=["c"])
    a.integrity_findings = [IntegrityFinding.NO_HASH]
    a.provenance = [Provenance(field="source_version", source="zlib.cmake")]
    b = _component("zlib", languages=["c++"])
    b.integrity_findings = [IntegrityFinding.NO_HASH, IntegrityFinding.UNPINNED_GIT]
    b.provenance = [Provenance(field="effective_version", source="Notice")]

    doc = _run(components=[a, b])
    comp = doc.components[0]
    assert set(comp.languages) == {"c", "c++"}
    assert comp.integrity_findings == [
        IntegrityFinding.NO_HASH,
        IntegrityFinding.UNPINNED_GIT,
    ]
    assert len(comp.provenance) >= 2


# ---------------------------------------------------------------------------
# Layered license resolver
# ---------------------------------------------------------------------------


def test_known_license_map_applied_and_provenance():
    comp = _component("eigen")
    doc = _run(components=[comp], profile=_KnownProfile())
    out = doc.components[0]
    assert out.license == "MPL-2.0 AND BSD-3-Clause"
    sources = [p.source for p in out.provenance if p.field == "license"]
    assert "known_licenses.yaml" in sources


def test_known_license_alias_aware_lookup():
    # googletest -> gtest canonical, known map has gtest -> BSD-3-Clause.
    comp = _component("googletest")
    doc = _run(components=[comp], profile=_KnownProfile())
    out = doc.components[0]
    assert out.name == "gtest"
    assert out.license == "BSD-3-Clause"


def test_license_unresolved_noassertion():
    comp = _component("some-private-lib")
    doc = _run(components=[comp])
    out = doc.components[0]
    assert out.license == "NOASSERTION"
    assert "license_unresolved" in [w.code for w in doc.warnings]


def test_curated_wins_and_flags_discrepancy():
    class _CuratedProfile(_KnownProfile):
        name = "curated"

        def dependency_license_default(self, component):
            if component.name == "protobuf":
                return "GPL-3.0-only"  # deliberately disagrees with known map
            return None

    comp = _component("protobuf")
    doc = _run(components=[comp], profile=_CuratedProfile())
    out = doc.components[0]
    # Curated value wins.
    assert out.license == "GPL-3.0-only"
    assert "license_discrepancy" in [w.code for w in doc.warnings]


# ---------------------------------------------------------------------------
# Curated Notice license + copyright layer (CANN Third_Party_..._Notice)
# ---------------------------------------------------------------------------


class _NoticeLicenseProfile(Profile):
    """A profile whose curated Notice declares license AND copyright per name."""

    name = "notice-lic"

    def __init__(self, records):
        self._records = records

    def data_sources(self):
        return _known_licenses_sources()

    def dependency_license_default(self, component):
        return None  # CANN deps stay NOASSERTION unless curated/known proves one

    def curated_records(self, repo_root):
        return self._records


def test_curated_notice_copyright_populates_component_copyright():
    # The CANN Notice gives googletest a Google copyright block; reconcile must
    # apply it to comp.copyright (alias-resolved googletest -> gtest), and the
    # Notice license fills comp.license.
    from sbom_profile_cann import CuratedRecord

    profile = _NoticeLicenseProfile(
        [
            CuratedRecord(
                name="gtest",
                license="BSD-3-Clause",
                copyright="Copyright 2018, Google Inc. All rights reserved",
            )
        ]
    )
    comp = _component("googletest")  # raw spelling; canonicalizes to gtest
    doc = _run(components=[comp], profile=profile, config=_CuratedConfig())
    out = doc.components[0]
    assert out.name == "gtest"
    assert "Google" in out.copyright
    assert out.license == "BSD-3-Clause"
    assert any(
        p.field == "copyright" and p.source == "curated_notice" for p in out.provenance
    )


def test_curated_notice_license_fills_when_known_absent():
    # A component with no known-map entry and no concrete license still gets the
    # Notice's declared license + copyright (curated layer fills the gap).
    from sbom_profile_cann import CuratedRecord

    profile = _NoticeLicenseProfile(
        [
            CuratedRecord(
                name="securec",
                license="MulanPSL-2.0",
                copyright="Copyright (c) Huawei Technologies Co., Ltd. 2014-2021.",
            )
        ]
    )
    comp = _component("securec")
    doc = _run(components=[comp], profile=profile, config=_CuratedConfig())
    out = doc.components[0]
    assert out.license == "MulanPSL-2.0"
    assert "Huawei" in out.copyright
    sources = [p.source for p in out.provenance if p.field == "license"]
    assert "curated_notice" in sources
    # No license_unresolved -> the curated layer resolved it.
    assert "license_unresolved" not in [w.code for w in doc.warnings]


def test_curated_notice_does_not_override_known_when_absent_license():
    # When the Notice has no license for a name but the known map does, the known
    # map still applies (the Notice copyright is independent of the license).
    from sbom_profile_cann import CuratedRecord

    profile = _NoticeLicenseProfile(
        [CuratedRecord(name="eigen", license=None, copyright="Copyright Eigen")]
    )
    comp = _component("eigen")
    doc = _run(components=[comp], profile=profile, config=_CuratedConfig())
    out = doc.components[0]
    assert out.license == "MPL-2.0 AND BSD-3-Clause"  # from the known map
    assert out.copyright == "Copyright Eigen"  # from the Notice


# ---------------------------------------------------------------------------
# Profile subject license default (FIX 2)
# ---------------------------------------------------------------------------


class _SubjectLicenseProfile(Profile):
    """A profile that defaults its OWN subjects to a non-SPDX LicenseRef."""

    name = "subject-license"

    def subject_license_default(self, subject):
        if subject.role == SubjectRole.NON_DISTRIBUTABLE_TEST:
            return None
        return "LicenseRef-CANN-Open-Software-License-2.0"


def test_cann_subject_gets_licenseref_default_when_unset():
    # A repo-owned subject whose license is unset gets the profile's
    # subject_license_default, with inline text so the LicenseRef is valid SPDX.
    s = Subject(
        id="ops_math",
        identity=Identity(kind=SubjectKind.CANN_PACKAGE, name="ops_math", version="9.0.0"),
        role=SubjectRole.PRIMARY,
    )
    res = CollectResult()
    doc = reconcile([res], [s], None, _SubjectLicenseProfile())
    out = doc.subjects[0]
    assert out.license == "LicenseRef-CANN-Open-Software-License-2.0"
    # A non-SPDX LicenseRef carries inline text for the emitter validators.
    assert out.license_text is not None


def test_subject_license_default_does_not_override_existing():
    # A subject license already set (e.g. by scancode enrich) is never replaced.
    s = Subject(
        id="ops_math",
        identity=Identity(kind=SubjectKind.CANN_PACKAGE, name="ops_math", version="9.0.0"),
        role=SubjectRole.PRIMARY,
        license="Apache-2.0",
    )
    res = CollectResult()
    doc = reconcile([res], [s], None, _SubjectLicenseProfile())
    assert doc.subjects[0].license == "Apache-2.0"


def test_subject_license_default_skipped_for_non_distributable():
    # The profile returns None for non-distributable roots -> stays unset.
    s = Subject(
        id="ut",
        identity=Identity(kind=SubjectKind.CANN_PACKAGE, name="ut"),
        role=SubjectRole.NON_DISTRIBUTABLE_TEST,
    )
    res = CollectResult()
    doc = reconcile([res], [s], None, _SubjectLicenseProfile())
    assert doc.subjects[0].license is None


def test_environment_tools_passed_through():
    from sbom.models import EnvironmentTool

    tool = EnvironmentTool(name="perl")
    res = CollectResult(environment_tools=[tool])
    doc = reconcile([res], [], None, GenericProfile())
    assert doc.environment_tools == [tool]
    # Never becomes a component.
    assert all(c.name != "perl" for c in doc.components)


def test_reachability_axis_not_collapsed_on_observation():
    comp = _component("torch")
    obs = Observation(
        source_kind=SourceKind.CMAKE_FIND_PACKAGE,
        usage_scope=UsageScope.EXAMPLE,
        declaration_reachability=DeclarationReachability.UNREACHABLE,
        unreachable_reason="dead_config_flag",
        ecosystem_data={"name": "torch"},
    )
    doc = _run(components=[comp], observations=[obs])
    out_obs = doc.components[0].observations[0]
    assert out_obs.declaration_reachability is DeclarationReachability.UNREACHABLE
    assert out_obs.usage_scope is UsageScope.EXAMPLE


# ---------------------------------------------------------------------------
# Post-assembly Document transform: usage-scope exclusion / subjects closure /
# environment-tool omission (the three config-driven filters).
# ---------------------------------------------------------------------------


def _cfg(**kw):
    """A real Config with just the fields the transform reads.

    Defaults to ``scope="all"`` (the full view) so each test exercises ONLY the
    explicit filter it passes (``exclude_scopes`` / ``subjects`` / ``no_env_tools``)
    without the release preset's runtime-only base layering on top. The release
    preset is covered separately by the drift / release-default suites.
    """
    from pathlib import Path

    from sbom.config import Config

    defaults = dict(repo_root=Path("."), network="off", scope="all")
    defaults.update(kw)
    return Config(**defaults)


def _attached_obs(source_kind, name, scope):
    """An observation already attached on a component (post-collection shape)."""
    return Observation(
        source_kind=source_kind, usage_scope=scope, ecosystem_data={"name": name}
    )


def test_exclude_usage_scope_drops_test_only_component_keeps_multiscope():
    # gtest: a single test-only observation -> dropped entirely under exclude test.
    gtest = _component("gtest", scopes=[UsageScope.TEST])
    gtest.observations.append(
        _attached_obs(SourceKind.CMAKE_LINK_LIBRARY, "gtest", UsageScope.TEST)
    )
    # torch: {runtime, build} -> survives, but the build observation is dropped
    # and its scope summary recomputed to {runtime}.
    torch = _component("torch", scopes=[UsageScope.RUNTIME, UsageScope.BUILD])
    torch.observations.append(
        _attached_obs(SourceKind.PYTHON_SETUP, "torch", UsageScope.RUNTIME)
    )
    torch.observations.append(
        _attached_obs(SourceKind.PYTHON_BUILD, "torch", UsageScope.BUILD)
    )

    e_runtime = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ops_math"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="torch"),
        relation_type=RelationType.DEPENDS_ON,
        usage_scope=UsageScope.RUNTIME,
    )
    e_test = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ops_math"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="gtest"),
        relation_type=RelationType.LINK,
        usage_scope=UsageScope.TEST,
    )

    doc = _run(
        components=[gtest, torch],
        edges=[e_test, e_runtime],
        config=_cfg(exclude_scopes=["test"]),
    )
    names = {c.name for c in doc.components}
    assert "gtest" not in names          # test-only component dropped
    assert "torch" in names              # multi-scope dep survives
    torch_out = next(c for c in doc.components if c.name == "torch")
    # Excluding 'test' touches none of torch's observations (runtime + build).
    assert set(torch_out.scopes) == {UsageScope.RUNTIME, UsageScope.BUILD}
    assert len(torch_out.observations) == 2
    # The test edge (to the dropped component) is gone; the runtime edge stays.
    assert {(e.to_ref.id, e.usage_scope) for e in doc.edges} == {
        ("torch", UsageScope.RUNTIME)
    }
    assert "excluded_scope" in [w.code for w in doc.warnings]


def test_exclude_build_scope_drops_pure_build_dep_keeps_torch():
    # A pure build dep (ninja) is dropped; torch (runtime+build) survives.
    ninja = _component("ninja", scopes=[UsageScope.BUILD])
    ninja.observations.append(
        _attached_obs(SourceKind.PYTHON_BUILD, "ninja", UsageScope.BUILD)
    )
    torch = _component("torch")
    torch.observations.append(
        _attached_obs(SourceKind.PYTHON_SETUP, "torch", UsageScope.RUNTIME)
    )
    torch.observations.append(
        _attached_obs(SourceKind.PYTHON_BUILD, "torch", UsageScope.BUILD)
    )

    doc = _run(components=[ninja, torch], config=_cfg(exclude_scopes=["build"]))
    names = {c.name for c in doc.components}
    assert "ninja" not in names
    assert "torch" in names
    torch_out = next(c for c in doc.components if c.name == "torch")
    # build observation removed; scope summary recomputed to {runtime}.
    assert set(torch_out.scopes) == {UsageScope.RUNTIME}
    assert len(torch_out.observations) == 1


def test_exclude_usage_scope_keeps_none_scoped_observations():
    # An observation with usage_scope=None is never excluded.
    comp = _component("graph")
    comp.observations.append(
        Observation(source_kind=SourceKind.CMAKE_LINK_LIBRARY,
                    ecosystem_data={"name": "graph"})
    )
    doc = _run(components=[comp], config=_cfg(exclude_scopes=["test", "build"]))
    assert any(c.name == "graph" for c in doc.components)


# ---------------------------------------------------------------------------
# Release keep-only-RUNTIME axis (the leak fix): under --scope release the
# transform survives an observation/edge IFF usage_scope == RUNTIME, so
# usage_scope=None AND every non-runtime scope are dropped — distinct from the
# exclusion axis above, which KEEPS None.
# ---------------------------------------------------------------------------


def test_release_keep_only_drops_none_and_nonruntime_keeps_runtime():
    # runtime dep survives; a None-scoped link lib and a build/test dep drop.
    eigen = _component("eigen", scopes=[UsageScope.RUNTIME])
    eigen.observations.append(
        _attached_obs(SourceKind.CMAKE_EXTERNAL_PROJECT, "eigen", UsageScope.RUNTIME)
    )
    # gtest_shared_build: a None-scoped external project (the historical leak).
    leaked = _component("gtest_shared_build")
    leaked.observations.append(
        Observation(
            source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
            usage_scope=None,
            ecosystem_data={"name": "gtest_shared_build"},
        )
    )
    # cann-cmake: a build-scoped tooling component.
    cann_cmake = _component("cann-cmake", scopes=[UsageScope.BUILD])
    cann_cmake.observations.append(
        _attached_obs(SourceKind.CMAKE_BUILD_TOOLING, "cann-cmake", UsageScope.BUILD)
    )

    e_runtime = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ops_math"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="eigen"),
        relation_type=RelationType.DEPENDS_ON,
        usage_scope=UsageScope.RUNTIME,
    )
    e_none = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ops_math"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="gtest_shared_build"),
        relation_type=RelationType.DEPENDS_ON,
        usage_scope=None,
    )

    doc = _run(
        components=[eigen, leaked, cann_cmake],
        edges=[e_runtime, e_none],
        config=_cfg(scope="release"),
    )
    names = {c.name for c in doc.components}
    assert names == {"eigen"}, f"keep-only-runtime must drop None + build; saw {names}"
    # Only the runtime edge survives (the None-scoped edge is dropped).
    assert {(e.to_ref.id, e.usage_scope) for e in doc.edges} == {
        ("eigen", UsageScope.RUNTIME)
    }
    assert "excluded_scope" in [w.code for w in doc.warnings]


def test_release_keep_only_composes_with_explicit_exclude_runtime():
    # --scope release + --exclude-scope runtime drops EVERYTHING (keep-only
    # {runtime} minus the runtime exclusion leaves nothing surviving).
    eigen = _component("eigen", scopes=[UsageScope.RUNTIME])
    eigen.observations.append(
        _attached_obs(SourceKind.CMAKE_EXTERNAL_PROJECT, "eigen", UsageScope.RUNTIME)
    )
    doc = _run(
        components=[eigen],
        config=_cfg(scope="release", exclude_scopes=["runtime"]),
    )
    assert doc.components == []


def test_subjects_closure_keeps_only_named_reachable_set():
    eigen = _component("eigen")
    abseil = _component("abseil-cpp")
    protobuf = _component("protobuf")
    torch = _component("torch")

    # ops_math -> protobuf -> abseil-cpp ; ops_math -> eigen
    e1 = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ops_math"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="protobuf"),
        relation_type=RelationType.DEPENDS_ON,
    )
    e2 = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.COMPONENT, id="protobuf"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="abseil-cpp"),
        relation_type=RelationType.DEPENDS_ON,
    )
    e3 = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ops_math"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="eigen"),
        relation_type=RelationType.DEPENDS_ON,
    )
    # ascend_ops -> torch (a DIFFERENT subject's dep, must be excluded)
    e4 = DependencyEdge(
        root_artifact_id="ascend_ops",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ascend_ops"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="torch"),
        relation_type=RelationType.DEPENDS_ON,
    )

    from sbom.models import EnvironmentTool

    res = CollectResult(
        components=[eigen, abseil, protobuf, torch],
        edges=[e1, e2, e3, e4],
        environment_tools=[
            EnvironmentTool(name="perl", root_artifact_id="ops_math"),
            EnvironmentTool(name="tar", root_artifact_id="ascend_ops"),
        ],
    )
    primary = Subject(
        id="ops_math",
        identity=Identity(kind=SubjectKind.CMAKE_PROJECT, name="ops_math"),
        role=SubjectRole.PRIMARY,
    )
    sibling = Subject(
        id="ascend_ops",
        identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="ascend_ops"),
        role=SubjectRole.SIBLING_ARTIFACT,
    )
    doc = reconcile(
        [res], [primary, sibling], _cfg(subjects=["ops_math"]), GenericProfile()
    )

    assert [s.id for s in doc.subjects] == ["ops_math"]
    names = {c.name for c in doc.components}
    assert names == {"protobuf", "abseil-cpp", "eigen"}  # closure of ops_math
    assert "torch" not in names                          # ascend_ops's dep gone
    assert all(e.root_artifact_id == "ops_math" for e in doc.edges)
    # env tools restricted to the kept subject.
    assert {t.name for t in doc.environment_tools} == {"perl"}


def test_subjects_closure_promotes_lowest_role_root_when_primary_dropped():
    from sbom.models import SubjectRole as SR

    torch = _component("torch")
    e = DependencyEdge(
        root_artifact_id="ascend_ops",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ascend_ops"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="torch"),
        relation_type=RelationType.DEPENDS_ON,
    )
    res = CollectResult(components=[torch], edges=[e])
    primary = Subject(
        id="ops_math",
        identity=Identity(kind=SubjectKind.CMAKE_PROJECT, name="ops_math"),
        role=SR.PRIMARY,
    )
    sibling = Subject(
        id="ascend_ops",
        identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="ascend_ops"),
        role=SR.SIBLING_ARTIFACT,
    )
    doc = reconcile(
        [res], [primary, sibling], _cfg(subjects=["ascend_ops"]), GenericProfile()
    )
    assert [s.id for s in doc.subjects] == ["ascend_ops"]
    # The kept subject is a valid emittable root for metadata.component.
    assert doc.subjects[0].emit_as_subject is True
    assert {c.name for c in doc.components} == {"torch"}


def test_no_env_tools_clears_environment_tools():
    from sbom.models import EnvironmentTool

    res = CollectResult(
        components=[_component("eigen")],
        environment_tools=[EnvironmentTool(name="perl"), EnvironmentTool(name="tar")],
    )
    doc = reconcile([res], [], _cfg(no_env_tools=True), GenericProfile())
    assert doc.environment_tools == []
    # Components are untouched.
    assert {c.name for c in doc.components} == {"eigen"}


def test_filters_noop_when_config_unset():
    # No exclude_scopes, no subjects, no no_env_tools -> nothing dropped.
    from sbom.models import EnvironmentTool

    gtest = _component("gtest")
    gtest.observations.append(
        _attached_obs(SourceKind.CMAKE_LINK_LIBRARY, "gtest", UsageScope.TEST)
    )
    res = CollectResult(
        components=[gtest], environment_tools=[EnvironmentTool(name="perl")]
    )
    doc = reconcile([res], [], _cfg(), GenericProfile())
    assert {c.name for c in doc.components} == {"gtest"}
    assert doc.environment_tools[0].name == "perl"
    assert "excluded_scope" not in [w.code for w in doc.warnings]


# ---------------------------------------------------------------------------
# Supply-chain provenance classification (Component.origin)
# ---------------------------------------------------------------------------


def _classify(comp, profile=None):
    from sbom.reconcile import _classify_component_provenance

    _classify_component_provenance([comp], profile or GenericProfile())
    return comp.origin


def _url_obs(url):
    return Observation(
        source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
        ecosystem_data={},
        canonical_url=url,
    )


class _ClaimsFirstParty(Profile):
    """Profile that authoritatively claims one name as first-party."""

    name = "fp"

    def component_provenance(self, component):
        if "mylib" in (component.name, *component.aliases):
            return "first-party"
        return None


def test_provenance_profile_verdict_is_authoritative():
    # A profile 'first-party' wins even over a real OSS license + upstream URL.
    comp = Component(
        name="mylib", license="MIT", observations=[_url_obs("https://x/mylib.tgz")]
    )
    assert _classify(comp, _ClaimsFirstParty()) == "first-party"


def test_provenance_python_is_third_party():
    assert _classify(Component(name="numpy", languages=["Python"])) == "third-party"


def test_provenance_upstream_url_is_third_party():
    comp = Component(name="zlib", observations=[_url_obs("https://x/zlib-1.3.tar.gz")])
    assert _classify(comp) == "third-party"


def test_provenance_template_url_is_not_proof():
    # An unexpanded ${...} path is not a real URL, and the license is NOASSERTION,
    # so origin stays unknown rather than being guessed third-party.
    comp = Component(name="rawlib", observations=[_url_obs("${CANN_3RD_LIB_PATH}/rawlib")])
    assert _classify(comp) == "unknown"


def test_provenance_concrete_oss_license_is_third_party():
    # boost-like: fetched as INTERFACE targets (no URL token) but a real OSS license.
    assert _classify(Component(name="boost", license="BSL-1.0")) == "third-party"


def test_provenance_cann_licenseref_is_not_a_third_party_signal():
    # A LicenseRef-* placeholder is not 'concrete OSS'; unclaimed + no URL -> unknown.
    comp = Component(name="internal", license="LicenseRef-CANN-Open-Software-License-2.0")
    assert _classify(comp) == "unknown"


def test_provenance_noassertion_no_url_is_unknown():
    assert _classify(Component(name="Threads", license="NOASSERTION")) == "unknown"
    assert _classify(Component(name="bare")) == "unknown"


def test_provenance_mixed_license_expression_is_order_independent():
    # A real OSS id anywhere in an SPDX expression -> third-party, regardless of
    # whether a LicenseRef-* placeholder precedes or follows it.
    assert _classify(Component(name="a", license="MIT OR LicenseRef-x")) == "third-party"
    assert _classify(Component(name="b", license="LicenseRef-x OR MIT")) == "third-party"
    assert (
        _classify(Component(name="c", license="Apache-2.0 WITH LLVM-exception"))
        == "third-party"
    )
    # An expression with ONLY LicenseRef placeholders is NOT a third-party signal.
    assert _classify(Component(name="d", license="LicenseRef-x OR LicenseRef-y")) == "unknown"


class _ClaimsThirdParty(Profile):
    """Profile that authoritatively asserts a class OTHER than first-party."""

    name = "tp"

    def component_provenance(self, component):
        return "third-party" if component.name == "vendored" else None


def test_provenance_profile_may_assert_third_party_verbatim():
    # A non-first-party profile verdict is honored verbatim, even with no generic
    # third-party signal (no Python, no URL, NOASSERTION license).
    comp = Component(name="vendored", license="NOASSERTION")
    assert _classify(comp, _ClaimsThirdParty()) == "third-party"


def _cann_reconcile(comp, observations=None):
    """Run the FULL reconcile pipeline with the real CANN profile and return the
    surviving component (origin classified end-to-end, not via the hook alone)."""
    from sbom_profile_cann import CannProfile

    res = CollectResult(components=[comp], observations=observations or [])
    doc = reconcile([res], [], _cfg(), CannProfile())
    return next(
        c for c in doc.components if comp.name in {c.name, *c.aliases}
    )


def test_provenance_lookalike_mirror_is_third_party_through_reconcile():
    # End-to-end: a look-alike CANN mirror URL (shares the 'cann' substring) must
    # NOT be read as first-party; the generic upstream-URL signal makes it third.
    obs = Observation(
        source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
        ecosystem_data={"name": "protobuf"},
        canonical_url=(
            "https://cann-3rd.obs.cn-north-4.myhuaweicloud.com/protobuf/protobuf-25.1.tar.gz"
        ),
    )
    assert _cann_reconcile(Component(name="protobuf"), [obs]).origin == "third-party"


def test_provenance_alias_first_party_through_reconcile():
    # A component canonicalized to a non-first-party name but carrying a first-party
    # ALIAS (case-insensitive) is classified first-party by the CANN profile.
    comp = _cann_reconcile(Component(name="some-wrapper", aliases=["OPBASE"]))
    assert comp.origin == "first-party"
