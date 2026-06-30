"""Unit tests for the CANN profile, exercised against the REAL CANN/ops-math
trees under /home/aron/testing/cann.

Each test targets one Profile hook. Where a tree file is present we assert
against its actual content; tests skip cleanly if the live tree is absent so the
suite stays runnable on a snapshot checkout.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sbom.models import (
    CmakeAuthority,
    CmakeAuthorityBranch,
    Component,
    Facet,
    Identity,
    IntegrityFinding,
    Observation,
    SourceKind,
    Subject,
    SubjectKind,
    SubjectMerge,
    SubjectRole,
    UsageScope,
)
from sbom.profile import Profile, get_profile, load_profiles

import sbom_profile_cann as cann
from sbom_profile_cann import (
    CannProfile,
    CannThirdPartyResolver,
    CuratedRecord,
    parse_list_yaml,
    parse_notice,
    parse_version_cmake,
)

CANN_ROOT = Path("/home/aron/testing/cann")
OPS_MATH = CANN_ROOT / "ops-math"
CMAKE_ROOT = CANN_ROOT / "cmake"

requires_tree = pytest.mark.skipif(
    not OPS_MATH.is_dir() or not CMAKE_ROOT.is_dir(),
    reason="live CANN tree not present",
)


@pytest.fixture()
def profile() -> CannProfile:
    return CannProfile()


# ---------------------------------------------------------------------------
# Registry / detection / contract
# ---------------------------------------------------------------------------


def test_profile_is_registered_and_resolvable():
    registry, warnings = load_profiles()
    assert "cann" in registry
    assert registry["cann"] is CannProfile
    assert all(w.code != "profile_load_failed" for w in warnings)
    inst, _ = get_profile("cann")
    assert isinstance(inst, Profile)
    assert inst.name == "cann"


@requires_tree
def test_detect_matches_ops_math_via_macro_usage():
    assert CannProfile.detect(OPS_MATH) is True


@requires_tree
def test_detect_matches_cmake_root_via_prepare_marker():
    assert CannProfile.detect(CMAKE_ROOT) is True


def test_detect_false_on_unrelated_dir(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text("project(foo)\n")
    assert CannProfile.detect(tmp_path) is False


@pytest.mark.parametrize(
    "rel,content",
    [
        # CANN repos that use the project/version macros or the fetch include but
        # NO add_cann_third_party (pto-isa / pypto / hccl class — previously missed).
        ("CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\ninit_cann_project(myrepo)\n"),
        ("CMakeLists.txt", "check_cann_pkg_build_deps(myrepo)\n"),
        ("version.cmake", 'set_cann_package(myrepo VERSION "1.0")\n'),
        ("cmake/fetch_cann_cmake.cmake", "# fetch the cann-cmake tree\n"),
    ],
)
def test_detect_matches_cann_markers_without_third_party(tmp_path: Path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    assert CannProfile.detect(tmp_path) is True


def _write_git_origin(repo: Path, url: str) -> None:
    """Write a minimal .git/config with an origin remote (no real git needed)."""
    (repo / ".git").mkdir(parents=True, exist_ok=True)
    (repo / ".git" / "config").write_text(f'[remote "origin"]\n\turl = {url}\n')


@pytest.mark.parametrize(
    "url,expected",
    [
        # cann org (secondary signal) — CANN repos with NO cann-cmake markers.
        ("git@gitcode.com:cann/pyasc.git", True),
        ("https://gitcode.com/cann/shmem.git", True),
        # Ascend org is deliberately NOT CANN (e.g. MindIE-LLM is a MulanPSL variant).
        ("https://gitcode.com/Ascend/MindIE-LLM.git", False),
        # An unrelated org under the same host is not CANN.
        ("https://gitcode.com/mindspore/mindspore.git", False),
        # The org name on a different host is not trusted.
        ("https://github.com/cann/something.git", False),
    ],
)
def test_detect_via_git_origin_org(tmp_path: Path, url, expected):
    # No cann-cmake markers present — only the git origin decides.
    _write_git_origin(tmp_path, url)
    assert CannProfile.detect(tmp_path) is expected


# ---------------------------------------------------------------------------
# custom_dep_macros
# ---------------------------------------------------------------------------


def test_custom_dep_macros_exposes_add_cann_third_party(profile: CannProfile):
    macros = profile.custom_dep_macros()
    assert "add_cann_third_party" in macros
    assert isinstance(macros["add_cann_third_party"], CannThirdPartyResolver)


@pytest.mark.parametrize(
    "name",
    ["eigen", "protobuf", "json", "gtest", "makeself-fetch"],
)
def test_resolver_anchors_at_effective_cmake_root(name: str):
    resolver = CannThirdPartyResolver()
    eff = Path("/some/effective/cmake")
    out = resolver([name], eff)
    assert out == [eff / "third_party" / f"{name}.cmake"]


def test_resolver_unknown_root_returns_empty():
    resolver = CannThirdPartyResolver()
    assert resolver(["eigen"], None) == []
    assert resolver([], Path("/eff")) == []


def test_resolver_strips_quotes():
    resolver = CannThirdPartyResolver()
    eff = Path("/eff")
    assert resolver(['"eigen"'], eff) == [eff / "third_party" / "eigen.cmake"]


@requires_tree
def test_resolver_points_at_real_fragment_files():
    resolver = CannThirdPartyResolver()
    for name in ("eigen", "protobuf", "json"):
        (frag,) = resolver([name], CMAKE_ROOT)
        assert frag.is_file(), frag


# ---------------------------------------------------------------------------
# package_metadata / version.cmake
# ---------------------------------------------------------------------------


def test_parse_version_cmake_table():
    text = """
    set_cann_package(ops_math VERSION "9.0.0")
    set_cann_build_dependencies(runtime ">=8.5")
    set_cann_build_dependencies(opbase ">=8.5")
    set_cann_run_dependencies(asc-tools ">=8.5")
    set_cann_run_dependencies(ops-legacy ">=8.5")
    """
    info = parse_version_cmake(text)
    assert info.name == "ops_math"
    assert info.version == "9.0.0"
    assert ("runtime", ">=8.5") in info.build_deps
    assert ("opbase", ">=8.5") in info.build_deps
    assert ("asc-tools", ">=8.5") in info.run_deps
    assert ("ops-legacy", ">=8.5") in info.run_deps


@requires_tree
def test_package_info_reads_real_version_cmake(profile: CannProfile):
    info = profile.package_info(OPS_MATH)
    assert info.name == "ops_math"
    assert info.version == "9.0.0"
    build_names = {n for n, _ in info.build_deps}
    run_names = {n for n, _ in info.run_deps}
    # Build deps from version.cmake.
    assert {
        "runtime",
        "opbase",
        "metadef",
        "ge-compiler",
        "bisheng-compiler",
        "asc-devkit",
        "ge-executor",
    } <= build_names
    # Run deps add asc-tools and ops-legacy.
    assert {"asc-tools", "ops-legacy"} <= run_names


@requires_tree
def test_package_metadata_emits_scoped_observations(profile: CannProfile):
    authority = CmakeAuthority(branch=CmakeAuthorityBranch.GIT, ref="master-016")
    obs = profile.package_metadata(OPS_MATH, authority)
    assert obs, "expected package observations"
    assert all(o.source_kind is SourceKind.CANN_PACKAGE for o in obs)
    assert all(o.version_constraint == ">=8.5" for o in obs)
    build_pkgs = {
        o.ecosystem_data["cann_package"]
        for o in obs
        if o.usage_scope is UsageScope.BUILD
    }
    run_pkgs = {
        o.ecosystem_data["cann_package"]
        for o in obs
        if o.usage_scope is UsageScope.RUNTIME
    }
    assert "ge-compiler" in build_pkgs
    assert "asc-tools" in run_pkgs
    # Primary package identity is carried on each observation.
    assert obs[0].ecosystem_data["primary_package"] == "ops_math"
    assert obs[0].ecosystem_data["primary_version"] == "9.0.0"


def test_package_metadata_missing_file_is_empty(profile: CannProfile, tmp_path: Path):
    authority = CmakeAuthority(branch=CmakeAuthorityBranch.GIT)
    assert profile.package_metadata(tmp_path, authority) == []


def test_package_metadata_stamps_source_revision(profile: CannProfile, tmp_path: Path):
    (tmp_path / "version.cmake").write_text(
        'set_cann_package(ops_math VERSION "9.0.0")\n'
        'set_cann_build_dependencies(runtime ">=8.5")\n'
    )
    authority = CmakeAuthority(
        branch=CmakeAuthorityBranch.GIT, ref="master-016", revision="deadbeef"
    )
    obs = profile.package_metadata(tmp_path, authority)
    assert obs and all(o.source_revision == "deadbeef" for o in obs)
    assert all(o.source_file == "version.cmake" for o in obs)


# ---------------------------------------------------------------------------
# build_tooling
# ---------------------------------------------------------------------------


def _authority(branch, **kw) -> CmakeAuthority:
    return CmakeAuthority(branch=branch, **kw)


def test_build_tooling_skipped_branch_emits_nothing(profile: CannProfile):
    comps, warns = profile.build_tooling(
        OPS_MATH, _authority(CmakeAuthorityBranch.SKIPPED_EXISTING_PROJECT)
    )
    assert comps == []
    assert warns == []


def test_build_tooling_tarball_branch(profile: CannProfile):
    comps, warns = profile.build_tooling(
        OPS_MATH, _authority(CmakeAuthorityBranch.TARBALL, ref="master-016")
    )
    assert len(comps) == 1
    c = comps[0]
    assert c.name == "cann-cmake"
    assert UsageScope.BUILD in c.scopes
    assert c.source_version == "master-016"
    assert c.effective_version == "master-016"
    assert c.checksums.get("sha256") == cann.CANN_CMAKE_TARBALL_SHA256
    assert c.observations[0].source_kind is SourceKind.CMAKE_BUILD_TOOLING
    assert not any(w.code == "cann_cmake_tag_mismatch" for w in warns)


def test_build_tooling_git_branch_with_resolved_commit(profile: CannProfile):
    comps, warns = profile.build_tooling(
        OPS_MATH,
        _authority(CmakeAuthorityBranch.GIT, ref="master-016", revision="abc123"),
    )
    c = comps[0]
    assert c.source_version == "master-016"
    assert c.vcs_ref is not None
    assert c.vcs_ref.requested == "master-016"
    assert c.vcs_ref.resolved_commit == "abc123"
    assert IntegrityFinding.UNPINNED_GIT not in c.integrity_findings


def test_build_tooling_git_branch_unpinned(profile: CannProfile):
    comps, _ = profile.build_tooling(
        OPS_MATH, _authority(CmakeAuthorityBranch.GIT, ref="master-016")
    )
    assert IntegrityFinding.UNPINNED_GIT in comps[0].integrity_findings


def test_build_tooling_local_dir_branch(profile: CannProfile):
    comps, warns = profile.build_tooling(
        OPS_MATH,
        _authority(CmakeAuthorityBranch.LOCAL_DIR, revision="localsha"),
    )
    c = comps[0]
    # local-dir is NOT master-016.
    assert c.source_version is None
    assert c.effective_version is None
    assert IntegrityFinding.LOCAL_SOURCE_UNVERIFIED in c.integrity_findings
    assert c.vcs_ref is not None and c.vcs_ref.resolved_commit == "localsha"
    assert any(w.code == "cann_cmake_local_override" for w in warns)


def test_build_tooling_cmake_as_input_excludes_component(profile: CannProfile):
    authority = _authority(
        CmakeAuthorityBranch.GIT,
        ref="master-016",
        authority_inputs={"trusted_input": True},
    )
    comps, warns = profile.build_tooling(OPS_MATH, authority)
    assert comps == []
    assert any(w.code == "cann_cmake_trusted_input" for w in warns)


def test_build_tooling_tag_mismatch(profile: CannProfile):
    comps, warns = profile.build_tooling(
        OPS_MATH, _authority(CmakeAuthorityBranch.GIT, ref="master-029")
    )
    assert any(w.code == "cann_cmake_tag_mismatch" for w in warns)


def test_build_tooling_tag_mismatch_under_cmake_as_input(profile: CannProfile):
    authority = _authority(
        CmakeAuthorityBranch.GIT,
        ref="master-029",
        authority_inputs={"trusted_input": True},
    )
    comps, warns = profile.build_tooling(OPS_MATH, authority)
    assert comps == []
    codes = {w.code for w in warns}
    assert "cann_cmake_trusted_input" in codes
    assert "cann_cmake_tag_mismatch" in codes


# ---------------------------------------------------------------------------
# curated enrichers
# ---------------------------------------------------------------------------


def test_parse_list_yaml_table():
    text = (
        "eigen:\n  version: 5.0.0\n  type: run\n"
        "googletest:\n  version: v1.14.0\n  type: test\n"
        "protobuf:\n  version: v25.1\n  type: run\n"
    )
    recs = {r.name: r for r in parse_list_yaml(text)}
    assert recs["eigen"].version == "5.0.0"
    assert recs["eigen"].declared_type == "run"
    # googletest canonicalizes to gtest.
    assert "gtest" in recs
    assert recs["gtest"].version == "v1.14.0"
    assert recs["protobuf"].version == "v25.1"


def test_parse_notice_table():
    text = (
        "Copyright Notice and License Texts\n"
        "Software: protobuf v3.13.0\n"
        "Copyright notice:\n"
        "Copyright 2008 Google Inc.\n"
        "\n"
        "License: BSD 3-Clause License\n"
        "some license body\n"
        "Copyright Notice and License Texts\n"
        "Software: json v3.11.3\n"
        "Copyright notice:\n"
        "Copyright 2013-2023 Niels Lohmann\n"
        "\n"
        "License: MIT License\n"
    )
    recs = {r.name: r for r in parse_notice(text)}
    assert recs["protobuf"].version == "v3.13.0"
    assert recs["protobuf"].license == "BSD-3-Clause"
    assert "Google" in recs["protobuf"].copyright
    assert recs["json"].license == "MIT"


def test_parse_notice_unknown_license_kept_raw():
    text = (
        "Software: weird 1.0\n"
        "Copyright notice:\n"
        "Copyright someone\n"
        "License: Some Exotic License\n"
    )
    (rec,) = parse_notice(text)
    assert rec.license == "Some Exotic License"
    assert rec.license_raw == "Some Exotic License"


@requires_tree
def test_curated_enrichers_load_real_files(profile: CannProfile):
    enrichers = profile.curated_enrichers(OPS_MATH)
    assert len(enrichers) == 2
    assert all(e.exists() for e in enrichers)  # type: ignore[attr-defined]


@requires_tree
def test_curated_records_merge_list_and_notice(profile: CannProfile):
    recs = {r.name: r for r in profile.curated_records(OPS_MATH)}
    # protobuf: List.yaml v25.1 (source) vs Notice v3.13.0 (effective) -> patched.
    assert "protobuf" in recs
    assert recs["protobuf"].license == "BSD-3-Clause"
    versions = {recs["protobuf"].version, recs["protobuf"].effective_version}
    assert "v25.1" in versions
    assert "v3.13.0" in versions
    # gtest license from Notice.
    assert recs["gtest"].license == "BSD-3-Clause"
    # makeself GPL from Notice.
    assert recs["makeself"].license == "GPL-2.0-only"
    assert recs["makeself"].copyright is not None


def test_curated_records_missing_files(profile: CannProfile, tmp_path: Path):
    assert profile.curated_records(tmp_path) == []


# ---------------------------------------------------------------------------
# alias_map
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spelling,canonical",
    [
        ("OPBASE", "opbase"),
        ("opbase", "opbase"),
        ("tilingapi", "tiling_api"),
        ("tiling_api", "tiling_api"),
        ("ASC", "asc-devkit"),
        ("securec", "securec"),
        ("c_sec", "securec"),
        ("ge_runner", "ge-executor"),
        ("ge_compiler", "ge-compiler"),
        ("cust_opapi", "opapi"),
        ("unified_dlog", "dlog"),
        # PEP 503-normalized so the CMake link edge reconciles onto the same
        # component as the Python wheel's ``torch_npu`` install_requires.
        ("torch_npu", "torch-npu"),
        ("mmpa", "mmpa"),
        ("rt2_registry_static", "rt2_registry_static"),
        ("exe_graph", "exe_graph"),
        ("graph_base", "graph_base"),
    ],
)
def test_alias_map_canonicalization(profile: CannProfile, spelling, canonical):
    amap = profile.alias_map()
    assert spelling in amap, spelling
    assert amap[spelling]["canonical"] == canonical


def test_alias_map_relation_types(profile: CannProfile):
    amap = profile.alias_map()
    # find_package module that is a package dep.
    assert amap["OPBASE"]["relation"] == "depends_on"
    # raw link library.
    assert amap["tiling_api"]["relation"] == "link"
    assert amap["torch_npu"]["relation"] == "link"
    # tooling.
    assert amap["bisheng-compiler"]["relation"] == "tooling"


def test_alias_relations_are_valid_relation_values(profile: CannProfile):
    from sbom.models import RelationType

    valid = {rt.value for rt in RelationType}
    for spelling, rec in profile.alias_map().items():
        assert rec["relation"] in valid, (spelling, rec)


def test_alias_map_loaded_from_data_file_and_returns_copy(profile: CannProfile):
    # The map is carried as a YAML data file (editable without code changes),
    # not a hardcoded dict.
    from sbom_profile_cann import _ALIAS_MAP_PATH

    assert _ALIAS_MAP_PATH.name == "aliases.yaml" and _ALIAS_MAP_PATH.is_file()
    # Mutating the returned map must not corrupt the cached copy.
    first = profile.alias_map()
    first["BOGUS"] = {"canonical": "x", "relation": "link"}
    assert "BOGUS" not in profile.alias_map()


# ---------------------------------------------------------------------------
# license defaults
# ---------------------------------------------------------------------------


def _subject(role: SubjectRole, kind=SubjectKind.CANN_PACKAGE) -> Subject:
    return Subject(
        id="x",
        identity=Identity(kind=kind, name="x", version="1.0.0"),
        role=role,
    )


def test_subject_license_default_for_owned_roles(profile: CannProfile):
    for role in (
        SubjectRole.PRIMARY,
        SubjectRole.SIBLING_ARTIFACT,
        SubjectRole.EXAMPLE,
        SubjectRole.EXPERIMENTAL,
        SubjectRole.ST_TEST,
        SubjectRole.CMAKE_PROJECT,
    ):
        assert (
            profile.subject_license_default(_subject(role))
            == cann.CANN_OPEN_LICENSE
        )


def test_subject_license_default_none_for_non_distributable(profile: CannProfile):
    assert (
        profile.subject_license_default(
            _subject(SubjectRole.NON_DISTRIBUTABLE_TEST)
        )
        is None
    )


def test_dependency_license_default_first_party_vs_other(profile: CannProfile):
    # Recognized first-party CANN packages/symbols get the CANN LicenseRef as a
    # profile default (matched on name or alias)...
    for name in ("opbase", "runtime", "ascendcl", "ge-compiler", "dlog"):
        assert (
            profile.dependency_license_default(Component(name=name))
            == cann.CANN_OPEN_LICENSE
        ), name
    assert (
        profile.dependency_license_default(Component(name="OPBASE"))
        == cann.CANN_OPEN_LICENSE
    )
    # ...but third-party (securec=libboundscheck), published OSS (torch-npu), and
    # unknown deps are NOT asserted — they keep deriving their own license (curated
    # Notice / file headers / network).
    for name in ("securec", "torch-npu", "eigen", "numpy", "nope-xyz"):
        assert profile.dependency_license_default(Component(name=name)) is None, name
    # bisheng-compiler is first-party but CLOSED-SOURCE: it is a key in the
    # first-party set (null license) so its license stays unasserted (None), NOT the
    # CANN Open License. (Provenance is verified separately below.)
    assert profile.dependency_license_default(Component(name="bisheng-compiler")) is None


def test_unknown_explicit_profile_warns_not_silent_downgrade():
    # An explicit but unregistered --repo-profile must surface a warning, not
    # silently drop the whole profile layer to the generic core — review E11.
    from sbom.profile import GenericProfile, get_profile

    prof, warns = get_profile("definitely-not-a-real-profile")
    assert isinstance(prof, GenericProfile)
    assert any(w.code == "profile_not_found" for w in warns)
    # auto / None detection -> NO profile_not_found (a legitimate fallback)
    _, w_auto = get_profile("auto")
    assert not any(w.code == "profile_not_found" for w in w_auto)


def test_first_party_licenses_loaded_from_data_file():
    from sbom_profile_cann import _FIRST_PARTY_PATH, _first_party_licenses

    assert _FIRST_PARTY_PATH.name == "first_party_licenses.yaml" and _FIRST_PARTY_PATH.is_file()
    fp = _first_party_licenses()
    assert fp["opbase"] == cann.CANN_OPEN_LICENSE
    assert "securec" not in fp and "torch-npu" not in fp  # third-party excluded


def test_license_default_split_subject_vs_dependency(profile: CannProfile):
    # The primary subject gets the CANN LicenseRef; a THIRD-PARTY dep stays unset.
    assert (
        profile.subject_license_default(_subject(SubjectRole.PRIMARY))
        == cann.CANN_OPEN_LICENSE
    )
    assert profile.dependency_license_default(Component(name="eigen")) is None


# ---------------------------------------------------------------------------
# component_provenance (supply-chain origin)
# ---------------------------------------------------------------------------


def _comp_with_url(name, url):
    obs = Observation(
        source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT, ecosystem_data={}, canonical_url=url
    )
    return Component(name=name, observations=[obs])


def test_component_provenance_first_party_by_name(profile: CannProfile):
    # CANN-internal libs / sibling packages (first_party_licenses.yaml) -> first-party.
    for name in ("platform", "metadef", "ge-compiler", "dlog", "ascendcl"):
        assert profile.component_provenance(Component(name=name)) == "first-party", name
    # ...matched on an alias too.
    assert (
        profile.component_provenance(Component(name="x", aliases=["opbase"]))
        == "first-party"
    )


def test_component_provenance_first_party_by_cann_org_url(profile: CannProfile):
    # Anything fetched from the gitcode.com/cann/<repo> org namespace is first-party.
    comp = _comp_with_url("somelib", "https://gitcode.com/cann/somelib/archive/v1.tar.gz")
    assert profile.component_provenance(comp) == "first-party"
    # A git+...@rev origin form resolves the same way.
    comp2 = _comp_with_url("runtime", "git+https://gitcode.com/cann/runtime.git@abc123")
    assert profile.component_provenance(comp2) == "first-party"
    # FQDN trailing dot + uppercase host/path are normalized before matching.
    comp3 = _comp_with_url("x", "git+https://GITCODE.COM./CANN/x.git@rev")
    assert profile.component_provenance(comp3) == "first-party"


def test_component_provenance_lookalike_mirrors_are_not_first_party(profile: CannProfile):
    # The third-party mirrors merely SHARE the 'cann' substring and must NOT match:
    #   gitcode.com/cann-src-third-party/... (libboundscheck)
    #   cann-3rd.obs.<region>.myhuaweicloud.com/... (eigen/protobuf/json/...)
    securec = _comp_with_url(
        "securec",
        "https://gitcode.com/cann-src-third-party/libboundscheck/releases/x.tar.gz",
    )
    protobuf = _comp_with_url(
        "protobuf",
        "https://cann-3rd.obs.cn-north-4.myhuaweicloud.com/protobuf/protobuf-25.1.tar.gz",
    )
    assert profile.component_provenance(securec) is None
    assert profile.component_provenance(protobuf) is None


def test_component_provenance_none_for_unrecognized(profile: CannProfile):
    # An unknown name with no CANN-org URL is left to the generic core (None).
    assert profile.component_provenance(Component(name="boost")) is None
    assert profile.component_provenance(Component(name="numpy")) is None


def test_component_provenance_closed_source_is_first_party_but_unlicensed(profile):
    # bisheng-compiler is closed-source CANN: provenance and license are decoupled
    # via a null entry in first_party_licenses.yaml — first-party provenance, but
    # NO asserted license (stays NOASSERTION, never the CANN Open License).
    bisheng = Component(name="bisheng-compiler")
    assert profile.component_provenance(bisheng) == "first-party"
    assert profile.dependency_license_default(bisheng) is None


# ---------------------------------------------------------------------------
# condition_vocabulary
# ---------------------------------------------------------------------------


def test_condition_vocabulary_tokens(profile: CannProfile):
    vocab = profile.condition_vocabulary()
    for token in (
        "TOPLEVEL_PROJECT",
        "ENABLE_TEST",
        "ENABLE_PACKAGE",
        "ENABLE_TORCH_EXTENSION",
        "PRODUCT_SIDE",
        "BUILD_WITH_INSTALLED_DEPENDENCY_CANN_PKG",
        "DOWNLOAD_OPS_TEST_KIT",
    ):
        assert token in vocab


def test_condition_vocabulary_torch_extension_flagged_dead(profile: CannProfile):
    vocab = profile.condition_vocabulary()
    assert vocab["ENABLE_TORCH_EXTENSION"].get("dead") is True


# ---------------------------------------------------------------------------
# classify_root / root_exclusion_policy
# ---------------------------------------------------------------------------


def _cmake_project_subject() -> Subject:
    return Subject(
        id="r",
        identity=Identity(kind=SubjectKind.CMAKE_PROJECT, name="r", version="1.0.0"),
        role=SubjectRole.CMAKE_PROJECT,
    )


@pytest.mark.parametrize(
    "rel,expected",
    [
        ("experimental/math/bitwise_not/examples", SubjectRole.EXAMPLE),
        ("experimental/math/fused_mul_add_n/examples", SubjectRole.EXAMPLE),
        ("experimental/math/fused_mul_add_n/tests/st", SubjectRole.ST_TEST),
        (
            "experimental/math/fused_mul_add_n/tests/st/torch",
            SubjectRole.ST_TEST,
        ),
        (
            "experimental/math/sort_with_index/tests/st/torch",
            SubjectRole.ST_TEST,
        ),
        (
            "experimental/math/fused_mul_add_n/tests/ut/op_host",
            SubjectRole.NON_DISTRIBUTABLE_TEST,
        ),
        (
            "examples/fast_kernel_launch_example",
            SubjectRole.MANUAL_EXAMPLE,
        ),
        ("experimental/math/floor_div", SubjectRole.EXPERIMENTAL),
        # A 'samples'/'sample' path segment marks a demo root -> EXAMPLE.
        ("samples/runtime/0_basic", SubjectRole.EXAMPLE),
        ("sample/kernel/launch", SubjectRole.EXAMPLE),
        ("demos/samples/foo", SubjectRole.EXAMPLE),
        # 'sample'/'samples' under experimental still classifies as example.
        ("experimental/math/x/samples/0", SubjectRole.EXAMPLE),
        # A 'tests/st' segment still wins over a sibling 'sample' word.
        ("samples/x/tests/st", SubjectRole.ST_TEST),
    ],
)
def test_classify_root_path_semantics(profile: CannProfile, rel, expected):
    path = OPS_MATH / rel
    role = profile.classify_root(
        path, _cmake_project_subject(), {"repo_root": OPS_MATH}
    )
    assert role == expected


def test_classify_root_falls_through_to_existing(profile: CannProfile):
    path = OPS_MATH / "common"
    role = profile.classify_root(
        path, _cmake_project_subject(), {"repo_root": OPS_MATH}
    )
    assert role == SubjectRole.CMAKE_PROJECT


def test_classify_root_without_repo_root(profile: CannProfile):
    # Absolute path still classified by its tail segments.
    path = Path("/anywhere/experimental/math/x/tests/st/torch")
    role = profile.classify_root(path, _cmake_project_subject(), {})
    assert role == SubjectRole.ST_TEST


# ---------------------------------------------------------------------------
# subject_facets
# ---------------------------------------------------------------------------


def _wheel(name: str, sid: str) -> Subject:
    return Subject(
        id=sid,
        identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name=name, version="1.0.0"),
        role=SubjectRole.SIBLING_ARTIFACT,
    )


def _cmake(name: str, sid: str, version="1.0.0") -> Subject:
    return Subject(
        id=sid,
        identity=Identity(
            kind=SubjectKind.CMAKE_PROJECT, name=name, version=version
        ),
        role=SubjectRole.CMAKE_PROJECT,
    )


def _cann_pkg(name: str, sid: str, version="9.0.0") -> Subject:
    return Subject(
        id=sid,
        identity=Identity(kind=SubjectKind.CANN_PACKAGE, name=name, version=version),
        role=SubjectRole.PRIMARY,
    )


def test_subject_facets_ascend_ops_absorbs_AscendOps(profile: CannProfile):
    subjects = [
        _wheel("ascend_ops", "wheel-ascend"),
        _cmake("AscendOps", "cmake-ascend"),
    ]
    merges = profile.subject_facets(subjects)
    assert len(merges) == 1
    m = merges[0]
    assert isinstance(m, SubjectMerge)
    assert m.keep_subject_id == "wheel-ascend"
    assert m.absorbed_subject_id == "cmake-ascend"
    assert m.build_graph_root_id == "cmake-ascend"
    assert m.facet == Facet(
        kind=SubjectKind.CMAKE_PROJECT, name="AscendOps", version="1.0.0"
    )


def test_subject_facets_ops_math_absorbs_math(profile: CannProfile):
    subjects = [
        _cann_pkg("ops_math", "pkg-opsmath"),
        _cmake("math", "cmake-math", version="1.0.0"),
    ]
    merges = profile.subject_facets(subjects)
    assert len(merges) == 1
    m = merges[0]
    assert m.keep_subject_id == "pkg-opsmath"
    assert m.absorbed_subject_id == "cmake-math"
    assert m.facet.name == "math"


def test_subject_facets_combined(profile: CannProfile):
    subjects = [
        _cann_pkg("ops_math", "pkg-opsmath"),
        _cmake("math", "cmake-math"),
        _wheel("ascend_ops", "wheel-ascend"),
        _cmake("AscendOps", "cmake-ascend"),
    ]
    merges = profile.subject_facets(subjects)
    keeps = {m.keep_subject_id for m in merges}
    assert keeps == {"pkg-opsmath", "wheel-ascend"}


def test_subject_facets_no_merge_when_partner_absent(profile: CannProfile):
    subjects = [_wheel("ascend_ops", "wheel-ascend")]
    assert profile.subject_facets(subjects) == []


def test_subject_facets_empty(profile: CannProfile):
    assert profile.subject_facets([]) == []
