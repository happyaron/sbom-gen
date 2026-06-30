"""Unit tests for sbom.collectors.cpp — the C++/CMake collector.

These exercise the policy layer (parse-record -> model translation), not the
static CMake parser itself.  We feed contract-shaped CMakeFile records (mirroring
the real ops-math / cann-cmake third_party graph) and assert on the produced
components, observations, typed edges, environment tools, and warnings.

Covered against the ops-math reference graph:
  • protobuf 25.1 -> 3.13.0 patched identity + protobuf -> abseil-cpp DEPENDS edge
  • eigen / json / gtest external projects, URL_HASH / TLS / no-hash findings
  • find_package() with conditions + requiredness (securec non-REQUIRED)
  • version.cmake set_cann_* package deps via profile.package_metadata
  • build tooling (cann-cmake) via profile.build_tooling
  • torch_extension reachability=unreachable + dead_config_flag
  • raw link-token classification (drop flags/genexprs/local; emit externals)
  • program/tool classifier -> EnvironmentTool vs domain-tool observation
  • every Observation/DependencyEdge carries root_artifact_id + source_revision
  • effective_cmake_root drives macro/include resolution
"""

from __future__ import annotations

from pathlib import Path

import pytest

import _cpp_stubs  # noqa: F401  (installs config/parse stubs if absent)

from sbom.cmake import parse
from sbom.config import Config
from sbom.collectors import cpp
from sbom.models import (
    ActivationCondition,
    CmakeAuthority,
    CmakeAuthorityBranch,
    Component,
    DeclarationReachability,
    FindPackageInfo,
    Identity,
    IntegrityFinding,
    Observation,
    Patch,
    RefKind,
    RelationType,
    SourceKind,
    Subject,
    SubjectKind,
    SubjectRole,
    UsageScope,
    VcsRef,
    Warning,
)
from sbom.profile import Profile


# ---------------------------------------------------------------------------
# Fixtures: a primary subject + authority + a profile we can configure
# ---------------------------------------------------------------------------


@pytest.fixture
def authority(tmp_path):
    root = tmp_path / "cann-cmake"
    root.mkdir()
    return CmakeAuthority(
        branch=CmakeAuthorityBranch.TARBALL,
        effective_cmake_root=root,
        ref="master-016",
        revision="abc123",
    )


@pytest.fixture
def primary():
    return Subject(
        id="ops_math",
        identity=Identity(
            kind=SubjectKind.CANN_PACKAGE, name="ops_math", version="9.0.0"
        ),
        role=SubjectRole.PRIMARY,
        source_path="",
    )


def _config(tmp_path):
    return Config(repo_root=tmp_path)


class _StubProfile(Profile):
    """A profile whose hooks we drive from the test."""

    name = "stub"

    def __init__(
        self,
        *,
        macros=None,
        pkg_obs=None,
        tooling=None,
        tooling_warnings=None,
    ):
        self._macros = macros or {}
        self._pkg_obs = pkg_obs or []
        self._tooling = tooling or []
        self._tooling_warnings = tooling_warnings or []

    def custom_dep_macros(self):
        return self._macros

    def package_metadata(self, repo_root, authority):
        return self._pkg_obs

    def build_tooling(self, repo_root, authority):
        return (self._tooling, self._tooling_warnings)


# ---------------------------------------------------------------------------
# parse-record factories (work with real OR stub parse module)
# ---------------------------------------------------------------------------


def _cmake_file(path, **kw):
    return parse.CMakeFile(path=Path(path), **kw)


def _ep(name, **kw):
    """Build an ExternalProject filling every required field with a default."""
    defaults = dict(
        source_version=None,
        set_version=None,
        canonical_url=None,
        resolved_url_or_path=None,
        url_hash=None,
        tls_verify=None,
        git_repository=None,
        git_tag=None,
        vcs_ref=None,
    )
    defaults.update(kw)
    return parse.ExternalProject(name=name, **defaults)


def _fc(name, **kw):
    defaults = dict(
        canonical_url=None,
        resolved_url_or_path=None,
        url_hash=None,
        git_repository=None,
        git_tag=None,
        vcs_ref=None,
    )
    defaults.update(kw)
    return parse.FetchContentDecl(name=name, **defaults)


def _link(raw, **kw):
    kw.setdefault("target_property", None)
    return parse.LinkLibraryToken(raw=raw, **kw)


def _patch(seq, monkeypatch, files_by_entry):
    """Monkeypatch parse.parse_recursive to return canned files per entry."""

    def fake(entry, effective_cmake_root, *, custom_macros=None):
        seq.append((Path(entry), effective_cmake_root, custom_macros))
        return files_by_entry

    monkeypatch.setattr(parse, "parse_recursive", fake)


# ---------------------------------------------------------------------------
# protobuf patched identity + protobuf -> abseil-cpp DEPENDS edge
# ---------------------------------------------------------------------------


def test_protobuf_patched_identity_and_abseil_depends_edge(
    tmp_path, authority, primary, monkeypatch
):
    primary.source_path = ""
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")

    protobuf_ep = _ep(
        "protobuf",
        source_version="25.1",
        set_version="3.13.0",
        resolved_url_or_path="https://example/protobuf-25.1.tar.gz",
        tls_verify=False,
        patches=[Patch(file="protobuf_25.1_change_version.patch", sha256="deadbeef")],
        depends=["abseil_build"],
        integrity_findings=[
            IntegrityFinding.NO_HASH,
            IntegrityFinding.TLS_VERIFICATION_DISABLED,
        ],
    )
    cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "protobuf.cmake",
        external_projects=[protobuf_ep],
    )
    seq = []
    _patch(seq, monkeypatch, [cf])

    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])

    # patched identity preserved separately
    pb = _find_component(result, "protobuf")
    assert pb.source_version == "25.1"
    assert pb.effective_version == "3.13.0"
    assert pb.patches and pb.patches[0].file.endswith("change_version.patch")
    assert IntegrityFinding.TLS_VERIFICATION_DISABLED in pb.integrity_findings
    assert IntegrityFinding.NO_HASH in pb.integrity_findings

    # subject -> protobuf edge
    subj_edges = [
        e
        for e in result.edges
        if e.from_ref.kind == RefKind.SUBJECT
        and e.to_ref.id == "protobuf"
    ]
    assert subj_edges and subj_edges[0].root_artifact_id == "ops_math"
    assert subj_edges[0].source_revision == "abc123"

    # protobuf -> abseil-cpp transitive (component -> component) DEPENDS edge
    cc_edges = [
        e
        for e in result.edges
        if e.from_ref.kind == RefKind.COMPONENT
        and e.from_ref.id == "protobuf"
        and e.to_ref.id == "abseil-cpp"
    ]
    assert cc_edges, "expected protobuf -> abseil-cpp component edge"
    assert cc_edges[0].relation_type == RelationType.DEPENDS_ON
    assert cc_edges[0].root_artifact_id == "ops_math"


# ---------------------------------------------------------------------------
# Authority drives macro/include resolution (effective_cmake_root, not raw)
# ---------------------------------------------------------------------------


def test_uses_effective_cmake_root_for_resolution(
    tmp_path, authority, primary, monkeypatch
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    macros = {"add_cann_third_party": object()}
    cf = _cmake_file(authority.effective_cmake_root / "x.cmake")
    seq = []
    _patch(seq, monkeypatch, [cf])

    cpp.collect(_config(tmp_path), _StubProfile(macros=macros), authority, [primary])

    assert seq, "parse_recursive should be called"
    _entry, eff_root, custom = seq[0]
    assert eff_root == authority.effective_cmake_root
    assert custom is macros


# ---------------------------------------------------------------------------
# json: URL_HASH present -> checksum; FetchContent path
# ---------------------------------------------------------------------------


def test_fetch_content_and_url_hash(tmp_path, authority, primary, monkeypatch):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    fc = _fc(
        "makeself",
        url_hash="bfa730a5",
        resolved_url_or_path="https://example/makeself.tar.gz",
    )
    cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "makeself-fetch.cmake",
        fetch_contents=[fc],
    )
    _patch([], monkeypatch, [cf])

    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    comp = _find_component(result, "makeself")
    assert comp.checksums.get("sha256") == "bfa730a5"
    obs = comp.observations[0]
    assert obs.source_kind == SourceKind.CMAKE_FETCH_CONTENT
    assert obs.root_artifact_id == "ops_math"


# ---------------------------------------------------------------------------
# find_package with conditions + requiredness
# ---------------------------------------------------------------------------


def test_find_package_requiredness_and_conditions(
    tmp_path, authority, primary, monkeypatch
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    securec = parse.FindPackageCall(
        name="securec",
        info=FindPackageInfo(required=False, quiet=None, effective_required=None),
    )
    dlog = parse.FindPackageCall(
        name="dlog",
        info=FindPackageInfo(required=True),
    )
    cf = _cmake_file(
        authority.effective_cmake_root / "dependencies.cmake",
        find_packages=[securec, dlog],
    )
    _patch([], monkeypatch, [cf])

    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])

    fp_obs = [
        o for o in result.observations if o.source_kind == SourceKind.CMAKE_FIND_PACKAGE
    ]
    by_required = [o.find_package.required for o in fp_obs]
    assert False in by_required, "securec is non-REQUIRED"
    assert True in by_required, "dlog is REQUIRED"
    # find_package observations + their edges carry root ownership
    for o in fp_obs:
        assert o.root_artifact_id == "ops_math"
        assert o.source_revision == "abc123"
    fp_edges = [e for e in result.edges if e.to_ref.id in ("securec", "dlog")]
    assert {e.to_ref.id for e in fp_edges} == {"securec", "dlog"}


# ---------------------------------------------------------------------------
# package_metadata (version.cmake set_cann_*) -> observations + edges
# ---------------------------------------------------------------------------


def test_package_metadata_hook(tmp_path, authority, primary, monkeypatch):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    _patch([], monkeypatch, [])

    ge = Observation(
        source_kind=SourceKind.CANN_PACKAGE,
        source_file="version.cmake",
        version_constraint=">=8.5",
        usage_scope=UsageScope.BUILD,
        ecosystem_data={"component": "ge-compiler"},
    )
    profile = _StubProfile(pkg_obs=[ge])
    result = cpp.collect(_config(tmp_path), profile, authority, [primary])

    pkg_obs = [
        o for o in result.observations if o.source_kind == SourceKind.CANN_PACKAGE
    ]
    assert pkg_obs and pkg_obs[0].root_artifact_id == "ops_math"
    assert pkg_obs[0].source_revision == "abc123"
    edges = [e for e in result.edges if e.to_ref.id == "ge-compiler"]
    assert edges and edges[0].from_ref.id == "ops_math"
    assert edges[0].usage_scope == UsageScope.BUILD


# ---------------------------------------------------------------------------
# build_tooling (cann-cmake) hook -> component + tooling edge + warnings
# ---------------------------------------------------------------------------


def test_build_tooling_hook(tmp_path, authority, primary, monkeypatch):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    _patch([], monkeypatch, [])
    cann_cmake = Component(name="cann-cmake", source_version="master-016")
    warn = Warning(code="cmake_authority_input_ambiguous", subject="cann-cmake")
    profile = _StubProfile(tooling=[cann_cmake], tooling_warnings=[warn])

    result = cpp.collect(_config(tmp_path), profile, authority, [primary])

    assert _find_component(result, "cann-cmake") is cann_cmake
    tooling_edges = [
        e for e in result.edges if e.relation_type == RelationType.TOOLING
    ]
    assert tooling_edges and tooling_edges[0].to_ref.id == "cann-cmake"
    assert warn in result.warnings


# ---------------------------------------------------------------------------
# torch_extension reachability: dead_config_flag
# ---------------------------------------------------------------------------


def test_torch_extension_unreachable_dead_flag(
    tmp_path, authority, monkeypatch
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    torch_root = Subject(
        id="npu_math_extension",
        identity=Identity(
            kind=SubjectKind.CMAKE_PROJECT, name="torch_ext", version=None
        ),
        role=SubjectRole.SIBLING_ARTIFACT,
        source_path="",
    )
    torch_fp = parse.FindPackageCall(
        name="Torch",
        info=FindPackageInfo(required=True),
        conditions=[ActivationCondition(expr="ENABLE_TORCH_EXTENSION")],
    )
    cf = _cmake_file(
        authority.effective_cmake_root / "torch_extension.cmake",
        find_packages=[torch_fp],
    )
    _patch([], monkeypatch, [cf])

    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [torch_root])
    obs = [o for o in result.observations if o.source_kind == SourceKind.CMAKE_FIND_PACKAGE]
    assert obs
    torch_obs = obs[0]
    assert torch_obs.declaration_reachability == DeclarationReachability.UNREACHABLE
    assert torch_obs.unreachable_reason == "dead_config_flag"
    # ownership stays with the torch root, NOT ops_math
    assert torch_obs.root_artifact_id == "npu_math_extension"
    edge = [e for e in result.edges if e.to_ref.id == "Torch"][0]
    assert edge.declaration_reachability == DeclarationReachability.UNREACHABLE


# ---------------------------------------------------------------------------
# Raw link-token classification table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expect_emit",
    [
        ("-Wl,-z,relro", False),     # linker flag dropped
        ("$<TARGET_OBJECTS:foo>", False),  # genexpr dropped
        ("local_tgt", False),        # local target (in local_targets) not external
        ("torch_npu", True),         # external library emitted
        ("ascendcl", True),
    ],
)
def test_link_token_classification(
    tmp_path, authority, monkeypatch, raw, expect_emit
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    root = Subject(
        id="st_root",
        identity=Identity(kind=SubjectKind.CMAKE_PROJECT, name="st_root"),
        role=SubjectRole.ST_TEST,
        source_path="",
    )
    tok = _link(raw)
    cf = _cmake_file(
        authority.effective_cmake_root / "tests" / "st" / "CMakeLists.txt",
        link_tokens=[tok],
        add_dependencies=[parse.AddDependenciesEdge(target="local_tgt", depends_on=[])],
    )
    _patch([], monkeypatch, [cf])

    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [root])
    link_edges = [e for e in result.edges if e.relation_type == RelationType.LINK]
    emitted = {e.to_ref.id for e in link_edges}
    if expect_emit:
        assert raw in emitted  # the external link token IS emitted as a LINK edge
        # ST root deps stay owned by the ST root
        for e in link_edges:
            assert e.root_artifact_id == "st_root"
            assert e.usage_scope == UsageScope.ST_TEST
    else:
        assert raw not in emitted


# ---------------------------------------------------------------------------
# Program/tool classifier: generic host tool -> EnvironmentTool (never component)
# ---------------------------------------------------------------------------


def test_program_classifier_environment_tool(
    tmp_path, authority, primary, monkeypatch
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    perl = parse.ProgramInvocation(
        name="perl",
        command_context="execute_process",
        required=True,
        source_file="openssl.cmake",
    )
    cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "openssl.cmake",
        programs=[perl],
    )
    _patch([], monkeypatch, [cf])

    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    assert result.environment_tools, "perl must become an EnvironmentTool"
    tool = result.environment_tools[0]
    assert tool.name == "perl"
    assert tool.root_artifact_id == "ops_math"
    assert tool.source_revision == "abc123"
    assert tool.source_authority == "cann-cmake"
    # perl is NOT a component
    assert not any(c.name == "perl" for c in result.components)


def test_program_classifier_domain_tool_observation(
    tmp_path, authority, primary, monkeypatch
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    protoc = parse.ProgramInvocation(
        name="host_protoc",
        command_context="find_program",
        path="/cache/protoc",
        source_file="protobuf.cmake",
    )
    cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "protobuf.cmake",
        programs=[protoc],
    )
    _patch([], monkeypatch, [cf])

    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    # domain tool -> observation, NOT an EnvironmentTool
    prog_obs = [
        o
        for o in result.observations
        if o.source_kind
        in (SourceKind.CMAKE_FIND_PROGRAM, SourceKind.CMAKE_IMPORTED_EXECUTABLE)
    ]
    assert prog_obs and prog_obs[0].ecosystem_data.get("program") == "host_protoc"
    assert not any(t.name == "host_protoc" for t in result.environment_tools)


# ---------------------------------------------------------------------------
# add_dependencies() -> component -> component edge
# ---------------------------------------------------------------------------


def test_add_dependencies_edges(tmp_path, authority, primary, monkeypatch):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "abseil-cpp.cmake",
        add_dependencies=[
            parse.AddDependenciesEdge(
                target="ascend_protobuf", depends_on=["protobuf_shared_build"]
            )
        ],
    )
    _patch([], monkeypatch, [cf])
    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    cc = [
        e
        for e in result.edges
        if e.from_ref.kind == RefKind.COMPONENT
        and e.to_ref.kind == RefKind.COMPONENT
    ]
    assert cc and cc[0].from_ref.id == "ascend_protobuf"
    assert cc[0].root_artifact_id == "ops_math"


# ---------------------------------------------------------------------------
# missing effective_cmake_root -> single-file fallback, no crash
# ---------------------------------------------------------------------------


def test_missing_effective_root_still_parses(tmp_path, primary, monkeypatch):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    auth = CmakeAuthority(
        branch=CmakeAuthorityBranch.SKIPPED_EXISTING_PROJECT,
        effective_cmake_root=None,
    )
    calls = []
    real = parse.parse_recursive
    monkeypatch.setattr(
        parse,
        "parse_recursive",
        lambda entry, root, **kw: (calls.append((entry, root)) or real(entry, root, **kw)),
    )
    result = cpp.collect(_config(tmp_path), _StubProfile(), auth, [primary])
    assert isinstance(result.components, list)
    # A missing effective root must not abort collection: parse_recursive is still
    # used (root=None) so macro_calls/plain includes are captured rather than lost.
    assert calls and all(root is None for _, root in calls)


# ---------------------------------------------------------------------------
# (a) NAME STASHING: find_package + program observations carry ['name']
# ---------------------------------------------------------------------------


def test_find_package_observation_stashes_name(
    tmp_path, authority, primary, monkeypatch
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    fp = parse.FindPackageCall(name="OPBASE", info=FindPackageInfo(required=True))
    cf = _cmake_file(
        authority.effective_cmake_root / "dependencies.cmake", find_packages=[fp]
    )
    _patch([], monkeypatch, [cf])
    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    fp_obs = [
        o for o in result.observations if o.source_kind == SourceKind.CMAKE_FIND_PACKAGE
    ]
    assert fp_obs and fp_obs[0].ecosystem_data.get("name") == "OPBASE"


def test_program_observation_stashes_name(
    tmp_path, authority, primary, monkeypatch
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    protoc = parse.ProgramInvocation(
        name="host_protoc",
        command_context="find_program",
        source_file="protobuf.cmake",
    )
    cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "protobuf.cmake",
        programs=[protoc],
    )
    _patch([], monkeypatch, [cf])
    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    prog_obs = [
        o
        for o in result.observations
        if o.source_kind
        in (SourceKind.CMAKE_FIND_PROGRAM, SourceKind.CMAKE_IMPORTED_EXECUTABLE)
    ]
    assert prog_obs
    # (g) host_protoc routes to the canonical 'protoc' tooling name, with the
    # raw spelling retained under 'program'.
    assert prog_obs[0].ecosystem_data.get("name") == "protoc"
    assert prog_obs[0].ecosystem_data.get("program") == "host_protoc"


def test_external_project_observation_stashes_name(
    tmp_path, authority, primary, monkeypatch
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "eigen.cmake",
        external_projects=[_ep("eigen")],
    )
    _patch([], monkeypatch, [cf])
    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    eigen = _find_component(result, "eigen")
    assert eigen.observations[0].ecosystem_data.get("name") == "eigen"


# ---------------------------------------------------------------------------
# (b) EDGE HYGIENE: drop self-loops + de-duplicate
# ---------------------------------------------------------------------------


def test_edge_self_loops_dropped(tmp_path, authority, primary, monkeypatch):
    """protobuf_src DEPENDS protobuf_host_build both collapse to 'protobuf' ->
    a protobuf->protobuf self-loop that must be dropped."""
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    pb = _ep("protobuf", depends=["protobuf_host_build"])  # collapses to protobuf
    cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "protobuf.cmake",
        external_projects=[pb],
    )
    _patch([], monkeypatch, [cf])
    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    self_loops = [
        e
        for e in result.edges
        if e.from_ref.kind == e.to_ref.kind and e.from_ref.id == e.to_ref.id
    ]
    assert not self_loops


def test_duplicate_edges_deduped(tmp_path, authority, primary, monkeypatch):
    """The same subject->component edge declared in two files collapses to one."""
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    cf1 = _cmake_file(
        authority.effective_cmake_root / "a.cmake",
        find_packages=[parse.FindPackageCall(name="dlog", info=FindPackageInfo())],
    )
    cf2 = _cmake_file(
        authority.effective_cmake_root / "b.cmake",
        find_packages=[parse.FindPackageCall(name="dlog", info=FindPackageInfo())],
    )
    _patch([], monkeypatch, [cf1, cf2])
    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    dlog_edges = [e for e in result.edges if e.to_ref.id == "dlog"]
    assert len(dlog_edges) == 1


def test_clean_edges_preserves_usage_scope_variants():
    # A runtime vs. build variant of the SAME edge must NOT be collapsed (the
    # dedup key includes usage_scope) — only exact same-scope duplicates collapse.
    from sbom.collectors.cpp import _clean_edges
    from sbom.models import DependencyEdge, Ref, RefKind, RelationType, UsageScope

    def _edge(scope):
        return DependencyEdge(
            root_artifact_id="m",
            from_ref=Ref(RefKind.SUBJECT, "m"),
            to_ref=Ref(RefKind.COMPONENT, "dlog"),
            relation_type=RelationType.LINK,
            usage_scope=scope,
        )

    out = _clean_edges([_edge(UsageScope.RUNTIME), _edge(UsageScope.BUILD), _edge(UsageScope.RUNTIME)])
    assert len(out) == 2  # runtime + build kept; the duplicate runtime collapsed
    assert {e.usage_scope for e in out} == {UsageScope.RUNTIME, UsageScope.BUILD}


# ---------------------------------------------------------------------------
# (c) PER-OBSERVATION source_revision: cann-cmake ref vs repo git rev
# ---------------------------------------------------------------------------


def test_per_observation_source_revision(
    tmp_path, authority, primary, monkeypatch
):
    """A fragment under effective_cmake_root carries the cann-cmake ref; a file
    under repo_root carries the repo git rev (mocked)."""
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    monkeypatch.setattr(cpp, "_git_describe", lambda root: "repo-rev-123")

    cmake_cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "eigen.cmake",
        external_projects=[_ep("eigen")],
    )
    repo_cf = _cmake_file(
        tmp_path / "cmake" / "dependencies.cmake",
        find_packages=[parse.FindPackageCall(name="dlog", info=FindPackageInfo())],
    )
    _patch([], monkeypatch, [cmake_cf, repo_cf])
    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])

    eigen = _find_component(result, "eigen")
    assert eigen.observations[0].source_revision == "abc123"  # cann-cmake revision
    dlog_obs = [
        o
        for o in result.observations
        if o.ecosystem_data.get("name") == "dlog"
    ]
    assert dlog_obs and dlog_obs[0].source_revision == "repo-rev-123"


# ---------------------------------------------------------------------------
# (d) gtest two-axis: call-site scope + macro gate on the fragment observation
# ---------------------------------------------------------------------------


def test_two_axis_call_site_scope_and_gate(
    tmp_path, authority, primary, monkeypatch
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    gate = ActivationCondition(expr="TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD")
    cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "gtest.cmake",
        external_projects=[_ep("gtest")],
        included_by=authority.effective_cmake_root / "ut.cmake",
        call_site_conditions=[gate],
    )
    _patch([], monkeypatch, [cf])
    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    gtest = _find_component(result, "gtest")
    obs = gtest.observations[0]
    # usage_scope derives from the including file (ut.cmake -> test)
    assert obs.usage_scope == UsageScope.TEST
    # the macro gate travels onto the observation's activation_condition
    assert any(
        "TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD" == c.expr
        for c in obs.activation_condition
    )


# ---------------------------------------------------------------------------
# (e) opbase local_source_unverified finding attaches to the component
# ---------------------------------------------------------------------------


def test_opbase_local_source_unverified_attached(
    tmp_path, authority, primary, monkeypatch
):
    (tmp_path / "CMakeLists.txt").write_text("project(math)\n")
    fc = _fc("opbase", git_repository="https://x/opbase.git", git_tag="b92c2c8")
    cf = _cmake_file(
        authority.effective_cmake_root / "third_party" / "opbase.cmake",
        fetch_contents=[fc],
        integrity_findings={
            "opbase": [IntegrityFinding.LOCAL_SOURCE_UNVERIFIED]
        },
    )
    _patch([], monkeypatch, [cf])
    result = cpp.collect(_config(tmp_path), _StubProfile(), authority, [primary])
    opbase = _find_component(result, "opbase")
    assert IntegrityFinding.LOCAL_SOURCE_UNVERIFIED in opbase.integrity_findings


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _find_component(result, name) -> Component:
    for c in result.components:
        if c.name == name:
            return c
    raise AssertionError(f"component {name!r} not found in {[c.name for c in result.components]}")
