"""Emit/validate tests for :mod:`sbom.emit.cyclonedx`, ``spdx`` and ``validate``.

Builds a small reconciled :class:`~sbom.models.Document` (two subjects, a patched
component, a transitive component, an :class:`~sbom.models.EnvironmentTool`, and
typed :class:`~sbom.models.DependencyEdge` endpoints), emits both formats, parses
them back, and asserts:

* the design's field-mapping fields survive emission,
* both libraries' own validators report no issues,
* reproducible output is byte-identical across two runs,
* an ``EnvironmentTool`` is NEVER rendered as a component/Package.
"""

from __future__ import annotations

import json

import pytest

from sbom.emit import EmitOptions
from sbom.emit import cyclonedx, spdx, validate
from sbom.models import (
    ActivationCondition,
    CommandContext,
    Component,
    DeclarationReachability,
    DependencyEdge,
    Document,
    EnvironmentTool,
    Facet,
    FindPackageInfo,
    Identity,
    IntegrityFinding,
    Observation,
    Patch,
    Ref,
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

REPRO_OPTS = EmitOptions(reproducible=True, source_date_epoch=1_700_000_000)
# The default detail level is "compact" (no per-observation sbomgen:obs:* and no
# evidence.occurrences). Tests that assert the verbose per-observation provenance
# request --detail full explicitly.
REPRO_FULL = EmitOptions(
    reproducible=True, source_date_epoch=1_700_000_000, detail="full"
)


def _all_spdx_annotation_comments(spd: dict) -> list[str]:
    """Collect annotation comments from the document AND every package.

    spdx-tools' JSON writer routes an annotation to its target element, so a
    package-targeted annotation is nested under that package's ``annotations``
    while document-targeted ones (env tools) stay at the top level.
    """
    comments = [a["comment"] for a in spd.get("annotations", [])]
    for pkg in spd.get("packages", []):
        comments.extend(a["comment"] for a in pkg.get("annotations", []))
    return comments


# ---------------------------------------------------------------------------
# Fixture document
# ---------------------------------------------------------------------------


@pytest.fixture
def document() -> Document:
    primary = Subject(
        id="ops_math",
        identity=Identity(SubjectKind.CANN_PACKAGE, "ops_math", "9.0.0"),
        role=SubjectRole.PRIMARY,
        license="LicenseRef-CANN-Open-Software-License-2.0",
        license_text="CANN Open Software License 2.0 — full text here.",
        facets=[Facet(SubjectKind.CMAKE_PROJECT, "math", "1.0.0")],
        repo_revision="abc123def",
        dependency_scopes=[UsageScope.RUNTIME, UsageScope.TEST],
    )
    sibling = Subject(
        id="ascend_ops",
        identity=Identity(SubjectKind.PYTHON_WHEEL, "ascend_ops", "1.0.0"),
        role=SubjectRole.SIBLING_ARTIFACT,
    )
    # A grouping-only root that must NOT appear as a Package/metadata subject.
    grouping = Subject(
        id="st_root",
        identity=Identity(SubjectKind.CMAKE_PROJECT, "st_root", "0.1"),
        role=SubjectRole.NON_DISTRIBUTABLE_TEST,
        emit_as_subject=False,
    )

    protobuf = Component(
        name="protobuf",
        type="library",
        languages=["cpp"],
        scopes=[UsageScope.RUNTIME],
        source_version="25.1",
        effective_version="3.13.0",
        patches=[Patch(file="protobuf_25.1_change_version.patch", sha256="de" * 32)],
        checksums={"sha256": "ab" * 32},
        license="BSD-3-Clause",
        integrity_findings=[
            IntegrityFinding.NO_HASH,
            IntegrityFinding.TLS_VERIFICATION_DISABLED,
        ],
        completeness={"python_transitives": "unresolved"},
        vcs_ref=VcsRef(requested="v25.1", resolved_commit="cafe" * 10),
        aliases=["protocolbuffers"],
        observations=[
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                source_file="cmake/third_party/protobuf.cmake",
                source_revision="master-016",
                root_artifact_id="ops_math",
                usage_scope=UsageScope.RUNTIME,
                canonical_url="https://github.com/protocolbuffers/protobuf/archive/v25.1.tar.gz",
                resolved_url_or_path="/cache/protobuf-25.1.tar.gz",
                activation_condition=[ActivationCondition(expr="TOPLEVEL_PROJECT")],
                find_package=FindPackageInfo(required=False, effective_required=True),
            )
        ],
    )
    abseil = Component(
        name="abseil-cpp",
        scopes=[UsageScope.RUNTIME],
        source_version="20230802.1",
        license="Apache-2.0",
        observations=[
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                source_file="cmake/third_party/abseil-cpp.cmake",
                source_revision="master-016",
                root_artifact_id="ops_math",
            )
        ],
    )
    # A component with a non-SPDX license carried as inline text.
    securec = Component(
        name="securec",
        scopes=[UsageScope.BUILD],
        license="Huawei Secure C Library License",
        observations=[
            Observation(
                source_kind=SourceKind.PYTHON_BUILD,
                source_file="setup.py",
                root_artifact_id="ascend_ops",
                usage_scope=UsageScope.BUILD,
            )
        ],
    )

    edges = [
        DependencyEdge(
            root_artifact_id="ops_math",
            from_ref=Ref(RefKind.SUBJECT, "ops_math"),
            to_ref=Ref(RefKind.COMPONENT, "protobuf"),
            relation_type=RelationType.DEPENDS_ON,
            usage_scope=UsageScope.RUNTIME,
        ),
        DependencyEdge(
            root_artifact_id="ops_math",
            from_ref=Ref(RefKind.COMPONENT, "protobuf"),
            to_ref=Ref(RefKind.COMPONENT, "abseil-cpp"),
            relation_type=RelationType.DEPENDS_ON,
        ),
        DependencyEdge(
            root_artifact_id="ascend_ops",
            from_ref=Ref(RefKind.SUBJECT, "ascend_ops"),
            to_ref=Ref(RefKind.COMPONENT, "securec"),
            relation_type=RelationType.BUILD_DEPENDENCY_OF,
            usage_scope=UsageScope.BUILD,
        ),
    ]
    tool = EnvironmentTool(
        name="perl",
        path="/usr/bin/perl",
        required=True,
        source_file="cmake/third_party/openssl.cmake",
        source_revision="master-016",
        source_authority="cann-cmake",
        command_context=CommandContext.FIND_PROGRAM,
        root_artifact_id="ops_math",
        activation_condition=[ActivationCondition(expr="ENABLE_SSL")],
    )
    return Document(
        subjects=[primary, sibling, grouping],
        components=[protobuf, abseil, securec],
        edges=edges,
        environment_tools=[tool],
        metadata={"generated_by": "sbom-gen-test"},
    )


# ---------------------------------------------------------------------------
# Validation passes
# ---------------------------------------------------------------------------


def test_cyclonedx_validates(document):
    text = cyclonedx.emit(document, REPRO_OPTS)
    assert validate.validate_cyclonedx(text) == []


def test_spdx_validates(document):
    text = spdx.emit(document, REPRO_OPTS)
    assert validate.validate_spdx(text) == []


# ---------------------------------------------------------------------------
# Reproducible output is byte-identical
# ---------------------------------------------------------------------------


def test_cyclonedx_reproducible_byte_identical(document):
    a = cyclonedx.emit(document, REPRO_OPTS)
    b = cyclonedx.emit(document, REPRO_OPTS)
    assert a == b
    # serialNumber is content-derived (stable), not random.
    assert json.loads(a)["serialNumber"].startswith("urn:uuid:")


def test_spdx_reproducible_byte_identical(document):
    a = spdx.emit(document, REPRO_OPTS)
    b = spdx.emit(document, REPRO_OPTS)
    assert a == b
    # documentNamespace is content-derived, stable across runs.
    assert "spdxdocs/sbom-gen" in json.loads(a)["documentNamespace"]


def test_cyclonedx_serial_number_changes_with_content(document):
    base = json.loads(cyclonedx.emit(document, REPRO_OPTS))["serialNumber"]
    document.components[0].effective_version = "9.9.9"
    changed = json.loads(cyclonedx.emit(document, REPRO_OPTS))["serialNumber"]
    assert base != changed


# ---------------------------------------------------------------------------
# Field survival — CycloneDX
# ---------------------------------------------------------------------------


def test_cyclonedx_identity_purl_and_subjects(document):
    bom = json.loads(cyclonedx.emit(document, REPRO_OPTS))
    assert bom["metadata"]["component"]["name"] == "ops_math"
    assert bom["metadata"]["component"]["purl"].startswith("pkg:generic/ops_math")
    names = {c["name"] for c in bom["components"]}
    # sibling subject is a component; grouping-only subject is NOT emitted.
    assert "ascend_ops" in names
    assert "st_root" not in names


def test_cyclonedx_pedigree_patches_and_hashes(document):
    bom = json.loads(cyclonedx.emit(document, REPRO_OPTS))
    pc = next(c for c in bom["components"] if c["name"] == "protobuf")
    assert pc["version"] == "3.13.0"  # effective_version
    assert pc["hashes"][0] == {"alg": "SHA-256", "content": "ab" * 32}
    ped = pc["pedigree"]
    assert ped["ancestors"][0]["version"] == "25.1"  # source_version
    assert "patched build" in ped["notes"]
    assert ped["patches"][0]["diff"]["url"] == "protobuf_25.1_change_version.patch"
    assert "de" * 32 in ped["patches"][0]["diff"]["text"]["content"]


def test_cyclonedx_external_references_urls(document):
    bom = json.loads(cyclonedx.emit(document, REPRO_OPTS))
    pc = next(c for c in bom["components"] if c["name"] == "protobuf")
    urls = {r["url"] for r in pc["externalReferences"]}
    assert any("protobuf/archive/v25.1" in u for u in urls)
    assert any("cafecafe" in u for u in urls)  # vcs_ref resolved_commit
    # The bare local resolved_url_or_path ("/cache/...") is NOT a URL and must not
    # be emitted as a distribution externalReference.
    assert "/cache/protobuf-25.1.tar.gz" not in urls


def test_cyclonedx_unexpanded_cmake_var_not_emitted_as_url():
    """An unexpanded ${CANN_3RD_LIB_PATH}/... cache path must never reach a URL
    field (it would serialize as percent-encoded $%7B...%7D junk). Only the real
    canonical_url survives as a distribution externalReference; the raw template
    stays available as sbomgen:obs provenance only."""
    comp = Component(
        name="eigen",
        scopes=[UsageScope.RUNTIME],
        observations=[
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                source_file="cmake/third_party/eigen.cmake",
                canonical_url="https://gitcode.com/cann-src-third-party/eigen/eigen-5.0.0.tar.gz",
                resolved_url_or_path="${CANN_3RD_LIB_PATH}/eigen-5.0.0.tar.gz",
            )
        ],
    )
    subj = Subject(
        id="ops_math",
        identity=Identity(SubjectKind.CANN_PACKAGE, "ops_math", "9.0.0"),
        role=SubjectRole.PRIMARY,
    )
    doc = Document(
        subjects=[subj],
        components=[comp],
        edges=[],
        environment_tools=[],
        warnings=[],
        metadata={},
    )
    raw = cyclonedx.emit(doc, REPRO_OPTS)
    assert "%7B" not in raw  # the exact reported symptom is gone
    bom = json.loads(raw)
    eigen = next(c for c in bom["components"] if c["name"] == "eigen")
    urls = {r["url"] for r in eigen.get("externalReferences", [])}
    assert urls == {"https://gitcode.com/cann-src-third-party/eigen/eigen-5.0.0.tar.gz"}
    assert validate.validate_cyclonedx(raw) == []


def test_nonstandard_license_id_routes_to_licenseref_and_validates():
    """A component license that looks like an SPDX id but isn't a real one (e.g.
    'MPL2' from a Notice) must not be emitted verbatim -- it routes to a
    LicenseRef so both formats stay valid."""
    comp = Component(
        name="eigen",
        scopes=[UsageScope.RUNTIME],
        license="MPL2",
        observations=[
            Observation(source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT, source_file="x.cmake")
        ],
    )
    subj = Subject(
        id="ops_nn",
        identity=Identity(SubjectKind.CANN_PACKAGE, "ops_nn", "9.0.0"),
        role=SubjectRole.PRIMARY,
    )
    doc = Document(
        subjects=[subj],
        components=[comp],
        edges=[],
        environment_tools=[],
        warnings=[],
        metadata={},
    )
    assert validate.validate_cyclonedx(cyclonedx.emit(doc, REPRO_OPTS)) == []
    assert validate.validate_spdx(spdx.emit(doc, REPRO_OPTS)) == []
    # SPDX carries it as an extracted LicenseRef, not a bare 'MPL2' license id.
    spd = json.loads(spdx.emit(doc, REPRO_OPTS))
    pkg = next(p for p in spd["packages"] if p["name"] == "eigen")
    assert pkg["licenseConcluded"].startswith("LicenseRef-")


def test_component_licenseref_self_registers_in_spdx():
    # A component citing a bare LicenseRef that NO subject provides must still emit
    # a hasExtractedLicensingInfos entry, or the document is invalid (review A2).
    subj = Subject(
        id="p", identity=Identity(SubjectKind.CANN_PACKAGE, "p", "1.0"),
        role=SubjectRole.PRIMARY,  # NOASSERTION -> does not register the ref
    )
    comp = Component(
        name="opbase", scopes=[UsageScope.RUNTIME],
        license="LicenseRef-CANN-Open-Software-License-2.0",
        observations=[Observation(source_kind=SourceKind.CANN_PACKAGE, source_file="v.cmake")],
    )
    doc = Document(subjects=[subj], components=[comp], edges=[], environment_tools=[],
                   warnings=[], metadata={})
    raw = spdx.emit(doc, REPRO_OPTS)
    assert validate.validate_spdx(raw) == []
    spd = json.loads(raw)
    refs = {e["licenseId"] for e in spd.get("hasExtractedLicensingInfos", [])}
    assert "LicenseRef-CANN-Open-Software-License-2.0" in refs


def test_component_spdxids_disambiguated_on_slug_collision():
    # 'foo/bar' and 'foo-bar' slug to the same SPDXRef-Package-foo-bar (review A3),
    # AND the harder cases the verifier found: a 3-way collision where the '-2'
    # form itself collides, and a '-source' pedigree id colliding with a sibling
    # named 'foo-source'. The shared-namespace claim() must keep ALL ids unique.
    subj = Subject(id="p", identity=Identity(SubjectKind.CANN_PACKAGE, "p", "1.0"),
                   role=SubjectRole.PRIMARY)
    comps = [
        Component(name="foo/bar", scopes=[UsageScope.RUNTIME], license="MIT"),
        Component(name="foo-bar", scopes=[UsageScope.RUNTIME], license="MIT"),
        Component(name="foo-bar-2", scopes=[UsageScope.RUNTIME], license="MIT"),
        # patched component -> emits a 'SPDXRef-Package-foo-source' pedigree pkg
        Component(name="foo", scopes=[UsageScope.RUNTIME], license="MIT",
                  source_version="1.0", effective_version="2.0",
                  patches=[Patch(file="p.patch", sha256="ab" * 32)]),
        Component(name="foo-source", scopes=[UsageScope.RUNTIME], license="MIT"),
    ]
    doc = Document(subjects=[subj], components=comps, edges=[], environment_tools=[],
                   warnings=[], metadata={})
    raw = spdx.emit(doc, REPRO_OPTS)
    assert validate.validate_spdx(raw) == []
    ids = [p["SPDXID"] for p in json.loads(raw)["packages"]]
    assert len(ids) == len(set(ids)), ids  # every SPDXID unique (incl. -source)


def test_emit_split_skips_non_emittable_subjects():
    # An ownership-only grouping root (emit_as_subject=False) must not get its own
    # split doc (it would be packages with no DESCRIBES -> invalid SPDX).
    keep = Subject(id="w", identity=Identity(SubjectKind.PYTHON_WHEEL, "w", "1.0"),
                   role=SubjectRole.PRIMARY)
    grouping = Subject(id="ex", identity=Identity(SubjectKind.PYTHON_WHEEL, "ex", "1.0"),
                       role=SubjectRole.MANUAL_EXAMPLE, emit_as_subject=False)
    doc = Document(subjects=[keep, grouping], components=[], edges=[],
                   environment_tools=[], warnings=[], metadata={})
    sp = spdx.emit_split(doc, REPRO_OPTS)
    cd = cyclonedx.emit_split(doc, REPRO_OPTS)
    assert set(sp) == {"w"} and set(cd) == {"w"}
    assert all(validate.validate_spdx(t) == [] for t in sp.values())


def test_emit_split_isolates_subject_closures():
    # Two independent subjects; dep2 belongs ONLY to app2's closure. Each split BOM
    # must contain only its own subject's dependency closure (no cross-leak).
    app1 = Subject(id="app1", identity=Identity(SubjectKind.PYTHON_WHEEL, "app1", "1.0"),
                   role=SubjectRole.PRIMARY)
    app2 = Subject(id="app2", identity=Identity(SubjectKind.PYTHON_WHEEL, "app2", "1.0"),
                   role=SubjectRole.PRIMARY)
    dep1 = Component(name="dep1", languages=["Python"])
    dep2 = Component(name="dep2", languages=["Python"])
    edges = [
        DependencyEdge(root_artifact_id="app1", from_ref=Ref(RefKind.SUBJECT, "app1"),
                       to_ref=Ref(RefKind.COMPONENT, "dep1"), relation_type=RelationType.DEPENDS_ON),
        DependencyEdge(root_artifact_id="app2", from_ref=Ref(RefKind.SUBJECT, "app2"),
                       to_ref=Ref(RefKind.COMPONENT, "dep2"), relation_type=RelationType.DEPENDS_ON),
    ]
    doc = Document(subjects=[app1, app2], components=[dep1, dep2], edges=edges,
                   environment_tools=[], warnings=[], metadata={})

    cd = cyclonedx.emit_split(doc, REPRO_OPTS)
    names1 = {c["name"] for c in json.loads(cd["app1"]).get("components", [])}
    names2 = {c["name"] for c in json.loads(cd["app2"]).get("components", [])}
    assert "dep1" in names1 and "dep2" not in names1
    assert "dep2" in names2 and "dep1" not in names2

    sp = spdx.emit_split(doc, REPRO_OPTS)
    pkgs1 = {p["name"] for p in json.loads(sp["app1"])["packages"]}
    assert "dep1" in pkgs1 and "dep2" not in pkgs1
    assert all(validate.validate_spdx(t) == [] for t in sp.values())


def test_emit_split_respects_edge_ownership_for_shared_component():
    # `shared` is depended on by BOTH apps; `shared -> app2_only` is OWNED by app2.
    # app1's split BOM must include `shared` but NOT app2_only (which it only
    # reaches by walking app2's exclusive edge through the shared node).
    app1 = Subject(id="app1", identity=Identity(SubjectKind.PYTHON_WHEEL, "app1", "1.0"),
                   role=SubjectRole.PRIMARY)
    app2 = Subject(id="app2", identity=Identity(SubjectKind.PYTHON_WHEEL, "app2", "1.0"),
                   role=SubjectRole.PRIMARY)
    shared = Component(name="shared", languages=["Python"])
    app2_only = Component(name="app2_only", languages=["Python"])

    def _e(root, frm_kind, frm, to):
        return DependencyEdge(root_artifact_id=root, from_ref=Ref(frm_kind, frm),
                              to_ref=Ref(RefKind.COMPONENT, to), relation_type=RelationType.DEPENDS_ON)

    doc = Document(
        subjects=[app1, app2], components=[shared, app2_only],
        edges=[
            _e("app1", RefKind.SUBJECT, "app1", "shared"),
            _e("app2", RefKind.SUBJECT, "app2", "shared"),
            _e("app2", RefKind.COMPONENT, "shared", "app2_only"),
        ],
        environment_tools=[], warnings=[], metadata={},
    )
    cd = cyclonedx.emit_split(doc, REPRO_OPTS)
    names1 = {c["name"] for c in json.loads(cd["app1"]).get("components", [])}
    names2 = {c["name"] for c in json.loads(cd["app2"]).get("components", [])}
    assert "shared" in names1 and "app2_only" not in names1
    assert {"shared", "app2_only"} <= names2


def test_split_output_basenames_sanitizes_and_disambiguates():
    from sbom.emit._common import split_output_basenames

    names = split_output_basenames(["../escaped", "/abs/path", "ops_math", "x/y", "x:y"])
    # No basename may carry a path separator, "..", or an absolute leader -> a
    # split write can never escape out_dir.
    for v in names.values():
        assert "/" not in v and "\\" not in v and ".." not in v
        assert not v.startswith((".", "/", "-"))
    assert names["ops_math"] == "ops_math"      # a clean, unique id is untouched
    assert names["../escaped"] == "escaped"     # traversal neutralized
    assert names["/abs/path"] == "abs_path"     # absolute leader neutralized
    # x/y and x:y both sanitize to x_y -> disambiguated to distinct names.
    assert names["x/y"] != names["x:y"]
    assert names["x/y"].startswith("x_y") and names["x:y"].startswith("x_y")


def test_emit_split_subject_ids_cannot_escape(tmp_path):
    # End-to-end: a malicious subject id does not produce an out-of-tree path.
    from sbom.emit._common import split_output_basenames

    base = split_output_basenames(["../../evil"])["../../evil"]
    written = tmp_path / f"{base}.cdx.json"
    written.write_text("{}")
    assert written.parent == tmp_path  # stayed inside the output dir
    assert not (tmp_path.parent / "evil.cdx.json").exists()


def test_component_purl_suppresses_pypi_for_direct_vcs_ref():
    # A Python DIRECT VCS reference is not a PyPI package -> no pkg:pypi purl; it
    # gets a pkg:generic purl carrying the real vcs_url instead.
    from sbom.emit._common import component_purl

    vcs = Component(
        name="private-lib", languages=["Python"], effective_version="1.0",
        observations=[Observation(
            source_kind=SourceKind.PYTHON_REQUIREMENT,
            ecosystem_data={"direct_reference": "git+https://github.com/acme/private-lib.git#egg=private-lib",
                            "vcs": "git"})],
    )
    purl = component_purl(vcs)
    assert purl.type == "generic" and purl.name == "private-lib"
    assert purl.qualifiers.get("vcs_url") == "git+https://github.com/acme/private-lib.git"

    # A real registry requirement still gets pkg:pypi.
    reg = Component(
        name="numpy", languages=["Python"], effective_version="2.1.0",
        observations=[Observation(source_kind=SourceKind.PYTHON_REQUIREMENT, ecosystem_data={})],
    )
    assert component_purl(reg).type == "pypi"

    # A direct-URL ref to an official WHEEL (no vcs scheme) IS the registry package
    # pinned to a file -> it keeps pkg:pypi (torch @ download.pytorch.org case).
    wheel = Component(
        name="torch", languages=["Python"], effective_version="2.7.1",
        observations=[Observation(
            source_kind=SourceKind.PYTHON_REQUIREMENT,
            ecosystem_data={"direct_reference": "https://download.pytorch.org/whl/cpu/torch-2.7.1.whl"})],
    )
    assert component_purl(wheel).type == "pypi"


def test_spdx_dedups_identical_relationships():
    # Two edges identical except source_file (reconcile preserves both as distinct
    # evidence) map to ONE emitted SPDX relationship — no duplicate.
    subj = Subject(id="s", identity=Identity(SubjectKind.PYTHON_WHEEL, "s", "1.0"), role=SubjectRole.PRIMARY)
    dep = Component(name="dep", languages=["Python"])

    def _e(sf):
        return DependencyEdge(root_artifact_id="s", from_ref=Ref(RefKind.SUBJECT, "s"),
                              to_ref=Ref(RefKind.COMPONENT, "dep"), relation_type=RelationType.DEPENDS_ON,
                              usage_scope=UsageScope.RUNTIME, source_file=sf)

    doc = Document(subjects=[subj], components=[dep], edges=[_e("a.cmake"), _e("b.cmake")],
                   environment_tools=[], warnings=[], metadata={})
    rels = json.loads(spdx.emit(doc, REPRO_OPTS))["relationships"]
    dep_rels = [r for r in rels if r["relationshipType"] == "DEPENDS_ON"
                and r["relatedSpdxElement"].endswith("dep")]
    assert len(dep_rels) == 1


def test_is_emittable_url_helper():
    from sbom.emit._common import is_emittable_url

    assert is_emittable_url("https://example.com/x.tar.gz")
    assert is_emittable_url("git+https://host/owner/repo.git@abc")
    assert not is_emittable_url("${CANN_3RD_LIB_PATH}/eigen.tar.gz")
    assert not is_emittable_url("/cache/eigen.tar.gz")  # bare local path
    assert not is_emittable_url("$<CONFIG>/x")
    assert not is_emittable_url(None)
    assert not is_emittable_url("")


def test_cyclonedx_cann_properties(document):
    # The per-observation sbomgen:obs:0:* properties are --detail full only.
    bom = json.loads(cyclonedx.emit(document, REPRO_FULL))
    pc = next(c for c in bom["components"] if c["name"] == "protobuf")
    props = {p["name"]: p["value"] for p in pc["properties"]}
    # integrity findings, reachability, activation, usage_scope, source_revision,
    # root, alias, completeness all land as sbomgen:* properties.
    assert props["sbomgen:integrity:no_hash"] == "true"
    assert props["sbomgen:integrity:tls_verification_disabled"] == "true"
    assert props["sbomgen:completeness:python_transitives"] == "unresolved"
    assert props["sbomgen:alias:name"] == "protocolbuffers"
    assert props["sbomgen:obs:0:source_revision"] == "master-016"
    assert props["sbomgen:obs:0:root"] == "ops_math"
    assert props["sbomgen:obs:0:reachability"] == "reached"
    assert props["sbomgen:obs:0:activation"] == "TOPLEVEL_PROJECT"
    assert props["sbomgen:obs:0:usage_scope"] == "runtime"
    assert props["sbomgen:obs:0:fp_required"] == "False"
    assert props["sbomgen:obs:0:fp_effective_required"] == "True"


def test_component_provenance_emitted_in_both_formats():
    # Component.origin -> sbomgen:component:origin in BOTH emitters; an unset
    # origin emits nothing. Present in compact mode (a summary signal, not obs:*).
    primary = Subject(
        id="pkg",
        identity=Identity(SubjectKind.PYTHON_WHEEL, "pkg", "1.0.0"),
        role=SubjectRole.PRIMARY,
    )
    doc = Document(
        subjects=[primary],
        components=[
            Component(name="platform", origin="first-party"),
            Component(name="boost", license="BSL-1.0", origin="third-party"),
            Component(name="Threads"),  # origin None -> no property/annotation
        ],
        edges=[],
        environment_tools=[],
        metadata={},
    )

    bom = json.loads(cyclonedx.emit(doc, REPRO_OPTS))
    assert validate.validate_cyclonedx(json.dumps(bom)) == []

    def cdx_prov(name):
        c = next(x for x in bom["components"] if x["name"] == name)
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        return props.get("sbomgen:component:origin")

    assert cdx_prov("platform") == "first-party"
    assert cdx_prov("boost") == "third-party"
    assert cdx_prov("Threads") is None

    sp = json.loads(spdx.emit(doc, REPRO_OPTS))
    assert validate.validate_spdx(json.dumps(sp)) == []

    def spdx_prov(name):
        p = next(x for x in sp["packages"] if x["name"] == name)
        return [
            a["comment"]
            for a in p.get("annotations", [])
            if "component:origin" in a["comment"]
        ]

    assert spdx_prov("platform") == ["sbomgen:component:origin=first-party"]
    assert spdx_prov("boost") == ["sbomgen:component:origin=third-party"]
    assert spdx_prov("Threads") == []


def test_component_provenance_kept_in_compact_with_obs_omitted():
    # The provenance signal is a SUMMARY signal: compact keeps it while omitting the
    # per-observation sbomgen:obs:N:* details; full restores the obs details.
    primary = Subject(
        id="pkg",
        identity=Identity(SubjectKind.PYTHON_WHEEL, "pkg", "1.0.0"),
        role=SubjectRole.PRIMARY,
    )
    obs = [
        Observation(
            source_kind=SourceKind.CMAKE_LINK_LIBRARY,
            ecosystem_data={"name": "lib"},
            source_file=f"f{i}.cmake",
        )
        for i in range(3)
    ]
    doc = Document(
        subjects=[primary],
        components=[Component(name="lib", origin="first-party", observations=obs)],
        edges=[],
        environment_tools=[],
        metadata={},
    )

    # compact (default): provenance present, obs:* absent.
    bom = json.loads(cyclonedx.emit(doc, REPRO_OPTS))
    props = {
        p["name"] for c in bom["components"] if c["name"] == "lib" for p in c.get("properties", [])
    }
    assert "sbomgen:component:origin" in props
    assert not any(n.startswith("sbomgen:obs:") for n in props)

    sp = json.loads(spdx.emit(doc, REPRO_OPTS))
    comments = [
        a["comment"] for p in sp["packages"] if p["name"] == "lib" for a in p.get("annotations", [])
    ]
    assert any("sbomgen:component:origin=first-party" in c for c in comments)
    assert not any("sbomgen:obs:" in c for c in comments)

    # full: provenance still present, obs:* now restored.
    props_full = {
        p["name"]
        for c in json.loads(cyclonedx.emit(doc, REPRO_FULL))["components"]
        if c["name"] == "lib"
        for p in c.get("properties", [])
    }
    assert "sbomgen:component:origin" in props_full
    assert any(n.startswith("sbomgen:obs:") for n in props_full)


def _python_doc():
    """A tiny doc with one pinned and one unpinned Python component."""
    primary = Subject(
        id="pkg",
        identity=Identity(SubjectKind.PYTHON_WHEEL, "pkg", "1.0.0"),
        role=SubjectRole.PRIMARY,
    )
    attrs = Component(
        name="attrs",
        languages=["Python"],
        scopes=[UsageScope.RUNTIME],
        source_version="24.2.0",
        effective_version="24.2.0",
        completeness={"python_transitives": "unresolved"},
        observations=[
            Observation(
                source_kind=SourceKind.PYTHON_REQUIREMENT,
                usage_scope=UsageScope.RUNTIME,
                version_constraint="==24.2.0",
                ecosystem_data={"name": "attrs"},
            )
        ],
    )
    numpy = Component(
        name="numpy",
        languages=["Python"],
        scopes=[UsageScope.RUNTIME],
        completeness={"python_transitives": "unresolved", "version": "unpinned"},
        observations=[
            Observation(
                source_kind=SourceKind.PYTHON_REQUIREMENT,
                usage_scope=UsageScope.RUNTIME,
                version_constraint="<2",
                ecosystem_data={"name": "numpy"},
            )
        ],
    )
    edges = [
        DependencyEdge(
            root_artifact_id="pkg",
            from_ref=Ref(RefKind.SUBJECT, "pkg"),
            to_ref=Ref(RefKind.COMPONENT, dep),
            relation_type=RelationType.DEPENDS_ON,
            usage_scope=UsageScope.RUNTIME,
        )
        for dep in ("attrs", "numpy")
    ]
    return Document(subjects=[primary], components=[attrs, numpy], edges=edges)


def test_cyclonedx_concrete_pin_purl_and_version():
    bom = json.loads(cyclonedx.emit(_python_doc(), REPRO_OPTS))
    by_name = {c["name"]: c for c in bom["components"]}
    attrs = by_name["attrs"]
    assert attrs["version"] == "24.2.0"
    assert attrs["purl"] == "pkg:pypi/attrs@24.2.0"


def test_python_wheel_subject_is_generic_but_pip_dep_is_pypi():
    """The point of subject_purl vs component_purl: a PYTHON_WHEEL subject is the
    artifact this repo BUILDS, identified generically (pkg:generic) — we can't
    verify offline it's published to PyPI. A python DEPENDENCY component IS a pip
    requirement fetched from PyPI, so it keeps pkg:pypi."""
    bom = json.loads(cyclonedx.emit(_python_doc(), REPRO_OPTS))
    # subject "pkg" (PYTHON_WHEEL) is the metadata.component primary -> generic.
    assert bom["metadata"]["component"]["purl"] == "pkg:generic/pkg@1.0.0"
    # its pip dependency keeps pypi.
    by_name = {c["name"]: c for c in bom["components"]}
    assert by_name["attrs"]["purl"] == "pkg:pypi/attrs@24.2.0"

    # Same distinction in SPDX (subject_purl drives both emitters).
    spd = json.loads(spdx.emit(_python_doc(), REPRO_OPTS))
    pkgs = {p["name"]: p for p in spd["packages"]}

    def purl_refs(pkg):
        return [
            r["referenceLocator"]
            for r in pkg.get("externalRefs", [])
            if r.get("referenceType") == "purl"
        ]

    assert purl_refs(pkgs["pkg"]) == ["pkg:generic/pkg@1.0.0"]
    assert purl_refs(pkgs["attrs"]) == ["pkg:pypi/attrs@24.2.0"]


def test_cyclonedx_unpinned_versionless_purl_and_marker():
    # --detail full so the sbomgen:obs:0:version_constraint property is present.
    bom = json.loads(cyclonedx.emit(_python_doc(), REPRO_FULL))
    numpy = next(c for c in bom["components"] if c["name"] == "numpy")
    assert "version" not in numpy                 # no concrete version emitted
    assert numpy["purl"] == "pkg:pypi/numpy"      # version-less purl
    props = {p["name"]: p["value"] for p in numpy["properties"]}
    assert props["sbomgen:completeness:version"] == "unpinned"
    assert props["sbomgen:obs:0:version_constraint"] == "<2"


def test_cyclonedx_python_doc_validates():
    assert validate.validate_cyclonedx(cyclonedx.emit(_python_doc(), REPRO_OPTS)) == []


def test_spdx_concrete_pin_versioninfo_and_unpinned_omits():
    # --detail full so the sbomgen:obs:0:version_constraint annotation is present.
    spd = json.loads(spdx.emit(_python_doc(), REPRO_FULL))
    pkgs = {p["name"]: p for p in spd["packages"]}
    assert pkgs["attrs"]["versionInfo"] == "24.2.0"
    assert "versionInfo" not in pkgs["numpy"]     # unpinned -> omitted
    comments = _all_spdx_annotation_comments(spd)
    assert any("sbomgen:completeness:version=unpinned" in c for c in comments)
    assert any("sbomgen:obs:0:version_constraint=<2" in c for c in comments)


def test_spdx_purl_externalref_pinned_and_unpinned():
    """Both pinned and UNPINNED python deps carry a purl externalRef in SPDX
    (parity with the subject emitter and the CycloneDX output)."""
    spd = json.loads(spdx.emit(_python_doc(), REPRO_OPTS))
    pkgs = {p["name"]: p for p in spd["packages"]}

    def purl_refs(pkg):
        return [
            r["referenceLocator"]
            for r in pkg.get("externalRefs", [])
            if r.get("referenceType") == "purl"
        ]

    assert purl_refs(pkgs["attrs"]) == ["pkg:pypi/attrs@24.2.0"]
    assert purl_refs(pkgs["numpy"]) == ["pkg:pypi/numpy"]  # version-less, present


def test_spdx_python_doc_validates():
    assert validate.validate_spdx(spdx.emit(_python_doc(), REPRO_OPTS)) == []


def test_cyclonedx_dependency_graph_typed_edges(document):
    bom = json.loads(cyclonedx.emit(document, REPRO_OPTS))
    deps = {d["ref"]: set(d.get("dependsOn", [])) for d in bom["dependencies"]}
    # subject -> component edge
    assert "component:protobuf" in deps["subject:ops_math"]
    # component -> component (transitive) edge
    assert "component:abseil-cpp" in deps["component:protobuf"]
    # sibling subject -> build dep
    assert "component:securec" in deps["subject:ascend_ops"]


def test_cyclonedx_environment_tool_is_property_not_component(document):
    bom = json.loads(cyclonedx.emit(document, REPRO_OPTS))
    names = {c["name"] for c in bom["components"]}
    assert "perl" not in names  # never a component
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["sbomgen:envtool:0:name"] == "perl"
    assert props["sbomgen:envtool:0:command_context"] == "find_program"
    assert props["sbomgen:envtool:0:source_authority"] == "cann-cmake"
    assert props["sbomgen:envtool:0:required"] == "True"


def test_cyclonedx_non_spdx_license_as_named_text(document):
    bom = json.loads(cyclonedx.emit(document, REPRO_OPTS))
    # securec: non-SPDX license name (no inline text) -> license.name.
    sc = next(c for c in bom["components"] if c["name"] == "securec")
    lic = sc["licenses"][0]["license"]
    assert lic["name"] == "Huawei Secure C Library License"
    # subject with non-SPDX license AND inline text -> license.text inlined.
    root = bom["metadata"]["component"]
    root_lic = root["licenses"][0]["license"]
    assert root_lic["name"] == "LicenseRef-CANN-Open-Software-License-2.0"
    assert "content" in root_lic["text"]
    assert "CANN Open Software License" in root_lic["text"]["content"]
    # protobuf's BSD-3-Clause is a valid SPDX expression.
    pc = next(c for c in bom["components"] if c["name"] == "protobuf")
    assert pc["licenses"][0]["expression"] == "BSD-3-Clause"


# ---------------------------------------------------------------------------
# Field survival — SPDX
# ---------------------------------------------------------------------------


def test_spdx_describes_each_subject(document):
    spd = json.loads(spdx.emit(document, REPRO_OPTS))
    rels = spd["relationships"]
    describes = {
        r["relatedSpdxElement"]
        for r in rels
        if r["relationshipType"] == "DESCRIBES"
    }
    assert "SPDXRef-Subject-ops-math" in describes
    assert "SPDXRef-Subject-ascend-ops" in describes
    # grouping-only subject not described
    assert "SPDXRef-Subject-st-root" not in describes


def test_spdx_purl_external_ref_not_spdxid(document):
    spd = json.loads(spdx.emit(document, REPRO_OPTS))
    subj = next(p for p in spd["packages"] if p["name"] == "ops_math")
    refs = subj["externalRefs"]
    purl = next(r for r in refs if r["referenceType"] == "purl")
    assert purl["referenceCategory"] == "PACKAGE-MANAGER" or purl[
        "referenceCategory"
    ] == "PACKAGE_MANAGER"
    assert purl["referenceLocator"].startswith("pkg:generic/ops_math")
    # SPDXID is NOT the purl.
    assert subj["SPDXID"] == "SPDXRef-Subject-ops-math"


def test_spdx_checksums_and_generated_from(document):
    spd = json.loads(spdx.emit(document, REPRO_OPTS))
    pc = next(p for p in spd["packages"] if p["name"] == "protobuf")
    assert pc["checksums"][0]["algorithm"] == "SHA256"
    assert pc["checksums"][0]["checksumValue"] == "ab" * 32
    assert "patched build" in pc["comment"]
    gen = [
        r
        for r in spd["relationships"]
        if r["relationshipType"] == "GENERATED_FROM"
        and r["spdxElementId"] == "SPDXRef-Package-protobuf"
    ]
    assert gen, "patched component must be GENERATED_FROM a source package"
    source_id = gen[0]["relatedSpdxElement"]
    assert any(p["SPDXID"] == source_id for p in spd["packages"])


def test_spdx_dependency_relationships_typed(document):
    spd = json.loads(spdx.emit(document, REPRO_OPTS))
    pairs = {
        (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
        for r in spd["relationships"]
    }
    assert (
        "SPDXRef-Subject-ops-math",
        "DEPENDS_ON",
        "SPDXRef-Package-protobuf",
    ) in pairs
    assert (
        "SPDXRef-Package-protobuf",
        "DEPENDS_ON",
        "SPDXRef-Package-abseil-cpp",
    ) in pairs
    # BUILD_DEPENDENCY_OF: build dep is the element, owner is the related element.
    assert (
        "SPDXRef-Package-securec",
        "BUILD_DEPENDENCY_OF",
        "SPDXRef-Subject-ascend-ops",
    ) in pairs


def test_spdx_environment_tool_is_annotation_not_package(document):
    spd = json.loads(spdx.emit(document, REPRO_OPTS))
    names = {p["name"] for p in spd["packages"]}
    assert "perl" not in names
    comments = _all_spdx_annotation_comments(spd)
    assert any("sbomgen:envtool:0:name=perl" in c for c in comments)
    assert any("sbomgen:envtool:0:source_authority=cann-cmake" in c for c in comments)


def test_spdx_non_spdx_license_extracted(document):
    spd = json.loads(spdx.emit(document, REPRO_OPTS))
    extracted = {e["licenseId"]: e for e in spd.get("hasExtractedLicensingInfos", [])}
    # subject's CANN license + securec's non-SPDX license both extracted.
    assert "LicenseRef-CANN-Open-Software-License-2.0" in extracted
    sc = next(p for p in spd["packages"] if p["name"] == "securec")
    assert sc["licenseConcluded"].startswith("LicenseRef-")


def test_spdx_observation_annotations(document):
    # The per-observation sbomgen:obs:0:* annotations are --detail full only.
    spd = json.loads(spdx.emit(document, REPRO_FULL))
    comments = _all_spdx_annotation_comments(spd)
    assert any("sbomgen:obs:0:source_revision=master-016" in c for c in comments)
    assert any("sbomgen:obs:0:reachability=reached" in c for c in comments)
    assert any("sbomgen:integrity:no_hash=true" in c for c in comments)
    assert any("sbomgen:alias:name=protocolbuffers" in c for c in comments)


# ---------------------------------------------------------------------------
# Property/annotation coverage for the late-surviving observation fields
# ---------------------------------------------------------------------------


@pytest.fixture
def coverage_document() -> Document:
    """A subject with three observation flavours that each exercise one of the
    late-reconcile fields: a cann_package constraint, a find_package
    requiredness, and a gtest-like usage_scope + activation.
    """
    primary = Subject(
        id="ops_math",
        identity=Identity(SubjectKind.CANN_PACKAGE, "ops_math", "9.0.0"),
        role=SubjectRole.PRIMARY,
    )
    opbase = Component(
        name="opbase",
        scopes=[UsageScope.RUNTIME],
        observations=[
            Observation(
                source_kind=SourceKind.CANN_PACKAGE,
                source_file="version.cmake",
                root_artifact_id="ops_math",
                usage_scope=UsageScope.RUNTIME,
                version_constraint=">=8.5",
            )
        ],
    )
    asc = Component(
        name="ASC",
        scopes=[UsageScope.BUILD],
        observations=[
            Observation(
                source_kind=SourceKind.CMAKE_FIND_PACKAGE,
                source_file="dependencies.cmake",
                root_artifact_id="ops_math",
                usage_scope=UsageScope.BUILD,
                find_package=FindPackageInfo(
                    required=False, quiet=True, effective_required=True
                ),
            )
        ],
    )
    gtest = Component(
        name="gtest",
        scopes=[UsageScope.TEST],
        observations=[
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                source_file="prepare.cmake",
                root_artifact_id="ops_math",
                usage_scope=UsageScope.TEST,
                activation_condition=[
                    ActivationCondition(expr="TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD")
                ],
            )
        ],
    )
    edges = [
        DependencyEdge(
            root_artifact_id="ops_math",
            from_ref=Ref(RefKind.SUBJECT, "ops_math"),
            to_ref=Ref(RefKind.COMPONENT, "opbase"),
            relation_type=RelationType.DEPENDS_ON,
        ),
    ]
    return Document(
        subjects=[primary],
        components=[opbase, asc, gtest],
        edges=edges,
    )


def test_cyclonedx_renders_all_surviving_obs_fields(coverage_document):
    # The per-observation sbomgen:obs:0:* properties are --detail full only.
    text = cyclonedx.emit(coverage_document, REPRO_FULL)
    assert validate.validate_cyclonedx(text) == []
    bom = json.loads(text)

    def props_of(name):
        c = next(c for c in bom["components"] if c["name"] == name)
        return {p["name"]: p["value"] for p in c["properties"]}, c

    opbase_props, _ = props_of("opbase")
    assert opbase_props["sbomgen:obs:0:version_constraint"] == ">=8.5"
    assert opbase_props["sbomgen:obs:0:usage_scope"] == "runtime"

    asc_props, asc_comp = props_of("ASC")
    assert asc_props["sbomgen:obs:0:fp_required"] == "False"
    assert asc_props["sbomgen:obs:0:fp_quiet"] == "True"
    assert asc_props["sbomgen:obs:0:fp_effective_required"] == "True"
    # BUILD usage_scope -> CycloneDX component scope optional.
    assert asc_comp["scope"] == "optional"

    gtest_props, gtest_comp = props_of("gtest")
    assert gtest_props["sbomgen:obs:0:usage_scope"] == "test"
    assert (
        gtest_props["sbomgen:obs:0:activation"]
        == "TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD"
    )
    assert gtest_comp["scope"] == "optional"


def test_spdx_renders_all_surviving_obs_fields(coverage_document):
    # The per-observation sbomgen:obs:0:* annotations are --detail full only.
    text = spdx.emit(coverage_document, REPRO_FULL)
    assert validate.validate_spdx(text) == []
    spd = json.loads(text)
    comments = _all_spdx_annotation_comments(spd)
    assert any("sbomgen:obs:0:version_constraint=>=8.5" in c for c in comments)
    assert any("sbomgen:obs:0:usage_scope=runtime" in c for c in comments)
    assert any("sbomgen:obs:0:fp_required=False" in c for c in comments)
    assert any("sbomgen:obs:0:fp_quiet=True" in c for c in comments)
    assert any("sbomgen:obs:0:fp_effective_required=True" in c for c in comments)
    assert any(
        "sbomgen:obs:0:activation=TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD" in c
        for c in comments
    )


def test_tool_version_threads_into_both_formats(coverage_document):
    opts = EmitOptions(
        reproducible=True, source_date_epoch=1_700_000_000, tool_version="1.2.3"
    )
    bom = json.loads(cyclonedx.emit(coverage_document, opts))
    tool = bom["metadata"]["tools"]["components"][0]
    assert tool["name"] == "sbom-gen"
    assert tool["version"] == "1.2.3"

    spd = json.loads(spdx.emit(coverage_document, opts))
    creators = spd["creationInfo"]["creators"]
    assert any("sbom-gen-1.2.3" in c for c in creators)


# ---------------------------------------------------------------------------
# Split emit
# ---------------------------------------------------------------------------


def test_cyclonedx_split_subjects(document):
    out = cyclonedx.emit_split(document, EmitOptions(subjects=["ops_math", "ascend_ops"]))
    assert set(out) == {"ops_math", "ascend_ops"}
    for text in out.values():
        assert validate.validate_cyclonedx(text) == []
    ops = json.loads(out["ops_math"])
    assert ops["metadata"]["component"]["name"] == "ops_math"


def test_spdx_split_subjects(document):
    out = spdx.emit_split(document, EmitOptions(subjects=["ops_math", "ascend_ops"]))
    assert set(out) == {"ops_math", "ascend_ops"}
    for text in out.values():
        assert validate.validate_spdx(text) == []


# ---------------------------------------------------------------------------
# validate.py negative cases
# ---------------------------------------------------------------------------


def test_validate_cyclonedx_reports_invalid():
    bad = '{"bomFormat":"CycloneDX","specVersion":"1.5","version":"notanint"}'
    warns = validate.validate_cyclonedx(bad)
    assert warns
    assert all(isinstance(w, Warning) for w in warns)
    assert all(w.code == "cyclonedx_invalid" for w in warns)


def test_validate_spdx_reports_invalid():
    warns = validate.validate_spdx("{ not valid spdx json")
    assert warns
    assert warns[0].code == "spdx_invalid"


# ---------------------------------------------------------------------------
# source_date_epoch threads through both formats
# ---------------------------------------------------------------------------


def test_timestamps_from_source_date_epoch(document):
    bom = json.loads(cyclonedx.emit(document, REPRO_OPTS))
    assert bom["metadata"]["timestamp"].startswith("2023-11-14")
    spd = json.loads(spdx.emit(document, REPRO_OPTS))
    assert spd["creationInfo"]["created"].startswith("2023-11-14")


# ---------------------------------------------------------------------------
# Completeness is per-component, NOT a document-level comment flood
# ---------------------------------------------------------------------------


def test_spdx_document_comment_omits_completeness(document):
    spd = json.loads(spdx.emit(document, REPRO_OPTS))
    # The document-level comment must NOT carry the per-component completeness
    # flood (or anything mentioning unpinned/unresolved). It is absent entirely.
    doc_comment = spd["creationInfo"].get("comment")
    assert doc_comment is None or (
        "completeness" not in doc_comment
        and "unpinned" not in doc_comment
        and "unresolved" not in doc_comment
    )
    # But the per-component sbomgen:completeness annotation still survives.
    comments = _all_spdx_annotation_comments(spd)
    assert any(
        "sbomgen:completeness:python_transitives=unresolved" in c for c in comments
    )


def test_spdx_unpinned_completeness_still_annotated():
    spd = json.loads(spdx.emit(_python_doc(), REPRO_OPTS))
    doc_comment = spd["creationInfo"].get("comment")
    assert doc_comment is None or "completeness" not in doc_comment
    comments = _all_spdx_annotation_comments(spd)
    # numpy is unpinned: its per-component completeness annotation must remain.
    assert any("sbomgen:completeness:version=unpinned" in c for c in comments)


# ---------------------------------------------------------------------------
# --guess-pypi-urls: opt-in constructed PyPI download URLs (Python only)
# ---------------------------------------------------------------------------

GUESS_OPTS = EmitOptions(
    reproducible=True, source_date_epoch=1_700_000_000, guess_pypi_urls=True
)


def _ext_ref_urls(comp: dict) -> set[str]:
    return {r["url"] for r in comp.get("externalReferences", [])}


def test_cyclonedx_guess_pypi_urls_pinned_and_unpinned():
    bom = json.loads(cyclonedx.emit(_python_doc(), GUESS_OPTS))
    by_name = {c["name"]: c for c in bom["components"]}
    attrs_refs = [
        r
        for r in by_name["attrs"]["externalReferences"]
        if r["type"] == "distribution"
    ]
    assert "https://pypi.org/project/attrs/24.2.0/" in {r["url"] for r in attrs_refs}
    numpy_dist = {
        r["url"]
        for r in by_name["numpy"]["externalReferences"]
        if r["type"] == "distribution"
    }
    assert "https://pypi.org/project/numpy/" in numpy_dist
    # purl unchanged regardless of the flag.
    assert by_name["attrs"]["purl"] == "pkg:pypi/attrs@24.2.0"
    assert by_name["numpy"]["purl"] == "pkg:pypi/numpy"
    props = {p["name"]: p["value"] for p in by_name["attrs"]["properties"]}
    assert props["sbomgen:python:download_url_source"] == "guessed"
    assert validate.validate_cyclonedx(cyclonedx.emit(_python_doc(), GUESS_OPTS)) == []


def test_cyclonedx_guess_pypi_urls_off_by_default():
    bom = json.loads(cyclonedx.emit(_python_doc(), REPRO_OPTS))
    for comp in bom["components"]:
        assert not any("pypi.org/project" in u for u in _ext_ref_urls(comp))
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        assert "sbomgen:python:download_url_source" not in props


def test_spdx_guess_pypi_urls_pinned_and_unpinned():
    spd = json.loads(spdx.emit(_python_doc(), GUESS_OPTS))
    pkgs = {p["name"]: p for p in spd["packages"]}
    assert pkgs["attrs"]["downloadLocation"] == "https://pypi.org/project/attrs/24.2.0/"
    assert pkgs["numpy"]["downloadLocation"] == "https://pypi.org/project/numpy/"
    comments = _all_spdx_annotation_comments(spd)
    assert any("sbomgen:python:download_url_source=guessed" in c for c in comments)
    assert validate.validate_spdx(spdx.emit(_python_doc(), GUESS_OPTS)) == []


def test_spdx_guess_pypi_urls_off_by_default():
    spd = json.loads(spdx.emit(_python_doc(), REPRO_OPTS))
    pkgs = {p["name"]: p for p in spd["packages"]}
    assert pkgs["attrs"]["downloadLocation"] == "NOASSERTION"
    assert pkgs["numpy"]["downloadLocation"] == "NOASSERTION"
    comments = _all_spdx_annotation_comments(spd)
    assert not any("download_url_source" in c for c in comments)


def test_guess_pypi_urls_pep503_normalizes_name():
    """A name with runs of [-_.] is normalized to single '-' lowercase."""
    primary = Subject(
        id="pkg",
        identity=Identity(SubjectKind.PYTHON_WHEEL, "pkg", "1.0.0"),
        role=SubjectRole.PRIMARY,
    )
    comp = Component(
        name="Foo._-Bar",
        languages=["Python"],
        scopes=[UsageScope.RUNTIME],
        source_version="2.0",
        effective_version="2.0",
        observations=[
            Observation(
                source_kind=SourceKind.PYTHON_REQUIREMENT,
                usage_scope=UsageScope.RUNTIME,
                ecosystem_data={"name": "Foo._-Bar"},
            )
        ],
    )
    doc = Document(subjects=[primary], components=[comp])
    bom = json.loads(cyclonedx.emit(doc, GUESS_OPTS))
    dist = {
        r["url"]
        for r in bom["components"][0]["externalReferences"]
        if r["type"] == "distribution"
    }
    assert "https://pypi.org/project/foo-bar/2.0/" in dist


def test_guess_pypi_urls_does_not_touch_non_python(document):
    """Non-Python components get no pypi URL even with the flag on."""
    bom = json.loads(cyclonedx.emit(document, GUESS_OPTS))
    pc = next(c for c in bom["components"] if c["name"] == "protobuf")
    assert not any("pypi.org/project" in u for u in _ext_ref_urls(pc))
    spd = json.loads(spdx.emit(document, GUESS_OPTS))
    pk = next(p for p in spd["packages"] if p["name"] == "protobuf")
    assert "pypi.org/project" not in pk["downloadLocation"]


# ---------------------------------------------------------------------------
# Subject-id uniqueness: distinct roots that slugify to the same SPDX id /
# CycloneDX bom-ref must get UNIQUE emitted ids (else invalid SPDX).
# ---------------------------------------------------------------------------


def _colliding_subjects_doc() -> Document:
    """Two distinct roots sharing a Subject.id ('Kernel_Sample') + the primary
    'rts' duplicated as a second root ('rts'), mirroring the real runtime repo.
    """
    rts_primary = Subject(
        id="rts",
        identity=Identity(SubjectKind.CMAKE_PROJECT, "rts", "1.0.0"),
        role=SubjectRole.PRIMARY,
        source_path="",
    )
    rts_root = Subject(
        id="rts",
        identity=Identity(SubjectKind.CMAKE_PROJECT, "rts", "1.0.0"),
        role=SubjectRole.CMAKE_PROJECT,
        source_path="src",
    )
    k1 = Subject(
        id="Kernel_Sample",
        identity=Identity(SubjectKind.CMAKE_PROJECT, "Kernel_Sample", "1.0.0"),
        role=SubjectRole.CMAKE_PROJECT,
        source_path="example/kernel/0",
    )
    k2 = Subject(
        id="Kernel_Sample",
        identity=Identity(SubjectKind.CMAKE_PROJECT, "Kernel_Sample", "1.0.0"),
        role=SubjectRole.CMAKE_PROJECT,
        source_path="example/kernel/1",
    )
    return Document(subjects=[rts_primary, rts_root, k1, k2], components=[], edges=[])


def test_spdx_subject_ids_unique_on_slug_collision():
    spd = json.loads(spdx.emit(_colliding_subjects_doc(), REPRO_OPTS))
    ids = [p["SPDXID"] for p in spd["packages"]]
    assert len(ids) == len(set(ids)), f"duplicate SPDXIDs: {ids}"
    # Every DESCRIBES relationship points at a real, unique subject package.
    describes = [
        r["relatedSpdxElement"]
        for r in spd["relationships"]
        if r["relationshipType"] == "DESCRIBES"
    ]
    assert len(describes) == 4
    assert len(set(describes)) == 4
    assert set(describes) <= set(ids)
    # The four emitted subject ids are slug-stable with deterministic suffixes.
    subj_ids = {p["SPDXID"] for p in spd["packages"]}
    assert "SPDXRef-Subject-rts" in subj_ids
    assert "SPDXRef-Subject-rts-2" in subj_ids
    assert "SPDXRef-Subject-Kernel-Sample" in subj_ids
    assert "SPDXRef-Subject-Kernel-Sample-2" in subj_ids


def test_spdx_subject_collision_doc_validates():
    text = spdx.emit(_colliding_subjects_doc(), REPRO_OPTS)
    assert validate.validate_spdx(text) == []


def test_cyclonedx_subject_bom_refs_unique_on_slug_collision():
    bom = json.loads(cyclonedx.emit(_colliding_subjects_doc(), REPRO_OPTS))
    refs = [bom["metadata"]["component"]["bom-ref"]]
    refs += [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs)), f"duplicate bom-refs: {refs}"
    assert "subject:rts" in refs
    assert "subject:rts-2" in refs
    assert "subject:Kernel_Sample" in refs
    assert "subject:Kernel_Sample-2" in refs


def test_cyclonedx_subject_collision_doc_validates():
    text = cyclonedx.emit(_colliding_subjects_doc(), REPRO_OPTS)
    assert validate.validate_cyclonedx(text) == []


# ---------------------------------------------------------------------------
# Occurrence dedup by location + compact/full detail policy
# ---------------------------------------------------------------------------


def _shared_dep_doc() -> Document:
    """One subject + one dependency seen by many roots at the SAME source_file
    (mirrors the real ``cann_device`` with 63 identical-location occurrences)."""
    primary = Subject(
        id="rts",
        identity=Identity(SubjectKind.CMAKE_PROJECT, "rts", "1.0.0"),
        role=SubjectRole.PRIMARY,
    )
    dep = Component(
        name="cann_device",
        scopes=[UsageScope.RUNTIME],
        license="MIT",
        integrity_findings=[IntegrityFinding.NO_HASH],
        completeness={"version": "unpinned"},
        observations=[
            Observation(
                source_kind=SourceKind.CMAKE_LINK_LIBRARY,
                source_file="cmake/device/CMakeLists.txt",
                root_artifact_id="rts",
                usage_scope=UsageScope.RUNTIME,
                ecosystem_data={"name": "cann_device"},
            )
            for _ in range(5)  # five identical-location observations
        ],
    )
    edges = [
        DependencyEdge(
            root_artifact_id="rts",
            from_ref=Ref(RefKind.SUBJECT, "rts"),
            to_ref=Ref(RefKind.COMPONENT, "cann_device"),
            relation_type=RelationType.DEPENDS_ON,
            usage_scope=UsageScope.RUNTIME,
        )
    ]
    return Document(subjects=[primary], components=[dep], edges=edges)


def test_cyclonedx_occurrences_deduped_by_location_in_full():
    bom = json.loads(cyclonedx.emit(_shared_dep_doc(), REPRO_FULL))
    dep = next(c for c in bom["components"] if c["name"] == "cann_device")
    occ = dep.get("evidence", {}).get("occurrences", [])
    # Five identical-location observations collapse to ONE occurrence.
    assert len(occ) == 1
    assert occ[0]["location"] == "cmake/device/CMakeLists.txt"


def test_cyclonedx_compact_omits_obs_and_occurrences_keeps_signals():
    # Default (compact) output.
    bom = json.loads(cyclonedx.emit(_shared_dep_doc(), REPRO_OPTS))
    dep = next(c for c in bom["components"] if c["name"] == "cann_device")
    props = {p["name"]: p["value"] for p in dep.get("properties", [])}
    # No verbose per-observation provenance, no occurrences.
    assert not any(k.startswith("sbomgen:obs:0") for k in props)
    assert "evidence" not in dep or not dep["evidence"].get("occurrences")
    # But the readable signals + license + version stay.
    assert dep["licenses"][0]["expression"] == "MIT"
    assert props["sbomgen:integrity:no_hash"] == "true"
    assert props["sbomgen:completeness:version"] == "unpinned"
    # The dependency graph survives.
    deps = {d["ref"]: set(d.get("dependsOn", [])) for d in bom["dependencies"]}
    assert "component:cann_device" in deps["subject:rts"]
    assert validate.validate_cyclonedx(cyclonedx.emit(_shared_dep_doc(), REPRO_OPTS)) == []


def test_cyclonedx_full_restores_obs_properties():
    bom = json.loads(cyclonedx.emit(_shared_dep_doc(), REPRO_FULL))
    dep = next(c for c in bom["components"] if c["name"] == "cann_device")
    props = {p["name"]: p["value"] for p in dep.get("properties", [])}
    assert props["sbomgen:obs:0:source_file"] == "cmake/device/CMakeLists.txt"
    assert props["sbomgen:obs:0:usage_scope"] == "runtime"


def test_spdx_compact_omits_obs_annotations_keeps_signals():
    spd = json.loads(spdx.emit(_shared_dep_doc(), REPRO_OPTS))
    comments = _all_spdx_annotation_comments(spd)
    assert not any("sbomgen:obs:0:" in c for c in comments)
    # Summary signals + license survive.
    assert any("sbomgen:integrity:no_hash=true" in c for c in comments)
    assert any("sbomgen:completeness:version=unpinned" in c for c in comments)
    dep = next(p for p in spd["packages"] if p["name"] == "cann_device")
    assert dep["licenseConcluded"] == "MIT"
    # The dependency relationship survives.
    pairs = {
        (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
        for r in spd["relationships"]
    }
    assert (
        "SPDXRef-Subject-rts",
        "DEPENDS_ON",
        "SPDXRef-Package-cann-device",  # _slug maps '_' -> '-'
    ) in pairs
    assert validate.validate_spdx(spdx.emit(_shared_dep_doc(), REPRO_OPTS)) == []


def test_spdx_full_restores_obs_annotations():
    spd = json.loads(spdx.emit(_shared_dep_doc(), REPRO_FULL))
    comments = _all_spdx_annotation_comments(spd)
    assert any("sbomgen:obs:0:source_file=cmake/device/CMakeLists.txt" in c for c in comments)
    assert any("sbomgen:obs:0:usage_scope=runtime" in c for c in comments)


def test_compact_and_full_both_reproducible():
    for opts in (REPRO_OPTS, REPRO_FULL):
        a = cyclonedx.emit(_shared_dep_doc(), opts)
        b = cyclonedx.emit(_shared_dep_doc(), opts)
        assert a == b
        sa = spdx.emit(_shared_dep_doc(), opts)
        sb = spdx.emit(_shared_dep_doc(), opts)
        assert sa == sb


# ---------------------------------------------------------------------------
# Repo origin (vcs_url qualifier + native externalReferences / downloadLocation)
# ---------------------------------------------------------------------------


def _origin_doc(vcs_url=None, homepage=None) -> Document:
    subj = Subject(
        id="ops_math",
        identity=Identity(SubjectKind.CANN_PACKAGE, "ops_math", "9.0.0"),
        role=SubjectRole.PRIMARY,
        homepage=homepage,
        vcs_url=vcs_url,
    )
    return Document(
        subjects=[subj],
        components=[],
        edges=[],
        environment_tools=[],
        warnings=[],
        metadata={},
    )


def test_subject_repo_origin_emitted_in_both_formats():
    vcs = "git+https://gitcode.com/cann/ops-math.git@abc123"
    home = "https://gitcode.com/cann/ops-math"
    doc = _origin_doc(vcs_url=vcs, homepage=home)

    # CycloneDX: the primary is metadata.component. Its purl carries the vcs_url
    # qualifier (the host stays pkg:generic), and externalReferences carry the
    # native vcs + website links.
    bom = json.loads(cyclonedx.emit(doc, REPRO_OPTS))
    mc = bom["metadata"]["component"]
    assert mc["purl"].startswith("pkg:generic/ops_math@9.0.0?")
    assert "vcs_url=" in mc["purl"]
    refs = {r["type"]: r["url"] for r in mc["externalReferences"]}
    assert refs["vcs"] == vcs
    assert refs["website"] == home

    # SPDX: the VCS locator becomes downloadLocation; homepage is set; the purl
    # externalRef carries the same vcs_url qualifier.
    spd = json.loads(spdx.emit(doc, REPRO_OPTS))
    pkg = next(p for p in spd["packages"] if p["name"] == "ops_math")
    assert pkg["downloadLocation"] == vcs
    assert pkg["homepage"] == home
    purl_ref = next(r for r in pkg["externalRefs"] if r["referenceType"] == "purl")
    assert "vcs_url=" in purl_ref["referenceLocator"]

    # Both still validate clean.
    assert validate.validate_cyclonedx(cyclonedx.emit(doc, REPRO_OPTS)) == []
    assert validate.validate_spdx(spdx.emit(doc, REPRO_OPTS)) == []


def test_subject_without_origin_stays_bare_generic():
    doc = _origin_doc()  # no vcs_url / homepage

    bom = json.loads(cyclonedx.emit(doc, REPRO_OPTS))
    mc = bom["metadata"]["component"]
    assert mc["purl"] == "pkg:generic/ops_math@9.0.0"  # no qualifier
    assert not any(
        r["type"] in ("vcs", "website") for r in mc.get("externalReferences", [])
    )

    spd = json.loads(spdx.emit(doc, REPRO_OPTS))
    pkg = next(p for p in spd["packages"] if p["name"] == "ops_math")
    assert pkg["downloadLocation"] == "NOASSERTION"
    assert "homepage" not in pkg or pkg["homepage"] in (None, "NOASSERTION")
