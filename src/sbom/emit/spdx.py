"""SPDX 2.3 JSON emitter.

Builds a :class:`spdx_tools.spdx.model.document.Document` from a reconciled
:class:`~sbom.models.Document` via ``spdx-tools``' object model and serializes it
to JSON. Implements the design's field-mapping table:

* each subject -> a ``Package`` + a ``DESCRIBES`` relationship from the document
* per-root ``DependencyEdge`` -> ``DEPENDS_ON`` / ``BUILD_DEPENDENCY_OF`` /
  ``GENERATED_FROM`` relationships with the owning ``Package`` as endpoint
* ``EnvironmentTool`` -> ``annotations`` (NEVER a ``Package``)
* purl -> ``externalRef`` (PACKAGE-MANAGER / purl), not the SPDXID
* ``checksums.sha256`` -> ``Package.checksums``
* ``canonical_url``/``resolved_url_or_path`` -> ``externalRef`` + ``downloadLocation``
  (with ``options.guess_pypi_urls`` a Python component with no resolved URL gets a
  constructed ``https://pypi.org/project/<name>/[<version>/]`` ``downloadLocation``)
* ``source_version``/``effective_version``/``patches`` -> package ``comment`` +
  a ``GENERATED_FROM`` relationship to a source package
* ``integrity_findings`` / per-observation facts / alias relation -> ``annotations``
* non-SPDX license -> ``LicenseRef-...`` + ``hasExtractedLicensingInfos``
* ``completeness`` -> per-component ``sbomgen:completeness:*`` annotations (NOT the
  document ``comment``)

With ``options.reproducible`` the ``created`` timestamp is fixed (from
``source_date_epoch``) and the ``documentNamespace`` is derived from a content
hash, with stable ordering, so two runs are byte-identical.
"""

from __future__ import annotations

import hashlib
import io
import re

from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo, Document as SpdxDocument
from spdx_tools.spdx.model.extracted_licensing_info import ExtractedLicensingInfo
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    PackagePurpose,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.version import Version
from spdx_tools.spdx.writer.json.json_writer import write_document_to_stream

from ..models import (
    Component,
    Document,
    EnvironmentTool,
    Observation,
    RefKind,
    RelationType,
    Subject,
)
from . import EmitOptions
from ._common import (
    PROP_NS,
    TOOL_NAME,
    component_purl,
    disambiguate_subject_ids,
    guessed_pypi_url,
    is_emittable_url,
    is_spdx_expression,
    licenseref_id_for,
    reproducible_timestamp,
    select_subjects,
    subject_closure_document,
    subject_purl,
)

import datetime

_FALLBACK_CREATED = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

# RelationType -> SPDX RelationshipType for an edge from owner -> dependency.
_EDGE_RELATIONSHIP = {
    RelationType.DEPENDS_ON: RelationshipType.DEPENDS_ON,
    RelationType.BUILD_DEPENDENCY_OF: RelationshipType.BUILD_DEPENDENCY_OF,
    RelationType.LINK: RelationshipType.DEPENDS_ON,
    RelationType.TOOLING: RelationshipType.BUILD_TOOL_OF,
}


def emit(document: Document, options: EmitOptions) -> str:
    """Build an SPDX 2.3 document and serialize it to a JSON string."""
    subjects = select_subjects(document.subjects, options.subjects)
    return _serialize(_build_document(document, subjects, options), options)


def emit_split(document: Document, options: EmitOptions) -> dict[str, str]:
    """Emit one SPDX doc per subject (filtered by ``options.subjects``).

    Only EMITTABLE subjects get their own document: an ownership-only grouping
    root (``emit_as_subject=False`` — a manual example / non-distributable test)
    has no subject package, so splitting it would yield a doc with component
    packages but no ``DESCRIBES`` relationship (invalid SPDX)."""
    subjects = select_subjects(document.subjects, options.subjects)
    out: dict[str, str] = {}
    for subject in subjects:
        if not subject.emit_as_subject:
            continue
        # Restrict to the subject's dependency closure so a split doc does not leak
        # other subjects' exclusive components.
        closure = subject_closure_document(document, subject)
        doc = _build_document(closure, [subject], options)
        out[subject.id] = _serialize(doc, options)
    return out


# ---------------------------------------------------------------------------
# Document construction
# ---------------------------------------------------------------------------


def _build_document(
    document: Document, subjects: list[Subject], options: EmitOptions
) -> SpdxDocument:
    annotations: list[Annotation] = []
    relationships: list[Relationship] = []
    extracted: dict[str, ExtractedLicensingInfo] = {}

    # Distinct discovered roots can share a Subject.id / slugify to the same
    # SPDXRef id; assign each subject object a unique emitted id so SPDXRef-Subject-*
    # never collides (invalid SPDX otherwise). Edges resolve by Subject.id via
    # ``subject_spdx_id`` (the first subject claiming an id owns that ref).
    unique_ids = disambiguate_subject_ids(subjects)

    packages: list[Package] = []
    subject_spdx_id: dict[str, str] = {}
    for subj in subjects:
        if not subj.emit_as_subject:
            continue
        spdx_id = _subject_spdx_id(unique_ids[id(subj)])
        subject_spdx_id.setdefault(subj.id, spdx_id)
        pkg = _subject_package(subj, spdx_id, extracted, annotations)
        packages.append(pkg)
        relationships.append(
            Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, spdx_id)
        )

    # Distinct component names can slug to the same SPDXRef id (``foo/bar`` and
    # ``foo-bar`` -> ``SPDXRef-Package-foo-bar``); SPDX forbids duplicate SPDXIDs.
    # ``claim`` walks a single shared id namespace, suffixing ``-<n>`` and
    # re-checking until the id is actually free -- so a ``-<n>`` form can't recreate
    # a collision with another component or with a ``-source`` pedigree id. The
    # stable sorted-by-name walk keeps it reproducible.
    used_spdx_ids: set[str] = set(subject_spdx_id.values())

    def claim(base: str) -> str:
        cand, n = base, 1
        while cand in used_spdx_ids:
            n += 1
            cand = f"{base}-{n}"
        used_spdx_ids.add(cand)
        return cand

    comp_spdx_id: dict[str, str] = {}
    extra_packages: list[Package] = []
    for comp in sorted(document.components, key=lambda c: c.name):
        spdx_id = claim(_component_spdx_id(comp))
        comp_spdx_id[comp.name] = spdx_id
        pkg = _component_package(
            comp, spdx_id, extracted, annotations, relationships, extra_packages,
            options, claim,
        )
        packages.append(pkg)
    packages.extend(extra_packages)

    _add_edges(
        document, subject_spdx_id, comp_spdx_id, subjects, relationships
    )
    _add_environment_tools(
        document.environment_tools, subjects, annotations, document
    )

    namespace = _namespace(document, subjects)
    created = reproducible_timestamp(options) or _now_or_fallback(options)

    doc_comment = _document_comment(document)

    creation_info = CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id="SPDXRef-DOCUMENT",
        name=_document_name(subjects),
        document_namespace=namespace,
        creators=[Actor(ActorType.TOOL, f"{TOOL_NAME}-{options.tool_version}")],
        created=created,
        license_list_version=Version(3, 20),
        document_comment=doc_comment,
    )

    return SpdxDocument(
        creation_info=creation_info,
        packages=packages,
        relationships=relationships,
        annotations=annotations,
        extracted_licensing_info=sorted(
            extracted.values(), key=lambda e: e.license_id or ""
        ),
    )


def _now_or_fallback(options: EmitOptions) -> datetime.datetime:
    if options.source_date_epoch is not None:
        return datetime.datetime.fromtimestamp(
            options.source_date_epoch, tz=datetime.timezone.utc
        )
    return datetime.datetime.now(tz=datetime.timezone.utc)


def _document_name(subjects: list[Subject]) -> str:
    emittable = [s for s in subjects if s.emit_as_subject]
    if emittable:
        return f"sbom-{emittable[0].identity.name}"
    return "sbom"


# ---------------------------------------------------------------------------
# Subjects -> Packages
# ---------------------------------------------------------------------------


def _subject_spdx_id(unique_id: str) -> str:
    return f"SPDXRef-Subject-{_slug(unique_id)}"


def _component_spdx_id(component: Component) -> str:
    return f"SPDXRef-Package-{_slug(component.name)}"


def _subject_package(
    subject: Subject,
    spdx_id: str,
    extracted: dict[str, ExtractedLicensingInfo],
    annotations: list[Annotation],
) -> Package:
    purl = subject_purl(subject)
    ext_refs = []
    if purl is not None:
        ext_refs.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=purl.to_string(),
            )
        )
    # Repo origin: the VCS locator becomes the downloadLocation (when a valid SPDX
    # location) and the browseable URL becomes the homepage.
    download = SpdxNoAssertion()
    if subject.vcs_url and _valid_download_location(subject.vcs_url):
        download = subject.vcs_url

    concluded = _license_value(subject.license, subject.license_text, extracted)
    pkg = Package(
        spdx_id=spdx_id,
        name=subject.identity.name,
        download_location=download,
        version=subject.identity.version,
        files_analyzed=False,
        homepage=subject.homepage or None,
        license_concluded=concluded,
        license_declared=concluded,
        copyright_text=subject.copyright or SpdxNoAssertion(),
        supplier=_supplier_actor(subject.supplier),
        external_references=ext_refs or None,
        primary_package_purpose=PackagePurpose.APPLICATION,
    )
    _annotate(
        annotations,
        spdx_id,
        [
            ("subject:id", subject.id),
            ("subject:role", subject.role.value),
            ("subject:build_graph_root", subject.build_graph_root_id),
            ("subject:repo_revision", subject.repo_revision),
        ],
    )
    for facet in subject.facets:
        val = f"{facet.kind.value}:{facet.name}"
        if facet.version:
            val = f"{val}@{facet.version}"
        _annotate(annotations, spdx_id, [("subject:facet", val)])
    for scope in subject.dependency_scopes:
        _annotate(
            annotations, spdx_id, [("subject:dependency_scope", scope.value)]
        )
    return pkg


# ---------------------------------------------------------------------------
# Components -> Packages
# ---------------------------------------------------------------------------


def _component_package(
    component: Component,
    spdx_id: str,
    extracted: dict[str, ExtractedLicensingInfo],
    annotations: list[Annotation],
    relationships: list[Relationship],
    extra_packages: list[Package],
    options: EmitOptions,
    claim=lambda x: x,
) -> Package:
    version = component.effective_version or component.source_version

    download = SpdxNoAssertion()
    for obs in component.observations:
        candidate = obs.canonical_url or obs.resolved_url_or_path
        if candidate and _valid_download_location(candidate):
            download = candidate
            break

    # opt-in guessed PyPI URL (Python components only) as the download_location.
    if options.guess_pypi_urls and isinstance(download, SpdxNoAssertion):
        pypi_url = guessed_pypi_url(component)
        if pypi_url is not None and _valid_download_location(pypi_url):
            download = pypi_url

    checksums = []
    sha = component.checksums.get("sha256") if component.checksums else None
    if sha:
        checksums.append(Checksum(ChecksumAlgorithm.SHA256, sha))

    ext_refs = []
    # PURL identity (PACKAGE-MANAGER / purl) — emitted whenever the component has
    # a purl, version-less or not, for parity with the subject emitter and the
    # CycloneDX output (an unpinned pypi dep still gets pkg:pypi/<name>).
    purl = component_purl(component)
    if purl is not None:
        ext_refs.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=purl.to_string(),
            )
        )
    for obs in component.observations:
        if is_emittable_url(obs.canonical_url):
            ext_refs.append(
                ExternalPackageRef(
                    category=ExternalPackageRefCategory.OTHER,
                    reference_type="canonical_url",
                    locator=obs.canonical_url,
                )
            )
            break

    comment = _component_comment(component)
    concluded = _license_value(component.license, None, extracted)

    pkg = Package(
        spdx_id=spdx_id,
        name=component.name,
        download_location=download,
        version=version,
        files_analyzed=False,
        checksums=checksums or None,
        license_concluded=concluded,
        license_declared=concluded,
        copyright_text=component.copyright or SpdxNoAssertion(),
        supplier=_supplier_actor(component.supplier),
        comment=comment,
        external_references=ext_refs or None,
        primary_package_purpose=PackagePurpose.LIBRARY,
    )

    # patches / source-vs-effective version -> a source Package the effective
    # package is GENERATED_FROM (design mapping table).
    has_source = (
        component.source_version is not None
        and component.effective_version is not None
        and component.source_version != component.effective_version
    )
    if has_source or component.patches:
        source_id = claim(f"{spdx_id}-source")
        source_pkg = Package(
            spdx_id=source_id,
            name=f"{component.name} (source)",
            download_location=download,
            version=component.source_version or version,
            files_analyzed=False,
            comment="upstream source before CANN build patches",
            primary_package_purpose=PackagePurpose.SOURCE,
        )
        extra_packages.append(source_pkg)
        relationships.append(
            Relationship(spdx_id, RelationshipType.GENERATED_FROM, source_id)
        )
        _annotate(
            annotations,
            spdx_id,
            [
                ("pedigree:source_version", component.source_version),
                ("pedigree:effective_version", component.effective_version),
            ],
        )
        for patch in component.patches:
            pval = patch.file
            if patch.sha256:
                pval = f"{patch.file} sha256:{patch.sha256}"
            _annotate(annotations, spdx_id, [("pedigree:patch", pval)])

    _annotate_component(component, spdx_id, annotations, options)
    if options.guess_pypi_urls and guessed_pypi_url(component) is not None:
        _annotate(
            annotations, spdx_id, [("python:download_url_source", "guessed")]
        )
    return pkg


def _component_comment(component: Component) -> str | None:
    parts = []
    if (
        component.source_version
        and component.effective_version
        and component.source_version != component.effective_version
    ):
        parts.append(
            f"patched build: source_version={component.source_version} "
            f"effective_version={component.effective_version}"
        )
    if component.patches:
        files = ", ".join(p.file for p in component.patches)
        parts.append(f"patches: {files}")
    return "; ".join(parts) if parts else None


def _annotate_component(
    component: Component,
    spdx_id: str,
    annotations: list[Annotation],
    options: EmitOptions,
) -> None:
    pairs: list[tuple[str, str | None]] = []
    for finding in component.integrity_findings:
        pairs.append((f"integrity:{finding.value}", "true"))
    for key, value in sorted(component.completeness.items()):
        pairs.append((f"completeness:{key}", str(value)))
    for alias in component.aliases:
        pairs.append(("alias:name", alias))
    for lang in component.languages:
        pairs.append(("language", lang))
    for scope in component.scopes:
        pairs.append(("obs:usage_scope", scope.value))
    if component.origin:
        pairs.append(("component:origin", component.origin))
    _annotate(annotations, spdx_id, pairs)

    # The verbose per-observation provenance (sbomgen:obs:N:*) is the bulk of the
    # output and is emitted only in --detail full; compact keeps the summary
    # signals above (integrity/completeness/alias/language/usage_scope).
    if options.detail == "full":
        for idx, obs in enumerate(component.observations):
            _annotate(annotations, spdx_id, _observation_pairs(obs, idx))


def _observation_pairs(obs: Observation, idx: int) -> list[tuple[str, str | None]]:
    p = f"obs:{idx}"
    pairs: list[tuple[str, str | None]] = [
        (f"{p}:source_kind", obs.source_kind.value),
        (f"{p}:source_file", obs.source_file),
        (f"{p}:source_revision", obs.source_revision),
        (f"{p}:root", obs.root_artifact_id),
        (f"{p}:reachability", obs.declaration_reachability.value),
        (f"{p}:unreachable_reason", obs.unreachable_reason),
        (f"{p}:version_constraint", obs.version_constraint),
        (f"{p}:canonical_url", obs.canonical_url),
        (f"{p}:resolved_url_or_path", obs.resolved_url_or_path),
    ]
    if obs.usage_scope is not None:
        pairs.append((f"{p}:usage_scope", obs.usage_scope.value))
    for cond in obs.activation_condition:
        pairs.append((f"{p}:activation", cond.expr))
    if obs.source_kind.value == "python_build":
        pairs.append((f"{p}:python_build", "true"))
    if obs.find_package is not None:
        fp = obs.find_package
        if fp.required is not None:
            pairs.append((f"{p}:fp_required", str(fp.required)))
        if fp.quiet is not None:
            pairs.append((f"{p}:fp_quiet", str(fp.quiet)))
        if fp.effective_required is not None:
            pairs.append((f"{p}:fp_effective_required", str(fp.effective_required)))
    return pairs


# ---------------------------------------------------------------------------
# Edges -> relationships
# ---------------------------------------------------------------------------


def _add_edges(
    document: Document,
    subject_spdx_id: dict[str, str],
    comp_spdx_id: dict[str, str],
    subjects: list[Subject],
    relationships: list[Relationship],
) -> None:
    def resolve(ref) -> str | None:
        if ref.kind == RefKind.SUBJECT:
            return subject_spdx_id.get(ref.id)
        return comp_spdx_id.get(ref.id)

    edges = sorted(
        document.edges,
        key=lambda e: (
            e.root_artifact_id or "",
            e.from_ref.kind.value,
            e.from_ref.id,
            e.to_ref.kind.value,
            e.to_ref.id,
            e.relation_type.value,
        ),
    )
    seen: set[tuple] = set()
    for edge in edges:
        src = resolve(edge.from_ref)
        dst = resolve(edge.to_ref)
        if src is None or dst is None:
            continue
        rel_type = _EDGE_RELATIONSHIP[edge.relation_type]
        comment = None
        if edge.usage_scope is not None:
            comment = f"usage_scope={edge.usage_scope.value}"
        # BUILD_DEPENDENCY_OF reads "<build-dep> BUILD_DEPENDENCY_OF <owner>", so
        # the dependency (to_ref) is the spdxElementId and the owning subject
        # (from_ref) is the relatedSpdxElement — inverted from DEPENDS_ON.
        element, related = (dst, src) if rel_type == RelationshipType.BUILD_DEPENDENCY_OF else (src, dst)
        # Several internal edges can map onto an IDENTICAL emitted relationship
        # (same endpoints/type/comment) — e.g. reconcile preserves source_file /
        # reachability variants that the SPDX relationship does not encode. Emit each
        # distinct relationship once (SPDX relationships are an unordered list with no
        # implicit dedup).
        key = (element, rel_type, related, comment)
        if key in seen:
            continue
        seen.add(key)
        relationships.append(Relationship(element, rel_type, related, comment=comment))


# ---------------------------------------------------------------------------
# Environment tools -> annotations on the document
# ---------------------------------------------------------------------------


def _add_environment_tools(
    tools: list[EnvironmentTool],
    subjects: list[Subject],
    annotations: list[Annotation],
    document: Document,
) -> None:
    subject_ids = {s.id for s in subjects if s.emit_as_subject}
    ordered = sorted(
        tools, key=lambda t: (t.root_artifact_id or "", t.name, t.source_file or "")
    )
    for idx, tool in enumerate(ordered):
        if (
            tool.root_artifact_id
            and subject_ids
            and tool.root_artifact_id not in subject_ids
        ):
            continue
        prefix = f"envtool:{idx}"
        pairs: list[tuple[str, str | None]] = [
            (f"{prefix}:name", tool.name),
            (f"{prefix}:path", tool.path),
            (f"{prefix}:version", tool.version),
            (
                f"{prefix}:required",
                None if tool.required is None else str(tool.required),
            ),
            (
                f"{prefix}:command_context",
                tool.command_context.value if tool.command_context else None,
            ),
            (f"{prefix}:source_file", tool.source_file),
            (f"{prefix}:source_revision", tool.source_revision),
            (f"{prefix}:source_authority", tool.source_authority),
            (f"{prefix}:root", tool.root_artifact_id),
        ]
        for cond in tool.activation_condition:
            pairs.append((f"{prefix}:activation", cond.expr))
        _annotate(annotations, "SPDXRef-DOCUMENT", pairs)


# ---------------------------------------------------------------------------
# Licenses
# ---------------------------------------------------------------------------


def _license_value(
    expr: str | None,
    text: str | None,
    extracted: dict[str, ExtractedLicensingInfo],
):
    """Return a parsed license expression for ``license_concluded``.

    A valid SPDX expression is parsed as-is. A non-SPDX expression/name is
    registered as a ``LicenseRef-...`` in ``extracted`` (with the text inlined
    when available) and returned as that symbol. ``None`` -> ``NoAssertion``.
    """
    from license_expression import get_spdx_licensing

    licensing = get_spdx_licensing()
    is_ref = bool(expr) and expr.lower().startswith("licenseref-")
    # A real SPDX expression (NOT a LicenseRef -- the SPDX license list does not
    # model those) with no extra text parses directly. A bare LicenseRef must NOT
    # short-circuit here: it has to fall through and be REGISTERED in `extracted`
    # (hasExtractedLicensingInfos), or the cited id is undefined and the document
    # is invalid.
    if expr and not is_ref and is_spdx_expression(expr) and not text:
        return licensing.parse(expr)
    if not expr and not text:
        return SpdxNoAssertion()

    ref_id = expr if is_ref else (licenseref_id_for(expr) if expr else "LicenseRef-Unknown")
    body = text or expr or "NOASSERTION"
    name = expr or ref_id
    existing = extracted.get(ref_id)
    # A SYNTHESIZED ref (from a license name/text) that slug-collides with a
    # different license must get a distinct id so a cited ref never rebinds to the
    # wrong text. An explicit LicenseRef id is a reference to ONE license -- never
    # disambiguated, just registered once.
    if not is_ref and existing is not None and (
        existing.extracted_text != body or existing.license_name != name
    ):
        import hashlib

        suffix = hashlib.sha1(f"{name}\x00{body}".encode("utf-8", "replace")).hexdigest()[:8]
        ref_id = f"{ref_id}-{suffix}"
        existing = extracted.get(ref_id)
    if existing is None:
        extracted[ref_id] = ExtractedLicensingInfo(
            license_id=ref_id, extracted_text=body, license_name=name,
        )
    return licensing.parse(ref_id)


# ---------------------------------------------------------------------------
# Document-level comment + namespace + helpers
# ---------------------------------------------------------------------------


def _document_comment(document: Document) -> str | None:
    # Per-component completeness is emitted as per-component
    # ``sbomgen:completeness:*`` annotations (see ``_annotate_component``), NOT
    # aggregated into the document comment — aggregating it flooded the global
    # comment with one entry per unpinned/unresolved dependency. There is no
    # other document-level info to surface here, so no document comment.
    return None


def _namespace(document: Document, subjects: list[Subject]) -> str:
    base = "https://spdx.org/spdxdocs/sbom-gen"
    name = _document_name(subjects)
    # A content-derived suffix keeps the namespace stable across reproducible
    # runs (no random UUID) yet unique to this document's content.
    fingerprint = _fingerprint(document, subjects)
    return f"{base}/{_slug(name)}-{fingerprint}"


def _fingerprint(document: Document, subjects: list[Subject]) -> str:
    h = hashlib.sha256()
    for subj in subjects:
        h.update(subj.id.encode("utf-8"))
        h.update((subj.identity.version or "").encode("utf-8"))
    for comp in sorted(document.components, key=lambda c: c.name):
        h.update(comp.name.encode("utf-8"))
        h.update((comp.effective_version or comp.source_version or "").encode())
    for edge in document.edges:
        h.update(edge.from_ref.id.encode("utf-8"))
        h.update(edge.to_ref.id.encode("utf-8"))
    return h.hexdigest()[:16]


def _annotate(
    annotations: list[Annotation],
    spdx_id: str,
    pairs: list[tuple[str, str | None]],
) -> None:
    for key, value in pairs:
        if value is None:
            continue
        annotations.append(
            Annotation(
                spdx_id=spdx_id,
                annotation_type=AnnotationType.OTHER,
                annotator=Actor(ActorType.TOOL, TOOL_NAME),
                annotation_date=_FALLBACK_CREATED,
                annotation_comment=f"{PROP_NS}:{key}={value}",
            )
        )


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9.\-]+", "-", text).strip("-") or "x"


def _supplier_actor(name: str | None):
    """A package ``supplier``: an Organization Actor when known, else NOASSERTION.

    NTIA requires a Supplier element; an explicit ``NOASSERTION`` is the honest
    "known unknown" rather than omitting the field (mirrors copyright_text). A
    blank / whitespace-only name is treated as unknown."""
    name = (name or "").strip()
    return Actor(ActorType.ORGANIZATION, name) if name else SpdxNoAssertion()


def _valid_download_location(location: str) -> bool:
    """True if ``location`` is a valid SPDX ``download_location``.

    Uses spdx-tools' own URI validator so an unexpanded CMake variable
    (``${CANN_3RD_LIB_PATH}/...``) or other non-URL path is never emitted as a
    download location (which the SPDX schema rejects); such values fall back to
    ``NOASSERTION``.
    """
    from spdx_tools.spdx.validation.uri_validators import (
        validate_download_location,
    )

    return validate_download_location(location) == []


# ---------------------------------------------------------------------------
# Serialization (with reproducible documentNamespace + fixed annotation dates)
# ---------------------------------------------------------------------------


def _serialize(document: SpdxDocument, options: EmitOptions) -> str:
    # Fix all annotation dates to the document creation date so reproducible
    # output is byte-identical (annotation_date is required by the model).
    created = document.creation_info.created
    for ann in document.annotations:
        ann.annotation_date = created

    buf = io.StringIO()
    write_document_to_stream(document, buf, validate=False)
    return buf.getvalue()
