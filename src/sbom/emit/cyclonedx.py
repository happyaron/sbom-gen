"""CycloneDX 1.5 JSON emitter.

Builds a :class:`cyclonedx.model.bom.Bom` from a reconciled
:class:`~sbom.models.Document` via ``cyclonedx-python-lib``'s object model and
serializes it to JSON. Implements the design's field-mapping table:

* identity/version + purl -> ``component.name/version`` + ``component.purl``
* per-root ``DependencyEdge`` graph -> ``dependencies`` rooted at the owning
  subject/component (typed endpoints resolved to bom-refs)
* ``source_version``/``effective_version``/``patches`` -> ``component.pedigree``
* ``canonical_url``/``resolved_url_or_path`` -> ``externalReferences``; with
  ``options.guess_pypi_urls`` a Python component also gets a constructed
  ``https://pypi.org/project/<name>/[<version>/]`` DISTRIBUTION externalReference
  (plus a ``sbomgen:python:download_url_source=guessed`` property)
* ``checksums.sha256`` -> ``component.hashes``
* ``integrity_findings`` + per-observation facts (source_revision, reachability,
  activation, usage_scope, python_build) + alias relation + completeness ->
  ``sbomgen:*`` ``properties`` (and ``evidence.occurrences``)
* ``EnvironmentTool`` -> BOM ``properties`` ``sbomgen:envtool:*`` (NEVER a component)
* non-SPDX license -> ``license.name`` + ``license.text``
* sibling/root subjects -> extra ``components``

With ``options.reproducible`` the timestamp is fixed (from
``source_date_epoch``), the ``serialNumber`` is derived from a content hash, and
ordering is stabilized so two runs are byte-identical.
"""

from __future__ import annotations

import hashlib
import uuid

from cyclonedx.model import (
    AttachedText,
    ExternalReference,
    ExternalReferenceType,
    HashAlgorithm,
    HashType,
    Property,
    XsUri,
)
from cyclonedx.model.bom import Bom
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.model.component import (
    Component as CdxComponent,
    ComponentScope,
    ComponentType,
    Diff,
    Patch as CdxPatch,
    PatchClassification,
    Pedigree,
)
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

from ..models import (
    Component,
    DependencyEdge,
    Document,
    EnvironmentTool,
    Observation,
    RefKind,
    Subject,
    SubjectKind,
    UsageScope,
)
from . import EmitOptions
from ._common import (
    PROP_NS,
    TOOL_NAME,
    TOOL_VENDOR,
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

# Map our SubjectKind/component-type to CycloneDX ComponentType.
_CDX_TYPE = {
    "application": ComponentType.APPLICATION,
    "library": ComponentType.LIBRARY,
}

# UsageScope -> CycloneDX component scope (only runtime/optional are expressible).
_RUNTIME_SCOPES = {UsageScope.RUNTIME}
_OPTIONAL_SCOPES = {
    UsageScope.TEST,
    UsageScope.BUILD,
    UsageScope.EXAMPLE,
    UsageScope.ST_TEST,
    UsageScope.MANUAL_EXAMPLE,
    UsageScope.EXPERIMENTAL,
}


def emit(document: Document, options: EmitOptions) -> str:
    """Build a CycloneDX 1.5 BOM and serialize it to a JSON string."""
    subjects = select_subjects(document.subjects, options.subjects)
    return _serialize(_build_bom(document, subjects, options), options)


def emit_split(document: Document, options: EmitOptions) -> dict[str, str]:
    """Emit one sub-BOM per subject (filtered by ``options.subjects``)."""
    subjects = select_subjects(document.subjects, options.subjects)
    out: dict[str, str] = {}
    for subject in subjects:
        if not subject.emit_as_subject:
            continue  # ownership-only grouping root: no standalone sub-BOM
        # Restrict to the subject's dependency closure so a split BOM does not leak
        # other subjects' exclusive components.
        closure = subject_closure_document(document, subject)
        bom = _build_bom(closure, [subject], options, primary=subject)
        out[subject.id] = _serialize(bom, options)
    return out


# ---------------------------------------------------------------------------
# BOM construction
# ---------------------------------------------------------------------------


def _build_bom(
    document: Document,
    subjects: list[Subject],
    options: EmitOptions,
    *,
    primary: Subject | None = None,
) -> Bom:
    bom = Bom()

    if primary is None:
        primary = _pick_primary(subjects)
    extra_subjects = [s for s in subjects if s is not primary and s.emit_as_subject]

    # Distinct discovered roots can share a Subject.id / slugify to the same
    # bom-ref; assign each subject object a unique emitted id so the subject
    # bom-refs never collide. Edges resolve by Subject.id via ``subject_obj``
    # (the first subject claiming an id owns that ref).
    unique_ids = disambiguate_subject_ids(subjects)

    subject_obj = {}  # subject.id -> CdxComponent (a Dependable)
    if primary is not None:
        meta = _subject_component(primary, unique_ids[id(primary)])
        bom.metadata.component = meta
        subject_obj.setdefault(primary.id, meta)
    for subj in extra_subjects:
        comp = _subject_component(subj, unique_ids[id(subj)])
        bom.components.add(comp)
        subject_obj.setdefault(subj.id, comp)

    comp_obj = {}  # component.name -> CdxComponent (a Dependable)
    for comp in sorted(document.components, key=lambda c: c.name):
        cdx = _component(comp, options)
        bom.components.add(cdx)
        comp_obj[comp.name] = cdx

    _add_edges(bom, document, subject_obj, comp_obj, subjects)
    _add_environment_tools(bom, document.environment_tools, subjects)
    _add_document_properties(bom, document)

    # Metadata tool (deterministic).
    bom.metadata.tools.components.add(
        CdxComponent(
            type=ComponentType.APPLICATION,
            name=TOOL_NAME,
            group=TOOL_VENDOR,
            version=options.tool_version,
        )
    )

    ts = reproducible_timestamp(options)
    if ts is not None:
        bom.metadata.timestamp = ts

    return bom


def _pick_primary(subjects: list[Subject]) -> Subject | None:
    from ..models import SubjectRole

    if not subjects:
        return None
    for subj in subjects:
        if subj.role == SubjectRole.PRIMARY:
            return subj
    emittable = [s for s in subjects if s.emit_as_subject]
    return emittable[0] if emittable else subjects[0]


# ---------------------------------------------------------------------------
# Subjects
# ---------------------------------------------------------------------------


def _subject_ref(unique_id: str) -> str:
    return f"subject:{unique_id}"


def _component_ref(component: Component) -> str:
    return f"component:{component.name}"


def _subject_component(subject: Subject, unique_id: str) -> CdxComponent:
    ctype = (
        ComponentType.APPLICATION
        if subject.identity.kind != SubjectKind.CMAKE_PROJECT
        else ComponentType.LIBRARY
    )
    purl = subject_purl(subject)
    comp = CdxComponent(
        type=ctype,
        name=subject.identity.name,
        version=subject.identity.version,
        bom_ref=_subject_ref(unique_id),
        purl=purl,
    )
    _apply_license(comp, subject.license, subject.license_text, subject.identity.name)
    if subject.copyright:
        comp.copyright = subject.copyright
    if subject.supplier and subject.supplier.strip():
        comp.supplier = OrganizationalEntity(name=subject.supplier.strip())

    # Repo origin (native externalReferences): VCS locator + browseable homepage.
    if subject.vcs_url:
        comp.external_references.add(
            ExternalReference(
                type=ExternalReferenceType.VCS,
                url=XsUri(subject.vcs_url),
                comment="repo origin",
            )
        )
    if subject.homepage:
        comp.external_references.add(
            ExternalReference(
                type=ExternalReferenceType.WEBSITE,
                url=XsUri(subject.homepage),
                comment="repo homepage",
            )
        )

    props = comp.properties
    props.add(Property(name=f"{PROP_NS}:subject:id", value=subject.id))
    props.add(Property(name=f"{PROP_NS}:subject:role", value=subject.role.value))
    if subject.build_graph_root_id:
        props.add(
            Property(
                name=f"{PROP_NS}:subject:build_graph_root",
                value=subject.build_graph_root_id,
            )
        )
    if subject.repo_revision:
        props.add(
            Property(
                name=f"{PROP_NS}:subject:repo_revision", value=subject.repo_revision
            )
        )
    for facet in subject.facets:
        val = f"{facet.kind.value}:{facet.name}"
        if facet.version:
            val = f"{val}@{facet.version}"
        props.add(Property(name=f"{PROP_NS}:subject:facet", value=val))
    for scope in subject.dependency_scopes:
        props.add(
            Property(name=f"{PROP_NS}:subject:dependency_scope", value=scope.value)
        )
    return comp


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------


def _component(component: Component, options: EmitOptions) -> CdxComponent:
    ctype = _CDX_TYPE.get(component.type, ComponentType.LIBRARY)
    version = component.effective_version or component.source_version
    comp = CdxComponent(
        type=ctype,
        name=component.name,
        version=version,
        bom_ref=_component_ref(component),
        scope=_component_scope(component.scopes),
        purl=component_purl(component),
    )
    _apply_license(comp, component.license, None, component.name)
    if component.copyright:
        comp.copyright = component.copyright
    if component.supplier and component.supplier.strip():
        comp.supplier = OrganizationalEntity(name=component.supplier.strip())

    # checksums -> hashes
    sha = component.checksums.get("sha256") if component.checksums else None
    if sha:
        comp.hashes.add(HashType(alg=HashAlgorithm.SHA_256, content=sha))

    # pedigree (source/effective version + patches)
    pedigree = _pedigree(component)
    if pedigree is not None:
        comp.pedigree = pedigree

    # external references (URLs) + vcs ref
    _add_external_references(comp, component)

    # opt-in guessed PyPI URL (Python components only)
    if options.guess_pypi_urls:
        pypi_url = guessed_pypi_url(component)
        if pypi_url is not None:
            comp.external_references.add(
                ExternalReference(
                    type=ExternalReferenceType.DISTRIBUTION,
                    url=XsUri(pypi_url),
                    comment="guessed_pypi_url",
                )
            )
            comp.properties.add(
                Property(
                    name=f"{PROP_NS}:python:download_url_source", value="guessed"
                )
            )

    # evidence + sbomgen:* properties
    _add_component_properties(comp, component, options)

    return comp


def _component_scope(scopes: list[UsageScope]) -> ComponentScope | None:
    scope_set = set(scopes)
    if scope_set & _RUNTIME_SCOPES:
        return ComponentScope.REQUIRED
    if scope_set & _OPTIONAL_SCOPES:
        return ComponentScope.OPTIONAL
    return None


def _pedigree(component: Component) -> Pedigree | None:
    has_ancestor = (
        component.source_version is not None
        and component.effective_version is not None
        and component.source_version != component.effective_version
    )
    patches = []
    for patch in component.patches:
        text = None
        if patch.sha256:
            text = AttachedText(content=f"sha256:{patch.sha256}")
        diff = Diff(text=text, url=XsUri(patch.file)) if patch.file else None
        patches.append(CdxPatch(type=PatchClassification.UNOFFICIAL, diff=diff))

    if not has_ancestor and not patches:
        return None

    ancestors = None
    notes = None
    if has_ancestor:
        ancestors = [
            CdxComponent(
                type=ComponentType.LIBRARY,
                name=component.name,
                version=component.source_version,
                bom_ref=f"ancestor:{component.name}",
            )
        ]
        notes = (
            f"patched build: source_version={component.source_version} "
            f"effective_version={component.effective_version}"
        )
    return Pedigree(ancestors=ancestors, patches=patches or None, notes=notes)


def _add_external_references(comp: CdxComponent, component: Component) -> None:
    # Only URL-typed values reach an externalReference URL slot. A non-URL local
    # path or an unexpanded build-variable template (``${CANN_3RD_LIB_PATH}/...``)
    # is suppressed here (it would serialize as percent-encoded junk); the raw
    # value still survives as a sbomgen:obs:*:resolved_url_or_path property.
    seen: set[tuple[str, str]] = set()
    for obs in component.observations:
        if is_emittable_url(obs.canonical_url):
            key = (ExternalReferenceType.DISTRIBUTION.value, obs.canonical_url)
            if key not in seen:
                seen.add(key)
                comp.external_references.add(
                    ExternalReference(
                        type=ExternalReferenceType.DISTRIBUTION,
                        url=XsUri(obs.canonical_url),
                        comment="canonical_url",
                    )
                )
        if is_emittable_url(obs.resolved_url_or_path):
            key = (ExternalReferenceType.DISTRIBUTION.value, obs.resolved_url_or_path)
            if key not in seen:
                seen.add(key)
                comp.external_references.add(
                    ExternalReference(
                        type=ExternalReferenceType.DISTRIBUTION,
                        url=XsUri(obs.resolved_url_or_path),
                        comment="resolved_url_or_path",
                    )
                )
    if component.vcs_ref is not None:
        ref = component.vcs_ref
        url = ref.resolved_commit or ref.requested
        if url:
            comp.external_references.add(
                ExternalReference(
                    type=ExternalReferenceType.VCS,
                    url=XsUri(url),
                    comment="vcs_ref",
                )
            )


def _add_component_properties(
    comp: CdxComponent, component: Component, options: EmitOptions
) -> None:
    props = comp.properties

    for finding in component.integrity_findings:
        props.add(
            Property(name=f"{PROP_NS}:integrity:{finding.value}", value="true")
        )
    for key, value in sorted(component.completeness.items()):
        props.add(
            Property(name=f"{PROP_NS}:completeness:{key}", value=str(value))
        )
    for alias in component.aliases:
        props.add(Property(name=f"{PROP_NS}:alias:name", value=alias))
    for lang in component.languages:
        props.add(Property(name=f"{PROP_NS}:language", value=lang))
    for scope in component.scopes:
        props.add(Property(name=f"{PROP_NS}:obs:usage_scope", value=scope.value))
    if component.origin:
        props.add(
            Property(name=f"{PROP_NS}:component:origin", value=component.origin)
        )

    full = options.detail == "full"

    # The verbose per-observation provenance (sbomgen:obs:N:* properties) and the
    # evidence.occurrences array are emitted only in --detail full. Compact keeps
    # the summary signals above plus the dependency graph.
    if full:
        occurrences = _deduped_occurrences(component)
        if occurrences:
            comp.evidence = ComponentEvidence(occurrences=occurrences)
        for idx, obs in enumerate(component.observations):
            _observation_properties(props, obs, idx)


def _deduped_occurrences(component: Component) -> list[Occurrence]:
    """One occurrence per UNIQUE source location (collapse identical locations).

    A dependency shared by many roots (e.g. ``cann_device`` seen by 63 sample
    projects at the SAME ``source_file``) otherwise yields 63 identical
    occurrences. Dedup by location and keep one entry; the bom_ref is stable
    per-component (the location index) so ``--reproducible`` output is
    byte-identical."""
    occurrences: list[Occurrence] = []
    seen: set[str] = set()
    for obs in component.observations:
        location = obs.source_file or obs.resolved_url_or_path or obs.canonical_url
        if not location or location in seen:
            continue
        seen.add(location)
        ctx = obs.source_revision
        occurrences.append(
            Occurrence(
                bom_ref=f"occurrence-{component.name}-{len(occurrences)}",
                location=location,
                additional_context=f"source_revision={ctx}" if ctx else None,
            )
        )
    return occurrences


def _observation_properties(props, obs: Observation, idx: int) -> None:
    p = f"{PROP_NS}:obs:{idx}"
    props.add(Property(name=f"{p}:source_kind", value=obs.source_kind.value))
    if obs.source_file:
        props.add(Property(name=f"{p}:source_file", value=obs.source_file))
    if obs.source_revision:
        props.add(Property(name=f"{p}:source_revision", value=obs.source_revision))
    if obs.root_artifact_id:
        props.add(Property(name=f"{p}:root", value=obs.root_artifact_id))
    props.add(
        Property(
            name=f"{p}:reachability", value=obs.declaration_reachability.value
        )
    )
    if obs.unreachable_reason:
        props.add(
            Property(name=f"{p}:unreachable_reason", value=obs.unreachable_reason)
        )
    if obs.usage_scope is not None:
        props.add(Property(name=f"{p}:usage_scope", value=obs.usage_scope.value))
    if obs.version_constraint:
        props.add(
            Property(name=f"{p}:version_constraint", value=obs.version_constraint)
        )
    # The raw URL/path provenance (parity with SPDX annotations). These are plain
    # property values, so an unexpanded ${CANN_3RD_LIB_PATH}/... template is kept
    # verbatim here even though it is suppressed from the externalReference URL.
    if obs.canonical_url:
        props.add(Property(name=f"{p}:canonical_url", value=obs.canonical_url))
    if obs.resolved_url_or_path:
        props.add(
            Property(name=f"{p}:resolved_url_or_path", value=obs.resolved_url_or_path)
        )
    for cond in obs.activation_condition:
        props.add(Property(name=f"{p}:activation", value=cond.expr))
    if obs.source_kind.value == "python_build":
        props.add(Property(name=f"{p}:python_build", value="true"))
    if obs.find_package is not None:
        fp = obs.find_package
        if fp.required is not None:
            props.add(Property(name=f"{p}:fp_required", value=str(fp.required)))
        if fp.quiet is not None:
            props.add(Property(name=f"{p}:fp_quiet", value=str(fp.quiet)))
        if fp.effective_required is not None:
            props.add(
                Property(
                    name=f"{p}:fp_effective_required",
                    value=str(fp.effective_required),
                )
            )


# ---------------------------------------------------------------------------
# Edges (dependency graph)
# ---------------------------------------------------------------------------


def _add_edges(
    bom: Bom,
    document: Document,
    subject_obj: dict[str, CdxComponent],
    comp_obj: dict[str, CdxComponent],
    subjects: list[Subject],
) -> None:
    def resolve(ref) -> CdxComponent | None:
        if ref.kind == RefKind.SUBJECT:
            return subject_obj.get(ref.id)
        return comp_obj.get(ref.id)

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
    for edge in edges:
        src = resolve(edge.from_ref)
        dst = resolve(edge.to_ref)
        if src is None or dst is None:
            continue
        bom.register_dependency(src, [dst])


# ---------------------------------------------------------------------------
# Environment tools + document properties
# ---------------------------------------------------------------------------


def _add_environment_tools(
    bom: Bom, tools: list[EnvironmentTool], subjects: list[Subject]
) -> None:
    subject_ids = {s.id for s in subjects}
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
        prefix = f"{PROP_NS}:envtool:{idx}"
        bom.metadata.properties.add(Property(name=f"{prefix}:name", value=tool.name))
        if tool.path:
            bom.metadata.properties.add(
                Property(name=f"{prefix}:path", value=tool.path)
            )
        if tool.version:
            bom.metadata.properties.add(
                Property(name=f"{prefix}:version", value=tool.version)
            )
        if tool.required is not None:
            bom.metadata.properties.add(
                Property(name=f"{prefix}:required", value=str(tool.required))
            )
        if tool.command_context is not None:
            bom.metadata.properties.add(
                Property(
                    name=f"{prefix}:command_context",
                    value=tool.command_context.value,
                )
            )
        if tool.source_file:
            bom.metadata.properties.add(
                Property(name=f"{prefix}:source_file", value=tool.source_file)
            )
        if tool.source_revision:
            bom.metadata.properties.add(
                Property(
                    name=f"{prefix}:source_revision", value=tool.source_revision
                )
            )
        if tool.source_authority:
            bom.metadata.properties.add(
                Property(
                    name=f"{prefix}:source_authority", value=tool.source_authority
                )
            )
        if tool.root_artifact_id:
            bom.metadata.properties.add(
                Property(name=f"{prefix}:root", value=tool.root_artifact_id)
            )
        for cond in tool.activation_condition:
            bom.metadata.properties.add(
                Property(name=f"{prefix}:activation", value=cond.expr)
            )


def _add_document_properties(bom: Bom, document: Document) -> None:
    for key, value in sorted(document.metadata.items()):
        bom.metadata.properties.add(
            Property(name=f"{PROP_NS}:doc:{key}", value=str(value))
        )


# ---------------------------------------------------------------------------
# Licenses
# ---------------------------------------------------------------------------


def _apply_license(
    comp: CdxComponent,
    expr: str | None,
    text: str | None,
    name: str,
) -> None:
    if not expr and not text:
        return
    if expr and is_spdx_expression(expr) and not text:
        comp.licenses.add(LicenseExpression(value=expr))
        return
    # Non-SPDX (or has inline text): emit as a named license with text.
    license_id = licenseref_id_for(expr) if expr else None
    attached = AttachedText(content=text) if text else None
    comp.licenses.add(
        DisjunctiveLicense(
            name=expr or license_id or name,
            text=attached,
        )
    )


# ---------------------------------------------------------------------------
# Serialization (with reproducible serialNumber)
# ---------------------------------------------------------------------------


def _serialize(bom: Bom, options: EmitOptions) -> str:
    if options.reproducible:
        # Derive a stable serial number from the content of a first pass.
        bom.serial_number = uuid.UUID(int=0)
        provisional = _output(bom)
        digest = hashlib.sha256(provisional.encode("utf-8")).digest()
        bom.serial_number = uuid.UUID(bytes=digest[:16], version=5)
    return _output(bom)


def _output(bom: Bom) -> str:
    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_5)
    return outputter.output_as_string(indent=2)
