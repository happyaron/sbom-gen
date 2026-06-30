"""Internal, format-agnostic data model for the SBOM generator.

This module is the single source of truth for the shapes that flow through the
three pipeline stages (Collect -> Reconcile -> Emit). It deliberately has NO
external dependencies: only the standard library. Collectors produce lists of
``Observation``/``Component``/``Subject``/``DependencyEdge``/``EnvironmentTool``/
``Warning`` records; ``reconcile`` merges them into a single ``Document``; the
emitters consume that ``Document``.

Design reference: ``SBOM_DESIGN.md`` rev. 12. Field names and enum members below
match that document exactly. In particular note:

* ``environment_tool`` is intentionally NOT a ``SourceKind`` -- an environment
  tool is a separate top-level record (:class:`EnvironmentTool`) and must never
  become a :class:`Component`.
* The two orthogonal axes ``declaration_reachability`` and ``usage_scope`` are
  never collapsed into a single "scope".
* ``DependencyEdge`` endpoints are typed (:class:`Ref` with ``kind`` =
  ``subject`` | ``component``) so the model can express ``subject -> component``
  and ``component -> component`` edges without inventing hidden records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SourceKind(str, Enum):
    """The declaration mechanism a single :class:`Observation` came from.

    ``environment_tool`` is intentionally absent: a host tool is recorded as a
    separate :class:`EnvironmentTool` and must never create a component.
    """

    CMAKE_EXTERNAL_PROJECT = "cmake_external_project"
    CMAKE_FETCH_CONTENT = "cmake_fetch_content"
    CMAKE_FIND_PACKAGE = "cmake_find_package"
    CMAKE_LINK_LIBRARY = "cmake_link_library"
    CMAKE_FIND_PROGRAM = "cmake_find_program"
    CMAKE_IMPORTED_EXECUTABLE = "cmake_imported_executable"
    CMAKE_BUILD_TOOLING = "cmake_build_tooling"
    PYTHON_REQUIREMENT = "python_requirement"
    PYTHON_SETUP = "python_setup"
    PYTHON_BUILD = "python_build"
    CANN_PACKAGE = "cann_package"
    INSTALLED_BINARY = "installed_binary"
    CURATED_NOTICE = "curated_notice"


class UsageScope(str, Enum):
    """Intended usage of a dependency, inferred from path/curated hints.

    This is the *intent* axis, distinct from :class:`DeclarationReachability`
    (whether the declaration is reached in a configure).
    """

    RUNTIME = "runtime"
    TEST = "test"
    BUILD = "build"
    EXAMPLE = "example"
    ST_TEST = "st_test"
    MANUAL_EXAMPLE = "manual_example"
    EXPERIMENTAL = "experimental"
    ENVIRONMENT = "environment"


class DeclarationReachability(str, Enum):
    """Whether a declaration is reached in a default/configured build."""

    REACHED = "reached"
    UNRESOLVED = "unresolved"
    UNREACHABLE = "unreachable"


class IntegrityFinding(str, Enum):
    """Stackable per-component integrity concerns (unioned across observations)."""

    NO_HASH = "no_hash"
    UNPINNED_GIT = "unpinned_git"
    TLS_VERIFICATION_DISABLED = "tls_verification_disabled"
    LOCAL_SOURCE_UNVERIFIED = "local_source_unverified"


class RelationType(str, Enum):
    """The semantic of a :class:`DependencyEdge`."""

    DEPENDS_ON = "depends_on"
    BUILD_DEPENDENCY_OF = "build_dependency_of"
    LINK = "link"
    TOOLING = "tooling"


class RefKind(str, Enum):
    """Whether a :class:`Ref` points at a subject or a component."""

    SUBJECT = "subject"
    COMPONENT = "component"


class SubjectKind(str, Enum):
    """The identity kind of a :class:`Subject`/:class:`Identity`."""

    CANN_PACKAGE = "cann_package"
    PYTHON_WHEEL = "python_wheel"
    CMAKE_PROJECT = "cmake_project"


class SubjectRole(str, Enum):
    """The role a :class:`Subject` plays in the combined SBOM.

    ``primary``/``sibling_artifact`` are core roles; the path-semantic roles
    (``example``/``st_test``/``manual_example``/``experimental``/
    ``non_distributable_test``) come from profile classification. The generic
    core only assigns ``cmake_project``/``unclassified`` when it discovers a
    standalone root.
    """

    PRIMARY = "primary"
    SIBLING_ARTIFACT = "sibling_artifact"
    MANUAL_EXAMPLE = "manual_example"
    EXAMPLE = "example"
    ST_TEST = "st_test"
    EXPERIMENTAL = "experimental"
    NON_DISTRIBUTABLE_TEST = "non_distributable_test"
    CMAKE_PROJECT = "cmake_project"
    UNCLASSIFIED = "unclassified"


class CmakeAuthorityBranch(str, Enum):
    """Which ``fetch_cann_cmake`` outcome wins (the four resolved outcomes)."""

    SKIPPED_EXISTING_PROJECT = "skipped_existing_project"
    LOCAL_DIR = "local_dir"
    TARBALL = "tarball"
    GIT = "git"


class CommandContext(str, Enum):
    """Where a program/tool invocation was found (for :class:`EnvironmentTool`)."""

    FIND_PROGRAM = "find_program"
    EXECUTE_PROCESS = "execute_process"
    ADD_CUSTOM_COMMAND = "add_custom_command"
    ADD_CUSTOM_TARGET = "add_custom_target"
    EP_CONFIGURE = "ep_configure"
    EP_BUILD = "ep_build"
    EP_INSTALL = "ep_install"
    EP_DOWNLOAD = "ep_download"
    EP_UPDATE = "ep_update"
    PATCH_COMMAND = "patch_command"


# ---------------------------------------------------------------------------
# Small value objects
# ---------------------------------------------------------------------------


@dataclass
class Identity:
    """A name/version identity tagged with a :class:`SubjectKind`."""

    kind: SubjectKind
    name: str
    version: str | None = None


@dataclass
class Facet:
    """An alternate identity of the SAME artifact (e.g. CMake project ≡ wheel)."""

    kind: SubjectKind
    name: str
    version: str | None = None


@dataclass
class SubjectMerge:
    """Instruction to collapse two discovered subjects into one.

    Returned by :meth:`sbom.profile.Profile.subject_facets` to drive the
    wheel↔CMake merge: the subject ``absorbed_subject_id`` is folded into
    ``keep_subject_id`` (e.g. CMake ``AscendOps`` into wheel ``ascend_ops``).
    ``build_graph_root_id`` names the ``cmake_project`` root that builds the kept
    subject; ``facet`` is the absorbed identity recorded on the kept subject's
    :attr:`Subject.facets`. ``discover_subjects`` applies the merge so both
    roots' deps attach to the same subject.
    """

    keep_subject_id: str
    absorbed_subject_id: str
    build_graph_root_id: str | None = None
    facet: Facet | None = None


@dataclass
class Ref:
    """A typed endpoint of a :class:`DependencyEdge`.

    ``id`` references either a :attr:`Subject.id` (when ``kind`` is
    ``subject``) or a :attr:`Component.name` (when ``kind`` is ``component``).
    """

    kind: RefKind
    id: str


@dataclass
class Patch:
    """A patch applied to a component's source, with its content hash."""

    file: str
    sha256: str | None = None


@dataclass
class VcsRef:
    """A version-control reference: what was requested vs what resolved."""

    requested: str | None = None
    resolved_commit: str | None = None


@dataclass
class FindPackageInfo:
    """``find_package`` requiredness facts for a ``cmake_find_package`` site.

    ``effective_required`` is derived from a nearby fatal check (e.g.
    ``GenerateEsPackage`` is ``QUIET`` yet fatal if missing); ``None`` means
    static parsing could not determine it.
    """

    required: bool | None = None
    quiet: bool | None = None
    effective_required: bool | None = None


@dataclass
class ActivationCondition:
    """A raw CMake/path/env gate, with an optional evaluated result.

    ``evaluated`` is set only when a build-profile assigns a concrete value;
    in ``declared-all`` it stays ``None`` (the raw expression is retained).
    """

    expr: str
    evaluated: bool | None = None


@dataclass
class Provenance:
    """Records which source file a particular field value came from."""

    field: str
    source: str


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------


@dataclass
class Observation:
    """One declaration site / mechanism for a component.

    The two orthogonal axes ``declaration_reachability`` (is it reached?) and
    ``usage_scope`` (what is it for?) are kept separate and never collapsed.
    Per-site facts (conditions, specifiers, URLs, ``find_package`` requiredness)
    live here so nothing is flattened onto the component's scalar fields.
    """

    source_kind: SourceKind
    source_file: str | None = None
    source_revision: str | None = None
    root_artifact_id: str | None = None

    declaration_reachability: DeclarationReachability = (
        DeclarationReachability.REACHED
    )
    unreachable_reason: str | None = None
    activation_condition: list[ActivationCondition] = field(default_factory=list)
    usage_scope: UsageScope | None = None
    version_constraint: str | None = None

    canonical_url: str | None = None
    resolved_url_or_path: str | None = None
    find_package: FindPackageInfo | None = None

    # extras, markers, hashes, link target, ...
    ecosystem_data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Subject (a.k.a. RootArtifact)
# ---------------------------------------------------------------------------


@dataclass
class Subject:
    """A distributable root artifact (a.k.a. RootArtifact).

    The repo builds multiple artifacts; each has its own identity and
    dependency set. ``facets`` capture alternate identities of the SAME
    artifact (wheel ≡ CMake project). ``build_graph_root_id`` names the
    ``cmake_project`` root that builds this subject. ``emit_as_subject`` is
    ``False`` for ownership-only grouping (non-distributable test/manual roots).
    ``dependency_scopes`` lists which scopes' deps belong to THIS subject.
    """

    id: str
    identity: Identity
    role: SubjectRole = SubjectRole.UNCLASSIFIED
    facets: list[Facet] = field(default_factory=list)
    build_graph_root_id: str | None = None
    emit_as_subject: bool = True
    supplier: str | None = None
    license: str | None = None
    license_text: str | None = None
    copyright: str | None = None
    source_path: str | None = None
    repo_revision: str | None = None
    purl: str | None = None
    dependency_scopes: list[UsageScope] = field(default_factory=list)
    #: Repo origin (see :mod:`sbom.origin`): the human project URL and a VCS
    #: locator (``git+https://host/owner/repo.git[@<rev>]``). The purl TYPE stays
    #: ``generic`` -- the origin rides as a ``vcs_url`` qualifier + native
    #: externalReferences / downloadLocation / homepage. ``None`` when the repo has
    #: no detectable origin and ``--repo-url`` was not given.
    homepage: str | None = None
    vcs_url: str | None = None


# Alias: the design refers to this type as both ``Subject`` and ``RootArtifact``.
RootArtifact = Subject


# ---------------------------------------------------------------------------
# Component
# ---------------------------------------------------------------------------


@dataclass
class Component:
    """A normalized dependency: unioned summary plus per-site observations.

    ``depends_on`` is a DERIVED rollup; the authority for edges is the
    document-level :class:`DependencyEdge` list. Scalar summary fields
    (``license``, ``supplier``, ...) are ``NOASSERTION``/``None`` until an
    enricher proves a value. ``scopes``, ``languages``, ``integrity_findings``
    and ``provenance`` are unioned across observations during reconcile.
    """

    name: str
    aliases: list[str] = field(default_factory=list)
    type: str = "library"  # library | application
    languages: list[str] = field(default_factory=list)
    scopes: list[UsageScope] = field(default_factory=list)

    source_version: str | None = None
    effective_version: str | None = None
    patches: list[Patch] = field(default_factory=list)

    supplier: str | None = None
    license: str | None = None
    copyright: str | None = None

    checksums: dict = field(default_factory=dict)  # {"sha256": ...}
    vcs_ref: VcsRef | None = None
    integrity_findings: list[IntegrityFinding] = field(default_factory=list)
    completeness: dict = field(default_factory=dict)  # e.g. {"python_transitives": "unresolved"}
    #: Supply-chain provenance class, DERIVED by reconcile (never by a collector):
    #: "first-party" (the repo's own / a sibling org component) | "third-party"
    #: (fetched OSS or a published package) | "unknown" (no proof of origin).
    origin: str | None = None
    #: A pre-resolved PURL string for NON-Python components, DERIVED by reconcile
    #: (curated upstream coordinate > mirror download_url > first-party vcs_url).
    #: Emitters serialize it verbatim; Python purls are still derived at emit.
    purl: str | None = None

    depends_on: list[str] = field(default_factory=list)  # derived rollup
    observations: list[Observation] = field(default_factory=list)
    provenance: list[Provenance] = field(default_factory=list)


def python_direct_reference(component: "Component") -> tuple[str, str] | None:
    """If a Python component's evidence is PURELY a VCS reference (``git+`` /
    ``hg+`` / ``svn+`` / ``bzr+``, e.g. ``git+https://github.com/acme/lib.git#egg=lib``),
    return ``(vcs_scheme, reference_url)``; else ``None``.

    A VCS reference points at a SOURCE REPO and is unambiguously NOT a
    PyPI-registry artifact, so it must receive neither a ``pkg:pypi`` purl NOR PyPI
    license/supplier enrichment (deps.dev / PyPI / ClearlyDefined keyed by
    ``pypi:<name>``) — a same-named registry package would otherwise supply a false
    license/supplier (the reviewed ``private-lib`` case).

    A plain direct-URL requirement (``torch @ https://download.pytorch.org/…/torch-2.7.1.whl``)
    is DELIBERATELY treated as registry-backed (returns ``None``): it is the named
    project pinned to a built distribution artifact, so the PyPI purl + license for
    that name are correct. Only a VCS source reference is suppressed. Shared by the
    emitters and the enrichers so the rule is defined once."""
    obs = component.observations or []
    if not obs:
        return None
    found: tuple[str, str] | None = None
    for o in obs:
        eco = o.ecosystem_data or {}
        vcs = eco.get("vcs")
        if not eco.get("direct_reference") or not vcs:
            return None  # a registry requirement or a direct-URL artifact -> registry-backed
        if found is None:
            found = (str(vcs), str(eco["direct_reference"]))
    return found


#: Hosts recognized as PyPI-compatible package indexes: a direct wheel URL from
#: one of these IS the named registry project (no name-collision risk).
_REGISTRY_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org", "download.pytorch.org"})


def _is_registry_host(host: str) -> bool:
    host = (host or "").lower()
    return host in _REGISTRY_HOSTS or host.endswith(".pythonhosted.org")


def python_unverified_direct_url(component: "Component") -> str | None:
    """For a Python component that is PURELY a direct-URL requirement (NOT a VCS
    ref, NOT a plain registry requirement) whose URL host is NOT a recognized
    package index, return that URL; else ``None``.

    Such a component is still given a ``pkg:pypi/<name>`` identity and PyPI
    enrichment (a wheel URL names the project), but on an UNVERIFIED host the name
    could collide with an unrelated PyPI project — so the caller surfaces a
    ``python_direct_url_unverified_host`` warning. A wheel on a recognized index
    (e.g. ``torch @ download.pytorch.org``) returns ``None`` (no warning)."""
    obs = component.observations or []
    if not obs:
        return None
    url: str | None = None
    for o in obs:
        eco = o.ecosystem_data or {}
        ref = eco.get("direct_reference")
        if not ref or eco.get("vcs"):
            return None  # a registry requirement, or a VCS ref (handled separately)
        if url is None:
            url = str(ref)
    if url is None:
        return None
    from urllib.parse import urlsplit

    host = urlsplit(url.split("#", 1)[0]).hostname or ""
    return None if _is_registry_host(host) else url


# ---------------------------------------------------------------------------
# Dependency edge (first-class, per-root)
# ---------------------------------------------------------------------------


@dataclass
class DependencyEdge:
    """A first-class, per-root dependency relationship with typed endpoints.

    Keeping edges separate from the component summary preserves *whose*
    dependency an edge is: ``root_artifact_id`` records the owning subject so a
    combined SBOM can distinguish a dependency of ``ops_math`` from a dependency
    of an included example/ST root.
    """

    root_artifact_id: str | None
    from_ref: Ref
    to_ref: Ref
    relation_type: RelationType
    usage_scope: UsageScope | None = None
    declaration_reachability: DeclarationReachability = (
        DeclarationReachability.REACHED
    )
    source_file: str | None = None
    source_revision: str | None = None


# ---------------------------------------------------------------------------
# Environment tool (never a Component)
# ---------------------------------------------------------------------------


@dataclass
class EnvironmentTool:
    """A generic host tool. Emitted as properties/annotations, never a component.

    ``source_revision``/``source_authority`` are required because many tools
    come from the authoritative ``cann-cmake`` tree rather than the repo under
    analysis, so host-tool provenance must survive authority-branch changes.
    """

    name: str
    path: str | None = None
    version: str | None = None
    required: bool | None = None
    source_file: str | None = None
    source_revision: str | None = None
    source_authority: str | None = None
    command_context: CommandContext | None = None
    root_artifact_id: str | None = None
    activation_condition: list[ActivationCondition] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CMake source authority
# ---------------------------------------------------------------------------


@dataclass
class CmakeAuthority:
    """The resolved ``fetch_cann_cmake`` authority, computed pre-collection.

    All ``add_cann_third_party()`` resolution uses ``effective_cmake_root``,
    never the raw ``--cmake-root``. It is a filesystem path (every consumer --
    cmake/parse.py include resolution, cmake/trace.py, collectors/cpp.py macro
    resolution -- treats it as one). ``ref``/``revision`` stay ``str`` (a VCS
    ref name and resolved commit). ``authority_inputs`` records the proof inputs
    that drove branch selection, e.g.
    ``{"cann_3rd_lib_path": {"value": ..., "source": "cli|cache|unset"}}``.
    """

    branch: CmakeAuthorityBranch
    effective_cmake_root: Path | None = None
    ref: str | None = None
    revision: str | None = None
    verified: bool = False
    authority_inputs: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Structured warning
# ---------------------------------------------------------------------------


@dataclass
class Warning:
    """A first-class warning record, asserted on by tests and surfaced in output.

    ``code`` is a stable machine code (e.g. ``missing_hash``,
    ``unreachable_entry_point``, ``cann_cmake_tag_mismatch``,
    ``license_unresolved``, ``unmapped_link_library``, ``excluded_scope``).
    """

    code: str
    subject: str | None = None
    detail: str | None = None


# ---------------------------------------------------------------------------
# Top-level document container
# ---------------------------------------------------------------------------


@dataclass
class Document:
    """The complete internal SBOM: the output of reconcile, input to emit."""

    subjects: list[Subject] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    edges: list[DependencyEdge] = field(default_factory=list)
    environment_tools: list[EnvironmentTool] = field(default_factory=list)
    warnings: list[Warning] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


# Alias: the design refers to the container as both ``Sbom`` and ``Document``.
Sbom = Document
