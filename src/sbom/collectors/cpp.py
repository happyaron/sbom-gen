"""C++/CMake collector.

Turns a repo's CMake graph into model records (components, observations,
edges, environment tools) per the design's ``CppCollector``.  All
``add_cann_third_party()``-style macro and ``include()`` resolution is done
against :attr:`CmakeAuthority.effective_cmake_root` (never the raw
``--cmake-root``).  Every produced :class:`Observation`/:class:`DependencyEdge`
carries ``root_artifact_id`` and ``source_revision`` so ownership and
authority survive reconcile and emit.

The heavy static CMake parsing lives in :mod:`sbom.cmake.parse`; this module is
the policy layer that turns those structured records into model objects, builds
typed edges, records patched identity, classifies link tokens and program/tool
invocations, and routes profile hooks.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ..config import Config
from ..models import (
    ActivationCondition,
    CmakeAuthority,
    Component,
    DeclarationReachability,
    DependencyEdge,
    Observation,
    Patch,
    Ref,
    RefKind,
    RelationType,
    SourceKind,
    Subject,
    SubjectRole,
    UsageScope,
    VcsRef,
    Warning,
)
from ..profile import Profile
from . import CollectResult
from ..cmake import parse
from .. import graph


# ---------------------------------------------------------------------------
# Scope inference from path / curated hints
# ---------------------------------------------------------------------------

#: Path fragments -> usage scope.  Order matters (most specific first).
_PATH_SCOPE_HINTS: list[tuple[str, UsageScope]] = [
    ("/tests/st/", UsageScope.ST_TEST),
    ("/test/st/", UsageScope.ST_TEST),
    ("/tests/ut", UsageScope.TEST),
    ("/ut.cmake", UsageScope.TEST),
    ("/tests/", UsageScope.TEST),
    ("/test/", UsageScope.TEST),
    ("/examples/", UsageScope.EXAMPLE),
    ("/example/", UsageScope.EXAMPLE),
    ("/experimental/", UsageScope.EXPERIMENTAL),
    # gtest_shared.cmake defines the shared-build googletest fragment; it is only
    # pulled in for the test (ut) closure, so its ExternalProject_Add target
    # (gtest_shared_build) is TEST-scoped at the call site even though the
    # fragment is appended directly rather than reached through ut.cmake.
    ("/gtest_shared.cmake", UsageScope.TEST),
    # fetch_cann_cmake.cmake only acquires the build-time CMake tooling tree
    # (cann-cmake); its declarations are BUILD scope, never runtime.
    ("/fetch_cann_cmake.cmake", UsageScope.BUILD),
    ("/package.cmake", UsageScope.BUILD),
]


def _scope_from_path(path: str | None) -> UsageScope | None:
    if not path:
        return None
    norm = path.replace("\\", "/").lower()
    for fragment, scope in _PATH_SCOPE_HINTS:
        if fragment in norm:
            return scope
    return None


def _role_to_scope(role: SubjectRole) -> UsageScope | None:
    """Map a discovered root's role to a usage scope for its deps."""
    return {
        SubjectRole.EXAMPLE: UsageScope.EXAMPLE,
        SubjectRole.ST_TEST: UsageScope.ST_TEST,
        SubjectRole.MANUAL_EXAMPLE: UsageScope.MANUAL_EXAMPLE,
        SubjectRole.EXPERIMENTAL: UsageScope.EXPERIMENTAL,
        SubjectRole.NON_DISTRIBUTABLE_TEST: UsageScope.TEST,
    }.get(role)


# ---------------------------------------------------------------------------
# Link-token alias normalization (built-in OSS spellings only; the full alias
# map lives in reconcile/profile -- unmapped externals surface there).
# ---------------------------------------------------------------------------

_BUILTIN_LINK_ALIASES = {
    "eigen": "eigen",
    "eigen3::eigen": "eigen",
    "eigen3": "eigen",
    "gtest": "gtest",
    "gtest_main": "gtest",
    "gmock": "gtest",
    "json": "json",
    "nlohmann_json": "json",
    "nlohmann-json": "json",
}


def _normalize_link_name(raw: str) -> str:
    return _BUILTIN_LINK_ALIASES.get(raw.lower(), raw)


# ---------------------------------------------------------------------------
# Defensive guard: never mint a component from an unexpanded CMake variable.
# ---------------------------------------------------------------------------

#: An unexpanded CMake variable reference (``${ARGN}``, ``${CMAKE_AR}``,
#: ``lib${FOO}``). Belt-and-suspenders alongside the parse.py classifiers: a name
#: matching this must never become a Component (it is a parse artifact, not a
#: dependency), e.g. ``find_package(${ARGN})`` inside a wrapper macro.
_UNEXPANDED_VAR_RE = re.compile(r"\$\{[^}]*\}")


def _is_unexpanded_var_name(name: str | None) -> bool:
    return bool(name) and bool(_UNEXPANDED_VAR_RE.search(name))


# ---------------------------------------------------------------------------
# Reachability: dead config flags (no consumer in the tree)
# ---------------------------------------------------------------------------

#: Config flags whose declarations are recorded but provably never reached.
_DEAD_CONFIG_FLAGS = {"ENABLE_TORCH_EXTENSION"}


def _condition_is_dead(conditions: list[ActivationCondition]) -> str | None:
    """Return the dead-config-flag reason if any condition references one."""
    for cond in conditions:
        for flag in _DEAD_CONFIG_FLAGS:
            if flag in cond.expr:
                return "dead_config_flag"
    return None


# ---------------------------------------------------------------------------
# Helpers to turn parse.py records into model objects
# ---------------------------------------------------------------------------


def _integrity_findings_from_parse(findings: list) -> list:
    """parse.py reports IntegrityFinding members directly; pass through."""
    return list(findings or [])


def _component_from_external_project(
    ep, *, source_revision: str | None
) -> Component:
    """Build a Component from an ExternalProject record, recording patched
    identity: source_version (filename/URL) vs effective_version (set(*_VERSION))
    when a patch rewrites it."""
    source_version = ep.source_version
    effective_version = ep.set_version if ep.set_version is not None else source_version

    vcs = ep.vcs_ref
    if vcs is None and (ep.git_repository or ep.git_tag):
        vcs = VcsRef(requested=ep.git_tag)

    checksums = {}
    if ep.url_hash:
        checksums["sha256"] = ep.url_hash

    comp = Component(
        name=ep.name,
        source_version=source_version,
        effective_version=effective_version,
        patches=list(ep.patches or []),
        checksums=checksums,
        vcs_ref=vcs,
        integrity_findings=_integrity_findings_from_parse(ep.integrity_findings),
    )
    return comp


def _component_from_fetch_content(fc, *, source_revision: str | None) -> Component:
    vcs = fc.vcs_ref
    if vcs is None and (fc.git_repository or fc.git_tag):
        vcs = VcsRef(requested=fc.git_tag)
    checksums = {}
    if fc.url_hash:
        checksums["sha256"] = fc.url_hash
    return Component(
        name=fc.name,
        checksums=checksums,
        vcs_ref=vcs,
        patches=list(fc.patches or []),
        integrity_findings=_integrity_findings_from_parse(fc.integrity_findings),
    )


# ---------------------------------------------------------------------------
# Per-observation source revision (cann-cmake ref vs repo git rev)
# ---------------------------------------------------------------------------


def _git_describe(repo_root: Path) -> str | None:
    """Best-effort ``git describe`` of the repo under analysis (cached once).

    Used to stamp observations whose facts come from files under the repo
    itself (ops-math) rather than the authoritative cann-cmake tree. Returns
    ``None`` when not a git checkout or git is unavailable.
    """
    for args in (
        ["describe", "--tags", "--always", "--dirty"],
        ["rev-parse", "--short", "HEAD"],
    ):
        try:
            out = subprocess.run(
                ["git", "-C", str(repo_root), *args],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    return None


class _RevisionResolver:
    """Maps a source_file path to the right ``source_revision``.

    Files under ``effective_cmake_root`` carry the authoritative cann-cmake
    ref/revision; files under ``repo_root`` carry the repo's own git revision
    (resolved once via ``git describe`` and cached). Anything else falls back to
    the cann-cmake authority revision so provenance is never lost.
    """

    def __init__(
        self,
        *,
        repo_root: Path,
        effective_root: Path | None,
        cmake_revision: str | None,
    ):
        self._repo_root = self._resolve(repo_root)
        self._effective_root = self._resolve(effective_root)
        self._cmake_revision = cmake_revision
        self._repo_revision: str | None = None
        self._repo_revision_resolved = False

    @staticmethod
    def _resolve(p: Path | None) -> Path | None:
        if p is None:
            return None
        try:
            return p.resolve()
        except OSError:
            return p

    def _repo_rev(self) -> str | None:
        if not self._repo_revision_resolved:
            self._repo_revision_resolved = True
            if self._repo_root is not None:
                self._repo_revision = _git_describe(self._repo_root)
        return self._repo_revision

    def for_file(self, source_file: str | None) -> str | None:
        if source_file is None:
            return self._cmake_revision
        try:
            p = Path(source_file).resolve()
        except OSError:
            p = Path(source_file)
        # cann-cmake tree wins: its fragments carry the pinned ref/revision.
        if self._effective_root is not None and _is_under(p, self._effective_root):
            return self._cmake_revision
        if self._repo_root is not None and _is_under(p, self._repo_root):
            return self._repo_rev() or self._cmake_revision
        return self._cmake_revision


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# The collector
# ---------------------------------------------------------------------------


def collect(
    config: Config,
    profile: Profile,
    authority: CmakeAuthority,
    subjects: list[Subject],
) -> CollectResult:
    """Run the full C++/CMake collection.  See module docstring + INTERFACE."""
    result = CollectResult()

    effective_root = authority.effective_cmake_root
    source_revision = authority.revision or authority.ref

    custom_macros = profile.custom_dep_macros()
    profile_tooling = _profile_tooling_names(profile)

    revisions = _RevisionResolver(
        repo_root=config.repo_root,
        effective_root=effective_root,
        cmake_revision=source_revision,
    )

    # Index subjects by id, and figure out which subject each cmake root builds.
    primary = _primary_subject(subjects)

    #: (macro_name, dep_name) custom-dep-macro calls whose fragment did not resolve
    #: -- the dependency is OMITTED, so we must warn rather than silently undercount.
    unresolved_deps: set[tuple[str, str]] = set()

    # 1-8: per-subject CMake graph walk.
    for subject in subjects:
        entry = _subject_entry_cmake(subject, config.repo_root)
        if entry is None:
            continue
        files = _parse_graph(entry, effective_root, custom_macros)
        _record_unresolved_dep_macros(
            files, custom_macros, effective_root, unresolved_deps
        )
        # (h) ccache: scan cann-cmake's prepare.cmake (+ gtest_shared.cmake when
        # in the include closure) for find_program ProgramInvocations so
        # find_program(CCACHE_PROGRAM ccache) is captured even when those files
        # are reached only through the custom-macro/closure rather than a plain
        # include() the static walk follows.
        files = _augment_with_tooling_files(files, effective_root)
        if not files:
            continue
        _collect_from_files(
            files,
            subject=subject,
            result=result,
            revisions=revisions,
            profile_tooling=profile_tooling,
        )

    # Surface every custom-dep-macro (add_cann_third_party(...)) call whose fragment
    # could not be resolved -- so an incomplete SBOM (e.g. missing --cmake-root ->
    # no protobuf/json/...) is a visible warning, not a silent undercount.
    for macro_name, dep in sorted(unresolved_deps):
        result.warnings.append(
            Warning(
                code="unresolved_third_party",
                subject=dep,
                detail=(
                    f"{macro_name}({dep}) did not resolve -- the CMake fragment "
                    f"'third_party/{dep}.cmake' was not found under the effective "
                    f"cmake tree ({effective_root}); this dependency is OMITTED from "
                    "the SBOM. Pass --cmake-root pointing at the cann-cmake tree."
                ),
            )
        )

    # 5: CANN package deps via profile.package_metadata (version.cmake set_cann_*).
    if primary is not None:
        for obs in profile.package_metadata(config.repo_root, authority):
            if obs.root_artifact_id is None:
                obs.root_artifact_id = primary.id
            if obs.source_revision is None:
                obs.source_revision = revisions.for_file(obs.source_file)
            result.observations.append(obs)
            comp_name = _observation_component_name(obs)
            if comp_name:
                result.edges.append(
                    DependencyEdge(
                        root_artifact_id=primary.id,
                        from_ref=Ref(kind=RefKind.SUBJECT, id=primary.id),
                        to_ref=Ref(kind=RefKind.COMPONENT, id=comp_name),
                        relation_type=RelationType.DEPENDS_ON,
                        usage_scope=obs.usage_scope,
                        declaration_reachability=obs.declaration_reachability,
                        source_file=obs.source_file,
                        source_revision=obs.source_revision,
                    )
                )

    # 9: build tooling (cann-cmake) via profile.build_tooling.
    tooling_components, tooling_warnings = profile.build_tooling(
        config.repo_root, authority
    )
    result.warnings.extend(tooling_warnings)
    for comp in tooling_components:
        result.components.append(comp)
        if primary is not None:
            result.edges.append(
                DependencyEdge(
                    root_artifact_id=primary.id,
                    from_ref=Ref(kind=RefKind.SUBJECT, id=primary.id),
                    to_ref=Ref(kind=RefKind.COMPONENT, id=comp.name),
                    relation_type=RelationType.TOOLING,
                    usage_scope=UsageScope.BUILD,
                    source_revision=source_revision,
                )
            )

    # (b) EDGE HYGIENE: drop self-loops and de-duplicate.
    result.edges = _clean_edges(result.edges)

    return result


# ---------------------------------------------------------------------------
# Edge hygiene: drop self-loops + de-duplicate
# ---------------------------------------------------------------------------


def _clean_edges(edges: list[DependencyEdge]) -> list[DependencyEdge]:
    """Drop ``from_ref==to_ref`` self-loops (protobuf->protobuf, json->json from
    collapsing protobuf_* build targets) and de-duplicate by the SEMANTIC edge key.

    Uses :func:`sbom.graph.semantic_edge_key` (shared with reconcile/emit), which
    keys on the endpoints/relation + ``usage_scope`` + ``declaration_reachability``
    — so a runtime vs. build/test variant stays distinct — but NOT the pure
    provenance fields, so the same logical edge declared in two ``.cmake`` files
    collapses to one graph edge (splitting it would emit duplicate SPDX
    relationships)."""
    return graph.dedup_edges(edges, key=graph.semantic_edge_key)


# ---------------------------------------------------------------------------
# Graph walking + record translation
# ---------------------------------------------------------------------------


def _collect_from_files(
    files,
    *,
    subject: Subject,
    result: CollectResult,
    revisions: _RevisionResolver,
    profile_tooling: set[str],
) -> None:
    """Translate every parsed CMakeFile into model records owned by ``subject``."""
    root_id = subject.id
    # Track which usage scope a root's deps default to (path-classified role).
    root_scope = _role_to_scope(subject.role)

    # Collect local target names across the whole graph for link classification.
    local_targets = _local_target_names(files)

    # Index components by name within this graph so file-level findings (opbase)
    # and protoc tooling observations can attach to an already-built component.
    comp_index: dict[str, Component] = {}

    for cf in files:
        file_path = str(cf.path)
        # (d) usage_scope derives from the CALL SITE chain (the including file),
        # not the fragment's own definition path: gtest.cmake included from
        # ut.cmake is test-scoped even though gtest.cmake itself is path-neutral.
        file_scope = _call_site_scope(cf, root_scope)
        # (d) the macro/include gate (e.g. add_cann_third_party's
        # TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD) is prepended to every
        # observation declared in the included fragment.
        site_conditions = list(cf.call_site_conditions or [])
        rev = revisions.for_file(file_path)

        # 2-3: ExternalProject_Add -> component + observation + edges.
        for ep in cf.external_projects:
            if _is_unexpanded_var_name(ep.name):
                continue
            comp = _component_from_external_project(ep, source_revision=rev)
            obs = Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                source_file=file_path,
                source_revision=rev,
                root_artifact_id=root_id,
                usage_scope=file_scope,
                activation_condition=list(site_conditions),
                canonical_url=ep.canonical_url,
                resolved_url_or_path=ep.resolved_url_or_path,
                ecosystem_data={"name": comp.name},
            )
            comp.observations.append(obs)
            result.components.append(comp)
            comp_index.setdefault(comp.name, comp)
            # subject -> component edge.
            result.edges.append(
                DependencyEdge(
                    root_artifact_id=root_id,
                    from_ref=Ref(kind=RefKind.SUBJECT, id=root_id),
                    to_ref=Ref(kind=RefKind.COMPONENT, id=comp.name),
                    relation_type=RelationType.DEPENDS_ON,
                    usage_scope=file_scope,
                    source_file=file_path,
                    source_revision=rev,
                )
            )
            # DEPENDS args -> component -> component edges (protobuf -> abseil-cpp).
            # Endpoints carry the collector's best-effort canonical spelling of
            # the well-known build-target names; reconcile's alias map remains the
            # final authority for de-dup.
            from_name = _depends_target_name(comp.name)
            for dep in ep.depends:
                result.edges.append(
                    DependencyEdge(
                        root_artifact_id=root_id,
                        from_ref=Ref(kind=RefKind.COMPONENT, id=from_name),
                        to_ref=Ref(
                            kind=RefKind.COMPONENT, id=_depends_target_name(dep)
                        ),
                        relation_type=RelationType.DEPENDS_ON,
                        usage_scope=file_scope,
                        source_file=file_path,
                        source_revision=rev,
                    )
                )

        # 2-3: FetchContent_Declare -> component + observation + edge.
        for fc in cf.fetch_contents:
            if _is_unexpanded_var_name(fc.name):
                continue
            comp = _component_from_fetch_content(fc, source_revision=rev)
            obs = Observation(
                source_kind=SourceKind.CMAKE_FETCH_CONTENT,
                source_file=file_path,
                source_revision=rev,
                root_artifact_id=root_id,
                usage_scope=file_scope,
                activation_condition=list(site_conditions),
                canonical_url=fc.canonical_url,
                resolved_url_or_path=fc.resolved_url_or_path,
                ecosystem_data={"name": comp.name},
            )
            comp.observations.append(obs)
            result.components.append(comp)
            comp_index.setdefault(comp.name, comp)
            result.edges.append(
                DependencyEdge(
                    root_artifact_id=root_id,
                    from_ref=Ref(kind=RefKind.SUBJECT, id=root_id),
                    to_ref=Ref(kind=RefKind.COMPONENT, id=comp.name),
                    relation_type=RelationType.DEPENDS_ON,
                    usage_scope=file_scope,
                    source_file=file_path,
                    source_revision=rev,
                )
            )

        # 4: find_package() with conditions + requiredness.
        for fp in cf.find_packages:
            # find_package(${ARGN}) inside a wrapper macro (e.g. cann-cmake's
            # prepare.cmake) carries an unexpanded variable as its "name"; it is a
            # parse artifact, never a real package.
            if _is_unexpanded_var_name(fp.name):
                continue
            conds = _merge_activation(site_conditions, fp.conditions)
            reach, reason = _reachability_for(conds)
            obs = Observation(
                source_kind=SourceKind.CMAKE_FIND_PACKAGE,
                source_file=file_path,
                source_revision=rev,
                root_artifact_id=root_id,
                usage_scope=file_scope,
                declaration_reachability=reach,
                unreachable_reason=reason,
                activation_condition=conds,
                find_package=fp.info,
                # (a) NAME STASHING: every find_package observation that must
                # resolve to a component carries its canonical name.
                ecosystem_data={"name": fp.name},
            )
            result.observations.append(obs)
            result.edges.append(
                DependencyEdge(
                    root_artifact_id=root_id,
                    from_ref=Ref(kind=RefKind.SUBJECT, id=root_id),
                    to_ref=Ref(kind=RefKind.COMPONENT, id=fp.name),
                    relation_type=RelationType.DEPENDS_ON,
                    usage_scope=file_scope,
                    declaration_reachability=reach,
                    source_file=file_path,
                    source_revision=rev,
                )
            )

        # 7: raw link libraries -> classify; emit only externals.
        for tok in cf.link_tokens:
            kind = parse.classify_link_token(tok, local_targets)
            if kind != "external":
                continue
            name = _normalize_link_name(tok.raw)
            if _is_unexpanded_var_name(name):
                continue
            obs = Observation(
                source_kind=SourceKind.CMAKE_LINK_LIBRARY,
                source_file=file_path,
                source_revision=rev,
                root_artifact_id=root_id,
                usage_scope=file_scope,
                activation_condition=_merge_activation(site_conditions, tok.conditions),
                ecosystem_data={"name": name, "link_target": tok.raw},
            )
            result.observations.append(obs)
            result.edges.append(
                DependencyEdge(
                    root_artifact_id=root_id,
                    from_ref=Ref(kind=RefKind.SUBJECT, id=root_id),
                    to_ref=Ref(kind=RefKind.COMPONENT, id=name),
                    relation_type=RelationType.LINK,
                    usage_scope=file_scope,
                    source_file=file_path,
                    source_revision=rev,
                )
            )

        # add_dependencies() -> component -> component edges.
        for ad in cf.add_dependencies:
            from_name = _depends_target_name(ad.target)
            for dep in ad.depends_on:
                result.edges.append(
                    DependencyEdge(
                        root_artifact_id=root_id,
                        from_ref=Ref(kind=RefKind.COMPONENT, id=from_name),
                        to_ref=Ref(
                            kind=RefKind.COMPONENT, id=_depends_target_name(dep)
                        ),
                        relation_type=RelationType.DEPENDS_ON,
                        usage_scope=file_scope,
                        source_file=file_path,
                        source_revision=rev,
                    )
                )

        # 8: program/tool classifier over the full command grammar.
        for inv in cf.programs:
            route = parse.classify_program(inv, profile_tooling)
            if route == "ignore":
                continue
            prog_rev = revisions.for_file(inv.source_file or file_path)
            if route == "environment_tool":
                tool = parse.program_to_environment_tool(
                    inv,
                    source_revision=prog_rev,
                    source_authority=_authority_label(prog_rev),
                    root_artifact_id=root_id,
                )
                result.environment_tools.append(tool)
            else:  # "component" -> domain tool: observation on its component.
                # (g) protoc/host_protoc route to the protoc domain tool; stash
                # ecosystem_data['name']='protoc' so it resolves/attaches to the
                # protobuf component as a tooling observation.
                tool_name = _domain_tool_name(inv.name)
                # A domain tool (protoc/host_protoc/...) is build tooling: its
                # usage scope is BUILD unless the CALL SITE is more specifically
                # classified (e.g. a test fragment). It must NOT inherit the
                # path-neutral RUNTIME default that third-party libraries use, so
                # derive the scope from the path-based classifier directly.
                prog_scope = _program_call_site_scope(cf, root_scope)
                obs = Observation(
                    source_kind=_program_source_kind(inv),
                    source_file=inv.source_file or file_path,
                    source_revision=prog_rev,
                    root_artifact_id=root_id,
                    usage_scope=prog_scope,
                    activation_condition=_merge_activation(
                        site_conditions, inv.conditions
                    ),
                    ecosystem_data={
                        "name": tool_name,
                        "program": inv.name,
                        "path": inv.path,
                    },
                )
                result.observations.append(obs)

    # (e) opbase local_source_unverified + any other file-level findings:
    # attach to the matching component built above (the FetchContent target).
    for cf in files:
        for comp_name, findings in (cf.integrity_findings or {}).items():
            comp = comp_index.get(comp_name)
            if comp is None:
                continue
            for f in findings:
                if f not in comp.integrity_findings:
                    comp.integrity_findings.append(f)


# ---------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------


def _call_site_scope(cf, root_scope):
    """Usage scope for a fragment's deps, derived from its CALL SITE chain.

    Prefer the scope of the file that included this fragment (e.g. gtest.cmake
    included from ut.cmake -> test), then the fragment's own path, then the
    root's role scope. Generalizes the gtest two-axis fix: a fragment's intent
    follows where it is pulled in from, not where it is defined.

    When nothing classifies the call site (path-neutral fragment of a
    distributable root, ``root_scope is None``) the dependency is part of the
    root's runtime closure, so it defaults to ``RUNTIME`` rather than ``None``.
    This is what makes the main-product third-party (eigen/protobuf/json/opbase/
    securec/...) carry ``usage_scope=runtime`` and survive the release view's
    keep-only-runtime filter, while genuinely unclassified leaks stay scoped by
    their (test/build) call site and are dropped. Example/ST/experimental roots
    pass a non-``None`` ``root_scope`` and are unaffected.

    The call site is the WHOLE include chain, scanned nearest-first: a
    path-neutral leaf reached via ``ut.cmake (test) -> middle (neutral) -> leaf``
    is still TEST, not a RUNTIME leak.
    """
    scope = _chain_scope(cf)
    if scope is not None:
        return scope
    return _scope_from_path(str(cf.path)) or root_scope or UsageScope.RUNTIME


def _chain_scope(cf):
    """The nearest definite path-scope across this fragment's include chain.

    Walks includers from the IMMEDIATE one outward (closest call site wins), so an
    ancestor's test/example classification propagates through path-neutral
    intermediate fragments instead of only the direct includer being consulted.
    """
    chain = getattr(cf, "include_chain", None)
    if not chain:
        chain = [cf.included_by] if cf.included_by is not None else []
    for includer in reversed(chain):
        if includer is None:
            continue
        scope = _scope_from_path(str(includer))
        if scope is not None:
            return scope
    return None


def _program_call_site_scope(cf, root_scope):
    """Usage scope for a domain build-tool invocation (protoc, ...).

    Like :func:`_call_site_scope` but BUILD-defaulting: a domain tool is build
    tooling, so a path-neutral call site yields ``BUILD`` rather than the
    runtime-closure default. A more specific path classification (test/example/
    ...) anywhere on the include chain, the fragment, or the root's role still wins.
    """
    scope = _chain_scope(cf)
    if scope is not None:
        return scope
    return _scope_from_path(str(cf.path)) or root_scope or UsageScope.BUILD


def _merge_activation(
    site_conditions: list[ActivationCondition],
    own_conditions: list[ActivationCondition],
) -> list[ActivationCondition]:
    """Prepend the call-site gate(s) to a declaration's own conditions, de-duped
    by expression. The macro gate (TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD)
    therefore travels onto every observation in the included fragment."""
    merged: list[ActivationCondition] = []
    seen: set[str] = set()
    for c in list(site_conditions or []) + list(own_conditions or []):
        if c.expr not in seen:
            seen.add(c.expr)
            merged.append(ActivationCondition(expr=c.expr, evaluated=c.evaluated))
    return merged


#: Domain-tool name normalization: the protoc family resolves to the canonical
#: ``protoc`` tooling name (attaches to the protobuf component via the alias map).
_DOMAIN_TOOL_ALIASES = {
    "host_protoc": "protoc",
    "protoc": "protoc",
}


def _domain_tool_name(raw: str) -> str:
    return _DOMAIN_TOOL_ALIASES.get(raw.lower(), raw)


def _reachability_for(
    conditions: list[ActivationCondition],
) -> tuple[DeclarationReachability, str | None]:
    reason = _condition_is_dead(conditions)
    if reason:
        return DeclarationReachability.UNREACHABLE, reason
    return DeclarationReachability.REACHED, None


def _depends_target_name(raw: str) -> str:
    """Map an internal build-target name to its component name.

    The transitive ``protobuf -> abseil-cpp`` edge is declared as
    ``DEPENDS abseil_build``; reconcile's alias map collapses build-target
    spellings, but we normalize the well-known ones here so the edge endpoint is
    a real component name.
    """
    mapping = {
        "abseil_build": "abseil-cpp",
        "protobuf_src": "protobuf",
        "protobuf_shared_build": "protobuf",
        "protobuf_host_build": "protobuf",
        "protobuf_static_build": "protobuf",
        "protobuf_host_static_build": "protobuf",
        "external_eigen": "eigen",
        "third_party_json": "json",
    }
    return mapping.get(raw, raw)


def _local_target_names(files) -> set[str]:
    names: set[str] = set()
    for cf in files:
        for ad in cf.add_dependencies:
            names.add(ad.target)
    return names


def _program_source_kind(inv) -> SourceKind:
    if inv.command_context == "find_program":
        return SourceKind.CMAKE_FIND_PROGRAM
    return SourceKind.CMAKE_IMPORTED_EXECUTABLE


def _authority_label(source_revision: str | None) -> str | None:
    if source_revision is None:
        return None
    return "cann-cmake"


def _observation_component_name(obs: Observation) -> str | None:
    """The component an observation refers to (from ecosystem_data hints)."""
    data = obs.ecosystem_data or {}
    return data.get("component") or data.get("name") or data.get("package")


def _profile_tooling_names(profile: Profile) -> set[str]:
    """The profile's domain-tool allowlist (names routed to 'component')."""
    vocab = {}
    try:
        vocab = profile.condition_vocabulary() or {}
    except Exception:  # noqa: BLE001 -- a profile hook must never abort collection
        vocab = {}
    tooling = vocab.get("build_tooling") if isinstance(vocab, dict) else None
    names = set(tooling) if tooling else set()
    # Domain build tools that are always SBOM components, not env tools.
    names |= {"protoc", "host_protoc", "bisheng-compiler", "op_build"}
    return names


def _primary_subject(subjects: list[Subject]) -> Subject | None:
    for s in subjects:
        if s.role == SubjectRole.PRIMARY:
            return s
    return subjects[0] if subjects else None


def _subject_entry_cmake(subject: Subject, repo_root: Path) -> Path | None:
    """Return the CMakeLists entry point that builds ``subject``.

    ``source_path`` is relative to ``repo_root``; an empty string means the repo
    root itself (the primary subject lives at the top-level CMakeLists).
    """
    src = subject.source_path
    if src is None:
        return None
    p = Path(src)
    if not p.is_absolute():
        p = repo_root / p
    if p.is_dir():
        for c in (p / "CMakeLists.txt", p / "CMakeLists_geir.txt"):
            if c.exists():
                return c
        return None
    if p.exists():
        return p
    return None


def _record_unresolved_dep_macros(
    files, custom_macros, effective_root: Path | None, out: set
) -> None:
    """Collect ``(macro_name, dep_name)`` for every custom-dep-macro call whose
    resolved fragment does not exist on disk.

    A profile registers ``add_cann_third_party`` (etc.) with a resolver to
    ``third_party/<name>.cmake`` under ``effective_root``. When that tree is absent
    (no ``--cmake-root`` and no fetched cann-cmake checkout), the resolver yields a
    non-existent / empty path, ``parse_recursive`` silently skips it, and the dep is
    dropped -- this surfaces it so the caller can warn instead of undercounting."""
    if not custom_macros:
        return
    for cf in files:
        for macro_name, margs in getattr(cf, "macro_calls", ()):
            resolver = custom_macros.get(macro_name)
            if resolver is None:
                continue
            try:
                resolved = resolver(margs, effective_root) or []
            except Exception:  # noqa: BLE001 -- a profile resolver must not crash collection
                resolved = []
            if any(p is not None and Path(p).exists() for p in resolved):
                continue
            dep = margs[0].strip().strip('"') if margs else macro_name
            if dep:
                out.add((macro_name, dep))


def _parse_graph(entry: Path, effective_root: Path | None, custom_macros):
    """Parse the include graph rooted at ``entry``.

    ``parse_recursive`` is used even when ``effective_root`` is ``None``: it still
    follows plain ``include()`` paths and captures custom-dep ``macro_calls`` (so a
    missing cann-cmake tree surfaces as ``unresolved_third_party`` rather than
    silently undercounting), while declining to follow the macros it cannot resolve.
    """
    return parse.parse_recursive(entry, effective_root, custom_macros=custom_macros)


#: cann-cmake files that carry build-tool find_program() calls the macro/closure
#: walk may not reach via plain include(): prepare.cmake (ccache) is always
#: parsed; gtest_shared.cmake only when gtest is already in the include closure.
_PREPARE_CMAKE_REL = ("function/prepare.cmake",)
_GTEST_SHARED_REL = "third_party/gtest_shared.cmake"


def _augment_with_tooling_files(files, effective_root: Path | None):
    """Append tooling fragments (prepare.cmake, gtest_shared.cmake) so their
    find_program() invocations (e.g. ``find_program(CCACHE_PROGRAM ccache)``)
    are captured (defect h)."""
    if effective_root is None:
        return files
    seen = {f.path.resolve() for f in files if f.path}
    extra: list = []

    def _add(rel: str) -> None:
        p = (effective_root / rel)
        try:
            key = p.resolve()
        except OSError:
            key = p
        if key in seen or not p.exists():
            return
        seen.add(key)
        extra.append(parse.parse_file(p))

    for rel in _PREPARE_CMAKE_REL:
        _add(rel)

    # gtest_shared.cmake only when gtest is part of the closure.
    in_closure = any(
        (f.path and f.path.name in ("gtest.cmake", "ut.cmake")) for f in files
    )
    if in_closure:
        _add(_GTEST_SHARED_REL)

    return list(files) + extra
