"""Python collector — pip/packaging-faithful Python dependency collection.

Implements the design's ``PyCollector`` (SBOM_DESIGN.md §Collectors → PyCollector)
against the frozen contract in INTERFACE.md::

    def collect(config, profile, subjects) -> CollectResult

What it does, faithfully to pip/`packaging` semantics (not naive line skipping):

* ``requirements.txt``: follow ``-r``/``--requirement`` recursively, apply
  ``-c``/``--constraint`` files, record ``-e``/direct-URL/VCS entries as direct
  dependencies with source metadata, parse extras + PEP 508 markers + ``--hash``;
  index options (``--extra-index-url``/``-i``/``--index-url``) are kept as
  file-level source metadata, never as packages.
* ``setup.py``: AST-extract ``name``/``version`` + ``install_requires`` (runtime),
  plus build-scope facts (setup-time imports of ``setuptools``/``wheel``, external
  build-tool invocations like ``cmake``/``ninja``, and statically-reachable
  ``cmdclass`` build-method import scanning, e.g. ``import torch``/``torch_npu``
  inside ``CMakeBuildCommand.run``).
* ``pyproject.toml``: ``[project].dependencies`` (runtime) + ``[build-system].requires``
  (build scope, ``source_kind=python_build``).

Build-scope observations MERGE with runtime observations for the same package:
one ``Component`` with ``scopes={runtime, build}`` rather than a duplicate.

File-level usage scope is assigned by profile/config policy (with sane defaults),
never hard-coded into the parser.

In static mode every entry is direct-declared and
``completeness={"python_transitives": "unresolved"}``.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet

from ..models import (
    Component,
    DependencyEdge,
    DeclarationReachability,
    Observation,
    Ref,
    RefKind,
    RelationType,
    SourceKind,
    Subject,
    SubjectRole,
    UsageScope,
    Warning,
)
from . import CollectResult

if TYPE_CHECKING:  # pragma: no cover - config.py is a sibling module, may not exist yet
    from ..config import Config


# Generic host tools that, when invoked from a setup.py build method, are recorded
# as build-tool dependency components (python_build scope) per the design's
# build-tool boundary (cmake/ninja via python_build are components).
_BUILD_TOOL_INVOCATIONS = {"cmake", "ninja", "make", "meson"}

# Setup-time imports that are themselves build backends/helpers (build scope).
_SETUP_BUILD_IMPORTS = {"setuptools", "wheel", "skbuild", "Cython", "cython", "pybind11"}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def collect(
    config: "Config", profile, subjects: list[Subject]
) -> CollectResult:
    """Collect Python dependencies for ``config.repo_root`` (see module docstring).

    Returns a :class:`CollectResult` with components (carrying their per-site
    observations), subject→component edges, and warnings. Build-scope
    observations merge with runtime ones onto a single component.
    """
    repo_root = Path(config.repo_root)
    result = CollectResult()

    # A registry keyed by canonical (normalized) package name so runtime and
    # build observations for the same dist collapse onto ONE component.
    registry: dict[str, Component] = {}
    # Track which (root_artifact_id, component_name, relation, scope) edges exist
    # so we don't emit duplicate edges.
    edge_keys: set[tuple] = set()

    primary_id = _primary_subject_id(subjects)

    # ---- requirements files ------------------------------------------------
    for req_file in _discover_requirements_files(repo_root):
        owner = _owning_subject_id(req_file, subjects, primary_id, repo_root)
        scope = _file_usage_scope(req_file, config, profile)
        _collect_requirements_file(
            req_file,
            repo_root,
            owner,
            scope,
            registry,
            result,
            edge_keys,
            seen_files=set(),
            is_constraint=False,
        )

    # ---- setup.py / pyproject.toml ----------------------------------------
    # A wheel's install_requires inherit the OWNING subject's scope: an example/
    # test wheel's runtime deps are example/test-scoped (trimmed from the release
    # view), not RUNTIME — mirroring cpp.py's _role_to_scope and the requirements
    # path's _file_usage_scope. build-system requires stay BUILD regardless.
    for setup_file in _discover_files(repo_root, "setup.py"):
        owner = _owning_subject_id(setup_file, subjects, primary_id, repo_root)
        install_scope = _path_install_scope(setup_file.parent, repo_root, profile)
        _collect_setup_py(setup_file, owner, install_scope, registry, result, edge_keys)

    for pyproject in _discover_files(repo_root, "pyproject.toml"):
        owner = _owning_subject_id(pyproject, subjects, primary_id, repo_root)
        install_scope = _path_install_scope(pyproject.parent, repo_root, profile)
        _collect_pyproject(pyproject, owner, install_scope, registry, result, edge_keys)

    # Components were collected into the registry; surface them on the result.
    result.components.extend(registry.values())
    return result


# ---------------------------------------------------------------------------
# requirements.txt parsing (pip-faithful)
# ---------------------------------------------------------------------------


def _collect_requirements_file(
    path: Path,
    repo_root: Path,
    owner: str | None,
    scope: UsageScope,
    registry: dict[str, Component],
    result: CollectResult,
    edge_keys: set[tuple],
    *,
    seen_files: set[Path],
    is_constraint: bool,
) -> dict[str, str]:
    """Parse one requirements/constraints file, following ``-r``/``-c`` recursively.

    Returns the constraint map ({canonical_name: specifier}) accumulated from any
    ``-c`` files referenced (so the caller can apply them). When ``is_constraint``
    is true the file's own pinned entries are returned as constraints rather than
    emitted as dependencies.
    """
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if resolved in seen_files:
        return {}  # break include cycles
    seen_files.add(resolved)

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        result.warnings.append(
            Warning(code="python_requirements_unreadable", subject=str(path), detail=str(exc))
        )
        return {}

    constraints: dict[str, str] = {}
    file_index_options: list[str] = []
    pending: list[tuple[str, list[str]]] = []  # (logical line, hash options)

    for logical, hashes in _logical_lines(text):
        stripped = logical.strip()
        if not stripped:
            continue

        tokens = stripped.split()
        opt = tokens[0]

        if opt in ("-r", "--requirement", "-c", "--constraint"):
            target = tokens[1] if len(tokens) > 1 else None
            if not target:
                continue
            child = (path.parent / target)
            is_c = opt in ("-c", "--constraint")
            child_constraints = _collect_requirements_file(
                child,
                repo_root,
                owner,
                scope,
                registry,
                result,
                edge_keys,
                seen_files=seen_files,
                is_constraint=is_c or is_constraint,
            )
            # Constraints discovered via -c propagate up so siblings can apply them.
            constraints.update(child_constraints)
            continue

        if opt in ("-i", "--index-url", "--extra-index-url"):
            if len(tokens) > 1:
                file_index_options.append(stripped)
            continue

        if opt in ("-f", "--find-links", "--no-index", "--pre", "--no-binary",
                   "--only-binary", "--require-hashes", "--trusted-host"):
            # Other pip controls: file-level metadata, not packages.
            if opt in ("--no-index", "--require-hashes", "--pre"):
                file_index_options.append(stripped)
            elif len(tokens) > 1:
                file_index_options.append(stripped)
            continue

        if opt in ("-e", "--editable"):
            url = tokens[1] if len(tokens) > 1 else ""
            _record_direct_url(
                url, scope, owner, str(path), registry, result, edge_keys,
                editable=True, hashes=hashes,
            )
            continue

        # A bare URL / VCS direct reference (e.g. "git+https://…", "https://…/x.whl",
        # or "pkg @ https://…").
        if _looks_like_direct_url(stripped):
            _record_direct_url(
                stripped, scope, owner, str(path), registry, result, edge_keys,
                editable=False, hashes=hashes,
            )
            continue

        # Otherwise a PEP 508 requirement specifier.
        pending.append((stripped, hashes))

    # If this is a constraint file, its requirements become constraints, not deps.
    if is_constraint:
        for spec, _hashes in pending:
            try:
                req = Requirement(spec)
            except InvalidRequirement:
                continue
            constraints[_canonical(req.name)] = str(req.specifier)
        return constraints

    # Emit normal requirements, applying any accumulated constraints.
    for spec, hashes in pending:
        try:
            req = Requirement(spec)
        except InvalidRequirement as exc:
            result.warnings.append(
                Warning(code="python_requirement_invalid", subject=spec, detail=str(exc))
            )
            continue
        applied_constraint = constraints.get(_canonical(req.name))
        _record_requirement(
            req, scope, owner, str(path), registry, result, edge_keys,
            hashes=hashes,
            index_options=file_index_options,
            applied_constraint=applied_constraint,
        )

    return constraints


def _record_requirement(
    req: Requirement,
    scope: UsageScope,
    owner: str | None,
    source_file: str,
    registry: dict[str, Component],
    result: CollectResult,
    edge_keys: set[tuple],
    *,
    hashes: list[str],
    index_options: list[str],
    applied_constraint: str | None,
) -> None:
    eco: dict = {}
    if req.extras:
        eco["extras"] = sorted(req.extras)
    if req.marker is not None:
        eco["marker"] = str(req.marker)
    if hashes:
        eco["hashes"] = list(hashes)
    if index_options:
        eco["index_options"] = list(index_options)
    if applied_constraint:
        eco["applied_constraint"] = applied_constraint

    spec = str(req.specifier) if req.specifier else None
    obs = Observation(
        source_kind=SourceKind.PYTHON_REQUIREMENT,
        source_file=source_file,
        root_artifact_id=owner,
        usage_scope=scope,
        version_constraint=spec,
        declaration_reachability=DeclarationReachability.REACHED,
        ecosystem_data=eco,
    )
    _attach(
        req.name, scope, obs, registry,
        source_constraint=spec, concrete=concrete_version(req.specifier),
    )
    _add_edge(owner, req.name, scope, source_file, registry, result, edge_keys)


def _record_direct_url(
    url: str,
    scope: UsageScope,
    owner: str | None,
    source_file: str,
    registry: dict[str, Component],
    result: CollectResult,
    edge_keys: set[tuple],
    *,
    editable: bool,
    hashes: list[str],
) -> None:
    name, vcs, location = _parse_direct_url(url)
    loc = (location or url).strip()
    # A scheme-less LOCAL-PATH install -- '-e .', '-e ./pkg', '-e /abs', or
    # 'name @ ./local' -- is the repo's OWN package (or a vendored sibling), not an
    # external indexable dependency. Emit nothing: registering it produced a
    # phantom component (e.g. '.' -> canonical '-' with an invalid pkg:pypi/- purl
    # and an owner -> '-' edge) that even survived the release view.
    if not vcs and "://" not in loc and "#egg=" not in loc:
        result.warnings.append(
            Warning(
                code="python_local_path_install_skipped",
                subject=url,
                detail="local-path install (editable self/sibling); not an external dependency",
            )
        )
        return
    if not name:
        result.warnings.append(
            Warning(code="python_direct_url_unnamed", subject=url,
                    detail="could not derive a project name from direct reference")
        )
        # Still record under a slug so it is not silently dropped.
        name = _slug_from_url(location or url)

    eco: dict = {"direct_reference": location or url}
    if editable:
        eco["editable"] = True
    if vcs:
        eco["vcs"] = vcs
    if hashes:
        eco["hashes"] = list(hashes)

    obs = Observation(
        source_kind=SourceKind.PYTHON_REQUIREMENT,
        source_file=source_file,
        root_artifact_id=owner,
        usage_scope=scope,
        resolved_url_or_path=location or url,
        canonical_url=location if vcs else None,
        declaration_reachability=DeclarationReachability.REACHED,
        ecosystem_data=eco,
    )
    _attach(name, scope, obs, registry, source_constraint=None)
    _add_edge(owner, name, scope, source_file, registry, result, edge_keys)


# ---------------------------------------------------------------------------
# setup.py parsing (AST)
# ---------------------------------------------------------------------------


def _role_to_scope(role: SubjectRole) -> UsageScope | None:
    """Usage scope for a wheel's runtime install_requires, by owning-subject role.

    ``None`` for a distributable role (PRIMARY / SIBLING_ARTIFACT / cmake_project /
    unclassified) -> the caller defaults to RUNTIME. Mirrors cpp.py._role_to_scope.
    """
    return {
        SubjectRole.EXAMPLE: UsageScope.EXAMPLE,
        SubjectRole.MANUAL_EXAMPLE: UsageScope.MANUAL_EXAMPLE,
        SubjectRole.ST_TEST: UsageScope.ST_TEST,
        SubjectRole.EXPERIMENTAL: UsageScope.EXPERIMENTAL,
        SubjectRole.NON_DISTRIBUTABLE_TEST: UsageScope.TEST,
    }.get(role)


def _path_install_scope(setup_dir: Path, repo_root: Path, profile) -> UsageScope:
    """The scope a wheel's install_requires take, classified by the setup file's
    PATH (role), not the resolved owner id.

    The owning subject can be wrong here: in the release view the subject set is
    already role-filtered, so an example wheel's root (``ascend_ops``) is gone and
    the file would mis-attribute to the primary -> RUNTIME -> leak. Classifying the
    directory directly (profile path semantics + the generic example-segment
    fallback, exactly as the subject collector does) is independent of that filter.
    """
    from ..models import Identity, SubjectKind
    from .subject import _generic_example_root

    try:
        rel = str(setup_dir.resolve().relative_to(repo_root.resolve()))
    except (ValueError, OSError):
        rel = ""
    rel = "" if rel == "." else rel
    role = SubjectRole.UNCLASSIFIED
    classify = getattr(profile, "classify_root", None)
    if callable(classify):
        probe = Subject(
            id="", identity=Identity(SubjectKind.CMAKE_PROJECT, "", None),
            role=SubjectRole.UNCLASSIFIED, source_path=rel,
        )
        role = classify(setup_dir, probe, {"repo_root": str(repo_root)})
    if role in (SubjectRole.CMAKE_PROJECT, SubjectRole.UNCLASSIFIED) and _generic_example_root(rel):
        role = SubjectRole.EXAMPLE
    return _role_to_scope(role) or UsageScope.RUNTIME


def _collect_setup_py(
    path: Path,
    owner: str | None,
    install_scope: UsageScope,
    registry: dict[str, Component],
    result: CollectResult,
    edge_keys: set[tuple],
) -> None:
    try:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
    except (OSError, SyntaxError) as exc:
        result.warnings.append(
            Warning(code="python_setup_unparsable", subject=str(path), detail=str(exc))
        )
        return

    constants = _collect_module_constants(tree)
    install_requires = _extract_install_requires(tree, constants)

    for spec in install_requires:
        try:
            req = Requirement(spec)
        except InvalidRequirement as exc:
            result.warnings.append(
                Warning(code="python_requirement_invalid", subject=spec, detail=str(exc))
            )
            continue
        eco: dict = {}
        if req.extras:
            eco["extras"] = sorted(req.extras)
        if req.marker is not None:
            eco["marker"] = str(req.marker)
        spec_str = str(req.specifier) if req.specifier else None
        obs = Observation(
            source_kind=SourceKind.PYTHON_SETUP,
            source_file=str(path),
            root_artifact_id=owner,
            usage_scope=install_scope,
            version_constraint=spec_str,
            declaration_reachability=DeclarationReachability.REACHED,
            ecosystem_data=eco,
        )
        _attach(
            req.name, install_scope, obs, registry,
            source_constraint=spec_str, concrete=concrete_version(req.specifier),
        )
        _add_edge(owner, req.name, install_scope, str(path), registry, result, edge_keys)

    # Build-scope: setup-time imports + external build-tool invocations +
    # cmdclass build-method import scanning.
    build_names = _scan_setup_build_deps(tree)
    for name in sorted(build_names):
        obs = Observation(
            source_kind=SourceKind.PYTHON_BUILD,
            source_file=str(path),
            root_artifact_id=owner,
            usage_scope=UsageScope.BUILD,
            declaration_reachability=DeclarationReachability.REACHED,
        )
        _attach(name, UsageScope.BUILD, obs, registry, source_constraint=None)
        _add_edge(
            owner, name, UsageScope.BUILD, str(path), registry, result, edge_keys,
            relation=RelationType.BUILD_DEPENDENCY_OF,
        )


def _extract_install_requires(tree: ast.Module, constants: dict[str, object]) -> list[str]:
    """Find the ``install_requires=[...]`` keyword of the ``setup(...)`` call."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_setup_call(node)):
            continue
        for kw in node.keywords:
            if kw.arg == "install_requires":
                return _literal_str_list(kw.value, constants)
    return []


def _scan_setup_build_deps(tree: ast.Module) -> set[str]:
    """Build-scope dependency names from a legacy setup.py.

    Includes:
      • module-level setup-time imports of build backends (setuptools/wheel/…);
      • external build-tool invocations (cmake/ninja) in cmdclass build methods;
      • imports inside statically-reachable cmdclass build-command ``run`` methods
        (e.g. ``import torch``/``torch_npu``).
    """
    names: set[str] = set()

    # Module-level imports of recognized build backends/helpers.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)) and _at_module_level(tree, node):
            for mod in _imported_top_modules(node):
                if mod in _SETUP_BUILD_IMPORTS:
                    names.add(_canonical(mod))

    # cmdclass build-method scanning: any Command-like class whose `run` method
    # imports packages or invokes external build tools.
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for method in node.body:
                if isinstance(method, ast.FunctionDef) and method.name == "run":
                    names |= _scan_build_method(method)

    return names


def _scan_build_method(method: ast.FunctionDef) -> set[str]:
    """Imports and external build-tool invocations inside a cmdclass ``run``."""
    found: set[str] = set()
    for sub in ast.walk(method):
        # imports inside the method body (import torch / import torch_npu)
        if isinstance(sub, (ast.Import, ast.ImportFrom)):
            for mod in _imported_top_modules(sub):
                found.add(_canonical(mod))
        # external build-tool invocation: subprocess.* (["cmake", ...]) or a list
        # literal beginning with a known build tool.
        if isinstance(sub, ast.List) and sub.elts:
            first = sub.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                tool = first.value.strip()
                if tool in _BUILD_TOOL_INVOCATIONS:
                    found.add(_canonical(tool))
        if isinstance(sub, ast.Call):
            for arg in sub.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.strip() in _BUILD_TOOL_INVOCATIONS:
                        found.add(_canonical(arg.value.strip()))
    return found


# ---------------------------------------------------------------------------
# pyproject.toml parsing
# ---------------------------------------------------------------------------


def _collect_pyproject(
    path: Path,
    owner: str | None,
    install_scope: UsageScope,
    registry: dict[str, Component],
    result: CollectResult,
    edge_keys: set[tuple],
) -> None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        result.warnings.append(
            Warning(code="python_pyproject_unparsable", subject=str(path), detail=str(exc))
        )
        return

    project = data.get("project") or {}
    for spec in project.get("dependencies", []) or []:
        _emit_pyproject_dep(
            spec, install_scope, SourceKind.PYTHON_SETUP, owner, path,
            registry, result, edge_keys, relation=RelationType.DEPENDS_ON,
        )

    build_system = data.get("build-system") or data.get("build_system") or {}
    for spec in build_system.get("requires", []) or []:
        _emit_pyproject_dep(
            spec, UsageScope.BUILD, SourceKind.PYTHON_BUILD, owner, path,
            registry, result, edge_keys, relation=RelationType.BUILD_DEPENDENCY_OF,
        )


def _emit_pyproject_dep(
    spec: str,
    scope: UsageScope,
    source_kind: SourceKind,
    owner: str | None,
    path: Path,
    registry: dict[str, Component],
    result: CollectResult,
    edge_keys: set[tuple],
    *,
    relation: RelationType,
) -> None:
    try:
        req = Requirement(spec)
    except InvalidRequirement as exc:
        result.warnings.append(
            Warning(code="python_requirement_invalid", subject=spec, detail=str(exc))
        )
        return
    eco: dict = {}
    if req.extras:
        eco["extras"] = sorted(req.extras)
    if req.marker is not None:
        eco["marker"] = str(req.marker)
    spec_str = str(req.specifier) if req.specifier else None
    obs = Observation(
        source_kind=source_kind,
        source_file=str(path),
        root_artifact_id=owner,
        usage_scope=scope,
        version_constraint=spec_str,
        declaration_reachability=DeclarationReachability.REACHED,
        ecosystem_data=eco,
    )
    _attach(
        req.name, scope, obs, registry,
        source_constraint=spec_str, concrete=concrete_version(req.specifier),
    )
    _add_edge(owner, req.name, scope, str(path), registry, result, edge_keys, relation=relation)


# ---------------------------------------------------------------------------
# Component / edge bookkeeping (runtime∪build merge on one component)
# ---------------------------------------------------------------------------


def _attach(
    raw_name: str,
    scope: UsageScope,
    obs: Observation,
    registry: dict[str, Component],
    *,
    source_constraint: str | None,
    concrete: str | None = None,
) -> Component:
    """Attach an observation to the canonical component, creating it if needed.

    Scopes union; build and runtime observations for the same dist collapse onto
    ONE component (so e.g. ``torch`` carries ``{runtime, build}``). When
    ``concrete`` is an EXACT pin (per :func:`concrete_version`) it sets the
    component's ``source_version``/``effective_version`` so the emitters carry a
    real ``component.version`` and an ``@version`` purl; a range/bare dep leaves
    the version axis unset (reconcile then records the ``unpinned`` marker).
    """
    canon = _canonical(raw_name)
    comp = registry.get(canon)
    if comp is None:
        comp = Component(
            name=canon,
            languages=["Python"],
            completeness={"python_transitives": "unresolved"},
        )
        registry[canon] = comp
    if raw_name != canon and raw_name not in comp.aliases:
        comp.aliases.append(raw_name)
    if scope not in comp.scopes:
        comp.scopes.append(scope)
    if concrete is not None and comp.source_version is None:
        comp.source_version = concrete
        comp.effective_version = concrete
    comp.observations.append(obs)
    return comp


def _add_edge(
    owner: str | None,
    raw_name: str,
    scope: UsageScope,
    source_file: str,
    registry: dict[str, Component],
    result: CollectResult,
    edge_keys: set[tuple],
    *,
    relation: RelationType = RelationType.DEPENDS_ON,
) -> None:
    canon = _canonical(raw_name)
    key = (owner, canon, relation.value, scope.value)
    if key in edge_keys:
        return
    edge_keys.add(key)
    result.edges.append(
        DependencyEdge(
            root_artifact_id=owner,
            from_ref=Ref(kind=RefKind.SUBJECT, id=owner) if owner else Ref(kind=RefKind.SUBJECT, id=""),
            to_ref=Ref(kind=RefKind.COMPONENT, id=canon),
            relation_type=relation,
            usage_scope=scope,
            source_file=source_file,
        )
    )


# ---------------------------------------------------------------------------
# Requirement-file line handling
# ---------------------------------------------------------------------------


def _logical_lines(text: str) -> list[tuple[str, list[str]]]:
    """Yield (logical line, hash-options) honoring pip line continuations.

    Strips full-line and trailing ``#`` comments, joins backslash continuations,
    and splits out ``--hash=...`` tokens onto the requirement they belong to.
    """
    out: list[tuple[str, list[str]]] = []
    buf: list[str] = []

    raw_lines = text.splitlines()
    for raw in raw_lines:
        line = raw
        # Strip comments (a leading '#', or ' #' inline — but not inside URLs with
        # fragments; pip treats ' #' as a comment start).
        if line.lstrip().startswith("#"):
            line = ""
        else:
            hash_idx = line.find(" #")
            if hash_idx != -1:
                line = line[:hash_idx]
        if line.rstrip().endswith("\\"):
            buf.append(line.rstrip()[:-1])
            continue
        buf.append(line)
        logical = " ".join(part.strip() for part in buf).strip()
        buf = []
        if not logical:
            continue
        req_part, hashes = _split_hashes(logical)
        out.append((req_part, hashes))

    if buf:
        logical = " ".join(part.strip() for part in buf).strip()
        if logical:
            req_part, hashes = _split_hashes(logical)
            out.append((req_part, hashes))
    return out


def _split_hashes(line: str) -> tuple[str, list[str]]:
    """Split ``--hash=algo:digest`` tokens off a requirement line."""
    tokens = line.split()
    kept: list[str] = []
    hashes: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--hash":
            if i + 1 < len(tokens):
                hashes.append(tokens[i + 1])
                i += 2
                continue
            i += 1
            continue
        if tok.startswith("--hash="):
            hashes.append(tok[len("--hash="):])
            i += 1
            continue
        kept.append(tok)
        i += 1
    return " ".join(kept), hashes


def _looks_like_direct_url(line: str) -> bool:
    if " @ " in line:
        return True
    head = line.split()[0]
    for prefix in ("git+", "hg+", "svn+", "bzr+", "http://", "https://", "file://"):
        if head.startswith(prefix):
            return True
    return False


def _parse_direct_url(ref: str) -> tuple[str | None, str | None, str]:
    """Parse a direct URL / VCS / ``name @ url`` reference.

    Returns ``(project_name|None, vcs_scheme|None, location)``.
    """
    ref = ref.strip()
    name: str | None = None
    location = ref

    if " @ " in ref:
        name_part, _, url_part = ref.partition(" @ ")
        try:
            name = Requirement(name_part.strip() + " @ " + url_part.strip()).name
        except InvalidRequirement:
            name = name_part.strip().split("[")[0] or None
        location = url_part.strip()

    vcs = None
    for scheme in ("git+", "hg+", "svn+", "bzr+"):
        if location.startswith(scheme):
            vcs = scheme.rstrip("+")
            break

    if name is None:
        # Try egg fragment: ...#egg=name
        if "#egg=" in location:
            egg = location.split("#egg=", 1)[1]
            name = egg.split("&")[0].split("[")[0] or None
        else:
            name = _slug_from_url(location)

    return name, vcs, location


def _slug_from_url(url: str) -> str:
    tail = url.rstrip("/").split("/")[-1]
    for ext in (".git", ".tar.gz", ".tgz", ".zip", ".whl", ".tar.bz2"):
        if tail.endswith(ext):
            tail = tail[: -len(ext)]
            break
    tail = tail.split("@")[0].split("#")[0]
    return tail or url


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _is_setup_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "setup"
    if isinstance(func, ast.Attribute):
        return func.attr == "setup"
    return False


def _collect_module_constants(tree: ast.Module) -> dict[str, object]:
    """Collect simple module-level ``NAME = <literal>`` assignments."""
    consts: dict[str, object] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                try:
                    consts[target.id] = ast.literal_eval(node.value)
                except (ValueError, TypeError, SyntaxError):
                    pass
    return consts


def _literal_str_list(value: ast.AST, constants: dict[str, object]) -> list[str]:
    """Evaluate an AST node expected to be a list of strings.

    Handles list/tuple literals and a bare ``Name`` referring to a module
    constant (a common setup.py pattern).
    """
    if isinstance(value, ast.Name) and value.id in constants:
        resolved = constants[value.id]
        if isinstance(resolved, (list, tuple)):
            return [str(x) for x in resolved if isinstance(x, str)]
        return []
    if isinstance(value, (ast.List, ast.Tuple)):
        out: list[str] = []
        for elt in value.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                out.append(elt.value)
            elif isinstance(elt, ast.Name) and elt.id in constants:
                resolved = constants[elt.id]
                if isinstance(resolved, str):
                    out.append(resolved)
        return out
    try:
        resolved = ast.literal_eval(value)
        if isinstance(resolved, (list, tuple)):
            return [str(x) for x in resolved if isinstance(x, str)]
    except (ValueError, TypeError, SyntaxError):
        pass
    return []


def _imported_top_modules(node: ast.AST) -> list[str]:
    """Top-level module names from an import statement."""
    out: list[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            out.append(alias.name.split(".")[0])
    elif isinstance(node, ast.ImportFrom):
        if node.module and node.level == 0:
            out.append(node.module.split(".")[0])
    return out


def _at_module_level(tree: ast.Module, target: ast.AST) -> bool:
    return target in tree.body


# ---------------------------------------------------------------------------
# Subject attribution & file discovery
# ---------------------------------------------------------------------------


def _primary_subject_id(subjects: list[Subject]) -> str | None:
    for s in subjects:
        if getattr(s, "role", None) is not None and s.role.value == "primary":
            return s.id
    return subjects[0].id if subjects else None


def _owning_subject_id(
    path: Path, subjects: list[Subject], primary_id: str | None, repo_root: Path
) -> str | None:
    """Attribute a python file to the subject whose ``source_path`` most deeply
    contains it. Falls back to the primary subject.

    ``source_path`` is relative to ``repo_root`` (an empty string means the repo
    root itself — the primary subject); it is resolved against ``repo_root`` so a
    deeper sibling (``examples/...``/``scripts/...``) wins over the primary by
    longest-prefix / most-specific match. Mirrors cpp.py's ``_subject_entry_cmake``.
    """
    try:
        file_dir = path.resolve().parent
    except OSError:
        file_dir = path.parent

    best_id: str | None = primary_id
    best_len = -1
    for s in subjects:
        sp = getattr(s, "source_path", None)
        if sp is None:
            continue
        p = Path(sp)
        if not p.is_absolute():
            p = repo_root / p
        try:
            base = p.resolve()
        except OSError:
            base = p
        try:
            file_dir.relative_to(base)
        except ValueError:
            continue
        depth = len(base.parts)
        if depth > best_len:
            best_len = depth
            best_id = s.id
    return best_id


def _discover_requirements_files(repo_root: Path) -> list[Path]:
    files = [
        p
        for p in repo_root.rglob("*.txt")
        if p.is_file() and _is_requirements_path(p)
    ]
    return sorted(files)


#: Requirements-file basenames recognized inside a ``requirements/`` directory
#: (e.g. ``requirements/build.txt``).
_REQUIREMENTS_DIR_STEMS = {"build", "runtime", "test"}


def _is_requirements_path(path: Path) -> bool:
    """True when ``path`` is a recognised requirements file.

    Matches ``requirements*.txt`` and ``*-requirements.txt`` anywhere, plus
    ``<build|runtime|test>.txt`` directly inside a ``requirements/`` directory
    (so the split-layout spellings the scope mapping understands are actually
    discovered)."""
    name = path.name.lower()
    if not name.endswith(".txt"):
        return False
    stem = name[:-4]
    if stem.startswith("requirements") or stem.endswith("-requirements"):
        return True
    if path.parent.name.lower() == "requirements" and stem in _REQUIREMENTS_DIR_STEMS:
        return True
    return False


def _discover_files(repo_root: Path, filename: str) -> list[Path]:
    return sorted(p for p in repo_root.rglob(filename) if p.is_file())


# ---------------------------------------------------------------------------
# File-level scope policy (default; overridable by profile/config)
# ---------------------------------------------------------------------------


def _file_usage_scope(path: Path, config: "Config", profile) -> UsageScope:
    """Resolve a requirements file's usage scope from profile/config policy.

    File-level scope is NOT hard-coded: a profile hook or config mapping may
    override it (those always win). Otherwise the FILENAME is consulted first
    (``requirements-build.txt`` → build, ``requirements-test.txt`` → test,
    ``requirements-runtime.txt``/``requirements.txt`` → runtime, with the
    ``build-requirements.txt`` / ``requirements/build.txt`` variants), then the
    containing-directory heuristic (``tests/*`` → test, ``examples/*`` → example),
    and finally runtime.
    """
    # Profile hook (optional, duck-typed so the generic core has no dependency).
    hook = getattr(profile, "python_file_scope", None)
    if callable(hook):
        scope = hook(path)
        if isinstance(scope, UsageScope):
            return scope

    # Config-provided mapping (duck-typed; e.g. profile_values may carry it).
    mapping = getattr(config, "python_file_scopes", None)
    if isinstance(mapping, dict):
        scope = mapping.get(str(path)) or mapping.get(path.name)
        if isinstance(scope, UsageScope):
            return scope
        if isinstance(scope, str):
            try:
                return UsageScope(scope)
            except ValueError:
                pass

    # Explicit build/test FILENAME tags are authoritative (they name the intent
    # directly), even over the containing directory. This catches the split
    # requirements layout (requirements-build.txt, build-requirements.txt,
    # requirements/build.txt, requirements-test.txt, ...) so e.g. pyasc's
    # requirements-build.txt deps are correctly BUILD (dropped under release).
    tagged = _requirements_tag_scope(path)
    if tagged is not None:
        return tagged

    # Otherwise the containing-directory heuristic, then runtime. A plain
    # requirements.txt / requirements-runtime.txt under tests/ or examples/ keeps
    # the directory scope; at the repo root it is runtime.
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    if "test" in name or "tests" in parts or "test" in parts:
        return UsageScope.TEST
    if "examples" in parts or "example" in parts:
        return UsageScope.EXAMPLE
    return UsageScope.RUNTIME


def _requirements_tag_scope(path: Path) -> UsageScope | None:
    """Map an EXPLICITLY-tagged requirements filename to a scope, else ``None``.

    Recognizes the common split-requirements spellings (case-insensitive):

    * ``requirements-build.txt`` / ``build-requirements.txt`` /
      ``requirements/build.txt`` → BUILD
    * ``requirements-test.txt`` / ``test-requirements.txt`` /
      ``requirements/test.txt`` / ``tests/requirements*.txt`` → TEST
    * ``requirements-runtime.txt`` / ``requirements/runtime.txt`` → RUNTIME

    A bare ``requirements.txt`` is intentionally NOT matched here: it carries no
    explicit tag, so it defers to the containing-directory heuristic (a plain
    ``examples/foo/requirements.txt`` stays EXAMPLE). Returns ``None`` when no
    explicit tag is present.
    """
    name = path.name.lower()
    parent = path.parent.name.lower()
    stem = name[:-4] if name.endswith(".txt") else name  # drop ".txt"

    def _tagged(tag: str) -> bool:
        # requirements-<tag> / <tag>-requirements / requirements/<tag>
        return (
            stem == f"requirements-{tag}"
            or stem == f"{tag}-requirements"
            or (parent == "requirements" and stem == tag)
        )

    if _tagged("build"):
        return UsageScope.BUILD
    if _tagged("test") or (parent == "tests" and stem.startswith("requirements")):
        return UsageScope.TEST
    if _tagged("runtime"):
        return UsageScope.RUNTIME
    return None


# ---------------------------------------------------------------------------
# Name normalization (PEP 503)
# ---------------------------------------------------------------------------


def _canonical(name: str) -> str:
    import re

    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# Concrete-version detection (PEP 440 / packaging-faithful)
# ---------------------------------------------------------------------------


def concrete_version(specifier: SpecifierSet) -> str | None:
    """Return the EXACT pin a specifier set names, or ``None`` for a range/bare.

    Per the static-mode policy an exact pin sets the component version; ranges
    and bare deps do not. A specifier is concrete IFF it is exactly ONE clause
    whose operator is ``==`` or ``===`` AND the version contains no wildcard
    (``*``). So ``attrs==24.2.0`` and ``x===1.2`` are concrete (``24.2.0`` /
    ``1.2``); ``numpy<2``, ``==1.4.*``, ``~=1.2``, ``>=3.20,<4.0`` and
    ``==1.0,!=1.0.1`` are NOT (constraint only).
    """
    clauses = list(specifier)
    if len(clauses) != 1:
        return None
    clause = clauses[0]
    if clause.operator not in ("==", "==="):
        return None
    if "*" in clause.version:
        return None
    return clause.version
