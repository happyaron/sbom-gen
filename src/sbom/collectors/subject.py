"""Subject / root-artifact discovery.

Discovers every distributable root artifact the repo builds:

* the primary CANN/CMake/wheel subject (``project()`` / package metadata),
* sibling Python wheels (``setup.py``/``pyproject.toml`` in sub-dirs),
* standalone CMake roots (a dir whose ``CMakeLists.txt`` has both
  ``cmake_minimum_required`` and ``project()``), via
  :func:`sbom.cmake.parse.discover_roots`.

Each discovered root starts with the neutral role
``cmake_project``/``unclassified``; the profile then assigns the path-semantic
role (:meth:`Profile.classify_root`) and may collapse co-located wheel+CMake
roots into one subject (:meth:`Profile.subject_facets`).  Excluded roles
(profile policy ∪ ``--exclude-scope`` role tokens) are dropped with an
``excluded_scope`` warning per dropped root.  Non-distributable test/manual
roots keep ``emit_as_subject=False`` (ownership grouping only).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..config import Config
from ..models import (
    Facet,
    Identity,
    Subject,
    SubjectKind,
    SubjectMerge,
    SubjectRole,
    Warning,
)
from ..profile import Profile
from ..cmake import parse
from .py_metadata import resolve_package_metadata


# ---------------------------------------------------------------------------
# Patterns for reading project()/version metadata statically
# ---------------------------------------------------------------------------

_VAR_REF_RE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")
#: Any unexpanded build-variable / generator-expression token (``${...}``,
#: ``$<...>``, ``$(...)``, ``$ENV{...}``) — one must never survive into an
#: emitted subject name.
_ANY_VAR_RE = re.compile(r"\$ENV\{[^}]*\}|\$\{[^}]*\}|\$<[^>]*>|\$\([^)]*\)")


def _has_build_var(value: str) -> bool:
    """True when ``value`` carries an unexpanded CMake build-variable marker."""
    return "${" in value or "$<" in value or "$(" in value


def _lookup_set_var(var: str, text: str) -> str | None:
    """The value of a ``set(<var> <value>)`` in ``text``, or ``None`` if absent.

    Shared by the project() name and version resolvers (CANN roots define both
    via a ``set(...)`` just above ``project()``)."""
    sm = re.search(
        rf"""set\(\s*{re.escape(var)}\s+["']?([A-Za-z0-9_\-./]+)["']?\s*\)""", text
    )
    return sm.group(1) if sm else None

#: Roles that are kept as ownership-only grouping, not shipped artifacts.
_NON_EMIT_ROLES = {
    SubjectRole.NON_DISTRIBUTABLE_TEST,
    SubjectRole.ST_TEST,
    SubjectRole.MANUAL_EXAMPLE,
}

#: Roles eligible for path-semantic (re)classification in step 4: the two neutral
#: CMake roles and the default sibling-wheel role. SIBLING_ARTIFACT is the
#: unconditional default a sub-dir wheel gets at discovery -- never a deliberate
#: profile assertion -- so it stays open to demotion (an example-dir wheel ->
#: example). PRIMARY is excluded: the canonical subject is never demoted.
_DEFAULT_ROLES = {
    SubjectRole.CMAKE_PROJECT,
    SubjectRole.UNCLASSIFIED,
    SubjectRole.SIBLING_ARTIFACT,
}


# ---------------------------------------------------------------------------
# Exclude-scope token -> role bridge (mirrors config.resolve_exclude_scope; the
# subject collector only needs the role half, so it is small and self-contained
# to avoid a hard import dependency on config's optional helper).
# ---------------------------------------------------------------------------

_EXCLUDE_ROLE_TOKENS = {
    "example": SubjectRole.EXAMPLE,
    "st_test": SubjectRole.ST_TEST,
    "manual_example": SubjectRole.MANUAL_EXAMPLE,
    "experimental": SubjectRole.EXPERIMENTAL,
    "non_distributable_test": SubjectRole.NON_DISTRIBUTABLE_TEST,
}


#: Whole path segments (case-insensitive) that mark a discovered standalone root
#: as a generic EXAMPLE in the core, when no profile assigned a definite role.
#: Conservative: a WHOLE segment must match (so 'examples_helper' or a 'src'/'lib'
#: substring never trips it). Tests/ are intentionally NOT here -- test-path
#: semantics are left to profiles.
_GENERIC_EXAMPLE_SEGMENTS = {
    "example",
    "examples",
    "sample",
    "samples",
    "demo",
    "demos",
    "tutorial",
    "tutorials",
}


def _generic_example_root(source_path: str | None) -> bool:
    """True when a repo-relative ``source_path`` has an example/sample SEGMENT.

    Matches a WHOLE path segment (case-insensitive) against
    :data:`_GENERIC_EXAMPLE_SEGMENTS`, so ``example/0_quickstart/...`` matches via
    its ``example`` segment while ``src/foo``, ``lib/foo`` and a substring like
    ``examples_helper`` do not.
    """
    norm = _norm_source_path(source_path)
    if not norm:
        return False
    return any(seg.lower() in _GENERIC_EXAMPLE_SEGMENTS for seg in norm.split("/"))


def _excluded_roles(config: Config, profile: Profile) -> tuple[set[SubjectRole], set[str]]:
    """Return (excluded roles, unrecognized tokens).

    The set unions three additive sources: the profile's
    ``root_exclusion_policy()``, the ``release`` scope preset's base roles
    (empty under ``--scope all``), and the explicit ``--exclude-scope`` role
    tokens. The preset composes additively so an explicit ``--exclude-scope``
    still applies on top in both ``release`` and ``all`` modes.
    """
    from ..config import release_excluded_roles

    roles: set[SubjectRole] = set(profile.root_exclusion_policy())
    roles |= release_excluded_roles(config)
    unknown: set[str] = set()
    for token in config.exclude_scopes:
        role = _resolve_exclude_token(token)
        if role is not None:
            roles.add(role)
        elif token not in _PURE_SCOPE_TOKENS:
            unknown.add(token)
    return roles, unknown


#: Tokens that map to a UsageScope only (no role) -- not unknown, just not a
#: root exclusion.  Kept in sync with config.resolve_exclude_scope.
_PURE_SCOPE_TOKENS = {"test", "build", "runtime"}


def _resolve_exclude_token(token: str):
    """Bridge a raw --exclude-scope token to a SubjectRole, if any.

    Prefer config.resolve_exclude_scope when it is importable (single source of
    truth); fall back to the local table otherwise.
    """
    try:
        from ..config import resolve_exclude_scope

        role, _scope = resolve_exclude_scope(token)
        return role
    except Exception:  # noqa: BLE001 -- config may be partial during parallel build
        return _EXCLUDE_ROLE_TOKENS.get(token)


# ---------------------------------------------------------------------------
# Subject discovery
# ---------------------------------------------------------------------------


def discover_subjects(
    config: Config, profile: Profile
) -> tuple[list[Subject], list[Warning]]:
    """Discover all distributable root artifacts.  See module docstring."""
    repo_root = config.repo_root
    warnings: list[Warning] = []
    subjects: list[Subject] = []

    # 1. Primary subject from project() + package metadata.
    primary = _primary_subject(repo_root)
    if primary is not None:
        subjects.append(primary)

    # 1b. A root-level Python package (setup.py / pyproject.toml) ALWAYS gets a
    #     python_wheel subject via the metadata resolver — even when there is no
    #     CMake primary and even when the version is unresolved. When the repo has
    #     no CMake primary at all, the root wheel becomes the primary subject.
    if _has_python_package(repo_root):
        role = (
            SubjectRole.SIBLING_ARTIFACT
            if primary is not None
            else SubjectRole.PRIMARY
        )
        root_wheel, w = _wheel_subject_from_root(repo_root, repo_root, role=role)
        warnings.extend(w)
        subjects.append(root_wheel)

    # 2. Sibling Python wheels (setup.py / pyproject in sub-dirs).
    for pkg_dir in _iter_sibling_package_dirs(repo_root):
        wheel, w = _wheel_subject_from_root(
            pkg_dir, repo_root, role=SubjectRole.SIBLING_ARTIFACT
        )
        warnings.extend(w)
        subjects.append(wheel)

    # 3. Standalone CMake roots (generic discovery; neutral role). The repo-root
    #    CMakeLists already produced the primary subject (and the primary's CMake
    #    identity is a facet), so skip it here. A CMake root that shares a dir with
    #    a wheel is still emitted as its own subject -- the profile's subject_facets
    #    decides whether to merge them (it must see both to do so).
    repo_root_resolved = repo_root.resolve()
    seen_cmake_dirs: set[Path] = set()
    for root_dir in parse.discover_roots(repo_root):
        rd = Path(root_dir).resolve()
        if rd == repo_root_resolved:
            continue
        if rd in seen_cmake_dirs:
            continue
        seen_cmake_dirs.add(rd)
        subjects.append(_cmake_root_subject(root_dir, repo_root))

    # 4. Profile assigns path-semantic roles to the neutral cmake roots AND to
    #    sibling wheels; the profile WINS (a definite role it returns is kept).
    #    When the profile leaves the role at a default, a CONSERVATIVE generic
    #    fallback in the core marks an example/sample/demo/tutorial root (whole
    #    repo-relative path SEGMENT match) as EXAMPLE. This lets a profile-less
    #    repo's example trees trim under the release scope.
    #
    #    A sub-dir wheel is assigned SIBLING_ARTIFACT unconditionally at discovery
    #    (step 2) -- that role is the wheel default, never a profile assertion, and
    #    it has never been path-checked. So a wheel BUILT BY an example tree (e.g.
    #    ops-math's examples/fast_kernel_launch_example/setup.py -> ascend_ops) must
    #    still get its example/test role here; otherwise the example's CMake root is
    #    folded into the wheel in step 5 and the wheel's stale SIBLING_ARTIFACT
    #    leaks into the release view. PRIMARY wheels are deliberately NOT eligible.
    #
    #    A CMake root co-located with a wheel (same source_path) is about to be
    #    absorbed by that wheel in step 5 and inherits the wheel's role, so the
    #    generic EXAMPLE fallback must NOT pre-reclassify the CMAKE root (that would
    #    block the merge, which only absorbs cmake_project/primary roles). The WHEEL
    #    itself at that path is not skipped -- it is the artifact that ships.
    wheel_paths = {
        _norm_source_path(s.source_path)
        for s in subjects
        if s.identity.kind is SubjectKind.PYTHON_WHEEL
    }
    package_context = {"repo_root": str(repo_root)}
    for subject in subjects:
        if subject.role in _DEFAULT_ROLES:
            path = (
                repo_root / subject.source_path
                if subject.source_path
                else repo_root
            )
            new_role = profile.classify_root(path, subject, package_context)
            co_located_cmake = (
                subject.identity.kind is SubjectKind.CMAKE_PROJECT
                and _norm_source_path(subject.source_path) in wheel_paths
            )
            if (
                new_role in _DEFAULT_ROLES
                and not co_located_cmake
                and _generic_example_root(subject.source_path)
            ):
                new_role = SubjectRole.EXAMPLE
            subject.role = new_role
            if new_role in _NON_EMIT_ROLES:
                subject.emit_as_subject = False

    # 5. Subject facets.
    #
    #    (a) GENERIC co-located merge: a python_wheel and a cmake_project that
    #        share the same source_path are the same artifact (the Python package
    #        is built by its co-located CMakeLists, e.g. pyasc's wheel 'pyasc' +
    #        project(AscIR)). The wheel identity is canonical; the CMake project
    #        becomes a facet + build_graph_root. This is the generic version of
    #        the profile's subject_facets hook.
    #    (b) Then the PROFILE's subject_facets merges (the CANN profile merges
    #        ascend_ops+AscendOps and npu_math_extension). Running the generic
    #        merge first and applying profile merges second composes cleanly; the
    #        merge application is idempotent (a pair already collapsed is a no-op),
    #        so ops-math's ops_math primary is never double-merged.
    generic_merges = _colocated_wheel_cmake_merges(subjects)
    subjects = _apply_merges(subjects, generic_merges)

    profile_merges = profile.subject_facets(subjects)
    subjects = _apply_merges(subjects, profile_merges)

    # 6. Exclusion: drop roots whose role is excluded (policy + scope tokens).
    excluded_roles, unknown_tokens = _excluded_roles(config, profile)
    for token in unknown_tokens:
        warnings.append(
            Warning(
                code="excluded_scope",
                subject=token,
                detail=f"unrecognized --exclude-scope token: {token}",
            )
        )
    kept: list[Subject] = []
    for subject in subjects:
        if subject.role in excluded_roles:
            warnings.append(
                Warning(
                    code="excluded_scope",
                    subject=subject.id,
                    detail=f"dropped root with role {subject.role.value}",
                )
            )
            continue
        kept.append(subject)

    kept = _dedup_identical_subjects(kept)

    return kept, warnings


# ---------------------------------------------------------------------------
# Identity de-dup (drop genuinely-duplicate roots before emission)
# ---------------------------------------------------------------------------


def _subject_identity_key(subject: Subject) -> tuple:
    """A structural identity for a discovered subject.

    Two subjects are the SAME discovered artifact when their id, identity
    (kind/name/version), role and (normalized) source_path all match — e.g. a
    root re-discovered through two passes. Distinct roots that merely slugify to
    the same SPDX id keep DIFFERENT ``source_path`` values, so they are NOT
    collapsed here (the emitters disambiguate their ids instead).
    """
    return (
        subject.id,
        subject.identity.kind,
        subject.identity.name,
        subject.identity.version,
        subject.role,
        _norm_source_path(subject.source_path),
    )


def _dedup_identical_subjects(subjects: list[Subject]) -> list[Subject]:
    """Drop genuinely-identical subjects (same id/identity/role/path), keep order.

    This removes a root that was discovered more than once with an identical
    identity so it is never emitted twice. It deliberately does NOT collapse two
    DIFFERENT roots that merely share an id/slug (they live at different
    ``source_path``s) — those are disambiguated by the emitters."""
    seen: set[tuple] = set()
    out: list[Subject] = []
    for subject in subjects:
        key = _subject_identity_key(subject)
        if key in seen:
            continue
        seen.add(key)
        out.append(subject)
    return out


# ---------------------------------------------------------------------------
# Merge application
# ---------------------------------------------------------------------------


def _apply_merges(subjects: list[Subject], merges) -> list[Subject]:
    """Apply ``SubjectMerge`` instructions, idempotently.

    A merge whose ``keep`` and ``absorbed`` are the same subject, or whose
    ``absorbed`` subject is already gone (collapsed by an earlier merge in this
    or a prior pass), is a no-op. This lets the generic co-located merge run
    before the profile merges without the profile re-merging an already-collapsed
    pair (so ops-math's ops_math primary is never double-merged).
    """
    by_id = {s.id: s for s in subjects}
    absorbed: set[str] = set()
    for merge in merges:
        if merge.keep_subject_id == merge.absorbed_subject_id:
            continue
        keep = by_id.get(merge.keep_subject_id)
        absorb = by_id.get(merge.absorbed_subject_id)
        if keep is None or absorb is None:
            continue
        if absorb.id in absorbed:
            continue
        facet = merge.facet
        if facet is None:
            facet = Facet(
                kind=absorb.identity.kind,
                name=absorb.identity.name,
                version=absorb.identity.version,
            )
        if facet not in keep.facets:
            keep.facets.append(facet)
        if merge.build_graph_root_id is not None:
            keep.build_graph_root_id = merge.build_graph_root_id
        elif keep.build_graph_root_id is None:
            keep.build_graph_root_id = absorb.id
        absorbed.add(absorb.id)
    return [s for s in subjects if s.id not in absorbed]


def _colocated_wheel_cmake_merges(subjects: list[Subject]) -> list[SubjectMerge]:
    """Generic merge: a wheel and a CMake project at the SAME source_path are one.

    When a ``python_wheel`` subject and a ``cmake_project`` subject share an
    (identical, normalized) ``source_path``, the Python package is built by its
    co-located ``CMakeLists.txt``. The wheel identity is canonical/primary; the
    CMake project is folded in as a :class:`Facet` and ``build_graph_root_id``.

    This deliberately ignores name matching — co-location is the signal (e.g.
    pyasc's wheel ``pyasc`` lives beside ``project(AscIR)``; the names differ).

    A co-located CMake subject whose role is the bare ``cmake_project`` (a
    discovered standalone root) OR the repo ``primary`` (the root CMakeLists won
    the primary slot only because the wheel identity wasn't known yet) is
    absorbed into the wheel; when the absorbed CMake subject was the primary the
    wheel inherits the ``primary`` role, so the wheel — not ``project(AscIR)`` —
    is the canonical subject. A primary that already carries CMake as a FACET
    (e.g. a CANN-package subject) has no standalone ``cmake_project`` subject to
    absorb, so it is left untouched.
    """
    wheels: dict[str, Subject] = {}
    cmake_projects: dict[str, list[Subject]] = {}
    for s in subjects:
        key = _norm_source_path(s.source_path)
        if s.identity.kind is SubjectKind.PYTHON_WHEEL:
            # First wheel at a path wins (deterministic by discovery order).
            wheels.setdefault(key, s)
        elif s.identity.kind is SubjectKind.CMAKE_PROJECT and s.role in (
            SubjectRole.CMAKE_PROJECT,
            SubjectRole.PRIMARY,
        ):
            cmake_projects.setdefault(key, []).append(s)

    merges: list[SubjectMerge] = []
    for key, wheel in wheels.items():
        for cmake_subject in cmake_projects.get(key, []):
            if cmake_subject.id == wheel.id:
                continue
            if cmake_subject.role is SubjectRole.PRIMARY:
                # The wheel becomes the canonical/primary subject.
                wheel.role = SubjectRole.PRIMARY
            merges.append(
                SubjectMerge(
                    keep_subject_id=wheel.id,
                    absorbed_subject_id=cmake_subject.id,
                    build_graph_root_id=cmake_subject.id,
                    facet=Facet(
                        kind=cmake_subject.identity.kind,
                        name=cmake_subject.identity.name,
                        version=cmake_subject.identity.version,
                    ),
                )
            )
    return merges


def _norm_source_path(source_path: str | None) -> str:
    """Normalize a subject ``source_path`` for co-location comparison.

    The repo root is ``""``; sub-dirs are repo-relative POSIX paths. Trailing
    slashes are stripped so ``"a/b"`` and ``"a/b/"`` compare equal.
    """
    if not source_path:
        return ""
    norm = str(source_path).replace("\\", "/").rstrip("/")
    return "" if norm in (".", "") else norm


# ---------------------------------------------------------------------------
# Building individual subjects
# ---------------------------------------------------------------------------


def _primary_subject(repo_root: Path) -> Subject | None:
    """The repo's primary subject from top-level CMakeLists + version.cmake.

    Identity is the CMake ``project()`` name/version; when a ``version.cmake``
    ``set_cann_package`` is present it becomes the (CANN package) primary
    identity with the CMake project recorded as a facet.
    """
    top = repo_root / "CMakeLists.txt"
    if not top.exists():
        return None
    cf = parse.parse_file(top)
    cmake_name = _resolve_project_name(cf.project_name, top)
    cmake_version = _resolve_project_version(cf.project_version, top)

    pkg_name, pkg_version = _read_version_cmake(repo_root / "version.cmake")

    if pkg_name:
        identity = Identity(
            kind=SubjectKind.CANN_PACKAGE, name=pkg_name, version=pkg_version
        )
        facets = []
        if cmake_name:
            facets.append(
                Facet(
                    kind=SubjectKind.CMAKE_PROJECT,
                    name=cmake_name,
                    version=cmake_version,
                )
            )
        subject = Subject(
            id=pkg_name,
            identity=identity,
            role=SubjectRole.PRIMARY,
            facets=facets,
            source_path="",
        )
        return subject

    if cmake_name:
        return Subject(
            id=cmake_name,
            identity=Identity(
                kind=SubjectKind.CMAKE_PROJECT,
                name=cmake_name,
                version=cmake_version,
            ),
            role=SubjectRole.PRIMARY,
            source_path="",
        )
    return None


def _cmake_root_subject(root_dir: Path, repo_root: Path) -> Subject:
    cmake = root_dir / "CMakeLists.txt"
    cf = parse.parse_file(cmake)
    name = _resolve_project_name(cf.project_name, cmake) or root_dir.name
    rel = _rel_path(root_dir, repo_root)
    return Subject(
        id=name,
        identity=Identity(
            kind=SubjectKind.CMAKE_PROJECT,
            name=name,
            version=_resolve_project_version(cf.project_version, cmake),
        ),
        role=SubjectRole.CMAKE_PROJECT,
        source_path=rel,
    )


def _wheel_subject_from_root(
    pkg_dir: Path, repo_root: Path, role: SubjectRole
) -> tuple[Subject, list[Warning]]:
    """Build a ``python_wheel`` subject for the package at ``pkg_dir``.

    Uses :func:`resolve_package_metadata` so the identity is robust to dynamic
    metadata (env-var defaults, version files, helper functions, …). The subject
    is ALWAYS created when a package exists — even when the version is ``None`` —
    and never dropped for unresolved metadata. ``source_path`` is the package dir.
    Returns the subject and any honesty warnings the resolver emitted.
    """
    meta = resolve_package_metadata(pkg_dir)
    rel = _rel_path(pkg_dir, repo_root)
    subject = Subject(
        id=meta.name,
        identity=Identity(
            kind=SubjectKind.PYTHON_WHEEL, name=meta.name, version=meta.version
        ),
        role=role,
        source_path=rel,
    )
    return subject, list(meta.warnings)


def _has_python_package(pkg_dir: Path) -> bool:
    return (pkg_dir / "setup.py").is_file() or _has_pep621_project(pkg_dir)


def _has_pep621_project(pkg_dir: Path) -> bool:
    """True when ``pyproject.toml`` declares a buildable package.

    A ``pyproject.toml`` that only configures tooling (e.g. MindIE-LLM's
    ``[tool.black]``-only file, or pyasc's coverage/ruff config) is NOT a package
    root on its own — only a ``[project]`` table or a ``[build-system]`` backend
    makes it one.
    """
    import tomllib

    path = pkg_dir / "pyproject.toml"
    if not path.is_file():
        return False
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return False
    return "project" in data or "build-system" in data or "build_system" in data


# ---------------------------------------------------------------------------
# Static metadata readers
# ---------------------------------------------------------------------------


def _resolve_project_name(name: str | None, cmake_file: Path) -> str | None:
    """Resolve a ``project(<name>)`` that references CMake build variables.

    A name with no ``${...}`` is returned unchanged. Otherwise each ``${VAR}`` is
    substituted from a ``set(VAR value)`` in the same file (CANN roots define the
    name via ``set(PKG_NAME ...)`` just above ``project()``). A ``${VAR}`` with no
    resolvable ``set()`` — e.g. hs-fbb's ``project(${CHIP}_CFBB)``, where ``CHIP``
    is a REQUIRED build-time argument (``if(NOT DEFINED CHIP) message(FATAL_ERROR)``)
    and thus unknowable statically — is DROPPED and the literal remainder kept
    (``${CHIP}_CFBB`` → ``CFBB``). An unexpanded ``${...}`` is never emitted as a
    name; when nothing literal remains, ``None`` is returned so the caller falls
    back to the directory basename.
    """
    if not name:
        return name
    stripped = name.strip()
    if not _has_build_var(stripped):
        return stripped

    try:
        text = cmake_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""

    resolved = _VAR_REF_RE.sub(lambda m: _lookup_set_var(m.group(1), text) or "", stripped)
    # Drop any residual token _VAR_REF_RE did not cover (generator exprs, $(),
    # $ENV{}, ${A-B} with punctuation), then tidy separators a dropped token left.
    resolved = _ANY_VAR_RE.sub("", resolved).strip("_-. ")
    while "__" in resolved:
        resolved = resolved.replace("__", "_")
    return resolved or None


def _resolve_project_version(version: str | None, cmake_file: Path) -> str | None:
    """Resolve / sanitize a ``project(... VERSION <v>)`` that references variables.

    A literal version passes through unchanged. A ``${VAR}`` is substituted from a
    same-file ``set()``; when it stays unresolved — e.g. ops-fft's
    ``project(${OPS_FFT} VERSION ${PROJECT_VERSION} ...)``, where
    ``PROJECT_VERSION`` is a build-time value not defined in the file — the version
    is DROPPED (``None``) rather than emitted raw, so the subject purl carries no
    ``@version`` instead of ``@%24%7BPROJECT_VERSION%7D``. Mirrors the
    component-version sanitizer in :func:`sbom.reconcile._sanitize_unresolved_versions`.
    """
    if not version or not _has_build_var(version):
        return version
    try:
        text = cmake_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    # Substitute resolvable ${VAR}s; leave an unresolved one in place so the guard
    # below detects it and drops the whole version (never assert a partial version).
    resolved = _VAR_REF_RE.sub(
        lambda m: _lookup_set_var(m.group(1), text) or m.group(0), version
    )
    if _has_build_var(resolved):
        return None
    return resolved.strip() or None


def _read_version_cmake(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, None
    text = path.read_text(encoding="utf-8", errors="replace")
    m = re.search(
        r"""set_cann_package\(\s*([A-Za-z0-9_\-]+)\s+VERSION\s+["']?([0-9][^)"'\s]*)""",
        text,
    )
    if m:
        return m.group(1), m.group(2)
    return None, None


def _iter_sibling_package_dirs(repo_root: Path):
    """Yield every Python package dir under sub-dirs (not the repo root itself).

    A package dir is one containing a ``setup.py`` or a PEP 621 / build-backend
    ``pyproject.toml``. Each dir is yielded once even when it has both files.
    """
    root = repo_root.resolve()
    seen: set[Path] = set()
    candidates: set[Path] = set()
    for setup_py in root.rglob("setup.py"):
        candidates.add(setup_py.parent)
    for pyproject in root.rglob("pyproject.toml"):
        candidates.add(pyproject.parent)
    for pkg_dir in sorted(candidates):
        resolved = pkg_dir.resolve()
        if resolved == root or resolved in seen:
            continue
        if not _has_python_package(pkg_dir):
            continue
        seen.add(resolved)
        yield pkg_dir


def _rel_path(path: Path, repo_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return str(path)
