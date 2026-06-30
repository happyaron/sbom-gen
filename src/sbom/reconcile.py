"""Merge collected records into a single :class:`~sbom.models.Document`.

``reconcile`` is the ONLY stage that produces a ``Document``. It:

* builds the :class:`AliasResolver` (built-in OSS aliases ∪ ``profile.alias_map()``),
* de-dups components by alias-resolved canonical name, UNIONing scopes,
  languages, integrity_findings and provenance across observations,
* attaches every unattached observation to its (alias-resolved) component,
* keeps ``source_version`` vs ``effective_version`` separate and flags
  patched-build mismatches,
* derives ``Component.depends_on`` from the first-class :class:`DependencyEdge`
  list (the edges remain the authority; per-root ownership is preserved and a
  ``subject -> component`` edge is never collapsed into a component rollup),
* runs the layered license resolver (curated > known map > cache scan > network
  > NOASSERTION), recording :class:`Provenance` and discrepancy ``Warning``s,
* raises ``unmapped_link_library`` for an external link token with no alias,
* carries every edge's ``root_artifact_id`` through unchanged.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from .models import (
    Component,
    DependencyEdge,
    Document,
    Provenance,
    RefKind,
    SourceKind,
    SubjectRole,
    UsageScope,
    Warning,
    python_unverified_direct_url,
)
from .profile import Profile
from .origin import apply_repo_origin
from . import graph

logger = logging.getLogger(__name__)

if TYPE_CHECKING:  # pragma: no cover - import only for type checking
    from pathlib import Path

    from .collectors import CollectResult
    from .config import Config
    from .models import Subject


# ---------------------------------------------------------------------------
# Built-in OSS aliases (generic core, profile-independent)
# ---------------------------------------------------------------------------

#: ``raw spelling -> (canonical_name, relation_type | None)``. The generic core
#: knows these regardless of profile; the profile's ``alias_map()`` extends them.
OSS_ALIASES: dict[str, tuple[str, str | None]] = {
    "googletest": ("gtest", None),
    "makeself-fetch": ("makeself", None),
    "nlohmann-json": ("json", None),
    "nlohmann_json": ("json", None),
}


# ---------------------------------------------------------------------------
# AliasResolver
# ---------------------------------------------------------------------------


class AliasResolver:
    """Map any spelling of a component to its canonical name + relation type.

    Built by :func:`build_alias_resolver` from the built-in OSS aliases unioned
    with the profile's ``alias_map()``. Lookups are case-insensitive on the raw
    spelling (CMake ``find_package(OPBASE)`` and version-cmake ``opbase`` resolve
    to the same canonical name), but the canonical name is returned verbatim as
    supplied by the alias source.
    """

    def __init__(self, table: dict[str, tuple[str, str | None]]):
        # Keyed by lowercased spelling so OPBASE/opbase/OpBase all resolve.
        self._table: dict[str, tuple[str, str | None]] = {
            key.lower(): value for key, value in table.items()
        }

    def canonical(self, name: str) -> str:
        """Return the canonical name for ``name`` (itself if unknown)."""
        entry = self._table.get(name.lower())
        return entry[0] if entry is not None else name

    def relation(self, name: str) -> str | None:
        """Return the alias relation type for ``name`` (a :class:`RelationType`
        value), or ``None`` when unmapped or the alias carries no relation."""
        entry = self._table.get(name.lower())
        return entry[1] if entry is not None else None

    def is_known(self, name: str) -> bool:
        """True when ``name`` has an explicit alias entry."""
        return name.lower() in self._table


#: Archive extensions a download URL's filename may carry.
_ARCHIVE_EXTS = (
    ".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst", ".tgz", ".tbz2", ".txz", ".zip",
)
#: A trailing ``-<version>`` / ``_<version>`` (digit-led, optional ``v`` prefix).
_VERSION_TAIL = re.compile(r"[-_]v?\d[\w.\-]*$")
#: A token that is ENTIRELY a version (``v1.3.1``, ``20230802.1``, ``1.9.5``).
_VERSIONISH = re.compile(r"^v?\d[\w.\-]*$")
#: URL path / filename segments that are scaffolding, never the package name —
#: so an archive-tag URL (``…/zlib/archive/refs/tags/v1.3.1.tar.gz``) or a noisy
#: asset (``makeself-release-2.5.0-patch1.tar.gz``) is not mistaken for one.
_GENERIC_SEG = frozenset({
    "release", "releases", "archive", "download", "downloads", "master", "main",
    "src", "source", "sources", "latest", "stable", "final", "dist", "repository",
    "refs", "tags", "tag", "blob", "raw", "heads", "-",
})


def _name_like(seg: str | None) -> str | None:
    """Return ``seg`` lowercased as a package name, or ``None`` if it can't be one
    (empty, pure-version, or a generic scaffolding word)."""
    if not seg:
        return None
    s = seg.strip("-_.").lower()
    if not s or s in _GENERIC_SEG or _VERSIONISH.match(s) or not re.search(r"[a-z]", s):
        return None
    return s


def _name_from_filename(fname: str) -> str | None:
    """The package name from an archive filename: strip the extension, a trailing
    ``-<version>``, and any trailing generic word (``makeself-release`` → ``makeself``)."""
    low = fname.lower()
    ext = next((e for e in _ARCHIVE_EXTS if low.endswith(e)), None)
    if ext is None:
        return None
    stem = _VERSION_TAIL.sub("", fname[: -len(ext)])
    parts = re.split(r"[-_]", stem)
    while len(parts) > 1 and parts[-1].lower() in _GENERIC_SEG:
        parts.pop()
    return _name_like("-".join(parts))


def _name_from_path(segs: list[str]) -> str | None:
    """The repo name from a hosted-git URL path (``owner/repo/…``): the segment
    before a hosting marker (``/archive/``, ``/releases/``, …), else the 2nd."""
    for i, seg in enumerate(segs):
        if seg.lower() in _GENERIC_SEG and i >= 1:
            return _name_like(segs[i - 1])
    if len(segs) >= 2:
        return _name_like(segs[1])
    return None


def _upstream_from_url(url: str | None) -> str | None:
    """Derive an upstream package name from an archive **download** URL.

    Two independent signals are read and must agree (or only one be available):
    the filename stem (``eigen-5.0.0.tar.gz`` → ``eigen``) and the hosted-git repo
    path segment (``…/eigen/releases/…`` → ``eigen``). When the filename is a bare
    version (GitHub/Gitee archive-tag URLs like ``…/zlib/archive/refs/tags/
    v1.3.1.tar.gz``) the path supplies the name; when the two NAME-like signals
    DISAGREE the result is ambiguous and ``None`` is returned (the component keeps
    its own name rather than being mis-renamed). Non-archive URLs and unexpanded
    ``${…}`` templates yield ``None``.
    """
    if not url or "${" in url or "$<" in url:
        return None
    base = url.split("?")[0].split("#")[0]
    if not any(base.lower().endswith(e) for e in _ARCHIVE_EXTS):
        return None
    from urllib.parse import urlsplit

    segs = [s for s in urlsplit(base).path.split("/") if s]
    if not segs:
        return None
    file_name = _name_from_filename(segs[-1])
    path_name = _name_from_path(segs[:-1])
    if file_name and path_name:
        return file_name if file_name == path_name else None
    return file_name or path_name


def _derivation_candidates(components: "list[Component]") -> list[tuple[str, str, str]]:
    """``(component_name, derived_upstream, canonical_url)`` for every component
    whose archive URL yields an upstream name DIFFERENT from its own name."""
    out: list[tuple[str, str, str]] = []
    for comp in components:
        for obs in comp.observations:
            url = getattr(obs, "canonical_url", None)
            upstream = _upstream_from_url(url)
            if upstream and upstream != comp.name.lower():
                out.append((comp.name, upstream, url))
                break  # first archive-URL observation wins
    return out


def _collision_upstreams(cands: list[tuple[str, str, str]]) -> set[str]:
    """Upstream names derived from MORE THAN ONE distinct URL — i.e. two genuinely
    different components would collapse onto one name. Such derivations are unsafe."""
    urls_by_upstream: dict[str, set[str]] = {}
    for _name, upstream, url in cands:
        urls_by_upstream.setdefault(upstream, set()).add(url)
    return {up for up, urls in urls_by_upstream.items() if len(urls) > 1}


def _derive_aliases(components: "list[Component]") -> dict[str, str]:
    """On-the-fly ``raw spelling -> upstream`` aliases from component download URLs.

    A third-party fetched via ``ExternalProject``/``FetchContent`` is often named
    after its CMake *target* (``external_eigen_nn``), not its upstream identity;
    the target's own ``canonical_url`` carries the real name in the archive it
    downloads, so the canonical identity is derivable with no hand-written map.
    Derivations whose upstream name collides across distinct URLs are SKIPPED so
    two genuinely-different dependencies are never silently merged (see
    :func:`_derive_alias_collisions` for the matching warning)."""
    cands = _derivation_candidates(components)
    collisions = _collision_upstreams(cands)
    derived: dict[str, str] = {}
    for name, upstream, _url in cands:
        if upstream not in collisions:
            derived.setdefault(name, upstream)
    return derived


def _derive_alias_collisions(components: "list[Component]") -> list[str]:
    """Upstream names that distinct components derive from different URLs (left
    un-merged by :func:`_derive_aliases`); surfaced as warnings by reconcile."""
    return sorted(_collision_upstreams(_derivation_candidates(components)))


def _config_aliases(config) -> dict[str, str]:
    """User-supplied ``spelling -> canonical`` aliases from ``[aliases]`` config."""
    raw = getattr(config, "aliases", None) if config is not None else None
    if not raw:
        return {}
    return {str(k): str(v) for k, v in raw.items() if k and v}


def build_alias_resolver(
    profile: Profile, config=None, components: "list[Component] | None" = None
) -> AliasResolver:
    """Combine every alias layer into one resolver.

    Precedence (highest wins on a shared spelling): **explicit ``[aliases]``
    config > profile ``alias_map()`` > built-in OSS aliases > on-the-fly
    derivation**. The derivation only FILLS spellings no curated layer covers (a
    guess never overrides a human), and its derived canonical is itself resolved
    through the curated layers (so a derived ``googletest`` still lands on
    ``gtest``). ``config``/``components`` are optional so existing callers that
    pass only ``profile`` keep the curated-only behaviour.
    """
    # Curated layers first (OSS < profile < config), each overriding the prior.
    table: dict[str, tuple[str, str | None]] = dict(OSS_ALIASES)
    for spelling, record in profile.alias_map().items():
        table[spelling] = (record.get("canonical", spelling), record.get("relation"))
    for spelling, canonical in _config_aliases(config).items():
        table[spelling] = (canonical, None)
    curated = AliasResolver(table)

    # On-the-fly derivation fills only uncovered spellings (curated always wins).
    if components:
        for spelling, raw_canonical in _derive_aliases(components).items():
            if curated.is_known(spelling):
                continue
            canonical = curated.canonical(raw_canonical)
            if canonical.lower() != spelling.lower():
                table.setdefault(spelling, (canonical, None))
    return AliasResolver(table)


# ---------------------------------------------------------------------------
# Component de-dup / union
# ---------------------------------------------------------------------------


def _union_extend(target: list, additions: list) -> None:
    """Append items of ``additions`` to ``target`` preserving order, no dups."""
    for item in additions:
        if item not in target:
            target.append(item)


def _merge_into(base: Component, other: Component, resolver: AliasResolver) -> None:
    """Fold ``other`` into ``base`` in place (UNION semantics)."""
    # Record the absorbed spelling as an alias so the canonical component keeps
    # a trace of every name it was seen under.
    if other.name != base.name:
        _union_extend(base.aliases, [other.name])
    _union_extend(base.aliases, other.aliases)

    _union_extend(base.languages, other.languages)
    _union_extend(base.scopes, other.scopes)
    _union_extend(base.integrity_findings, other.integrity_findings)
    _union_extend(base.provenance, other.provenance)
    _union_extend(base.patches, other.patches)
    _union_extend(base.depends_on, other.depends_on)
    base.observations.extend(other.observations)

    # source_version vs effective_version are kept SEPARATE; first non-None wins
    # per axis (mismatches are flagged downstream, not collapsed here).
    if base.source_version is None:
        base.source_version = other.source_version
    if base.effective_version is None:
        base.effective_version = other.effective_version

    # Scalar summary fields: keep the first proven (non-None) value.
    for attr in ("supplier", "license", "copyright", "vcs_ref"):
        if getattr(base, attr) is None and getattr(other, attr) is not None:
            setattr(base, attr, getattr(other, attr))

    for key, value in other.checksums.items():
        base.checksums.setdefault(key, value)
    for key, value in other.completeness.items():
        base.completeness.setdefault(key, value)

    if "application" in (base.type, other.type):
        base.type = "application"


def _dedup_components(
    components: list[Component], resolver: AliasResolver
) -> tuple[list[Component], dict[str, Component]]:
    """Collapse components sharing an alias-resolved canonical name.

    Returns the de-duped list (order = first appearance) and an index from every
    spelling/alias seen to the surviving canonical component.
    """
    by_canonical: dict[str, Component] = {}
    ordered: list[Component] = []
    index: dict[str, Component] = {}

    for comp in components:
        canonical = resolver.canonical(comp.name)
        existing = by_canonical.get(canonical)
        if existing is None:
            # Re-key onto the canonical name so later observations attach cleanly.
            if comp.name != canonical:
                _union_extend(comp.aliases, [comp.name])
                comp.name = canonical
            by_canonical[canonical] = comp
            ordered.append(comp)
            existing = comp
        else:
            _merge_into(existing, comp, resolver)

        index[canonical] = existing
        index[comp.name] = existing
        for alias in existing.aliases:
            index[alias] = existing

    return ordered, index


# ---------------------------------------------------------------------------
# Observation attachment
# ---------------------------------------------------------------------------


#: ``ecosystem_data`` keys (in priority order) that may carry the resolvable
#: component name. Per the SHARED NAMING CONVENTION producers SHOULD set
#: ``name``; the legacy keys (``cann_package``/``program``/...) are read
#: defensively so a producer that has not migrated yet still resolves.
_NAME_KEYS = (
    "name",
    "component",
    "canonical_name",
    "cann_package",
    "program",
    "link_target",
    "target",
)


def _observation_name(obs) -> str | None:
    """Best-effort component name an unattached observation refers to.

    Resolution order (the SHARED NAMING CONVENTION):

    1. an explicit ``name`` attribute on the observation, if present;
    2. ``ecosystem_data`` keys, in the order of :data:`_NAME_KEYS`
       (``name``, ``component``, ``canonical_name``, ``cann_package``,
       ``program``, ``link_target``, ``target``);
    3. ``obs.find_package.name`` for a ``cmake_find_package`` site.

    Without the legacy-key fallbacks the ``cann_package`` (version.cmake),
    ``find_package`` and program/tool observations -- which stash the target
    spelling under ``cann_package``/``program`` rather than ``name`` -- would be
    dropped as ``unattached_observation`` instead of attaching to their
    component.
    """
    explicit = getattr(obs, "name", None)
    if explicit:
        return explicit

    data = obs.ecosystem_data or {}
    for key in _NAME_KEYS:
        value = data.get(key)
        if value:
            return value

    find_package = getattr(obs, "find_package", None)
    fp_name = getattr(find_package, "name", None)
    if fp_name:
        return fp_name

    return None


def _attach_observations(
    observations: list,
    index: dict[str, Component],
    resolver: AliasResolver,
    ordered: list[Component],
) -> list[Warning]:
    """Attach each unattached observation to its alias-resolved component.

    A link-library observation whose token resolves to no known component and
    carries no alias raises ``unmapped_link_library``.
    """
    warnings: list[Warning] = []
    for obs in observations:
        name = _observation_name(obs)
        if name is None:
            warnings.append(
                Warning(
                    code="unattached_observation",
                    subject=None,
                    detail=f"observation {obs.source_kind.value} carries no component name",
                )
            )
            continue
        canonical = resolver.canonical(name)
        comp = index.get(canonical) or index.get(name)
        if comp is None:
            if obs.source_kind is SourceKind.CMAKE_LINK_LIBRARY and not resolver.is_known(
                name
            ):
                warnings.append(
                    Warning(
                        code="unmapped_link_library",
                        subject=name,
                        detail="external link token not covered by the alias map",
                    )
                )
                continue
            # Materialize a new component for an otherwise-unseen observation.
            comp = Component(name=canonical)
            if name != canonical:
                _union_extend(comp.aliases, [name])
            ordered.append(comp)
            index[canonical] = comp
            index[name] = comp
        comp.observations.append(obs)
        _absorb_observation_facts(comp, obs)
    return warnings


def _absorb_observation_facts(comp: Component, obs) -> None:
    """UNION an observation's per-site facts up onto the component summary."""
    if obs.usage_scope is not None:
        _union_extend(comp.scopes, [obs.usage_scope])


# ---------------------------------------------------------------------------
# Curated facts (profile-supplied Notice / List.yaml)
# ---------------------------------------------------------------------------


def _normalize_version(value: str | None) -> str | None:
    """Drop a leading ``v`` so curated ``v25.1`` matches the cmake bare ``25.1``."""
    if value is None:
        return None
    value = value.strip()
    if len(value) > 1 and value[0] in "vV" and value[1].isdigit():
        return value[1:]
    return value


def _apply_curated_records(
    components: list[Component],
    config: "Config | None",
    profile: Profile,
    resolver: AliasResolver,
) -> None:
    """Fold profile-supplied curated VERSION facts onto matching components.

    The CANN profile's ``curated_records(repo_root)`` parses the
    ``Third_Party_..._List.yaml`` (source/declared version) and the ``..._Notice``
    (the patched effective version, when it differs) into one record per
    component. This wires the version facts into reconcile so a patched build is
    visible *before* :func:`_flag_version_mismatches` runs: protobuf keeps its
    cmake ``source_version=25.1`` and gains ``effective_version=3.13.0`` from the
    Notice, triggering ``patched_build``. License/copyright stay with the layered
    resolver (curated license precedence lives in :func:`_resolve_licenses`).

    The hook is optional (only the CANN-style profile defines it); a profile
    without it -- or with no curated files -- is a silent no-op.
    """
    repo_root = getattr(config, "repo_root", None)
    if repo_root is None:
        return
    curated_records = getattr(profile, "curated_records", None)
    if curated_records is None:
        return
    try:
        records = curated_records(repo_root)
    except Exception:  # noqa: BLE001 - a broken enricher must not crash reconcile
        return

    by_name: dict[str, Component] = {}
    for comp in components:
        by_name.setdefault(comp.name, comp)
        by_name.setdefault(resolver.canonical(comp.name), comp)
        for alias in comp.aliases:
            by_name.setdefault(alias, comp)

    for rec in records:
        name = getattr(rec, "name", None)
        if not name:
            continue
        comp = by_name.get(name) or by_name.get(resolver.canonical(name))
        if comp is None:
            continue

        source = _normalize_version(getattr(rec, "version", None))
        effective = _normalize_version(getattr(rec, "effective_version", None))

        # cmake-sourced source_version wins; fill it only when absent.
        if comp.source_version is None and source is not None:
            comp.source_version = source
        # The Notice is authoritative for the patched effective version.
        if effective is not None:
            comp.effective_version = effective


# ---------------------------------------------------------------------------
# Version reconciliation / patched-build flags
# ---------------------------------------------------------------------------


def _curated_license_copyright(
    config: "Config | None",
    profile: Profile,
    resolver: AliasResolver,
) -> dict[str, tuple[str | None, str | None]]:
    """Return ``{canonical_name: (license, copyright)}`` from the profile's
    curated Notice records (CANN: the ``..._Notice`` License + Copyright blocks).

    The CANN profile's ``curated_records(repo_root)`` parses the Notice's
    per-third-party ``License:`` line AND ``Copyright notice:`` block; this folds
    both into a map keyed by the alias-resolved canonical name so the license
    resolver can apply BOTH the declared license and the declared copyright as a
    high-confidence layer. Best-effort: a profile without the hook, no curated
    files, or a parse error yields an empty map (a silent no-op).
    """
    repo_root = getattr(config, "repo_root", None)
    if repo_root is None:
        return {}
    curated_records = getattr(profile, "curated_records", None)
    if curated_records is None:
        return {}
    try:
        records = curated_records(repo_root)
    except Exception:  # noqa: BLE001 - a broken enricher must not crash reconcile
        return {}

    out: dict[str, tuple[str | None, str | None]] = {}
    for rec in records:
        name = getattr(rec, "name", None)
        if not name:
            continue
        canonical = resolver.canonical(name)
        out[canonical] = (
            getattr(rec, "license", None),
            getattr(rec, "copyright", None),
        )
    return out


def _flag_version_mismatches(components: list[Component]) -> list[Warning]:
    """Emit a ``patched_build`` warning where source != effective version."""
    warnings: list[Warning] = []
    for comp in components:
        src = comp.source_version
        eff = comp.effective_version
        if src is not None and eff is not None and src != eff:
            warnings.append(
                Warning(
                    code="patched_build",
                    subject=comp.name,
                    detail=f"source_version {src} != effective_version {eff}",
                )
            )
    return warnings


def _concrete_pin(constraint: str | None) -> str | None:
    """Return the exact pin a Python ``version_constraint`` names, else ``None``.

    Delegates to the collector's packaging-faithful :func:`concrete_version`
    (one ``==``/``===`` clause, no wildcard) so reconcile and the collector agree
    on what counts as a concrete pin. A non-parseable or empty constraint is not
    a pin.
    """
    if not constraint:
        return None
    try:
        from packaging.specifiers import InvalidSpecifier, SpecifierSet

        from .collectors.python import concrete_version
    except Exception:  # pragma: no cover - packaging is a hard dependency
        return None
    try:
        return concrete_version(SpecifierSet(constraint))
    except InvalidSpecifier:
        return None


def _flag_version_pin_conflicts(components: list[Component]) -> list[Warning]:
    """Resolve conflicting concrete pins across a component's observations.

    All observations of a component are scanned for an EXACT pin (the same
    concrete-version rule the collector uses). When two observations carry
    DIFFERENT concrete pins, one is kept deterministically (the lowest PEP 440
    version, ties broken by string order) and a ``version_pin_conflict`` warning
    is emitted. The kept pin wins over any first-seen ``source_version`` so the
    emitted ``component.version`` matches the resolved pin.
    """
    from packaging.version import InvalidVersion, Version

    warnings: list[Warning] = []
    for comp in components:
        pins = []
        seen: set[str] = set()
        for obs in comp.observations:
            pin = _concrete_pin(getattr(obs, "version_constraint", None))
            if pin is not None and pin not in seen:
                seen.add(pin)
                pins.append(pin)
        if len(pins) < 2:
            continue

        def _key(p: str):
            try:
                return (0, Version(p), p)
            except InvalidVersion:
                return (1, Version("0"), p)

        chosen = min(pins, key=_key)
        warnings.append(
            Warning(
                code="version_pin_conflict",
                subject=comp.name,
                detail=(
                    f"conflicting concrete pins {sorted(pins)}; kept {chosen}"
                ),
            )
        )
        # Resolve to the deterministic lowest pin, but ONLY overwrite a version
        # axis that is unset or itself one of the conflicting pins. A curated
        # Notice / cmake value of a DIFFERENT provenance (e.g. protobuf source
        # 25.1, patched-build effective 3.13.0) is authoritative over a
        # requirements.txt pin and must not be clobbered -- doing so would also
        # silence the patched_build mismatch (which needs source != effective).
        # The conflict warning fires regardless.
        if comp.source_version is None or comp.source_version in seen:
            comp.source_version = chosen
        if comp.effective_version is None or comp.effective_version in seen:
            comp.effective_version = chosen
    return warnings


def _flag_unpinned_versions(components: list[Component]) -> None:
    """Mark the version axis ``unpinned`` for any component with no concrete pin.

    The static-mode policy: a component carries a concrete version ONLY when an
    EXACT pin was found (a Python ``==X`` requirement set ``source_version``, or a
    cmake/curated source/effective version). When NONE of a component's
    observations yields a concrete version -- bare/range Python deps (``numpy``,
    ``numpy<2``) and CANN package deps that only carry a ``>=8.5`` constraint --
    ``completeness['version']`` becomes ``'unpinned'``. A component that already
    has a concrete version (eigen 5.0.0, protobuf from the cmake/curated layer)
    is never marked.
    """
    for comp in components:
        if comp.source_version is None and comp.effective_version is None:
            comp.completeness.setdefault("version", "unpinned")


def _has_unexpanded_var(value: str) -> bool:
    """True if ``value`` carries an unexpanded build-variable marker."""
    return "${" in value or "$<" in value or "$(" in value


def _sanitize_unresolved_versions(components: list[Component]) -> None:
    """Null versions/constraints that are unexpanded build-variable templates.

    A version captured statically from a CMake macro can be an unexpanded variable
    -- e.g. cann-cmake's foreach-driven ``set(CPACK_PACKAGE_VERSION
    "${CANN_VERSION_${component}_VERSION}")`` (``prepare.cmake``) yields the literal
    template, not a version. It must never be emitted as a ``version`` /
    ``versionInfo`` / purl ``@version``. Treat it as unknown: clear
    source/effective_version and mark ``completeness['version']='unresolved'``
    (distinct from ``'unpinned'`` -- a value WAS declared, we just cannot resolve
    it statically). Observation ``version_constraint``s carrying an unexpanded
    variable are dropped for the same reason. Runs BEFORE
    :func:`_flag_unpinned_versions`, whose ``setdefault`` then leaves the
    ``'unresolved'`` marker intact.
    """
    for comp in components:
        unresolved = False
        if comp.source_version and _has_unexpanded_var(comp.source_version):
            comp.source_version = None
            unresolved = True
        if comp.effective_version and _has_unexpanded_var(comp.effective_version):
            comp.effective_version = None
            unresolved = True
        for obs in comp.observations:
            if obs.version_constraint and _has_unexpanded_var(obs.version_constraint):
                obs.version_constraint = None
        if unresolved:
            comp.completeness["version"] = "unresolved"


# ---------------------------------------------------------------------------
# Dependency edge rollup
# ---------------------------------------------------------------------------


def _derive_depends_on(
    components: list[Component],
    edges: list[DependencyEdge],
    index: dict[str, Component],
    resolver: AliasResolver,
) -> None:
    """Derive ``Component.depends_on`` from component->component edges only.

    Edges remain the authority. A ``subject -> component`` edge is NOT collapsed
    into a component rollup (per-root ownership lives on the edge); only
    ``component -> component`` edges contribute to ``depends_on``.
    """
    for edge in edges:
        if edge.from_ref.kind is not RefKind.COMPONENT:
            continue
        if edge.to_ref.kind is not RefKind.COMPONENT:
            continue
        from_canonical = resolver.canonical(edge.from_ref.id)
        to_canonical = resolver.canonical(edge.to_ref.id)
        comp = index.get(from_canonical) or index.get(edge.from_ref.id)
        if comp is None:
            continue
        _union_extend(comp.depends_on, [to_canonical])


def _canonicalize_edges(
    edges: list[DependencyEdge], resolver: AliasResolver
) -> None:
    """Rewrite component endpoint ids to their canonical spelling in place.

    Subject endpoints (``RefKind.SUBJECT``) are left untouched; only component
    endpoints are alias-normalized so an edge to ``OPBASE`` and one to ``opbase``
    point at the same canonical component. ``root_artifact_id`` is preserved."""
    for edge in edges:
        if edge.from_ref.kind is RefKind.COMPONENT:
            edge.from_ref.id = resolver.canonical(edge.from_ref.id)
        if edge.to_ref.kind is RefKind.COMPONENT:
            edge.to_ref.id = resolver.canonical(edge.to_ref.id)


def _dedup_edges(edges: list[DependencyEdge]) -> list[DependencyEdge]:
    """Drop self-loops and EXACT-duplicate edges, preserving first-seen order.

    Uses :func:`sbom.graph.exact_edge_key` (semantic key PLUS provenance), so two
    distinct evidence sites for the same relationship survive while a truly
    byte-identical edge — produced by alias canonicalization mapping several raw
    spellings onto one pair, or a component declared through multiple equivalent
    build targets in one ``.cmake`` — collapses to one."""
    return graph.dedup_edges(edges, key=graph.exact_edge_key)


# ---------------------------------------------------------------------------
# Layered license resolver
# ---------------------------------------------------------------------------


def _load_known_license_map(profile: Profile | None = None) -> dict[str, str]:
    """Load the known-license map: generic-core default + profile override.

    Every ``known-licenses`` :class:`~sbom.data_sources.DataSource` is merged in
    precedence order (core first, profile last) so a profile entry overrides a
    generic one. Tolerates a missing enrich module / data file (a vendored map is
    an optimization, never a hard input).
    """
    try:
        from .data_sources import build_data_sources, sources_named
        from .enrich import known_licenses
    except Exception:  # noqa: BLE001 - registry/enricher unavailable -> core fallback
        return _core_known_map_fallback()

    # The registry result is authoritative: merge every source in precedence order
    # (core first, profile last). A source that EXISTS but fails to load is skipped
    # AND logged (never silently dropping a profile override); the loop result is
    # returned even if empty rather than masking it with a core-only re-read.
    merged: dict[str, str] = {}
    for source in sources_named(build_data_sources(profile), "known-licenses"):
        try:
            merged.update(known_licenses.load_map(source.path))
        except Exception:  # noqa: BLE001
            logger.warning("known-licenses source failed to load: %s", source.path)
    return merged


def _core_known_map_fallback() -> dict[str, str]:
    """Read the core known-license map directly (used only when the data-source
    registry / enricher is unavailable)."""
    try:
        import yaml  # type: ignore
        from importlib import resources

        text = (resources.files("sbom.data") / "known_licenses.yaml").read_text()
        loaded = yaml.safe_load(text) or {}
        return {str(k).lower(): str(v) for k, v in loaded.items()}
    except Exception:  # noqa: BLE001
        return {}


def _apply_depsdev_cache(
    components: list[Component], config: "Config | None", profile: Profile
) -> list[Warning]:
    """Apply the vendored depsdev cache as a license layer (offline + on).

    Merges every ``depsdev`` source (core default + profile override) plus
    an explicit ``config.depsdev_cache`` path (highest precedence), then fills
    still-unresolved Python licenses. Always safe to call: an empty/missing cache
    is a no-op."""
    try:
        from .data_sources import build_data_sources, sources_named
        from .enrich import depsdev_cache
    except Exception:  # noqa: BLE001
        return []
    paths = [s.path for s in sources_named(build_data_sources(profile), "depsdev")]
    override = getattr(config, "depsdev_cache", None) if config is not None else None
    if override:
        paths.append(override)  # depsdev_cache.load() coerces to Path
    return depsdev_cache.apply(components, depsdev_cache.load(paths))


def _apply_deps_dir_cache(components: list[Component], profile: Profile) -> list[Warning]:
    """Apply the vendored deps-dir source cache (license + copyright) as an OFFLINE
    layer (the seeded, committed counterpart of the live ``--deps-dir`` resolver).

    Merges every ``deps-dir`` source (core default + profile override) and fills
    still-unset license/copyright. Always safe to call: an empty/missing cache is a
    no-op."""
    try:
        from .data_sources import build_data_sources, sources_named
        from .enrich import deps_dir_cache
    except Exception:  # noqa: BLE001
        return []
    paths = [s.path for s in sources_named(build_data_sources(profile), "deps-dir")]
    return deps_dir_cache.apply(components, deps_dir_cache.load(paths))


def _apply_clearlydefined(
    components: list[Component], config: "Config | None", profile: Profile
) -> list[Warning]:
    """Apply the vendored ClearlyDefined snapshot (supplier + copyright) as a layer.

    Always safe to call (offline + online); an empty/missing cache is a no-op. Fills
    third-party supplier/copyright the profile/license layers did not."""
    try:
        from .data_sources import build_data_sources, sources_named
        from .enrich import clearlydefined
    except Exception:  # noqa: BLE001
        return []
    paths = [s.path for s in sources_named(build_data_sources(profile), "clearlydefined")]
    # The curated upstream coordinates let CD match C++ third-party (keyed by git
    # host/org/name), not just PyPI.
    purl_map = _load_third_party_purls(profile)
    return clearlydefined.apply(components, clearlydefined.load(paths), purl_map)


def _warn_unverified_direct_urls(components: list[Component]) -> list[Warning]:
    """Flag a Python component that is a direct-URL requirement on an UNRECOGNIZED
    host (e.g. ``name @ https://vendor.example/name-1.0.whl``).

    Such a component is still given a ``pkg:pypi/<name>`` identity + PyPI enrichment
    (the wheel URL names the project), but on an unverified host that name could
    collide with an unrelated PyPI project. The warning makes the name-match
    explicit so a general-repo consumer can verify it — a wheel on a recognized
    index (pythonhosted / pytorch) is trusted silently."""
    warnings: list[Warning] = []
    for comp in components:
        url = python_unverified_direct_url(comp)
        if url:
            warnings.append(
                Warning(
                    code="python_direct_url_unverified_host",
                    subject=comp.name,
                    detail=(
                        f"{comp.name} is a direct-URL requirement on an unrecognized host "
                        f"({url}); its PyPI identity/license is assumed from the name — "
                        f"verify it is the intended package."
                    ),
                )
            )
    return warnings


def _resolve_licenses(
    components: list[Component],
    config: "Config | None",
    profile: Profile,
    resolver: AliasResolver,
) -> list[Warning]:
    """Run the license layers in precedence order:
    scancode (if enrich) > curated (Notice/List) > known-map > cache > network >
    NOASSERTION. Copyright follows: scancode > curated-Notice > none.

    Each layer records :class:`Provenance`; when the curated layer and the known
    map disagree on a component, BOTH are recorded and a ``license_discrepancy``
    warning is emitted rather than silently picking one. A component with no
    proven license after every layer gets ``NOASSERTION`` and a
    ``license_unresolved`` warning. A component with no concrete license still
    gets the curated Notice's declared license/copyright when present.
    """
    warnings: list[Warning] = []

    # Layer 1: curated repo files (profile-supplied). Highest non-scancode
    # precedence. Two curated sources, both authoritative over the known map:
    #   (a) profile.dependency_license_default(comp) — a profile policy default;
    #   (b) the curated Notice's declared License AND Copyright block (CANN's
    #       Third_Party_..._Notice), resolved via curated_records.
    curated: dict[str, str] = {}
    notice = _curated_license_copyright(config, profile, resolver)
    for comp in components:
        default = profile.dependency_license_default(comp)
        if default is not None:
            curated[comp.name] = default
            comp.license = default
            # Mark it as a profile ASSUMPTION (not verified per-package metadata),
            # so consumers can tell an asserted license from a proven one.
            comp.completeness.setdefault("license", "profile-default")
            comp.provenance.append(
                Provenance(field="license", source="profile.dependency_license_default")
            )

        notice_license, notice_copyright = notice.get(comp.name, (None, None))
        if notice_license is not None and comp.name not in curated:
            curated[comp.name] = notice_license
            comp.license = notice_license
            comp.provenance.append(
                Provenance(field="license", source="curated_notice")
            )
        # Copyright from the curated Notice (scancode may still override later).
        if notice_copyright and comp.copyright is None:
            comp.copyright = notice_copyright
            comp.provenance.append(
                Provenance(field="copyright", source="curated_notice")
            )

    # Layer 2: bundled known-license map (alias-aware lookup); generic-core
    # default merged with the active profile's override.
    known_map = _load_known_license_map(profile)

    def lookup_known(comp: Component) -> str | None:
        for candidate in (comp.name, *comp.aliases):
            for key in (candidate, resolver.canonical(candidate)):
                if key in known_map:
                    return known_map[key]
                if key.lower() in known_map:
                    return known_map[key.lower()]
        return None

    for comp in components:
        known = lookup_known(comp)
        if known is None:
            continue
        if comp.name in curated:
            if curated[comp.name] != known:
                comp.provenance.append(
                    Provenance(field="license", source="known_licenses.yaml")
                )
                warnings.append(
                    Warning(
                        code="license_discrepancy",
                        subject=comp.name,
                        detail=f"curated {curated[comp.name]} != known {known}",
                    )
                )
            continue
        if comp.license is None:
            comp.license = known
            comp.provenance.append(
                Provenance(field="license", source="known_licenses.yaml")
            )

    # Layer 2.5: --deps-dir on-disk REAL source (offline). Resolves each
    # component's source under --deps-dir (plain dir / archive / git mirror with
    # version branches + Readme.opensource manifest), fills license/copyright from
    # it, and yields a source_map the ScanCode layer scans for thorough
    # copyright/license. Placed above cache_scan/depsdev so real-source data wins
    # among the fill layers (curated/known above still win). Fill-only.
    deps_source_map: dict[str, Path] = {}
    deps_cleanups: list = []
    if config is not None and getattr(config, "deps_dir", None):
        from .enrich import deps_dir as deps_dir_mod

        dw, deps_source_map, deps_cleanups = deps_dir_mod.apply(components, config, profile)
        warnings.extend(dw)

    # The vendored deps-dir source cache (the seeded snapshot) runs ALWAYS — it is
    # the offline counterpart that makes real-source C++ licenses available without
    # the --deps-dir tree present. Fill-only, so the live resolution above (when
    # --deps-dir is given) and curated/known layers still win.
    warnings.extend(_apply_deps_dir_cache(components, profile))

    # The deps-dir layer materialized temp extractions (deps_cleanups); the
    # try/finally guarantees they are released even if a layer below raises, so a
    # crash in cache_scan/depsdev/net/scancode can never leak temp dirs.
    try:
        # Layer 3 (cache scan) + Layer 3.5 (vendored depsdev cache) + Layer 4 (live
        # network). The vendored depsdev cache is consulted ALWAYS (offline +
        # online), just above live network so a cached hit avoids a live call.
        if config is not None:
            warnings.extend(_run_optional_enricher("cache_scan", components, config))
            warnings.extend(_apply_depsdev_cache(components, config, profile))
            if getattr(config, "network", "off") == "on":
                warnings.extend(_run_optional_enricher("net", components, config))

        # Layer 0: ScanCode enrich/fallback (config-gated, HIGHEST priority for
        # enrich/both). Runs over the already-resolved layers so the displaced prior
        # value can be stashed for crosscheck/both reporting; only a CONFIDENT
        # on-disk detection overrides. 'fallback' is fill-only (no override, no
        # prior stash). The deps-dir source_map supplies on-disk targets even for
        # components with no local observation (the cann-src-third-party mirrors).
        scancode_mode = getattr(config, "scancode", None) if config is not None else None
        if config is not None and scancode_mode in ("enrich", "fallback", "both"):
            warnings.extend(
                _run_scancode_enrich(
                    components,
                    config,
                    source_overrides=deps_source_map,
                    fill_only=(scancode_mode == "fallback"),
                )
            )
    finally:
        # Release the deps-dir temp extractions now the ScanCode layer has read them.
        for _cleanup in deps_cleanups:
            try:
                _cleanup()
            except Exception:  # noqa: BLE001 - cleanup must never abort reconcile
                pass

    # Layer 5: NOASSERTION fallback.
    for comp in components:
        if comp.license is None:
            comp.license = "NOASSERTION"
            warnings.append(
                Warning(code="license_unresolved", subject=comp.name, detail=None)
            )

    return warnings


def _run_scancode_enrich(
    components: list[Component],
    config: "Config",
    source_overrides: "dict[str, Path] | None" = None,
    fill_only: bool = False,
) -> list[Warning]:
    """ScanCode enrich layer: set ``component.license``/``copyright`` from a
    CONFIDENT ScanCode detection on each component's on-disk target dir.

    ``source_overrides`` (``{component.name: dir}``, from the ``--deps-dir``
    layer) supplies the scan dir for components with no local observation — it
    takes precedence over :func:`sbom.enrich.scancode.target_dir_for`.

    In the default (``enrich``/``both``) mode a confident detection OVERRIDES
    ``.license`` and the displaced prior value is stashed as
    ``Provenance(field='license_prior', …)`` so the crosscheck pass can report
    ``ours=<prior> scancode=<applied>``. In ``fill_only`` mode (``--scancode
    fallback``) the detection FILLS ``.license`` only when still unset and NO
    prior is stashed — curated/known/pre-seed values are never overridden.
    Copyright is always filled only when empty. If ScanCode is unavailable a
    single ``scancode_unavailable`` warning is emitted and the layer is a no-op.
    """
    from .enrich import scancode as sc

    warnings: list[Warning] = []
    runner = sc.ScancodeRunner(getattr(config, "scancode_path", None))
    if not runner.available():
        warnings.append(
            Warning(
                code="scancode_unavailable",
                subject=None,
                detail=(
                    f"{runner.unavailable_detail}; skipped scancode "
                    f"{'fallback' if fill_only else 'enrich'}, kept the normal resolver"
                ),
            )
        )
        return warnings

    # Map each component to its on-disk target dir; scan the unique dirs once.
    # A deps-dir override wins; otherwise an observation path is resolved against
    # config.repo_root so the scan hits the real source tree, not the process CWD.
    overrides = source_overrides or {}
    repo_root = getattr(config, "repo_root", None)
    targets: list[tuple[Component, Path]] = []
    for comp in components:
        target = overrides.get(comp.name) or sc.target_dir_for(comp, repo_root)
        if target is not None:
            targets.append((comp, target))

    if not targets:
        return warnings

    unique_dirs = list(dict.fromkeys(t for _, t in targets))
    scanned = runner.scan_paths(unique_dirs, timeout=sc.DEFAULT_TIMEOUT)

    for comp, target in targets:
        result = scanned.get(target)
        if result is None:
            warnings.append(
                Warning(
                    code="scancode_scan_failed",
                    subject=comp.name,
                    detail=f"scancode could not scan {target}",
                )
            )
            continue
        # License and copyright are applied INDEPENDENTLY: a confident license
        # overrides (or fills) .license; a detected copyright fills .copyright when
        # empty — so a target with a copyright but NO confident license
        # (NOASSERTION) still gets its copyright (e.g. pyasc: Huawei copyright,
        # license unknown).
        if result.spdx_license_expression is not None:
            if fill_only:
                if comp.license is None:
                    comp.license = result.spdx_license_expression
                    comp.provenance.append(Provenance(field="license", source="scancode"))
            else:
                prior = comp.license  # may be None (NOASSERTION not yet applied)
                comp.provenance.append(
                    Provenance(field="license_prior", source=prior if prior is not None else "NOASSERTION")
                )
                comp.license = result.spdx_license_expression
                comp.provenance.append(Provenance(field="license", source="scancode"))

        copyright_summary = result.copyright_summary()
        if copyright_summary and comp.copyright is None:
            comp.copyright = copyright_summary
            comp.provenance.append(Provenance(field="copyright", source="scancode"))

    return warnings


def _run_scancode_enrich_subjects(
    subjects: list["Subject"], config: "Config", fill_only: bool = False
) -> list[Warning]:
    """ScanCode enrich layer for subjects (the subject counterpart of
    :func:`_run_scancode_enrich`).

    A confident on-disk detection sets ``subject.license`` (and
    ``subject.license_text`` when a non-SPDX ``LicenseRef-…`` is synthesized),
    stashing the displaced prior value as ``__scancode_prior_license__`` in a
    transient attribute the crosscheck pass reads. In ``fill_only`` mode
    (``--scancode fallback``) it sets ``.license`` only when still unset and does
    NOT stash a prior. Subjects without a usable ScanCode binary emit one
    ``scancode_unavailable`` warning and the layer is a no-op."""
    from .enrich import scancode as sc

    warnings: list[Warning] = []
    if not subjects:
        return warnings

    runner = sc.ScancodeRunner(getattr(config, "scancode_path", None))
    if not runner.available():
        warnings.append(
            Warning(
                code="scancode_unavailable",
                subject=None,
                detail=f"{runner.unavailable_detail}; skipped scancode subject enrich",
            )
        )
        return warnings

    repo_root = getattr(config, "repo_root", None)
    targets: dict[str, Path] = {}
    by_id: dict[str, "Subject"] = {}
    for subject in subjects:
        target = sc.target_dir_for(subject, repo_root)
        if target is not None:
            targets[subject.id] = target
            by_id[subject.id] = subject

    if not targets:
        return warnings

    unique_dirs = list(dict.fromkeys(targets.values()))
    scanned = runner.scan_paths(unique_dirs, timeout=sc.DEFAULT_TIMEOUT)

    for sid, target in targets.items():
        subject = by_id[sid]
        result = scanned.get(target)
        if result is None:
            # Parity with the component enrich path: a scan that returned no
            # result (timeout / non-zero exit / malformed JSON) is surfaced, not
            # silently swallowed.
            warnings.append(
                Warning(
                    code="scancode_scan_failed",
                    subject=subject.identity.name,
                    detail=f"scancode could not scan {target}",
                )
            )
            continue
        # License and copyright are applied INDEPENDENTLY: a confident license
        # sets .license; a detected copyright fills .copyright when empty — so a
        # subject with a copyright but NO confident license (NOASSERTION) still
        # gets its copyright (e.g. pyasc: Huawei copyright, license unknown).
        if result.spdx_license_expression is not None:
            if fill_only:
                if subject.license is None:
                    subject.license = result.spdx_license_expression
                    if result.license_text is not None:
                        subject.license_text = result.license_text
            else:
                prior = subject.license
                subject.license = result.spdx_license_expression
                if result.license_text is not None:
                    subject.license_text = result.license_text
                # Stash the displaced prior value for the crosscheck pass.
                setattr(subject, "__scancode_prior_license__", prior)

        copyright_summary = result.copyright_summary()
        if copyright_summary and subject.copyright is None:
            subject.copyright = copyright_summary

    return warnings


def _resolve_subject_licenses(
    subjects: list["Subject"], profile: Profile
) -> None:
    """Apply the profile's subject license default to repo-owned subjects.

    A repo-owned subject whose ``license`` is still unset after the scancode
    enrich pass gets ``profile.subject_license_default(subject)`` (CANN returns
    ``LicenseRef-CANN-Open-Software-License-2.0`` for its distributable roles).
    A non-SPDX ``LicenseRef-…`` default is paired with inline text via
    :func:`sbom.enrich.licenseref.synthesize` so the emitters can satisfy the
    SPDX/CycloneDX validators. Precedence: scancode (if enrich) >
    profile.subject_license_default > NOASSERTION — so a license already set by
    scancode enrich is never overridden.
    """
    from .enrich.licenseref import is_spdx_expression, synthesize

    subject_default = getattr(profile, "subject_license_default", None)
    if subject_default is None:
        return

    for subject in subjects:
        if subject.license is not None:
            continue
        default = subject_default(subject)
        if default is None:
            continue
        subject.license = default
        # A non-SPDX LicenseRef-… needs inline text for valid SPDX/CycloneDX.
        if not is_spdx_expression(default) or default.startswith("LicenseRef-"):
            if subject.license_text is None:
                _ref_id, text = synthesize(default, default)
                subject.license_text = text


def _run_optional_enricher(
    module_name: str, components: list[Component], config: "Config"
) -> list[Warning]:
    """Call ``sbom.enrich.<module_name>.apply`` if present; else no-op."""
    try:
        from importlib import import_module

        module = import_module(f".enrich.{module_name}", package="sbom")
    except Exception:  # noqa: BLE001 - enricher not implemented yet
        return []
    apply = getattr(module, "apply", None)
    if apply is None:
        return []
    try:
        result = apply(components, config)
    except Exception as exc:  # noqa: BLE001 - an optional enricher (esp. one that
        # parses an untrusted network/scancode response) must never abort SBOM
        # generation; degrade to a warning and keep the already-resolved licenses.
        return [
            Warning(
                code=f"{module_name}_enricher_failed",
                subject=None,
                detail=f"{module_name} enricher raised {type(exc).__name__}: {exc}",
            )
        ]
    return list(result) if result else []


# ---------------------------------------------------------------------------
# Post-assembly Document transform (config-driven filters)
# ---------------------------------------------------------------------------


def _apply_usage_scope_exclusion(
    document: Document,
    excluded: set[UsageScope],
    keep_only: set[UsageScope] | None = None,
) -> None:
    """Filter the Document by usage scope along two composable axes (in place).

    Two independent filters are applied to every :class:`~sbom.models.Observation`
    and :class:`~sbom.models.DependencyEdge` (by the time this runs every
    observation lives on its component, so there is no separate unattached list):

    * ``excluded`` — the EXCLUSION axis (from explicit ``--exclude-scope`` tokens
      and the release preset's non-runtime base): a record is dropped when its
      ``usage_scope`` is in this set. ``usage_scope is None`` is NEVER excluded by
      this axis (an unflagged record survives an explicit user exclusion).
    * ``keep_only`` — the optional KEEP-ONLY axis (the release preset's
      runtime-only constraint, ``{RUNTIME}``): when not ``None`` a record survives
      IFF its ``usage_scope`` is in this set, so ``usage_scope is None`` and every
      scope outside the set are dropped.

    A record is dropped when ``(usage_scope in excluded)`` OR
    ``(keep_only is not None AND usage_scope not in keep_only)``. Components left
    with zero observations are removed; ``Component.scopes`` is recomputed from
    the survivors; edges to/from a dropped component are dropped too. Emits one
    ``excluded_scope`` Warning summarising the counts.
    """
    if not excluded and keep_only is None:
        return

    def _scope_drops(scope: UsageScope | None) -> bool:
        if scope in excluded:
            return True
        if keep_only is not None and scope not in keep_only:
            return True
        return False

    dropped_obs = 0
    surviving_components: list[Component] = []
    dropped_component_names: set[str] = set()

    for comp in document.components:
        kept_obs = [o for o in comp.observations if not _scope_drops(o.usage_scope)]
        dropped_obs += len(comp.observations) - len(kept_obs)
        comp.observations = kept_obs
        if not kept_obs:
            dropped_component_names.add(comp.name)
            continue
        # Recompute the unioned scope summary from the surviving observations.
        comp.scopes = []
        for obs in kept_obs:
            if obs.usage_scope is not None and obs.usage_scope not in comp.scopes:
                comp.scopes.append(obs.usage_scope)
        surviving_components.append(comp)

    document.components = surviving_components

    # Prune stale depends_on rollups: a survivor must not keep a dependency on a
    # component the filter just dropped (a dangling internal reference).
    if dropped_component_names:
        for comp in surviving_components:
            comp.depends_on = [
                d for d in comp.depends_on if d not in dropped_component_names
            ]

    def _edge_drops(edge: DependencyEdge) -> bool:
        if _scope_drops(edge.usage_scope):
            return True
        if (
            edge.from_ref.kind is RefKind.COMPONENT
            and edge.from_ref.id in dropped_component_names
        ):
            return True
        if (
            edge.to_ref.kind is RefKind.COMPONENT
            and edge.to_ref.id in dropped_component_names
        ):
            return True
        return False

    kept_edges = [e for e in document.edges if not _edge_drops(e)]
    dropped_edges = len(document.edges) - len(kept_edges)
    document.edges = kept_edges

    if keep_only is not None:
        axis = "keep-only [" + ", ".join(sorted(s.value for s in keep_only)) + "]"
        if excluded:
            axis += " + exclude [" + ", ".join(sorted(s.value for s in excluded)) + "]"
    else:
        axis = "exclude [" + ", ".join(sorted(s.value for s in excluded)) + "]"
    document.warnings.append(
        Warning(
            code="excluded_scope",
            subject=None,
            detail=(
                f"usage-scope filter {axis} dropped "
                f"{dropped_obs} observation(s), "
                f"{len(dropped_component_names)} component(s), "
                f"{dropped_edges} edge(s)"
            ),
        )
    )


#: Lower number = preferred as the emitted root when the primary is dropped.
_ROLE_PRIORITY: dict[SubjectRole, int] = {
    SubjectRole.PRIMARY: 0,
    SubjectRole.SIBLING_ARTIFACT: 1,
    SubjectRole.CMAKE_PROJECT: 2,
    SubjectRole.UNCLASSIFIED: 3,
    SubjectRole.EXAMPLE: 4,
    SubjectRole.MANUAL_EXAMPLE: 5,
    SubjectRole.ST_TEST: 6,
    SubjectRole.EXPERIMENTAL: 7,
    SubjectRole.NON_DISTRIBUTABLE_TEST: 8,
}


def _apply_subjects_closure(document: Document, wanted_ids: list[str]) -> None:
    """Restrict the Document to ``wanted_ids`` + their dependency closure.

    Keeps only the named subjects (matched by ``Subject.id``, falling back to
    ``identity.name``); BFS over the dependency edges from those subjects keeps
    the reachable component set; edges among kept nodes survive; environment
    tools survive when their ``root_artifact_id`` belongs to a kept subject. If
    the document's primary subject is dropped, the lowest-role kept subject is
    promoted to the emitted root so ``metadata.component`` stays valid.
    """
    wanted = set(wanted_ids)
    kept_subjects = [
        s for s in document.subjects if s.id in wanted or s.identity.name in wanted
    ]
    kept_subject_ids = {s.id for s in kept_subjects}

    # Dependency closure: components reachable from the kept subjects (shared with
    # the emit --split closure via sbom.graph, so both compute the same set).
    reachable_components = graph.reachable_components(
        document.edges, [s.id for s in kept_subjects]
    )

    document.components = [
        c for c in document.components if c.name in reachable_components
    ]
    # Prune depends_on to the reachable set so no survivor dangles to a dropped one.
    for comp in document.components:
        comp.depends_on = [d for d in comp.depends_on if d in reachable_components]

    def _node_kept(kind: RefKind, ident: str) -> bool:
        if kind is RefKind.SUBJECT:
            return ident in kept_subject_ids
        return ident in reachable_components

    document.edges = [
        e
        for e in document.edges
        if _node_kept(e.from_ref.kind, e.from_ref.id)
        and _node_kept(e.to_ref.kind, e.to_ref.id)
    ]

    document.environment_tools = [
        t
        for t in document.environment_tools
        if t.root_artifact_id is None or t.root_artifact_id in kept_subject_ids
    ]

    # Ensure a valid emitted root: if no kept subject is PRIMARY, promote the
    # lowest-role kept subject (preferring emittable ones) to the front.
    if kept_subjects and not any(
        s.role is SubjectRole.PRIMARY for s in kept_subjects
    ):
        def _root_key(subj: "Subject") -> tuple:
            return (
                0 if subj.emit_as_subject else 1,
                _ROLE_PRIORITY.get(subj.role, 99),
            )

        root = min(kept_subjects, key=_root_key)
        root.emit_as_subject = True
        kept_subjects = [root] + [s for s in kept_subjects if s is not root]

    document.subjects = kept_subjects


def _transform_document(document: Document, config: "Config | None") -> Document:
    """Apply the config-driven filters to the assembled Document (in place).

    Ordering: usage-scope exclusion first (FEATURE 1), then the ``--subjects``
    dependency-closure filter (FEATURE 2), then environment-tool omission
    (FEATURE 3). Reconcile remains the only Document producer; this runs at its
    tail so collectors/emitters are untouched.

    The ``release`` scope preset (the default) expands ADDITIVELY into these same
    inputs: ``excluded_usage_scopes(config)`` folds in the preset's non-runtime
    exclusion base AND any explicit ``--exclude-scope`` token, while
    ``release_keep_usage_scopes(config)`` adds the runtime-only KEEP-ONLY axis (so
    unclassified ``usage_scope=None`` records are dropped under release too). The
    env-tool omission ORs the preset with the explicit ``--no-env-tools`` flag.
    ``--scope all`` contributes neither axis, so the only filtering is whatever
    the user requested explicitly.
    """
    if config is None:
        return document

    from .config import (
        excluded_usage_scopes,
        release_keep_usage_scopes,
        release_no_env_tools,
    )

    excluded = excluded_usage_scopes(config)
    keep_only = release_keep_usage_scopes(config)
    if excluded or keep_only is not None:
        _apply_usage_scope_exclusion(document, excluded, keep_only)

    wanted = getattr(config, "subjects", None)
    if wanted:
        _apply_subjects_closure(document, wanted)

    if getattr(config, "no_env_tools", False) or release_no_env_tools(config):
        document.environment_tools = []

    return document


# ---------------------------------------------------------------------------
# Supply-chain provenance classification
# ---------------------------------------------------------------------------

#: A real ``scheme://`` URL prefix (mirrors ``emit._common.is_emittable_url`` without
#: importing the emit layer -- reconcile must not depend on the emitters).
_URL_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def _has_upstream_download(component: Component) -> bool:
    """True if any observation carries a real upstream download URL.

    A genuine ``scheme://`` URL (not a local path, and not an unexpanded
    ``${...}``/``$<...>``/``$(...)`` build template, which we cannot resolve
    statically) is evidence the component was FETCHED from an external source ->
    third-party. Mirrors ``emit._common.is_emittable_url``."""
    for obs in component.observations:
        url = getattr(obs, "canonical_url", None)
        if not url or "${" in url or "$<" in url or "$(" in url:
            continue
        if _URL_SCHEME.match(url):
            return True
    return False


#: SPDX expression operators to skip when scanning license tokens.
_LICENSE_OPERATORS = {"AND", "OR", "WITH"}


def _has_concrete_oss_license(component: Component) -> bool:
    """True if the component's license carries a concrete real SPDX id.

    A resolved OSS license that is neither ``NOASSERTION`` nor a ``LicenseRef-*``
    placeholder (CANN-internal libs use ``LicenseRef-CANN-...``) is strong evidence
    of a published third-party component even when no download URL was captured --
    e.g. ``boost`` is fetched as INTERFACE link targets with no tarball token, but
    its license resolves to ``BSL-1.0``.

    Scans every token of an SPDX expression (not just the head) so the signal is
    order-independent: ``MIT OR LicenseRef-x`` and ``LicenseRef-x OR MIT`` are both
    third-party because each contains a real OSS id."""
    lic = component.license
    if not lic or lic == "NOASSERTION":
        return False
    for tok in re.split(r"[\s()]+", lic):
        tok = tok.strip().rstrip("+")
        if not tok or tok.upper() in _LICENSE_OPERATORS:
            continue
        if tok != "NOASSERTION" and not tok.startswith("LicenseRef-"):
            return True
    return False


def _classify_component_provenance(components: list[Component], profile: Profile) -> None:
    """Stamp ``Component.origin`` (``first-party`` | ``third-party`` | ``unknown``).

    The profile is authoritative when it recognizes the component as its own
    first-party surface (a repo-internal library or a sibling component from the
    same publishing org). Otherwise the generic third-party signals apply, in any
    combination:
    a published Python package, a real upstream download URL, or a concrete OSS
    license id the profile did not claim. Anything left (a raw link lib no profile
    claims, with no URL and only ``NOASSERTION``) stays ``unknown`` -- an honest
    "origin unproven" rather than a guess."""
    hook = getattr(profile, "component_provenance", None)
    for comp in components:
        declared = hook(comp) if callable(hook) else None
        if declared:
            comp.origin = declared
        elif (
            "Python" in comp.languages
            or _has_upstream_download(comp)
            or _has_concrete_oss_license(comp)
        ):
            comp.origin = "third-party"
        else:
            comp.origin = "unknown"


def _first_download_url(component: Component) -> str | None:
    """The first real ``scheme://`` upstream URL on a component (no template), else
    None — the download_url qualifier for a mirror-fetched third-party."""
    for obs in component.observations:
        url = getattr(obs, "canonical_url", None)
        if not url or "${" in url or "$<" in url or "$(" in url:
            continue
        if _URL_SCHEME.match(url):
            return url
    return None


def _load_third_party_purls(profile: Profile) -> dict[str, str]:
    """Load the curated ``name -> upstream PURL coordinate`` map (profile data)."""
    out: dict[str, str] = {}
    try:
        import yaml  # type: ignore

        from .data_sources import build_data_sources, sources_named

        for source in sources_named(build_data_sources(profile), "third-party-purls"):
            try:
                raw = yaml.safe_load(source.path.read_text(encoding="utf-8")) or {}
            except Exception:  # noqa: BLE001
                continue
            if isinstance(raw, dict):
                for name, coord in raw.items():
                    if coord:
                        out[str(name).lower()] = str(coord)
    except Exception:  # noqa: BLE001
        pass
    return out


def _resolve_component_purls(
    components: list[Component], subjects: list, profile: Profile
) -> None:
    """Stamp ``Component.purl`` for NON-Python components, most-specific first:

    1. a curated upstream coordinate (``pkg:github/...``) + version — the true
       upstream identity for well-known OSS fetched from a mirror;
    2. a real download URL -> ``pkg:generic/<name>@<v>?download_url=…[&checksum=…]``;
    3. a ``first-party`` component -> ``pkg:generic/<name>?vcs_url=<repo origin>``.

    Otherwise left ``None`` (system/unknown — the name is the NTIA look-up key).
    Python components keep their ``pkg:pypi`` purl derived at emit."""
    from packageurl import PackageURL

    curated = _load_third_party_purls(profile)
    repo_vcs = next(
        (s.vcs_url for s in subjects if getattr(s, "vcs_url", None)), None
    )
    for comp in components:
        if "Python" in (comp.languages or []):
            continue
        version = comp.effective_version or comp.source_version

        coord = None
        for name in (comp.name, *comp.aliases):
            coord = curated.get(name.lower())
            if coord:
                break
        if coord:
            try:
                base = PackageURL.from_string(coord)
                comp.purl = PackageURL(
                    type=base.type,
                    namespace=base.namespace,
                    name=base.name,
                    version=version,
                ).to_string()
                # The curated upstream coordinate's org (namespace) is a clean NTIA
                # Supplier for a C++ third-party (protobuf -> protocolbuffers,
                # eigen -> libeigen) — fill it when nothing better was found.
                if comp.supplier is None and base.namespace:
                    comp.supplier = base.namespace
                    comp.provenance.append(
                        Provenance(field="supplier", source="upstream-purl")
                    )
                continue
            except Exception:  # noqa: BLE001 - a malformed curated coordinate is skipped
                pass

        url = _first_download_url(comp)
        if url:
            qualifiers = {"download_url": url}
            sha = comp.checksums.get("sha256") if comp.checksums else None
            if sha:
                qualifiers["checksum"] = f"sha256:{sha}"
            comp.purl = PackageURL(
                type="generic", name=comp.name, version=version, qualifiers=qualifiers
            ).to_string()
            continue

        if comp.origin == "first-party" and repo_vcs and _URL_SCHEME.match(repo_vcs):
            comp.purl = PackageURL(
                type="generic",
                name=comp.name,
                version=version,
                qualifiers={"vcs_url": repo_vcs},
            ).to_string()


def _resolve_suppliers(
    components: list[Component], subjects: list, profile: Profile
) -> None:
    """Set the NTIA Supplier element for FIRST-PARTY artifacts from the profile.

    Repo-owned subjects and ``first-party`` components get
    ``profile.first_party_supplier()`` (the publishing org). This is
    AUTHORITATIVE: it OVERWRITES any third-party guess an earlier enricher
    (depsdev PyPI author / ClearlyDefined) may have set on a first-party
    component that happens to be a published package, so a CANN-internal package on
    PyPI is the org, not a coincidental upstream author. Third-party / unknown
    components keep their enricher-supplied supplier. Runs after provenance."""
    hook = getattr(profile, "first_party_supplier", None)
    org = hook() if callable(hook) else None
    if not org:
        return
    for subject in subjects:
        subject.supplier = org  # repo-owned -> authoritative
    for comp in components:
        if comp.origin == "first-party":
            comp.supplier = org  # authoritative over any third-party guess


# ---------------------------------------------------------------------------
# Top-level reconcile
# ---------------------------------------------------------------------------


def reconcile(
    results: list["CollectResult"],
    subjects: list["Subject"],
    config: "Config | None",
    profile: Profile,
) -> Document:
    """Merge all collector outputs into a single :class:`Document`.

    This is the only function that produces a ``Document``.
    """
    all_components: list[Component] = []
    all_observations: list = []
    all_edges: list[DependencyEdge] = []
    environment_tools: list = []
    warnings: list[Warning] = []

    for result in results:
        all_components.extend(result.components)
        all_observations.extend(result.observations)
        all_edges.extend(result.edges)
        environment_tools.extend(result.environment_tools)
        warnings.extend(result.warnings)

    # The resolver is built AFTER components are gathered so on-the-fly derivation
    # can read their download URLs, and with config so [aliases] overrides apply.
    resolver = build_alias_resolver(profile, config, all_components)
    for upstream in _derive_alias_collisions(all_components):
        warnings.append(
            Warning(
                code="derived_alias_collision",
                subject=upstream,
                detail=(
                    "distinct components derive the same upstream name from "
                    "different URLs; left un-merged (add an explicit [aliases] "
                    "entry to disambiguate)"
                ),
            )
        )

    ordered, index = _dedup_components(all_components, resolver)
    warnings.extend(_attach_observations(all_observations, index, resolver, ordered))

    _canonicalize_edges(all_edges, resolver)
    all_edges = _dedup_edges(all_edges)
    _derive_depends_on(ordered, all_edges, index, resolver)

    _apply_curated_records(ordered, config, profile, resolver)
    warnings.extend(_flag_version_pin_conflicts(ordered))
    warnings.extend(_flag_version_mismatches(ordered))
    _sanitize_unresolved_versions(ordered)
    _flag_unpinned_versions(ordered)
    warnings.extend(_resolve_licenses(ordered, config, profile, resolver))
    warnings.extend(_warn_unverified_direct_urls(ordered))

    # Provenance is classified AFTER licenses/aliases settle so the profile matches
    # on the final canonical name + aliases, and after observations are attached so
    # the upstream-URL signal is in scope.
    _classify_component_provenance(ordered, profile)

    # NTIA Supplier precedence: first-party (profile) is AUTHORITATIVE; third-party
    # supplier comes from the depsdev cache (PyPI author, applied in the license
    # layer above) then ClearlyDefined (git-org + copyright). _resolve_suppliers
    # runs LAST and overwrites first-party components/subjects, so an enricher guess
    # on a first-party package never wins.
    warnings.extend(_apply_clearlydefined(ordered, config, profile))
    _resolve_suppliers(ordered, subjects, profile)

    # ScanCode enrich for subjects (config-gated). Components are enriched inside
    # _resolve_licenses (the license layer); subjects carry their own
    # license/license_text and always have a local source_path, so they are
    # enriched here where the subject list is in scope.
    subject_scancode_mode = getattr(config, "scancode", None) if config is not None else None
    if subject_scancode_mode in ("enrich", "fallback", "both"):
        warnings.extend(
            _run_scancode_enrich_subjects(
                list(subjects), config, fill_only=(subject_scancode_mode == "fallback")
            )
        )

    # Profile subject-license default: a repo-owned subject still without a
    # license (scancode did not set one) gets profile.subject_license_default().
    # Precedence: scancode (if enrich) > profile default > NOASSERTION.
    _resolve_subject_licenses(list(subjects), profile)

    # Stamp the repo VCS origin (homepage / vcs_url / revision) onto every
    # subject: --repo-url > profile.repo_origin() > .git/config auto-detect.
    apply_repo_origin(subjects, config, profile)

    # Resolve a PURL for non-Python components (needs the repo origin just stamped
    # on subjects for the first-party vcs_url fallback).
    _resolve_component_purls(ordered, subjects, profile)

    document = Document(
        subjects=list(subjects),
        components=ordered,
        edges=all_edges,
        environment_tools=environment_tools,
        warnings=warnings,
        metadata={},
    )

    # The config-driven filters (usage-scope exclusion, --subjects closure,
    # --no-env-tools) run at the tail so reconcile stays the only Document
    # producer and collectors/emitters need no changes.
    return _transform_document(document, config)


__all__ = [
    "AliasResolver",
    "build_alias_resolver",
    "reconcile",
    "OSS_ALIASES",
]
