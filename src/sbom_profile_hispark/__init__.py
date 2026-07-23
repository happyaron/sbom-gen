"""HiSpark repo profile plugin.

Registered via the ``sbom.profiles`` entry point as
``hispark = "sbom_profile_hispark:HisparkProfile"`` (see ``pyproject.toml``).

HiSpark is HiSilicon's open developer-board / wearable / IoT solution family
(``gitcode.com/HiSpark/<repo>`` — e.g. ``hs-fbb``, ``fbb_ws63``,
``hi_aiot_solution``, ``Hi3516CV610``). The repos are OpenHarmony/LiteOS-based
C/C++ firmware trees that VENDOR their third-party open source as source
subtrees under ``open_source/`` and ``third_party/`` roots, rather than fetching
them through a CMake dependency macro the generic collector understands.

:class:`HisparkProfile` therefore surfaces those bundled components from the
**actual on-disk tree** (:meth:`package_metadata`) and resolves each one's
license from its **own embedded ``LICENSE``/``COPYING`` file** where present
(:meth:`curated_records`, reusing the generic ``sbom.enrich.cache_scan``
heuristics), falling back to a curated *upstream-truth* known-license map
(:meth:`data_sources`) for well-known components that ship no license file.

The repo's aggregate ``LICENSE.OpenSource`` / ``COPYRIGHT.OpenSource`` manifests
are deliberately **NOT** a generation input — a hand-maintained manifest can
drift from what the tree actually contains. They are used only to VERIFY the
generated SBOM (:meth:`crosscheck_manifest`), never to produce it.

Design notes:

* CMake parsing / license scanning is NOT reimplemented here — the generic
  ``sbom.cmake.parse`` and ``sbom.enrich.cache_scan`` helpers are reused.
* The generic core must never import this module except through the entry-point
  registry (:func:`sbom.profile.load_profiles`).
* Nothing in this module touches the CANN profile or the generic core, so it
  cannot regress either.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from sbom.data_sources import CURATED, DERIVED, DataSource
from sbom.models import (
    CmakeAuthority,
    Component,
    Observation,
    SourceKind,
    Subject,
    SubjectRole,
    UsageScope,
)
from sbom.profile import Profile

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

#: The git host + owner that identify a HiSpark repo. Detection is by VCS origin
#: only (the reliable signal shared by every HiSpark repo); no marker-file scan.
_HISPARK_GIT_HOSTS = frozenset({"gitcode.com"})
_HISPARK_GIT_OWNERS = frozenset({"hispark"})

#: NTIA Supplier for HiSpark's own (first-party) artifacts (from each repo's
#: top-level ``COPYRIGHT`` file).
HISPARK_SUPPLIER = "HiSilicon (Shanghai) Technologies Co., Ltd."

#: Fallback first-party license when a repo's own top-level LICENSE cannot be
#: resolved to an SPDX id (the OpenHarmony/HiSpark norm; overridden per-repo by
#: :meth:`_own_subject_license` scanning the actual LICENSE file).
HISPARK_DEFAULT_SUBJECT_LICENSE = "Apache-2.0"


# ---------------------------------------------------------------------------
# Vendored-source discovery (package_metadata / curated_records)
# ---------------------------------------------------------------------------

#: Directory names whose immediate child directories are vendored third-party
#: components.
_VENDOR_ROOT_NAMES = frozenset({"open_source", "third_party"})

#: Child directory names under a vendored root that are build glue / tooling,
#: never a real upstream component.
_SKIP_COMPONENT_NAMES = frozenset({"cmake", "build", "scripts", "prebuilt"})

#: Path segments that mark a vendored root as build glue rather than real
#: vendored source (e.g. ``src/build/cmake/open_source`` holds ``*.cmake``
#: fragments, not component subtrees).
_BUILD_GLUE_SEGMENTS = frozenset({"cmake"})

#: A version embedded in a directory name: ``mbedtls_v3.6.5`` -> ``3.6.5``,
#: ``libogg-1.3.5`` -> ``1.3.5``, ``lzma_25.01`` -> ``25.01``.
_VERSION_RE = re.compile(r"[_\-]v?(\d+(?:\.\d+)+)")
#: The version tail stripped to recover a subdir's name stem (used to confirm a
#: version subdir belongs to its parent component, not a nested sub-library).
_VERSION_TAIL_RE = re.compile(r"[_\-]?v?\d+(?:\.\d+)+.*$", re.IGNORECASE)

#: License basenames scanned in a component's own tree (reused from cache_scan
#: for the actual detection; this depth cap keeps the walk cheap).
_MAX_SCAN_DEPTH = 2


@dataclass
class VendoredComponent:
    """One third-party component discovered as an on-disk vendored subtree.

    ``name`` is the canonical (lowercased) component name; ``version`` is
    recovered from a version-named source subdirectory when present (else
    ``None`` -> the component is honestly reported unpinned). ``license`` is set
    only when the component's OWN embedded ``LICENSE``/``COPYING`` file resolves
    to an SPDX id (the curated upstream known-license map fills the rest).
    ``rel_path`` is the component dir and ``source_rel_path`` the resolved real
    source dir, both repo-relative (so the ScanCode / deps-dir layers can target
    them against ``config.repo_root``).
    """

    name: str
    version: str | None = None
    effective_version: str | None = None
    license: str | None = None
    copyright: str | None = None
    rel_path: str = ""
    source_rel_path: str = ""


def _canonical_name(dir_name: str) -> str:
    """Canonical component name for a vendored directory basename (lowercased)."""
    return dir_name.strip().lower()


def _extract_version(name: str) -> str | None:
    """Return the version embedded in a directory name, or ``None``."""
    m = _VERSION_RE.search(name)
    return m.group(1) if m else None


def _name_stem(name: str) -> str:
    """Strip a trailing ``[_-]v?<version>...`` tail to recover the name stem."""
    return _VERSION_TAIL_RE.sub("", name).strip("_-").lower()


def _version_subdir_matches(component: str, subdir: str) -> bool:
    """True when a version-named ``subdir`` belongs to ``component``.

    Guards against adopting a nested sub-library's version as the component's
    own — e.g. ``t_cose/QCBOR_v1.2`` must NOT make ``t_cose`` version ``1.2``,
    while ``mbedtls/mbedtls_v3.6.5`` and ``7-zip-lzma-sdk/lzma_25.01`` (shared
    ``lzma`` token) legitimately do.
    """
    stem = _name_stem(subdir)
    comp = component.lower()
    if not stem:
        return True
    return stem in comp or comp in stem


def _resolve_source_and_version(comp_dir: Path) -> tuple[Path, str | None]:
    """Resolve a component dir to its real source dir + version.

    Many HiSpark components nest their real source in a single version-named
    subdirectory (``mbedtls/mbedtls_v3.6.5``); that subdir is the license/source
    root and yields the version. When no owning version subdir exists the
    component dir itself is the source root (version from its own name, else
    ``None``).
    """
    try:
        subdirs = [d for d in comp_dir.iterdir() if d.is_dir()]
    except OSError:
        return comp_dir, _extract_version(comp_dir.name)

    versioned = [
        (d, v)
        for d in subdirs
        if (v := _extract_version(d.name)) is not None
        and _version_subdir_matches(comp_dir.name, d.name)
    ]
    if len(versioned) == 1:
        return versioned[0]
    if len(versioned) > 1:
        # Ambiguous (several versioned source dirs) -> keep the highest, so the
        # emitted version is deterministic rather than iteration-order dependent.
        versioned.sort(key=lambda dv: _version_key(dv[1]))
        return versioned[-1]
    return comp_dir, _extract_version(comp_dir.name)


def _version_key(version: str) -> tuple:
    """Sort key for a dotted version string (numeric where possible)."""
    parts = []
    for token in version.split("."):
        parts.append((0, int(token)) if token.isdigit() else (1, token))
    return tuple(parts)


def _scan_embedded_license(source_dir: Path, comp_dir: Path) -> str | None:
    """Best-effort SPDX id from a component's OWN embedded license files.

    Reuses the generic ``cache_scan`` heuristics (SPDX-License-Identifier
    header, conflict-aware primary-file selection, MulanPSL/BSD/etc.), scanning
    the resolved source dir first, then the component dir, then one level down.
    Returns ``None`` when no license file resolves confidently (honest — the
    curated upstream map then fills it, else NOASSERTION).
    """
    from sbom.enrich.cache_scan import _find_license_files, _pick_license

    for base in _unique_paths(source_dir, comp_dir):
        spdx, _lf = _pick_license(_find_license_files(base))
        if spdx is not None:
            return spdx
    # One level down (some trees put LICENSE under a single source/ or doc/ dir).
    for base in _unique_paths(source_dir, comp_dir):
        try:
            children = [c for c in base.iterdir() if c.is_dir()]
        except OSError:
            continue
        for child in children:
            spdx, _lf = _pick_license(_find_license_files(child))
            if spdx is not None:
                return spdx
    return None


def _unique_paths(*paths: Path) -> list[Path]:
    seen: dict[Path, None] = {}
    for p in paths:
        seen.setdefault(p, None)
    return list(seen)


def _iter_vendor_roots(repo_root: Path):
    """Yield directories named ``open_source``/``third_party`` that hold real
    vendored source (skipping ``.git`` and build-glue ``cmake`` locations)."""
    for path in repo_root.rglob("*"):
        if path.name not in _VENDOR_ROOT_NAMES or not path.is_dir():
            continue
        parts = {p.lower() for p in path.relative_to(repo_root).parts}
        if ".git" in parts:
            continue
        if parts & _BUILD_GLUE_SEGMENTS:
            continue
        yield path


@lru_cache(maxsize=8)
def _discover(repo_root: Path) -> tuple[VendoredComponent, ...]:
    """Discover every vendored third-party component under the repo tree.

    Deduped by canonical name (a component vendored under two roots collapses;
    the record carrying the most information — version/license — is kept). The
    result is cached per ``repo_root`` because reconcile calls the profile's
    curated hooks several times.
    """
    repo_root = Path(repo_root)
    found: dict[str, VendoredComponent] = {}

    for root in _iter_vendor_roots(repo_root):
        try:
            children = sorted(c for c in root.iterdir() if c.is_dir())
        except OSError:
            continue
        for comp_dir in children:
            if comp_dir.name.startswith(".") or comp_dir.name.lower() in _SKIP_COMPONENT_NAMES:
                continue
            name = _canonical_name(comp_dir.name)
            source_dir, version = _resolve_source_and_version(comp_dir)
            license_id = _scan_embedded_license(source_dir, comp_dir)
            rec = VendoredComponent(
                name=name,
                version=version,
                license=license_id,
                rel_path=_rel(repo_root, comp_dir),
                source_rel_path=_rel(repo_root, source_dir),
            )
            existing = found.get(name)
            if existing is None:
                found[name] = rec
            else:
                _merge_vendored(existing, rec)

    return tuple(found[name] for name in sorted(found))


def _rel(repo_root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _merge_vendored(base: VendoredComponent, other: VendoredComponent) -> None:
    """Fold a duplicate discovery into ``base`` (prefer proven facts)."""
    if base.version is None and other.version is not None:
        base.version = other.version
    if base.license is None and other.license is not None:
        base.license = other.license
        base.source_rel_path = other.source_rel_path


# ---------------------------------------------------------------------------
# Curated record (shape reconcile reads via getattr: name/version/license/...)
# ---------------------------------------------------------------------------


@dataclass
class HisparkCuratedRecord:
    """License/version/copyright facts reconcile folds onto a component.

    Deliberately mirrors the attribute surface the core reads
    (``name``/``version``/``effective_version``/``license``/``copyright``) so no
    core change is needed. Only proven values are non-``None``: a scanned
    embedded license, a version recovered from the source subdir. Everything
    unresolved stays ``None`` (the known-license map / NOASSERTION take over)."""

    name: str
    version: str | None = None
    effective_version: str | None = None
    license: str | None = None
    copyright: str | None = None


# ---------------------------------------------------------------------------
# Root classification (classify_root)
# ---------------------------------------------------------------------------


def _classify_path(rel_parts: tuple[str, ...]) -> SubjectRole | None:
    """Path-semantic role for a discovered standalone CMake root.

    HiSpark trees carry board demos under ``samples/``, ``vendor/.../demo`` and
    ``examples/``, and host-side test harnesses under ``test(s)/``. These are
    not distributable firmware, so classifying them lets the default release
    view trim them while ``--scope all`` keeps them.
    """
    parts = tuple(p for p in rel_parts if p not in (".", ""))
    lowered = {p.lower() for p in parts}
    if lowered & {"test", "tests"}:
        return SubjectRole.NON_DISTRIBUTABLE_TEST
    if lowered & {"samples", "sample", "example", "examples", "demo", "demos"}:
        return SubjectRole.EXAMPLE
    # A CMake root INSIDE a vendored third-party tree is not a distributable
    # firmware subject — the tree is already surfaced as a third-party component
    # by package_metadata. Classify it EXAMPLE so the release view trims the
    # duplicate root (e.g. CMSIS-DSP ships its own project() CMakeLists).
    if lowered & _VENDOR_ROOT_NAMES:
        return SubjectRole.EXAMPLE
    return None


# ---------------------------------------------------------------------------
# The profile
# ---------------------------------------------------------------------------


class HisparkProfile(Profile):
    """Concrete ``Profile`` registered as ``hispark`` in the ``sbom.profiles`` group.

    Isolates all HiSpark knowledge behind the :class:`sbom.profile.Profile`
    hooks. ``name = "hispark"``. Must not be imported by the generic core except
    via the entry-point registry.
    """

    name = "hispark"

    def __init__(self) -> None:
        self._repo_root: Path | None = None
        self._own_license: str | None = None
        self._own_license_computed = False

    # -- Auto-detection ---------------------------------------------------

    @staticmethod
    def _git_origin_owner(repo_root: Path) -> tuple[str, str] | None:
        """Return ``(host, owner)`` for the repo's git origin, or ``None``."""
        from urllib.parse import urlsplit

        from sbom.origin import _from_git_config

        norm = _from_git_config(repo_root)
        if not norm:
            return None
        u = urlsplit(norm[0])  # norm[0] is the normalized https web URL
        host = (u.hostname or "").rstrip(".").lower()
        segs = [s for s in u.path.split("/") if s]
        owner = segs[0].lower() if segs else ""
        return host, owner

    @classmethod
    def detect(cls, repo_root: Path) -> bool:
        """Return ``True`` when ``repo_root``'s git origin is a HiSpark repo.

        Detection is by VCS origin only — ``gitcode.com/HiSpark/<repo>`` — the
        single reliable signal every HiSpark repo shares (``hs-fbb``,
        ``fbb_ws63``, ``hi_aiot_solution``, ``Hi3516CV610``). It never matches a
        CANN (``gitcode.com/cann``) origin, so the two profiles cannot collide.
        """
        owner = cls._git_origin_owner(Path(repo_root))
        if owner is None:
            return False
        host, org = owner
        return host in _HISPARK_GIT_HOSTS and org in _HISPARK_GIT_OWNERS

    # -- Package metadata (vendored-source discovery) ---------------------

    def package_metadata(
        self, repo_root: Path, authority: CmakeAuthority
    ) -> list[Observation]:
        """Surface every on-disk vendored third-party component as an observation.

        Each ``open_source/``/``third_party/`` child directory becomes one
        runtime-scope observation carrying its canonical name (so the core
        materializes a component and the C++ collector wires a
        ``subject -> component`` DEPENDS_ON edge) and its resolved on-disk source
        path (so the ScanCode/deps-dir layers can target the real tree). Version
        and license are attached separately via :meth:`curated_records`.
        """
        self._repo_root = Path(repo_root)
        revision = authority.revision or authority.ref
        observations: list[Observation] = []
        for rec in _discover(Path(repo_root)):
            observations.append(
                Observation(
                    source_kind=SourceKind.CURATED_NOTICE,
                    source_file=rec.rel_path,
                    source_revision=revision,
                    usage_scope=UsageScope.RUNTIME,
                    resolved_url_or_path=rec.source_rel_path,
                    ecosystem_data={"name": rec.name},
                )
            )
        return observations

    # -- Curated records (license + version from the real tree) -----------

    def curated_records(self, repo_root: Path) -> list[HisparkCuratedRecord]:
        """Version (from the source subdir) + license (from the embedded LICENSE
        file) for each discovered vendored component.

        License comes ONLY from the component's own on-disk license file (via the
        reused ``cache_scan`` heuristics); when none resolves the license stays
        ``None`` here so the curated upstream known-license map / NOASSERTION take
        over. This is the highest-confidence license layer — real embedded text
        beats the curated upstream guess."""
        self._repo_root = Path(repo_root)
        return [
            HisparkCuratedRecord(
                name=rec.name,
                version=rec.version,
                license=rec.license,
                copyright=rec.copyright,
            )
            for rec in _discover(Path(repo_root))
        ]

    # -- Vendored data files ----------------------------------------------

    def data_sources(self) -> list:
        """Vendored data files the HiSpark profile contributes.

        ``known-licenses`` reuses the generic-core name so it EXTENDS the core
        map (curated upstream identities for well-known components that ship no
        embedded license file — mbedtls/lz4/musl/...). ``aliases`` is
        HiSpark-only (the ``CMSISDSP*`` split-library link tokens). Both are
        cross-checked against — never derived from — the repo manifests."""
        data = Path(__file__).parent / "data"
        return [
            DataSource(
                "aliases",
                DERIVED,
                data / "aliases.yaml",
                "yaml",
                "HiSpark link-token -> canonical component aliases (CMSIS-DSP split libs).",
            ),
            DataSource(
                "known-licenses",
                CURATED,
                data / "known_licenses.yaml",
                "yaml",
                "Curated upstream licenses for well-known vendored OSS (no embedded LICENSE).",
            ),
        ]

    # -- Alias map --------------------------------------------------------

    def alias_map(self) -> dict[str, dict]:
        """Canonical-name aliases (loaded from ``data/aliases.yaml``).

        Chiefly the ``CMSISDSP<Fn>`` split-library CMake link targets, which all
        belong to the one ``cmsis-dsp`` component; without them each raises an
        ``unmapped_link_library`` warning."""
        return _load_alias_map()

    # -- Supplier (NTIA) --------------------------------------------------

    def first_party_supplier(self) -> str | None:
        """``HiSilicon (Shanghai) Technologies Co., Ltd.`` — HiSpark's supplier."""
        return HISPARK_SUPPLIER

    # -- License defaults -------------------------------------------------

    def subject_license_default(self, subject: Subject) -> str | None:
        """The repo's own license for its distributable subjects.

        Resolved from the repo's actual top-level ``LICENSE``/``COPYING`` file
        (via the reused ``cache_scan`` SPDX heuristic) so it is correct per-repo
        — ``Apache-2.0`` for hs-fbb/fbb_ws63/hi_aiot_solution, the custom
        ``Hi3516CV610 SDK License`` for that SDK. Ownership-only test groupings
        get no default. Falls back to the OpenHarmony/HiSpark norm when the file
        cannot be resolved."""
        if subject.role == SubjectRole.NON_DISTRIBUTABLE_TEST:
            return None
        return self._own_subject_license()

    def _own_subject_license(self) -> str | None:
        if self._own_license_computed:
            return self._own_license
        self._own_license_computed = True
        self._own_license = HISPARK_DEFAULT_SUBJECT_LICENSE
        if self._repo_root is not None:
            from sbom.enrich.cache_scan import _find_license_files, _pick_license, _read_safe

            license_files = _find_license_files(self._repo_root)
            spdx, _lf = _pick_license(license_files)
            if spdx is not None:
                self._own_license = spdx
            elif license_files:
                # No SPDX id (e.g. a custom SDK license) — use the license title
                # line as a LicenseRef name; the core synthesizes inline text.
                title = _first_title_line(_read_safe(license_files[0]))
                if title:
                    self._own_license = title
        return self._own_license

    # -- Supply-chain provenance ------------------------------------------

    def component_provenance(self, component: Component) -> str | None:
        """Mark a vendored component ``third-party``.

        Any component with an observation sourced from an ``open_source``/
        ``third_party`` tree is bundled upstream OSS — third-party, even before a
        license/URL is proven (so it is not left ``unknown`` by the generic
        core). Everything else defers to the core classifier."""
        for obs in component.observations:
            src = (obs.source_file or "") + " " + (obs.resolved_url_or_path or "")
            segs = re.split(r"[\\/ ]", src.lower())
            if "open_source" in segs or "third_party" in segs:
                return "third-party"
        return None

    # -- Root classification ----------------------------------------------

    def classify_root(
        self,
        path: Path,
        cmake_project: Subject,
        package_context: dict,
    ) -> SubjectRole:
        """Classify a discovered standalone CMake root by path semantics
        (board samples/demos -> example, host test harnesses -> non-dist test)."""
        path = Path(path)
        repo_root = package_context.get("repo_root") if package_context else None
        if repo_root is not None:
            try:
                rel_parts = path.resolve().relative_to(Path(repo_root).resolve()).parts
            except (ValueError, OSError):
                rel_parts = path.parts
        else:
            rel_parts = path.parts
        role = _classify_path(rel_parts)
        return role if role is not None else cmake_project.role

    # -- Verification-only manifest cross-check ---------------------------

    def crosscheck_manifest(self, repo_root: Path) -> list[dict]:
        """Compare the GENERATED component licenses against the repo's
        ``LICENSE.OpenSource`` manifest — a VERIFICATION aid, never a generation
        input.

        Returns one row per component present in either source:
        ``{name, generated, manifest, agree}`` where ``generated`` is what the
        profile derived from the real tree (embedded scan / curated upstream) and
        ``manifest`` is the license the aggregate ``LICENSE.OpenSource`` declares
        for that component's directory. Divergence flags either manifest drift or
        a gap in the curated map — for a human to adjudicate, not for the tool to
        silently reconcile."""
        repo_root = Path(repo_root)
        generated = {rec.name: rec.license for rec in _discover(repo_root)}
        # Fill still-unknown ones from the curated upstream map for a fair compare.
        known = _load_known_license_map()
        for name in list(generated):
            if generated[name] is None:
                generated[name] = known.get(name)
        manifest = _parse_license_opensource(repo_root)

        rows: list[dict] = []
        for name in sorted(set(generated) | set(manifest)):
            gen = generated.get(name)
            man = manifest.get(name)
            rows.append(
                {
                    "name": name,
                    "generated": gen,
                    "manifest": man,
                    "agree": (gen is not None and man is not None and gen == man),
                }
            )
        return rows


# ---------------------------------------------------------------------------
# Data-file loaders (cached)
# ---------------------------------------------------------------------------

_ALIAS_MAP_PATH = Path(__file__).parent / "data" / "aliases.yaml"
_KNOWN_LICENSES_PATH = Path(__file__).parent / "data" / "known_licenses.yaml"


@lru_cache(maxsize=1)
def _load_alias_map() -> dict[str, dict]:
    import yaml

    with open(_ALIAS_MAP_PATH, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    out: dict[str, dict] = {}
    for spelling, record in raw.items():
        if isinstance(record, dict):
            out[str(spelling)] = {
                "canonical": record.get("canonical", spelling),
                "relation": record.get("relation"),
            }
        else:
            out[str(spelling)] = {"canonical": str(record), "relation": None}
    return out


@lru_cache(maxsize=1)
def _load_known_license_map() -> dict[str, str]:
    import yaml

    with open(_KNOWN_LICENSES_PATH, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return {str(k).lower(): str(v) for k, v in raw.items()}


# ---------------------------------------------------------------------------
# Small text helpers
# ---------------------------------------------------------------------------


def _first_title_line(text: str) -> str | None:
    """The first non-empty, non-boilerplate line of a license file — used as a
    LicenseRef name for a custom license with no SPDX id."""
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith(("(", "#")):
            return s[:120]
    return None


#: License-section header in ``LICENSE.OpenSource`` (VERIFICATION ONLY).
_MANIFEST_HEADER_RE = re.compile(
    r"directories below are licensed under\s+(.+?)\.?\s*$", re.IGNORECASE
)
#: Human license strings in the manifests -> SPDX ids (VERIFICATION ONLY).
_MANIFEST_LICENSE_TO_SPDX = {
    "apache license, version 2.0": "Apache-2.0",
    "apache license, version 2.0 with llvm exceptions": "Apache-2.0 WITH LLVM-exception",
    "mit license": "MIT",
    "bsd 3-clause license": "BSD-3-Clause",
    "bsd 2-clause license": "BSD-2-Clause",
    "bsd-2-clause-freebsd": "BSD-2-Clause",
    "bsd-1-clause license": "BSD-1-Clause",
    "mulan psl v2": "MulanPSL-2.0",
    "public domain license": "LicenseRef-Public-Domain",
    "zlib/libpng license": "Zlib",
    "eclipse public license(epl) v2.0": "EPL-2.0",
    "eclipse public license version 2.0": "EPL-2.0",
    "gnu general public license, version 2": "GPL-2.0-only",
    "gnu lesser general public license version 2.1": "LGPL-2.1-only",
}


def _parse_license_opensource(repo_root: Path) -> dict[str, str]:
    """Parse ``LICENSE.OpenSource`` into ``{component_name: spdx}`` for the
    verification cross-check ONLY (never a generation input)."""
    path = repo_root / "LICENSE.OpenSource"
    if not path.is_file():
        return {}
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return {}
    out: dict[str, str] = {}
    current: str | None = None
    for line in lines:
        header = _MANIFEST_HEADER_RE.search(line)
        if header:
            raw = header.group(1).strip().lower()
            current = _MANIFEST_LICENSE_TO_SPDX.get(raw)
            continue
        s = line.strip()
        if current and s.startswith("./"):
            # Component name = basename of the listed dir (or file stem).
            base = s.rstrip("/").split("/")[-1]
            base = re.sub(r"\.(c|h|cpp|hpp|cc)$", "", base)
            name = _canonical_name(base)
            out.setdefault(name, current)
    return out


__all__ = [
    "HisparkProfile",
    "VendoredComponent",
    "HisparkCuratedRecord",
]
