"""CANN repo profile plugin.

Registered via the ``sbom.profiles`` entry point as
``cann = "sbom_profile_cann:CannProfile"`` (see ``pyproject.toml``).

:class:`CannProfile` implements every :class:`sbom.profile.Profile` hook against
the real CANN/ops-math trees:

* ``custom_dep_macros`` -- ``add_cann_third_party(name)`` resolves
  ``<effective_cmake_root>/third_party/<name>.cmake`` (plus the local
  ``include(cmake/third_party/<x>.cmake)`` shorthand).
* ``package_metadata`` -- ``version.cmake`` ``set_cann_*`` build/run deps with
  ``>=`` constraints, plus the primary ``ops_math`` subject identity.
* ``build_tooling`` -- ``fetch_cann_cmake.cmake`` -> a ``cann-cmake`` build-scope
  component, branch-specific identity (skipped / local-dir / tarball / git), with
  the trusted-input / local-override / tag-mismatch warning policy.
* ``curated_enrichers`` -- ``Third_Party_Open_Source_Software_List.yaml`` +
  ``..._Notice`` parsers (license + copyright).
* ``alias_map`` -- CANN canonical-name map with relation types.
* ``subject_license_default`` / ``dependency_license_default`` -- subject-owned
  ``LicenseRef-CANN-Open-Software-License-2.0`` vs dependency ``NOASSERTION``.
* ``condition_vocabulary`` -- ``TOPLEVEL_PROJECT`` / ``ENABLE_*`` / ``PRODUCT_SIDE`` / ....
* ``classify_root`` + ``root_exclusion_policy`` -- path-semantic roles.
* ``subject_facets`` -- collapse the ``ascend_ops``/``AscendOps`` wheel<->CMake
  pair, the ``npu_math_extension`` wheel, and the ``ops_math``/``math`` facet.

The generic core must never import this module except through the entry-point
registry (:func:`sbom.profile.load_profiles`). CMake parsing is NOT reimplemented
here -- ``sbom.cmake.parse`` helpers are reused (imported lazily so the profile
loads even before that module lands, and degrades gracefully if a parse helper is
missing).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from sbom.models import (
    CmakeAuthority,
    CmakeAuthorityBranch,
    Component,
    Facet,
    IntegrityFinding,
    Observation,
    Provenance,
    SourceKind,
    Subject,
    SubjectKind,
    SubjectMerge,
    SubjectRole,
    UsageScope,
    VcsRef,
    Warning,
)
from sbom.data_sources import CURATED, DERIVED, NETWORK, DataSource
from sbom.profile import Profile

# ---------------------------------------------------------------------------
# Markers / constants
# ---------------------------------------------------------------------------

#: Sibling/``--cmake-root`` marker file that implies the CANN profile.
_CANN_MARKER_FILE = Path("cmake") / "function" / "prepare.cmake"
#: Macro whose usage in any CMake file implies the CANN profile.
#: CANN-specific substrings in any CMake file that imply the CANN profile. Any one
#: match -> CANN. Beyond ``add_cann_third_party`` (third-party fetch), CANN repos
#: are identified by the cann-cmake project/version macros and the fetch include
#: even when they pull no third-party (e.g. pto-isa, pypto, hccl).
_CANN_MARKER_USAGES = (
    "add_cann_third_party(",
    "init_cann_project(",
    "set_cann_package(",
    "check_cann_pkg_build_deps(",
    "add_cann_target_options(",
    "add_cann_version_info_targets(",
    "fetch_cann_cmake",
)
_CMAKE_GLOBS = ("CMakeLists.txt", "*.cmake")

#: SECONDARY detection signal: a git origin owned by the CANN org. Catches CANN
#: repos that do NOT use the cann-cmake framework (e.g. pyasc, shmem — Python/other
#: builds). Scoped to the ``cann`` org ONLY (NOT ``Ascend``): an Ascend-org repo
#: like MindIE-LLM may carry a different license (a MulanPSL variant), not the CANN
#: Open Software License, so it must NOT inherit the CANN subject-license default.
_CANN_GIT_HOSTS = frozenset({"gitcode.com"})
_CANN_GIT_ORGS = frozenset({"cann"})

#: Repo-owned subject license (non-SPDX -> emitted as a LicenseRef + text).
CANN_OPEN_LICENSE = "LicenseRef-CANN-Open-Software-License-2.0"
#: NTIA Supplier for CANN's own (first-party) artifacts.
CANN_SUPPLIER = "Huawei Technologies Co., Ltd."

#: Pinned ``cann-cmake`` ref the ``fetch_cann_cmake.cmake`` git/tarball branch
#: acquires (``fetch_cann_cmake.cmake:17``).
CANN_CMAKE_TAG = "master-016"
#: Git repository the git branch clones from.
CANN_CMAKE_GIT = "https://gitcode.com/cann/cmake.git"
#: SHA256 of the pinned tarball (``fetch_cann_cmake.cmake:22``).
CANN_CMAKE_TARBALL_SHA256 = (
    "9167f7296590685b459d6abae6cc4b6e95db3db755af66b2c5b3c3f4908b3b39"
)

#: Curated product files (relative to repo_root) the enrichers consume.
CURATED_LIST_YAML = "Third_Party_Open_Source_Software_List.yaml"
CURATED_NOTICE = "Third_Party_Open_Source_Software_Notice"
VERSION_CMAKE = "version.cmake"
FETCH_CANN_CMAKE = Path("cmake") / "fetch_cann_cmake.cmake"


# ---------------------------------------------------------------------------
# Macro resolver (custom_dep_macros)
# ---------------------------------------------------------------------------


@dataclass
class CannThirdPartyResolver:
    """Resolver for ``add_cann_third_party(name)``.

    The CppCollector hands this object an ``effective_cmake_root`` (from the
    :class:`~sbom.models.CmakeAuthority` decision -- NEVER the raw
    ``--cmake-root``) and a macro invocation's args. It returns the ``.cmake``
    fragment(s) the macro ``include()``s:
    ``<effective_cmake_root>/third_party/<name>.cmake``.

    The macro body (``prepare.cmake:241-244``) is
    ``if(TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD) include(... third_party/<name>.cmake)``
    so callers also receive the gating condition via :attr:`activation_condition`.
    """

    #: Raw gating expression the macro wraps its include() in.
    activation_condition: str = "TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD"

    def fragment_subdir(self) -> str:
        """The subdir under ``effective_cmake_root`` the macro includes from."""
        return "third_party"

    def resolve(
        self, args: list[str], effective_cmake_root: Path | None
    ) -> list[Path]:
        """Expand one ``add_cann_third_party(<name> ...)`` call to fragments.

        ``args`` is the macro's argument list (``["eigen"]`` for
        ``add_cann_third_party(eigen)``); only the first positional arg names the
        fragment. Returns ``[<effective_cmake_root>/third_party/<name>.cmake]``.
        When ``effective_cmake_root`` is unknown the path cannot be anchored, so
        an empty list is returned (the collector then records an unresolved
        include rather than guessing the raw ``--cmake-root``).
        """
        if not args or effective_cmake_root is None:
            return []
        name = args[0].strip().strip('"')
        if not name:
            return []
        return [Path(effective_cmake_root) / self.fragment_subdir() / f"{name}.cmake"]

    # The collector calls the resolver like ``macro(args, effective_cmake_root)``.
    def __call__(
        self, args: list[str], effective_cmake_root: Path | None
    ) -> list[Path]:
        return self.resolve(args, effective_cmake_root)


# ---------------------------------------------------------------------------
# version.cmake parsing (package_metadata)
# ---------------------------------------------------------------------------

_RE_SET_PACKAGE = re.compile(
    r'set_cann_package\(\s*([A-Za-z0-9_.\-]+)\s+VERSION\s+"?([^")\s]+)"?\s*\)'
)
_RE_BUILD_DEP = re.compile(
    r'set_cann_build_dependencies\(\s*([A-Za-z0-9_.\-]+)\s+"?([^")]+?)"?\s*\)'
)
_RE_RUN_DEP = re.compile(
    r'set_cann_run_dependencies\(\s*([A-Za-z0-9_.\-]+)\s+"?([^")]+?)"?\s*\)'
)


@dataclass
class CannPackageInfo:
    """Parsed ``version.cmake`` facts: the package and its declared deps."""

    name: str | None = None
    version: str | None = None
    build_deps: list[tuple[str, str]] = field(default_factory=list)  # (name, constraint)
    run_deps: list[tuple[str, str]] = field(default_factory=list)


def parse_version_cmake(text: str) -> CannPackageInfo:
    """Parse the ``set_cann_package``/``set_cann_*_dependencies`` calls.

    Mirrors ``ops-math/version.cmake``::

        set_cann_package(ops_math VERSION "9.0.0")
        set_cann_build_dependencies(runtime ">=8.5")
        set_cann_run_dependencies(asc-tools ">=8.5")

    Returns a :class:`CannPackageInfo` preserving declaration order and
    distinguishing build vs run constraints.
    """
    info = CannPackageInfo()
    pkg = _RE_SET_PACKAGE.search(text)
    if pkg:
        info.name = pkg.group(1)
        info.version = pkg.group(2)
    for m in _RE_BUILD_DEP.finditer(text):
        info.build_deps.append((m.group(1), m.group(2).strip()))
    for m in _RE_RUN_DEP.finditer(text):
        info.run_deps.append((m.group(1), m.group(2).strip()))
    return info


# ---------------------------------------------------------------------------
# Curated file parsers (curated_enrichers)
# ---------------------------------------------------------------------------

# Mapping from the human license strings in the Notice to SPDX/LicenseRef ids.
_NOTICE_LICENSE_TO_SPDX = {
    "bsd 3-clause license": "BSD-3-Clause",
    "mit license": "MIT",
    "apache license v2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0",
    "gpl v2.0": "GPL-2.0-only",
    "mulan permissive software license version 2": "MulanPSL-2.0",
    "bsl-1.0": "BSL-1.0",
}

# Curated component name -> canonical SBOM component name (List.yaml/Notice use
# upstream spellings that the alias map also normalizes).
_CURATED_NAME_TO_CANONICAL = {
    "googletest": "gtest",
    "json": "json",
    "makeself": "makeself",
    "protobuf": "protobuf",
    "eigen": "eigen",
    "libboundscheck": "libboundscheck",
}


def _spdx_for_notice_license(raw: str) -> str | None:
    """Normalize a Notice ``License:`` string to an SPDX id when recognized."""
    return _NOTICE_LICENSE_TO_SPDX.get(raw.strip().lower())


@dataclass
class CuratedRecord:
    """A curated license/version/copyright fact for one component.

    ``version`` is the source/declared version (from List.yaml or the Notice
    header). ``effective_version`` is set when the Notice records a different
    (e.g. patched) version than the List.yaml, so reconcile can flag a patched
    build (protobuf List.yaml ``v25.1`` vs Notice ``v3.13.0``).
    """

    name: str
    version: str | None = None
    effective_version: str | None = None
    declared_type: str | None = None  # run | test | build (from List.yaml)
    license: str | None = None  # SPDX id when recognized, else raw string
    license_raw: str | None = None  # the original Notice/yaml license string
    copyright: str | None = None
    source: str = CURATED_LIST_YAML


def parse_list_yaml(text: str) -> list[CuratedRecord]:
    """Parse ``Third_Party_Open_Source_Software_List.yaml``.

    The file is a flat ``name: {version, type}`` map::

        eigen:
          version: 5.0.0
          type: run

    Parsed with PyYAML when available, falling back to a tiny line parser so the
    enricher works without optional deps. Returns one :class:`CuratedRecord` per
    entry, with canonicalized names.
    """
    records: list[CuratedRecord] = []
    data: dict | None = None
    try:
        import yaml  # type: ignore

        loaded = yaml.safe_load(text)
        if isinstance(loaded, dict):
            data = loaded
    except Exception:
        data = None

    if data is None:
        data = _fallback_parse_flat_yaml(text)

    for raw_name, body in data.items():
        if not isinstance(body, dict):
            continue
        canonical = _CURATED_NAME_TO_CANONICAL.get(raw_name, raw_name)
        records.append(
            CuratedRecord(
                name=canonical,
                version=_str_or_none(body.get("version")),
                declared_type=_str_or_none(body.get("type")),
                source=CURATED_LIST_YAML,
            )
        )
    return records


def _fallback_parse_flat_yaml(text: str) -> dict[str, dict]:
    """Minimal two-level YAML parser for ``name:\\n  key: value`` blocks."""
    data: dict[str, dict] = {}
    current: str | None = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            current = line.strip().rstrip(":").strip()
            data[current] = {}
        elif current is not None and ":" in line:
            key, _, val = line.strip().partition(":")
            data[current][key.strip()] = val.strip()
    return data


def parse_notice(text: str) -> list[CuratedRecord]:
    """Parse ``Third_Party_Open_Source_Software_Notice``.

    The file is a sequence of blocks introduced by ``Software: <name> <version>``
    (the colon may or may not have a space), each followed by a
    ``Copyright notice:`` section and a ``License: <name>`` line. Returns one
    :class:`CuratedRecord` per block, mapping the human license string to an SPDX
    id when recognized (else the raw string is retained for LicenseRef handling).
    """
    records: list[CuratedRecord] = []
    lines = text.splitlines()

    # Find the index of every "Software:" header.
    headers: list[int] = [
        i for i, ln in enumerate(lines) if re.match(r"\s*Software\s*:", ln)
    ]
    for pos, start in enumerate(headers):
        end = headers[pos + 1] if pos + 1 < len(headers) else len(lines)
        block = lines[start:end]
        rec = _parse_notice_block(block)
        if rec is not None:
            records.append(rec)
    return records


def _parse_notice_block(block: list[str]) -> CuratedRecord | None:
    header = block[0]
    m = re.match(r"\s*Software\s*:\s*(.+)$", header)
    if not m:
        return None
    name_ver = m.group(1).strip()
    # Last whitespace-separated token is the version when it looks version-ish.
    name, version = _split_name_version(name_ver)
    canonical = _CURATED_NAME_TO_CANONICAL.get(name, name)

    license_raw: str | None = None
    copyright_lines: list[str] = []
    in_copyright = False
    for ln in block[1:]:
        lic = re.match(r"\s*License\s*:\s*(.+)$", ln)
        if lic:
            license_raw = lic.group(1).strip()
            in_copyright = False
            continue
        if re.match(r"\s*Copyright notice\s*:", ln):
            in_copyright = True
            continue
        if in_copyright:
            stripped = ln.strip()
            if not stripped:
                in_copyright = False
                continue
            if stripped.lower().startswith("copyright") or stripped.startswith("(c)"):
                copyright_lines.append(stripped)

    spdx = _spdx_for_notice_license(license_raw) if license_raw else None
    return CuratedRecord(
        name=canonical,
        version=version,
        license=spdx or license_raw,
        license_raw=license_raw,
        copyright="\n".join(copyright_lines) or None,
        source=CURATED_NOTICE,
    )


def _split_name_version(name_ver: str) -> tuple[str, str | None]:
    """Split ``protobuf v3.13.0`` -> ``("protobuf", "v3.13.0")``."""
    parts = name_ver.split()
    if len(parts) >= 2 and re.search(r"\d", parts[-1]):
        return " ".join(parts[:-1]), parts[-1]
    return name_ver, None


def _str_or_none(val) -> str | None:
    if val is None:
        return None
    return str(val).strip() or None


def _merge_curated(existing: CuratedRecord, incoming: CuratedRecord) -> None:
    """Fold ``incoming`` into ``existing`` for the same component name.

    The List.yaml carries the source/declared version + type; the Notice carries
    the license, copyright, and (when different) the effective version. The Notice
    license always wins over a List.yaml one (curated authority), and a differing
    Notice version is recorded as ``effective_version`` so a patched build is
    visible (protobuf List.yaml ``v25.1`` source vs Notice ``v3.13.0`` effective).
    """
    if incoming.source == CURATED_NOTICE:
        existing.license = incoming.license or existing.license
        existing.license_raw = incoming.license_raw or existing.license_raw
        existing.copyright = incoming.copyright or existing.copyright
        if incoming.version and existing.version and incoming.version != existing.version:
            existing.effective_version = incoming.version
        elif incoming.version and not existing.version:
            existing.version = incoming.version
    else:  # List.yaml
        existing.declared_type = incoming.declared_type or existing.declared_type
        if incoming.version:
            # The Notice header version becomes effective if it already differs.
            if existing.version and existing.version != incoming.version:
                existing.effective_version = existing.version
            existing.version = incoming.version


@dataclass
class CuratedEnricher:
    """A curated-file enricher the core runs if its file exists.

    The core calls :meth:`load` with ``repo_root`` to get a list of
    :class:`CuratedRecord`. Curated facts take precedence over the generic
    known-license map (design "License / copyright discovery"). Two enrichers are
    returned by :meth:`CannProfile.curated_enrichers`: the List.yaml (version +
    type) and the Notice (license + copyright). The Notice is the authority for
    ``effective_version`` mapping; the List.yaml maps to ``source_version``.
    """

    path: Path
    kind: str  # "list_yaml" | "notice"

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> list[CuratedRecord]:
        if not self.exists():
            return []
        try:
            text = self.path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        if self.kind == "list_yaml":
            return parse_list_yaml(text)
        return parse_notice(text)


# ---------------------------------------------------------------------------
# Root classification (classify_root / root_exclusion_policy)
# ---------------------------------------------------------------------------


def _classify_path(rel_parts: tuple[str, ...]) -> SubjectRole | None:
    """Path-semantic role for a discovered standalone CMake root.

    Encodes the CANN path policy:

    * ``.../tests/st/torch/...``   -> ``st_test`` (a torch ST harness; also
      non-distributable, handled by the caller via ``emit_as_subject``).
    * ``.../tests/st/...``         -> ``st_test``.
    * ``.../tests/ut/...`` / ``.../tests/...`` -> ``non_distributable_test``.
    * ``.../examples/...``         -> ``example``.
    * ``examples/...`` (top-level) -> ``example`` (or ``manual_example`` for the
      explicitly-skipped ``fast_kernel_launch_example``).
    * ``.../sample/...`` / ``.../samples/...`` -> ``example`` (the runtime repo's
      example trees use a ``sample``/``samples`` segment rather than ``examples``;
      they ship as demos, not distributable artifacts).
    * ``experimental/...``         -> ``experimental`` (unless a more specific
      examples/tests segment overrides).
    """
    parts = tuple(p for p in rel_parts if p not in (".", ""))
    if not parts:
        return None

    # tests/st/torch -> st_test ; tests/st -> st_test ; other tests -> non-dist test
    if "tests" in parts:
        ti = parts.index("tests")
        tail = parts[ti + 1 :]
        if tail and tail[0] == "st":
            return SubjectRole.ST_TEST
        return SubjectRole.NON_DISTRIBUTABLE_TEST

    if "examples" in parts:
        # The top-level fast_kernel_launch_example is skipped in the normal tree
        # (examples/CMakeLists.txt:22-24) -> a manual (opt-in) example.
        if "fast_kernel_launch_example" in parts:
            return SubjectRole.MANUAL_EXAMPLE
        return SubjectRole.EXAMPLE

    if "fast_kernel_launch_example" in parts:
        return SubjectRole.MANUAL_EXAMPLE

    # A 'sample'/'samples' path segment marks a demo root (e.g. the runtime repo's
    # ~62 same-shaped sample CMake projects). Classified EXAMPLE so the release
    # scope trims them, like the examples/ trees.
    if "sample" in parts or "samples" in parts:
        return SubjectRole.EXAMPLE

    if "experimental" in parts:
        return SubjectRole.EXPERIMENTAL

    return None


# ---------------------------------------------------------------------------
# Alias map (alias_map) -- relation values use sbom.models.RelationType values
# ---------------------------------------------------------------------------

#: The profile-carried alias data file (spelling -> {canonical, relation}), shipped
#: alongside this package. Edit it to extend coverage without touching Python.
_ALIAS_MAP_PATH = Path(__file__).parent / "data" / "aliases.yaml"
_ALIAS_MAP_CACHE: dict[str, dict] | None = None

#: First-party CANN component -> license (data/first_party_licenses.yaml). Keys are
#: lowercased on load for case-insensitive name/alias matching.
_FIRST_PARTY_PATH = Path(__file__).parent / "data" / "first_party_licenses.yaml"
_FIRST_PARTY_CACHE: dict[str, str] | None = None


def _first_party_licenses() -> dict[str, str | None]:
    """Load ``data/first_party_licenses.yaml`` (cached; keys lowercased).

    A key maps to its declared license, or to ``None`` for a first-party CANN
    component whose license is deliberately NOT asserted (closed-source /
    proprietary, e.g. ``bisheng-compiler``). Membership (key present) drives
    ``component_provenance`` ⇒ first-party; only a non-``None`` value is used as a
    ``dependency_license_default``, so a null-licensed entry stays NOASSERTION."""
    global _FIRST_PARTY_CACHE
    if _FIRST_PARTY_CACHE is None:
        import yaml

        with open(_FIRST_PARTY_PATH, encoding="utf-8") as fh:
            raw: dict = yaml.safe_load(fh) or {}
        _FIRST_PARTY_CACHE = {
            str(k).lower(): (None if v is None else str(v)) for k, v in raw.items()
        }
    return _FIRST_PARTY_CACHE


#: (host, first-path-segment) pairs that identify a CANN first-party origin. The org
#: is exactly ``gitcode.com/cann/<repo>``; the look-alike THIRD-PARTY mirror
#: namespaces -- ``gitcode.com/cann-src-third-party/`` (libboundscheck) and the
#: ``cann-3rd.obs.<region>.myhuaweicloud.com`` OBS bucket (eigen/protobuf/json/...)
#: -- merely contain the substring "cann" and must NOT match.
_FIRST_PARTY_ORIGINS = (("gitcode.com", "cann"),)


def _is_cann_org_url(url: str | None) -> bool:
    """True if ``url`` is under a CANN first-party origin (``gitcode.com/cann/*``).

    Matches on (host, first path segment) so the org namespace is distinguished
    from third-party mirrors that merely share the ``cann`` substring."""
    if not url:
        return False
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    # urlsplit keeps a fully-qualified trailing dot ('gitcode.com.'); normalize it
    # away so an FQDN form still matches the origin tuple.
    host = (parts.hostname or "").rstrip(".").lower()
    segs = [s for s in parts.path.split("/") if s]
    first = segs[0].lower() if segs else ""
    return (host, first) in _FIRST_PARTY_ORIGINS


def _build_alias_map() -> dict[str, dict]:
    """Load the CANN canonical-name map (spelling -> ``{canonical, relation}``).

    Maps every raw spelling seen across mechanisms (find_package module names,
    package-dep names, raw link tokens) so reconcile de-dups the same component
    seen under different mechanisms and an unmapped raw link token raises
    ``unmapped_link_library`` instead of duplicating/dropping a component.

    The map lives in :data:`_ALIAS_MAP_PATH` (``data/aliases.yaml``) — a data file
    carried with the profile — so coverage is extended by editing YAML, not code.
    A copy is returned so callers cannot mutate the cached map.
    """
    global _ALIAS_MAP_CACHE
    if _ALIAS_MAP_CACHE is None:
        import yaml

        with open(_ALIAS_MAP_PATH, encoding="utf-8") as fh:
            raw: dict = yaml.safe_load(fh) or {}
        out: dict[str, dict] = {}
        for spelling, record in raw.items():
            if isinstance(record, dict):
                out[str(spelling)] = {
                    "canonical": record.get("canonical", spelling),
                    "relation": record.get("relation"),
                }
            else:  # tolerate a bare ``spelling: canonical`` string entry
                out[str(spelling)] = {"canonical": str(record), "relation": None}
        _ALIAS_MAP_CACHE = out
    return dict(_ALIAS_MAP_CACHE)


# ---------------------------------------------------------------------------
# Condition vocabulary (condition_vocabulary)
# ---------------------------------------------------------------------------


def _condition_vocabulary() -> dict[str, object]:
    """Known CANN condition tokens and their semantics.

    The collector/build-profile evaluator uses these to interpret activation
    gates. ``kind`` distinguishes a top-level/path predicate, an ON/OFF option,
    a value flag, and the authority-branch gate.
    """
    return {
        "TOPLEVEL_PROJECT": {
            "kind": "predicate",
            "meaning": "ops-math configured as the top-level project (NOT PROJECT_SOURCE_DIR)",
        },
        "ENABLE_UNIFIED_BUILD": {"kind": "option", "default": None},
        "ENABLE_TEST": {"kind": "option", "default": False},
        "ENABLE_PACKAGE": {"kind": "option", "default": False},
        "ENABLE_EXPERIMENTAL": {"kind": "option", "default": False},
        "ENABLE_CUSTOM": {"kind": "option", "default": False},
        "ENABLE_BINARY": {"kind": "option", "default": False},
        "ENABLE_STATIC": {"kind": "option", "default": False},
        "ENABLE_TORCH_EXTENSION": {
            "kind": "option",
            "default": None,
            "dead": True,  # no consumer in the tree -> dead_config_flag
        },
        "ENABLE_CCACHE": {"kind": "option", "default": True},
        "PRODUCT_SIDE": {"kind": "value", "values": ["device", "host"]},
        "BUILD_WITH_INSTALLED_DEPENDENCY_CANN_PKG": {
            "kind": "option",
            "default_depends_on": "TOPLEVEL_PROJECT",
        },
        "DOWNLOAD_OPS_TEST_KIT": {"kind": "option", "default": False},
        "ASCEND_OP_NAME": {"kind": "value", "values": None},
        "TARGET_ARCH": {"kind": "value", "values": ["x86_64", "aarch64"]},
    }


# ---------------------------------------------------------------------------
# The profile
# ---------------------------------------------------------------------------


class CannProfile(Profile):
    """Concrete ``Profile`` registered as ``cann`` in the ``sbom.profiles`` group.

    Isolates all CANN/ops-math knowledge behind the :class:`sbom.profile.Profile`
    hooks. ``name = "cann"``. Must not be imported by the generic core except via
    the entry-point registry.
    """

    name = "cann"

    # -- Auto-detection ---------------------------------------------------

    @staticmethod
    def _git_origin_is_cann(repo_root: Path) -> bool:
        """True when the repo's git origin is owned by the CANN org (e.g.
        ``gitcode.com/cann/<repo>``). The SECONDARY detection signal, for CANN repos
        that carry no cann-cmake marker. Scoped to ``cann`` only (see
        :data:`_CANN_GIT_ORGS`); an ``Ascend``-org repo is deliberately NOT matched."""
        from urllib.parse import urlsplit

        from sbom.origin import _from_git_config

        norm = _from_git_config(repo_root)
        if not norm:
            return False
        u = urlsplit(norm[0])  # norm[0] is the normalized https web URL
        host = (u.hostname or "").lower()
        segs = [s for s in u.path.split("/") if s]
        owner = segs[0].lower() if segs else ""
        return host in _CANN_GIT_HOSTS and owner in _CANN_GIT_ORGS

    @classmethod
    def detect(cls, repo_root: Path) -> bool:
        """Return ``True`` when ``repo_root`` is a CANN repo.

        Two kinds of evidence: (1) CANN CMake-framework markers — the
        ``cmake/function/prepare.cmake`` marker file, the conventional
        ``cmake/fetch_cann_cmake.cmake`` / ``version.cmake`` (fast paths), or any
        ``_CANN_MARKER_USAGES`` substring in a ``CMakeLists.txt``/``*.cmake``;
        (2) a git origin under the ``cann`` org (:meth:`_git_origin_is_cann`),
        which catches CANN repos with no cann-cmake markers (Python/other builds).
        """
        repo_root = Path(repo_root)

        # Fast paths: conventional CANN marker files (avoid scanning the whole tree).
        if (repo_root / _CANN_MARKER_FILE).is_file():
            return True
        if (repo_root / FETCH_CANN_CMAKE).is_file():
            return True
        version_cmake = repo_root / VERSION_CMAKE
        if version_cmake.is_file():
            try:
                if "set_cann_package(" in version_cmake.read_text(errors="ignore"):
                    return True
            except OSError:
                pass

        # Secondary signal: a CANN-org git origin (cheap; before the tree scan).
        if cls._git_origin_is_cann(repo_root):
            return True

        for glob in _CMAKE_GLOBS:
            for path in repo_root.rglob(glob):
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if any(marker in text for marker in _CANN_MARKER_USAGES):
                    return True

        return False

    # -- CMake macros -----------------------------------------------------

    def custom_dep_macros(self) -> dict[str, object]:
        """``add_cann_third_party`` -> resolver to ``third_party/<name>.cmake``.

        The resolver anchors every fragment at
        :attr:`CmakeAuthority.effective_cmake_root` (never the raw
        ``--cmake-root``). The local shorthand ``include(cmake/third_party/<x>.cmake)``
        needs no macro -- the generic include() walk handles it -- but its target
        directory is the same fragment subdir, so the collector can treat both as
        one third-party surface.
        """
        return {"add_cann_third_party": CannThirdPartyResolver()}

    # -- Package metadata -------------------------------------------------

    def package_metadata(
        self, repo_root: Path, authority: CmakeAuthority
    ) -> list[Observation]:
        """Parse ``version.cmake`` ``set_cann_*`` deps into observations.

        Each build dep -> a ``cann_package`` observation with ``usage_scope=build``
        and the ``>=`` constraint; each run dep -> ``usage_scope=runtime``. The
        ``set_cann_package(ops_math VERSION 9.0.0)`` line is the primary subject's
        identity (carried on the Subject by ``discover_subjects``); it is recorded
        here as a self-observation only via ``ecosystem_data`` so the primary
        version survives even if the subject collector misses it.
        """
        path = Path(repo_root) / VERSION_CMAKE
        if not path.is_file():
            return []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        info = parse_version_cmake(text)
        revision = authority.revision or authority.ref
        observations: list[Observation] = []

        def make_obs(name: str, constraint: str, scope: UsageScope) -> Observation:
            return Observation(
                source_kind=SourceKind.CANN_PACKAGE,
                source_file=VERSION_CMAKE,
                source_revision=revision,
                usage_scope=scope,
                version_constraint=constraint,
                ecosystem_data={
                    "cann_package": name,
                    "primary_package": info.name,
                    "primary_version": info.version,
                },
            )

        for name, constraint in info.build_deps:
            observations.append(make_obs(name, constraint, UsageScope.BUILD))
        for name, constraint in info.run_deps:
            observations.append(make_obs(name, constraint, UsageScope.RUNTIME))

        return observations

    def package_info(self, repo_root: Path) -> CannPackageInfo:
        """Convenience accessor for the parsed ``version.cmake`` (tests/subject)."""
        path = Path(repo_root) / VERSION_CMAKE
        if not path.is_file():
            return CannPackageInfo()
        try:
            return parse_version_cmake(
                path.read_text(encoding="utf-8", errors="ignore")
            )
        except OSError:
            return CannPackageInfo()

    # -- Build tooling ----------------------------------------------------

    def build_tooling(
        self, repo_root: Path, authority: CmakeAuthority
    ) -> tuple[list[Component], list[Warning]]:
        """Model ``fetch_cann_cmake.cmake`` -> a ``cann-cmake`` component.

        Branch-specific behaviour (per :class:`CmakeAuthorityBranch`):

        * ``skipped_existing_project`` -- the fetch block is skipped (configured
          under a parent ``project()``); NO ``cann-cmake`` component, no warning
          (the macros come from the inherited provider).
        * ``local_dir`` -- an arbitrary local checkout is the actual source;
          component version is ``NOASSERTION`` (NOT ``master-016``) with a
          ``local_source_unverified`` finding and a ``cann_cmake_local_override``
          warning; identity carries the resolved git commit when known.
        * ``tarball`` -- pinned ``master-016`` + sha256.
        * ``git`` -- requested ref (``master-016``) + resolved commit when known.

        Under ``--cmake-source-authority cmake-as-input`` the resolver records the
        branch but marks ``effective_cmake_root`` as trusted input; in that case
        the ``cann-cmake`` component is EXCLUDED with a ``cann_cmake_trusted_input``
        warning. A ``cann_cmake_tag_mismatch`` is emitted when the resolved ref
        differs from the pin.
        """
        warnings: list[Warning] = []

        if authority.branch == CmakeAuthorityBranch.SKIPPED_EXISTING_PROJECT:
            return ([], [])

        trusted_input = bool(authority.authority_inputs.get("trusted_input"))
        if trusted_input:
            warnings.append(
                Warning(
                    code="cann_cmake_trusted_input",
                    subject="cann-cmake",
                    detail="cmake-as-input: cann-cmake excluded (trusted generator input)",
                )
            )
            warnings.extend(self._tag_mismatch_warnings(authority))
            return ([], warnings)

        component = self._cann_cmake_component(authority)
        warnings.extend(self._tag_mismatch_warnings(authority))

        if authority.branch == CmakeAuthorityBranch.LOCAL_DIR:
            warnings.append(
                Warning(
                    code="cann_cmake_local_override",
                    subject="cann-cmake",
                    detail="local-dir branch: arbitrary local cann-cmake checkout "
                    "is authoritative; master-016 not assumed",
                )
            )

        return ([component], warnings)

    def _cann_cmake_component(self, authority: CmakeAuthority) -> Component:
        revision = authority.revision or authority.ref
        observation = Observation(
            source_kind=SourceKind.CMAKE_BUILD_TOOLING,
            source_file=str(FETCH_CANN_CMAKE),
            source_revision=revision,
            usage_scope=UsageScope.BUILD,
        )
        component = Component(
            name="cann-cmake",
            type="library",
            languages=["cmake"],
            scopes=[UsageScope.BUILD],
            observations=[observation],
            provenance=[
                Provenance(field="source", source=str(FETCH_CANN_CMAKE)),
            ],
        )

        if authority.branch == CmakeAuthorityBranch.LOCAL_DIR:
            component.source_version = None  # NOASSERTION
            component.effective_version = None
            component.integrity_findings = [IntegrityFinding.LOCAL_SOURCE_UNVERIFIED]
            if authority.revision:
                component.vcs_ref = VcsRef(resolved_commit=authority.revision)
        elif authority.branch == CmakeAuthorityBranch.TARBALL:
            component.source_version = CANN_CMAKE_TAG
            component.effective_version = CANN_CMAKE_TAG
            component.checksums = {"sha256": CANN_CMAKE_TARBALL_SHA256}
        elif authority.branch == CmakeAuthorityBranch.GIT:
            component.source_version = authority.ref or CANN_CMAKE_TAG
            component.effective_version = authority.revision or authority.ref
            component.vcs_ref = VcsRef(
                requested=authority.ref or CANN_CMAKE_TAG,
                resolved_commit=authority.revision,
            )
            if not authority.revision:
                component.integrity_findings = [IntegrityFinding.UNPINNED_GIT]

        return component

    @staticmethod
    def _tag_mismatch_warnings(authority: CmakeAuthority) -> list[Warning]:
        """Emit ``cann_cmake_tag_mismatch`` when the resolved ref != the pin."""
        ref = authority.ref
        if ref and ref != CANN_CMAKE_TAG:
            return [
                Warning(
                    code="cann_cmake_tag_mismatch",
                    subject="cann-cmake",
                    detail=f"resolved cann-cmake ref {ref!r} != pinned {CANN_CMAKE_TAG!r}",
                )
            ]
        return []

    # -- Curated enrichers ------------------------------------------------

    def curated_enrichers(self, repo_root: Path) -> list[object]:
        """Return the List.yaml + Notice enrichers (run if their files exist)."""
        repo_root = Path(repo_root)
        return [
            CuratedEnricher(repo_root / CURATED_LIST_YAML, "list_yaml"),
            CuratedEnricher(repo_root / CURATED_NOTICE, "notice"),
        ]

    def curated_records(self, repo_root: Path) -> list[CuratedRecord]:
        """Merge the List.yaml (source_version/type) and Notice (license/effective
        version/copyright) facts into one curated record per component.

        The Notice is authoritative for ``effective_version`` and license; the
        List.yaml maps to ``source_version``. When both name the same component
        the records merge (e.g. protobuf: List.yaml ``v25.1`` source vs Notice
        ``v3.13.0`` effective -- both retained, flagged as a patched build by
        reconcile).
        """
        merged: dict[str, CuratedRecord] = {}
        for enricher in self.curated_enrichers(repo_root):
            for rec in enricher.load():  # type: ignore[attr-defined]
                existing = merged.get(rec.name)
                if existing is None:
                    merged[rec.name] = rec
                    continue
                _merge_curated(existing, rec)
        return list(merged.values())

    # -- Vendored data files ----------------------------------------------

    def data_sources(self) -> list:
        """Vendored data files the CANN profile contributes / overrides.

        ``aliases`` + ``first-party`` are CANN-only; ``known-licenses`` +
        ``depsdev`` reuse the generic-core names so they OVERRIDE/EXTEND the
        core defaults (merged on top). Drives map merges and ``--refresh-data``."""
        data = Path(__file__).parent / "data"
        return [
            DataSource(
                "aliases",
                DERIVED,
                data / "aliases.yaml",
                "yaml",
                "CANN canonical-name alias map (partly URL-derivable).",
            ),
            DataSource(
                "first-party",
                CURATED,
                data / "first_party_licenses.yaml",
                "yaml",
                "CANN first-party component names -> declared license (or null).",
            ),
            DataSource(
                "third-party-purls",
                CURATED,
                data / "third_party_purls.yaml",
                "yaml",
                "Well-known third-party name -> upstream PURL coordinate.",
            ),
            DataSource(
                "known-licenses",
                CURATED,
                data / "known_licenses.yaml",
                "yaml",
                "CANN-tuned OSS license overrides (merged over the core map).",
            ),
            DataSource(
                "depsdev",
                NETWORK,
                data / "depsdev_cache.json",
                "json",
                "CANN network license/version snapshot (overrides the core cache).",
            ),
            DataSource(
                "clearlydefined",
                NETWORK,
                data / "clearlydefined_cache.json",
                "json",
                "CANN ClearlyDefined supplier/copyright snapshot (overrides core).",
            ),
            DataSource(
                "deps-dir",
                DERIVED,
                data / "deps_dir_cache.json",
                "json",
                "CANN on-disk source license/copyright snapshot "
                "(cann-src-third-party; overrides core).",
            ),
        ]

    # -- Alias map --------------------------------------------------------

    def alias_map(self) -> dict[str, dict]:
        """Return the CANN canonical-name aliases with relation types."""
        return _build_alias_map()

    # -- Supplier (NTIA) --------------------------------------------------

    def first_party_supplier(self) -> str | None:
        """``Huawei Technologies Co., Ltd.`` — supplier of CANN's own artifacts.

        Fills the NTIA Supplier element for repo-owned subjects + first-party
        components; third-party suppliers come from the ClearlyDefined enricher."""
        return CANN_SUPPLIER

    # -- License defaults (subject vs dependency are separate) ------------

    def subject_license_default(self, subject: Subject) -> str | None:
        """``LicenseRef-CANN-Open-Software-License-2.0`` for repo-owned subjects.

        Applies to every repo-owned subject role (the primary CANN package, the
        sibling wheels, discovered CMake roots, examples/experimental/ST roots --
        all carry the repo's own license). ``NON_DISTRIBUTABLE_TEST`` roots are
        ownership-only groupings that ship nothing, so they get no default
        license.
        """
        if subject.role == SubjectRole.NON_DISTRIBUTABLE_TEST:
            return None
        return CANN_OPEN_LICENSE

    def dependency_license_default(self, component: Component) -> str | None:
        """A first-party CANN dependency's license, or ``None``.

        Recognized Huawei CANN packages / internal libraries (``data/
        first_party_licenses.yaml``) ship under the CANN Open Software License, so
        the profile asserts it as a DEFAULT — matched on the component's canonical
        name OR any recorded alias (so ``OPBASE``≡``opbase`` resolves). Third-party
        (``securec``=libboundscheck), published OSS (``torch-npu``), and Python
        deps are deliberately absent, so they keep deriving their license from
        their own evidence (curated Notice, file headers, network) rather than
        being mislabelled CANN. ``None`` for anything not first-party."""
        fp = _first_party_licenses()
        for name in (component.name, *component.aliases):
            lic = fp.get(name.lower())
            if lic is not None:
                return lic
        return None

    # -- Supply-chain provenance -----------------------------------------

    def component_provenance(self, component: Component) -> str | None:
        """``"first-party"`` for a CANN-org component, else ``None``.

        Two signals mark a component as CANN first-party:

        1. **Origin URL** under ``gitcode.com/cann/*`` -- any sibling CANN project
           fetched by URL. This is the generalizable rule and is robust against the
           look-alike third-party mirrors (``cann-src-third-party``, the
           ``cann-3rd`` OBS bucket), which fail the (host, ``cann``) test.
        2. **Recognized name** -- a CANN-internal library or sibling package
           (``data/first_party_licenses.yaml`` keys), matched on the canonical name
           or any alias, for the in-repo libs / package deps that carry no static
           URL (``platform``, ``metadef``, ``ge-compiler`` ...).

        ``None`` for everything else (``securec``/``libboundscheck``, the fetched
        OSS, Python deps, ``bisheng-compiler``) so the generic core classifies it
        third-party (has an upstream URL) or unknown."""
        for obs in component.observations:
            if _is_cann_org_url(getattr(obs, "canonical_url", None)):
                return "first-party"
        fp = _first_party_licenses()
        for name in (component.name, *component.aliases):
            if name.lower() in fp:
                return "first-party"
        return None

    # -- Condition vocabulary --------------------------------------------

    def condition_vocabulary(self) -> dict[str, object]:
        """Return the CANN condition tokens and their semantics."""
        return _condition_vocabulary()

    # -- Root classification (profile/config policy) ----------------------

    def classify_root(
        self,
        path: Path,
        cmake_project: Subject,
        package_context: dict,
    ) -> SubjectRole:
        """Classify a discovered standalone CMake root by path semantics.

        ``package_context`` may carry ``repo_root`` so the path is classified
        relative to the repo. Falls through to the existing role when no
        path-semantic rule matches (the generic ``cmake_project``/``unclassified``).
        """
        path = Path(path)
        repo_root = package_context.get("repo_root") if package_context else None
        rel_parts: tuple[str, ...]
        if repo_root is not None:
            try:
                rel_parts = path.resolve().relative_to(Path(repo_root).resolve()).parts
            except (ValueError, OSError):
                rel_parts = path.parts
        else:
            rel_parts = path.parts

        role = _classify_path(rel_parts)
        if role is not None:
            return role
        return cmake_project.role

    def root_exclusion_policy(self) -> set[SubjectRole]:
        """Policy-driven excluded roles.

        By default ``declared-all`` keeps every discovered root; the CANN policy
        excludes nothing automatically (the user opts in via ``--exclude-scope``).
        Non-distributable test roots stay in the document for ownership but are
        marked ``emit_as_subject=False`` by ``discover_subjects`` -- that is not an
        exclusion. Returning an empty set keeps omissions explicit.
        """
        return set()

    # -- Subject facets ---------------------------------------------------

    def subject_facets(self, subjects: list[Subject]) -> list[SubjectMerge]:
        """Bind co-located wheel/CMake roots into facets of one subject.

        Three merges (when both sides are present in ``subjects``):

        * wheel ``ascend_ops`` 1.0.0 absorbs CMake ``AscendOps`` 1.0.0 -- the
          CMake project becomes the ``build_graph_root_id`` / CMake facet of the
          wheel, so ``torch``/``torch_npu`` runtime deps and CMake link deps share
          one subject.
        * primary ``ops_math`` 9.0.0 absorbs CMake ``math`` 1.0.0 as a facet.
        * the ``npu_math_extension`` wheel keeps its own CMake build graph
          (``scripts/torch_extension``) as a facet/build_graph_root when a matching
          CMake root is present.

        Matching is by identity name/kind so it is robust to id spelling.
        """
        by_name_kind: dict[tuple[str, SubjectKind], Subject] = {}
        for s in subjects:
            by_name_kind[(s.identity.name, s.identity.kind)] = s

        merges: list[SubjectMerge] = []

        merges.extend(
            self._merge_pair(
                by_name_kind,
                wheel_name="ascend_ops",
                cmake_name="AscendOps",
            )
        )
        merges.extend(
            self._merge_pair(
                by_name_kind,
                wheel_name="ops_math",
                cmake_name="math",
                keep_kind=SubjectKind.CANN_PACKAGE,
            )
        )
        merges.extend(
            self._merge_pair(
                by_name_kind,
                wheel_name="npu_math_extension",
                cmake_name="npu_math_extension",
            )
        )

        return merges

    @staticmethod
    def _merge_pair(
        by_name_kind: dict[tuple[str, SubjectKind], Subject],
        *,
        wheel_name: str,
        cmake_name: str,
        keep_kind: SubjectKind = SubjectKind.PYTHON_WHEEL,
    ) -> list[SubjectMerge]:
        keep = by_name_kind.get((wheel_name, keep_kind))
        absorbed = by_name_kind.get((cmake_name, SubjectKind.CMAKE_PROJECT))
        if keep is None or absorbed is None or keep.id == absorbed.id:
            return []
        facet = Facet(
            kind=absorbed.identity.kind,
            name=absorbed.identity.name,
            version=absorbed.identity.version,
        )
        return [
            SubjectMerge(
                keep_subject_id=keep.id,
                absorbed_subject_id=absorbed.id,
                build_graph_root_id=absorbed.id,
                facet=facet,
            )
        ]
