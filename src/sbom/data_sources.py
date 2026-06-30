"""DataSource registry — a uniform handle on the tool's vendored data files.

A :class:`DataSource` names a vendored file (the generic OSS license map, the
depsdev cache, a profile's alias / first-party map), its ``kind``
(``curated`` | ``derived`` | ``network``) and the path it reads (and, for
refreshable kinds, writes). The generic core registers its own built-ins; a
profile contributes more — and may OVERRIDE/EXTEND a built-in by reusing its
``name`` — via :meth:`sbom.profile.Profile.data_sources`.

The registry exists so the rest of the tool can (a) merge a generic default with a
profile override (``known-licenses``, ``depsdev``) without the generic core
ever importing profile data — the profile *pushes* its sources through the hook —
and (b) drive ``--refresh-data`` uniformly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

#: Source kinds. ``curated`` = hand-authored domain knowledge (refresh validates
#: only); ``derived`` = machine-derivable (refresh suggests); ``network`` =
#: fetched from an external service (refresh re-fetches).
CURATED = "curated"
DERIVED = "derived"
NETWORK = "network"

_CORE_DATA = Path(__file__).parent / "data"


@dataclass(frozen=True)
class DataSource:
    """One vendored data file the tool reads (and may refresh)."""

    name: str  # "known-licenses" | "depsdev" | "aliases" | "first-party"
    kind: str  # CURATED | DERIVED | NETWORK
    path: Path  # the vendored file
    fmt: str = "yaml"  # "yaml" | "json"
    description: str = ""


def core_data_sources() -> list[DataSource]:
    """The generic core's built-in data files (usable for ANY repo/profile)."""
    return [
        DataSource(
            "known-licenses",
            CURATED,
            _CORE_DATA / "known_licenses.yaml",
            "yaml",
            "Generic OSS license map (license resolver layer 2).",
        ),
        DataSource(
            "depsdev",
            NETWORK,
            _CORE_DATA / "depsdev_cache.json",
            "json",
            "Vendored deps.dev/PyPI license+version snapshot.",
        ),
        DataSource(
            "clearlydefined",
            NETWORK,
            _CORE_DATA / "clearlydefined_cache.json",
            "json",
            "Vendored ClearlyDefined supplier/copyright/source snapshot.",
        ),
        DataSource(
            "deps-dir",
            DERIVED,
            _CORE_DATA / "deps_dir_cache.json",
            "json",
            "Vendored on-disk dependency-source license/copyright snapshot.",
        ),
    ]


def build_data_sources(profile: object | None) -> list[DataSource]:
    """Core built-ins followed by the active profile's contributed sources.

    A profile source whose ``name`` matches a core one is an override/extension:
    it is kept AFTER the core entry so map merges (core first, profile last) let
    the profile win on key conflicts, and the LAST entry is the refresh write
    target. Tolerant of a profile without the hook (stub profiles in tests)."""
    sources = list(core_data_sources())
    hook = getattr(profile, "data_sources", None)
    if callable(hook):
        try:
            extra = hook() or []
        except Exception:  # noqa: BLE001 - a profile hook must never crash the core
            extra = []
        sources.extend(s for s in extra if isinstance(s, DataSource))
    return sources


def sources_named(sources: list[DataSource], name: str) -> list[DataSource]:
    """All sources with ``name`` in precedence order (core first, profile last)."""
    return [s for s in sources if s.name == name]
