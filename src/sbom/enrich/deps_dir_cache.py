"""Deps-dir source cache — a vendored snapshot of on-disk dependency-source scans.

A ``--refresh-data deps-dir --deps-dir <tree>`` run resolves each dependency's
license + copyright from its REAL source on disk (the cann-src-third-party git
mirrors, plus any plain dirs / archives) and writes them to this JSON file carried
in the repo. This module reads that file and applies it as an OFFLINE license +
copyright layer that runs ALWAYS — so a normal run (NO ``--deps-dir``) still gets
accurate, real-source C++ licenses for the seeded long tail that the Python-centric
``depsdev`` / ``clearlydefined`` caches miss. Only the refresh path writes.

This is the durable, committed counterpart of the live :mod:`sbom.enrich.deps_dir`
resolver: the live path handles new/unseeded deps when ``--deps-dir`` is given; the
cache makes the same data available without the source tree present.

File format (machine-written, sorted keys for stable diffs)::

    {
      "schema": 1,
      "entries": {
        "eigen": {"license": "MPL-2.0", "copyright": "Copyright (c) ...",
                  "version": "5.0.0", "source": "deps-dir git branch 5.0.0.x",
                  "fetched": "2026-06-28"}
      }
    }

Keys are the lowercased component name (deps-dir spans ANY ecosystem, not just
PyPI, so keys are NOT ecosystem-prefixed). Unlike :mod:`sbom.enrich.depsdev_cache`
this is NOT Python-only — it is the primary offline license source for C++ deps.
A profile's first-party supplier still overrides nothing here (the cache carries
no supplier); reconcile's supplier resolver is unaffected.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Component, Provenance, Warning

_SCHEMA = 1


def cache_key(name: str) -> str:
    """The cache key for a component name (lowercased; ecosystem-agnostic)."""
    return name.strip().lower()


def load(paths) -> dict[str, dict]:
    """Merge the cache files in ``paths`` (later wins). Missing/corrupt files are
    skipped silently — a vendored cache is an optimization, never a hard input."""
    merged: dict[str, dict] = {}
    for p in paths:
        if not p:
            continue
        try:
            data = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        entries = data.get("entries") if isinstance(data, dict) else None
        if isinstance(entries, dict):
            for key, rec in entries.items():
                if isinstance(rec, dict):
                    merged[str(key)] = rec
    return merged


def apply(components: list[Component], cache: dict[str, dict]) -> list[Warning]:
    """Fill each component's still-unset license + copyright from ``cache``.

    Alias-aware: a component is matched by its name OR any alias (lowercased), so a
    ``securec`` component resolves a ``libboundscheck``-keyed entry and vice versa.
    Fills only unset fields — curated / known-map values set by higher layers are
    never overridden. Records ``Provenance(source="deps-dir-cache")``."""
    if not cache:
        return []
    for comp in components:
        entry = None
        for cand in (comp.name, *comp.aliases):
            entry = cache.get(cache_key(cand))
            if entry:
                break
        if not entry:
            continue
        if comp.license is None and entry.get("license"):
            comp.license = entry["license"]
            comp.provenance.append(Provenance(field="license", source="deps-dir-cache"))
        if comp.copyright is None and entry.get("copyright"):
            comp.copyright = entry["copyright"]
            comp.provenance.append(Provenance(field="copyright", source="deps-dir-cache"))
    return []


def dump(entries: dict[str, dict]) -> str:
    """Serialize a cache file deterministically (sorted keys, trailing newline)."""
    payload = {"schema": _SCHEMA, "entries": entries}
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
