"""Network-result cache — a vendored snapshot of deps.dev/PyPI lookups.

A previous ``--refresh-data depsdev`` run resolves each Python dependency's
license (and the version it resolved) and writes it to a JSON file carried in the
repo. This module reads that file and applies it as a license layer that runs
ALWAYS — offline and online — so a normal run reuses the snapshot instead of (or
before) hitting the network. Only the refresh path writes; normal runs read.

File format (machine-written, sorted keys for stable diffs)::

    {
      "schema": 1,
      "entries": {
        "pypi:numpy": {"license": "BSD-3-Clause", "version": "2.1.0",
                       "source": "deps.dev/pypi/numpy", "fetched": "2026-06-28"}
      }
    }

Keys are ``<ecosystem>:<pep503-name>`` (only ``pypi`` is wired up today, mirroring
:mod:`sbom.enrich.net`). We apply **license + supplier** (the latter from PyPI
``info.author``/``maintainer``, written by ``--refresh-data depsdev``);
version/source/fetched are recorded for provenance and refresh bookkeeping. A
profile's first-party supplier still overrides this for first-party components
(reconcile runs ``_resolve_suppliers`` last).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Component, Provenance, Warning, python_direct_reference

_SCHEMA = 1


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def cache_key(name: str, ecosystem: str = "pypi") -> str:
    """The cache key for a component name (ecosystem-prefixed, PEP 503 normalized)."""
    return f"{ecosystem}:{_pep503(name)}"


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


def _is_python(comp: Component) -> bool:
    return "Python" in (comp.languages or [])


def apply(components: list[Component], cache: dict[str, dict]) -> list[Warning]:
    """Fill each PYTHON component's still-unset license + supplier from ``cache``.

    Python-only for the same reason as :mod:`sbom.enrich.net`: PyPI is the only
    ecosystem wired up, so matching a C++ component by name would attribute a
    coincidentally same-named PyPI package's metadata. Fills only unset fields; the
    profile's first-party supplier overrides this later (reconcile). The recorded
    ``version`` is a dynamic network resolution left out of the component's static
    version (it stays informational in the cache)."""
    if not cache:
        return []
    for comp in components:
        if not _is_python(comp) or python_direct_reference(comp) is not None:
            continue  # not a PyPI-registry package -> no pypi-keyed enrichment
        entry = cache.get(cache_key(comp.name))
        if not entry:
            continue
        if comp.license is None and entry.get("license"):
            comp.license = entry["license"]
            comp.provenance.append(Provenance(field="license", source="depsdev"))
        if comp.supplier is None and entry.get("supplier"):
            comp.supplier = entry["supplier"]
            comp.provenance.append(Provenance(field="supplier", source="depsdev"))
    return []


def dump(entries: dict[str, dict]) -> str:
    """Serialize a cache file deterministically (sorted keys, trailing newline)."""
    payload = {"schema": _SCHEMA, "entries": entries}
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
