"""ClearlyDefined enricher — curated component metadata for the NTIA gaps.

`ClearlyDefined <https://clearlydefined.io>`_ (a Linux Foundation / OSI
initiative) harvests + curates per-component metadata keyed by *coordinates*
``<type>/<provider>/<namespace>/<name>/<revision>`` (e.g.
``pypi/pypi/-/numpy/1.26.0``). Its API returns a declared license, attribution /
copyright parties, and the source location. We use it to fill the **Supplier**
(NTIA) and **copyright** elements for THIRD-PARTY components — license is already
resolved by the dedicated layers, so it is not re-applied here.

Same vendored-snapshot pattern as :mod:`sbom.enrich.depsdev_cache`: a JSON cache
(``clearlydefined_cache.json``) is consulted ALWAYS (offline + online); only
``--refresh-data clearlydefined`` writes it. Two coordinate kinds:

* **PyPI** (Python deps) -> ``pypi/pypi/-/<name>/<rev>``, keyed ``pypi:<name>``.
* **C++ third-party** with a curated upstream coordinate (``third_party_purls.yaml``
  ``pkg:github|gitlab/<org>/<name>``) -> ``git/<host>/<org>/<name>/<sha>`` (the
  version TAG is resolved to a commit SHA via ``git ls-remote``, since CD harvests
  C++ under a SHA), keyed ``<host>:<org>/<name>``. This gives C++ a copyright
  source INDEPENDENT of the (optional, may-disappear) repo Notice; supplier rides
  along (= the org). License is owned by the dedicated layers and not re-applied.

File format (sorted keys)::

    {"schema": 1, "entries": {
        "pypi:numpy": {"supplier": "numpy", "copyright": "Copyright (c) ...", ...},
        "github:protocolbuffers/protobuf": {"supplier": "protocolbuffers",
            "copyright": "Copyright (c) 2016 Google; ...",
            "coordinates": "git/github/protocolbuffers/protobuf/<sha>",
            "fetched": "2026-06-28"}}}
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

from packageurl import PackageURL

from ..models import Component, Provenance, Warning, python_direct_reference

_SCHEMA = 1
API_BASE = "https://api.clearlydefined.io/definitions"
_ALLOWED_HOST = "api.clearlydefined.io"
_TIMEOUT = 30
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
#: How many attribution parties to fold into a copyright string.
_MAX_PARTIES = 5
#: PURL type -> git host base, for the C++ tag->SHA lookup. Only registered VCS
#: hosts whose coordinates ClearlyDefined harvests under ``git/<provider>/...``.
_GIT_HOSTS = {"github": "https://github.com", "gitlab": "https://gitlab.com"}


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _coord_from_purl(coord_purl: str):
    """Parse a curated upstream coordinate (``pkg:github/org/name``), or None."""
    try:
        return PackageURL.from_string(coord_purl)
    except (ValueError, TypeError):
        return None


def component_key(component: Component, purl_map: dict | None = None) -> str | None:
    """The cache key for a component, or ``None``.

    PyPI Python deps -> ``pypi:<pep503>``. A C++ third-party with a curated upstream
    coordinate (``purl_map`` from ``third_party_purls.yaml``) -> ``<host>:<org>/<name>``
    (e.g. ``github:protocolbuffers/protobuf``) so its ClearlyDefined entry (keyed by
    git host/org/name) is matchable offline without needing the SHA."""
    if "Python" in (component.languages or []):
        # A direct/VCS reference is not a PyPI-registry package -> no pypi: key,
        # so it never matches a same-named pypi: ClearlyDefined entry.
        if python_direct_reference(component) is not None:
            return None
        return f"pypi:{_pep503(component.name)}"
    if purl_map:
        for name in (component.name, *component.aliases):
            coord = purl_map.get(name.lower())
            if not coord:
                continue
            base = _coord_from_purl(coord)
            if base and base.type in _GIT_HOSTS and base.namespace:
                return f"{base.type}:{base.namespace}/{base.name}"
    return None


def coordinates_for(component: Component, version: str | None) -> str | None:
    """ClearlyDefined PyPI coordinates for a Python component, or ``None``.

    ``pypi/pypi/-/<name>/<revision>`` — a revision is required, so a component with
    no concrete/resolved version yields ``None``. (C++ uses :func:`git_coordinates`,
    which must resolve a git SHA.)"""
    if "Python" not in (component.languages or []):
        return None
    if not version:
        return None
    return f"pypi/pypi/-/{_pep503(component.name)}/{version}"


def git_coordinates(coord_purl: str, version: str | None) -> str | None:
    """Resolve a curated ``pkg:github|gitlab/org/name`` + version tag into a
    ClearlyDefined git coordinate ``git/<host>/<org>/<name>/<sha>``, or ``None``.

    ClearlyDefined harvests C++ libs under a git COMMIT SHA (not a version tag), so
    the version is resolved to a SHA via ``git ls-remote`` (trying ``v<version>``
    then ``<version>``). Network + the ``git`` binary required (refresh-time only)."""
    import subprocess

    if not version:
        return None
    base = _coord_from_purl(coord_purl)
    if base is None or base.type not in _GIT_HOSTS or not base.namespace:
        return None
    git_url = f"{_GIT_HOSTS[base.type]}/{base.namespace}/{base.name}"
    for ref in (f"refs/tags/v{version}", f"refs/tags/{version}"):
        try:
            out = subprocess.run(
                ["git", "ls-remote", git_url, ref],
                capture_output=True, text=True, timeout=_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        line = out.stdout.strip().split("\n", 1)[0]
        if line:
            sha = line.split()[0]
            return f"git/{base.type}/{base.namespace}/{base.name}/{sha}"
    return None


# ---------------------------------------------------------------------------
# HTTP (injectable for tests; SSRF-guarded to api.clearlydefined.io over https)
# ---------------------------------------------------------------------------

_http_get: Callable[[str], str] | None = None


def set_http_get(fn: Callable[[str], str] | None) -> None:
    """Inject an HTTP GET (tests mock this; never a live call in CI)."""
    global _http_get  # noqa: PLW0603
    _http_get = fn


def _default_http_get(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != _ALLOWED_HOST:
        raise ValueError(f"refusing non-allowlisted URL: {url}")
    req = urllib.request.Request(
        url, headers={"User-Agent": "sbom-gen/0.1 (+clearlydefined enricher)"}
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
        return resp.read(_MAX_RESPONSE_BYTES + 1).decode("utf-8", "replace")


def _get(url: str) -> str:
    return (_http_get or _default_http_get)(url)


# ---------------------------------------------------------------------------
# Live resolve (used by --refresh-data clearlydefined)
# ---------------------------------------------------------------------------


def resolve(coordinates: str) -> dict | None:
    """Live ClearlyDefined lookup for ``coordinates`` -> extracted dict, or None."""
    try:
        body = _get(f"{API_BASE}/{coordinates}")
        data = json.loads(body)
    except Exception:  # noqa: BLE001 - any network/parse error -> miss
        return None
    return _extract(data) if isinstance(data, dict) else None


#: Real VCS hosts whose ``sourceLocation.namespace`` is a genuine org (a clean
#: supplier). Registry providers (``pypi``/``npm``/...) carry no org namespace.
_GIT_PROVIDERS = {"github", "gitlab", "gitee", "bitbucket", "gitcode"}
#: A well-formed copyright line: ``Copyright [(c)] <year(s)> <entity>``. CD's
#: auto-scanned ``parties`` are noisy ("(c) N Revealed", "Stone Tickle", a bare
#: "Copyright 2026"); require a year FOLLOWED BY an alphabetic entity so we keep
#: only real copyright statements and never assert garbage / entity-less lines.
_COPYRIGHT_RE = re.compile(r"(?i)copyright\s*(?:\(c\)|©)?\s*,?\s*\d{4}[\d,\s.–-]*[A-Za-z]")


def _extract(data: dict) -> dict | None:
    """Extract ONLY clean signals from a ClearlyDefined definition.

    Supplier comes from a real VCS org namespace; copyright from well-formed
    ``Copyright <year> ...`` lines (the noisy auto-scan fragments are dropped).
    For PyPI coordinates CD usually has neither, so a definition often yields just
    its declared license (which the dedicated license layers, not this, apply)."""
    licensed = data.get("licensed") or {}
    described = data.get("described") or {}
    source = described.get("sourceLocation") or {}

    supplier = None
    if source.get("namespace") and source.get("provider") in _GIT_PROVIDERS:
        supplier = source["namespace"]

    parties = (
        ((licensed.get("facets") or {}).get("core") or {}).get("attribution") or {}
    ).get("parties") or []
    clean: list[str] = []
    for party in parties:
        s = str(party).strip()
        if _COPYRIGHT_RE.search(s) and s not in clean:
            clean.append(s)
    copyright_ = "; ".join(clean[:_MAX_PARTIES]) or None

    src_url = source.get("url") or described.get("projectWebsite") or None
    declared = licensed.get("declared")

    out: dict = {}
    if supplier:
        out["supplier"] = supplier
    if copyright_:
        out["copyright"] = copyright_
    if src_url:
        out["source"] = src_url
    if declared and declared not in ("NOASSERTION", "OTHER", "NONE"):
        out["license"] = declared
    return out or None


# ---------------------------------------------------------------------------
# Cache load / apply / dump
# ---------------------------------------------------------------------------


def load(paths) -> dict[str, dict]:
    """Merge cache files (later wins); missing/corrupt skipped."""
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


def apply(
    components: list[Component],
    cache: dict[str, dict],
    purl_map: dict | None = None,
) -> list[Warning]:
    """Fill third-party **supplier** + **copyright** from the cache (if unset).

    License is owned by the dedicated license layers and is NOT re-applied here.
    Matches PyPI components by name and C++ third-party by their curated upstream
    coordinate (``purl_map`` from ``third_party_purls.yaml``) — see
    :func:`component_key`."""
    if not cache:
        return []
    for comp in components:
        key = component_key(comp, purl_map)
        if not key:
            continue
        entry = cache.get(key)
        if not entry:
            continue
        if comp.supplier is None and entry.get("supplier"):
            comp.supplier = entry["supplier"]
            comp.provenance.append(Provenance(field="supplier", source="clearlydefined"))
        if comp.copyright is None and entry.get("copyright"):
            comp.copyright = entry["copyright"]
            comp.provenance.append(Provenance(field="copyright", source="clearlydefined"))
    return []


def dump(entries: dict[str, dict]) -> str:
    """Serialize a cache file deterministically (sorted keys, trailing newline)."""
    return json.dumps({"schema": _SCHEMA, "entries": entries}, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
