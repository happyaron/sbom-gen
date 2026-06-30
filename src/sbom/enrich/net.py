"""Network enricher (layer 4, opt-in).

Fetches license and version metadata from:
- **deps.dev** (https://deps.dev) — primary source for both Python and C++
  packages (PyPI ecosystem).
- **PyPI JSON API** (https://pypi.org/pypi/<name>/json) — fallback / extra
  detail for Python packages.

Only active when ``config.network == "on"``.  No live calls are made in unit
tests; the network I/O is isolated behind :data:`_http_get` so tests can
inject a mock.

C++ note: the design mentions downloading the archive and scanning its license
file when network is on.  That behaviour is architecturally separate from the
deps.dev lookup and is deferred to the archive-download path (not yet
implemented); this module covers the metadata-API path.

A network-computed sha256 is recorded under ``checksums["network_sha256"]``
and is NEVER equated to a checked-in URL_HASH (by design).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Callable

from ..models import Component, Provenance, Warning, python_direct_reference

if TYPE_CHECKING:  # pragma: no cover
    from ..config import Config

# ---------------------------------------------------------------------------
# Injection point for mocking (no live calls in unit tests)
# ---------------------------------------------------------------------------

#: Replaceable HTTP GET function.  Receives a URL string and returns the
#: decoded response body as ``str``, or raises ``urllib.error.URLError`` /
#: ``ValueError`` on failure.  Tests replace this with a mock/fake.
_http_get: Callable[[str], str] = None  # type: ignore[assignment]


#: Only these hosts (and their subdomains) are queried, over https. A 3xx that
#: would redirect off-host -- via a compromised intermediary -- is rejected so the
#: enricher can't be steered to an internal/arbitrary target (SSRF). 8 MiB caps a
#: hostile/oversized body (scipy's per-version JSON is ~90 KB; the cap is generous).
_ALLOWED_HOSTS = ("deps.dev", "pypi.org")
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def _host_allowed(url: str) -> bool:
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https":
        return False
    host = (u.hostname or "").lower()
    return any(host == h or host.endswith("." + h) for h in _ALLOWED_HOSTS)


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    """Allow a redirect only to an https URL on an allowed host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _host_allowed(newurl):
            raise urllib.error.HTTPError(
                newurl, code, "redirect to disallowed host blocked", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_GuardedRedirect())


def _default_http_get(url: str) -> str:
    if not _host_allowed(url):
        raise urllib.error.URLError(f"refusing non-allowed URL: {url!r}")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "sbom-gen/0.1 (https://github.com/cann/sbom-gen)"},
    )
    with _OPENER.open(req, timeout=15) as resp:  # noqa: S310
        if not _host_allowed(resp.geturl()):
            raise urllib.error.URLError("response landed on a disallowed host")
        data = resp.read(_MAX_RESPONSE_BYTES + 1)
    if len(data) > _MAX_RESPONSE_BYTES:
        raise ValueError("response exceeds size cap")
    return data.decode("utf-8", errors="replace")


def _get_http(url: str) -> str:
    """Call the currently-installed HTTP GET function."""
    getter = _http_get if _http_get is not None else _default_http_get
    return getter(url)


def set_http_get(fn: Callable[[str], str] | None) -> None:
    """Replace the HTTP GET implementation (used by tests to inject a mock).

    Pass ``None`` to restore the default ``urllib``-based implementation.
    """
    global _http_get  # noqa: PLW0603
    _http_get = fn  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# deps.dev API
# ---------------------------------------------------------------------------

_DEPSDEV_BASE = "https://deps.dev/_/s"


def _depsdev_url(ecosystem: str, name: str, version: str | None = None) -> str:
    """Build a deps.dev package-info URL.

    Example: ``https://deps.dev/_/s/pypi/p/numpy`` or
    ``https://deps.dev/_/s/pypi/p/numpy/v/1.26.0``.
    """
    enc_name = urllib.parse.quote(name, safe="")
    if version:
        enc_ver = urllib.parse.quote(version, safe="")
        return f"{_DEPSDEV_BASE}/{ecosystem}/p/{enc_name}/v/{enc_ver}"
    return f"{_DEPSDEV_BASE}/{ecosystem}/p/{enc_name}"


def _fetch_depsdev(
    ecosystem: str, name: str, version: str | None = None
) -> dict | None:
    """Fetch package metadata from deps.dev; return parsed JSON or ``None``."""
    url = _depsdev_url(ecosystem, name, version)
    try:
        body = _get_http(url)
        return json.loads(body)
    except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError):
        return None


#: Tokens an upstream API returns to mean "no recognized license", NOT a license.
#: deps.dev emits ``non-standard`` for any license its scanner can't reduce to a
#: clean SPDX id; treating it as a license masks the real one (and never falls
#: through to the PyPI classifier path that would resolve it).
_NON_LICENSE_TOKENS = {"non-standard", "noassertion", "unknown", "none", "null", ""}


def _clean_license_token(tok: object) -> str | None:
    """Return ``tok`` as a license string, or ``None`` if it is a non-license."""
    if tok is None:
        return None
    s = str(tok).strip()
    if not s or s.lower() in _NON_LICENSE_TOKENS:
        return None
    return s


def _join_licenses(values) -> str | None:
    """Join the real license tokens in ``values`` (sentinels dropped) with AND."""
    clean = [c for c in (_clean_license_token(v) for v in values) if c]
    return " AND ".join(clean) if clean else None


def _resolved_version_depsdev(data: dict) -> str | None:
    """The concrete version deps.dev resolved (its default/latest), if any.

    Used to turn an UNPINNED PyPI fallback into a version-specific query: the
    bare ``/pypi/<name>/json`` endpoint returns every release + every file
    (multi-MB for scipy/numpy/tensorflow — slow and timeout-prone), whereas
    ``/pypi/<name>/<version>/json`` is ~90 KB and carries the same classifiers.
    """
    if not isinstance(data, dict):
        return None
    ver = data.get("defaultVersion")
    if isinstance(ver, str) and ver:
        return ver
    vd = data.get("version")
    vd = vd if isinstance(vd, dict) else {}
    vk = vd.get("versionKey")
    vk = vk if isinstance(vk, dict) else {}
    for candidate in (vd.get("version"), vk.get("version")):
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def _extract_license_depsdev(data: dict) -> str | None:
    """Extract the SPDX license expression from a deps.dev response.

    deps.dev's ``non-standard`` sentinel (and other non-license tokens) are
    dropped, so a package whose license metadata isn't a clean SPDX id falls
    through to the PyPI classifier path rather than being labelled ``non-standard``.
    """
    # Untrusted response: every level is type-guarded so a malformed/redirected
    # body degrades to None rather than raising (which would abort reconcile).
    if not isinstance(data, dict):
        return None
    # deps.dev returns licenses at different paths depending on the API version.
    # v3 alpha: data["version"]["licenses"] = ["MIT", ...]
    vd = data.get("version")
    version_data = vd if isinstance(vd, dict) else data
    licenses = version_data.get("licenses") or version_data.get("license")
    if isinstance(licenses, list) and licenses:
        return _join_licenses(licenses)
    if isinstance(licenses, str):
        return _clean_license_token(licenses)
    # Older/alternate shape: data["package"]["versions"][0]["licenses"]
    for pkg_key in ("package", "packageKey"):
        pkg = data.get(pkg_key)
        if not isinstance(pkg, dict):
            continue
        versions = pkg.get("versions")
        for ver_entry in versions if isinstance(versions, list) else []:
            if not isinstance(ver_entry, dict):
                continue
            lics = ver_entry.get("licenses")
            if isinstance(lics, list) and lics:
                joined = _join_licenses(lics)
                if joined:
                    return joined
    return None


# ---------------------------------------------------------------------------
# PyPI JSON API
# ---------------------------------------------------------------------------

_PYPI_BASE = "https://pypi.org/pypi"


def _pypi_url(name: str, version: str | None = None) -> str:
    enc_name = urllib.parse.quote(name, safe="")
    if version:
        enc_ver = urllib.parse.quote(version, safe="")
        return f"{_PYPI_BASE}/{enc_name}/{enc_ver}/json"
    return f"{_PYPI_BASE}/{enc_name}/json"


def _fetch_pypi(name: str, version: str | None = None) -> dict | None:
    """Fetch package metadata from PyPI JSON API; return parsed JSON or ``None``."""
    url = _pypi_url(name, version)
    try:
        body = _get_http(url)
        return json.loads(body)
    except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError):
        return None


def _extract_license_pypi(data: dict) -> str | None:
    """Extract the license string from a PyPI JSON response (untrusted: every
    level is type-guarded so a malformed body returns None instead of raising)."""
    if not isinstance(data, dict):
        return None
    info = data.get("info")
    if not isinstance(info, dict):
        return None
    # Prefer classifiers over the bare 'license' field (more structured).
    classifiers = info.get("classifiers")
    if not isinstance(classifiers, list):
        classifiers = []
    spdx_ids = []
    for clf in classifiers:
        if isinstance(clf, str) and clf.startswith("License :: OSI Approved ::"):
            # e.g. "License :: OSI Approved :: MIT License"
            parts = clf.split("::")
            if len(parts) >= 3:
                label = parts[-1].strip()
                # Map common labels to SPDX ids
                spdx = _PYPI_CLASSIFIER_TO_SPDX.get(label)
                if spdx:
                    spdx_ids.append(spdx)
                elif label:
                    spdx_ids.append(label)
    if spdx_ids:
        return " AND ".join(sorted(set(spdx_ids)))
    # Fall back to the bare 'license' field — but reject sentinels and a full
    # license TEXT (PyPI's `license` is often the entire license body, e.g.
    # scipy/numpy, which must not become a license id; the classifier path above
    # already covers those, and an unresolved id is better than a 2 KB blob).
    lic = _clean_license_token(info.get("license"))
    if lic and "\n" not in lic and len(lic) <= 64:
        return lic
    return None


# Common PyPI classifier label → SPDX id mapping (non-exhaustive).
_PYPI_CLASSIFIER_TO_SPDX: dict[str, str] = {
    "MIT License": "MIT",
    "BSD License": "BSD-3-Clause",
    "BSD 2-Clause \"Simplified\" License": "BSD-2-Clause",
    "BSD 3-Clause \"New\" or \"Revised\" License": "BSD-3-Clause",
    "Apache Software License": "Apache-2.0",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "ISC License (ISCL)": "ISC",
    "The Unlicense (Unlicense)": "Unlicense",
    "Public Domain": "Unlicense",
    "Python Software Foundation License": "PSF-2.0",
}


# ---------------------------------------------------------------------------
# Language detection helpers
# ---------------------------------------------------------------------------

def _is_python_component(comp: Component) -> bool:
    """Return True if the component has any Python observations."""
    return any(lang.lower() == "python" for lang in comp.languages) or any(
        obs.source_kind.value.startswith("python")
        for obs in comp.observations
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resolve_pypi(name: str, version: str | None = None) -> dict | None:
    """Live deps.dev + PyPI lookup for one PyPI package, or ``None``.

    Returns ``{"license": <spdx>, "version": <resolved>, "source": <url tag>}`` —
    no component mutation and no "already set" guard. This is the building block
    for ``--refresh-data depsdev`` (which (re-)fetches regardless of any
    existing value); :func:`apply` is the normal-run path that only FILLS unset
    licenses.

    A supplied ``version`` is tried first, but if it yields nothing it is RETRIED
    version-less (latest/default). A Python component that shares its name with a
    C++ one can carry the C++ version (e.g. ``protobuf`` 25.1, which has no PyPI
    release), and some version-specific endpoints lack license classifiers — the
    fallback resolves both rather than reporting a spurious miss."""
    result = _resolve_pypi_once(name, version)
    if result is None and version is not None:
        result = _resolve_pypi_once(name, None)
    return result


def pypi_supplier(name: str, version: str | None = None) -> str | None:
    """The PyPI ``author`` (or ``maintainer``) for a package — a clean NTIA Supplier
    when present, else ``None``. Sparse for modern packages that put authorship in
    ``author_email`` / project metadata rather than the flat ``author`` field."""
    data = _fetch_pypi(name, version)
    info = (data or {}).get("info") or {}
    for key in ("author", "maintainer"):
        value = (info.get(key) or "").strip()
        if value:
            return value
    return None


def _resolve_pypi_once(name: str, version: str | None) -> dict | None:
    data = _fetch_depsdev("pypi", name, version)
    if data is not None:
        spdx_expr = _extract_license_depsdev(data)
        resolved_version = version or _resolved_version_depsdev(data)
        if spdx_expr:
            return {
                "license": spdx_expr,
                "version": resolved_version,
                "source": f"deps.dev/pypi/{name}",
            }
        if version is None:
            version = _resolved_version_depsdev(data)

    pypi_data = _fetch_pypi(name, version)
    if pypi_data is not None:
        spdx_expr = _extract_license_pypi(pypi_data)
        if spdx_expr:
            return {
                "license": spdx_expr,
                "version": version,
                "source": f"pypi.org/{name}",
            }
    return None

def apply(components: list[Component], config: "Config") -> list[Warning]:
    """Fetch license/version metadata from deps.dev and PyPI (opt-in).

    No-op when ``config.network != "on"``.

    For each PYTHON component whose ``license`` is not yet set: query the deps.dev
    PyPI ecosystem, falling back to the PyPI JSON API.

    Non-Python components are deliberately SKIPPED: the only ecosystem wired up is
    PyPI, and querying it by name for a C++/CANN component (``dlog``, ``securec``,
    …) attributes the license of a coincidentally same-named PyPI package — a
    false positive. Proper C++ ecosystem support is a future task; until then a
    non-Python component is left ``None`` (→ NOASSERTION) rather than guessed.

    A network-resolved sha256 is stored under ``checksums["network_sha256"]``
    and is NEVER equated to a checked-in ``URL_HASH``.
    """
    warnings: list[Warning] = []

    network = getattr(config, "network", "off")
    if network != "on":
        return warnings

    for comp in components:
        if comp.license is not None:
            continue
        if not _is_python_component(comp) or python_direct_reference(comp) is not None:
            continue  # not a PyPI-registry package -> skip deps.dev/PyPI enrichment

        version = comp.effective_version or comp.source_version

        # -- Try deps.dev first (PyPI ecosystem) --
        depsdev_data = _fetch_depsdev("pypi", comp.name, version)
        if depsdev_data is not None:
            spdx_expr = _extract_license_depsdev(depsdev_data)
            if spdx_expr:
                comp.license = spdx_expr
                comp.provenance.append(
                    Provenance(field="license", source=f"deps.dev/pypi/{comp.name}")
                )
                continue
            # deps.dev knew the package but not a clean license. Borrow the version
            # it resolved so the PyPI fallback hits the SMALL version-specific
            # endpoint rather than the multi-MB full-package JSON (scipy's
            # /pypi/scipy/json is multi-MB and times out non-deterministically).
            if version is None:
                version = _resolved_version_depsdev(depsdev_data)

        # -- Fall back to the PyPI JSON API (classifier-based SPDX ids) ------
        pypi_data = _fetch_pypi(comp.name, version)
        if pypi_data is not None:
            spdx_expr = _extract_license_pypi(pypi_data)
            if spdx_expr:
                comp.license = spdx_expr
                comp.provenance.append(
                    Provenance(field="license", source=f"pypi.org/{comp.name}")
                )
                continue

        # -- Unresolved after network lookup ---------------------------------
        warnings.append(
            Warning(
                code="license_unresolved",
                subject=comp.name,
                detail="network lookup (deps.dev + PyPI) did not return a license",
            )
        )

    return warnings
