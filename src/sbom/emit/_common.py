"""Shared helpers for the CycloneDX and SPDX emitters.

Kept separate from ``emit/__init__.py`` (which holds the frozen ``EmitOptions``
contract) so the emitters can share license/timestamp/identity logic without
touching the contract module.
"""

from __future__ import annotations

import datetime
import hashlib
import re
from collections import Counter

from packageurl import PackageURL

from ..models import Component, Document, RefKind, Subject, python_direct_reference
from .. import graph
from . import EmitOptions

#: Namespace prefix for all custom CycloneDX properties / SPDX annotation keys.
#: Tool-owned (named after this tool, not any repo); used for all repos,
#: including generic ones.
PROP_NS = "sbomgen"

TOOL_VENDOR = "cann"
TOOL_NAME = "sbom-gen"

# Fixed fallback timestamp for reproducible mode when no source_date_epoch is
# given (the Unix epoch, UTC).
_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def _safe_basename(name: str) -> str:
    """A filesystem-safe basename: only ``[A-Za-z0-9._-]``, no leading/trailing
    separators, never empty. Strips path separators, ``..`` and absolute-path
    leaders so the value can never escape a directory when used as a filename."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")
    return safe or "subject"


def split_output_basenames(subject_ids: list[str]) -> dict[str, str]:
    """Map each subject id to a UNIQUE, filesystem-safe basename for a per-subject
    split output file.

    Subject ids come from package/CMake metadata and are NOT trusted as filenames:
    a raw ``../escaped`` id would otherwise write outside the output dir.
    :func:`_safe_basename` neutralizes separators/``..``/absolute paths; bases that
    then collide (two ids sanitizing to the same name) are disambiguated with a
    short stable hash of the original id, deterministically."""
    bases = {sid: _safe_basename(sid) for sid in subject_ids}
    counts = Counter(bases.values())
    out: dict[str, str] = {}
    for sid in subject_ids:
        base = bases[sid]
        if counts[base] > 1:
            base = f"{base}-{hashlib.sha256(sid.encode('utf-8')).hexdigest()[:8]}"
        out[sid] = base
    return out


def subject_closure_document(document: Document, subject: Subject) -> Document:
    """Return a NEW Document restricted to *subject* + its dependency closure.

    A per-subject split BOM must contain ONLY the components reachable from that
    subject (BFS over the edge graph), not every component in the combined
    document — otherwise app1's split BOM leaks app2's exclusive dependencies.
    Edges and environment tools are filtered to the kept nodes. Mirrors the
    closure ``reconcile`` applies for ``--subjects``. Component objects are shared
    (emit reads them read-only); the original document is not mutated.
    """
    reachable = graph.reachable_components(document.edges, [subject.id])

    def _kept(kind: RefKind, ident: str) -> bool:
        return ident == subject.id if kind is RefKind.SUBJECT else ident in reachable

    return Document(
        subjects=[subject],
        components=[c for c in document.components if c.name in reachable],
        edges=[
            e
            for e in document.edges
            if _kept(e.from_ref.kind, e.from_ref.id) and _kept(e.to_ref.kind, e.to_ref.id)
        ],
        environment_tools=[
            t
            for t in document.environment_tools
            if t.root_artifact_id is None or t.root_artifact_id == subject.id
        ],
        warnings=document.warnings,
        metadata=document.metadata,
    )

# A pragmatic SPDX-license-expression recognizer. The license-expression library
# does the authoritative parsing, but importing it lazily keeps the emitters
# light; this regex screens obvious non-SPDX strings (e.g. full license names,
# "CANN Open Software License 2.0") so they route to LicenseRef/text instead.
_SPDX_TOKEN = re.compile(
    r"^[A-Za-z0-9.\-+()\s]+$"
)


def reproducible_timestamp(options: EmitOptions) -> datetime.datetime | None:
    """Return the timestamp to stamp, or ``None`` to use the library default.

    In reproducible mode a fixed timestamp is required: ``source_date_epoch`` if
    provided, else the Unix epoch. Otherwise ``None`` (caller leaves the default,
    typically wall-clock now).
    """
    if not options.reproducible:
        if options.source_date_epoch is not None:
            return datetime.datetime.fromtimestamp(
                options.source_date_epoch, tz=datetime.timezone.utc
            )
        return None
    if options.source_date_epoch is not None:
        return datetime.datetime.fromtimestamp(
            options.source_date_epoch, tz=datetime.timezone.utc
        )
    return _EPOCH


def select_subjects(
    subjects: list[Subject], wanted_ids: list[str] | None
) -> list[Subject]:
    """Filter ``subjects`` to ``wanted_ids`` (preserving order); ``None`` = all."""
    if wanted_ids is None:
        return list(subjects)
    wanted = set(wanted_ids)
    return [s for s in subjects if s.id in wanted]


def disambiguate_subject_ids(subjects: list[Subject]) -> dict[int, str]:
    """Map each subject object to a UNIQUE, slug-stable emitted id.

    Distinct discovered roots can share a ``Subject.id`` (e.g. ~62 same-named
    ``project(Runtime_Sample)`` example roots) or slugify to the same SPDX
    id/CycloneDX bom-ref. Emitting them verbatim produces duplicate
    ``SPDXRef-Subject-*`` ids (invalid SPDX) and colliding CycloneDX bom-refs.

    This walks the subjects in their stable discovery order and, for each, derives
    the base emitted id from ``subject.id``; the FIRST subject claiming a base id
    keeps it, and every later collision gets a deterministic ``-<n>`` suffix
    (``Runtime_Sample``, ``Runtime_Sample-2``, …). The result is keyed by
    ``id(subject)`` so each subject object resolves to its own unique id even when
    two subjects compare equal on ``Subject.id``. Callers slugify the returned id
    for the format-specific ref. Deterministic because discovery order is stable.
    """
    used: dict[str, int] = {}
    out: dict[int, str] = {}
    for subject in subjects:
        base = subject.id
        # Disambiguate on the SLUG, not the raw id: two DISTINCT ids can slugify to
        # the same SPDXRef (e.g. `PROJECT_NAME` and the unexpanded `${PROJECT_NAME}`
        # both -> SPDXRef-Subject-PROJECT-NAME). Keying on the slug makes the
        # function genuinely "slug-stable" (its contract) so SPDX never emits a
        # duplicate SPDXID; the `-<n>` suffix rides through the slug as `…-<n>`.
        key = _ref_slug(base)
        count = used.get(key, 0)
        if count == 0:
            emitted = base
        else:
            emitted = f"{base}-{count + 1}"
        used[key] = count + 1
        out[id(subject)] = emitted
    return out


def _ref_slug(text: str) -> str:
    """The most-collapsing emitted-ref slug (matches SPDX's SPDXRef slug). Used to
    disambiguate subject ids at the level where collisions actually occur."""
    return re.sub(r"[^A-Za-z0-9.\-]+", "-", text).strip("-") or "x"


def is_spdx_expression(expr: str) -> bool:
    """True if ``expr`` is a plausibly valid SPDX license expression.

    Delegates to the canonical ``enrich.licenseref.is_spdx_expression`` (the
    contract owner of this decision) so the emitters and the enricher agree on
    what counts as SPDX vs. a ``LicenseRef-…`` candidate. Falls back to a local
    token check only if that module is unavailable.
    """
    if not expr:
        return False
    try:
        from ..enrich.licenseref import is_spdx_expression as _impl

        return _impl(expr)
    except Exception:
        return bool(_SPDX_TOKEN.match(expr)) and " " not in expr.strip()


def licenseref_id_for(expr_or_name: str) -> str:
    """Return a ``LicenseRef-<slug>`` id for a non-SPDX license string.

    Delegates slug generation to ``enrich.licenseref.synthesize`` so the id
    matches what the enricher would produce; falls back to a local slug if the
    module is unavailable.
    """
    if expr_or_name.startswith("LicenseRef-"):
        return expr_or_name
    try:
        from ..enrich.licenseref import synthesize

        ref_id, _ = synthesize(expr_or_name, expr_or_name)
        return ref_id
    except Exception:
        slug = re.sub(r"[^A-Za-z0-9.\-]+", "-", expr_or_name.strip()).strip("-")
        return f"LicenseRef-{slug or 'unknown'}"


def subject_purl(subject: Subject) -> PackageURL | None:
    """A ``pkg:generic`` PURL for a subject — what this repo BUILDS.

    Every subject is identified generically, regardless of ``identity.kind``. A
    built Python wheel (``PYTHON_WHEEL``) is NOT necessarily published to PyPI, so
    asserting ``pkg:pypi`` for it would falsely claim PyPI provenance we cannot
    verify offline; ``pkg:generic`` is the honest, consistent choice — the same
    one the ``CANN_PACKAGE`` primary already uses. (Dependency components that are
    genuine pip requirements keep ``pkg:pypi`` via ``component_purl``; only the
    subject side is generic.) Name is used as-is — the generic purl type doesn't
    require PEP 503 lowercasing.

    When the subject carries a repo origin (``subject.vcs_url``), it rides as a
    ``vcs_url`` qualifier (e.g. ``...?vcs_url=git%2Bhttps://gitcode.com/cann/...``)
    — the spec-blessed, validator-safe way to record VCS provenance without
    inventing an unregistered host purl type.
    """
    qualifiers = {"vcs_url": subject.vcs_url} if subject.vcs_url else None
    return PackageURL(
        type="generic",
        name=subject.identity.name,
        version=subject.identity.version,
        qualifiers=qualifiers,
    )


def pep503_name(name: str) -> str:
    """Normalize a project name per PEP 503: lowercase, runs of ``[-_.]`` -> ``-``."""
    return re.sub(r"[-_.]+", "-", name).lower()


_URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")


def is_emittable_url(value: str | None) -> bool:
    """True if ``value`` may go into a URL-typed field (externalReference URL).

    A CycloneDX ``externalReference`` URL must be a real URL, not a local path or
    a template carrying an unexpanded build variable. Statically we cannot expand
    a CANN cache path like ``${CANN_3RD_LIB_PATH}/eigen-5.0.0.tar.gz`` (or a CMake
    generator expression ``$<...>``), so emitting it into a URL slot serializes as
    percent-encoded junk (``$%7BCANN_3RD_LIB_PATH%7D/...``). Require a
    ``scheme://`` and reject any unexpanded ``${...}`` / ``$<...>`` / ``$(...)``
    marker. The raw value is still kept as ``sbomgen:obs:*`` provenance — only the
    URL-typed emission is suppressed. Mirrors SPDX ``_valid_download_location``.
    """
    if not value:
        return False
    if "${" in value or "$<" in value or "$(" in value:
        return False
    return bool(_URL_SCHEME_RE.match(value))


def guessed_pypi_url(component: Component) -> str | None:
    """A constructed canonical PyPI project URL for a Python component.

    ``https://pypi.org/project/<pep503-name>/<version>/`` when a concrete version
    exists, else ``https://pypi.org/project/<pep503-name>/``. Returns ``None`` for
    non-Python components. This is a *guess* (the flag name conveys that): it is
    derived from the name/version, not a verified artifact link.
    """
    if "Python" not in component.languages:
        return None
    name = pep503_name(component.name)
    version = component.effective_version or component.source_version
    if version:
        return f"https://pypi.org/project/{name}/{version}/"
    return f"https://pypi.org/project/{name}/"


def component_purl(component: Component) -> PackageURL | None:
    """Best-effort PURL for a dependency component.

    A Python component (``languages`` includes ``Python``) normally gets a
    ``pkg:pypi/<name>`` purl. The ``@version`` qualifier is included ONLY when a
    concrete version is known (an EXACT pin set ``source_version``/
    ``effective_version``); a range/bare/unpinned dep emits a version-less purl
    (e.g. ``pkg:pypi/numpy``). A Python component that is a VCS source reference
    (``git+``/``hg+``/…) does NOT get a pypi purl — that would falsely claim a
    registry package for a source repo and mislead provenance / vuln matching; it
    gets a ``pkg:generic`` purl carrying the real ``vcs_url`` instead. (A
    direct-URL wheel keeps ``pkg:pypi`` — it is the named project pinned to a file.)
    A NON-Python component uses the PURL reconcile pre-resolved on
    ``component.purl`` (curated upstream coordinate / mirror download_url /
    first-party vcs_url), or carries no purl when none was resolved.
    """
    if "Python" not in component.languages:
        if component.purl:
            try:
                return PackageURL.from_string(component.purl)
            except ValueError:
                return None
        return None

    version = component.effective_version or component.source_version

    direct = python_direct_reference(component)
    if direct is not None:
        # A VCS source reference -> a pkg:generic purl carrying the real vcs_url
        # (NOT a false pkg:pypi for a source repo).
        _vcs, ref = direct
        url = ref.split("#", 1)[0].strip()  # drop the pip "#egg=" fragment
        return PackageURL(
            type="generic",
            name=component.name.lower(),
            version=version,
            qualifiers={"vcs_url": url},
        )

    return PackageURL(type="pypi", name=component.name.lower(), version=version)
