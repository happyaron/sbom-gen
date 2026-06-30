"""ScanCode license/copyright backend (opt-in, two modes).

ScanCode Toolkit is a heavyweight, separately-installed scanner (it is NOT a
dependency of sbom-gen — we shell out to its CLI). This module wraps it behind
:class:`ScancodeRunner`, parses its JSON, and aggregates a per-scanned-root
license/copyright result the reconcile/crosscheck layers consume.

Two modes, both gated by ``config.scancode`` (``enrich`` | ``crosscheck`` |
``both``):

* **enrich** — the HIGHEST-priority license layer. For each subject and each
  component with a local target directory, run ScanCode; a confident SPDX
  detection sets ``.license`` (and ``.copyright`` from holders/copyrights) and
  records ``Provenance(field='license', source='scancode')``, stashing the
  displaced prior value so crosscheck/both can report it.
* **crosscheck** — a QA pass over the finished ``Document`` that asserts NO
  license values; it compares ScanCode's SPDX license against the Document's
  resolved license per subject/component and emits a
  ``license_crosscheck_mismatch`` warning per difference plus a
  ``license-crosscheck.json`` report.

Confidence handling (the honesty rule — never assert a guess):

* a detection whose expression is ``unknown-license-reference`` /
  ``LicenseRef-scancode-unknown-license-reference`` → NOASSERTION;
* a detection whose best match score is below :data:`CONFIDENCE_THRESHOLD`
  (default 80) → NOASSERTION;
* a non-SPDX ``LicenseRef-scancode-*`` token → mapped through
  :mod:`sbom.enrich.licenseref` (a synthesized ``LicenseRef-<slug>`` + text).

Resilience: a missing binary, a non-zero exit, a timeout, or malformed JSON
yields a :class:`~sbom.models.Warning`, never a crash.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import Warning
from . import licenseref

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..config import Config
    from ..models import Component, Document, Subject
    from ..profile import Profile


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

#: Best-match score (0-100) at or above which a ScanCode detection is trusted.
#: Below this, the detection is treated as NOASSERTION rather than asserting a
#: low-confidence guess. ScanCode reports ~92 for a real Apache-2.0 file.
CONFIDENCE_THRESHOLD: float = 80.0

#: Default per-invocation timeout (seconds). ScanCode has a ~1.2s cold start and
#: scans ~10 files/sec, so a small bounded surface stays well under this.
DEFAULT_TIMEOUT: float = 120.0

#: License/copyright-bearing filenames scanned at the target-dir surface. We do
#: NOT recurse the whole tree (performance); we scan these specific files plus
#: the top-level directory entries.
_LICENSE_FILE_GLOBS = (
    "LICENSE*",
    "LICENCE*",
    "COPYING*",
    "COPYRIGHT*",
    "NOTICE*",
)

#: ScanCode tokens that mean "I could not identify a real license" — never
#: asserted as a concluded license.
_UNKNOWN_TOKENS = frozenset(
    {
        "unknown-license-reference",
        "LicenseRef-scancode-unknown-license-reference",
    }
)


# ---------------------------------------------------------------------------
# Aggregated result
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """The aggregated ScanCode finding for one scanned root.

    ``spdx_license_expression`` is ``None`` when ScanCode found nothing
    confident (unknown reference or a below-threshold score) — the caller then
    keeps the normal resolver result (enrich) or treats it as NOASSERTION
    (crosscheck). ``license_text`` carries inline text for a synthesized
    ``LicenseRef-…`` so emitters can satisfy the SPDX validators.
    """

    spdx_license_expression: str | None = None
    score: float = 0.0
    copyrights: list[str] = field(default_factory=list)
    holders: list[str] = field(default_factory=list)
    detection_rules: list[str] = field(default_factory=list)
    license_text: str | None = None

    def copyright_summary(self) -> str | None:
        """A single ``copyright`` string for ``Component.copyright`` (holders
        preferred, then raw copyright lines), or ``None`` when neither is set."""
        if self.holders:
            return "; ".join(self.holders)
        if self.copyrights:
            return "; ".join(self.copyrights)
        return None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class ScancodeRunner:
    """Resolve + invoke the ScanCode binary and parse its JSON output.

    ``scancode_path`` is the explicit binary path (``Config.scancode_path``);
    when ``None`` the runner falls back to ``scancode`` on ``PATH``.
    :meth:`available` reports whether a binary was found. The runner shells out;
    ScanCode is not imported as a library and is not a dependency of sbom-gen.
    """

    def __init__(self, scancode_path: str | None = None):
        self._explicit = scancode_path
        self._resolved, self._reason = self._resolve(scancode_path)

    @staticmethod
    def _executable(path: Path) -> bool:
        return path.is_file() and os.access(path, os.X_OK)

    @classmethod
    def _resolve(cls, scancode_path: str | None) -> tuple[str | None, str | None]:
        """Locate the ScanCode binary, returning ``(path, reason_if_unresolved)``.

        Precedence: explicit ``--scancode-path`` > ``$SCANCODE_PATH`` > ``$PATH``
        (``shutil.which``) > the running interpreter's own ``bin/`` (catches a
        ``pip install scancode-toolkit`` into the SAME venv even when that venv is
        not "activated", so its ``bin/`` is absent from ``$PATH``). An explicit
        path that is not an executable file is a hard error (no fall-through) so a
        typo is surfaced, not silently masked by a different binary."""
        if scancode_path:
            candidate = Path(scancode_path)
            if cls._executable(candidate):
                return str(candidate), None
            return None, f"--scancode-path {scancode_path!r} is not an executable file"

        env = os.environ.get("SCANCODE_PATH")
        if env and cls._executable(Path(env)):
            return str(Path(env)), None

        found = shutil.which("scancode")
        if found:
            return found, None

        venv_bin = Path(sys.executable).parent / "scancode"
        if cls._executable(venv_bin):
            return str(venv_bin), None

        return None, (
            "ScanCode not found (looked at --scancode-path, $SCANCODE_PATH, $PATH, "
            "and the venv bin); `pip install scancode-toolkit` or pass --scancode-path"
        )

    @property
    def binary(self) -> str | None:
        """The resolved binary path, or ``None`` when ScanCode is unavailable."""
        return self._resolved

    @property
    def unavailable_detail(self) -> str:
        """A human-actionable reason ScanCode is unavailable (for the warning)."""
        return self._reason or "ScanCode unavailable"

    def available(self) -> bool:
        """True when a usable ScanCode binary was resolved."""
        return self._resolved is not None

    # -- scanning ----------------------------------------------------------

    def scan_paths(
        self,
        paths: list[Path],
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> dict[Path, ScanResult]:
        """Scan each root in ``paths``; return ``{root: ScanResult}``.

        Each root is scanned independently: its license/copyright-bearing files
        (``LICENSE``/``COPYING``/``NOTICE``/``COPYRIGHT*``) plus the top-level
        directory entries are passed to ScanCode (a bounded surface — we do NOT
        recurse giant trees). A root that raises (timeout / non-zero exit /
        malformed JSON) is simply absent from the returned dict; the caller
        records a :class:`~sbom.models.Warning`. A root with no confident
        detection yields a :class:`ScanResult` with ``spdx_license_expression is
        None``.
        """
        results: dict[Path, ScanResult] = {}
        if not self.available():
            return results
        for root in paths:
            scan_json = self._run_one(root, timeout=timeout)
            if scan_json is None:
                continue
            results[root] = aggregate(scan_json)
        return results

    def scan_tree(self, root: "Path", *, timeout: float = DEFAULT_TIMEOUT) -> "ScanResult | None":
        """Scan a directory in a SINGLE recursive ScanCode invocation; return the
        aggregated :class:`ScanResult` (or ``None`` on failure / unavailable).

        Use this when *root* is ALREADY a small bounded surface (e.g. a ``--deps-dir``
        materialized extraction) — one ``scancode -cl <dir>`` call is far cheaper than
        :meth:`scan_paths`' per-file invocations, which matter when seeding dozens of
        deps. Do NOT point it at a giant unbounded tree."""
        if root is None or not self.available():
            return None
        doc = self._run_single_input(Path(root), timeout=timeout)
        if doc is None:
            return None
        return aggregate(doc)

    def _run_one(self, root: Path, *, timeout: float) -> dict | None:
        """Run ScanCode over the bounded surface of ``root``; return a merged
        parsed-JSON document (or ``None`` on any failure).

        Each target in the bounded surface is scanned as its OWN single-input
        ``scancode`` invocation and the per-file ``files`` arrays are merged.
        ScanCode 32.5.0 rejects *multiple* ABSOLUTE inputs in one call
        (``all input paths must be relative when using multiple inputs``) — and
        the failure was previously swallowed, dropping the whole scan — so a
        single absolute path per call is the robust form.
        """
        targets = _scan_surface(root)
        if not targets:
            return None
        merged_files: list[dict] = []
        any_ok = False
        for target in targets:
            doc = self._run_single_input(target, timeout=timeout)
            if doc is None:
                continue
            any_ok = True
            files = doc.get("files")
            if isinstance(files, list):
                merged_files.extend(files)
        if not any_ok:
            return None
        return {"files": merged_files}

    def _run_single_input(self, target: Path, *, timeout: float) -> dict | None:
        """Run ScanCode on ONE input path; return parsed JSON (or ``None``)."""
        with tempfile.TemporaryDirectory(prefix="sbom-scancode-") as tmp:
            out = Path(tmp) / "scancode.json"
            cmd = [
                str(self._resolved),
                "-cl",
                "--json-pp",
                str(out),
                str(target),
            ]
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout,
                    check=True,
                )
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                OSError,
            ):
                return None
            try:
                return json.loads(out.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None


# ---------------------------------------------------------------------------
# Scan-surface scoping (performance — bounded, never a full-tree walk)
# ---------------------------------------------------------------------------


def _scan_surface(root: Path) -> list[Path]:
    """Return the bounded set of paths to hand ScanCode for ``root``.

    For a directory: the license/copyright-bearing files it contains
    (``LICENSE*``/``COPYING*``/``NOTICE*``/``COPYRIGHT*``) PLUS the top-level
    directory entries (so a notice embedded in a top-level source/header is seen
    too) — but NOT a recursive walk. For a single file: that file. A
    nonexistent path yields an empty list.
    """
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []

    targets: list[Path] = []
    seen: set[Path] = set()

    def _add(p: Path) -> None:
        if p not in seen and p.exists():
            seen.add(p)
            targets.append(p)

    for pattern in _LICENSE_FILE_GLOBS:
        for match in sorted(root.glob(pattern)):
            if match.is_file():
                _add(match)

    try:
        for child in sorted(root.iterdir()):
            if child.is_file():
                _add(child)
    except OSError:
        pass

    return targets


# ---------------------------------------------------------------------------
# Aggregation / parsing
# ---------------------------------------------------------------------------


def _best_detection(file_entry: dict) -> tuple[str | None, float, list[str]]:
    """Return ``(spdx_expr, best_score, rule_ids)`` for one ScanCode file entry.

    Prefers the detection whose best match score is highest; reads the SPDX form
    from ``license_expression_spdx`` (falling back to the file-level
    ``detected_license_expression_spdx``). Returns ``(None, 0.0, [])`` when the
    file carries no detection.
    """
    detections = file_entry.get("license_detections") or []
    best_expr: str | None = None
    best_spdx: str | None = None
    best_score = -1.0
    rule_ids: list[str] = []
    for det in detections:
        matches = det.get("matches") or []
        score = max((float(m.get("score") or 0.0) for m in matches), default=0.0)
        for m in matches:
            rid = m.get("rule_identifier")
            if rid and rid not in rule_ids:
                rule_ids.append(rid)
        if score > best_score:
            best_score = score
            best_expr = det.get("license_expression")
            best_spdx = det.get("license_expression_spdx")

    if best_expr is None:
        # Fall back to the file-level fields (e.g. a clue with no detection).
        best_spdx = file_entry.get("detected_license_expression_spdx")
        best_expr = file_entry.get("detected_license_expression")
        best_score = 0.0 if best_spdx is None else best_score

    spdx = best_spdx if best_spdx is not None else best_expr
    return spdx, max(best_score, 0.0), rule_ids


def _is_unknown(expr: str | None) -> bool:
    """True when ``expr`` is one of ScanCode's "unknown" placeholders."""
    if not expr:
        return True
    return any(tok in expr for tok in _UNKNOWN_TOKENS)


def _is_license_file(path: str | None) -> bool:
    """True when ``path`` looks like a dedicated license/notice file (preferred
    as the authoritative detection over an incidental in-source header)."""
    if not path:
        return False
    name = Path(path).name.upper()
    return name.startswith(("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"))


def aggregate(scan_json: dict, *, threshold: float = CONFIDENCE_THRESHOLD) -> ScanResult:
    """Aggregate a parsed ScanCode JSON document into one :class:`ScanResult`.

    Aggregation policy:

    * prefer the highest-score license detection coming from a license/notice
      file (``LICENSE``/``COPYING``/``NOTICE``/``COPYRIGHT``); fall back to the
      best detection from any scanned file;
    * an ``unknown-license-reference`` /
      ``LicenseRef-scancode-unknown-license-reference`` expression, or a best
      score below ``threshold``, yields ``spdx_license_expression = None`` (do
      NOT assert a guess);
    * a non-SPDX ``LicenseRef-scancode-*`` token is mapped through
      :func:`sbom.enrich.licenseref.synthesize` to a ``LicenseRef-<slug>`` plus
      inline text;
    * copyrights and holders are UNIONed across every scanned file.
    """
    files = scan_json.get("files") or []

    chosen_spdx: str | None = None
    chosen_score = 0.0
    chosen_rules: list[str] = []
    chosen_is_license_file = False

    copyrights: list[str] = []
    holders: list[str] = []

    for entry in files:
        if entry.get("type") == "directory":
            # union copyright/holders even from a dir node (usually empty)
            _union(copyrights, [c.get("copyright") for c in entry.get("copyrights") or []])
            _union(holders, [h.get("holder") for h in entry.get("holders") or []])
            continue

        spdx, score, rules = _best_detection(entry)
        is_lic_file = _is_license_file(entry.get("path"))

        _union(copyrights, [c.get("copyright") for c in entry.get("copyrights") or []])
        _union(holders, [h.get("holder") for h in entry.get("holders") or []])

        if spdx is None:
            continue

        # Prefer a detection from an actual license/notice file; otherwise keep
        # the highest score seen so far.
        better = False
        if is_lic_file and not chosen_is_license_file:
            better = True
        elif is_lic_file == chosen_is_license_file and score > chosen_score:
            better = True
        if chosen_spdx is None:
            better = True

        if better:
            chosen_spdx = spdx
            chosen_score = score
            chosen_rules = rules
            chosen_is_license_file = is_lic_file

    result = ScanResult(
        score=chosen_score,
        copyrights=copyrights,
        holders=holders,
        detection_rules=chosen_rules,
    )

    # Confidence gate: unknown reference or below-threshold → no assertion.
    if _is_unknown(chosen_spdx) or chosen_score < threshold:
        result.spdx_license_expression = None
        return result

    # Map a non-SPDX LicenseRef-scancode-* token to a synthesized LicenseRef.
    if isinstance(chosen_spdx, str) and chosen_spdx.startswith("LicenseRef-scancode-"):
        name = chosen_spdx.removeprefix("LicenseRef-scancode-")
        ref_id, text = licenseref.synthesize(chosen_spdx, name)
        result.spdx_license_expression = ref_id
        result.license_text = text
        return result

    result.spdx_license_expression = chosen_spdx
    return result


def _union(target: list[str], additions) -> None:
    """Append non-empty, non-duplicate string items to ``target`` in order."""
    for item in additions:
        if item and item not in target:
            target.append(item)


# ---------------------------------------------------------------------------
# Target-dir resolution (subject vs. component)
# ---------------------------------------------------------------------------


def target_dir_for(
    subject_or_component: "Subject | Component",
    repo_root: "Path | str | None" = None,
) -> Path | None:
    """Return the on-disk path ScanCode should scan for a subject/component.

    * a :class:`~sbom.models.Subject` → its ``source_path``, resolved against
      ``repo_root`` when relative (subjects carry a *repo-relative*
      ``source_path``; the empty string ``""`` means the repo root itself — the
      primary subject). Mirrors the resolution in ``collectors/python.py`` and
      ``collectors/cpp.py`` (``_subject_entry_cmake``): a relative path is
      joined onto ``repo_root`` so ScanCode scans the real source tree, NOT the
      process CWD.
    * a :class:`~sbom.models.Component` → its observations'
      ``resolved_url_or_path`` (also ``repo_root``-resolved when relative) IFF
      that is an existing local directory (ScanCode can only read on-disk
      source); otherwise ``None`` — most components in static offline mode have
      no local source and are skipped.
    """
    base = Path(repo_root) if repo_root is not None else None
    base_resolved = None
    if base is not None:
        try:
            base_resolved = base.resolve()
        except OSError:
            base_resolved = base

    def _resolve(value: str) -> Path | None:
        p = Path(value)
        # An absolute path is explicitly resolved (a configured-mode SOURCE_DIR, or
        # an out-of-tree cache) and used as-is. A RELATIVE path is joined onto
        # repo_root and CONFINED: a crafted ``../`` must not make ScanCode read
        # files outside the repository (checked on a resolved copy so ``..`` can't
        # escape; ``p`` itself is returned unchanged).
        if p.is_absolute() or base is None:
            return p
        joined = base / p
        if base_resolved is not None:
            try:
                rp = joined.resolve()
            except OSError:
                return None
            if rp != base_resolved and base_resolved not in rp.parents:
                return None
        return joined

    source_path = getattr(subject_or_component, "source_path", None)
    if source_path is not None and hasattr(subject_or_component, "identity"):
        # A Subject: "" is a valid source_path meaning the repo root itself.
        path = _resolve(source_path)
        if path is not None and path.exists():
            return path
        return None

    # A Component: look for a local directory among its observations.
    observations = getattr(subject_or_component, "observations", None)
    if observations:
        for obs in observations:
            resolved = getattr(obs, "resolved_url_or_path", None)
            if not resolved:
                continue
            path = _resolve(resolved)
            if path is not None and path.is_dir():
                return path
    return None


# ---------------------------------------------------------------------------
# Crosscheck (mode b) — a QA pass over the finished Document
# ---------------------------------------------------------------------------

#: Filename of the per-run crosscheck report written under the output dir.
CROSSCHECK_REPORT_NAME = "license-crosscheck.json"


def _normalize(expr: str | None) -> str:
    """Normalize a license expression for an agreement comparison."""
    return (expr or "NOASSERTION").strip()


def crosscheck(
    document: "Document",
    config: "Config",
    out_dir: Path,
    profile: "Profile | None" = None,
) -> tuple[list[Warning], list[dict]]:
    """Compare ScanCode's SPDX license against the Document's resolved license.

    Returns ``(warnings, report_rows)``. Each report row is 3-WAY when the
    profile exposes a curated Notice for the component:
    ``{name, ours, scancode, curated, agree}`` (``curated`` is the Notice's
    declared license, or ``None``). ``agree`` always reflects the ``ours`` vs
    ``scancode`` comparison — the curated column is informational and the
    ``license_crosscheck_mismatch`` warning semantics are unchanged. The caller
    writes the report to ``<out_dir>/license-crosscheck.json``.

    Two paths:

    * ``config.scancode == 'crosscheck'`` (standalone): NO license value was
      changed, so this RUNS ScanCode on the same subjects/components and compares
      ``ours=<document license>`` vs ``scancode=<detection>``.
    * ``config.scancode == 'both'``: enrich already applied ScanCode, so the
      report is built from the stashed displaced-prior values
      (``ours=<prior> scancode=<applied>``) WITHOUT re-running ScanCode.

    A difference emits ``Warning(code='license_crosscheck_mismatch',
    subject=<name>, detail='ours=<x> scancode=<y> score=<s>')``. If ScanCode is
    unavailable in standalone mode, a single ``scancode_unavailable`` warning is
    emitted and an empty report is returned.
    """
    curated = _curated_license_map(config, profile)
    mode = getattr(config, "scancode", None)
    if mode == "both":
        return _crosscheck_from_prior(document, curated)
    return _crosscheck_live(document, config, curated)


def _crosscheck_live(
    document: "Document", config: "Config", curated: dict[str, str | None]
) -> tuple[list[Warning], list[dict]]:
    """Standalone crosscheck: run ScanCode and compare against resolved licenses."""
    warnings: list[Warning] = []
    rows: list[dict] = []

    runner = ScancodeRunner(getattr(config, "scancode_path", None))
    if not runner.available():
        warnings.append(
            Warning(
                code="scancode_unavailable",
                subject=None,
                detail=f"{runner.unavailable_detail}; skipped license crosscheck",
            )
        )
        return warnings, rows

    repo_root = getattr(config, "repo_root", None)

    # Collect (name, ours_license, target_dir) for every subject + component
    # that has a local target dir.
    items: list[tuple[str, str | None, Path]] = []
    for subject in document.subjects:
        target = target_dir_for(subject, repo_root)
        if target is not None:
            items.append((subject.identity.name, subject.license, target))
    for comp in document.components:
        target = target_dir_for(comp, repo_root)
        if target is not None:
            items.append((comp.name, comp.license, target))

    if not items:
        return warnings, rows

    unique_dirs = list(dict.fromkeys(t for _, _, t in items))
    scanned = runner.scan_paths(unique_dirs, timeout=DEFAULT_TIMEOUT)

    for name, ours, target in items:
        result = scanned.get(target)
        sc_license = result.spdx_license_expression if result is not None else None
        score = result.score if result is not None else 0.0
        rows.append(
            _crosscheck_row(name, ours, sc_license, score, curated.get(name))
        )
        if not _agree(ours, sc_license):
            warnings.append(
                Warning(
                    code="license_crosscheck_mismatch",
                    subject=name,
                    detail=f"ours={ours} scancode={sc_license} score={score}",
                )
            )
    return warnings, rows


def _agree(ours: str | None, scancode: str | None) -> bool:
    return _normalize(ours) == _normalize(scancode)


def _crosscheck_row(
    name: str,
    ours: str | None,
    scancode: str | None,
    score: float,
    curated: str | None,
) -> dict:
    """Build one crosscheck report row.

    When a curated Notice declared license is available for ``name`` the row is
    3-WAY ``{name, ours, scancode, curated, agree}`` (``curated`` is ``None``
    when the Notice has no declared license for the component). ``agree`` always
    reflects the ``ours`` vs ``scancode`` comparison (the crosscheck warning
    semantics are unchanged); the curated column is informational.
    """
    return {
        "name": name,
        "ours": ours,
        "scancode": scancode,
        "curated": curated,
        "score": score,
        "agree": _agree(ours, scancode),
    }


def _curated_license_map(
    config: "Config | None", profile: "Profile | None"
) -> dict[str, str | None]:
    """Return ``{component_name: curated Notice declared license}`` for the
    profile's curated records, so the crosscheck report can be 3-WAY.

    Resolved via ``profile.curated_records(repo_root)`` (the CANN profile's
    Notice + List.yaml parse). Best-effort: no profile, a profile without the
    hook, no curated files, or any parse error yields an empty map (the report
    stays 2-way for those names). Keyed by the curated record's canonical
    component name.
    """
    if config is None or profile is None:
        return {}
    repo_root = getattr(config, "repo_root", None)
    if repo_root is None:
        return {}
    curated_records = getattr(profile, "curated_records", None)
    if curated_records is None:
        return {}
    try:
        records = curated_records(repo_root)
    except Exception:  # noqa: BLE001 - a broken enricher must not crash QA
        return {}

    # Key by the alias-resolved canonical name so a Notice record named
    # ``libboundscheck`` matches the ``securec`` component/subject row (same
    # canonicalization reconcile uses).
    canonical = _alias_canonicalizer(profile)
    out: dict[str, str | None] = {}
    for rec in records:
        name = getattr(rec, "name", None)
        if name:
            out[canonical(name)] = getattr(rec, "license", None)
    return out


def _alias_canonicalizer(profile: "Profile"):
    """Return a ``name -> canonical name`` function from the profile's alias map
    (identity when the profile has no usable alias map)."""
    alias_map = getattr(profile, "alias_map", None)
    table: dict[str, str] = {}
    if alias_map is not None:
        try:
            for spelling, record in alias_map().items():
                canonical = record.get("canonical", spelling)
                table[spelling.lower()] = canonical
        except Exception:  # noqa: BLE001 - a broken alias map must not crash QA
            table = {}

    def _canonical(name: str) -> str:
        return table.get(name.lower(), name)

    return _canonical


def _crosscheck_from_prior(
    document: "Document", curated: dict[str, str | None]
) -> tuple[list[Warning], list[dict]]:
    """`both` mode: build the report from the displaced prior values stashed by
    the enrich layer (ours=prior, scancode=applied). Does NOT re-run ScanCode."""
    warnings: list[Warning] = []
    rows: list[dict] = []

    def _emit(name: str, prior: str | None, applied: str | None, score: float) -> None:
        rows.append(_crosscheck_row(name, prior, applied, score, curated.get(name)))
        if not _agree(prior, applied):
            warnings.append(
                Warning(
                    code="license_crosscheck_mismatch",
                    subject=name,
                    detail=f"ours={prior} scancode={applied} score={score}",
                )
            )

    for subject in document.subjects:
        prior = getattr(subject, "__scancode_prior_license__", _SENTINEL)
        if prior is _SENTINEL:
            continue  # scancode did not apply to this subject
        _emit(subject.identity.name, prior, subject.license, 0.0)

    for comp in document.components:
        prior = _prior_from_provenance(comp)
        if prior is _SENTINEL:
            continue
        _emit(comp.name, prior, comp.license, 0.0)

    return warnings, rows


#: Distinguishes "no scancode application" from "scancode applied, prior was None".
_SENTINEL = object()


def _prior_from_provenance(comp: "Component"):
    """Return the displaced prior license stashed by the component enrich layer,
    or :data:`_SENTINEL` when scancode did not apply to this component."""
    applied = any(
        p.field == "license" and p.source == "scancode" for p in comp.provenance
    )
    if not applied:
        return _SENTINEL
    for p in comp.provenance:
        if p.field == "license_prior":
            return None if p.source == "NOASSERTION" else p.source
    return None


__all__ = [
    "ScancodeRunner",
    "ScanResult",
    "aggregate",
    "target_dir_for",
    "crosscheck",
    "CONFIDENCE_THRESHOLD",
    "DEFAULT_TIMEOUT",
    "CROSSCHECK_REPORT_NAME",
]
