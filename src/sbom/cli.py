"""Orchestration entry point for the ``sbom`` console script.

This module wires the pipeline together (Collect -> Reconcile -> Emit) per the
``cli.main`` narration in ``INTERFACE.md``:

1. ``config = parse_args(argv)``
2. ``profile, w = get_profile(config.repo_profile, config.repo_root)`` -- any
   ``profile_load_failed`` warnings are surfaced, never a silent downgrade.
3. ``authority, w = resolve_cmake_authority(...)``
4. ``subjects, w = subject.discover_subjects(config, profile)``
5. run the collectors (subject + cpp + python) in static mode + profile hooks
6. ``document = reconcile(results, subjects, config, profile)``
7. for each requested format: emit + validate, write to ``out_dir`` (split per
   subject when ``config.split_subjects``)

The sibling modules (``config``, ``cmake.parse``, ``collectors.*``,
``reconcile``, ``emit.*``) are imported lazily inside :func:`run`/:func:`main`
so this module stays importable while those modules are written in parallel and
so a missing optional dependency surfaces only when the pipeline actually runs.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .models import Document, Warning

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids import at runtime
    from .config import Config


# Exit codes (process-level policy).
EXIT_OK = 0
EXIT_VALIDATION_FAILED = 1
EXIT_FATAL = 2

# Map a requested --format token to (module attr, file extension, validator).
_FORMAT_MODULES = {
    "cyclonedx": ("sbom.emit.cyclonedx", "cdx.json", "validate_cyclonedx"),
    "spdx": ("sbom.emit.spdx", "spdx.json", "validate_spdx"),
}


def run(config: "Config") -> Document:
    """Programmatic entry: run the full pipeline and return the ``Document``.

    No argv parsing and no file writing happen here, so library callers and
    tests can inspect the reconciled :class:`~sbom.models.Document` directly.
    All warnings raised along the way are collected onto ``document.warnings``.
    """
    # Lazy imports: the sibling modules are written in parallel and may pull in
    # heavy optional deps; importing here keeps this module standalone-importable.
    from .cmake.parse import resolve_cmake_authority
    from .collectors import CollectResult, cpp, python, subject
    from .profile import get_profile
    from .reconcile import reconcile

    warnings: list[Warning] = []

    # 2. Resolve the profile (a broken entry point is surfaced, not swallowed).
    profile, profile_warnings = get_profile(config.repo_profile, config.repo_root)
    warnings.extend(profile_warnings)

    # 3. Resolve the CMake authority pre-collection (feeds every collector).
    authority, authority_warnings = resolve_cmake_authority(
        config.repo_root,
        config.cmake_root,
        cmake_source_authority=config.cmake_source_authority,
        cmake_defines=config.cmake_defines,
        profile_values=config.profile_values,
        allow_input_fallback=config.allow_input_fallback,
        resolve_cmake_ref=config.resolve_cmake_ref,
        network=config.network,
    )
    warnings.extend(authority_warnings)

    # 4. Discover the authoritative subject set.
    subjects, subject_warnings = subject.discover_subjects(config, profile)
    warnings.extend(subject_warnings)

    # 5. Run the collectors. Only the STATIC path is implemented; the configured /
    #    both modes (CMake File API + configure-trace) are accepted for forward
    #    compatibility but NOT yet implemented, so warn rather than silently
    #    under-report build-configured deps. cpp.collect already invokes the
    #    profile's package_metadata + build_tooling hooks WITH root attribution and
    #    edges, so they must NOT be re-invoked here -- doing so produced a second,
    #    root-less copy of every CANN-package observation (duplicate sbomgen:obs).
    if config.collector_mode in ("configured", "both"):
        warnings.append(
            Warning(
                code="collector_mode_unimplemented",
                subject=None,
                detail=(
                    f"--collector-mode {config.collector_mode} is not yet implemented; "
                    "ran the static collector only (configured CMake File API / "
                    "configure-trace collection is planned)."
                ),
            )
        )
    results: list[CollectResult] = [
        cpp.collect(config, profile, authority, subjects),
        python.collect(config, profile, subjects),
    ]

    # 6. Reconcile is the only stage that produces a Document.
    document = reconcile(results, subjects, config, profile)

    # Stash the resolved profile as a transient attribute (NOT in
    # document.metadata, which the emitters serialise) so the cli-orchestrated
    # ScanCode crosscheck QA pass can ask it for curated Notice licenses (the
    # 3-way report column) without re-resolving the profile.
    setattr(document, "__profile__", profile)

    # Fold the pre-reconcile warnings in (reconcile owns its own warnings).
    document.warnings = list(warnings) + list(document.warnings)
    return document


def main(argv: list[str] | None = None) -> int:
    """The ``sbom`` console script (also ``python -m sbom``).

    Parses ``argv`` into a :class:`~sbom.config.Config`, runs the pipeline via
    :func:`run`, emits + validates each requested format, writes the outputs to
    ``config.out_dir`` (honouring ``--split-subjects`` and ``--subjects``),
    prints a summary including warning counts, and returns a process exit code.
    """
    from importlib import import_module

    from . import __version__
    from .config import parse_args
    from .emit import EmitOptions
    from .emit._common import split_output_basenames

    config = parse_args(argv)

    # --refresh-data: regenerate/validate a vendored data file and exit; no SBOM.
    if getattr(config, "refresh_data", None):
        from .refresh import run_refresh

        try:
            return run_refresh(config)
        except Exception as exc:  # noqa: BLE001 - top-level fatal boundary
            print(f"sbom: fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
            return EXIT_FATAL

    try:
        document = run(config)
    except Exception as exc:  # noqa: BLE001 - top-level fatal boundary
        print(f"sbom: fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_FATAL

    options = EmitOptions(
        reproducible=config.reproducible,
        source_date_epoch=config.source_date_epoch,
        split_subjects=config.split_subjects,
        subjects=config.subjects,
        tool_version=__version__,
        guess_pypi_urls=config.guess_pypi_urls,
        detail=getattr(config, "detail", "compact"),
    )

    out_dir = Path(config.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ScanCode crosscheck (config.scancode in {crosscheck, both}): a QA pass over
    # the finished Document. It writes <out_dir>/license-crosscheck.json and folds
    # any license_crosscheck_mismatch warnings onto the document. In 'crosscheck'
    # mode no license value was changed (it runs scancode live); in 'both' mode
    # enrich already applied scancode, so the report is built from the displaced
    # prior values. 'enrich' alone writes no report.
    if getattr(config, "scancode", None) in ("crosscheck", "both"):
        _run_crosscheck(document, config, out_dir)

    validation_warnings: list[Warning] = []
    written: list[Path] = []

    for fmt in config.formats:
        spec = _FORMAT_MODULES.get(fmt)
        if spec is None:
            validation_warnings.append(
                Warning(code="unknown_format", subject=fmt, detail="unrecognized --format")
            )
            continue
        module_name, ext, validator_name = spec
        emitter = import_module(module_name)
        validate_mod = import_module("sbom.emit.validate")
        validator = getattr(validate_mod, validator_name)

        if config.split_subjects:
            per_subject = emitter.emit_split(document, options)
            # Subject ids are untrusted metadata, not filenames — sanitize so a
            # crafted id (e.g. '../escaped') cannot write outside out_dir.
            basenames = split_output_basenames(list(per_subject))
            for subject_id, text in per_subject.items():
                validation_warnings.extend(validator(text))
                path = out_dir / f"{basenames[subject_id]}.{ext}"
                path.write_text(text)
                written.append(path)
        else:
            text = emitter.emit(document, options)
            validation_warnings.extend(validator(text))
            path = out_dir / f"sbom.{ext}"
            path.write_text(text)
            written.append(path)

    all_warnings = list(document.warnings) + validation_warnings
    _print_summary(document, written, all_warnings)

    return EXIT_VALIDATION_FAILED if validation_warnings else EXIT_OK


def _run_crosscheck(document: Document, config: "Config", out_dir: Path) -> None:
    """Run the ScanCode license crosscheck and write the report.

    Folds any ``license_crosscheck_mismatch`` (and ``scancode_unavailable``)
    warnings onto ``document.warnings`` and writes the per-row report to
    ``<out_dir>/license-crosscheck.json``. Never raises: a broken crosscheck
    must not take down the run.
    """
    import json

    from .enrich import scancode as sc

    profile = getattr(document, "__profile__", None)

    try:
        warnings, rows = sc.crosscheck(document, config, out_dir, profile)
    except Exception as exc:  # noqa: BLE001 - QA pass must never crash the run
        document.warnings.append(
            Warning(
                code="scancode_crosscheck_failed",
                subject=None,
                detail=f"{type(exc).__name__}: {exc}",
            )
        )
        return

    document.warnings.extend(warnings)
    report_path = out_dir / sc.CROSSCHECK_REPORT_NAME
    try:
        report_path.write_text(json.dumps(rows, indent=2, sort_keys=True))
    except OSError:
        pass


def _print_summary(
    document: Document, written: list[Path], warnings: list[Warning]
) -> None:
    """Print a one-screen run summary (subjects/components/tools + warnings)."""
    n_subjects = len(document.subjects)
    n_components = len(document.components)
    n_edges = len(document.edges)
    n_tools = len(document.environment_tools)

    print("sbom: generated SBOM", file=sys.stderr)
    print(
        f"  subjects={n_subjects} components={n_components} "
        f"edges={n_edges} environment_tools={n_tools}",
        file=sys.stderr,
    )
    for path in written:
        print(f"  wrote {path}", file=sys.stderr)

    if warnings:
        counts: dict[str, int] = {}
        for w in warnings:
            counts[w.code] = counts.get(w.code, 0) + 1
        total = sum(counts.values())
        print(f"  warnings: {total}", file=sys.stderr)
        for code in sorted(counts):
            print(f"    {code}: {counts[code]}", file=sys.stderr)
    else:
        print("  warnings: 0", file=sys.stderr)


__all__ = ["main", "run"]
