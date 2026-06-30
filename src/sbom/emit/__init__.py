"""Emitters: render a reconciled :class:`~sbom.models.Document` to standard SBOM
formats via the official libraries (cyclonedx-python-lib, spdx-tools).

Emitters only read the Document; they never collect or mutate it. No hand-rolled
JSON and no vendored schemas — validation uses each library's own validator.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EmitOptions:
    """Options shared by every emitter."""

    reproducible: bool = False
    source_date_epoch: int | None = None
    split_subjects: bool = False
    subjects: list[str] | None = None  # which subject ids to emit (None = all)
    tool_version: str = "0"  # stamped as the generator's version in both formats
    # When True, construct a canonical https://pypi.org/project/<name>/[<version>/]
    # download URL for Python components (a guess, not a verified artifact link).
    guess_pypi_urls: bool = False
    # Output verbosity. "compact" (the default) omits the per-observation verbose
    # provenance (the sbomgen:obs:N:* CycloneDX properties / sbomgen:obs:*
    # annotations) and the CycloneDX evidence.occurrences array, keeping the
    # readable summary (name/version/type/purl/licenses/copyright/hashes, the
    # dependency graph, and the integrity/completeness/alias/subject/pedigree
    # signals). "full" restores the complete per-observation output. In BOTH modes
    # evidence.occurrences (when emitted) is deduped to one entry per unique
    # source location.
    detail: str = "compact"
