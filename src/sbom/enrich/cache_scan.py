"""Local source-cache LICENSE/COPYING scan enricher (layer 3).

Scans extracted dependency directories under ``CANN_3RD_LIB_PATH`` (offline)
for ``LICENSE``/``COPYING`` files and applies a best-effort SPDX-id heuristic
match.  Sets ``component.license`` and ``component.checksums`` when a
confident match is found.  Does NOT make network calls.

The ``Config`` object consumed here is the one defined in ``sbom.config``
(not yet written at the time this module was implemented, so a
``TYPE_CHECKING``-only import is used and the function accepts any object
with ``network`` and ``cmake_defines`` attributes at runtime).
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import Component, IntegrityFinding, Provenance, Warning

if TYPE_CHECKING:  # pragma: no cover
    from ..config import Config

# ---------------------------------------------------------------------------
# SPDX substring / heuristic matcher
# ---------------------------------------------------------------------------

# Each entry is (pattern_in_license_text, spdx_id).  Patterns are checked in
# order; first match wins.  Patterns are case-insensitive substrings unless
# wrapped in a compiled regex.
_SPDX_HINTS: list[tuple[re.Pattern[str] | str, str]] = [
    # Apache 2.0 — check before generic "Apache"
    (re.compile(r"apache\s+license.*version\s+2", re.IGNORECASE | re.DOTALL), "Apache-2.0"),
    (re.compile(r"apache-2\.0", re.IGNORECASE), "Apache-2.0"),
    # MIT
    (re.compile(r"\bpermission\s+is\s+hereby\s+granted.*mit\b", re.IGNORECASE | re.DOTALL), "MIT"),
    (re.compile(r"\bpermission\s+is\s+hereby\s+granted,\s+free\s+of\s+charge\b", re.IGNORECASE), "MIT"),
    # BSD-3-Clause
    (re.compile(r"neither\s+the\s+name.*nor\s+the\s+names\s+of\s+its\s+contributors", re.IGNORECASE | re.DOTALL), "BSD-3-Clause"),
    # BSD-2-Clause
    (re.compile(r"redistribution\s+and\s+use.*permitted.*2\s+conditions", re.IGNORECASE | re.DOTALL), "BSD-2-Clause"),
    # MPL-2.0
    (re.compile(r"mozilla\s+public\s+license.*version\s+2", re.IGNORECASE), "MPL-2.0"),
    # LGPL-2.1
    (re.compile(r"gnu\s+lesser\s+general\s+public\s+license.*version\s+2\.1", re.IGNORECASE), "LGPL-2.1-only"),
    # GPL-2.0
    (re.compile(r"gnu\s+general\s+public\s+license.*version\s+2", re.IGNORECASE), "GPL-2.0-only"),
    # GPL-3.0
    (re.compile(r"gnu\s+general\s+public\s+license.*version\s+3", re.IGNORECASE), "GPL-3.0-only"),
    # ISC
    (re.compile(r"\bisc\s+license\b", re.IGNORECASE), "ISC"),
    # Zlib
    (re.compile(r"\bzlib\s+license\b", re.IGNORECASE), "Zlib"),
    (re.compile(r"this\s+software\s+is\s+provided\s+'as-is'.*zlib", re.IGNORECASE | re.DOTALL), "Zlib"),
    # BSL-1.0 (Boost)
    (re.compile(r"boost\s+software\s+license.*version\s+1\.0", re.IGNORECASE), "BSL-1.0"),
    # MulanPSL (common in Chinese-origin OSS; text is often Chinese — match the
    # canonical coscl.org.cn URL marker and the Chinese title as well as English).
    (re.compile(r"mulanpsl2|mulan\s+psl\s+v2|mulan\s+permissive\s+software\s+license[,， ]*\s*version\s+2", re.IGNORECASE), "MulanPSL-2.0"),
    (re.compile(r"木兰宽松许可证[，,].*第\s*2\s*版", re.DOTALL), "MulanPSL-2.0"),
    (re.compile(r"mulanpsl1|mulan\s+psl\s+v1|mulan\s+permissive\s+software\s+license[,， ]*\s*version\s+1", re.IGNORECASE), "MulanPSL-1.0"),
    (re.compile(r"木兰宽松许可证[，,].*第\s*1\s*版", re.DOTALL), "MulanPSL-1.0"),
    # Unlicense
    (re.compile(r"this\s+is\s+free\s+and\s+unencumbered\s+software\s+released\s+into\s+the\s+public\s+domain", re.IGNORECASE), "Unlicense"),
    # CC0
    (re.compile(r"creative\s+commons.*cc0", re.IGNORECASE), "CC0-1.0"),
    # SPDX identifier line (present in many modern projects)
    (re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9\-\.+ ]+)", re.IGNORECASE), "_spdx_id_line"),
]


def _spdx_match(text: str) -> str | None:
    """Return a best-effort SPDX id for *text*, or ``None`` if unrecognised.

    Checks for an ``SPDX-License-Identifier:`` header first (highest
    confidence), then falls back to heuristic substring matching.
    """
    # Highest confidence: explicit SPDX-License-Identifier header.
    id_match = re.search(
        r"SPDX-License-Identifier:\s*([A-Za-z0-9\-\.+ ()]+)",
        text,
        re.IGNORECASE,
    )
    if id_match:
        candidate = id_match.group(1).strip()
        if candidate and candidate not in ("NOASSERTION", "NONE"):
            return candidate

    # Heuristic patterns.
    for pattern, spdx_id in _SPDX_HINTS:
        if spdx_id == "_spdx_id_line":
            # Already handled above.
            continue
        if isinstance(pattern, re.Pattern):
            if pattern.search(text):
                return spdx_id
        else:
            if pattern.lower() in text.lower():
                return spdx_id

    return None


# ---------------------------------------------------------------------------
# License file candidates
# ---------------------------------------------------------------------------

_LICENSE_FILENAMES = frozenset(
    {
        "LICENSE",
        "LICENSE.txt",
        "LICENSE.md",
        "LICENSE.rst",
        "LICENCE",
        "LICENCE.txt",
        "COPYING",
        "COPYING.txt",
        "COPYING.LESSER",
        "COPYRIGHT",
    }
)


#: License-file basename PREFIXES (case-insensitive). Catches real-world variants
#: the exact-name set misses: ``LICENSE.TXT`` (case), ``LICENSE.MIT`` (nlohmann),
#: ``LICENSE_1_0.txt`` (Boost), ``COPYING.LESSER``, etc.
_LICENSE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT")


def _find_license_files(dep_dir: Path) -> list[Path]:
    """Return license files found directly inside *dep_dir* (non-recursive).

    Matches case-insensitively by basename PREFIX (``LICENSE*`` / ``LICENCE*`` /
    ``COPYING*`` / ``COPYRIGHT*``) plus the exact-name set, so common decorations
    (``LICENSE.TXT``, ``LICENSE.MIT``, ``LICENSE_1_0.txt``) are picked up."""
    found = []
    try:
        for child in dep_dir.iterdir():
            if not child.is_file():
                continue
            up = child.name.upper()
            if up.startswith(_LICENSE_PREFIXES) or child.name in _LICENSE_FILENAMES:
                found.append(child)
    except OSError:
        pass
    return found


#: Bare canonical license-file names (case-insensitive): when several license
#: files disagree, the bare one is the project's PRIMARY license (e.g. eigen ships
#: COPYING.APACHE/BSD/MPL2/… alongside a bare LICENSE that IS the MPL-2.0 primary).
_CANONICAL_LICENSE_NAMES = frozenset(
    {"LICENSE", "LICENSE.TXT", "LICENSE.MD", "LICENSE.RST", "LICENCE", "LICENCE.TXT", "COPYING", "COPYING.TXT"}
)


def _pick_license(license_files: list[Path]) -> tuple[str | None, Path | None]:
    """Choose one SPDX id from possibly-many license files, CONFLICT-AWARE.

    All files agree → that id. They DISAGREE (a multi-license project) → prefer the
    bare canonical ``LICENSE``/``COPYING`` file (the declared primary); if none is
    present it is genuinely ambiguous and ``(None, None)`` is returned rather than
    asserting an arbitrary (alphabetically-first) license. A single confident match
    is returned directly."""
    detections: list[tuple[Path, str]] = []
    for lf in sorted(license_files):
        spdx = _spdx_match(_read_safe(lf))
        if spdx is not None:
            detections.append((lf, spdx))
    if not detections:
        return None, None
    if len({spdx for _, spdx in detections}) == 1:
        return detections[0][1], detections[0][0]
    for lf, spdx in detections:
        if lf.name.upper() in _CANONICAL_LICENSE_NAMES:
            return spdx, lf
    return None, None  # multi-license, no canonical file — do not guess


def _read_safe(path: Path, max_bytes: int = 65_536) -> str:
    """Read up to *max_bytes* from a file, returning empty string on error."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""


def _sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of *path*."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65_536), b""):
                h.update(chunk)
    except OSError:
        pass
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply(components: list[Component], config: "Config") -> list[Warning]:
    """Scan extracted dep dirs under ``CANN_3RD_LIB_PATH`` for license files.

    For each component whose ``license`` field is not yet set:

    1. Derive the candidate directory path as
       ``<CANN_3RD_LIB_PATH>/<component.name>`` (case-insensitive name match
       attempted when exact name isn't present).
    2. Look for ``LICENSE``/``COPYING`` files in that directory.
    3. Apply :func:`_spdx_match` to each found file.
    4. If a confident match is found, set ``component.license``, record
       ``Provenance(field="license", source=str(license_file))``, and add a
       checksum for the license file itself.
    5. When only a local source was available and it was unverified, the
       ``IntegrityFinding.LOCAL_SOURCE_UNVERIFIED`` flag is left on the
       component (not added here — it's a collector responsibility; we just
       don't remove it).

    Does nothing when ``config.network == "on"`` — that is the net enricher's
    job.  This layer is strictly offline.
    """
    warnings: list[Warning] = []

    # Resolve CANN_3RD_LIB_PATH from config.cmake_defines or the environment.
    third_lib_path: Path | None = None
    cmake_defines: dict[str, str] = getattr(config, "cmake_defines", {})
    if "CANN_3RD_LIB_PATH" in cmake_defines:
        third_lib_path = Path(cmake_defines["CANN_3RD_LIB_PATH"])
    else:
        env_val = os.environ.get("CANN_3RD_LIB_PATH")
        if env_val:
            third_lib_path = Path(env_val)
            # The CMake authority resolution deliberately ignores the environment
            # (explicit --cmake-define/config/cache only). Honor the env var here for
            # the conventional CANN workflow, but SURFACE it so an ambient CI value
            # can't silently change license enrichment without showing up anywhere.
            warnings.append(
                Warning(
                    code="cache_scan_env_source",
                    subject="CANN_3RD_LIB_PATH",
                    detail=(
                        "license cache dir taken from the CANN_3RD_LIB_PATH environment "
                        "variable (not an explicit --cmake-define/config input); pass it "
                        "explicitly for reproducible, auditable enrichment."
                    ),
                )
            )

    if third_lib_path is None or not third_lib_path.is_dir():
        # No cache dir available; nothing to scan.
        return warnings

    # Build a lowercased name → actual-dir mapping for fuzzy lookup.
    try:
        available: dict[str, Path] = {
            child.name.lower(): child
            for child in third_lib_path.iterdir()
            if child.is_dir()
        }
    except OSError:
        return warnings

    for comp in components:
        if comp.license is not None:
            # Already resolved by a higher-priority layer.
            continue

        # Candidate directory names: exact, then aliases.
        candidates = [comp.name] + list(comp.aliases)
        dep_dir: Path | None = None
        for cname in candidates:
            # Try exact, then lowercased.
            exact = third_lib_path / cname
            if exact.is_dir():
                dep_dir = exact
                break
            lowered = available.get(cname.lower())
            if lowered is not None:
                dep_dir = lowered
                break

        if dep_dir is None:
            continue

        license_files = _find_license_files(dep_dir)
        if not license_files:
            continue

        matched_id, matched_file = _pick_license(license_files)

        if matched_id is not None and matched_file is not None:
            comp.license = matched_id
            comp.provenance.append(
                Provenance(field="license", source=str(matched_file))
            )
            # Record the checksum of the license file for traceability.
            lic_sha256 = _sha256_file(matched_file)
            if lic_sha256:
                existing = comp.checksums.get("license_file_sha256")
                if existing is None:
                    comp.checksums["license_file_sha256"] = lic_sha256
        else:
            # Found license files but couldn't match an SPDX id — warn.
            file_list = ", ".join(str(lf) for lf in license_files[:3])
            warnings.append(
                Warning(
                    code="license_unresolved",
                    subject=comp.name,
                    detail=(
                        f"found license file(s) under {dep_dir} but could not "
                        f"match an SPDX identifier: {file_list}"
                    ),
                )
            )

    return warnings
