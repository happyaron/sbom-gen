"""CMake File API reader (the planned ``configured`` collection mode).

NOTE: this module exists and is unit-tested, but is NOT yet wired into the
pipeline — ``--collector-mode configured``/``both`` currently emit a
``collector_mode_unimplemented`` warning and run the static collector only. The
code below is the intended implementation for when that dispatch is added.

Reads a CMake File API reply directory (codemodel v2) when present and returns
a :class:`FileApiGraph`.  When the reply directory is absent or malformed the
function returns an empty graph plus a :class:`~sbom.models.Warning`, so callers
can treat this module as gracefully-degrading.

This module answers the *graph* question (targets, link relationships, install
relationships) and deliberately does NOT attempt to extract ExternalProject_Add
URLs, patches or TLS_VERIFY — that is parse.py / trace.py territory.

Usage
-----
``read_reply(reply_dir)`` — parse an already-generated reply directory.
``configure_and_query(repo_root, build_dir, cmake_defines=...)`` — run cmake
with the File API query stanza and then call ``read_reply``.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Warning

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public dataclasses (per INTERFACE.md)
# ---------------------------------------------------------------------------


@dataclass
class FileApiTarget:
    """One CMake target parsed from a File API codemodel reply."""

    name: str
    type: str  # EXECUTABLE | STATIC_LIBRARY | SHARED_LIBRARY | MODULE_LIBRARY | …
    link_libraries: list[str] = field(default_factory=list)
    imported: bool = False


@dataclass
class FileApiGraph:
    """Aggregated graph from a CMake File API reply."""

    targets: list[FileApiTarget] = field(default_factory=list)
    install_relationships: list[tuple[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_QUERY_DIR_PARTS = (".cmake", "api", "v1", "query", "client-sbomgen")
_REPLY_DIR_PARTS = (".cmake", "api", "v1", "reply")
_QUERY_CODEGEN_V2 = "codemodel-v2"


def _write_query(build_dir: Path) -> None:
    """Write the File API query file so CMake generates a reply on next configure."""
    query_dir = build_dir.joinpath(*_QUERY_DIR_PARTS)
    query_dir.mkdir(parents=True, exist_ok=True)
    (query_dir / _QUERY_CODEGEN_V2).write_text("")


def _find_index(reply_dir: Path) -> Path | None:
    """Return the most recent index JSON file in *reply_dir*, or None."""
    indices = sorted(reply_dir.glob("index-*.json"))
    return indices[-1] if indices else None


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _parse_targets(reply_dir: Path, codemodel: dict) -> list[FileApiTarget]:
    """Walk the codemodel reply and collect :class:`FileApiTarget` records."""
    targets: list[FileApiTarget] = []

    configurations = codemodel.get("configurations", [])
    for config in configurations:
        for target_ref in config.get("targets", []):
            json_file = target_ref.get("jsonFile")
            if not json_file:
                continue
            target_path = reply_dir / json_file
            if not target_path.exists():
                _log.debug("File API target file missing: %s", target_path)
                continue
            try:
                tdata = _load_json(target_path)
            except (json.JSONDecodeError, OSError) as exc:
                _log.debug("Failed to parse target %s: %s", target_path, exc)
                continue

            name = tdata.get("name", "")
            ttype = tdata.get("type", "UNKNOWN")
            imported = bool(tdata.get("isImported", False))

            link_libs: list[str] = []
            link_section = tdata.get("link", {})
            for item in link_section.get("commandFragments", []):
                role = item.get("role", "")
                fragment = item.get("fragment", "")
                # Only collect library fragments (not flags, paths, …)
                if role == "libraries" and fragment:
                    link_libs.append(fragment.strip())

            # Also collect explicit dependencies recorded under "dependencies"
            for dep in tdata.get("dependencies", []):
                dep_id = dep.get("id", "")
                if dep_id:
                    link_libs.append(dep_id)

            targets.append(
                FileApiTarget(
                    name=name,
                    type=ttype,
                    link_libraries=link_libs,
                    imported=imported,
                )
            )

    return targets


def _parse_install_relationships(codemodel: dict) -> list[tuple[str, str]]:
    """Extract (target_name, install_destination) pairs from the codemodel."""
    pairs: list[tuple[str, str]] = []
    for config in codemodel.get("configurations", []):
        for proj in config.get("projects", []):
            proj_name = proj.get("name", "")
            for dir_entry in proj.get("directories", []):
                dest = dir_entry.get("installDestination", "")
                if dest:
                    pairs.append((proj_name, dest))
    return pairs


# ---------------------------------------------------------------------------
# Public API (per INTERFACE.md)
# ---------------------------------------------------------------------------


def read_reply(reply_dir: Path) -> tuple[FileApiGraph, list[Warning]]:
    """Parse an already-generated File API reply directory (no configure).

    Returns ``(graph, warnings)``.  If the reply directory is absent or no
    index is found, ``graph`` is empty and a warning with code
    ``fileapi_reply_missing`` is returned so callers can degrade gracefully.
    """
    warnings: list[Warning] = []

    if not reply_dir.exists():
        warnings.append(
            Warning(
                code="fileapi_reply_missing",
                detail=f"File API reply directory not found: {reply_dir}",
            )
        )
        return FileApiGraph(), warnings

    index_path = _find_index(reply_dir)
    if index_path is None:
        warnings.append(
            Warning(
                code="fileapi_reply_missing",
                detail=f"No index-*.json found in {reply_dir}",
            )
        )
        return FileApiGraph(), warnings

    try:
        index = _load_json(index_path)
    except (json.JSONDecodeError, OSError) as exc:
        warnings.append(
            Warning(
                code="fileapi_parse_error",
                detail=f"Failed to parse File API index {index_path}: {exc}",
            )
        )
        return FileApiGraph(), warnings

    # Locate the codemodel reply object.
    # The CMake File API index reply section is:
    #   {"client-<name>": {"codemodel-v2": {"kind": "codemodel", "jsonFile": …}},
    #    "stateless":      {"codemodel-v2": {"kind": "codemodel", "jsonFile": …}}}
    # We search two levels deep to handle both the client-namespaced and
    # stateless shapes, as well as any future nesting variations.
    codemodel_path: Path | None = None
    reply_section = index.get("reply", {})
    for top_val in reply_section.values():
        if not isinstance(top_val, dict):
            continue
        # Direct shape: {"kind": "codemodel", "jsonFile": …}
        if top_val.get("kind") == "codemodel":
            json_file = top_val.get("jsonFile")
            if json_file:
                codemodel_path = reply_dir / json_file
                break
        # Nested shape: {"codemodel-v2": {"kind": "codemodel", "jsonFile": …}}
        for inner_val in top_val.values():
            if isinstance(inner_val, dict) and inner_val.get("kind") == "codemodel":
                json_file = inner_val.get("jsonFile")
                if json_file:
                    codemodel_path = reply_dir / json_file
                    break
        if codemodel_path:
            break

    if codemodel_path is None or not codemodel_path.exists():
        warnings.append(
            Warning(
                code="fileapi_no_codemodel",
                detail="No codemodel reply object found in File API index",
            )
        )
        return FileApiGraph(), warnings

    try:
        codemodel = _load_json(codemodel_path)
    except (json.JSONDecodeError, OSError) as exc:
        warnings.append(
            Warning(
                code="fileapi_parse_error",
                detail=f"Failed to parse codemodel reply {codemodel_path}: {exc}",
            )
        )
        return FileApiGraph(), warnings

    targets = _parse_targets(reply_dir, codemodel)
    install_relationships = _parse_install_relationships(codemodel)

    return FileApiGraph(targets=targets, install_relationships=install_relationships), warnings


def configure_and_query(
    repo_root: Path,
    build_dir: Path,
    *,
    cmake_defines: dict[str, str],
) -> tuple[FileApiGraph, list[Warning]]:
    """Configure *repo_root* with the File API query stanza and parse the reply.

    .. warning::
       This **executes the target repo's CMake** (``cmake <repo>`` runs its
       ``CMakeLists.txt`` -- ``execute_process`` / custom commands / generator
       scripts run arbitrary host commands). It is opt-in (``--collector-mode``
       defaults to ``static``); run it only against a trusted repo, ideally
       sandboxed. The scratch *build_dir* bounds file writes, not command execution.

    On failure (cmake not found, configure error) the function returns an empty
    graph plus a warning rather than raising.

    Does NOT expose ExternalProject_Add URLs/patches/TLS_VERIFY — use parse.py or
    trace.py for acquisition metadata.
    """
    warnings: list[Warning] = []

    build_dir.mkdir(parents=True, exist_ok=True)
    _write_query(build_dir)

    cmake_cmd = ["cmake"]
    for key, val in cmake_defines.items():
        cmake_cmd += [f"-D{key}={val}"]
    cmake_cmd += [str(repo_root), "-B", str(build_dir)]

    try:
        result = subprocess.run(
            cmake_cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        warnings.append(
            Warning(
                code="fileapi_cmake_not_found",
                detail="cmake executable not found; skipping File API collection",
            )
        )
        return FileApiGraph(), warnings
    except subprocess.TimeoutExpired:
        warnings.append(
            Warning(
                code="fileapi_configure_timeout",
                detail=f"cmake configure timed out for {repo_root}",
            )
        )
        return FileApiGraph(), warnings

    if result.returncode != 0:
        warnings.append(
            Warning(
                code="fileapi_configure_failed",
                detail=(
                    f"cmake configure exited {result.returncode} for {repo_root}; "
                    f"stderr: {result.stderr[:500]}"
                ),
            )
        )
        return FileApiGraph(), warnings

    reply_dir = build_dir.joinpath(*_REPLY_DIR_PARTS)
    graph, rw = read_reply(reply_dir)
    warnings.extend(rw)
    return graph, warnings
