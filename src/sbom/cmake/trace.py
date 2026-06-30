"""CMake configure-trace acquisition metadata (planned).

NOTE: this module exists and is unit-tested, but is NOT yet invoked anywhere in
the pipeline (no collector dispatch runs it, and ``--resolve-cmake-ref`` resolves
the cann-cmake ref via ``git ls-remote``, not a CMake trace). The code below is
the intended implementation for when configure-trace collection is wired in.

Runs cmake with ``--trace-expand`` (or ``--trace-format=json-v1`` if available)
in a scratch build directory, then reconstructs
:class:`~sbom.cmake.parse.CMakeFile` records from the trace output.

.. warning::
   This **EXECUTES the target repository's CMake** -- a ``CMakeLists.txt`` can run
   arbitrary host commands (``execute_process``, ``file(DOWNLOAD)``, custom
   commands). It is NOT side-effect-free, and the scratch directory bounds only
   *file writes*, not command execution. Disabling FetchContent network access
   (default) does not change that. This mode is opt-in (``--collector-mode``
   defaults to ``static``, which never runs CMake) and must be run only against a
   TRUSTED repo, ideally sandboxed -- see :func:`trace_configure`.

This module captures acquisition metadata (URLs, hashes, patches, git refs,
resolved branches) that a static parse may miss due to generator expressions or
complex variable indirection.

Graceful degradation
--------------------
If cmake is not found, or the configure fails, or the trace log cannot be
parsed, :func:`trace_configure` returns an empty :class:`TraceResult` plus a
:class:`~sbom.models.Warning` — it never raises.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..models import Warning
from .parse import (
    CMakeFile,
    ExternalProject,
    FetchContentDecl,
    FindPackageCall,
    IncludeStmt,
    VcsRef,
)

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public dataclass (per INTERFACE.md)
# ---------------------------------------------------------------------------


@dataclass
class TraceResult:
    """Output of a cmake configure-trace run."""

    files: list[CMakeFile]  # same shape parse.py produces
    warnings: list  # list[Warning]


# ---------------------------------------------------------------------------
# Internal: JSON-v1 trace parsing
# ---------------------------------------------------------------------------


def _parse_json_trace(trace_text: str) -> list[dict]:
    """Parse ``--trace-format=json-v1`` output into a list of event dicts.

    Each line of the trace is an independent JSON object.
    """
    events: list[dict] = []
    for line in trace_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            _log.debug("Skipping non-JSON trace line: %s", line[:120])
    return events


def _parse_text_trace(trace_text: str) -> list[dict]:
    """Parse ``--trace-expand`` text output into synthetic event dicts.

    Format of each line::

        /path/to/file.cmake(42):  cmake_command(arg1 arg2 ...)

    We reconstruct a pseudo-event dict with keys ``file``, ``line``, ``cmd``,
    ``args`` so the rest of the pipeline can treat both formats uniformly.
    """
    # Pattern: optional leading whitespace, path (possibly with spaces but
    # cmake paths rarely have them), parenthesised line number, colon,
    # spaces, command name, parenthesised args.
    pattern = re.compile(
        r'^(?P<file>.+?)\((?P<line>\d+)\):\s+(?P<cmd>\w+)\((?P<args>.*)\)\s*$'
    )
    events: list[dict] = []
    for raw_line in trace_text.splitlines():
        m = pattern.match(raw_line)
        if not m:
            continue
        # Split args on whitespace respecting quoted strings (best-effort).
        args_raw = m.group("args").strip()
        args = _split_cmake_args(args_raw)
        events.append(
            {
                "file": m.group("file"),
                "line": int(m.group("line")),
                "cmd": m.group("cmd").lower(),
                "args": args,
            }
        )
    return events


# ---------------------------------------------------------------------------
# CMake argument tokeniser (best-effort, handles double-quoted strings)
# ---------------------------------------------------------------------------


def _split_cmake_args(raw: str) -> list[str]:
    """Tokenise a cmake argument list (space-separated, double-quote aware)."""
    tokens: list[str] = []
    current: list[str] = []
    in_quotes = False
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == '"' and not in_quotes:
            in_quotes = True
        elif ch == '"' and in_quotes:
            in_quotes = False
        elif ch == ' ' and not in_quotes:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(ch)
        i += 1
    if current:
        tokens.append("".join(current))
    return [t for t in tokens if t]


# ---------------------------------------------------------------------------
# Internal: reconstruct CMakeFile records from events
# ---------------------------------------------------------------------------


def _keyword_args(args: list[str], keywords: list[str]) -> dict[str, list[str]]:
    """Group a cmake keyword-argument list by keyword."""
    result: dict[str, list[str]] = {k: [] for k in keywords}
    current_key: str | None = None
    for arg in args:
        if arg in keywords:
            current_key = arg
        elif current_key is not None:
            result[current_key].append(arg)
    return result


def _reconstruct_files(events: list[dict]) -> list[CMakeFile]:
    """Convert trace events into a list of :class:`CMakeFile` records."""
    # Map path string -> CMakeFile being built
    file_map: dict[str, CMakeFile] = {}

    def get_file(path_str: str) -> CMakeFile:
        if path_str not in file_map:
            file_map[path_str] = CMakeFile(path=Path(path_str))
        return file_map[path_str]

    EP_KEYWORDS = [
        "URL", "URL_HASH", "GIT_REPOSITORY", "GIT_TAG",
        "TLS_VERIFY", "PATCH_COMMAND", "DEPENDS",
        "CONFIGURE_COMMAND", "BUILD_COMMAND", "INSTALL_COMMAND",
        "DOWNLOAD_COMMAND", "UPDATE_COMMAND",
    ]
    FC_KEYWORDS = [
        "GIT_REPOSITORY", "GIT_TAG", "URL", "URL_HASH", "PATCH_COMMAND",
    ]
    FP_KEYWORDS = ["REQUIRED", "QUIET", "COMPONENTS", "OPTIONAL_COMPONENTS"]
    INCLUDE_KEYWORDS: list[str] = []

    for ev in events:
        cmd: str = ev.get("cmd", "").lower()
        args: list[str] = ev.get("args", [])
        src_file: str = ev.get("file", "")
        if not src_file or not args:
            continue

        cmake_file = get_file(src_file)

        if cmd == "externalproject_add":
            name = args[0] if args else ""
            kw = _keyword_args(args[1:], EP_KEYWORDS)

            url = kw["URL"][0] if kw["URL"] else None
            url_hash: str | None = None
            if kw["URL_HASH"]:
                raw_hash = kw["URL_HASH"][0]
                # cmake format is SHA256=<value>
                if "=" in raw_hash:
                    url_hash = raw_hash.split("=", 1)[1]
                else:
                    url_hash = raw_hash

            git_repo = kw["GIT_REPOSITORY"][0] if kw["GIT_REPOSITORY"] else None
            git_tag = kw["GIT_TAG"][0] if kw["GIT_TAG"] else None
            vcs: VcsRef | None = None
            if git_repo or git_tag:
                vcs = VcsRef(requested=git_tag)

            tls_raw = kw["TLS_VERIFY"][0].upper() if kw["TLS_VERIFY"] else None
            tls_verify: bool | None = None
            if tls_raw == "OFF":
                tls_verify = False
            elif tls_raw == "ON":
                tls_verify = True

            ep = ExternalProject(
                name=name,
                source_version=None,
                set_version=None,
                canonical_url=url,
                resolved_url_or_path=url,
                url_hash=url_hash,
                tls_verify=tls_verify,
                git_repository=git_repo,
                git_tag=git_tag,
                vcs_ref=vcs,
                depends=kw["DEPENDS"],
            )
            cmake_file.external_projects.append(ep)

        elif cmd == "fetchcontent_declare":
            name = args[0] if args else ""
            kw = _keyword_args(args[1:], FC_KEYWORDS)

            url = kw["URL"][0] if kw["URL"] else None
            url_hash: str | None = None
            if kw["URL_HASH"]:
                raw_hash = kw["URL_HASH"][0]
                url_hash = raw_hash.split("=", 1)[1] if "=" in raw_hash else raw_hash

            git_repo = kw["GIT_REPOSITORY"][0] if kw["GIT_REPOSITORY"] else None
            git_tag = kw["GIT_TAG"][0] if kw["GIT_TAG"] else None
            vcs = VcsRef(requested=git_tag) if (git_repo or git_tag) else None

            fc = FetchContentDecl(
                name=name,
                canonical_url=url,
                resolved_url_or_path=url,
                url_hash=url_hash,
                git_repository=git_repo,
                git_tag=git_tag,
                vcs_ref=vcs,
            )
            cmake_file.fetch_contents.append(fc)

        elif cmd == "find_package":
            from ..models import FindPackageInfo

            pkg_name = args[0] if args else ""
            flags = set(a.upper() for a in args[1:])
            info = FindPackageInfo(
                required="REQUIRED" in flags,
                quiet="QUIET" in flags,
            )
            cmake_file.find_packages.append(FindPackageCall(name=pkg_name, info=info))

        elif cmd == "include":
            path_str = args[0] if args else ""
            cmake_file.includes.append(
                IncludeStmt(path=path_str, resolved=None)
            )

        elif cmd == "project":
            proj_name = args[0] if args else None
            cmake_file.project_name = proj_name
            # Check for VERSION keyword
            if "VERSION" in args:
                idx = args.index("VERSION")
                if idx + 1 < len(args):
                    cmake_file.project_version = args[idx + 1]

        elif cmd == "cmake_minimum_required":
            if "VERSION" in args:
                idx = args.index("VERSION")
                if idx + 1 < len(args):
                    cmake_file.cmake_minimum_required = args[idx + 1]

    return list(file_map.values())


# ---------------------------------------------------------------------------
# Public API (per INTERFACE.md)
# ---------------------------------------------------------------------------


def trace_configure(
    repo_root: Path,
    scratch_dir: Path,
    *,
    cmake_defines: dict[str, str],
    effective_cmake_root: Path,
) -> TraceResult:
    """Run a trace configure of the target repo and reconstruct CMakeFile records.

    .. warning::
       **This EXECUTES the target repository's CMake at configure time.** A repo's
       ``CMakeLists.txt`` can run arbitrary host commands (``execute_process``,
       ``file(DOWNLOAD)``, custom commands, generator scripts). This is NOT
       side-effect-free: only run configured/trace mode against a repository you
       trust, and prefer a sandbox / container / throwaway user. The mode is opt-in
       (``--collector-mode`` defaults to ``static``, which never runs CMake).

    FetchContent network fetches are best-effort disabled via
    ``-DFETCHCONTENT_UPDATES_DISCONNECTED=ON`` / ``-DFETCHCONTENT_FULLY_DISCONNECTED=ON``,
    and the configure runs inside *scratch_dir* so the source tree is not modified --
    but neither prevents a determined repo from running other commands.

    On any failure (cmake not found, configure error, parse error) the function
    returns an empty :class:`TraceResult` plus a :class:`~sbom.models.Warning`.
    """
    collected_warnings: list[Warning] = []

    scratch_dir.mkdir(parents=True, exist_ok=True)

    # Build cmake command: try json-v1 first (cmake >= 3.17), fall back to
    # plain --trace-expand.  We detect which to use based on cmake version.
    base_defines: dict[str, str] = {
        # Disable network fetches
        "FETCHCONTENT_UPDATES_DISCONNECTED": "ON",
        "FETCHCONTENT_FULLY_DISCONNECTED": "ON",
        **cmake_defines,
    }
    if effective_cmake_root:
        base_defines.setdefault("CANN_3RD_LIB_PATH", str(effective_cmake_root))

    define_flags: list[str] = [f"-D{k}={v}" for k, v in base_defines.items()]

    # Prefer json-v1 trace format
    trace_log = scratch_dir / "cmake_trace.json"
    cmd_json = [
        "cmake",
        *define_flags,
        "--trace-format=json-v1",
        f"--trace-redirect={trace_log}",
        str(repo_root),
        "-B", str(scratch_dir / "build"),
    ]

    use_json_format = True
    try:
        result = subprocess.run(
            cmd_json,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        collected_warnings.append(
            Warning(
                code="trace_cmake_not_found",
                detail="cmake executable not found; skipping trace collection",
            )
        )
        return TraceResult(files=[], warnings=collected_warnings)
    except subprocess.TimeoutExpired:
        collected_warnings.append(
            Warning(
                code="trace_configure_timeout",
                detail=f"cmake trace configure timed out for {repo_root}",
            )
        )
        return TraceResult(files=[], warnings=collected_warnings)

    # If json-v1 flag is unrecognised (older cmake), fall back to text trace
    if result.returncode != 0 and "--trace-format" in result.stderr:
        _log.debug("json-v1 trace not supported; falling back to --trace-expand")
        use_json_format = False
        trace_log = scratch_dir / "cmake_trace.txt"
        cmd_text = [
            "cmake",
            *define_flags,
            "--trace-expand",
            f"--trace-redirect={trace_log}",
            str(repo_root),
            "-B", str(scratch_dir / "build"),
        ]
        try:
            result = subprocess.run(
                cmd_text,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            collected_warnings.append(
                Warning(
                    code="trace_configure_timeout",
                    detail=f"cmake trace configure timed out for {repo_root}",
                )
            )
            return TraceResult(files=[], warnings=collected_warnings)

    if result.returncode != 0:
        collected_warnings.append(
            Warning(
                code="trace_configure_failed",
                detail=(
                    f"cmake trace configure exited {result.returncode} for {repo_root}; "
                    f"stderr: {result.stderr[:500]}"
                ),
            )
        )
        return TraceResult(files=[], warnings=collected_warnings)

    # Read trace output
    if not trace_log.exists():
        # Some cmake versions write trace to stderr even with --trace-redirect
        trace_text = result.stderr
        if not trace_text:
            collected_warnings.append(
                Warning(
                    code="trace_no_output",
                    detail=f"cmake trace produced no output (log: {trace_log})",
                )
            )
            return TraceResult(files=[], warnings=collected_warnings)
    else:
        trace_text = trace_log.read_text(encoding="utf-8", errors="replace")

    try:
        if use_json_format:
            events = _parse_json_trace(trace_text)
        else:
            events = _parse_text_trace(trace_text)
        files = _reconstruct_files(events)
    except Exception as exc:  # noqa: BLE001
        collected_warnings.append(
            Warning(
                code="trace_parse_error",
                detail=f"Failed to parse cmake trace output: {exc}",
            )
        )
        return TraceResult(files=[], warnings=collected_warnings)

    if not files:
        collected_warnings.append(
            Warning(
                code="trace_no_records",
                detail="cmake trace parsed but produced no CMakeFile records",
            )
        )

    return TraceResult(files=files, warnings=collected_warnings)
