"""Static CMake parser (no build).

This is the riskiest module: in ``declared-all`` it is the only mode that sees
every conditional branch. It consumes ``.cmake``/``CMakeLists.txt`` text plus the
:class:`~sbom.models.CmakeAuthority` and produces the structured records the
``CppCollector`` turns into model objects. It never configures or runs CMake.

The parser is deliberately tolerant: malformed input yields partial records,
never an exception. Variable references (``${FOO}``) are kept as raw text unless
a ``set()`` in the same file proves a value; URL candidates inside an
``if()/elseif()/else()`` chain are split into a *canonical* ``https://`` URL and
the *resolved* local-cache path/URL the first branch would select.
"""

from __future__ import annotations

import bisect
import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..models import (
    ActivationCondition,
    CmakeAuthority,
    CmakeAuthorityBranch,
    CommandContext,
    EnvironmentTool,
    FindPackageInfo,
    IntegrityFinding,
    Patch,
    VcsRef,
    Warning,
)

__all__ = [
    "ExternalProject",
    "FetchContentDecl",
    "FindPackageCall",
    "IncludeStmt",
    "LinkLibraryToken",
    "AddDependenciesEdge",
    "ProgramInvocation",
    "CMakeFile",
    "parse_file",
    "parse_recursive",
    "tokenize_command",
    "classify_link_token",
    "classify_program",
    "program_to_environment_tool",
    "discover_roots",
    "resolve_cmake_authority",
]


# ---------------------------------------------------------------------------
# Parse-layer dataclasses (per INTERFACE.md §sbom/cmake/parse.py)
# ---------------------------------------------------------------------------


@dataclass
class ExternalProject:
    name: str
    source_version: str | None  # from filename/URL
    set_version: str | None  # from set(*_VERSION ...)
    canonical_url: str | None
    resolved_url_or_path: str | None
    url_hash: str | None  # SHA256 from URL_HASH, else None
    tls_verify: bool | None  # None=unspecified; False ⇒ tls finding
    git_repository: str | None
    git_tag: str | None
    vcs_ref: VcsRef | None
    patches: list[Patch] = field(default_factory=list)
    depends: list[str] = field(default_factory=list)
    commands: dict[str, str] = field(default_factory=dict)
    integrity_findings: list[IntegrityFinding] = field(default_factory=list)


@dataclass
class FetchContentDecl:
    name: str
    canonical_url: str | None
    resolved_url_or_path: str | None
    url_hash: str | None
    git_repository: str | None
    git_tag: str | None
    vcs_ref: VcsRef | None
    patches: list[Patch] = field(default_factory=list)
    integrity_findings: list[IntegrityFinding] = field(default_factory=list)


@dataclass
class FindPackageCall:
    name: str
    info: FindPackageInfo
    conditions: list[ActivationCondition] = field(default_factory=list)


@dataclass
class IncludeStmt:
    path: str  # raw include() argument
    resolved: Path | None  # resolved against effective_cmake_root
    conditions: list[ActivationCondition] = field(default_factory=list)


@dataclass
class LinkLibraryToken:
    raw: str  # one token from a link line
    target_property: str | None  # set()-var it was expanded from, if any
    conditions: list[ActivationCondition] = field(default_factory=list)


@dataclass
class AddDependenciesEdge:
    target: str
    depends_on: list[str]


@dataclass
class ProgramInvocation:
    """A raw program/tool invocation (classified later by classify_program)."""

    name: str
    command_context: str  # CommandContext value (see mapping)
    path: str | None = None
    args: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    required: bool | None = None
    conditions: list[ActivationCondition] = field(default_factory=list)
    source_file: str | None = None


@dataclass
class CMakeFile:
    """Everything parse.py extracts from one CMake file."""

    path: Path
    includes: list[IncludeStmt] = field(default_factory=list)
    external_projects: list[ExternalProject] = field(default_factory=list)
    fetch_contents: list[FetchContentDecl] = field(default_factory=list)
    find_packages: list[FindPackageCall] = field(default_factory=list)
    link_tokens: list[LinkLibraryToken] = field(default_factory=list)
    add_dependencies: list[AddDependenciesEdge] = field(default_factory=list)
    programs: list[ProgramInvocation] = field(default_factory=list)
    project_name: str | None = None
    project_version: str | None = None
    cmake_minimum_required: str | None = None
    macro_calls: list[tuple[str, list[str]]] = field(default_factory=list)

    # --- call-site context (populated by parse_recursive, NOT parse_file) -----
    #: The file that include()'d / macro-expanded this one (the call site). The
    #: usage_scope of this fragment's deps derives from this chain, not from the
    #: fragment's own definition path (e.g. gtest.cmake is included from
    #: ut.cmake -> test scope).
    included_by: Path | None = None
    #: The FULL ordered include chain that pulled this file in (root entrypoint
    #: first, immediate includer last; ``included_by`` is its last element). The
    #: collector classifies usage_scope from the most-specific call site across the
    #: WHOLE chain -- so a path-neutral fragment reached via a deep test/example
    #: entrypoint is scoped test/example, not RUNTIME (it would otherwise leak into
    #: the release view). Empty for a single-file parse / the entry file.
    include_chain: list[Path] = field(default_factory=list)
    #: The raw gating expressions active at the call site that pulled this file
    #: in (the surrounding if() at the include statement + any custom-macro gate,
    #: e.g. add_cann_third_party's TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD).
    call_site_conditions: list[ActivationCondition] = field(default_factory=list)
    #: File-level integrity findings keyed by the component they attach to
    #: (e.g. opbase -> local_source_unverified). The CppCollector attaches each
    #: to the matching component.
    integrity_findings: dict[str, list[IntegrityFinding]] = field(
        default_factory=dict
    )
    #: Parallel to :attr:`macro_calls`: the if()-gate stack active at each macro
    #: call site. parse_recursive merges these (plus the macro's own gate) into
    #: the expanded fragment's call_site_conditions.
    macro_call_conditions: list[list[ActivationCondition]] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Low-level tokenizing of CMake command invocations
# ---------------------------------------------------------------------------

_COMMAND_NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")


@dataclass
class _Command:
    name: str
    args: list[str]
    raw_args: str
    start: int  # offset of '(' open
    end: int  # offset just past the matching ')'


def _strip_comments(text: str) -> str:
    """Remove ``#`` line comments and ``#[[ ... ]]`` bracket comments while
    preserving newlines so command offsets stay roughly stable."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("#[[", i):
            j = text.find("]]", i + 3)
            if j == -1:
                j = n
            else:
                j += 2
            out.append("\n" * text.count("\n", i, j))
            i = j
            continue
        nl = text.find("\n", i)
        if nl == -1:
            nl = n
        out.append(_strip_line_comment(text[i:nl]))
        if nl < n:
            out.append("\n")
        i = nl + 1
    return "".join(out)


def _strip_line_comment(line: str) -> str:
    in_str = False
    for idx, ch in enumerate(line):
        if ch == '"':
            backslashes = 0
            k = idx - 1
            while k >= 0 and line[k] == "\\":
                backslashes += 1
                k -= 1
            if backslashes % 2 == 0:
                in_str = not in_str
        elif ch == "#" and not in_str:
            return line[:idx]
    return line


def _split_args(raw: str) -> list[str]:
    """Split an argument blob into CMake arguments, honoring quotes."""
    args: list[str] = []
    i = 0
    n = len(raw)
    cur: list[str] = []
    in_str = False
    while i < n:
        ch = raw[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                cur.append(raw[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
                i += 1
                continue
            cur.append(ch)
            i += 1
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch.isspace():
            if cur:
                args.append("".join(cur))
                cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    if cur:
        args.append("".join(cur))
    return args


def _iter_commands(text: str):
    """Yield :class:`_Command` for every ``name(...)`` invocation."""
    n = len(text)
    for m in _COMMAND_NAME_RE.finditer(text):
        name = m.group(1)
        open_paren = m.end() - 1
        depth = 1
        i = open_paren + 1
        in_str = False
        while i < n and depth > 0:
            ch = text[i]
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    in_str = False
                i += 1
                continue
            if ch == '"':
                in_str = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        close = i
        raw_args = text[open_paren + 1 : close - 1]
        yield _Command(
            name=name,
            args=_split_args(raw_args),
            raw_args=raw_args,
            start=open_paren,
            end=close,
        )


# ---------------------------------------------------------------------------
# Condition tracking: if()/elseif()/else()/endif() stack
# ---------------------------------------------------------------------------


#: Single-entry cache. Parsing one file calls ``_condition_stack_at`` once per
#: command (10 call sites), each previously re-tokenizing the whole prefix ->
#: O(n^2). All calls within a file share the SAME ``text`` object, so we compute
#: the if-stack in ONE forward pass and cache it by ``text`` identity -> O(n).
_COND_CACHE_TEXT: str | None = None
_COND_CACHE: tuple[list[int], list[list[ActivationCondition]]] | None = None


def _condition_marks(text: str) -> tuple[list[int], list[list[ActivationCondition]]]:
    """``(ends, stacks)`` — for each command in order, its END offset and the
    if-gate stack AFTER that command. Built once per file (cached by identity)."""
    global _COND_CACHE_TEXT, _COND_CACHE
    if _COND_CACHE_TEXT is not text or _COND_CACHE is None:
        ends: list[int] = []
        stacks: list[list[ActivationCondition]] = []
        stack: list[ActivationCondition] = []
        for cmd in _iter_commands(text):
            low = cmd.name.lower()
            if low == "if":
                stack.append(ActivationCondition(expr=cmd.raw_args.strip()))
            elif low == "elseif":
                if stack:
                    stack.pop()
                stack.append(ActivationCondition(expr=f"NOT ({cmd.raw_args.strip()})"))
            elif low == "else":
                if stack:
                    prev = stack.pop()
                    stack.append(ActivationCondition(expr=f"NOT ({prev.expr})"))
            elif low == "endif":
                if stack:
                    stack.pop()
            ends.append(cmd.end)
            stacks.append(list(stack))
        _COND_CACHE_TEXT = text
        _COND_CACHE = (ends, stacks)
    return _COND_CACHE


def _condition_stack_at(text: str, offset: int) -> list[ActivationCondition]:
    """Return the if()-gate stack active at ``offset`` (raw expressions).

    Equivalent to re-parsing ``text[:offset]`` (the gate enclosing a command at
    ``offset`` = the stack after every command that ENDS at/before ``offset``), but
    served from the per-file one-pass index instead of re-tokenizing each call.
    """
    ends, stacks = _condition_marks(text)
    i = bisect.bisect_right(ends, offset) - 1
    return list(stacks[i]) if i >= 0 else []


# ---------------------------------------------------------------------------
# Variable resolution (best-effort, file-local set())
# ---------------------------------------------------------------------------

_VAR_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _collect_set_vars(text: str) -> dict[str, list[str]]:
    """Map each ``set(VAR value...)`` to its assigned value(s).

    Every value is kept so URL extraction can recover both the canonical https
    URL and the local fallback when a variable is assigned across an if chain.
    """
    out: dict[str, list[str]] = {}
    for cmd in _iter_commands(text):
        if cmd.name.lower() != "set" or not cmd.args:
            continue
        var = cmd.args[0]
        rest = cmd.args[1:]
        if "CACHE" in rest:
            rest = rest[: rest.index("CACHE")]
        else:
            rest = [a for a in rest if a not in ("PARENT_SCOPE", "FORCE")]
        out.setdefault(var, [])
        out[var].extend(rest)
    return out


def _resolve_var(token: str, set_vars: dict[str, list[str]]) -> str | None:
    m = _VAR_REF_RE.fullmatch(token.strip())
    if not m:
        return None
    vals = set_vars.get(m.group(1))
    return vals[-1] if vals else None


def _all_values_for(token: str, set_vars: dict[str, list[str]]) -> list[str]:
    m = _VAR_REF_RE.fullmatch(token.strip())
    if not m:
        return [token]
    return set_vars.get(m.group(1), [])


# ---------------------------------------------------------------------------
# Version extraction
# ---------------------------------------------------------------------------

_FILENAME_VERSION_RE = re.compile(
    r"[-/](?:v)?(\d+(?:\.\d+)+(?:[-.]?[A-Za-z0-9]+)?)"
    r"(?:\.tar\.gz|\.tar\.bz2|\.tar\.xz|\.tgz|\.zip|/?$)"
)
_SET_VERSION_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*_VERSION$")


def _version_from_filename(url: str | None) -> str | None:
    if not url:
        return None
    base = url.rstrip("/").split("/")[-1]
    m = _FILENAME_VERSION_RE.search("/" + base)
    if m:
        return m.group(1)
    m2 = re.search(r"-(\d+(?:\.\d+)+)$", base)
    if m2:
        return m2.group(1)
    return None


def _set_version_from_text(text: str) -> str | None:
    for cmd in _iter_commands(text):
        if cmd.name.lower() != "set" or len(cmd.args) < 2:
            continue
        if _SET_VERSION_RE.match(cmd.args[0]):
            return cmd.args[1]
    return None


# ---------------------------------------------------------------------------
# URL / hash extraction
# ---------------------------------------------------------------------------


def _is_url(s: str) -> bool:
    return bool(re.match(r"^(https?|ftp|git|ssh)://", s)) or s.startswith("git@")


def _split_url_candidates(
    url_arg: str, set_vars: dict[str, list[str]]
) -> tuple[str | None, str | None]:
    """Return (canonical_url, resolved_url_or_path) for a URL argument.

    The argument is typically ``${REQ_URL}`` assigned multiple times across an
    if/elseif/else chain (local cache fallbacks first, canonical https URL
    last). canonical = the first https-style URL among the candidates; resolved
    = the first (highest-priority) candidate an actual configure would select.
    """
    candidates = _all_values_for(url_arg, set_vars)
    if not candidates:
        return (None, None)
    canonical = next((c for c in candidates if _is_url(c)), None)
    return (canonical, candidates[0])


_SHA256_RE = re.compile(r"SHA256=([0-9a-fA-F]{64})")


def _extract_url_hash(args: list[str]) -> str | None:
    for i, a in enumerate(args):
        m = _SHA256_RE.search(a)
        if m:
            return m.group(1).lower()
        if a.upper() == "URL_HASH" and i + 1 < len(args):
            m2 = _SHA256_RE.search(args[i + 1])
            if m2:
                return m2.group(1).lower()
        if a.upper() == "SHA256" and i + 1 < len(args):
            if re.fullmatch(r"[0-9a-fA-F]{64}", args[i + 1]):
                return args[i + 1].lower()
    return None


def _kw_value(args: list[str], keyword: str) -> str | None:
    for i, a in enumerate(args):
        if a == keyword and i + 1 < len(args):
            return args[i + 1]
    return None


_EP_KEYWORDS = {
    "URL", "URL_HASH", "URL_MD5", "DOWNLOAD_DIR", "DOWNLOAD_NAME", "SOURCE_DIR",
    "BINARY_DIR", "PREFIX", "TMP_DIR", "STAMP_DIR", "LOG_DIR", "INSTALL_DIR",
    "GIT_REPOSITORY", "GIT_TAG", "GIT_SHALLOW", "GIT_PROGRESS", "GIT_SUBMODULES",
    "GIT_CONFIG", "SVN_REPOSITORY", "HG_REPOSITORY", "TLS_VERIFY", "TLS_CAINFO",
    "TIMEOUT", "PATCH_COMMAND", "CONFIGURE_COMMAND", "BUILD_COMMAND",
    "INSTALL_COMMAND", "TEST_COMMAND", "DOWNLOAD_COMMAND", "UPDATE_COMMAND",
    "BUILD_IN_SOURCE", "BUILD_ALWAYS", "CONFIGURE_HANDLED_BY_BUILD", "DEPENDS",
    "EXCLUDE_FROM_ALL", "STEP_TARGETS", "CMAKE_ARGS", "CMAKE_CACHE_ARGS",
    "LIST_SEPARATOR", "LOG_DOWNLOAD", "LOG_CONFIGURE", "LOG_BUILD", "LOG_INSTALL",
    "USES_TERMINAL_DOWNLOAD", "SOURCE_SUBDIR", "OVERRIDE_FIND_PACKAGE",
    "FIND_PACKAGE_ARGS", "SYSTEM",
}

_COMMAND_FIELDS = {
    "CONFIGURE_COMMAND": ("configure", "ep_configure"),
    "BUILD_COMMAND": ("build", "ep_build"),
    "INSTALL_COMMAND": ("install", "ep_install"),
    "DOWNLOAD_COMMAND": ("download", "ep_download"),
    "UPDATE_COMMAND": ("update", "ep_update"),
    "PATCH_COMMAND": ("patch", "patch_command"),
}


def _collect_multi_value(args: list[str], keyword: str) -> list[str]:
    """Collect every value following ``keyword`` until the next known keyword."""
    out: list[str] = []
    i = 0
    n = len(args)
    while i < n:
        if args[i] == keyword:
            j = i + 1
            while j < n and args[j] not in _EP_KEYWORDS:
                out.append(args[j])
                j += 1
            i = j
            continue
        i += 1
    return out


def _command_str(args: list[str], keyword: str) -> str | None:
    """Reconstruct a ``keyword <tokens...>`` value as a single string.

    Returns "" for an explicitly-emptied command (``CONFIGURE_COMMAND ""``) and
    None when the keyword is absent.
    """
    if keyword not in args:
        return None
    toks = _collect_multi_value(args, keyword)
    return " ".join(toks)


def _depends_args(args: list[str]) -> list[str]:
    return _collect_multi_value(args, "DEPENDS")


# ---------------------------------------------------------------------------
# Patch parsing
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()


def _patches_from_command(
    command: str | None, source_file: Path | None
) -> list[Patch]:
    """Extract patch files referenced in a PATCH_COMMAND string (+ sha256)."""
    if not command:
        return []
    patches: list[Patch] = []
    seen: set[str] = set()
    for tok in command.split():
        cleaned = tok.lstrip("<").strip()
        if cleaned.endswith(".patch") or cleaned.endswith(".diff"):
            base = Path(cleaned).name
            if base in seen:
                continue
            seen.add(base)
            sha = None
            if source_file is not None:
                sha = _sha256_file(source_file.parent / base)
            patches.append(Patch(file=base, sha256=sha))
    return patches


# ---------------------------------------------------------------------------
# TLS_VERIFY + integrity findings
# ---------------------------------------------------------------------------


def _tls_verify(args: list[str]) -> bool | None:
    """Resolve a literal ``TLS_VERIFY`` value, or ``None`` when indeterminate.

    Only an explicit ON/OFF literal is conclusive. An unresolved ``${VAR}`` (or any
    unrecognized token) must NOT be read as disabled — returning ``False`` there
    would emit a spurious ``TLS_VERIFICATION_DISABLED`` finding for a value we
    simply cannot evaluate statically. Mirrors the trace-mode logic.
    """
    val = _kw_value(args, "TLS_VERIFY")
    if val is None:
        return None
    upper = val.upper()
    if upper in ("ON", "TRUE", "1", "YES"):
        return True
    if upper in ("OFF", "FALSE", "0", "NO"):
        return False
    return None


_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def _is_mutable_git_tag(tag: str | None) -> bool:
    if not tag:
        return True
    if tag.startswith("${"):
        return True  # unresolved variable -> can't prove pin
    if _COMMIT_SHA_RE.match(tag):
        return False
    return True  # branch or named tag may move -> unpinned


def _integrity_findings(
    *,
    url_hash: str | None,
    tls_verify: bool | None,
    git_repository: str | None,
    git_tag: str | None,
    resolved_url_or_path: str | None,
) -> list[IntegrityFinding]:
    findings: list[IntegrityFinding] = []
    is_git = git_repository is not None
    if not is_git and url_hash is None:
        findings.append(IntegrityFinding.NO_HASH)
    if tls_verify is False:
        findings.append(IntegrityFinding.TLS_VERIFICATION_DISABLED)
    if is_git and _is_mutable_git_tag(git_tag):
        findings.append(IntegrityFinding.UNPINNED_GIT)
    if (
        resolved_url_or_path
        and not _is_url(resolved_url_or_path)
        and not is_git
        and url_hash is None
    ):
        findings.append(IntegrityFinding.LOCAL_SOURCE_UNVERIFIED)
    return findings


# ---------------------------------------------------------------------------
# opbase-style local-source-unverified detector
# ---------------------------------------------------------------------------

_PIN_TAG_RE = re.compile(
    r"\b(?:git\s+checkout|GIT_TAG)\b\s+\$\{([A-Za-z_][A-Za-z0-9_]*)\}", re.IGNORECASE
)
_FC_NAME_RE = re.compile(
    r"FetchContent_Declare\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE
)


def _detect_local_source_unverified(text: str) -> dict[str, list[IntegrityFinding]]:
    """Detect the opbase pattern: a local source dir guarded only by
    ``if(EXISTS ...)`` whose branch never checks out the pinned tag, while
    sibling branches DO pin it (``git checkout ${TAG}`` / ``GIT_TAG ${TAG}``).

    Returns ``{component_name: [LOCAL_SOURCE_UNVERIFIED]}`` for each affected
    component (the ``FetchContent_Declare`` name in the sibling branch, e.g.
    ``opbase``). The CppCollector attaches the finding to that component.
    """
    # The pinned tag is applied somewhere in the file but only in sibling
    # branches: split the top-level if/elseif/else chain into branches and look
    # for (a) a leading branch that resolves a local source path under an
    # if(EXISTS ...) gate with no pin, and (b) a sibling branch that does pin.
    branches = _split_top_level_if_branches(text)
    if len(branches) < 2:
        return {}

    has_unpinned_local = False
    pinned_tag_vars: set[str] = set()
    fc_names: list[str] = []
    for branch in branches:
        body = branch["body"]
        guard = branch["guard"]
        pins = {m.group(1) for m in _PIN_TAG_RE.finditer(body)}
        if pins:
            pinned_tag_vars |= pins
        for m in _FC_NAME_RE.finditer(body):
            fc_names.append(m.group(1))
        # A local-source branch: the guard is an EXISTS check on a *directory*
        # path and the branch body itself applies no pin.
        if "EXISTS" in guard.upper() and not pins:
            if _guard_resolves_local_source(body, guard):
                has_unpinned_local = True

    if has_unpinned_local and pinned_tag_vars and fc_names:
        return {
            name: [IntegrityFinding.LOCAL_SOURCE_UNVERIFIED] for name in fc_names
        }
    return {}


def _guard_resolves_local_source(body: str, guard: str) -> bool:
    """True when an EXISTS-guarded branch resolves a local source dir path
    (``get_filename_component(... REALPATH)`` or a ``set(*_SOURCE_*  ...)``)."""
    low = body.lower()
    return (
        "get_filename_component" in low
        or "source_path" in low
        or "source_dir" in low
    )


def _split_top_level_if_branches(text: str) -> list[dict[str, str]]:
    """Split the file's first top-level if/elseif/else chain into branches.

    Each branch dict carries ``guard`` (the if/elseif expression, "" for else)
    and ``body`` (the text between this branch keyword and the next). Nested
    if()s are tracked so only the top-level chain is split.
    """
    matches = list(_iter_commands(text))
    branches: list[dict[str, str]] = []
    depth = 0
    chain_open = False
    cur_guard: str | None = None
    cur_start = 0
    for cmd in matches:
        low = cmd.name.lower()
        if low == "if":
            if depth == 0 and not chain_open:
                chain_open = True
                cur_guard = cmd.raw_args.strip()
                cur_start = cmd.end
            depth += 1
        elif low in ("elseif", "else") and depth == 1 and chain_open:
            branches.append(
                {"guard": cur_guard or "", "body": text[cur_start : cmd.start]}
            )
            cur_guard = cmd.raw_args.strip() if low == "elseif" else ""
            cur_start = cmd.end
        elif low == "endif":
            depth -= 1
            if depth == 0 and chain_open:
                branches.append(
                    {"guard": cur_guard or "", "body": text[cur_start : cmd.start]}
                )
                break
    return branches


# ---------------------------------------------------------------------------
# ExternalProject_Add / FetchContent_Declare extraction
# ---------------------------------------------------------------------------


def _build_external_project(
    cmd: _Command, set_vars: dict[str, list[str]], source_file: Path | None
) -> ExternalProject:
    args = cmd.args
    name = args[0] if args else ""

    url_arg = _kw_value(args, "URL")
    canonical_url, resolved = (None, None)
    if url_arg is not None:
        canonical_url, resolved = _split_url_candidates(url_arg, set_vars)

    url_hash = _extract_url_hash(args)
    tls = _tls_verify(args)

    git_repo = _kw_value(args, "GIT_REPOSITORY")
    if git_repo and git_repo.startswith("${"):
        git_repo = _resolve_var(git_repo, set_vars) or git_repo
    git_tag = _kw_value(args, "GIT_TAG")
    if git_tag and git_tag.startswith("${"):
        git_tag = _resolve_var(git_tag, set_vars) or git_tag

    vcs_ref = VcsRef(requested=git_tag) if (git_repo or git_tag) else None

    commands: dict[str, str] = {}
    for kw, (key, _ctx) in _COMMAND_FIELDS.items():
        cstr = _command_str(args, kw)
        if cstr is not None:
            commands[key] = cstr

    patches = _patches_from_command(commands.get("patch"), source_file)
    src_ver = _version_from_filename(resolved) or _version_from_filename(canonical_url)

    findings = _integrity_findings(
        url_hash=url_hash,
        tls_verify=tls,
        git_repository=git_repo,
        git_tag=git_tag,
        resolved_url_or_path=resolved,
    )

    return ExternalProject(
        name=name,
        source_version=src_ver,
        set_version=None,
        canonical_url=canonical_url,
        resolved_url_or_path=resolved,
        url_hash=url_hash,
        tls_verify=tls,
        git_repository=git_repo,
        git_tag=git_tag,
        vcs_ref=vcs_ref,
        patches=patches,
        depends=_depends_args(args),
        commands=commands,
        integrity_findings=findings,
    )


def _build_fetch_content(
    cmd: _Command, set_vars: dict[str, list[str]], source_file: Path | None
) -> FetchContentDecl:
    args = cmd.args
    name = args[0] if args else ""
    if name.startswith("${"):
        name = _resolve_var(name, set_vars) or name

    url_arg = _kw_value(args, "URL")
    canonical_url, resolved = (None, None)
    if url_arg is not None:
        canonical_url, resolved = _split_url_candidates(url_arg, set_vars)

    url_hash = _extract_url_hash(args)

    git_repo = _kw_value(args, "GIT_REPOSITORY")
    if git_repo and git_repo.startswith("${"):
        git_repo = _resolve_var(git_repo, set_vars) or git_repo
    git_tag = _kw_value(args, "GIT_TAG")
    if git_tag and git_tag.startswith("${"):
        git_tag = _resolve_var(git_tag, set_vars) or git_tag

    vcs_ref = VcsRef(requested=git_tag) if (git_repo or git_tag) else None
    patches = _patches_from_command(_command_str(args, "PATCH_COMMAND"), source_file)

    findings = _integrity_findings(
        url_hash=url_hash,
        tls_verify=_tls_verify(args),
        git_repository=git_repo,
        git_tag=git_tag,
        resolved_url_or_path=resolved,
    )

    return FetchContentDecl(
        name=name,
        canonical_url=canonical_url,
        resolved_url_or_path=resolved,
        url_hash=url_hash,
        git_repository=git_repo,
        git_tag=git_tag,
        vcs_ref=vcs_ref,
        patches=patches,
        integrity_findings=findings,
    )


# ---------------------------------------------------------------------------
# find_package
# ---------------------------------------------------------------------------


def _build_find_package(
    cmd: _Command, text: str, fatal_nearby: bool
) -> FindPackageCall:
    args = cmd.args
    name = args[0] if args else ""
    required = "REQUIRED" in args
    quiet = "QUIET" in args
    if required:
        effective_required: bool | None = True
    elif fatal_nearby:
        effective_required = True
    else:
        effective_required = None
    info = FindPackageInfo(
        required=required,
        quiet=quiet if quiet else None,
        effective_required=effective_required,
    )
    conditions = _condition_stack_at(text, cmd.start)
    return FindPackageCall(name=name, info=info, conditions=conditions)


def _has_nearby_fatal_check(text: str, name: str, after_offset: int) -> bool:
    """Detect a nearby ``if(NOT <name>_FOUND) ... FATAL_ERROR`` fatal check
    following a (often QUIET) find_package, marking effective_required=True."""
    window = text[after_offset : after_offset + 1500]
    found_var = f"{name}_FOUND"
    return found_var in window and "FATAL_ERROR" in window


# ---------------------------------------------------------------------------
# Link library token extraction
# ---------------------------------------------------------------------------

_LINK_COMMANDS = {"target_link_libraries", "link_libraries"}
_LINK_SCOPE_KW = {"PRIVATE", "PUBLIC", "INTERFACE", "LINK_PRIVATE", "LINK_PUBLIC"}


def _extract_link_tokens(
    cmd: _Command, text: str, set_vars: dict[str, list[str]]
) -> list[LinkLibraryToken]:
    conditions = _condition_stack_at(text, cmd.start)
    tokens: list[LinkLibraryToken] = []
    args = cmd.args
    start = 1 if cmd.name.lower() == "target_link_libraries" else 0
    for raw in args[start:]:
        if raw in _LINK_SCOPE_KW:
            continue
        m = _VAR_REF_RE.fullmatch(raw.strip())
        if m:
            var = m.group(1)
            vals = set_vars.get(var)
            if vals:
                for v in vals:
                    if v in _LINK_SCOPE_KW:
                        continue
                    tokens.append(
                        LinkLibraryToken(
                            raw=v, target_property=var, conditions=list(conditions)
                        )
                    )
            else:
                # unexpanded variable: keep raw so collector can warn/resolve later
                tokens.append(
                    LinkLibraryToken(
                        raw=raw, target_property=var, conditions=list(conditions)
                    )
                )
            continue
        tokens.append(
            LinkLibraryToken(raw=raw, target_property=None, conditions=list(conditions))
        )
    return tokens


def classify_link_token(token: LinkLibraryToken, local_targets: set[str]) -> str:
    """Return one of: "drop", "local", or "external".

    Drops linker flags (``-Wl,*``, ``-*`` options), generator expressions
    (``$<...>``) and any token carrying an unexpanded CMake variable reference
    (``${...}``); resolves a token defined as a local target; otherwise it is an
    external library to emit as a component.

    A token is a real dependency only when it has NO unexpanded ``${`` substring:
    a bare ``${ARGN}`` is CMake macro-varargs (never a library) and an embedded
    reference like ``lib${FOO}name`` is not a resolvable name either, so both are
    dropped the same way ``$<...>`` generator expressions are.
    """
    raw = token.raw.strip()
    if not raw:
        return "drop"
    if "$<" in raw:
        return "drop"
    if raw.startswith("-"):
        return "drop"
    if "${" in raw:
        return "drop"
    if raw in local_targets:
        return "local"
    return "external"


# ---------------------------------------------------------------------------
# add_dependencies edges
# ---------------------------------------------------------------------------


def _extract_add_dependencies(cmd: _Command) -> AddDependenciesEdge | None:
    if len(cmd.args) < 2:
        return None
    return AddDependenciesEdge(target=cmd.args[0], depends_on=list(cmd.args[1:]))


# ---------------------------------------------------------------------------
# Shell-compound command tokenization
# ---------------------------------------------------------------------------

_VAR_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_REDIRECT_TOKENS = {"<", ">", ">>", "2>", "2>&1", "&>", "1>"}


def tokenize_command(raw: str) -> list[list[str]]:
    """Split a shell-compound command into sub-commands.

    Splits on ``&&``, ``;``, pipes (``|``/``||``) and background ``&``; strips
    redirects (``<``/``>``/``2>&1``...) and their operands plus leading
    ``VAR=val`` prefixes. Recognizes ``$(MAKE)`` as a single token and keeps
    ``cmake -E`` helper argv intact. Returns one token-list per sub-command
    (empty sub-commands dropped).
    """
    if not raw or not raw.strip():
        return []
    tokens = _shell_split(raw)
    sub: list[list[str]] = []
    cur: list[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        t = tokens[i]
        if t in ("&&", ";", "|", "||", "&"):
            if cur:
                sub.append(_strip_command(cur))
            cur = []
            i += 1
            continue
        if t in _REDIRECT_TOKENS:
            if i + 1 < n and tokens[i + 1] not in ("&&", ";", "|", "||", "&"):
                i += 2
            else:
                i += 1
            continue
        cur.append(t)
        i += 1
    if cur:
        sub.append(_strip_command(cur))
    return [s for s in sub if s]


def _strip_command(tokens: list[str]) -> list[str]:
    out = list(tokens)
    while out and _VAR_ASSIGN_RE.match(out[0]):
        out.pop(0)
    return out


def _shell_split(raw: str) -> list[str]:
    """Tokenize a shell string, keeping ``$(MAKE)``/``$(...)`` and quoted runs
    intact and separating operators (``&&``, ``;``, ``|``, redirects)."""
    tokens: list[str] = []
    i = 0
    n = len(raw)
    cur: list[str] = []

    def flush():
        if cur:
            tokens.append("".join(cur))
            cur.clear()

    while i < n:
        ch = raw[i]
        if ch == "$" and i + 1 < n and raw[i + 1] == "(":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if raw[j] == "(":
                    depth += 1
                elif raw[j] == ")":
                    depth -= 1
                j += 1
            cur.append(raw[i:j])
            i = j
            continue
        if ch in ('"', "'"):
            q = ch
            j = i + 1
            while j < n and raw[j] != q:
                j += 1
            cur.append(raw[i + 1 : j])
            i = j + 1
            continue
        if ch.isspace():
            flush()
            i += 1
            continue
        if ch == "&" and i + 1 < n and raw[i + 1] == "&":
            flush()
            tokens.append("&&")
            i += 2
            continue
        if ch == "|" and i + 1 < n and raw[i + 1] == "|":
            flush()
            tokens.append("||")
            i += 2
            continue
        if ch == "&":
            flush()
            tokens.append("&")
            i += 1
            continue
        if ch == "|":
            flush()
            tokens.append("|")
            i += 1
            continue
        if ch == ";":
            flush()
            tokens.append(";")
            i += 1
            continue
        if ch == "<":
            # CMake placeholders like <SOURCE_DIR> / <BINARY_DIR> are part of a
            # token, not a shell input redirect.
            m = re.match(r"<[A-Za-z_][A-Za-z0-9_]*>", raw[i:])
            if m:
                cur.append(m.group(0))
                i += m.end()
                continue
            flush()
            tokens.append("<")
            i += 1
            continue
        if ch == ">":
            flush()
            if i + 1 < n and raw[i + 1] == ">":
                tokens.append(">>")
                i += 2
            else:
                tokens.append(">")
                i += 1
            continue
        cur.append(ch)
        i += 1
    flush()
    return tokens


# ---------------------------------------------------------------------------
# Program / tool discovery
# ---------------------------------------------------------------------------

_HOST_TOOLS = {
    "perl", "ccache", "cp", "mv", "rm", "mkdir", "python", "python3", "bash",
    "sh", "patch", "tar", "chmod", "chown", "git", "ln", "touch", "sed", "awk",
    "echo", "cat", "find", "xargs", "unzip", "gzip", "make", "env", "export",
    "unset", "true", "false", "pwd", "cd", "wget", "curl",
}

_DOMAIN_TOOLS = {
    "protoc", "host_protoc", "bisheng", "bisheng-compiler", "op_build",
    "ninja", "cmake",
}

#: ``${VAR}`` (lowercased, braces stripped) -> the real program it expands to.
#: An unresolved ``${VAR}`` that is NOT here resolves to a sentinel (dropped) so
#: build-system cache vars (cmake_ar, cmake_c_compiler, arm_cxx_compiler,
#: ascend_python_executable, ...) never leak through as garbage tool names.
_VAR_TO_PROGRAM = {
    "protobuf_protoc_executable": "protoc",
    "host_protoc": "host_protoc",
    "protoc_program": "protoc",
    "cmake_command": "cmake",
    "cmake_make_program": "make",
    "make": "$(MAKE)",
}

#: Sentinel returned by ``_program_basename`` for an unresolvable ``${VAR}``
#: token; the caller drops the invocation entirely instead of emitting garbage.
_DROP_PROGRAM = None


def _program_basename(token: str):
    """Resolve a program token to a basename (handle $(MAKE), paths, vars).

    Returns ``None`` for an unresolved ``${VAR}`` that does not map to a real,
    known binary (via :data:`_VAR_TO_PROGRAM`). Lowercasing the bare variable
    name and treating it as a tool produced garbage (``cmake_ar``,
    ``cmake_c_compiler``, ``arm_cxx_compiler``, ``ascend_python_executable``),
    so such tokens are now dropped rather than guessed.
    """
    t = token.strip()
    if t == "$(MAKE)":
        return "$(MAKE)"
    if t.startswith("${") and t.endswith("}"):
        inner = t[2:-1].lower()
        mapped = _VAR_TO_PROGRAM.get(inner)
        if mapped is not None:
            return mapped
        if "cmake_command" in inner:
            return "cmake"
        return _DROP_PROGRAM
    if not t:
        return _DROP_PROGRAM
    return Path(t).name


def _find_program_invocation(
    cmd: _Command, text: str, source_file: Path | None
) -> ProgramInvocation | None:
    """``find_program(<VAR> [NAMES] name [PATHS ...] [REQUIRED])``."""
    args = cmd.args
    if len(args) < 2:
        return None
    name = None
    if "NAMES" in args:
        ni = args.index("NAMES")
        if ni + 1 < len(args):
            name = args[ni + 1]
    if name is None:
        name = args[1]
    prog = _program_basename(name)
    if not prog:
        return None
    required = "REQUIRED" in args
    conditions = _condition_stack_at(text, cmd.start)
    return ProgramInvocation(
        name=prog,
        command_context="find_program",
        required=required,
        conditions=conditions,
        source_file=str(source_file) if source_file else None,
    )


def _imported_executable(
    cmd: _Command, text: str, source_file: Path | None
) -> ProgramInvocation | None:
    """``add_executable(<name> IMPORTED ...)`` -> a program invocation."""
    args = cmd.args
    if not args or "IMPORTED" not in args:
        return None
    prog = _program_basename(args[0])
    if not prog:
        return None
    conditions = _condition_stack_at(text, cmd.start)
    return ProgramInvocation(
        name=prog,
        command_context="find_program",
        required=None,
        conditions=conditions,
        source_file=str(source_file) if source_file else None,
    )


def _command_program_invocations(
    raw_command: str,
    context_value: str,
    conditions: list[ActivationCondition],
    source_file: Path | None,
) -> list[ProgramInvocation]:
    invs: list[ProgramInvocation] = []
    # An ExternalProject_Add *_COMMAND field may chain extra commands with the
    # literal `COMMAND` keyword; split on it first, then shell-tokenize each.
    sub_commands: list[list[str]] = []
    for chunk in re.split(r"(?:^|\s)COMMAND(?:\s|$)", raw_command):
        sub_commands.extend(tokenize_command(chunk))
    for sub in sub_commands:
        if not sub:
            continue
        prog = _program_basename(sub[0])
        if not prog:
            continue
        invs.append(
            ProgramInvocation(
                name=prog,
                command_context=context_value,
                args=sub[1:],
                tokens=sub,
                conditions=list(conditions),
                source_file=str(source_file) if source_file else None,
            )
        )
    return invs


_EXECUTE_KEYWORDS = {
    "COMMAND", "WORKING_DIRECTORY", "TIMEOUT", "RESULT_VARIABLE",
    "RESULTS_VARIABLE", "OUTPUT_VARIABLE", "ERROR_VARIABLE", "INPUT_FILE",
    "OUTPUT_FILE", "ERROR_FILE", "OUTPUT_QUIET", "ERROR_QUIET",
    "OUTPUT_STRIP_TRAILING_WHITESPACE", "ERROR_STRIP_TRAILING_WHITESPACE",
    "ENCODING", "ECHO_OUTPUT_VARIABLE", "ECHO_ERROR_VARIABLE", "COMMAND_ECHO",
    "DEPENDS", "OUTPUT", "MAIN_DEPENDENCY", "COMMENT", "VERBATIM", "USES_TERMINAL",
    "BYPRODUCTS", "IMPLICIT_DEPENDS", "JOB_POOL", "ALL", "SOURCES",
}


def _execute_process_invocations(
    cmd: _Command, text: str, source_file: Path | None
) -> list[ProgramInvocation]:
    """``execute_process(COMMAND <argv...> ...)`` -> invocation(s)."""
    conditions = _condition_stack_at(text, cmd.start)
    return _multi_command_invocations(
        cmd.args, conditions, source_file, "execute_process"
    )


def _custom_command_invocations(
    cmd: _Command, text: str, source_file: Path | None, context_value: str
) -> list[ProgramInvocation]:
    """add_custom_command / add_custom_target: each COMMAND block -> invocation."""
    conditions = _condition_stack_at(text, cmd.start)
    return _multi_command_invocations(
        cmd.args, conditions, source_file, context_value
    )


def _multi_command_invocations(
    args: list[str],
    conditions: list[ActivationCondition],
    source_file: Path | None,
    context_value: str,
) -> list[ProgramInvocation]:
    invs: list[ProgramInvocation] = []
    i = 0
    n = len(args)
    while i < n:
        if args[i] == "COMMAND":
            j = i + 1
            argv: list[str] = []
            while j < n and args[j] not in _EXECUTE_KEYWORDS:
                argv.append(args[j])
                j += 1
            if argv:
                prog = _program_basename(argv[0])
                if prog:
                    invs.append(
                        ProgramInvocation(
                            name=prog,
                            command_context=context_value,
                            args=argv[1:],
                            tokens=argv,
                            conditions=list(conditions),
                            source_file=str(source_file) if source_file else None,
                        )
                    )
            i = j
            continue
        i += 1
    return invs


def classify_program(inv: ProgramInvocation, profile_tooling: set[str]) -> str:
    """Program/tool boundary classifier.

    Returns "component" for domain/packaged build tools (incl. anything in
    ``profile_tooling``), "environment_tool" for generic host tools, and
    "ignore" for pure flags / ``cmake -E`` internals / redirect remnants.
    """
    name = inv.name.strip()
    low = name.lower()
    if not name or name.startswith("-"):
        return "ignore"
    # An unexpanded CMake variable reference (${ARGN}, ${CMAKE_AR}, foo${BAR})
    # is never a real program; drop it the same way the link classifier does.
    if "${" in name:
        return "ignore"
    if low == "cmake" and inv.args and inv.args[0] == "-E":
        return "ignore"
    if name in profile_tooling or low in profile_tooling:
        return "component"
    if low in _DOMAIN_TOOLS:
        return "component"
    if low in _HOST_TOOLS or name == "$(MAKE)" or low == "$(make)":
        return "environment_tool"
    # Catch-all: quarantine an unrecognized token rather than minting an
    # EnvironmentTool from it. Unresolved build-system cache vars (cmake_ar,
    # cmake_c_compiler, arm_cxx_compiler, ascend_python_executable, ...) would
    # otherwise leak through as garbage environment tools.
    return "ignore"


_CONTEXT_MAP = {
    "find_program": CommandContext.FIND_PROGRAM,
    "execute_process": CommandContext.EXECUTE_PROCESS,
    "add_custom_command": CommandContext.ADD_CUSTOM_COMMAND,
    "add_custom_target": CommandContext.ADD_CUSTOM_TARGET,
    "ep_configure": CommandContext.EP_CONFIGURE,
    "ep_build": CommandContext.EP_BUILD,
    "ep_install": CommandContext.EP_INSTALL,
    "ep_download": CommandContext.EP_DOWNLOAD,
    "ep_update": CommandContext.EP_UPDATE,
    "patch_command": CommandContext.PATCH_COMMAND,
}


def program_to_environment_tool(
    inv: ProgramInvocation,
    *,
    source_revision: str | None,
    source_authority: str | None,
    root_artifact_id: str | None,
) -> EnvironmentTool:
    """Build the EnvironmentTool record for an "environment_tool" invocation."""
    return EnvironmentTool(
        name=inv.name,
        path=inv.path,
        required=inv.required,
        source_file=inv.source_file,
        source_revision=source_revision,
        source_authority=source_authority,
        command_context=_CONTEXT_MAP.get(inv.command_context),
        root_artifact_id=root_artifact_id,
        activation_condition=list(inv.conditions),
    )


# ---------------------------------------------------------------------------
# include() resolution
# ---------------------------------------------------------------------------


def _extract_include(
    cmd: _Command,
    text: str,
    set_vars: dict[str, list[str]],
    effective_cmake_root: Path | None,
    source_file: Path | None,
) -> IncludeStmt | None:
    if not cmd.args:
        return None
    raw = cmd.args[0]
    conditions = _condition_stack_at(text, cmd.start)
    resolved = _resolve_include_path(raw, set_vars, effective_cmake_root, source_file)
    return IncludeStmt(path=raw, resolved=resolved, conditions=conditions)


def _resolve_include_path(
    raw: str,
    set_vars: dict[str, list[str]],
    effective_cmake_root: Path | None,
    source_file: Path | None,
) -> Path | None:
    """Resolve an include() argument to a filesystem path when possible."""
    dir_str = str(source_file.parent) if source_file else None
    root_str = str(effective_cmake_root) if effective_cmake_root else None

    # PROJECT_SOURCE_DIR / CMAKE_SOURCE_DIR refer to the project being built
    # (where its top-level CMakeLists.txt lives), NOT the cann-cmake tooling tree
    # (effective_cmake_root). A pure file parser cannot know the project root for
    # certain, so try both meanings (source-file directory first, then the cmake
    # root) and keep the first candidate that exists on disk.
    project_dir_candidates = [d for d in (dir_str, root_str) if d is not None]
    if not project_dir_candidates:
        project_dir_candidates = [None]

    def _expand(arg: str, project_dir: str | None) -> str | None:
        subs = {
            "CMAKE_CURRENT_LIST_DIR": dir_str,
            "CMAKE_CURRENT_SOURCE_DIR": project_dir,
            "PROJECT_SOURCE_DIR": project_dir,
            "CANN_CMAKE_DIR": root_str,
            "CMAKE_SOURCE_DIR": project_dir,
        }

        def repl(m):
            v = subs.get(m.group(1))
            return v if v is not None else m.group(0)

        out = _VAR_REF_RE.sub(repl, arg)
        if "${" in out:
            for var, vals in set_vars.items():
                if vals:
                    out = out.replace("${" + var + "}", vals[-1])
        return None if "${" in out else out

    first_candidate: Path | None = None
    for project_dir in project_dir_candidates:
        expanded = _expand(raw, project_dir)
        if expanded is None:
            continue
        p = Path(expanded)
        candidates: list[Path] = []
        if p.is_absolute():
            candidates.append(p)
        else:
            if source_file is not None:
                candidates.append(source_file.parent / p)
            if effective_cmake_root is not None:
                candidates.append(effective_cmake_root / p)
        for c in candidates:
            if c.exists():
                return c.resolve()
        if first_candidate is None and candidates:
            first_candidate = candidates[0].resolve()
    return first_candidate


# ---------------------------------------------------------------------------
# Custom macro invocations
# ---------------------------------------------------------------------------


def _extract_macro_call(
    cmd: _Command, custom_macros: dict[str, object]
) -> tuple[str, list[str]] | None:
    if cmd.name in custom_macros:
        return (cmd.name, list(cmd.args))
    return None


# ---------------------------------------------------------------------------
# parse_file / parse_recursive
# ---------------------------------------------------------------------------


def parse_file(path: Path) -> CMakeFile:
    """Statically parse ONE cmake file. Never follows include()."""
    return _parse_file_inner(path, effective_cmake_root=None, custom_macros={})


def _parse_file_inner(
    path: Path,
    effective_cmake_root: Path | None,
    custom_macros: dict[str, object],
) -> CMakeFile:
    cf = CMakeFile(path=path)
    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return cf
    text = _strip_comments(raw_text)
    set_vars = _collect_set_vars(text)

    for cmd in _iter_commands(text):
        low = cmd.name.lower()

        if low == "cmake_minimum_required":
            ver = _kw_value(cmd.args, "VERSION")
            cf.cmake_minimum_required = ver or (
                cmd.args[1] if len(cmd.args) > 1 else None
            )

        elif low == "project":
            if cmd.args:
                cf.project_name = cmd.args[0]
                pv = _kw_value(cmd.args, "VERSION")
                if pv:
                    cf.project_version = pv

        elif low == "include":
            stmt = _extract_include(cmd, text, set_vars, effective_cmake_root, path)
            if stmt is not None:
                cf.includes.append(stmt)

        elif low == "externalproject_add":
            cf.external_projects.append(_build_external_project(cmd, set_vars, path))
            cf.programs.extend(_ep_command_invocations(cmd, text, path))

        elif low == "fetchcontent_declare":
            cf.fetch_contents.append(_build_fetch_content(cmd, set_vars, path))

        elif low == "find_package":
            fatal = bool(cmd.args) and _has_nearby_fatal_check(
                text, cmd.args[0], cmd.end
            )
            cf.find_packages.append(_build_find_package(cmd, text, fatal))

        elif low in _LINK_COMMANDS:
            cf.link_tokens.extend(_extract_link_tokens(cmd, text, set_vars))

        elif low == "add_dependencies":
            edge = _extract_add_dependencies(cmd)
            if edge is not None:
                cf.add_dependencies.append(edge)

        elif low == "find_program":
            inv = _find_program_invocation(cmd, text, path)
            if inv is not None:
                cf.programs.append(inv)

        elif low == "add_executable":
            inv = _imported_executable(cmd, text, path)
            if inv is not None:
                cf.programs.append(inv)

        elif low == "execute_process":
            cf.programs.extend(_execute_process_invocations(cmd, text, path))

        elif low == "add_custom_command":
            cf.programs.extend(
                _custom_command_invocations(cmd, text, path, "add_custom_command")
            )

        elif low == "add_custom_target":
            cf.programs.extend(
                _custom_command_invocations(cmd, text, path, "add_custom_target")
            )

        else:
            mc = _extract_macro_call(cmd, custom_macros)
            if mc is not None:
                cf.macro_calls.append(mc)
                cf.macro_call_conditions.append(_condition_stack_at(text, cmd.start))

    sv = _set_version_from_text(text)
    if sv:
        for ep in cf.external_projects:
            if ep.set_version is None:
                ep.set_version = sv

    cf.integrity_findings = _detect_local_source_unverified(text)

    return cf


def _ep_command_invocations(
    cmd: _Command, text: str, source_file: Path | None
) -> list[ProgramInvocation]:
    """Programs invoked in ExternalProject_Add *_COMMAND fields."""
    conditions = _condition_stack_at(text, cmd.start)
    invs: list[ProgramInvocation] = []
    for kw, (_key, ctx) in _COMMAND_FIELDS.items():
        cstr = _command_str(cmd.args, kw)
        if cstr:
            invs.extend(
                _command_program_invocations(cstr, ctx, conditions, source_file)
            )
    return invs


def parse_recursive(
    entry: Path,
    effective_cmake_root: Path,
    *,
    custom_macros: dict[str, object] | None = None,
) -> list[CMakeFile]:
    """Parse ``entry``, then recursively follow include() (and custom-macro
    expansions), resolving paths against ``effective_cmake_root``. Dedups by
    resolved path; cycles are broken."""
    custom_macros = custom_macros or {}
    visited: set[Path] = set()
    out: list[CMakeFile] = []
    # Each work item carries the call site that pulled the file in: the file
    # that included it and the gating conditions active at that include/macro
    # call (so usage_scope/activation derive from the CALL SITE chain, not the
    # fragment's own definition path).
    stack: list[
        tuple[Path, Path | None, list[ActivationCondition], list[Path]]
    ] = [(entry, None, [], [])]

    while stack:
        current, included_by, call_conds, chain = stack.pop()
        try:
            key = current.resolve()
        except OSError:
            key = current
        if key in visited:
            continue
        visited.add(key)
        if not current.exists():
            continue
        cf = _parse_file_inner(current, effective_cmake_root, custom_macros)
        cf.included_by = included_by
        cf.include_chain = list(chain)
        cf.call_site_conditions = list(call_conds)
        out.append(cf)

        # Children inherit the chain extended with the CURRENT file (their includer).
        child_chain = chain + [current]
        for inc in cf.includes:
            if inc.resolved is not None and inc.resolved not in visited:
                child_conds = _merge_conditions(call_conds, inc.conditions)
                stack.append((inc.resolved, current, child_conds, child_chain))

        for idx, (macro_name, margs) in enumerate(cf.macro_calls):
            resolver = custom_macros.get(macro_name)
            site_conds = (
                cf.macro_call_conditions[idx]
                if idx < len(cf.macro_call_conditions)
                else []
            )
            gate = _macro_gate_conditions(resolver)
            child_conds = _merge_conditions(call_conds, site_conds, gate)
            for resolved in _resolve_macro(
                margs, resolver, effective_cmake_root
            ):
                if resolved is not None and resolved.resolve() not in visited:
                    stack.append((resolved, current, child_conds, child_chain))

    return out


def _merge_conditions(*condition_lists) -> list[ActivationCondition]:
    """Union activation conditions across call-site layers, de-duped by expr."""
    merged: list[ActivationCondition] = []
    seen: set[str] = set()
    for conds in condition_lists:
        for c in conds or []:
            if c.expr not in seen:
                seen.add(c.expr)
                merged.append(ActivationCondition(expr=c.expr, evaluated=c.evaluated))
    return merged


def _macro_gate_conditions(resolver: object) -> list[ActivationCondition]:
    """The gating expression a custom-macro wraps its include() in.

    A profile resolver may expose ``activation_condition`` (a raw expression,
    e.g. add_cann_third_party's ``TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD``).
    Read it defensively; absent/empty ⇒ no gate.
    """
    expr = getattr(resolver, "activation_condition", None)
    if isinstance(expr, str) and expr.strip():
        return [ActivationCondition(expr=expr.strip())]
    return []


def _resolve_macro(
    args: list[str],
    resolver: object,
    effective_cmake_root: Path | None,
) -> list[Path]:
    """Resolve a custom-macro invocation to the .cmake fragment(s) it includes."""
    results: list[Path] = []
    if callable(resolver):
        try:
            res = resolver(args, effective_cmake_root)
        except Exception:  # noqa: BLE001 -- a profile resolver must not crash parse
            return []
        if res is None:
            return []
        if isinstance(res, (list, tuple)):
            results.extend(Path(r) for r in res)
        else:
            results.append(Path(res))
        return results
    if effective_cmake_root is not None and args:
        results.append(effective_cmake_root / "third_party" / f"{args[0]}.cmake")
    return results


# ---------------------------------------------------------------------------
# discover_roots
# ---------------------------------------------------------------------------


def discover_roots(repo_root: Path) -> list[Path]:
    """Find every directory whose CMakeLists.txt has BOTH
    cmake_minimum_required and project(). Returns standalone CMake roots."""
    roots: list[Path] = []
    if not repo_root.exists():
        return roots
    for cml in sorted(repo_root.rglob("CMakeLists.txt")):
        try:
            text = _strip_comments(cml.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        has_min = has_project = False
        for cmd in _iter_commands(text):
            low = cmd.name.lower()
            if low == "cmake_minimum_required":
                has_min = True
            elif low == "project":
                has_project = True
            if has_min and has_project:
                break
        if has_min and has_project:
            roots.append(cml.parent.resolve())
    return roots


# ---------------------------------------------------------------------------
# Authority resolution (the four fetch_cann_cmake outcomes)
# ---------------------------------------------------------------------------

_CANN_CMAKE_TAG = "master-016"
#: The cann-cmake upstream the ``fetch_cann_cmake.cmake`` GIT branch clones from
#: (``GIT_REPOSITORY``). Used by ``--resolve-cmake-ref`` to resolve the pinned ref
#: to a commit via ``git ls-remote``.
_CANN_CMAKE_GIT = "https://gitcode.com/cann/cmake.git"


def _ls_remote_sha(url: str, ref: str) -> str | None:
    """Resolve a remote git *ref* to its 40-hex commit SHA via ``git ls-remote``.

    A network operation (the building block of ``--resolve-cmake-ref``). Returns
    the SHA, or ``None`` on ANY failure — no network, git absent, ref not found, or
    a non-SHA response — so the caller degrades to the unpinned path rather than
    crashing. ``git ls-remote <url> <ref>`` prints ``<sha>\\t<refname>`` lines; the
    first field of the first line is taken."""
    try:
        res = subprocess.run(
            ["git", "ls-remote", url, ref],
            capture_output=True,
            timeout=30,
            check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    out = res.stdout.decode("utf-8", errors="replace").strip()
    if not out:
        return None
    sha = out.split()[0].strip()
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None


def resolve_cmake_authority(
    repo_root: Path,
    cmake_root: Path | None,
    *,
    cmake_source_authority: str,
    cmake_defines: dict[str, str],
    profile_values: dict[str, str],
    allow_input_fallback: bool,
    resolve_cmake_ref: bool,
    network: str,
) -> tuple[CmakeAuthority, list[Warning]]:
    """Resolve which fetch_cann_cmake branch wins using ONLY pre-project() state.

    Precedence for authority inputs: trace > explicit --cmake-define/config >
    bare cache > default. A bare cache value for CANN_3RD_LIB_PATH is AMBIGUOUS
    (cannot prove it was set before line 12) -> assume Git branch + emit
    ``cmake_authority_input_ambiguous``.

    The four branches: skipped_existing_project (gated on
    project_source_dir_predefined), local_dir, tarball (master-016 + sha256),
    git (ref + resolved commit). Under cmake-as-input the cann-cmake component is
    excluded (``cann_cmake_trusted_input``) and effective_cmake_root=--cmake-root.
    """
    warnings: list[Warning] = []

    value, source = _resolve_authority_input(repo_root, cmake_defines, profile_values)
    authority_inputs = {"cann_3rd_lib_path": {"value": value, "source": source}}

    # --- skipped_existing_project gate ------------------------------------
    psd = profile_values.get("project_source_dir_predefined")
    if psd is not None and psd.lower() in ("true", "on", "1", "yes"):
        return (
            CmakeAuthority(
                branch=CmakeAuthorityBranch.SKIPPED_EXISTING_PROJECT,
                effective_cmake_root=cmake_root,
                authority_inputs=authority_inputs,
            ),
            warnings,
        )

    # --- cmake-as-input policy --------------------------------------------
    if cmake_source_authority == "cmake-as-input":
        # Mark the cmake tree as trusted generator input so the profile's
        # build_tooling() EXCLUDES the cann-cmake component — it gates on this
        # marker, which was previously never set, so the "excluded" component was
        # still emitted. build_tooling() emits the cann_cmake_trusted_input warning
        # when it performs the exclusion (so no duplicate is emitted here).
        authority_inputs["trusted_input"] = True
        auth = CmakeAuthority(
            branch=CmakeAuthorityBranch.GIT,
            effective_cmake_root=cmake_root,
            ref=_CANN_CMAKE_TAG,
            authority_inputs=authority_inputs,
        )
        _maybe_tag_mismatch(auth, cmake_root, warnings)
        return auth, warnings

    # --- actual-build: branch selection -----------------------------------
    if source in ("cli", "config") and value:
        lib_path = Path(value)
        local_cann = lib_path / "cann-cmake"
        if local_cann.is_dir():
            warnings.append(
                Warning(
                    code="cann_cmake_local_override",
                    subject="cann-cmake",
                    detail=f"local cann-cmake override at {local_cann}; version NOASSERTION.",
                )
            )
            return (
                CmakeAuthority(
                    branch=CmakeAuthorityBranch.LOCAL_DIR,
                    effective_cmake_root=local_cann,
                    verified=False,
                    authority_inputs=authority_inputs,
                ),
                warnings,
            )
        tarball = lib_path / f"cmake-{_CANN_CMAKE_TAG}.tar.gz"
        if tarball.is_file():
            auth = CmakeAuthority(
                branch=CmakeAuthorityBranch.TARBALL,
                effective_cmake_root=cmake_root,
                ref=_CANN_CMAKE_TAG,
                verified=True,
                authority_inputs=authority_inputs,
            )
            _maybe_tag_mismatch(auth, cmake_root, warnings)
            return auth, warnings
        # supplied but neither local dir nor tarball present -> fall to Git
    elif source == "cache":
        warnings.append(
            Warning(
                code="cmake_authority_input_ambiguous",
                subject="CANN_3RD_LIB_PATH",
                detail=(
                    "bare cache value cannot prove a pre-include -D; assuming Git "
                    "branch (master-016)."
                ),
            )
        )

    # --- Git branch (default / ambiguous / supplied-but-absent) -----------
    auth = CmakeAuthority(
        branch=CmakeAuthorityBranch.GIT,
        effective_cmake_root=cmake_root,
        ref=_CANN_CMAKE_TAG,
        verified=False,
        authority_inputs=authority_inputs,
    )
    _maybe_tag_mismatch(auth, cmake_root, warnings)

    if resolve_cmake_ref:
        # Resolve the pinned ref to a commit via `git ls-remote` (network). On
        # success the cann-cmake component becomes PINNED (revision + vcs_ref, no
        # UNPINNED_GIT); on failure (offline / git absent / ref gone) degrade to the
        # unpinned path with a cmake_ref_resolution_failed warning rather than a
        # silent unpinned component.
        sha = _ls_remote_sha(_CANN_CMAKE_GIT, _CANN_CMAKE_TAG) if network == "on" else None
        if sha:
            auth.revision = sha
            auth.verified = True
        else:
            warnings.append(
                Warning(
                    code="cmake_ref_resolution_failed",
                    subject="cann-cmake",
                    detail=(
                        f"--resolve-cmake-ref: could not resolve {_CANN_CMAKE_TAG} via "
                        f"git ls-remote {_CANN_CMAKE_GIT}; cann-cmake left unpinned."
                    ),
                )
            )
    elif not _root_matches_pin(cmake_root):
        if cmake_root is None or not allow_input_fallback:
            warnings.append(
                Warning(
                    code="cmake_acquisition_metadata_unresolved",
                    subject="cann-cmake",
                    detail="offline and pin unresolvable; cannot obtain master-016.",
                )
            )
        else:
            warnings.append(
                Warning(
                    code="cmake_acquisition_metadata_unresolved",
                    subject="cann-cmake",
                    detail="parsing --cmake-root as fallback (not actual-build evidence).",
                )
            )
    return auth, warnings


def _resolve_authority_input(
    repo_root: Path,
    cmake_defines: dict[str, str],
    profile_values: dict[str, str],
) -> tuple[str | None, str]:
    """Return (value, source) for CANN_3RD_LIB_PATH.

    Precedence: explicit --cmake-define/config > bare CMakeCache.txt > unset.
    """
    if "CANN_3RD_LIB_PATH" in cmake_defines:
        return cmake_defines["CANN_3RD_LIB_PATH"], "cli"
    if "CANN_3RD_LIB_PATH" in profile_values:
        return profile_values["CANN_3RD_LIB_PATH"], "config"
    cache_val = _read_cache_value(repo_root, "CANN_3RD_LIB_PATH")
    if cache_val is not None:
        return cache_val, "cache"
    return None, "unset"


_CACHE_LINE_RE = re.compile(r"^([A-Za-z0-9_]+):[A-Za-z]+=(.*)$")


def _read_cache_value(repo_root: Path, key: str) -> str | None:
    for cache in (
        repo_root / "CMakeCache.txt",
        repo_root / "build" / "CMakeCache.txt",
    ):
        if not cache.is_file():
            continue
        try:
            for line in cache.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                m = _CACHE_LINE_RE.match(line.strip())
                if m and m.group(1) == key:
                    return m.group(2)
        except OSError:
            continue
    return None


def _root_matches_pin(cmake_root: Path | None) -> bool:
    """Best-effort: does --cmake-root describe the pinned ref?

    A present --cmake-root is treated as matching unless a ref marker
    (CMAKE_REF / .cann_cmake_ref / VERSION) records a different ref.
    """
    if cmake_root is None:
        return False
    for marker in ("CMAKE_REF", ".cann_cmake_ref", "VERSION"):
        p = cmake_root / marker
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if _CANN_CMAKE_TAG in content:
            return True
        if content and content != _CANN_CMAKE_TAG:
            return False
    return True


def _maybe_tag_mismatch(
    auth: CmakeAuthority, cmake_root: Path | None, warnings: list[Warning]
) -> None:
    if cmake_root is None:
        return
    if not _root_matches_pin(cmake_root):
        warnings.append(
            Warning(
                code="cann_cmake_tag_mismatch",
                subject="cann-cmake",
                detail=f"--cmake-root does not match pinned ref {auth.ref}.",
            )
        )
