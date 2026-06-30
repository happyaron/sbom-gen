"""``--deps-dir`` on-disk dependency-source resolver + license/copyright enricher.

Locates each component's real SOURCE under ``--deps-dir`` and extracts an
accurate license + copyright from it, fully offline (no network). It is the
"new dependency, no pre-seed data" fallback: a dep that has no curated Notice,
no known-license entry and no cached metadata still gets a real license +
copyright straight from the source on disk.

Three on-disk layouts are understood (auto-detected per dep):

1. **Plain directory** — ``<deps-dir>/<name>/`` containing the source tree.
2. **Archive file** — ``<deps-dir>/<name>-<version>.tar.gz`` (``.tgz`` / ``.zip``
   / ``.tar.*``); extracted (bounded surface only) to a temp dir.
3. **Git mirror** (the CANN ``cann-src-third-party`` convention) —
   ``<deps-dir>/<name>/`` is a git repo whose DEFAULT branch is *informational*:
   its working-tree ``LICENSE`` is known-inaccurate and is **never read**. The
   real per-release source lives on a version-named branch (e.g. ``5.0.0.x``,
   ``1.1.16x``, ``v9.12.x``, ``5.0.0.x-h0.trunk``) that stores a release ARCHIVE
   (``<name>-<version>.tar.gz``/``.zip``) plus, when present, a Huawei
   ``Readme.opensource`` manifest carrying the authoritative ``License:`` +
   ``Copyright Notice(s):``.

Per-dep source precedence: ``Readme.opensource`` manifest (license + copyright)
> the release archive's ``LICENSE`` (cache_scan heuristic) / ScanCode copyright.
For a git mirror the default branch is NEVER consulted — when the dep IS a mirror
(has version branches) but none matches the component version, the dep is SKIPPED
with a warning rather than falling back to the inaccurate default branch.

This layer FILLS only: it sets ``license``/``copyright`` only where still unset,
and emits a ``deps_dir_license_discrepancy`` warning (never a silent override)
when a manifest disagrees with an already-resolved license. The materialized
source dirs are also handed to the ScanCode enrich layer (``--scancode``) via the
returned ``source_map`` so ScanCode can read copyright + a thorough license from
the real tree; the caller cleans the temp extractions up afterwards.
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from ..models import Component, Provenance, Warning
from . import cache_scan

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..config import Config
    from ..profile import Profile


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Recognised source-archive suffixes, longest-compound first.
_ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".tar",
    ".zip",
)

#: Default/informational branch names — never read as a source of truth.
_DEFAULT_BRANCHES = frozenset({"master", "main", "trunk", "develop", "head"})

#: Bounded extraction depth: only the archive's top-level files (root/ + file)
#: plus license-bearing files anywhere are extracted, so a huge archive (e.g.
#: or-tools) is not unpacked in full just to read its LICENSE/top surface.
_MAX_SURFACE_DEPTH = 2

#: Decompression-bomb / disk-fill guards (the surface bounds depth+count, not
#: SIZE). License/notice/top-level files are small; a member or total over these
#: caps is skipped rather than written. Tunable but deliberately generous.
_MAX_MEMBER_BYTES = 32 * 1024 * 1024        # 32 MB per extracted file
_MAX_TOTAL_BYTES = 256 * 1024 * 1024        # 256 MB total written per archive
#: Cap on the in-memory archive blob (git-show stdout / file read) before extract.
_MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024     # 1 GB

#: Imprecise ``License:`` tokens whose exact SPDX variant must be read from the
#: license text (e.g. ``BSD`` → ``BSD-3-Clause``) rather than asserted verbatim.
_VAGUE_LICENSE_TOKENS = frozenset(
    {"bsd", "gpl", "lgpl", "agpl", "apache", "mpl", "cc", "gnu", "mit license"}
)


# ---------------------------------------------------------------------------
# Small git helpers (the app shells out to git; git is not imported)
# ---------------------------------------------------------------------------


def _git_text(repo: Path, args: list[str]) -> str | None:
    """Run ``git -C <repo> <args>`` and return stdout text, or ``None`` on failure."""
    try:
        res = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            timeout=60,
            check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return res.stdout.decode("utf-8", errors="replace")


def _git_bytes(repo: Path, args: list[str]) -> bytes | None:
    """Run ``git -C <repo> <args>`` and return raw stdout bytes (for blobs)."""
    try:
        res = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            timeout=120,
            check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return res.stdout


_LFS_PREFIX = b"version https://git-lfs.github.com/spec/"


def _lfs_oid(data: bytes) -> str | None:
    """Return the sha256 oid if *data* is a Git LFS pointer blob, else ``None``.

    A committed LFS file shows up via ``git show`` as a tiny pointer
    (``version https://git-lfs…\\noid sha256:<hex>\\nsize <n>``), NOT the archive."""
    if not data.startswith(_LFS_PREFIX):
        return None
    m = re.search(rb"oid sha256:([0-9a-f]{64})", data[:400])
    return m.group(1).decode() if m else None


def _lfs_local_object(repo: Path, oid: str) -> bytes | None:
    """Read a locally-fetched LFS object (``.git/lfs/objects/aa/bb/<oid>``), or
    ``None`` when it was never ``git lfs pull``-ed (the offline case)."""
    git_dir_out = _git_text(repo, ["rev-parse", "--git-dir"])
    git_dir = repo / ".git"
    if git_dir_out:
        cand = Path(git_dir_out.strip())
        git_dir = cand if cand.is_absolute() else (repo / cand)
    obj = git_dir / "lfs" / "objects" / oid[:2] / oid[2:4] / oid
    try:
        if obj.is_file() and obj.stat().st_size <= _MAX_ARCHIVE_BYTES:
            return obj.read_bytes()
    except OSError:
        return None
    return None


def _is_git_repo(path: Path) -> bool:
    """True when *path* is itself a git repository ROOT (not merely inside one).

    A bare ``rev-parse --git-dir`` SUCCEEDS for any path under a git working tree,
    so a plain-directory dep that happens to sit inside an enclosing checkout (e.g.
    a deps tree vendored under the project repo) would be mis-routed to the
    git-mirror resolver and read the ENCLOSING repo's branches. Require the dep to
    be the repo root: a ``.git`` entry directly under it (dir for a normal repo,
    file for a worktree/submodule), or ``rev-parse --show-toplevel`` == the dep."""
    if (path / ".git").exists():
        return True
    top = _git_text(path, ["rev-parse", "--show-toplevel"])
    if top is None:
        return False
    try:
        return Path(top.strip()).resolve() == path.resolve()
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Version <-> branch matching
# ---------------------------------------------------------------------------


def _component_versions(component: Component) -> list[str]:
    """Candidate versions to key the mirror lookup by, MOST-authoritative first.

    The cann-src-third-party mirror's branches/archives are named by the UPSTREAM
    version, so ``source_version`` is tried before ``effective_version``: a patched
    component (e.g. protobuf source 25.1 → effective 3.13.0) must resolve against
    the upstream ``25.1.x`` branch, not the patched Notice version. Both are tried
    (deduped) so a component carrying only one of them still resolves."""
    out: list[str] = []
    for v in (component.source_version, component.effective_version):
        if v and v not in out:
            out.append(v)
    return out


def _norm_name(text: str) -> str:
    """Collapse a name/stem for fuzzy matching (drop ``-``/``_``/``.``, lowercase)."""
    return re.sub(r"[-_.]", "", text.lower())


def _normalize_version(value: str) -> str:
    """Reduce a version or branch label to a comparable dotted-number string.

    Extracts the first dotted-number RUN, so a prefix/suffix decoration is
    tolerated: ``v9.12.x`` → ``9.12``; ``1.1.16x`` → ``1.1.16``;
    ``5.0.0.x-h0.trunk`` → ``5.0.0``; ``3.11.x`` → ``3.11``; ``release-v5.0.0`` →
    ``5.0.0``. A plain version (``5.0.0``) is unchanged; a label with no digits
    (e.g. ``trunk``) yields ``""``."""
    m = re.search(r"\d+(?:\.\d+)*", value)
    return m.group(0) if m else ""


def _looks_versioned(name: str) -> bool:
    """True when a branch name looks like a release line (``v?N[.N...]…`` at the
    start) — the cann-src-third-party mirror convention (``5.0.0.x``, ``1.1.16x``,
    ``v9.12.x``, ``20250127.0.x``, ``2024-02-01-x``).

    NOTE: a mirror that named its release branches with a leading word
    (``release-v5.0.0``, ``rel/5.0.0``) would NOT be recognized here, so the repo
    would be treated as a normal clone and its working tree used. The convention in
    use always leads with the version, so this is a documented bound, not a silent
    gap; broadening to "contains a version" is deliberately avoided because it would
    misclassify a genuine normal clone that merely has a versionish feature branch."""
    if name.lower() in _DEFAULT_BRANCHES:
        return False
    return re.match(r"v?\d+(\.\d+)*", name.strip()) is not None


def _match_score(want: str, branch: str) -> int | None:
    """Dotted-prefix match score between two normalized versions, or ``None``.

    Returns the count of matching leading dotted components when one is a prefix
    of the other (``3.11`` vs ``3.11.3`` → 2; ``5.0.0`` vs ``5.0.0`` → 3); a
    mismatch in any shared component yields ``None`` (no match).
    """
    wp = [p for p in want.split(".") if p]
    bp = [p for p in branch.split(".") if p]
    if not wp or not bp:
        return None
    n = min(len(wp), len(bp))
    for i in range(n):
        if wp[i] != bp[i]:
            return None
    return n


def _branches(repo: Path) -> dict[str, str] | None:
    """Return ``{branch_label: full_ref}`` for every non-default branch, or
    ``None`` when git could not enumerate refs at all.

    Both local (``refs/heads``) and remote-tracking (``refs/remotes/origin``)
    refs are included; the ``origin/`` prefix is stripped for the label but the
    full ref is kept so ``git show <ref>:<path>`` resolves. ``HEAD`` pointers and
    the default/informational branches (master/main/…) are dropped.

    ``None`` (git FAILED — corrupt repo / git unavailable / permission error) is
    kept DISTINCT from an empty dict (git succeeded, no non-default branches): the
    caller must NOT treat a failed enumeration as a "normal clone" and read the
    informational working tree — see :func:`_resolve_git`.
    """
    text = _git_text(
        repo, ["for-each-ref", "--format=%(refname:short)", "refs/heads", "refs/remotes"]
    )
    if text is None:
        return None
    out: dict[str, str] = {}
    for line in text.splitlines():
        ref = line.strip()
        if not ref or ref.endswith("/HEAD") or ref == "HEAD":
            continue
        label = ref.split("/", 1)[1] if ref.startswith("origin/") else ref
        if label.lower() in _DEFAULT_BRANCHES:
            continue
        out.setdefault(label, ref)
    return out


def _versioned_branches(repo: Path) -> dict[str, str] | None:
    """``{release-line label: full_ref}`` for the repo, or ``None`` when git could
    not enumerate refs (corrupt repo / git unavailable — the caller MUST skip,
    never read the working tree)."""
    branches = _branches(repo)
    if branches is None:
        return None
    return {label: ref for label, ref in branches.items() if _looks_versioned(label)}


def _pick_ref(versioned: dict[str, str], version: str | None) -> str | None:
    """Best release-branch ref for *version* among *versioned*, or ``None``.

    Highest dotted-prefix score wins, then a CLEAN branch over a ``-suffix``
    variant (``5.0.0.x`` over ``5.0.0.x-h0.trunk``), then the shortest label."""
    if not version:
        return None
    want = _normalize_version(version)
    if not want:
        return None
    ranked: list[tuple[int, int, int, str, str]] = []
    for label, ref in versioned.items():
        score = _match_score(want, _normalize_version(label))
        if score is None:
            continue
        has_suffix = 1 if ("-" in label or "_" in label) else 0
        ranked.append((-score, has_suffix, len(label), label, ref))
    if not ranked:
        return None
    ranked.sort()
    return ranked[0][4]


def latest_version(repo: Path) -> str | None:
    """The highest release-line version for *repo*, for seeding (``--refresh-data
    deps-dir``). Returns the normalized version of the numerically-greatest version
    branch, or ``None`` for a normal clone / non-mirror / unreadable repo."""
    versioned = _versioned_branches(repo)
    if not versioned:
        return None

    def _key(label: str) -> list[int]:
        return [int(n) for n in re.findall(r"\d+", _normalize_version(label))] or [0]

    best = max(versioned, key=_key)
    return _normalize_version(best) or None


def select_branch(repo: Path, version: str | None) -> tuple[str | None, list[str] | None]:
    """Pick the version-named branch ref for *version*.

    Returns ``(chosen_ref, version_branch_labels)``:

    * ``version_branch_labels is None`` — git could not enumerate refs (corrupt
      repo / git unavailable); the caller MUST skip and NOT read the working tree.
    * ``version_branch_labels == []`` — git succeeded and the repo is a normal
      clone (no mirror branches); the caller may use the working tree.
    * ``chosen_ref`` is the best release branch ref for *version*, or ``None``
      when the repo IS a mirror but no branch matches — the caller must then SKIP
      (never read the informational default branch).
    """
    versioned = _versioned_branches(repo)
    if versioned is None:
        return None, None
    if not versioned:
        return None, []
    return _pick_ref(versioned, version), sorted(versioned)


# ---------------------------------------------------------------------------
# Readme.opensource manifest
# ---------------------------------------------------------------------------


@dataclass
class Manifest:
    """A parsed Huawei ``Readme.opensource`` manifest (license + copyright)."""

    license_token: str | None = None
    full_license_text: str | None = None
    copyrights: list[str] = field(default_factory=list)

    def resolved_license(self) -> str | None:
        """Best SPDX id for the PRIMARY license.

        Prefers the explicit ``License:`` token when it is a precise, single SPDX
        id — the manifest's declared primary license is authoritative and, crucially,
        a manifest that BUNDLES sub-component licenses (e.g. nlohmann/json carries
        MIT + Apache-2.0 + BSD-3-Clause) would otherwise have its full-text
        heuristic latch onto a bundled license rather than the real one. A vague
        token (bare ``BSD`` / ``GPL`` / …) falls back to a heuristic match on the
        first license's full text, which resolves the precise version/variant.
        """
        token = (self.license_token or "").strip()
        if (
            token
            and token.lower() not in _VAGUE_LICENSE_TOKENS
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-+]*", token)
        ):
            return token
        if self.full_license_text:
            spdx = cache_scan._spdx_match(self.full_license_text)
            if spdx:
                return spdx
        return token or None

    def copyright_text(self, *, max_chars: int = 2000) -> str | None:
        """Deduplicated copyright holders joined into one field, length-capped."""
        if not self.copyrights:
            return None
        joined = "; ".join(self.copyrights)
        if len(joined) > max_chars:
            joined = joined[: max_chars - 1].rstrip("; ") + "…"
        return joined


def parse_manifest(text: str) -> Manifest:
    """Parse a ``Readme.opensource`` manifest body.

    Recognised blocks: the global ``Copyright Notice(s):`` holder list, the FIRST
    (primary) ``License: <id>`` token, and that license's ``Full License Text:``.
    Subsequent ``License:`` blocks are IGNORED — a manifest bundling sub-component
    licenses (MIT + Apache-2.0 + …) lists the real license first; reading past it
    would mis-attribute a bundled license. Copyright lines are deduplicated
    (case-insensitively), preserving order.
    """
    license_token: str | None = None
    copyrights: list[str] = []
    license_lines: list[str] = []
    section: str | None = None  # None | "copyright" | "license_text"
    seen_license = False

    for raw in text.splitlines():
        stripped = raw.strip()
        low = stripped.lower()
        if low.startswith("license:"):
            if seen_license:
                break  # a bundled sub-license block — stop at the primary
            val = stripped.split(":", 1)[1].strip()
            if val:
                license_token = val
            seen_license = True
            section = None
            continue
        if low.startswith("copyright notice") and not seen_license:
            # The global copyright block precedes the primary License:. Never
            # re-open it afterwards — a "copyright notice" line inside the license
            # body (e.g. GPL boilerplate) or a bundled sub-license block must not
            # bleed license text into the copyright holders.
            section = "copyright"
            continue
        if low.startswith("full license text"):
            section = "license_text" if seen_license else None
            continue
        # Any other "Header:" line closes the current copyright block.
        if re.match(r"^[A-Za-z][\w ()/]*:", stripped) and section == "copyright":
            section = None
            continue
        if section == "copyright" and stripped:
            copyrights.append(stripped)
        elif section == "license_text":
            license_lines.append(raw)

    seen: set[str] = set()
    uniq: list[str] = []
    for c in copyrights:
        key = c.lower()
        if key not in seen:
            seen.add(key)
            uniq.append(c)

    full_text = "\n".join(license_lines).strip() or None
    return Manifest(license_token=license_token, full_license_text=full_text, copyrights=uniq)


# ---------------------------------------------------------------------------
# Archive handling (bounded extraction)
# ---------------------------------------------------------------------------


def _is_archive(name: str) -> bool:
    low = name.lower()
    return any(low.endswith(suf) for suf in _ARCHIVE_SUFFIXES)


def _archive_stem(name: str) -> str:
    low = name.lower()
    for suf in _ARCHIVE_SUFFIXES:
        if low.endswith(suf):
            return name[: -len(suf)]
    return name


def _wanted_member(name: str) -> bool:
    """True for an archive member to extract: a top-level file (root/ + file) or
    any license/notice-bearing file (so a nested LICENSE is still seen)."""
    parts = [p for p in name.split("/") if p]
    if not parts:
        return False
    if len(parts) <= _MAX_SURFACE_DEPTH:
        return True
    return _is_license_basename(parts[-1])


def _is_license_basename(base: str) -> bool:
    up = base.upper()
    return up.startswith(("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE")) or up == "README.OPENSOURCE"


def _safe_member(name: str, dest: Path) -> bool:
    """True when extracting *name* stays inside *dest* (no absolute path, no ``..``
    traversal). An explicit, Python-version-independent guard — it does NOT rely on
    tarfile's ``filter='data'`` (absent on Python < 3.12)."""
    if name.startswith(("/", "\\")) or ".." in Path(name).parts:
        return False
    droot = dest.resolve()
    try:
        target = (dest / name).resolve()
    except OSError:
        return False
    return target == droot or droot in target.parents


def _extract_tar_bytes(data: bytes, dest: Path) -> bool:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members = []
            total = 0
            for m in tf.getmembers():
                if not (m.isreg() and _wanted_member(m.name) and _safe_member(m.name, dest)):
                    continue
                if m.size > _MAX_MEMBER_BYTES:
                    continue  # decompression-bomb guard: skip an oversized member
                if total + m.size > _MAX_TOTAL_BYTES:
                    break     # total-size budget exhausted
                total += m.size
                members.append(m)
            try:
                tf.extractall(dest, members=members, filter="data")
            except TypeError:  # Python < 3.12 has no data filter; members are pre-sanitized
                tf.extractall(dest, members=members)
    except (tarfile.TarError, OSError, EOFError):
        return False
    return True


def _extract_zip_bytes(data: bytes, dest: Path) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            total = 0
            for info in zf.infolist():
                if info.is_dir() or not _wanted_member(info.filename):
                    continue
                if not _safe_member(info.filename, dest):
                    continue
                # Guard on the DECLARED uncompressed size before extracting.
                if info.file_size > _MAX_MEMBER_BYTES:
                    continue
                if total + info.file_size > _MAX_TOTAL_BYTES:
                    break
                total += info.file_size
                zf.extract(info, dest)
    except (zipfile.BadZipFile, OSError):
        return False
    return True


def _extract_bytes(name: str, data: bytes, dest: Path) -> Path | None:
    """Extract an archive's bounded surface from *data* into *dest*; return the
    scan root (the single inner top dir, or *dest*)."""
    if not data or len(data) > _MAX_ARCHIVE_BYTES:
        return None
    ok = _extract_zip_bytes(data, dest) if name.lower().endswith(".zip") else _extract_tar_bytes(data, dest)
    if not ok:
        return None
    return _descend_single_root(dest)


def _extract_file(path: Path, dest: Path) -> Path | None:
    try:
        if path.stat().st_size > _MAX_ARCHIVE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return _extract_bytes(path.name, data, dest)


def _descend_single_root(dest: Path) -> Path:
    """If *dest* holds exactly one subdirectory and no files, return it (the
    archive's wrapping top dir); otherwise return *dest*."""
    try:
        children = list(dest.iterdir())
    except OSError:
        return dest
    dirs = [c for c in children if c.is_dir()]
    files = [c for c in children if c.is_file()]
    if len(dirs) == 1 and not files:
        return dirs[0]
    return dest


# ---------------------------------------------------------------------------
# Dep lookup under --deps-dir
# ---------------------------------------------------------------------------


def find_dep(component: Component, deps_root: Path) -> Path | None:
    """Locate *component*'s on-disk entry under *deps_root*.

    Tries, for the component's name and each alias: an exact (case-insensitive)
    dir/file, a ``<name>-<version>`` dir, a ``<name>-<version>.<archive>`` file,
    and a normalized fuzzy match (``-``/``_``/``.`` and case ignored, so
    ``or-tools`` matches ``ortools``). Returns the matched path or ``None``.
    """
    try:
        # Sorted for deterministic resolution when two entries collide on a
        # lowercased / normalized key (e.g. or-tools vs ortools, json dir vs
        # json.tar.gz): the first in a stable order wins, not an arbitrary one.
        children = sorted(deps_root.iterdir())
    except OSError:
        return None

    by_exact: dict[str, Path] = {}
    by_norm: dict[str, Path] = {}
    for child in children:
        by_exact.setdefault(child.name.lower(), child)
        stem = _archive_stem(child.name) if child.is_file() else child.name
        by_norm.setdefault(_norm_name(stem), child)

    names = [component.name, *component.aliases]
    versions = _component_versions(component)

    # Exact / name-version (dir or archive) — try every (name, version) pairing.
    for cand in names:
        cl = cand.lower()
        if cl in by_exact:
            return by_exact[cl]
        for version in versions:
            nv = f"{cand}-{version}".lower()
            if nv in by_exact:
                return by_exact[nv]
            for suf in _ARCHIVE_SUFFIXES:
                if (nv + suf) in by_exact:
                    return by_exact[nv + suf]

    # Normalized fuzzy (catches or-tools/ortools, name-version stems).
    for cand in names:
        nn = _norm_name(cand)
        if nn in by_norm:
            return by_norm[nn]
        for version in versions:
            nnv = _norm_name(f"{cand}{version}")
            if nnv in by_norm:
                return by_norm[nnv]
    return None


# ---------------------------------------------------------------------------
# Resolved source
# ---------------------------------------------------------------------------


@dataclass
class ResolvedSource:
    """A materialized, scannable source location for a component."""

    path: Path | None                       # a scannable directory (or None)
    manifest: Manifest | None
    origin: str                             # provenance detail
    _cleanup: Callable[[], None] | None = None

    def cleanup(self) -> None:
        if self._cleanup is not None:
            self._cleanup()


def _read_manifest_dir(directory: Path) -> Manifest | None:
    """Parse a ``Readme.opensource`` sitting at the top of *directory* (ci)."""
    try:
        for child in directory.iterdir():
            if child.is_file() and child.name.lower() == "readme.opensource":
                return parse_manifest(cache_scan._read_safe(child))
    except OSError:
        return None
    return None


def _find_branch_archive(repo: Path, ref: str, names: list[str]) -> str | None:
    """Pick the release archive on *ref* (prefer a name-matching ``.tar.gz``)."""
    text = _git_text(repo, ["ls-tree", "--name-only", ref])
    if not text:
        return None
    archives = [n.strip() for n in text.splitlines() if n.strip() and _is_archive(n.strip())]
    if not archives:
        return None
    wanted = {_norm_name(n) for n in names}

    def rank(n: str) -> tuple[int, int, int, str]:
        stem_norm = _norm_name(_archive_stem(n))
        matches = 0 if any(w and w in stem_norm for w in wanted) else 1
        nl = n.lower()
        is_tar = 0 if (nl.endswith(".tar.gz") or nl.endswith(".tgz")) else 1
        return (matches, is_tar, len(n), n)

    archives.sort(key=rank)
    return archives[0]


def _branch_manifest(repo: Path, ref: str) -> Manifest | None:
    text = _git_text(repo, ["ls-tree", "--name-only", ref])
    if not text:
        return None
    for n in text.splitlines():
        name = n.strip()
        if "/" not in name and name.lower() == "readme.opensource":
            body = _git_text(repo, ["show", f"{ref}:{name}"])
            if body:
                return parse_manifest(body)
    return None


def _resolve_git(
    component: Component, dep: Path, tmp_parent: str | None
) -> tuple[ResolvedSource | None, Warning | None]:
    """Resolve a git-mirror dep: pick the version branch, read its manifest, and
    materialize its release archive. The default branch is NEVER read."""
    versioned = _versioned_branches(dep)
    if versioned is None:
        # git could not enumerate refs (corrupt repo / git unavailable). This is
        # a git repo (.git present or show-toplevel == dep), so its working tree is
        # an informational default branch we must NOT trust — SKIP, never read it.
        return None, Warning(
            code="deps_dir_git_unreadable",
            subject=component.name,
            detail=(
                f"{dep.name}: git refs unreadable (corrupt repo or git unavailable); "
                f"skipped (the default branch is informational and never trusted)"
            ),
        )
    if not versioned:
        # A genuine normal clone (git works, no release-line branches): the working
        # tree IS the source of truth.
        return (
            ResolvedSource(path=dep, manifest=_read_manifest_dir(dep), origin=f"deps-dir working tree {dep.name}"),
            None,
        )
    # Try every candidate version (source_version first — the mirror is keyed by
    # the UPSTREAM version, not a patched effective version).
    versions = _component_versions(component)
    ref = None
    for version in versions:
        ref = _pick_ref(versioned, version)
        if ref is not None:
            break
    if ref is None:
        return None, Warning(
            code="deps_dir_no_branch",
            subject=component.name,
            detail=(
                f"{dep.name}: no version branch matched version(s) {versions or ['<none>']} "
                f"among {sorted(versioned)}; skipped (default branch is informational)"
            ),
        )

    manifest = _branch_manifest(dep, ref)
    archive = _find_branch_archive(dep, ref, [component.name, *component.aliases])
    label = ref.split("/", 1)[1] if ref.startswith("origin/") else ref
    path: Path | None = None
    cleanup: Callable[[], None] | None = None
    lfs_warn: Warning | None = None
    if archive is not None:
        data = _git_bytes(dep, ["show", f"{ref}:{archive}"])
        if data:
            oid = _lfs_oid(data)
            if oid is not None:
                # The committed blob is a Git LFS pointer; the real archive is only
                # available if `git lfs pull` fetched it into .git/lfs/objects.
                local = _lfs_local_object(dep, oid)
                if local is not None:
                    data = local
                else:
                    data = None
                    lfs_warn = Warning(
                        code="deps_dir_lfs_pointer",
                        subject=component.name,
                        detail=(
                            f"{dep.name}: {archive} on {label} is an unfetched Git LFS "
                            f"object; run 'git lfs pull' in the mirror to enable license "
                            f"extraction (using manifest/curation meanwhile)"
                        ),
                    )
        if data:
            tmp = Path(tempfile.mkdtemp(prefix="sbom-depsdir-", dir=tmp_parent))
            path = _extract_bytes(archive, data, tmp)
            if path is None:
                shutil.rmtree(tmp, ignore_errors=True)
            else:
                cleanup = lambda: shutil.rmtree(tmp, ignore_errors=True)  # noqa: E731

    return (
        ResolvedSource(path=path, manifest=manifest, origin=f"deps-dir git branch {label}", _cleanup=cleanup),
        lfs_warn,
    )


def resolve_source(
    component: Component, deps_root: Path, *, tmp_parent: str | None = None
) -> tuple[ResolvedSource | None, Warning | None]:
    """Resolve a component to a scannable source + optional manifest.

    Returns ``(ResolvedSource | None, Warning | None)``. Dispatches on the
    on-disk layout: git mirror → :func:`_resolve_git`; plain dir → used directly;
    archive file → extracted to a temp dir. A dep not found under *deps_root*
    yields ``(None, None)`` (silent — most components are not vendored here).
    """
    dep = find_dep(component, deps_root)
    if dep is None:
        return None, None

    if dep.is_dir() and _is_git_repo(dep):
        return _resolve_git(component, dep, tmp_parent)

    if dep.is_dir():
        return ResolvedSource(path=dep, manifest=_read_manifest_dir(dep), origin=f"deps-dir {dep.name}"), None

    if dep.is_file() and _is_archive(dep.name):
        tmp = Path(tempfile.mkdtemp(prefix="sbom-depsdir-", dir=tmp_parent))
        path = _extract_file(dep, tmp)
        if path is None:
            shutil.rmtree(tmp, ignore_errors=True)
            return None, Warning(
                code="deps_dir_extract_failed",
                subject=component.name,
                detail=f"could not extract {dep}",
            )
        return (
            ResolvedSource(
                path=path,
                manifest=_read_manifest_dir(path),
                origin=f"deps-dir archive {dep.name}",
                _cleanup=lambda: shutil.rmtree(tmp, ignore_errors=True),
            ),
            None,
        )
    return None, None


# ---------------------------------------------------------------------------
# License-file scan on a materialized dir (cache_scan heuristic, license-only)
# ---------------------------------------------------------------------------


def _scan_license_dir(directory: Path) -> tuple[str | None, Path | None]:
    """Best-effort SPDX id from LICENSE/COPYING files at *directory*'s top.

    Conflict-aware (via :func:`cache_scan._pick_license`): a multi-license dir
    (e.g. eigen's COPYING.APACHE/BSD/MPL2 + a bare LICENSE) resolves to the bare
    canonical file's license, or ``None`` if genuinely ambiguous — never an
    arbitrary alphabetically-first pick."""
    return cache_scan._pick_license(cache_scan._find_license_files(directory))


# ---------------------------------------------------------------------------
# Public API — the reconcile license/copyright layer
# ---------------------------------------------------------------------------


def apply(
    components: list[Component], config: "Config", profile: "Profile | None" = None
) -> tuple[list[Warning], dict[str, Path], list[Callable[[], None]]]:
    """Fill license/copyright from on-disk sources under ``config.deps_dir``.

    Returns ``(warnings, source_map, cleanups)``:

    * ``source_map`` maps ``component.name`` → a materialized scannable directory,
      handed to the ScanCode enrich layer so it reads copyright + a thorough
      license from the REAL tree (not just the LICENSE heuristic here).
    * ``cleanups`` are callables the caller MUST invoke after the ScanCode layer
      has run, to remove the temp extractions.

    Fill-only semantics: ``license``/``copyright`` are set only where unset; a
    manifest license that disagrees with an already-resolved one emits a
    ``deps_dir_license_discrepancy`` warning instead of overriding.
    """
    warnings: list[Warning] = []
    source_map: dict[str, Path] = {}
    cleanups: list[Callable[[], None]] = []

    deps_root = Path(getattr(config, "deps_dir", None) or "")
    if not deps_root.is_dir():
        warnings.append(
            Warning(
                code="deps_dir_missing",
                subject=None,
                detail=f"--deps-dir {deps_root} is not a directory",
            )
        )
        return warnings, source_map, cleanups

    for comp in components:
        rs, warn = resolve_source(comp, deps_root)
        if warn is not None:
            warnings.append(warn)
        if rs is None:
            continue
        if rs._cleanup is not None:
            cleanups.append(rs.cleanup)
        if rs.path is not None and rs.path.is_dir():
            source_map[comp.name] = rs.path

        # Manifest (authoritative for the mirror): license + copyright.
        if rs.manifest is not None:
            lic = rs.manifest.resolved_license()
            if lic:
                if comp.license is None:
                    comp.license = lic
                    comp.provenance.append(Provenance(field="license", source=f"deps_dir:{rs.origin}"))
                elif comp.license not in (lic, "NOASSERTION"):
                    warnings.append(
                        Warning(
                            code="deps_dir_license_discrepancy",
                            subject=comp.name,
                            detail=f"resolved {comp.license} != {rs.origin} manifest {lic}",
                        )
                    )
            cright = rs.manifest.copyright_text()
            if cright and comp.copyright is None:
                comp.copyright = cright
                comp.provenance.append(Provenance(field="copyright", source=f"deps_dir:{rs.origin}"))

        # LICENSE-file heuristic on the materialized tree (license only if unset).
        if comp.license is None and rs.path is not None:
            spdx, lf = _scan_license_dir(rs.path)
            if spdx is not None:
                comp.license = spdx
                comp.provenance.append(Provenance(field="license", source=f"deps_dir:{lf}"))

    return warnings, source_map, cleanups


__all__ = [
    "Manifest",
    "ResolvedSource",
    "apply",
    "resolve_source",
    "find_dep",
    "select_branch",
    "parse_manifest",
]
