"""Repository origin (VCS host + homepage) resolution for subjects.

Every subject is built from THIS repo; recording where the repo lives — its VCS
host and, when known, a checkout-able revision — gives SBOM consumers a real
provenance anchor. The purl TYPE deliberately stays ``generic``:

* hosts like gitcode are NOT registered purl types, so ``pkg:gitcode/...`` would
  break vulnerability matching and strict validators downstream; and
* a CANN *product* version (``9.0.0``) is not a git ref, so it must not sit in a
  VCS-type purl's ``@version`` slot.

Instead the origin is recorded the spec-blessed way: as a ``vcs_url`` purl
qualifier on the generic purl, and as native CycloneDX externalReferences /
SPDX ``downloadLocation`` + ``homepage``.

Resolution priority (first hit wins):

1. ``config.repo_url``            -- explicit ``--repo-url`` (authoritative).
2. ``profile.repo_origin(root)``  -- a profile that knows its canonical URL.
3. ``.git/config`` remote origin  -- offline auto-detect for a git checkout.

The revision (a clean ``HEAD`` commit) is best-effort and only appended to the
VCS locator when resolvable; it is never required.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RepoOrigin:
    """A resolved repository origin.

    ``web_url`` is the human, browseable project URL (``https://host/owner/repo``)
    and ``vcs_url`` is the VCS locator in the SPDX/pip form
    (``git+https://host/owner/repo.git[@<rev>]``). ``revision`` is the bare
    commit/tag, when known.
    """

    web_url: str
    vcs_url: str
    revision: str | None = None


def resolve_repo_origin(config, profile) -> RepoOrigin | None:
    """Resolve the repo origin per the priority order; ``None`` if undetectable."""
    repo_root = _repo_root(config)

    explicit = getattr(config, "repo_url", None) if config is not None else None
    if explicit:
        norm = _normalize_remote(explicit)
        if norm is not None:
            return _with_revision(norm, repo_root)

    if profile is not None and repo_root is not None:
        hook = getattr(profile, "repo_origin", None)
        if callable(hook):
            origin = hook(repo_root)
            if isinstance(origin, RepoOrigin):
                return origin

    if repo_root is not None:
        norm = _from_git_config(repo_root)
        if norm is not None:
            return _with_revision(norm, repo_root)

    return None


def apply_repo_origin(subjects, config, profile) -> None:
    """Stamp the resolved origin onto every subject (in place; no-op if none)."""
    origin = resolve_repo_origin(config, profile)
    if origin is None:
        return
    for subject in subjects:
        subject.homepage = origin.web_url
        subject.vcs_url = origin.vcs_url
        if origin.revision and not subject.repo_revision:
            subject.repo_revision = origin.revision


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _repo_root(config) -> Path | None:
    root = getattr(config, "repo_root", None) if config is not None else None
    return Path(root) if root is not None else None


def _with_revision(norm: tuple[str, str], repo_root: Path | None) -> RepoOrigin:
    web_url, vcs_base = norm
    rev = _head_commit(repo_root) if repo_root is not None else None
    vcs_url = f"{vcs_base}@{rev}" if rev else vcs_base
    return RepoOrigin(web_url=web_url, vcs_url=vcs_url, revision=rev)


def _from_git_config(repo_root: Path) -> tuple[str, str] | None:
    cfg = repo_root / ".git" / "config"
    if not cfg.is_file():
        return None
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # The url within the [remote "origin"] section, up to the next section header.
    m = re.search(
        r'\[remote\s+"origin"\][^\[]*?^\s*url\s*=\s*(\S+)',
        text,
        re.MULTILINE,
    )
    if not m:
        return None
    return _normalize_remote(m.group(1))


def _normalize_remote(raw: str) -> tuple[str, str] | None:
    """Normalize a git remote (scp / https / ssh / git) to (web_url, vcs_base).

    Returns ``(https://host/owner/repo, git+https://host/owner/repo.git)`` or
    ``None`` when the value is not a recognizable remote (e.g. a bare local path).
    Public hosts are reached over https regardless of the original scheme.
    """
    raw = raw.strip()
    if not raw:
        return None

    host = path = None
    if "://" in raw:
        from urllib.parse import urlsplit

        u = urlsplit(raw)
        host = u.hostname
        path = u.path
    else:
        # scp-like: [user@]host:path  (no scheme).
        m = re.match(r"^(?:[\w.+-]+@)?([\w.-]+):(.+)$", raw)
        if m:
            host, path = m.group(1), m.group(2)

    if not host or not path:
        return None
    # urlsplit().hostname strips the brackets off an IPv6 literal; re-wrap it so
    # the composed authority is RFC 3986-valid (an unbracketed ':' host reparses
    # wrong / raises and fails the SPDX URL validator).
    if ":" in host:
        host = f"[{host}]"
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    path = path.strip("/")
    if not path:
        return None

    web_url = f"https://{host}/{path}"
    vcs_url = f"git+https://{host}/{path}.git"
    return web_url, vcs_url


def _head_commit(repo_root: Path) -> str | None:
    """The repo's ``HEAD`` commit SHA, or ``None`` when not a git checkout.

    A clean, checkout-able ref for the VCS locator (unlike ``git describe``, which
    can yield a ``-dirty`` suffix that is not a valid ref).
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode == 0 and out.stdout.strip():
        return out.stdout.strip()
    return None
