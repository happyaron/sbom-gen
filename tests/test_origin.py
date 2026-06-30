"""Unit tests for :mod:`sbom.origin` — repo VCS-origin resolution.

Covers remote-URL normalization (scp / https / ssh / git, with and without a
``.git`` suffix), ``.git/config`` parsing, the resolution priority
(``--repo-url`` > profile hook > ``.git/config``), and subject stamping. Tests
are hermetic: they never assume the temp dir is (or is not) a real git checkout
beyond what is asserted, and the only place a revision could appear tolerates its
absence.
"""

from __future__ import annotations

from pathlib import Path

from sbom.config import Config
from sbom.models import Identity, Subject, SubjectKind, SubjectRole
from sbom.origin import (
    RepoOrigin,
    _from_git_config,
    _normalize_remote,
    apply_repo_origin,
    resolve_repo_origin,
)
from sbom.profile import GenericProfile, Profile


# ---------------------------------------------------------------------------
# _normalize_remote
# ---------------------------------------------------------------------------


def test_normalize_scp_form():
    assert _normalize_remote("git@gitcode.com:cann/ops-math.git") == (
        "https://gitcode.com/cann/ops-math",
        "git+https://gitcode.com/cann/ops-math.git",
    )


def test_normalize_https_with_and_without_git_suffix():
    expected = (
        "https://github.com/owner/repo",
        "git+https://github.com/owner/repo.git",
    )
    assert _normalize_remote("https://github.com/owner/repo.git") == expected
    assert _normalize_remote("https://github.com/owner/repo") == expected


def test_normalize_ssh_form_forces_https():
    assert _normalize_remote("ssh://git@gitcode.com/cann/pyasc.git") == (
        "https://gitcode.com/cann/pyasc",
        "git+https://gitcode.com/cann/pyasc.git",
    )


def test_normalize_nested_namespace_path():
    # A group/subgroup path is preserved verbatim in both URLs.
    assert _normalize_remote("git@gitlab.com:group/sub/repo.git") == (
        "https://gitlab.com/group/sub/repo",
        "git+https://gitlab.com/group/sub/repo.git",
    )


def test_normalize_ipv6_literal_host_is_bracketed():
    # urlsplit().hostname drops the brackets; the composed URL must restore them
    # (RFC 3986) so it reparses cleanly instead of raising on .port.
    from urllib.parse import urlsplit

    web, vcs = _normalize_remote("ssh://git@[2001:db8::1]:2222/owner/repo.git")
    assert web == "https://[2001:db8::1]/owner/repo"
    assert vcs == "git+https://[2001:db8::1]/owner/repo.git"
    assert urlsplit(web).hostname == "2001:db8::1"  # reparses, no ValueError


def test_normalize_rejects_bare_local_path():
    assert _normalize_remote("/srv/git/local-repo") is None
    assert _normalize_remote("") is None
    assert _normalize_remote("not-a-remote") is None


# ---------------------------------------------------------------------------
# _from_git_config
# ---------------------------------------------------------------------------


def _write_git_config(repo: Path, url: str) -> None:
    gitdir = repo / ".git"
    gitdir.mkdir(parents=True, exist_ok=True)
    (gitdir / "config").write_text(
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        '[remote "origin"]\n'
        f"\turl = {url}\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        '[remote "upstream"]\n'
        "\turl = git@example.com:other/repo.git\n",
        encoding="utf-8",
    )


def test_from_git_config_reads_origin_not_upstream(tmp_path):
    _write_git_config(tmp_path, "git@gitcode.com:cann/ops-math.git")
    assert _from_git_config(tmp_path) == (
        "https://gitcode.com/cann/ops-math",
        "git+https://gitcode.com/cann/ops-math.git",
    )


def test_from_git_config_absent(tmp_path):
    assert _from_git_config(tmp_path) is None


# ---------------------------------------------------------------------------
# resolve_repo_origin priority
# ---------------------------------------------------------------------------


class _FixedOriginProfile(Profile):
    name = "fixed"

    def repo_origin(self, repo_root):
        return RepoOrigin(
            web_url="https://example.com/team/proj",
            vcs_url="git+https://example.com/team/proj.git@deadbeef",
            revision="deadbeef",
        )


def test_explicit_repo_url_wins_over_git_config(tmp_path):
    _write_git_config(tmp_path, "git@gitcode.com:cann/ops-math.git")
    cfg = Config(repo_root=tmp_path, repo_url="https://github.com/owner/override")
    origin = resolve_repo_origin(cfg, GenericProfile())
    assert origin is not None
    assert origin.web_url == "https://github.com/owner/override"
    assert origin.vcs_url.startswith("git+https://github.com/owner/override.git")


def test_profile_hook_used_when_no_explicit_url(tmp_path):
    # No --repo-url; the profile hook outranks .git/config auto-detection.
    _write_git_config(tmp_path, "git@gitcode.com:cann/ops-math.git")
    cfg = Config(repo_root=tmp_path)
    origin = resolve_repo_origin(cfg, _FixedOriginProfile())
    assert origin == RepoOrigin(
        web_url="https://example.com/team/proj",
        vcs_url="git+https://example.com/team/proj.git@deadbeef",
        revision="deadbeef",
    )


def test_git_config_used_as_last_resort(tmp_path):
    _write_git_config(tmp_path, "git@gitcode.com:cann/runtime.git")
    cfg = Config(repo_root=tmp_path)
    origin = resolve_repo_origin(cfg, GenericProfile())
    assert origin is not None
    assert origin.web_url == "https://gitcode.com/cann/runtime"
    # The temp dir is not a real checkout, so no revision is appended.
    assert origin.vcs_url.startswith("git+https://gitcode.com/cann/runtime.git")


def test_resolve_none_when_no_origin(tmp_path):
    cfg = Config(repo_root=tmp_path)
    assert resolve_repo_origin(cfg, GenericProfile()) is None


# ---------------------------------------------------------------------------
# apply_repo_origin stamping
# ---------------------------------------------------------------------------


def test_apply_repo_origin_stamps_every_subject(tmp_path):
    _write_git_config(tmp_path, "git@gitcode.com:cann/ops-math.git")
    cfg = Config(repo_root=tmp_path)
    subjects = [
        Subject(
            id="ops_math",
            identity=Identity(SubjectKind.CANN_PACKAGE, "ops_math", "9.0.0"),
            role=SubjectRole.PRIMARY,
        ),
        Subject(
            id="npu_math_extension",
            identity=Identity(SubjectKind.PYTHON_WHEEL, "npu_math_extension", "1.0.0"),
            role=SubjectRole.SIBLING_ARTIFACT,
        ),
    ]
    apply_repo_origin(subjects, cfg, GenericProfile())
    for s in subjects:
        assert s.homepage == "https://gitcode.com/cann/ops-math"
        assert s.vcs_url.startswith("git+https://gitcode.com/cann/ops-math.git")


def test_apply_repo_origin_noop_without_origin(tmp_path):
    cfg = Config(repo_root=tmp_path)
    subj = Subject(
        id="x",
        identity=Identity(SubjectKind.CANN_PACKAGE, "x", "1.0"),
        role=SubjectRole.PRIMARY,
    )
    apply_repo_origin([subj], cfg, GenericProfile())
    assert subj.homepage is None and subj.vcs_url is None
