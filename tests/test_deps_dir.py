"""Unit tests for sbom.enrich.deps_dir (the --deps-dir on-disk source resolver).

Covers the version→branch heuristic, Readme.opensource manifest parsing, bounded
archive extraction, dep lookup, the git-mirror resolver (including the SECURITY
constraint that the informational default branch's LICENSE is NEVER read), and
the fill-only ``apply`` license/copyright layer. A real on-disk git repository is
built per test so the actual git code paths (for-each-ref / ls-tree / show) run.
"""

from __future__ import annotations

import io
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sbom.models import Component
from sbom.enrich import deps_dir as dd


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@dataclass
class _Config:
    """Minimal Config stub (apply() reads only ``deps_dir``)."""

    deps_dir: str | None = None
    scancode: str | None = None
    scancode_path: str | None = None


def _comp(name: str, version: str | None = None, aliases: list[str] | None = None) -> Component:
    return Component(name=name, effective_version=version, aliases=aliases or [])


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _make_tar_gz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _make_mirror(root: Path, name: str, branches: dict[str, dict[str, bytes]], *, master_license: str = "INACCURATE master LICENSE\n") -> Path:
    """Create a git repo whose master is informational and whose given branches
    each hold the supplied ``{path: bytes}`` files (orphan branches)."""
    repo = root / name
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "master")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "LICENSE").write_text(master_license)
    (repo / "README.md").write_text(f"{name} master (informational)\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "master")
    for bname, files in branches.items():
        _git(repo, "checkout", "-q", "--orphan", bname)
        _git(repo, "rm", "-rfq", ".")
        for path, data in files.items():
            f = repo / path
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", bname)
    _git(repo, "checkout", "-q", "master")
    return repo


_MIT_TEXT = (
    "MIT License\n\nPermission is hereby granted, free of charge, to any person "
    "obtaining a copy of this software...\n"
)
_APACHE_TEXT = "Apache License\nVersion 2.0, January 2004\n"
_BSD3_TEXT = (
    "Redistribution and use in source and binary forms... Neither the name of the "
    "copyright holder nor the names of its contributors may be used to endorse...\n"
)


# ---------------------------------------------------------------------------
# Version <-> branch matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("v9.12.x", "9.12"),
        ("1.1.16x", "1.1.16"),
        ("5.0.0.x-h0.trunk", "5.0.0"),
        ("3.11.x", "3.11"),
        ("3.4", "3.4"),
        ("5.0.0", "5.0.0"),
        ("v2.5.0.x", "2.5.0"),
    ],
)
def test_normalize_version(raw, expected):
    assert dd._normalize_version(raw) == expected


@pytest.mark.parametrize(
    "want,branch,score",
    [
        ("5.0.0", "5.0.0", 3),
        ("3.11.3", "3.11", 2),
        ("3.11.3", "3.10", None),
        ("3.11.3", "3.12.0", None),
        ("9.12", "9.12", 2),
        ("1.2.3", "1", 1),
    ],
)
def test_match_score(want, branch, score):
    assert dd._match_score(want, branch) == score


def test_select_branch_exact_and_suffix_tiebreak(tmp_path):
    repo = _make_mirror(
        tmp_path,
        "eigen",
        {
            "3.4": {"eigen-3.4.tar.gz": _make_tar_gz({"eigen-3.4/LICENSE": b"x"})},
            "5.0.0.x": {"eigen-5.0.0.tar.gz": _make_tar_gz({"eigen-5.0.0/COPYING": b"x"})},
            "5.0.0.x-h0.trunk": {"eigen-5.0.0.tar.gz": _make_tar_gz({"eigen-5.0.0/COPYING": b"x"})},
        },
    )
    ref, versioned = dd.select_branch(repo, "5.0.0")
    # The clean branch wins over the -h0.trunk variant on an equal score.
    assert ref == "5.0.0.x"
    assert set(versioned) == {"3.4", "5.0.0.x", "5.0.0.x-h0.trunk"}


def test_select_branch_no_match_returns_none_but_lists_branches(tmp_path):
    repo = _make_mirror(
        tmp_path,
        "eigen",
        {"3.4": {"a.tar.gz": _make_tar_gz({"a/LICENSE": b"x"})},
         "5.0.0.x": {"a.tar.gz": _make_tar_gz({"a/LICENSE": b"x"})}},
    )
    ref, versioned = dd.select_branch(repo, "9.9.9")
    assert ref is None
    assert versioned  # it IS a mirror -> caller must skip, not use master


def test_select_branch_normal_clone_has_no_version_branches(tmp_path):
    repo = _make_mirror(tmp_path, "plainrepo", {})  # only master
    ref, versioned = dd.select_branch(repo, "1.0.0")
    assert ref is None
    assert versioned == []


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------


def test_parse_manifest_uses_first_license_block_only():
    text = (
        "Software: json 3.11.3\n"
        "Copyright Notice(s):\n"
        "Copyright (c) 2013-2022 Niels Lohmann\n"
        "Copyright (c) 2013-2022 Niels Lohmann\n"  # duplicate -> deduped
        "Copyright 2018 The Abseil Authors\n"
        "License: MIT\n"
        "Full License Text:\n"
        "MIT License\n"
        "License: Apache-2.0\n"          # bundled sub-license -> IGNORED
        "Full License Text:\n"
        "Apache License Version 2.0\n"
    )
    m = dd.parse_manifest(text)
    assert m.license_token == "MIT"
    assert m.resolved_license() == "MIT"
    assert m.copyrights == [
        "Copyright (c) 2013-2022 Niels Lohmann",
        "Copyright 2018 The Abseil Authors",
    ]
    assert "Apache" not in (m.full_license_text or "")


def test_manifest_vague_token_falls_back_to_full_text():
    m = dd.Manifest(license_token="BSD", full_license_text=_BSD3_TEXT)
    assert m.resolved_license() == "BSD-3-Clause"


def test_manifest_clean_token_preferred_over_bundled_fulltext():
    # token MIT but full text (incorrectly) contains Apache -> token wins.
    m = dd.Manifest(license_token="MIT", full_license_text=_APACHE_TEXT)
    assert m.resolved_license() == "MIT"


def test_manifest_copyright_text_capped():
    m = dd.Manifest(copyrights=["Copyright X " * 50, "Copyright Y"])
    out = m.copyright_text(max_chars=40)
    assert out is not None and len(out) <= 40


# ---------------------------------------------------------------------------
# Dep lookup
# ---------------------------------------------------------------------------


def test_find_dep_exact_alias_namever_normalized(tmp_path):
    (tmp_path / "eigen").mkdir()
    (tmp_path / "libboundscheck").mkdir()
    (tmp_path / "or-tools").mkdir()
    (tmp_path / "json-3.11.3").mkdir()
    (tmp_path / "boost-1.84.0.tar.gz").write_bytes(b"x")

    assert dd.find_dep(_comp("eigen"), tmp_path).name == "eigen"
    # alias -> libboundscheck
    assert dd.find_dep(_comp("securec", aliases=["libboundscheck"]), tmp_path).name == "libboundscheck"
    # normalized fuzzy: ortools -> or-tools
    assert dd.find_dep(_comp("ortools"), tmp_path).name == "or-tools"
    # name-version dir
    assert dd.find_dep(_comp("json", "3.11.3"), tmp_path).name == "json-3.11.3"
    # archive stem
    assert dd.find_dep(_comp("boost", "1.84.0"), tmp_path).name == "boost-1.84.0.tar.gz"
    # miss
    assert dd.find_dep(_comp("nonexistent"), tmp_path) is None


# ---------------------------------------------------------------------------
# resolve_source — the git mirror
# ---------------------------------------------------------------------------


def test_resolve_git_mirror_manifest_and_extraction(tmp_path):
    manifest = (
        "Software: json 3.11.3\n"
        "Copyright Notice(s):\n"
        "Copyright (c) 2013-2022 Niels Lohmann\n"
        "License: MIT\n"
        "Full License Text:\n"
        "MIT License\n"
    )
    archive = _make_tar_gz({"json-3.11.3/LICENSE.MIT": _MIT_TEXT.encode(), "json-3.11.3/src.h": b"// code\n"})
    repo = _make_mirror(
        tmp_path,
        "json",
        {"3.11.x": {"json-3.11.3.tar.gz": archive, "Readme.opensource": manifest.encode()}},
    )
    rs, warn = dd.resolve_source(_comp("json", "3.11.3"), tmp_path)
    assert warn is None and rs is not None
    assert rs.manifest is not None
    assert rs.manifest.resolved_license() == "MIT"
    assert rs.manifest.copyright_text().startswith("Copyright (c) 2013-2022 Niels Lohmann")
    # the archive was materialized to a scannable dir containing the inner tree
    assert rs.path is not None and rs.path.is_dir()
    assert (rs.path / "LICENSE.MIT").exists()
    rs.cleanup()


def test_resolve_git_mirror_NEVER_reads_master_license(tmp_path):
    # SECURITY CONSTRAINT: master LICENSE is inaccurate and must be ignored.
    archive = _make_tar_gz({"dep-1.0.0/LICENSE": _MIT_TEXT.encode()})
    repo = _make_mirror(
        tmp_path,
        "dep",
        {"1.0.x": {"dep-1.0.0.tar.gz": archive}},
        master_license=_APACHE_TEXT,  # the trap: master claims Apache
    )
    rs, warn = dd.resolve_source(_comp("dep", "1.0.0"), tmp_path)
    assert rs is not None
    spdx, lf = dd._scan_license_dir(rs.path)
    assert spdx == "MIT"  # from the branch archive, NOT master's Apache
    rs.cleanup()


def test_resolve_git_mirror_no_branch_match_skips_with_warning(tmp_path):
    archive = _make_tar_gz({"dep-1.0.0/LICENSE": _MIT_TEXT.encode()})
    _make_mirror(tmp_path, "dep", {"1.0.x": {"dep-1.0.0.tar.gz": archive}}, master_license=_APACHE_TEXT)
    rs, warn = dd.resolve_source(_comp("dep", "7.7.7"), tmp_path)
    assert rs is None
    assert warn is not None and warn.code == "deps_dir_no_branch"


def test_resolve_normal_clone_uses_working_tree(tmp_path):
    # No version branches -> a normal clone -> working tree is used.
    repo = _make_mirror(tmp_path, "plain", {}, master_license=_MIT_TEXT)
    rs, warn = dd.resolve_source(_comp("plain", "1.0.0"), tmp_path)
    assert warn is None and rs is not None
    spdx, _ = dd._scan_license_dir(rs.path)
    assert spdx == "MIT"


def test_resolve_git_failure_skips_NEVER_reads_master(tmp_path, monkeypatch):
    # SECURITY: a git-mirror (.git present) whose git cannot enumerate refs must be
    # SKIPPED, not fall back to the informational master working tree (Apache trap).
    archive = _make_tar_gz({"dep-1.0.0/LICENSE": _MIT_TEXT.encode()})
    _make_mirror(tmp_path, "dep", {"1.0.x": {"dep-1.0.0.tar.gz": archive}}, master_license=_APACHE_TEXT)
    monkeypatch.setattr(dd, "_git_text", lambda *a, **k: None)  # git enumeration fails
    rs, warn = dd.resolve_source(_comp("dep", "1.0.0"), tmp_path)
    assert rs is None
    assert warn is not None and warn.code == "deps_dir_git_unreadable"


def test_select_branch_distinguishes_git_failure_from_empty(tmp_path, monkeypatch):
    repo = _make_mirror(tmp_path, "dep", {"1.0.x": {"a.tar.gz": _make_tar_gz({"a/LICENSE": b"x"})}})
    monkeypatch.setattr(dd, "_git_text", lambda *a, **k: None)
    ref, versioned = dd.select_branch(repo, "1.0.0")
    assert ref is None and versioned is None  # None == git failed (not [] == normal clone)


def test_plain_dir_inside_enclosing_git_repo_not_misrouted(tmp_path):
    # A PLAIN dep dir living INSIDE an enclosing git checkout (which has a
    # version-looking branch) must be read as a plain dir — NOT misrouted to the
    # git-mirror resolver, which would enumerate the ENCLOSING repo's branches.
    enclosing = tmp_path / "project"
    enclosing.mkdir()
    _git(enclosing, "init", "-q", "-b", "master")
    _git(enclosing, "config", "user.email", "t@t")
    _git(enclosing, "config", "user.name", "t")
    (enclosing / "x").write_text("x")
    _git(enclosing, "add", "-A")
    _git(enclosing, "commit", "-qm", "c")
    _git(enclosing, "branch", "v9.9.9")  # version-looking branch on the ENCLOSING repo
    deps = enclosing / "deps"
    deps.mkdir()
    dep = deps / "fmt"
    dep.mkdir()
    (dep / "LICENSE").write_text(_MIT_TEXT)

    assert dd._is_git_repo(dep) is False  # not a repo ROOT
    rs, warn = dd.resolve_source(_comp("fmt", "10.0.0"), deps)
    assert warn is None and rs is not None
    assert dd._scan_license_dir(rs.path)[0] == "MIT"  # plain dir read, not skipped/misattributed


def test_lfs_pointer_without_object_warns_not_extracted(tmp_path):
    pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 12345\n"
    _make_mirror(tmp_path, "boostish", {"1.0.x": {"boostish-1.0.0.tar.gz": pointer}}, master_license=_APACHE_TEXT)
    rs, warn = dd.resolve_source(_comp("boostish", "1.0.0"), tmp_path)
    assert warn is not None and warn.code == "deps_dir_lfs_pointer"
    assert rs is not None and rs.path is None  # the pointer is NOT treated as an archive


def test_lfs_pointer_with_local_object_extracts(tmp_path):
    import hashlib

    real = _make_tar_gz({"boostish-1.0.0/LICENSE": _BSD3_TEXT.encode()})
    oid = hashlib.sha256(real).hexdigest()
    pointer = (
        b"version https://git-lfs.github.com/spec/v1\noid sha256:"
        + oid.encode()
        + b"\nsize "
        + str(len(real)).encode()
        + b"\n"
    )
    repo = _make_mirror(tmp_path, "boostish", {"1.0.x": {"boostish-1.0.0.tar.gz": pointer}})
    objdir = repo / ".git" / "lfs" / "objects" / oid[:2] / oid[2:4]
    objdir.mkdir(parents=True)
    (objdir / oid).write_bytes(real)
    rs, warn = dd.resolve_source(_comp("boostish", "1.0.0"), tmp_path)
    assert warn is None and rs is not None and rs.path is not None
    assert dd._scan_license_dir(rs.path)[0] == "BSD-3-Clause"
    rs.cleanup()


def test_multilicense_dir_resolves_to_bare_license_primary(tmp_path):
    # eigen-style: many COPYING.<id> variants + a bare LICENSE = the primary.
    archive = _make_tar_gz(
        {
            "eigenish-1.0/COPYING.APACHE": _APACHE_TEXT.encode(),
            "eigenish-1.0/COPYING.BSD": _BSD3_TEXT.encode(),
            "eigenish-1.0/LICENSE": b"Mozilla Public License Version 2.0\n",
        }
    )
    _make_mirror(tmp_path, "eigenish", {"1.0.x": {"eigenish-1.0.tar.gz": archive}})
    rs, warn = dd.resolve_source(_comp("eigenish", "1.0"), tmp_path)
    assert warn is None and rs is not None
    assert dd._scan_license_dir(rs.path)[0] == "MPL-2.0"  # bare LICENSE wins, not alphabetical Apache
    rs.cleanup()


def test_multilicense_dir_no_canonical_is_ambiguous(tmp_path):
    archive = _make_tar_gz(
        {"x-1.0/COPYING.APACHE": _APACHE_TEXT.encode(), "x-1.0/COPYING.BSD": _BSD3_TEXT.encode()}
    )
    _make_mirror(tmp_path, "x", {"1.0.x": {"x-1.0.tar.gz": archive}})
    rs, _ = dd.resolve_source(_comp("x", "1.0"), tmp_path)
    assert dd._scan_license_dir(rs.path)[0] is None  # conflicting, no bare LICENSE -> defer
    rs.cleanup()


def test_dual_version_resolves_patched_via_source_version(tmp_path):
    # A patched component (source 25.1 → effective 3.13.0) must resolve against the
    # UPSTREAM branch the mirror is keyed by (25.1.x), not the patched version.
    archive = _make_tar_gz({"protobuf-25.1/LICENSE": _BSD3_TEXT.encode()})
    _make_mirror(tmp_path, "protobuf", {"v25.1.x": {"protobuf-25.1.tar.gz": archive}})
    comp = Component(name="protobuf", source_version="25.1", effective_version="3.13.0")
    rs, warn = dd.resolve_source(comp, tmp_path)
    assert warn is None and rs is not None
    assert "25.1" in rs.origin and "3.13.0" not in rs.origin
    assert dd._scan_license_dir(rs.path)[0] == "BSD-3-Clause"
    rs.cleanup()


def test_extract_member_size_cap_skips_bomb(tmp_path, monkeypatch):
    monkeypatch.setattr(dd, "_MAX_MEMBER_BYTES", 5000)
    data = _make_tar_gz({"pkg/big.bin": b"A" * 50000, "pkg/LICENSE": _MIT_TEXT.encode()})
    dest = tmp_path / "o"
    dest.mkdir()
    root = dd._extract_bytes("x.tar.gz", data, dest)
    assert not (root / "big.bin").exists()  # oversized member skipped (bomb guard)
    assert (root / "LICENSE").exists()       # the small license still extracted


def test_extract_zip_member_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(dd, "_MAX_MEMBER_BYTES", 5000)
    data = _make_zip({"pkg/big.bin": b"A" * 50000, "pkg/LICENSE": _MIT_TEXT.encode()})
    dest = tmp_path / "z"
    dest.mkdir()
    root = dd._extract_bytes("x.zip", data, dest)
    assert not (root / "big.bin").exists()
    assert (root / "LICENSE").exists()


def test_archive_blob_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(dd, "_MAX_ARCHIVE_BYTES", 10)
    data = _make_tar_gz({"pkg/LICENSE": _MIT_TEXT.encode()})
    dest = tmp_path / "o"
    dest.mkdir()
    assert dd._extract_bytes("x.tar.gz", data, dest) is None  # blob over cap refused


def test_resolve_archive_file(tmp_path):
    (tmp_path).joinpath("dep-2.0.0.tar.gz").write_bytes(
        _make_tar_gz({"dep-2.0.0/LICENSE": _BSD3_TEXT.encode()})
    )
    rs, warn = dd.resolve_source(_comp("dep", "2.0.0"), tmp_path)
    assert warn is None and rs is not None and rs.path is not None
    spdx, _ = dd._scan_license_dir(rs.path)
    assert spdx == "BSD-3-Clause"
    rs.cleanup()


def test_resolve_plain_dir(tmp_path):
    d = tmp_path / "dep"
    d.mkdir()
    (d / "LICENSE").write_text(_MIT_TEXT)
    rs, warn = dd.resolve_source(_comp("dep"), tmp_path)
    assert warn is None and rs is not None
    assert dd._scan_license_dir(rs.path)[0] == "MIT"


def test_resolve_miss_is_silent(tmp_path):
    rs, warn = dd.resolve_source(_comp("absent"), tmp_path)
    assert rs is None and warn is None


# ---------------------------------------------------------------------------
# Bounded extraction
# ---------------------------------------------------------------------------


def test_extract_bounded_surface(tmp_path):
    # A deep tree: only top-level files + license files (any depth) are extracted.
    archive = _make_tar_gz(
        {
            "pkg/LICENSE": b"MIT License\nPermission is hereby granted, free of charge\n",
            "pkg/README": b"top\n",
            "pkg/src/deep/buried.c": b"// deep\n",
            "pkg/src/deep/COPYING": b"copying\n",
        }
    )
    dest = tmp_path / "out"
    dest.mkdir()
    root = dd._extract_bytes("pkg.tar.gz", archive, dest)
    assert root is not None
    assert (root / "LICENSE").exists()
    assert (root / "README").exists()
    assert (root / "src" / "deep" / "COPYING").exists()  # license file kept
    assert not (root / "src" / "deep" / "buried.c").exists()  # deep non-license dropped


def test_extract_zip_path_traversal_guard(tmp_path):
    data = _make_zip({"../escape.txt": b"evil", "pkg/LICENSE": _MIT_TEXT.encode()})
    dest = tmp_path / "z"
    dest.mkdir()
    dd._extract_bytes("x.zip", data, dest)
    assert not (tmp_path / "escape.txt").exists()


def test_extract_tar_path_traversal_guard(tmp_path):
    # The tar guard must hold independent of tarfile filter='data' (absent on 3.11).
    data = _make_tar_gz({"../escape.txt": b"evil", "pkg/LICENSE": _MIT_TEXT.encode()})
    dest = tmp_path / "t"
    dest.mkdir()
    root = dd._extract_bytes("x.tar.gz", data, dest)
    assert not (tmp_path / "escape.txt").exists()
    assert (root / "LICENSE").exists()  # the legit member still extracted


def test_safe_member_rejects_traversal_and_absolute(tmp_path):
    assert dd._safe_member("pkg/LICENSE", tmp_path) is True
    assert dd._safe_member("../escape", tmp_path) is False
    assert dd._safe_member("/etc/passwd", tmp_path) is False
    assert dd._safe_member("a/../../b", tmp_path) is False


# ---------------------------------------------------------------------------
# apply() — the fill-only license/copyright layer
# ---------------------------------------------------------------------------


def test_apply_fills_license_and_copyright_and_source_map(tmp_path):
    manifest = (
        "Software: dep 1.0.0\nCopyright Notice(s):\nCopyright (c) 2020 Acme\n"
        "License: MIT\nFull License Text:\nMIT License\n"
    )
    archive = _make_tar_gz({"dep-1.0.0/LICENSE": _MIT_TEXT.encode()})
    _make_mirror(tmp_path, "dep", {"1.0.x": {"dep-1.0.0.tar.gz": archive, "Readme.opensource": manifest.encode()}})
    comp = _comp("dep", "1.0.0")
    cfg = _Config(deps_dir=str(tmp_path))
    warnings, source_map, cleanups = dd.apply([comp], cfg)
    assert comp.license == "MIT"
    assert comp.copyright == "Copyright (c) 2020 Acme"
    assert "dep" in source_map and source_map["dep"].is_dir()
    assert any(p.source.startswith("deps_dir:") for p in comp.provenance)
    for c in cleanups:
        c()


def test_apply_is_fill_only_and_warns_on_discrepancy(tmp_path):
    manifest = "Software: dep 1.0.0\nLicense: Apache-2.0\nFull License Text:\nApache License Version 2.0\n"
    archive = _make_tar_gz({"dep-1.0.0/LICENSE": _APACHE_TEXT.encode()})
    _make_mirror(tmp_path, "dep", {"1.0.x": {"dep-1.0.0.tar.gz": archive, "Readme.opensource": manifest.encode()}})
    comp = _comp("dep", "1.0.0")
    comp.license = "MIT"  # already resolved by a higher layer
    cfg = _Config(deps_dir=str(tmp_path))
    warnings, _, cleanups = dd.apply([comp], cfg)
    assert comp.license == "MIT"  # NOT overridden
    assert any(w.code == "deps_dir_license_discrepancy" for w in warnings)
    for c in cleanups:
        c()


def test_apply_missing_deps_dir_warns(tmp_path):
    cfg = _Config(deps_dir=str(tmp_path / "does-not-exist"))
    warnings, source_map, cleanups = dd.apply([_comp("dep", "1.0.0")], cfg)
    assert any(w.code == "deps_dir_missing" for w in warnings)
    assert source_map == {} and cleanups == []


# ---------------------------------------------------------------------------
# End-to-end through reconcile (layer wiring + no temp leak)
# ---------------------------------------------------------------------------


def test_reconcile_wires_deps_dir_and_cleans_temp(tmp_path):
    from sbom.config import Config
    from sbom.reconcile import reconcile
    from sbom.collectors import CollectResult
    from sbom.profile import GenericProfile
    from sbom.models import Observation, SourceKind, UsageScope

    manifest = (
        "Software: json 3.11.3\nCopyright Notice(s):\nCopyright (c) 2013 Niels Lohmann\n"
        "License: MIT\nFull License Text:\nMIT License\n"
    )
    archive = _make_tar_gz({"json-3.11.3/LICENSE": _MIT_TEXT.encode()})
    deps = tmp_path / "deps"
    deps.mkdir()
    _make_mirror(deps, "json", {"3.11.x": {"json-3.11.3.tar.gz": archive, "Readme.opensource": manifest.encode()}})

    comp = Component(name="json", effective_version="3.11.3")
    comp.observations.append(
        Observation(source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT, usage_scope=UsageScope.RUNTIME,
                    ecosystem_data={"name": "json"})
    )
    res = CollectResult(components=[comp], observations=[], edges=[])
    cfg = Config(repo_root=tmp_path, deps_dir=str(deps), scope="all")

    before = set(Path("/tmp").glob("sbom-depsdir-*"))
    doc = reconcile([res], [], cfg, GenericProfile())
    after = set(Path("/tmp").glob("sbom-depsdir-*"))

    out = next(c for c in doc.components if c.name == "json")
    assert out.license == "MIT"
    assert any(p.field == "license" and p.source.startswith("deps_dir:") for p in out.provenance)
    assert before == after  # temp extraction cleaned up


# ---------------------------------------------------------------------------
# deps_dir_cache — the seeded offline snapshot
# ---------------------------------------------------------------------------


def test_cache_apply_alias_aware_and_fill_only():
    from sbom.enrich import deps_dir_cache as ddc

    cache = {"libboundscheck": {"license": "MulanPSL-2.0", "copyright": "Copyright Huawei"}}
    # alias-aware: securec resolves the libboundscheck-keyed entry
    comp = Component(name="securec", aliases=["libboundscheck"])
    ddc.apply([comp], cache)
    assert comp.license == "MulanPSL-2.0"
    assert comp.copyright == "Copyright Huawei"
    assert any(p.source == "deps-dir-cache" for p in comp.provenance)

    # fill-only: an already-set license is not overridden, copyright still fills
    comp2 = Component(name="json")
    comp2.license = "MIT"
    ddc.apply([comp2], {"json": {"license": "Apache-2.0", "copyright": "c"}})
    assert comp2.license == "MIT"
    assert comp2.copyright == "c"


def test_cache_load_merge_and_corrupt_skip(tmp_path):
    from sbom.enrich import deps_dir_cache as ddc

    f1 = tmp_path / "a.json"
    f1.write_text(ddc.dump({"a": {"license": "MIT"}}))
    f2 = tmp_path / "b.json"
    f2.write_text(ddc.dump({"a": {"license": "Apache-2.0"}, "b": {"license": "BSD-3-Clause"}}))
    merged = ddc.load([f1, f2])
    assert merged["a"]["license"] == "Apache-2.0"  # later wins
    assert merged["b"]["license"] == "BSD-3-Clause"

    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert "a" in ddc.load([bad, f1])  # corrupt file skipped, valid still loaded
    assert ddc.load([tmp_path / "missing.json"]) == {}


def test_refresh_deps_dir_writes_cache(tmp_path):
    from sbom.config import Config
    from sbom import refresh
    from sbom.data_sources import DataSource, DERIVED, build_data_sources

    deps = tmp_path / "deps"
    deps.mkdir()
    archive = _make_tar_gz({"fmt-10.0.0/LICENSE": _MIT_TEXT.encode()})
    _make_mirror(deps, "fmt", {"10.0.x": {"fmt-10.0.0.tar.gz": archive}})
    # a plain-dir dep too
    plain = deps / "acme"
    plain.mkdir()
    (plain / "LICENSE").write_text(_BSD3_TEXT)

    cache_file = tmp_path / "deps_dir_cache.json"
    cache_file.write_text('{"schema":1,"entries":{}}')

    class _P:
        def data_sources(self):
            return [DataSource("deps-dir", DERIVED, cache_file, "json", "")]

    cfg = Config(repo_root=tmp_path, deps_dir=str(deps))
    rc = refresh._refresh_deps_dir_cache(cfg, _P(), build_data_sources(_P()))
    assert rc == 0
    import json

    data = json.loads(cache_file.read_text())
    assert data["entries"]["fmt"]["license"] == "MIT"
    assert data["entries"]["fmt"]["version"] == "10.0"
    assert data["entries"]["acme"]["license"] == "BSD-3-Clause"


def test_refresh_deps_dir_requires_deps_dir(tmp_path):
    from sbom.config import Config
    from sbom import refresh
    from sbom.data_sources import build_data_sources

    cfg = Config(repo_root=tmp_path)  # no deps_dir
    rc = refresh._refresh_deps_dir_cache(cfg, None, build_data_sources(None))
    assert rc == 1


def test_reconcile_cleans_temp_even_when_later_layer_raises(tmp_path, monkeypatch):
    from sbom import reconcile as reconcile_mod
    from sbom.config import Config
    from sbom.collectors import CollectResult
    from sbom.profile import GenericProfile
    from sbom.models import Observation, SourceKind, UsageScope

    archive = _make_tar_gz({"json-3.11.3/LICENSE": _MIT_TEXT.encode()})
    deps = tmp_path / "deps"
    deps.mkdir()
    _make_mirror(deps, "json", {"3.11.x": {"json-3.11.3.tar.gz": archive}})
    comp = Component(name="json", effective_version="3.11.3")
    comp.observations.append(
        Observation(source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT, usage_scope=UsageScope.RUNTIME,
                    ecosystem_data={"name": "json"})
    )
    res = CollectResult(components=[comp], observations=[], edges=[])
    cfg = Config(repo_root=tmp_path, deps_dir=str(deps), scope="all")

    def boom(*a, **k):
        raise RuntimeError("layer below deps-dir failed")

    monkeypatch.setattr(reconcile_mod, "_apply_depsdev_cache", boom)
    before = set(Path("/tmp").glob("sbom-depsdir-*"))
    with pytest.raises(RuntimeError):
        reconcile_mod.reconcile([res], [], cfg, GenericProfile())
    after = set(Path("/tmp").glob("sbom-depsdir-*"))
    assert before == after  # try/finally released the temp despite the raise
