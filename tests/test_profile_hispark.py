"""Unit tests for the HiSpark profile.

Two layers, mirroring ``test_profile_cann.py``:

* SYNTHETIC fixtures (a tmp tree) exercise the vendored-source discovery,
  version recovery, embedded-license scan, alias/known-license data files, and
  detection — no external checkout required, so they always run.
* A guarded REAL-TREE smoke test runs the full generator against the live
  ``../hispark/hs-fbb`` checkout when present (skipped otherwise).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sbom.models import SourceKind, SubjectRole, UsageScope
from sbom.profile import detect_profile, get_profile, load_profiles
from sbom_profile_hispark import (
    HisparkProfile,
    _discover,
    _extract_version,
    _resolve_source_and_version,
    _version_subdir_matches,
)

HISPARK_ROOT = Path("/home/aron/testing/cann/hispark")
HS_FBB = HISPARK_ROOT / "hs-fbb"

requires_tree = pytest.mark.skipif(
    not HS_FBB.is_dir(), reason="live HiSpark tree not present"
)


# ---------------------------------------------------------------------------
# Registry / detection
# ---------------------------------------------------------------------------


def test_profile_is_registered_and_resolvable():
    registry, warnings = load_profiles()
    assert "hispark" in registry
    assert registry["hispark"] is HisparkProfile
    assert all(w.code != "profile_load_failed" for w in warnings)
    inst, _ = get_profile("hispark")
    assert inst.name == "hispark"


def _write_git_origin(repo: Path, url: str) -> None:
    (repo / ".git").mkdir(parents=True, exist_ok=True)
    (repo / ".git" / "config").write_text(
        f'[remote "origin"]\n\turl = {url}\n', encoding="utf-8"
    )


def test_detect_matches_hispark_origin(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_git_origin(repo, "https://gitcode.com/HiSpark/some-board.git")
    assert HisparkProfile.detect(repo) is True


def test_detect_rejects_non_hispark_origin(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_git_origin(repo, "https://gitcode.com/cann/ops-math.git")
    assert HisparkProfile.detect(repo) is False
    # And the registry picks cann-not-hispark logic apart cleanly: no origin -> no match.
    bare = tmp_path / "bare"
    bare.mkdir()
    assert HisparkProfile.detect(bare) is False


# ---------------------------------------------------------------------------
# Version recovery
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("mbedtls_v3.6.5", "3.6.5"),
        ("libogg-1.3.5", "1.3.5"),
        ("lzma_25.01", "25.01"),
        ("QCBOR_v1.2", "1.2"),
        ("musl", None),
        ("source", None),
        ("riscv", None),
    ],
)
def test_extract_version(name, expected):
    assert _extract_version(name) == expected


def test_version_subdir_ownership_guard():
    # A version subdir belongs to its parent only when the name stems relate:
    assert _version_subdir_matches("mbedtls", "mbedtls_v3.6.5") is True
    assert _version_subdir_matches("7-zip-lzma-sdk", "lzma_25.01") is True  # shared 'lzma'
    # t_cose bundles QCBOR — QCBOR's version must NOT become t_cose's version.
    assert _version_subdir_matches("t_cose", "QCBOR_v1.2") is False


# ---------------------------------------------------------------------------
# Vendored-source discovery + embedded-license scan (synthetic tree)
# ---------------------------------------------------------------------------

_APACHE_HEADER = "SPDX-License-Identifier: Apache-2.0\nApache License Version 2.0\n"
_MIT_TEXT = "MIT License\n\nPermission is hereby granted, free of charge, ...\n"


def _make_tree(root: Path) -> None:
    osrc = root / "src" / "open_source"
    # nested version subdir + embedded LICENSE -> version AND license from tree
    (osrc / "mbedtls" / "mbedtls_v3.6.5").mkdir(parents=True)
    (osrc / "mbedtls" / "mbedtls_v3.6.5" / "LICENSE").write_text(_APACHE_HEADER)
    # flat component with a top-level LICENSE
    (osrc / "stb").mkdir(parents=True)
    (osrc / "stb" / "LICENSE").write_text(_MIT_TEXT)
    # component with a bundled sub-library whose version must NOT be adopted
    (osrc / "t_cose" / "QCBOR_v1.2").mkdir(parents=True)
    # component with no license file at all -> license stays None (honest)
    (osrc / "musl" / "src").mkdir(parents=True)
    # a build-glue open_source dir under cmake/ must be ignored
    (root / "src" / "build" / "cmake" / "open_source").mkdir(parents=True)
    (root / "src" / "build" / "cmake" / "open_source" / "foo.cmake").write_text("# glue")
    # a second vendored root: third_party
    (root / "third_party" / "cjson").mkdir(parents=True)


def test_discover_synthetic(tmp_path):
    _make_tree(tmp_path)
    recs = {r.name: r for r in _discover(tmp_path)}

    assert set(recs) == {"mbedtls", "stb", "t_cose", "musl", "cjson"}
    # version + license from the real tree
    assert recs["mbedtls"].version == "3.6.5"
    assert recs["mbedtls"].license == "Apache-2.0"
    assert recs["stb"].license == "MIT"
    # ownership guard: t_cose did NOT inherit QCBOR's 1.2
    assert recs["t_cose"].version is None
    # no embedded license -> None (curated map / NOASSERTION take over downstream)
    assert recs["musl"].license is None
    # build-glue cmake/open_source contributed nothing
    assert "foo" not in recs


def test_package_metadata_and_curated_records(tmp_path):
    _make_tree(tmp_path)
    prof = HisparkProfile()

    class _Auth:
        revision = "deadbeef"
        ref = None

    obs = prof.package_metadata(tmp_path, _Auth())
    assert obs, "expected vendored-component observations"
    assert all(o.usage_scope is UsageScope.RUNTIME for o in obs)
    assert all(o.source_kind is not SourceKind.CMAKE_LINK_LIBRARY for o in obs)
    # the naming convention: every observation carries its canonical name so the
    # core materializes a component (and never drops it as unattached).
    assert all(o.ecosystem_data.get("name") for o in obs)

    records = {r.name: r for r in prof.curated_records(tmp_path)}
    assert records["mbedtls"].license == "Apache-2.0"
    assert records["mbedtls"].version == "3.6.5"


# ---------------------------------------------------------------------------
# Data files + policy hooks
# ---------------------------------------------------------------------------


def test_alias_map_covers_cmsisdsp_and_boundscheck():
    amap = HisparkProfile().alias_map()
    assert amap["CMSISDSPBasicMath"]["canonical"] == "cmsis-dsp"
    assert amap["bounds_checking_function"]["canonical"] == "libboundscheck"


def test_known_licenses_are_curated_upstream():
    from sbom_profile_hispark import _load_known_license_map

    known = _load_known_license_map()
    assert known["mbedtls"] == "Apache-2.0"
    assert known["lz4"] == "BSD-2-Clause"
    assert known["libboundscheck"] == "MulanPSL-2.0"
    # deliberately-omitted version-sensitive projects stay absent (-> honest NOASSERTION)
    assert "openssl" not in known


def test_classify_root_marks_vendored_and_sample_roots():
    prof = HisparkProfile()
    ctx = {"repo_root": Path("/repo")}

    class _S:
        role = SubjectRole.CMAKE_PROJECT

    assert (
        prof.classify_root(Path("/repo/src/open_source/CMSIS-DSP"), _S(), ctx)
        is SubjectRole.EXAMPLE
    )
    assert (
        prof.classify_root(Path("/repo/samples/native_samples/foo"), _S(), ctx)
        is SubjectRole.EXAMPLE
    )
    assert (
        prof.classify_root(Path("/repo/src/application"), _S(), ctx)
        is SubjectRole.CMAKE_PROJECT  # unchanged
    )


def test_subject_license_default_from_repo_license(tmp_path):
    (tmp_path / "LICENSE").write_text(_APACHE_HEADER)
    prof = HisparkProfile()
    prof.package_metadata(tmp_path, type("A", (), {"revision": None, "ref": None})())

    class _Subj:
        role = SubjectRole.PRIMARY

    assert prof.subject_license_default(_Subj()) == "Apache-2.0"


# ---------------------------------------------------------------------------
# Real-tree smoke test (guarded)
# ---------------------------------------------------------------------------


@requires_tree
def test_real_hs_fbb_detects_and_generates():
    assert detect_profile(HS_FBB)[0] == "hispark"

    from sbom.cli import run
    from sbom.config import Config

    doc = run(Config(repo_root=HS_FBB, scope="all", reproducible=True))
    by_name = {c.name: c for c in doc.components}

    # vendored third-party surfaced with real version + license from the tree
    assert "mbedtls" in by_name
    assert by_name["mbedtls"].source_version == "3.6.5"
    assert by_name["mbedtls"].license == "Apache-2.0"
    # CMSIS-DSP split link tokens collapsed onto one component -> no unmapped warnings
    assert "cmsis-dsp" in by_name
    assert not [w for w in doc.warnings if w.code == "unmapped_link_library"]
    # curated upstream map filled a component that ships no embedded LICENSE
    assert by_name["lz4"].license == "BSD-2-Clause"
    # vendored components are classed third-party, not left unknown
    assert by_name["mbedtls"].origin == "third-party"


@requires_tree
def test_real_hs_fbb_crosscheck_runs():
    rows = HisparkProfile().crosscheck_manifest(HS_FBB)
    assert rows
    # the cross-check agrees with the manifest on well-known components
    agree = {r["name"] for r in rows if r["agree"]}
    assert "mbedtls" in agree
