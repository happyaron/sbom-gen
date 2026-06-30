"""Tests for the opt-in ScanCode license/copyright backend.

All tests are hermetic and MOCKED — they do NOT require ScanCode installed.
The parser/aggregator is exercised against recorded JSON fixtures under
``tests/fixtures/scancode/``; the enrich and crosscheck integrations run with
:class:`~sbom.enrich.scancode.ScancodeRunner` monkeypatched to return fixture
data (no subprocess). One gated LIVE test runs the real ScanCode binary and is
skipped when it is absent.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sbom.config import Config
from sbom.enrich import scancode as sc
from sbom.models import (
    Component,
    Document,
    Identity,
    Observation,
    Provenance,
    SourceKind,
    Subject,
    SubjectKind,
)

FIXTURES = Path(__file__).parent / "fixtures" / "scancode"
LIVE_SCANCODE = Path("/home/aron/testing/cann/.scancode-venv/bin/scancode")


def _load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _config(**kw) -> Config:
    base = dict(repo_root=Path("."))
    base.update(kw)
    return Config(**base)


# ===========================================================================
# Aggregator / parser (against recorded fixtures)
# ===========================================================================


class TestAggregate:
    def test_clean_apache(self):
        r = sc.aggregate(_load("apache_clean"))
        assert r.spdx_license_expression == "Apache-2.0"
        assert r.score == pytest.approx(92.78)
        assert "apache-2.0_58.RULE" in r.detection_rules

    def test_clean_apache_copyright_and_holder(self):
        r = sc.aggregate(_load("apache_clean"))
        assert r.holders == ["The Example Authors"]
        assert r.copyrights == ["Copyright 2014 The Example Authors"]
        # holders preferred for the single-string summary
        assert r.copyright_summary() == "The Example Authors"

    def test_unknown_reference_is_noassertion(self):
        r = sc.aggregate(_load("unknown_reference"))
        assert r.spdx_license_expression is None

    def test_low_score_is_noassertion(self):
        r = sc.aggregate(_load("low_score"))
        # The detection is BSD-3-Clause but its score (41.5) is below threshold.
        assert r.spdx_license_expression is None
        assert r.score == pytest.approx(41.5)

    def test_low_score_passes_with_lowered_threshold(self):
        r = sc.aggregate(_load("low_score"), threshold=40.0)
        assert r.spdx_license_expression == "BSD-3-Clause"

    def test_copyrights_holders_unioned(self):
        r = sc.aggregate(_load("copyrights_holders"))
        assert r.spdx_license_expression == "MIT"
        assert r.holders == ["Alice Example", "Bob Example"]
        assert r.copyrights == [
            "Copyright (c) 2020 Alice Example",
            "Copyright (c) 2021 Bob Example",
        ]
        assert r.copyright_summary() == "Alice Example; Bob Example"

    def test_prefers_license_file_over_source_header(self):
        # copyrights_holders has BOTH a LICENSE (score 100) and src.c (score 80);
        # the LICENSE file detection wins.
        r = sc.aggregate(_load("copyrights_holders"))
        assert r.spdx_license_expression == "MIT"
        assert r.score == pytest.approx(100.0)

    def test_empty_document(self):
        r = sc.aggregate({"files": []})
        assert r.spdx_license_expression is None
        assert r.copyrights == []
        assert r.holders == []


class TestLicenseRefMapping:
    def test_licenseref_scancode_mapped_to_synthesized_ref(self):
        r = sc.aggregate(_load("licenseref_scancode"))
        # A non-SPDX LicenseRef-scancode-* is mapped through licenseref.synthesize.
        assert r.spdx_license_expression == "LicenseRef-proprietary-license"
        assert r.license_text is not None
        assert "scancode" in r.license_text  # raw token preserved as the text

    def test_licenseref_scancode_carries_copyright(self):
        r = sc.aggregate(_load("licenseref_scancode"))
        assert r.holders == ["Acme Corp"]


# ===========================================================================
# Runner binary resolution
# ===========================================================================


class TestRunnerResolution:
    def test_explicit_missing_path_unavailable(self, tmp_path):
        runner = sc.ScancodeRunner(str(tmp_path / "nope" / "scancode"))
        assert not runner.available()
        assert runner.binary is None

    def test_explicit_existing_path_available(self, tmp_path):
        fake = tmp_path / "scancode"
        fake.write_text("#!/bin/sh\n")
        fake.chmod(0o755)  # a usable binary must be executable
        runner = sc.ScancodeRunner(str(fake))
        assert runner.available()
        assert runner.binary == str(fake)

    def test_explicit_non_executable_is_unavailable(self, tmp_path):
        f = tmp_path / "scancode"
        f.write_text("not executable\n")  # exists but no +x
        runner = sc.ScancodeRunner(str(f))
        assert not runner.available()
        assert "not an executable file" in runner.unavailable_detail

    def test_env_var_and_venv_bin_discovery(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sc.shutil, "which", lambda name: None)
        exe = tmp_path / "scancode"
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
        monkeypatch.setenv("SCANCODE_PATH", str(exe))
        assert sc.ScancodeRunner(None).binary == str(exe)
        # $SCANCODE_PATH wins; clear it and the venv-bin fallback is searched
        monkeypatch.delenv("SCANCODE_PATH")
        monkeypatch.setattr(sc.sys, "executable", str(tmp_path / "python"))
        assert sc.ScancodeRunner(None).binary == str(exe)  # tmp_path/scancode == venv bin

    def test_path_fallback(self, monkeypatch):
        monkeypatch.setattr(sc.shutil, "which", lambda name: "/usr/bin/scancode")
        runner = sc.ScancodeRunner(None)
        assert runner.available()
        assert runner.binary == "/usr/bin/scancode"

    def test_no_binary_anywhere(self, monkeypatch):
        monkeypatch.setattr(sc.shutil, "which", lambda name: None)
        runner = sc.ScancodeRunner(None)
        assert not runner.available()

    def test_scan_paths_noop_when_unavailable(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sc.shutil, "which", lambda name: None)
        runner = sc.ScancodeRunner(None)
        assert runner.scan_paths([tmp_path]) == {}


# ===========================================================================
# target_dir_for
# ===========================================================================


class TestTargetDirFor:
    def test_subject_source_path(self, tmp_path):
        subj = Subject(
            id="s1",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pkg"),
            source_path=str(tmp_path),
        )
        assert sc.target_dir_for(subj) == tmp_path

    def test_relative_dotdot_source_path_is_confined(self, tmp_path):
        # A relative '../secret' must NOT escape repo_root (no scanning outside it).
        repo = tmp_path / "repo"
        (repo / "sub").mkdir(parents=True)
        (tmp_path / "secret").mkdir()
        escape = Subject(id="x", identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="x"),
                         source_path="../secret")
        assert sc.target_dir_for(escape, repo) is None
        # an in-tree relative path is still returned
        intree = Subject(id="y", identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="y"),
                         source_path="sub")
        assert sc.target_dir_for(intree, repo) == repo / "sub"

    def test_subject_missing_source_path(self):
        subj = Subject(
            id="s1",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pkg"),
            source_path=None,
        )
        assert sc.target_dir_for(subj) is None

    def test_subject_nonexistent_source_path(self):
        subj = Subject(
            id="s1",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pkg"),
            source_path="/no/such/path/xyz",
        )
        assert sc.target_dir_for(subj) is None

    def test_component_local_dir_observation(self, tmp_path):
        comp = Component(name="eigen")
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(tmp_path),
            )
        )
        assert sc.target_dir_for(comp) == tmp_path

    def test_component_url_not_local_dir(self):
        comp = Component(name="eigen")
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path="https://example.com/eigen.tar.gz",
            )
        )
        assert sc.target_dir_for(comp) is None

    def test_component_no_observations(self):
        comp = Component(name="eigen")
        assert sc.target_dir_for(comp) is None

    def test_subject_relative_source_path_resolved_against_repo_root(self, tmp_path):
        # A subject's source_path is REPO-RELATIVE; target_dir_for must join it
        # onto repo_root (mirrors collectors/python.py + cpp.py) so the scan hits
        # the real source tree, NOT the process CWD.
        repo = tmp_path / "repo"
        sub = repo / "examples" / "pyasc"
        sub.mkdir(parents=True)
        subj = Subject(
            id="s1",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pyasc"),
            source_path="examples/pyasc",
        )
        assert sc.target_dir_for(subj, repo) == sub
        # Without repo_root the bare relative path does not exist -> None.
        assert sc.target_dir_for(subj) is None

    def test_subject_empty_source_path_is_repo_root(self, tmp_path):
        # The primary subject carries source_path="" meaning the repo root itself.
        subj = Subject(
            id="primary",
            identity=Identity(kind=SubjectKind.CANN_PACKAGE, name="ops_math"),
            source_path="",
        )
        assert sc.target_dir_for(subj, tmp_path) == tmp_path

    def test_component_relative_observation_resolved_against_repo_root(self, tmp_path):
        repo = tmp_path / "repo"
        dep = repo / "third_party" / "eigen"
        dep.mkdir(parents=True)
        comp = Component(name="eigen")
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path="third_party/eigen",
            )
        )
        assert sc.target_dir_for(comp, repo) == dep


# ===========================================================================
# Scan-surface scoping
# ===========================================================================


class TestScanSurface:
    def test_single_file(self, tmp_path):
        f = tmp_path / "LICENSE"
        f.write_text("MIT")
        assert sc._scan_surface(f) == [f]

    def test_directory_picks_license_and_top_level(self, tmp_path):
        (tmp_path / "LICENSE").write_text("MIT")
        (tmp_path / "COPYING").write_text("GPL")
        (tmp_path / "main.c").write_text("int main(){}")
        sub = tmp_path / "deep"
        sub.mkdir()
        (sub / "nested.c").write_text("x")  # must NOT be included (no recursion)
        surface = sc._scan_surface(tmp_path)
        names = {p.name for p in surface}
        assert "LICENSE" in names
        assert "COPYING" in names
        assert "main.c" in names
        assert "nested.c" not in names

    def test_nonexistent(self, tmp_path):
        assert sc._scan_surface(tmp_path / "nope") == []


# ===========================================================================
# Runner invocation shape: ONE input path per scancode call
# ===========================================================================


class TestRunnerInvocation:
    """ScanCode 32.5.0 rejects multiple ABSOLUTE inputs in one call; the runner
    must invoke scancode with a SINGLE input path per call and merge results."""

    def _fake_run_factory(self, calls):
        def _fake_run(cmd, capture_output, timeout, check):
            # The output path follows --json-pp; write a per-input JSON doc.
            out = Path(cmd[cmd.index("--json-pp") + 1])
            # The input path is the LAST arg (exactly one per call).
            inputs = cmd[cmd.index("--json-pp") + 2 :]
            calls.append(inputs)
            name = Path(inputs[0]).name
            out.write_text(
                json.dumps(
                    {
                        "files": [
                            {
                                "path": inputs[0],
                                "type": "file",
                                "license_detections": [
                                    {
                                        "license_expression": "mit",
                                        "license_expression_spdx": "MIT",
                                        "matches": [
                                            {"score": 99.0, "rule_identifier": f"{name}.RULE"}
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                )
            )

            class _R:
                returncode = 0

            return _R()

        return _fake_run

    def test_each_target_is_its_own_single_input_call(self, tmp_path, monkeypatch):
        (tmp_path / "LICENSE").write_text("MIT")
        (tmp_path / "main.c").write_text("int main(){}")
        fake = tmp_path / "scancode"
        fake.write_text("#!/bin/sh\n")
        fake.chmod(0o755)
        runner = sc.ScancodeRunner(str(fake))

        calls: list[list[str]] = []
        monkeypatch.setattr(sc.subprocess, "run", self._fake_run_factory(calls))

        results = runner.scan_paths([tmp_path])
        # One invocation per target file in the bounded surface, each with a
        # SINGLE input path (never multiple absolute inputs in one call).
        assert len(calls) >= 2
        assert all(len(inputs) == 1 for inputs in calls)
        # All surface files were merged into one aggregated result.
        assert results[tmp_path].spdx_license_expression == "MIT"

    def test_partial_failure_still_aggregates(self, tmp_path, monkeypatch):
        (tmp_path / "LICENSE").write_text("MIT")
        (tmp_path / "main.c").write_text("x")
        fake = tmp_path / "scancode"
        fake.write_text("#!/bin/sh\n")
        fake.chmod(0o755)
        runner = sc.ScancodeRunner(str(fake))

        import subprocess as _sp

        def _fake_run(cmd, capture_output, timeout, check):
            out = Path(cmd[cmd.index("--json-pp") + 1])
            inputs = cmd[cmd.index("--json-pp") + 2 :]
            # The .c input fails (non-zero exit); the LICENSE succeeds.
            if inputs[0].endswith("main.c"):
                raise _sp.CalledProcessError(1, cmd)
            out.write_text(
                json.dumps(
                    {
                        "files": [
                            {
                                "path": inputs[0],
                                "type": "file",
                                "license_detections": [
                                    {
                                        "license_expression": "mit",
                                        "license_expression_spdx": "MIT",
                                        "matches": [{"score": 99.0}],
                                    }
                                ],
                            }
                        ]
                    }
                )
            )

            class _R:
                returncode = 0

            return _R()

        monkeypatch.setattr(sc.subprocess, "run", _fake_run)
        results = runner.scan_paths([tmp_path])
        # The successful LICENSE scan is not dropped by the failed sibling.
        assert results[tmp_path].spdx_license_expression == "MIT"


# ===========================================================================
# A fake runner used by the enrich/crosscheck integration tests
# ===========================================================================


class _FakeRunner:
    """A drop-in ScancodeRunner that returns canned ScanResults by path."""

    def __init__(self, results: dict[Path, sc.ScanResult], available: bool = True):
        self._results = results
        self._available = available
        self.scanned: list[Path] = []

    def available(self) -> bool:
        return self._available

    @property
    def unavailable_detail(self) -> str:
        return "ScanCode not found (test stub)"

    def scan_paths(self, paths, *, timeout=None):
        self.scanned.extend(paths)
        return {p: self._results[p] for p in paths if p in self._results}


def _install_fake_runner(monkeypatch, results, available=True):
    fake = _FakeRunner(results, available=available)
    monkeypatch.setattr(sc, "ScancodeRunner", lambda path=None: fake)
    return fake


# ===========================================================================
# ENRICH mode (mode a) — component + subject license/copyright override
# ===========================================================================


class TestEnrichComponents:
    def test_confident_detection_overrides_license(self, tmp_path, monkeypatch):
        from sbom import reconcile

        dep = tmp_path / "eigen"
        dep.mkdir()
        comp = Component(name="eigen")
        comp.license = "MPL-2.0 AND BSD-3-Clause"  # prior from known map
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        result = sc.ScanResult(
            spdx_license_expression="Apache-2.0",
            score=95.0,
            holders=["The Eigen Authors"],
        )
        _install_fake_runner(monkeypatch, {dep: result})

        config = _config(scancode="enrich")
        warnings = reconcile._run_scancode_enrich([comp], config)

        assert comp.license == "Apache-2.0"
        assert comp.copyright == "The Eigen Authors"
        assert any(p.field == "license" and p.source == "scancode" for p in comp.provenance)
        # The displaced prior value is stashed for crosscheck/both.
        assert any(
            p.field == "license_prior" and p.source == "MPL-2.0 AND BSD-3-Clause"
            for p in comp.provenance
        )
        assert warnings == []

    def test_no_confident_detection_keeps_prior(self, tmp_path, monkeypatch):
        from sbom import reconcile

        dep = tmp_path / "lib"
        dep.mkdir()
        comp = Component(name="lib")
        comp.license = "BSD-3-Clause"
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        result = sc.ScanResult(spdx_license_expression=None, score=30.0)
        _install_fake_runner(monkeypatch, {dep: result})

        config = _config(scancode="enrich")
        reconcile._run_scancode_enrich([comp], config)
        assert comp.license == "BSD-3-Clause"
        assert not any(p.source == "scancode" for p in comp.provenance)

    def test_no_local_source_skipped(self, monkeypatch):
        from sbom import reconcile

        comp = Component(name="numpy")  # no local dir
        comp.license = "BSD-3-Clause"
        _install_fake_runner(monkeypatch, {})
        config = _config(scancode="enrich")
        warnings = reconcile._run_scancode_enrich([comp], config)
        assert comp.license == "BSD-3-Clause"
        assert warnings == []

    def test_source_overrides_used_over_observation(self, tmp_path, monkeypatch):
        # The --deps-dir source_map (component.name -> materialized dir) takes
        # precedence over target_dir_for's observation path.
        from sbom import reconcile

        deps_src = tmp_path / "materialized"
        deps_src.mkdir()
        obs_dir = tmp_path / "obs"
        obs_dir.mkdir()
        comp = Component(name="eigen")
        comp.observations.append(
            Observation(source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT, resolved_url_or_path=str(obs_dir))
        )
        result = sc.ScanResult(spdx_license_expression="MPL-2.0", score=95.0, holders=["Eigen"])
        fake = _install_fake_runner(monkeypatch, {deps_src: result})

        config = _config(scancode="enrich")
        reconcile._run_scancode_enrich([comp], config, source_overrides={"eigen": deps_src})
        # It scanned the deps-dir override, NOT the observation dir.
        assert deps_src in fake.scanned and obs_dir not in fake.scanned
        assert comp.license == "MPL-2.0"

    def test_fallback_is_fill_only_no_override_no_prior(self, tmp_path, monkeypatch):
        # fill_only=True must NOT override an existing license and must NOT stash a
        # license_prior (that is enrich/both semantics only).
        from sbom import reconcile

        dep = tmp_path / "lib"
        dep.mkdir()
        comp = Component(name="lib")
        comp.license = "BSD-3-Clause"  # already resolved by a higher layer
        result = sc.ScanResult(spdx_license_expression="Apache-2.0", score=99.0, holders=["X"])
        _install_fake_runner(monkeypatch, {dep: result})

        config = _config(scancode="fallback")
        reconcile._run_scancode_enrich([comp], config, source_overrides={"lib": dep}, fill_only=True)
        assert comp.license == "BSD-3-Clause"  # NOT overridden
        assert not any(p.field == "license_prior" for p in comp.provenance)
        assert comp.copyright == "X"  # copyright still filled when empty

    def test_fallback_fills_unset_license(self, tmp_path, monkeypatch):
        from sbom import reconcile

        dep = tmp_path / "lib"
        dep.mkdir()
        comp = Component(name="lib")  # license None
        result = sc.ScanResult(spdx_license_expression="MIT", score=99.0)
        _install_fake_runner(monkeypatch, {dep: result})

        config = _config(scancode="fallback")
        reconcile._run_scancode_enrich([comp], config, source_overrides={"lib": dep}, fill_only=True)
        assert comp.license == "MIT"
        assert any(p.field == "license" and p.source == "scancode" for p in comp.provenance)

    def test_copyright_applied_without_confident_license(self, tmp_path, monkeypatch):
        # A scan that finds a COPYRIGHT but NO confident license (NOASSERTION)
        # must still set .copyright (independent of license detection) — e.g.
        # pyasc: Huawei copyright, license unknown.
        from sbom import reconcile

        dep = tmp_path / "pyasc"
        dep.mkdir()
        comp = Component(name="pyasc")  # license None, NOASSERTION not yet applied
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        result = sc.ScanResult(
            spdx_license_expression=None,  # no confident license
            score=0.0,
            holders=["Huawei Technologies Co., Ltd."],
        )
        _install_fake_runner(monkeypatch, {dep: result})

        config = _config(scancode="enrich")
        reconcile._run_scancode_enrich([comp], config)

        # Copyright was applied; license stays unset (no false license).
        assert comp.copyright == "Huawei Technologies Co., Ltd."
        assert comp.license is None
        assert any(
            p.field == "copyright" and p.source == "scancode" for p in comp.provenance
        )
        # No license provenance was recorded (no confident detection).
        assert not any(
            p.field == "license" and p.source == "scancode" for p in comp.provenance
        )

    def test_prior_none_stashed_as_noassertion(self, tmp_path, monkeypatch):
        from sbom import reconcile

        dep = tmp_path / "lib"
        dep.mkdir()
        comp = Component(name="lib")  # license None
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        result = sc.ScanResult(spdx_license_expression="MIT", score=99.0)
        _install_fake_runner(monkeypatch, {dep: result})
        config = _config(scancode="enrich")
        reconcile._run_scancode_enrich([comp], config)
        assert comp.license == "MIT"
        assert any(
            p.field == "license_prior" and p.source == "NOASSERTION"
            for p in comp.provenance
        )

    def test_scan_failure_warns(self, tmp_path, monkeypatch):
        from sbom import reconcile

        dep = tmp_path / "lib"
        dep.mkdir()
        comp = Component(name="lib")
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        _install_fake_runner(monkeypatch, {})  # dep not in results -> failure
        config = _config(scancode="enrich")
        warnings = reconcile._run_scancode_enrich([comp], config)
        assert any(w.code == "scancode_scan_failed" and w.subject == "lib" for w in warnings)


class TestEnrichSubjects:
    def test_subject_license_overridden(self, tmp_path, monkeypatch):
        from sbom import reconcile

        subj = Subject(
            id="pkg",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pkg"),
            source_path=str(tmp_path),
            license="LicenseRef-curated",
        )
        result = sc.ScanResult(spdx_license_expression="Apache-2.0", score=95.0)
        _install_fake_runner(monkeypatch, {tmp_path: result})
        config = _config(scancode="enrich")
        warnings = reconcile._run_scancode_enrich_subjects([subj], config)
        assert subj.license == "Apache-2.0"
        assert getattr(subj, "__scancode_prior_license__") == "LicenseRef-curated"
        assert warnings == []

    def test_subject_licenseref_sets_text(self, tmp_path, monkeypatch):
        from sbom import reconcile

        subj = Subject(
            id="pkg",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pkg"),
            source_path=str(tmp_path),
        )
        result = sc.ScanResult(
            spdx_license_expression="LicenseRef-proprietary-license",
            score=99.0,
            license_text="proprietary license text",
        )
        _install_fake_runner(monkeypatch, {tmp_path: result})
        config = _config(scancode="enrich")
        reconcile._run_scancode_enrich_subjects([subj], config)
        assert subj.license == "LicenseRef-proprietary-license"
        assert subj.license_text == "proprietary license text"

    def test_subject_copyright_applied_without_confident_license(
        self, tmp_path, monkeypatch
    ):
        # A subject scan that finds a COPYRIGHT but NO confident license must
        # still set .copyright while leaving the license unset (pyasc subject:
        # Huawei copyright, license NOASSERTION).
        from sbom import reconcile

        subj = Subject(
            id="pyasc",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pyasc"),
            source_path=str(tmp_path),
        )
        result = sc.ScanResult(
            spdx_license_expression=None,  # no confident license
            score=0.0,
            holders=["Huawei Technologies Co., Ltd."],
        )
        _install_fake_runner(monkeypatch, {tmp_path: result})
        config = _config(scancode="enrich")
        reconcile._run_scancode_enrich_subjects([subj], config)

        assert subj.copyright == "Huawei Technologies Co., Ltd."
        assert subj.license is None  # no false license
        # No prior was stashed (scancode did not apply a license).
        assert not hasattr(subj, "__scancode_prior_license__")

    def test_subject_scan_failure_warns(self, tmp_path, monkeypatch):
        # Parity with the component enrich path: a None scan result emits a
        # scancode_scan_failed warning instead of silently swallowing it.
        from sbom import reconcile

        subj = Subject(
            id="pkg",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pyasc"),
            source_path=str(tmp_path),
            license="MIT",
        )
        _install_fake_runner(monkeypatch, {})  # tmp_path not in results -> failure
        config = _config(scancode="enrich")
        warnings = reconcile._run_scancode_enrich_subjects([subj], config)
        assert any(
            w.code == "scancode_scan_failed" and w.subject == "pyasc" for w in warnings
        )
        assert subj.license == "MIT"  # untouched on failure

    def test_subject_relative_source_path_scanned_against_repo_root(
        self, tmp_path, monkeypatch
    ):
        # The subject enrich path resolves a repo-relative source_path against
        # config.repo_root before scanning (so pyasc scans the pyasc repo).
        from sbom import reconcile

        repo = tmp_path / "repo"
        sub = repo / "pyasc"
        sub.mkdir(parents=True)
        subj = Subject(
            id="pkg",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pyasc"),
            source_path="pyasc",
        )
        result = sc.ScanResult(spdx_license_expression="Apache-2.0", score=95.0)
        fake = _install_fake_runner(monkeypatch, {sub: result})
        config = _config(scancode="enrich", repo_root=repo)
        reconcile._run_scancode_enrich_subjects([subj], config)
        assert sub in fake.scanned  # resolved path, not the bare "pyasc"
        assert subj.license == "Apache-2.0"


# ===========================================================================
# scancode_unavailable graceful path
# ===========================================================================


class TestScancodeUnavailable:
    def test_enrich_components_unavailable_warns_and_noop(self, monkeypatch):
        from sbom import reconcile

        _install_fake_runner(monkeypatch, {}, available=False)
        comp = Component(name="eigen")
        comp.license = "MIT"
        config = _config(scancode="enrich")
        warnings = reconcile._run_scancode_enrich([comp], config)
        assert comp.license == "MIT"
        assert any(w.code == "scancode_unavailable" for w in warnings)

    def test_enrich_subjects_unavailable_warns(self, tmp_path, monkeypatch):
        from sbom import reconcile

        _install_fake_runner(monkeypatch, {}, available=False)
        subj = Subject(
            id="pkg",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pkg"),
            source_path=str(tmp_path),
        )
        config = _config(scancode="enrich")
        warnings = reconcile._run_scancode_enrich_subjects([subj], config)
        assert any(w.code == "scancode_unavailable" for w in warnings)

    def test_crosscheck_unavailable_warns(self, tmp_path, monkeypatch):
        _install_fake_runner(monkeypatch, {}, available=False)
        subj = Subject(
            id="pkg",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pkg"),
            source_path=str(tmp_path),
            license="MIT",
        )
        doc = Document(subjects=[subj])
        config = _config(scancode="crosscheck")
        warnings, rows = sc.crosscheck(doc, config, tmp_path)
        assert any(w.code == "scancode_unavailable" for w in warnings)
        assert rows == []


# ===========================================================================
# CROSSCHECK mode (mode b)
# ===========================================================================


class TestCrosscheckLive:
    def test_mismatch_emits_warning_and_row(self, tmp_path, monkeypatch):
        dep = tmp_path / "eigen"
        dep.mkdir()
        comp = Component(name="eigen")
        comp.license = "MPL-2.0 AND BSD-3-Clause"
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        result = sc.ScanResult(spdx_license_expression="Apache-2.0", score=95.0)
        _install_fake_runner(monkeypatch, {dep: result})

        doc = Document(components=[comp])
        config = _config(scancode="crosscheck")
        warnings, rows = sc.crosscheck(doc, config, tmp_path)

        assert any(
            w.code == "license_crosscheck_mismatch" and w.subject == "eigen"
            for w in warnings
        )
        assert len(rows) == 1
        row = rows[0]
        assert row["name"] == "eigen"
        assert row["ours"] == "MPL-2.0 AND BSD-3-Clause"
        assert row["scancode"] == "Apache-2.0"
        assert row["agree"] is False

    def test_agreement_emits_no_warning(self, tmp_path, monkeypatch):
        dep = tmp_path / "lib"
        dep.mkdir()
        comp = Component(name="lib")
        comp.license = "Apache-2.0"
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        result = sc.ScanResult(spdx_license_expression="Apache-2.0", score=95.0)
        _install_fake_runner(monkeypatch, {dep: result})

        doc = Document(components=[comp])
        config = _config(scancode="crosscheck")
        warnings, rows = sc.crosscheck(doc, config, tmp_path)
        assert not any(w.code == "license_crosscheck_mismatch" for w in warnings)
        assert rows[0]["agree"] is True

    def test_crosscheck_does_not_change_license(self, tmp_path, monkeypatch):
        dep = tmp_path / "eigen"
        dep.mkdir()
        comp = Component(name="eigen")
        comp.license = "MPL-2.0 AND BSD-3-Clause"
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        result = sc.ScanResult(spdx_license_expression="Apache-2.0", score=95.0)
        _install_fake_runner(monkeypatch, {dep: result})
        doc = Document(components=[comp])
        config = _config(scancode="crosscheck")
        sc.crosscheck(doc, config, tmp_path)
        # standalone crosscheck must NOT mutate the license
        assert comp.license == "MPL-2.0 AND BSD-3-Clause"

    def test_subject_crosscheck(self, tmp_path, monkeypatch):
        subj = Subject(
            id="pkg",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pkg"),
            source_path=str(tmp_path),
            license="MIT",
        )
        result = sc.ScanResult(spdx_license_expression="Apache-2.0", score=95.0)
        _install_fake_runner(monkeypatch, {tmp_path: result})
        doc = Document(subjects=[subj])
        config = _config(scancode="crosscheck")
        warnings, rows = sc.crosscheck(doc, config, tmp_path)
        assert rows[0]["name"] == "pkg"
        assert rows[0]["ours"] == "MIT"
        assert rows[0]["scancode"] == "Apache-2.0"
        assert any(w.code == "license_crosscheck_mismatch" for w in warnings)


class _CuratedNoticeProfile:
    """A profile whose curated Notice declares licenses, for 3-way crosscheck."""

    name = "curated-notice"

    def curated_records(self, repo_root):
        from sbom_profile_cann import CuratedRecord

        return [
            CuratedRecord(name="eigen", license="MPL-2.0 AND BSD-3-Clause"),
            CuratedRecord(name="gtest", license="BSD-3-Clause"),
        ]


class TestCrosscheck3Way:
    def test_live_row_carries_curated_column(self, tmp_path, monkeypatch):
        # When the profile exposes a curated Notice, each row is 3-way:
        # {name, ours, scancode, curated, agree}.
        dep = tmp_path / "eigen"
        dep.mkdir()
        comp = Component(name="eigen")
        comp.license = "MPL-2.0 AND BSD-3-Clause"
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        result = sc.ScanResult(spdx_license_expression="Apache-2.0", score=95.0)
        _install_fake_runner(monkeypatch, {dep: result})

        doc = Document(components=[comp])
        config = _config(scancode="crosscheck")
        warnings, rows = sc.crosscheck(
            doc, config, tmp_path, _CuratedNoticeProfile()
        )

        row = rows[0]
        assert row["name"] == "eigen"
        assert row["ours"] == "MPL-2.0 AND BSD-3-Clause"
        assert row["scancode"] == "Apache-2.0"
        # The curated column carries the Notice's declared license.
        assert row["curated"] == "MPL-2.0 AND BSD-3-Clause"
        # agree still reflects ours-vs-scancode (unchanged warning semantics).
        assert row["agree"] is False
        assert any(w.code == "license_crosscheck_mismatch" for w in warnings)

    def test_curated_column_null_without_profile(self, tmp_path, monkeypatch):
        # No profile -> the curated column is present but null (report still 3-way
        # shape so consumers can rely on the key existing).
        dep = tmp_path / "lib"
        dep.mkdir()
        comp = Component(name="lib")
        comp.license = "Apache-2.0"
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        result = sc.ScanResult(spdx_license_expression="Apache-2.0", score=95.0)
        _install_fake_runner(monkeypatch, {dep: result})
        doc = Document(components=[comp])
        config = _config(scancode="crosscheck")
        _, rows = sc.crosscheck(doc, config, tmp_path)  # no profile
        assert rows[0]["curated"] is None

    def test_both_mode_row_carries_curated_column(self, tmp_path):
        # 'both' mode (prior-based) is also 3-way.
        comp = Component(name="gtest")
        comp.license = "BSD-3-Clause"  # applied by enrich
        comp.provenance.append(
            Provenance(field="license_prior", source="NOASSERTION")
        )
        comp.provenance.append(Provenance(field="license", source="scancode"))
        doc = Document(components=[comp])
        config = _config(scancode="both")
        _, rows = sc.crosscheck(doc, config, tmp_path, _CuratedNoticeProfile())
        assert rows[0]["name"] == "gtest"
        assert rows[0]["curated"] == "BSD-3-Clause"


class TestCrosscheckBoth:
    def test_both_uses_stashed_prior_no_rescan(self, tmp_path, monkeypatch):
        # In 'both' mode enrich already applied scancode; crosscheck reads the
        # stashed prior value and does NOT rerun the scanner.
        comp = Component(name="eigen")
        comp.license = "Apache-2.0"  # applied by enrich
        comp.provenance.append(Provenance(field="license_prior", source="MPL-2.0 AND BSD-3-Clause"))
        comp.provenance.append(Provenance(field="license", source="scancode"))

        subj = Subject(
            id="pkg",
            identity=Identity(kind=SubjectKind.PYTHON_WHEEL, name="pkg"),
            source_path=str(tmp_path),
            license="GPL-3.0-only",  # applied by enrich
        )
        setattr(subj, "__scancode_prior_license__", "LicenseRef-curated")

        # A runner that would explode if called — proves no rescan happens.
        def _boom(path=None):
            raise AssertionError("scancode must not run in 'both' crosscheck")

        monkeypatch.setattr(sc, "ScancodeRunner", _boom)

        doc = Document(subjects=[subj], components=[comp])
        config = _config(scancode="both")
        warnings, rows = sc.crosscheck(doc, config, tmp_path)

        names = {r["name"]: r for r in rows}
        assert names["eigen"]["ours"] == "MPL-2.0 AND BSD-3-Clause"
        assert names["eigen"]["scancode"] == "Apache-2.0"
        assert names["pkg"]["ours"] == "LicenseRef-curated"
        assert names["pkg"]["scancode"] == "GPL-3.0-only"
        assert len([w for w in warnings if w.code == "license_crosscheck_mismatch"]) == 2

    def test_both_skips_components_scancode_did_not_touch(self, tmp_path):
        comp = Component(name="untouched")
        comp.license = "MIT"  # from normal resolver, no scancode provenance
        doc = Document(components=[comp])
        config = _config(scancode="both")
        warnings, rows = sc.crosscheck(doc, config, tmp_path)
        assert rows == []
        assert warnings == []

    def test_both_prior_noassertion_agreement(self, tmp_path):
        comp = Component(name="lib")
        comp.license = "NOASSERTION"
        comp.provenance.append(Provenance(field="license_prior", source="NOASSERTION"))
        comp.provenance.append(Provenance(field="license", source="scancode"))
        doc = Document(components=[comp])
        config = _config(scancode="both")
        warnings, rows = sc.crosscheck(doc, config, tmp_path)
        # prior None/NOASSERTION vs applied NOASSERTION -> agree
        assert rows[0]["agree"] is True
        assert not any(w.code == "license_crosscheck_mismatch" for w in warnings)


# ===========================================================================
# CLI wiring: the crosscheck report is written; enrich writes none
# ===========================================================================


class TestCliCrosscheckReport:
    def test_report_written(self, tmp_path, monkeypatch):
        from sbom import cli

        dep = tmp_path / "eigen"
        dep.mkdir()
        comp = Component(name="eigen")
        comp.license = "MPL-2.0 AND BSD-3-Clause"
        comp.observations.append(
            Observation(
                source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
                resolved_url_or_path=str(dep),
            )
        )
        result = sc.ScanResult(spdx_license_expression="Apache-2.0", score=95.0)
        _install_fake_runner(monkeypatch, {dep: result})

        doc = Document(components=[comp])
        config = _config(scancode="crosscheck")
        cli._run_crosscheck(doc, config, tmp_path)

        report = tmp_path / sc.CROSSCHECK_REPORT_NAME
        assert report.exists()
        rows = json.loads(report.read_text())
        assert rows[0]["name"] == "eigen"
        assert any(w.code == "license_crosscheck_mismatch" for w in doc.warnings)

    def test_crosscheck_exception_is_caught(self, tmp_path, monkeypatch):
        from sbom import cli

        def _boom(document, config, out_dir):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(sc, "crosscheck", _boom)
        doc = Document()
        config = _config(scancode="crosscheck")
        cli._run_crosscheck(doc, config, tmp_path)
        assert any(w.code == "scancode_crosscheck_failed" for w in doc.warnings)


# ===========================================================================
# Config / CLI parsing
# ===========================================================================


class TestConfigParsing:
    def test_default_off(self):
        from sbom.config import parse_args

        cfg = parse_args(["--repo-root", "."])
        assert cfg.scancode is None
        assert cfg.scancode_path is None

    def test_scancode_enrich(self):
        from sbom.config import parse_args

        cfg = parse_args(["--repo-root", ".", "--scancode", "enrich"])
        assert cfg.scancode == "enrich"

    def test_scancode_both_with_path(self):
        from sbom.config import parse_args

        cfg = parse_args(
            ["--repo-root", ".", "--scancode", "both", "--scancode-path", "/x/scancode"]
        )
        assert cfg.scancode == "both"
        assert cfg.scancode_path == "/x/scancode"

    def test_invalid_mode_rejected(self):
        from sbom.config import parse_args

        with pytest.raises(SystemExit):
            parse_args(["--repo-root", ".", "--scancode", "bogus"])

    def test_config_file_scancode(self, tmp_path):
        from sbom.config import parse_args

        toml = tmp_path / "sbom.toml"
        toml.write_text('scancode = "crosscheck"\nscancode_path = "/y/scancode"\n')
        cfg = parse_args(["--repo-root", ".", "--config", str(toml)])
        assert cfg.scancode == "crosscheck"
        assert cfg.scancode_path == "/y/scancode"


# ===========================================================================
# Gated LIVE test — runs the real ScanCode binary (skipped when absent)
# ===========================================================================


@pytest.mark.skipif(
    not LIVE_SCANCODE.is_file() and shutil.which("scancode") is None,
    reason="ScanCode binary not installed",
)
def test_live_scancode_parses(tmp_path):
    """Run the REAL ScanCode on a tiny Apache-2.0 file and assert it parses."""
    binary = str(LIVE_SCANCODE) if LIVE_SCANCODE.is_file() else shutil.which("scancode")
    lic = tmp_path / "LICENSE"
    lic.write_text(
        "Apache License\n"
        "Version 2.0, January 2004\n"
        "http://www.apache.org/licenses/\n\n"
        'Licensed under the Apache License, Version 2.0 (the "License");\n'
        "you may not use this file except in compliance with the License.\n"
        "You may obtain a copy of the License at\n\n"
        "    http://www.apache.org/licenses/LICENSE-2.0\n\n"
        "Unless required by applicable law or agreed to in writing, software\n"
        'distributed under the License is distributed on an "AS IS" BASIS.\n'
        "Copyright 2014 The Example Authors\n"
    )
    runner = sc.ScancodeRunner(binary)
    assert runner.available()
    results = runner.scan_paths([tmp_path], timeout=120.0)
    assert tmp_path in results
    res = results[tmp_path]
    # The real scanner should detect Apache-2.0 with a confident score.
    assert res.spdx_license_expression == "Apache-2.0"
    assert res.score >= sc.CONFIDENCE_THRESHOLD
