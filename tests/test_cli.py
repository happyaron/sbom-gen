"""CLI orchestration tests for :mod:`sbom.cli`.

The sibling pipeline modules (``config``, ``cmake.parse``, ``collectors.*``,
``reconcile``, ``emit.*``) are written in parallel, so these tests stub them via
``sys.modules`` injection and exercise the orchestration wiring + summary/exit
behaviour without requiring a full real run. The argparse-level ``--help`` test
is guarded so it activates once the real ``sbom.config`` module exists.
"""

from __future__ import annotations

import importlib
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sbom.collectors import CollectResult
from sbom.emit import EmitOptions
from sbom.models import (
    Component,
    Document,
    EnvironmentTool,
    Identity,
    Subject,
    SubjectKind,
    Warning,
)


# ---------------------------------------------------------------------------
# A minimal stand-in for sbom.config.Config (mirrors the frozen field list).
# ---------------------------------------------------------------------------


@dataclass
class FakeConfig:
    repo_root: Path = Path(".")
    repo_profile: str | None = None
    cmake_root: Path | None = None
    scope: str = "all"
    detail: str = "compact"
    build_profile: str = "declared-all"
    formats: list = field(default_factory=lambda: ["cyclonedx", "spdx"])
    collector_mode: str = "static"
    cmake_source_authority: str = "actual-build"
    network: str = "off"
    resolve_cmake_ref: bool = False
    allow_input_fallback: bool = False
    exclude_scopes: list = field(default_factory=list)
    subjects: list | None = None
    split_subjects: bool = False
    no_env_tools: bool = False
    guess_pypi_urls: bool = False
    scancode: str | None = None
    scancode_path: str | None = None
    profile_values: dict = field(default_factory=dict)
    cmake_defines: dict = field(default_factory=dict)
    reproducible: bool = False
    source_date_epoch: int | None = None
    out_dir: Path = Path("./out")


def _import_cli_fresh():
    """Re-import sbom.cli to bind whatever sibling stubs are in sys.modules."""
    sys.modules.pop("sbom.cli", None)
    return importlib.import_module("sbom.cli")


@pytest.fixture
def stub_pipeline(monkeypatch):
    """Install stub sibling modules so cli.run/main execute end to end.

    Returns the captured-call recorder so individual tests can assert on the
    arguments cli passed to each stage.
    """
    calls: dict[str, object] = {}

    subj = Subject(
        id="ops_math",
        identity=Identity(kind=SubjectKind.CMAKE_PROJECT, name="ops_math"),
    )
    comp = Component(name="eigen")
    tool = EnvironmentTool(name="perl")

    document = Document(
        subjects=[subj],
        components=[comp],
        environment_tools=[tool],
        warnings=[Warning(code="missing_hash", subject="eigen")],
    )

    # --- sbom.profile.get_profile -----------------------------------------
    class _Profile:
        name = "generic"

        def package_metadata(self, repo_root, authority):
            calls["package_metadata"] = (repo_root, authority)
            return []

        def build_tooling(self, repo_root, authority):
            calls["build_tooling"] = (repo_root, authority)
            return ([], [Warning(code="cann_cmake_trusted_input")])

    import sbom.profile as profile_mod

    def _get_profile(name, repo_root=None):
        calls["get_profile"] = (name, repo_root)
        return (_Profile(), [Warning(code="profile_load_failed", subject="bad")])

    monkeypatch.setattr(profile_mod, "get_profile", _get_profile)

    # --- sbom.cmake.parse.resolve_cmake_authority -------------------------
    parse_stub = types.ModuleType("sbom.cmake.parse")

    def _resolve_cmake_authority(repo_root, cmake_root, **kw):
        calls["resolve_cmake_authority"] = (repo_root, cmake_root, kw)
        return (object(), [Warning(code="cmake_authority_input_ambiguous")])

    parse_stub.resolve_cmake_authority = _resolve_cmake_authority
    monkeypatch.setitem(sys.modules, "sbom.cmake.parse", parse_stub)

    # --- collectors.subject / cpp / python --------------------------------
    subject_stub = types.ModuleType("sbom.collectors.subject")

    def _discover_subjects(config, profile):
        calls["discover_subjects"] = (config, profile)
        return ([subj], [Warning(code="excluded_scope", subject="examples")])

    subject_stub.discover_subjects = _discover_subjects

    cpp_stub = types.ModuleType("sbom.collectors.cpp")

    def _cpp_collect(config, profile, authority, subjects):
        calls["cpp.collect"] = (config, profile, authority, subjects)
        return CollectResult(components=[comp])

    cpp_stub.collect = _cpp_collect

    python_stub = types.ModuleType("sbom.collectors.python")

    def _py_collect(config, profile, subjects):
        calls["python.collect"] = (config, profile, subjects)
        return CollectResult()

    python_stub.collect = _py_collect

    monkeypatch.setitem(sys.modules, "sbom.collectors.subject", subject_stub)
    monkeypatch.setitem(sys.modules, "sbom.collectors.cpp", cpp_stub)
    monkeypatch.setitem(sys.modules, "sbom.collectors.python", python_stub)

    # Expose the submodules as attributes on the real collectors package so
    # `from .collectors import cpp, python, subject` resolves them.
    import sbom.collectors as collectors_pkg

    monkeypatch.setattr(collectors_pkg, "subject", subject_stub, raising=False)
    monkeypatch.setattr(collectors_pkg, "cpp", cpp_stub, raising=False)
    monkeypatch.setattr(collectors_pkg, "python", python_stub, raising=False)

    # --- reconcile.reconcile ----------------------------------------------
    reconcile_stub = types.ModuleType("sbom.reconcile")

    def _reconcile(results, subjects, config, profile):
        calls["reconcile"] = (results, subjects, config, profile)
        return document

    reconcile_stub.reconcile = _reconcile
    monkeypatch.setitem(sys.modules, "sbom.reconcile", reconcile_stub)

    # --- emitters + validate ----------------------------------------------
    cdx_stub = types.ModuleType("sbom.emit.cyclonedx")
    cdx_stub.emit = lambda doc, opts: '{"bomFormat": "CycloneDX"}'
    cdx_stub.emit_split = lambda doc, opts: {
        s.id: '{"bomFormat": "CycloneDX"}' for s in doc.subjects
    }

    spdx_stub = types.ModuleType("sbom.emit.spdx")
    spdx_stub.emit = lambda doc, opts: '{"spdxVersion": "SPDX-2.3"}'
    spdx_stub.emit_split = lambda doc, opts: {
        s.id: '{"spdxVersion": "SPDX-2.3"}' for s in doc.subjects
    }

    validate_stub = types.ModuleType("sbom.emit.validate")
    validate_stub.validate_cyclonedx = lambda text: []
    validate_stub.validate_spdx = lambda text: []

    monkeypatch.setitem(sys.modules, "sbom.emit.cyclonedx", cdx_stub)
    monkeypatch.setitem(sys.modules, "sbom.emit.spdx", spdx_stub)
    monkeypatch.setitem(sys.modules, "sbom.emit.validate", validate_stub)

    # --- sbom.config.parse_args -------------------------------------------
    config_stub = types.ModuleType("sbom.config")
    config_stub.Config = FakeConfig
    config_stub._next = FakeConfig()

    def _parse_args(argv=None):
        calls["parse_args"] = argv
        return config_stub._next

    config_stub.parse_args = _parse_args
    monkeypatch.setitem(sys.modules, "sbom.config", config_stub)

    calls["__document__"] = document
    calls["__validate__"] = validate_stub
    calls["__config_mod__"] = config_stub
    calls["__cdx__"] = cdx_stub
    calls["__spdx__"] = spdx_stub
    return calls


def test_cli_imports_standalone():
    """sbom.cli imports with only sbom.models present (no sibling stubs)."""
    sys.modules.pop("sbom.cli", None)
    mod = importlib.import_module("sbom.cli")
    assert hasattr(mod, "main")
    assert hasattr(mod, "run")


def test_run_calls_pipeline_in_order(stub_pipeline):
    cli = _import_cli_fresh()
    doc = cli.run(FakeConfig(repo_profile="cann", cmake_root=Path("/cmake")))

    # Every stage ran. NOTE: package_metadata/build_tooling are invoked INSIDE
    # cpp.collect (with root attribution + edges), not at the cli level, so they are
    # not separately orchestrated here (cpp.collect is stubbed in this test).
    for stage in (
        "resolve_cmake_authority",
        "discover_subjects",
        "cpp.collect",
        "python.collect",
        "reconcile",
    ):
        assert stage in stub_pipeline, f"{stage} not invoked"

    # cpp.collect received the discovered subjects + the resolved authority.
    _, _, authority, subjects = stub_pipeline["cpp.collect"]
    assert [s.id for s in subjects] == ["ops_math"]
    assert authority is stub_pipeline["reconcile"][3] or authority is not None

    # Pre-reconcile warnings (profile/authority/subject) folded into the doc.
    codes = {w.code for w in doc.warnings}
    assert "profile_load_failed" in codes
    assert "cmake_authority_input_ambiguous" in codes
    assert "excluded_scope" in codes


def test_run_warns_when_collector_mode_unimplemented(stub_pipeline):
    cli = _import_cli_fresh()
    # configured/both are accepted but not implemented; the run must WARN (and still
    # run static) rather than silently under-report build-configured deps. (The
    # static default emitting NO such warning is covered by every other run test,
    # e.g. test_run_calls_pipeline_in_order.)
    doc = cli.run(FakeConfig(collector_mode="configured"))
    assert "collector_mode_unimplemented" in {w.code for w in doc.warnings}


def test_run_passes_two_results_to_reconcile(stub_pipeline):
    cli = _import_cli_fresh()
    cli.run(FakeConfig())
    results = stub_pipeline["reconcile"][0]
    # cpp + python only; the profile hooks now run INSIDE cpp.collect (no separate
    # cli-level hook bundle, which used to duplicate every package_metadata obs).
    assert len(results) == 2
    assert all(isinstance(r, CollectResult) for r in results)


def test_main_writes_outputs_and_returns_ok(stub_pipeline, tmp_path):
    cfg = FakeConfig(out_dir=tmp_path, formats=["cyclonedx", "spdx"])
    stub_pipeline["__config_mod__"]._next = cfg

    cli = _import_cli_fresh()
    rc = cli.main([])
    assert rc == cli.EXIT_OK

    assert (tmp_path / "sbom.cdx.json").is_file()
    assert (tmp_path / "sbom.spdx.json").is_file()


def test_main_split_subjects_writes_per_subject(stub_pipeline, tmp_path):
    cfg = FakeConfig(out_dir=tmp_path, formats=["cyclonedx"], split_subjects=True)
    stub_pipeline["__config_mod__"]._next = cfg

    cli = _import_cli_fresh()
    rc = cli.main([])
    assert rc == cli.EXIT_OK
    assert (tmp_path / "ops_math.cdx.json").is_file()


def test_main_emit_options_carry_config_flags(stub_pipeline, tmp_path):
    captured = {}

    def _capture_emit(doc, opts):
        captured["opts"] = opts
        return "{}"

    stub_pipeline["__cdx__"].emit = _capture_emit

    cfg = FakeConfig(
        out_dir=tmp_path,
        formats=["cyclonedx"],
        reproducible=True,
        source_date_epoch=1700000000,
        subjects=["ops_math"],
        guess_pypi_urls=True,
        detail="full",
    )
    stub_pipeline["__config_mod__"]._next = cfg

    cli = _import_cli_fresh()
    cli.main([])

    opts = captured["opts"]
    assert isinstance(opts, EmitOptions)
    assert opts.reproducible is True
    assert opts.source_date_epoch == 1700000000
    assert opts.subjects == ["ops_math"]
    assert opts.guess_pypi_urls is True
    assert opts.detail == "full"


def test_main_validation_failure_sets_nonzero_exit(stub_pipeline, tmp_path):
    stub_pipeline["__validate__"].validate_cyclonedx = lambda text: [
        Warning(code="cyclonedx_invalid", detail="boom")
    ]
    cfg = FakeConfig(out_dir=tmp_path, formats=["cyclonedx"])
    stub_pipeline["__config_mod__"]._next = cfg

    cli = _import_cli_fresh()
    rc = cli.main([])
    assert rc == cli.EXIT_VALIDATION_FAILED


def test_main_fatal_pipeline_error_returns_fatal(stub_pipeline, tmp_path, monkeypatch):
    cfg = FakeConfig(out_dir=tmp_path)
    stub_pipeline["__config_mod__"]._next = cfg

    cli = _import_cli_fresh()

    def _boom(config):
        raise RuntimeError("collector exploded")

    monkeypatch.setattr(cli, "run", _boom)
    rc = cli.main([])
    assert rc == cli.EXIT_FATAL


def test_main_unknown_format_warns_not_crashes(stub_pipeline, tmp_path):
    cfg = FakeConfig(out_dir=tmp_path, formats=["bogus"])
    stub_pipeline["__config_mod__"]._next = cfg

    cli = _import_cli_fresh()
    rc = cli.main([])
    # unknown_format is recorded as a validation-style warning -> nonzero.
    assert rc == cli.EXIT_VALIDATION_FAILED
    # Nothing written for an unknown format.
    assert not list(tmp_path.glob("*.json"))


def test_main_parse_args_receives_argv(stub_pipeline, tmp_path):
    stub_pipeline["__config_mod__"]._next = FakeConfig(out_dir=tmp_path)
    cli = _import_cli_fresh()
    cli.main(["--repo-root", "./x"])
    assert stub_pipeline["parse_args"] == ["--repo-root", "./x"]


# ---------------------------------------------------------------------------
# argparse-level behaviour against the REAL config module, once it exists.
# ---------------------------------------------------------------------------


def _real_config_available() -> bool:
    sys.modules.pop("sbom.config", None)
    try:
        mod = importlib.import_module("sbom.config")
    except Exception:
        return False
    return hasattr(mod, "parse_args")


@pytest.mark.skipif(
    not _real_config_available(),
    reason="sbom.config (parse_args) not yet implemented",
)
def test_help_exits_zero():
    sys.modules.pop("sbom.config", None)
    sys.modules.pop("sbom.cli", None)
    cli = importlib.import_module("sbom.cli")
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0


# ---------------------------------------------------------------------------
# Config-driven filters flow through cli.run into the REAL reconcile transform
# (the summary the CLI prints must reflect the post-filter Document).
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_collectors_real_reconcile(monkeypatch):
    """Stub the collectors/authority/profile but keep the REAL reconcile.

    This lets a test feed concrete records into ``cli.run`` and observe the
    config-driven Document transform (usage-scope exclusion, --subjects closure,
    --no-env-tools) running at reconcile's tail.
    """
    from sbom.models import (
        DependencyEdge,
        Identity,
        Ref,
        RefKind,
        RelationType,
        SubjectRole,
        UsageScope,
    )

    gtest = Component(name="gtest", scopes=[UsageScope.TEST])
    from sbom.models import Observation, SourceKind

    gtest.observations.append(
        Observation(
            source_kind=SourceKind.CMAKE_LINK_LIBRARY,
            usage_scope=UsageScope.TEST,
            ecosystem_data={"name": "gtest"},
        )
    )
    eigen = Component(name="eigen", scopes=[UsageScope.RUNTIME])
    eigen.observations.append(
        Observation(
            source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
            usage_scope=UsageScope.RUNTIME,
            ecosystem_data={"name": "eigen"},
        )
    )

    subj = Subject(
        id="ops_math",
        identity=Identity(kind=SubjectKind.CMAKE_PROJECT, name="ops_math"),
        role=SubjectRole.PRIMARY,
    )
    edge_eigen = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ops_math"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="eigen"),
        relation_type=RelationType.DEPENDS_ON,
        usage_scope=UsageScope.RUNTIME,
    )
    edge_gtest = DependencyEdge(
        root_artifact_id="ops_math",
        from_ref=Ref(kind=RefKind.SUBJECT, id="ops_math"),
        to_ref=Ref(kind=RefKind.COMPONENT, id="gtest"),
        relation_type=RelationType.LINK,
        usage_scope=UsageScope.TEST,
    )
    tool = EnvironmentTool(name="perl", root_artifact_id="ops_math")

    class _Profile:
        name = "generic"

        def alias_map(self):
            return {}

        def dependency_license_default(self, component):
            return None

        def package_metadata(self, repo_root, authority):
            return []

        def build_tooling(self, repo_root, authority):
            return ([], [])

    import sbom.profile as profile_mod

    monkeypatch.setattr(
        profile_mod, "get_profile", lambda name, repo_root=None: (_Profile(), [])
    )

    parse_stub = types.ModuleType("sbom.cmake.parse")
    parse_stub.resolve_cmake_authority = lambda repo_root, cmake_root, **kw: (
        object(),
        [],
    )
    monkeypatch.setitem(sys.modules, "sbom.cmake.parse", parse_stub)

    subject_stub = types.ModuleType("sbom.collectors.subject")
    subject_stub.discover_subjects = lambda config, profile: ([subj], [])
    cpp_stub = types.ModuleType("sbom.collectors.cpp")
    cpp_stub.collect = lambda config, profile, authority, subjects: CollectResult(
        components=[gtest, eigen],
        edges=[edge_eigen, edge_gtest],
        environment_tools=[tool],
    )
    python_stub = types.ModuleType("sbom.collectors.python")
    python_stub.collect = lambda config, profile, subjects: CollectResult()

    monkeypatch.setitem(sys.modules, "sbom.collectors.subject", subject_stub)
    monkeypatch.setitem(sys.modules, "sbom.collectors.cpp", cpp_stub)
    monkeypatch.setitem(sys.modules, "sbom.collectors.python", python_stub)

    import sbom.collectors as collectors_pkg

    monkeypatch.setattr(collectors_pkg, "subject", subject_stub, raising=False)
    monkeypatch.setattr(collectors_pkg, "cpp", cpp_stub, raising=False)
    monkeypatch.setattr(collectors_pkg, "python", python_stub, raising=False)

    sys.modules.pop("sbom.reconcile", None)


def test_cli_run_applies_usage_scope_exclusion(stub_collectors_real_reconcile):
    cli = _import_cli_fresh()
    doc = cli.run(FakeConfig(exclude_scopes=["test"]))
    names = {c.name for c in doc.components}
    assert "gtest" not in names  # test-only component dropped by the transform
    assert "eigen" in names
    assert "excluded_scope" in {w.code for w in doc.warnings}


def test_cli_run_applies_no_env_tools(stub_collectors_real_reconcile):
    cli = _import_cli_fresh()
    doc = cli.run(FakeConfig(no_env_tools=True))
    assert doc.environment_tools == []


def test_cli_summary_reflects_post_filter_document(
    stub_collectors_real_reconcile, tmp_path, capsys
):
    cli = _import_cli_fresh()
    # Real reconcile + real emitters would be heavy; assert on cli.run's doc and
    # the summary printer reading it.
    doc = cli.run(FakeConfig(exclude_scopes=["test"]))
    cli._print_summary(doc, [], doc.warnings)
    err = capsys.readouterr().err
    # gtest dropped -> one component remains in the printed summary.
    assert "components=1" in err
