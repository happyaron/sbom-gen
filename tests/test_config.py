"""Unit tests for sbom/config.py.

Covers:
- parse_args: every documented flag with representative values
- TOML merge precedence (CLI overrides file)
- resolve_exclude_scope bridge (all documented tokens + unknown)
- --resolve-cmake-ref implies --network on
- SOURCE_DATE_EPOCH honored when --reproducible
- load_config_file round-trip
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sbom.config import (
    Config,
    excluded_usage_scopes,
    load_config_file,
    parse_args,
    resolve_exclude_scope,
)
from sbom.models import SubjectRole, UsageScope


# ---------------------------------------------------------------------------
# resolve_exclude_scope — table-driven
# ---------------------------------------------------------------------------

_EXPECTED_BRIDGE: list[tuple[str, SubjectRole | None, UsageScope | None]] = [
    ("example",                SubjectRole.EXAMPLE,              UsageScope.EXAMPLE),
    ("st_test",                SubjectRole.ST_TEST,              UsageScope.ST_TEST),
    ("manual_example",         SubjectRole.MANUAL_EXAMPLE,       UsageScope.MANUAL_EXAMPLE),
    ("experimental",           SubjectRole.EXPERIMENTAL,         UsageScope.EXPERIMENTAL),
    ("non_distributable_test", SubjectRole.NON_DISTRIBUTABLE_TEST, None),
    ("test",                   None,                             UsageScope.TEST),
    ("build",                  None,                             UsageScope.BUILD),
    ("runtime",                None,                             UsageScope.RUNTIME),
]


@pytest.mark.parametrize("token,expected_role,expected_scope", _EXPECTED_BRIDGE)
def test_resolve_exclude_scope_known(token, expected_role, expected_scope):
    role, scope = resolve_exclude_scope(token)
    assert role == expected_role
    assert scope == expected_scope


def test_resolve_exclude_scope_unknown_returns_none_none():
    role, scope = resolve_exclude_scope("totally_unknown_token")
    assert role is None
    assert scope is None


# ---------------------------------------------------------------------------
# excluded_usage_scopes — the UsageScope-axis helper used by reconcile
# ---------------------------------------------------------------------------


def test_excluded_usage_scopes_from_tokens():
    scopes = excluded_usage_scopes(["test", "build"])
    assert scopes == {UsageScope.TEST, UsageScope.BUILD}


def test_excluded_usage_scopes_from_config(tmp_path):
    # scope="all" so only the explicit token bridge contributes (no preset base).
    cfg = Config(repo_root=tmp_path, scope="all", exclude_scopes=["runtime", "example"])
    scopes = excluded_usage_scopes(cfg)
    assert scopes == {UsageScope.RUNTIME, UsageScope.EXAMPLE}


def test_excluded_usage_scopes_skips_role_only_tokens():
    # non_distributable_test is a role with no usage scope -> contributes nothing.
    assert excluded_usage_scopes(["non_distributable_test"]) == set()


def test_excluded_usage_scopes_ignores_unknown_tokens():
    assert excluded_usage_scopes(["totally_unknown"]) == set()


def test_excluded_usage_scopes_empty():
    assert excluded_usage_scopes([]) == set()


# ---------------------------------------------------------------------------
# Release scope preset — the new default view vs. the full "all" view
# ---------------------------------------------------------------------------


def test_release_preset_excludes_all_non_runtime_usage_scopes(tmp_path):
    from sbom.config import release_excluded_usage_scopes

    cfg = Config(repo_root=tmp_path, scope="release")
    assert release_excluded_usage_scopes(cfg) == {
        UsageScope.TEST,
        UsageScope.BUILD,
        UsageScope.EXAMPLE,
        UsageScope.ST_TEST,
        UsageScope.MANUAL_EXAMPLE,
        UsageScope.EXPERIMENTAL,
        UsageScope.ENVIRONMENT,
    }
    # i.e. everything except RUNTIME.
    assert UsageScope.RUNTIME not in release_excluded_usage_scopes(cfg)


def test_release_preset_excludes_non_distributable_roles(tmp_path):
    from sbom.config import release_excluded_roles

    cfg = Config(repo_root=tmp_path, scope="release")
    assert release_excluded_roles(cfg) == {
        SubjectRole.EXAMPLE,
        SubjectRole.EXPERIMENTAL,
        SubjectRole.ST_TEST,
        SubjectRole.MANUAL_EXAMPLE,
        SubjectRole.NON_DISTRIBUTABLE_TEST,
    }


def test_release_preset_omits_env_tools(tmp_path):
    from sbom.config import release_no_env_tools

    assert release_no_env_tools(Config(repo_root=tmp_path, scope="release")) is True
    assert release_no_env_tools(Config(repo_root=tmp_path, scope="all")) is False


def test_release_keep_usage_scopes_runtime_only(tmp_path):
    from sbom.config import release_keep_usage_scopes

    # release -> keep-only {RUNTIME}; all -> None (no keep-only constraint).
    assert release_keep_usage_scopes(Config(repo_root=tmp_path, scope="release")) == {
        UsageScope.RUNTIME
    }
    assert release_keep_usage_scopes(Config(repo_root=tmp_path, scope="all")) is None
    # default Config is release.
    assert release_keep_usage_scopes(Config(repo_root=tmp_path)) == {UsageScope.RUNTIME}


def test_scope_all_applies_no_release_base_filters(tmp_path):
    from sbom.config import (
        release_excluded_roles,
        release_excluded_usage_scopes,
        release_keep_usage_scopes,
        release_no_env_tools,
    )

    cfg = Config(repo_root=tmp_path, scope="all")
    assert release_excluded_usage_scopes(cfg) == set()
    assert release_excluded_roles(cfg) == set()
    assert release_no_env_tools(cfg) is False
    assert release_keep_usage_scopes(cfg) is None


def test_excluded_usage_scopes_release_folds_in_preset(tmp_path):
    # Default (release) Config: excluded_usage_scopes folds in the preset base.
    cfg = Config(repo_root=tmp_path)
    assert cfg.scope == "release"
    scopes = excluded_usage_scopes(cfg)
    assert UsageScope.RUNTIME not in scopes
    assert UsageScope.TEST in scopes and UsageScope.BUILD in scopes


def test_release_preset_composes_additively_with_explicit_tokens(tmp_path):
    # release scope + explicit --exclude-scope runtime drops EVERYTHING.
    cfg = Config(repo_root=tmp_path, scope="release", exclude_scopes=["runtime"])
    assert excluded_usage_scopes(cfg) == set(UsageScope)


def test_scope_all_plus_exclude_test_still_drops_test(tmp_path):
    # --scope all applies no preset, but an explicit token still filters.
    cfg = Config(repo_root=tmp_path, scope="all", exclude_scopes=["test"])
    assert excluded_usage_scopes(cfg) == {UsageScope.TEST}


# ---------------------------------------------------------------------------
# parse_args — basic defaults
# ---------------------------------------------------------------------------

def test_parse_args_minimal_requires_repo_root(tmp_path):
    """Minimal invocation: only --repo-root is required conceptually; others default."""
    cfg = parse_args(["--repo-root", str(tmp_path)])
    assert cfg.repo_root == tmp_path
    assert cfg.repo_profile is None
    assert cfg.cmake_root is None
    assert cfg.scope == "release"
    assert cfg.build_profile == "declared-all"
    assert cfg.formats == ["cyclonedx", "spdx"]
    assert cfg.collector_mode == "static"
    assert cfg.cmake_source_authority == "actual-build"
    assert cfg.network == "off"
    assert cfg.detail == "compact"
    assert cfg.resolve_cmake_ref is False
    assert cfg.allow_input_fallback is False
    assert cfg.exclude_scopes == []
    assert cfg.subjects is None
    assert cfg.split_subjects is False
    assert cfg.no_env_tools is False
    assert cfg.guess_pypi_urls is False
    assert cfg.profile_values == {}
    assert cfg.cmake_defines == {}
    assert cfg.reproducible is False
    assert cfg.source_date_epoch is None
    assert cfg.out_dir == Path("./out")


# ---------------------------------------------------------------------------
# parse_args — individual flags
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flag,dest,expected", [
    (["--repo-profile", "cann"],        "repo_profile",          "cann"),
    (["--scope", "all"],                "scope",                 "all"),
    (["--scope", "release"],            "scope",                 "release"),
    (["--detail", "full"],              "detail",                "full"),
    (["--detail", "compact"],           "detail",                "compact"),
    (["--build-profile", "enable_test"],"build_profile",         "enable_test"),
    (["--collector-mode", "configured"],"collector_mode",        "configured"),
    (["--collector-mode", "both"],      "collector_mode",        "both"),
    (["--cmake-source-authority", "cmake-as-input"], "cmake_source_authority", "cmake-as-input"),
    (["--network", "on"],               "network",               "on"),
    (["--split-subjects"],              "split_subjects",        True),
    (["--no-env-tools"],                "no_env_tools",          True),
    (["--guess-pypi-urls"],             "guess_pypi_urls",       True),
    (["--allow-input-fallback"],        "allow_input_fallback",  True),
    (["--reproducible"],                "reproducible",          True),
])
def test_parse_args_single_flags(tmp_path, flag, dest, expected):
    cfg = parse_args(["--repo-root", str(tmp_path)] + flag)
    assert getattr(cfg, dest) == expected


def test_parse_args_cmake_root(tmp_path):
    cfg = parse_args(["--repo-root", str(tmp_path), "--cmake-root", str(tmp_path / "cmake")])
    assert cfg.cmake_root == tmp_path / "cmake"


def test_parse_args_out_dir(tmp_path):
    cfg = parse_args(["--repo-root", str(tmp_path), "--out-dir", str(tmp_path / "dist")])
    assert cfg.out_dir == tmp_path / "dist"


def test_parse_args_format_comma_separated(tmp_path):
    cfg = parse_args(["--repo-root", str(tmp_path), "--format", "cyclonedx,spdx"])
    assert cfg.formats == ["cyclonedx", "spdx"]


def test_parse_args_format_single(tmp_path):
    cfg = parse_args(["--repo-root", str(tmp_path), "--format", "cyclonedx"])
    assert cfg.formats == ["cyclonedx"]


def test_parse_args_subjects_comma_separated(tmp_path):
    cfg = parse_args(["--repo-root", str(tmp_path), "--subjects", "ops_math,npu_math_extension"])
    assert cfg.subjects == ["ops_math", "npu_math_extension"]


def test_parse_args_subjects_none_when_absent(tmp_path):
    cfg = parse_args(["--repo-root", str(tmp_path)])
    assert cfg.subjects is None


# ---------------------------------------------------------------------------
# parse_args — repeatable KEY=VALUE flags
# ---------------------------------------------------------------------------

def test_parse_args_cmake_define_single(tmp_path):
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--cmake-define", "CANN_3RD_LIB_PATH=/path/to/3rd",
    ])
    assert cfg.cmake_defines == {"CANN_3RD_LIB_PATH": "/path/to/3rd"}


def test_parse_args_cmake_define_repeated(tmp_path):
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--cmake-define", "CANN_3RD_LIB_PATH=/path/to/3rd",
        "--cmake-define", "TARGET_ARCH=aarch64",
    ])
    assert cfg.cmake_defines == {
        "CANN_3RD_LIB_PATH": "/path/to/3rd",
        "TARGET_ARCH": "aarch64",
    }


def test_parse_args_profile_value_single(tmp_path):
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--profile-value", "product_side=device",
    ])
    assert cfg.profile_values == {"product_side": "device"}


def test_parse_args_profile_value_comma_in_one_flag(tmp_path):
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--profile-value", "product_side=device,target_arch=aarch64",
    ])
    assert cfg.profile_values == {"product_side": "device", "target_arch": "aarch64"}


def test_parse_args_profile_value_repeated(tmp_path):
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--profile-value", "product_side=device",
        "--profile-value", "target_arch=aarch64",
    ])
    assert cfg.profile_values == {"product_side": "device", "target_arch": "aarch64"}


# ---------------------------------------------------------------------------
# parse_args — --exclude-scope (csv + repeatable)
# ---------------------------------------------------------------------------

def test_parse_args_exclude_scope_single(tmp_path):
    cfg = parse_args(["--repo-root", str(tmp_path), "--exclude-scope", "example"])
    assert "example" in cfg.exclude_scopes


def test_parse_args_exclude_scope_csv(tmp_path):
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--exclude-scope", "experimental,manual_example",
    ])
    assert "experimental" in cfg.exclude_scopes
    assert "manual_example" in cfg.exclude_scopes


def test_parse_args_exclude_scope_repeated(tmp_path):
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--exclude-scope", "example",
        "--exclude-scope", "st_test",
    ])
    assert "example" in cfg.exclude_scopes
    assert "st_test" in cfg.exclude_scopes


def test_parse_args_exclude_scopes_are_raw_strings(tmp_path):
    """exclude_scopes must contain raw token strings, not resolved enums."""
    cfg = parse_args(["--repo-root", str(tmp_path), "--exclude-scope", "example"])
    for item in cfg.exclude_scopes:
        assert isinstance(item, str)


# ---------------------------------------------------------------------------
# --resolve-cmake-ref implies --network on
# ---------------------------------------------------------------------------

def test_resolve_cmake_ref_implies_network_on(tmp_path):
    cfg = parse_args(["--repo-root", str(tmp_path), "--resolve-cmake-ref"])
    assert cfg.resolve_cmake_ref is True
    assert cfg.network == "on"


def test_resolve_cmake_ref_with_explicit_network_on(tmp_path):
    """Explicit --network on + --resolve-cmake-ref is fine."""
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--resolve-cmake-ref",
        "--network", "on",
    ])
    assert cfg.network == "on"
    assert cfg.resolve_cmake_ref is True


def test_network_off_without_resolve_cmake_ref(tmp_path):
    cfg = parse_args(["--repo-root", str(tmp_path), "--network", "off"])
    assert cfg.network == "off"
    assert cfg.resolve_cmake_ref is False


# ---------------------------------------------------------------------------
# SOURCE_DATE_EPOCH + --reproducible
# ---------------------------------------------------------------------------

def test_reproducible_reads_source_date_epoch(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    cfg = parse_args(["--repo-root", str(tmp_path), "--reproducible"])
    assert cfg.reproducible is True
    assert cfg.source_date_epoch == 1700000000


def test_reproducible_no_env_var(tmp_path, monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    cfg = parse_args(["--repo-root", str(tmp_path), "--reproducible"])
    assert cfg.reproducible is True
    assert cfg.source_date_epoch is None


def test_source_date_epoch_ignored_without_reproducible(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    cfg = parse_args(["--repo-root", str(tmp_path)])
    # reproducible not set → SOURCE_DATE_EPOCH not consumed
    assert cfg.reproducible is False
    assert cfg.source_date_epoch is None


# ---------------------------------------------------------------------------
# load_config_file + TOML merge precedence
# ---------------------------------------------------------------------------

def _write_toml(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content))


def test_load_config_file_basic(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        repo_root = "./ops-math"
        repo_profile = "cann"
        network = "on"

        [cmake.defines]
        CANN_3RD_LIB_PATH = "/path/to/3rd"

        [profile.values]
        product_side = "device"
    """)
    cfg_dict = load_config_file(toml)
    assert cfg_dict["repo_root"] == "./ops-math"
    assert cfg_dict["repo_profile"] == "cann"
    assert cfg_dict["network"] == "on"
    assert cfg_dict["cmake"]["defines"]["CANN_3RD_LIB_PATH"] == "/path/to/3rd"
    assert cfg_dict["profile"]["values"]["product_side"] == "device"


def test_cli_cmake_define_merges_with_file_block(tmp_path):
    # A single CLI --cmake-define overrides per-key but keeps the rest of the file
    # [cmake.defines] block (no longer discards it) — review issue #13.
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        [cmake.defines]
        A = "fromfile"
        B = "fileonly"
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path), "--config", str(toml),
        "--cmake-define", "A=fromcli",
    ])
    assert cfg.cmake_defines == {"A": "fromcli", "B": "fileonly"}


def test_malformed_cmake_define_is_clean_cli_error(tmp_path):
    # No '=' -> a clean argparse error (SystemExit/2), not a raw traceback (E12).
    with pytest.raises(SystemExit):
        parse_args(["--repo-root", str(tmp_path), "--cmake-define", "NOEQUALS"])


def test_missing_config_file_is_clean_cli_error(tmp_path):
    with pytest.raises(SystemExit):
        parse_args(["--repo-root", str(tmp_path), "--config", str(tmp_path / "nope.toml")])


def test_toml_aliases_table_loads_into_config(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        [aliases]
        "Eigen3::EigenNn" = "eigen"
        abseil_build_nn = "abseil-cpp"
    """)
    cfg = parse_args(["--repo-root", str(tmp_path), "--config", str(toml)])
    assert cfg.aliases == {"Eigen3::EigenNn": "eigen", "abseil_build_nn": "abseil-cpp"}


def test_config_aliases_default_empty(tmp_path):
    cfg = parse_args(["--repo-root", str(tmp_path)])
    assert cfg.aliases == {}


def test_toml_merge_cli_overrides_file(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        scope = "runtime"
        network = "on"
        build_profile = "from_file"
    """)
    # CLI explicitly sets scope and network; build_profile not overridden
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
        "--scope", "all",      # CLI overrides file
        # --network not on CLI → file value "on" should win
    ])
    assert cfg.scope == "all"          # CLI wins
    assert cfg.network == "on"         # file wins (CLI absent)
    assert cfg.build_profile == "from_file"  # file wins (CLI absent)


def test_toml_honors_depsdev_cache_and_refresh_data(tmp_path):
    # These two CLI-equivalent keys were previously omitted from the file merge.
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        depsdev_cache = "./my_cache.json"
        refresh_data = "depsdev"
        deps_dir = "../cann-src-third-party"
    """)
    cfg = parse_args(["--repo-root", str(tmp_path), "--config", str(toml)])
    assert cfg.depsdev_cache == "./my_cache.json"
    assert cfg.refresh_data == "depsdev"
    assert cfg.deps_dir == "../cann-src-third-party"


def test_toml_merge_cmake_defines(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        [cmake.defines]
        CANN_3RD_LIB_PATH = "/from/file"
    """)
    # CLI --cmake-define should override file cmake_defines
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
        "--cmake-define", "CANN_3RD_LIB_PATH=/from/cli",
    ])
    assert cfg.cmake_defines["CANN_3RD_LIB_PATH"] == "/from/cli"


def test_toml_merge_cmake_defines_file_only(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        [cmake.defines]
        CANN_3RD_LIB_PATH = "/from/file"
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
    ])
    assert cfg.cmake_defines["CANN_3RD_LIB_PATH"] == "/from/file"


def test_toml_merge_profile_values(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        [profile.values]
        product_side = "host"
        target_arch = "x86_64"
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
    ])
    assert cfg.profile_values == {"product_side": "host", "target_arch": "x86_64"}


def test_toml_merge_profile_values_cli_wins(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        [profile.values]
        product_side = "host"
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
        "--profile-value", "product_side=device",
    ])
    assert cfg.profile_values["product_side"] == "device"


def test_toml_merge_exclude_scopes(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        exclude_scopes = ["experimental", "st_test"]
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
    ])
    assert "experimental" in cfg.exclude_scopes
    assert "st_test" in cfg.exclude_scopes


def test_toml_merge_subjects_list(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        subjects = ["ops_math", "npu_math_extension"]
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
    ])
    assert cfg.subjects == ["ops_math", "npu_math_extension"]


def test_toml_merge_no_env_tools(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        no_env_tools = true
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
    ])
    assert cfg.no_env_tools is True


def test_toml_merge_detail(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        detail = "full"
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
    ])
    assert cfg.detail == "full"


def test_detail_cli_overrides_file(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        detail = "full"
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
        "--detail", "compact",
    ])
    assert cfg.detail == "compact"


def test_toml_merge_guess_pypi_urls(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        guess_pypi_urls = true
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
    ])
    assert cfg.guess_pypi_urls is True


def test_toml_merge_formats(tmp_path):
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        formats = ["cyclonedx"]
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
    ])
    assert cfg.formats == ["cyclonedx"]


def test_toml_merge_resolve_cmake_ref_implies_network(tmp_path):
    """If the config file sets resolve_cmake_ref = true, network must become on."""
    toml = tmp_path / "sbom.toml"
    _write_toml(toml, """\
        resolve_cmake_ref = true
    """)
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--config", str(toml),
    ])
    assert cfg.resolve_cmake_ref is True
    assert cfg.network == "on"


# ---------------------------------------------------------------------------
# Config is a proper dataclass instance
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Full CLI example from the design doc
# ---------------------------------------------------------------------------

def test_full_cli_example(tmp_path):
    """Mirror the example from SBOM_DESIGN.md §CLI."""
    cmake_dir = tmp_path / "cmake"
    cmake_dir.mkdir()
    cfg = parse_args([
        "--repo-root", str(tmp_path),
        "--repo-profile", "cann",
        "--cmake-root", str(cmake_dir),
        "--scope", "all",
        "--build-profile", "declared-all",
        "--format", "cyclonedx,spdx",
        "--collector-mode", "static",
        "--cmake-source-authority", "actual-build",
        "--network", "on",
        "--resolve-cmake-ref",
        "--allow-input-fallback",
        "--exclude-scope", "experimental,manual_example",
        "--subjects", "ops_math,npu_math_extension,ascend_ops",
        "--split-subjects",
        "--profile-value", "product_side=device,target_arch=aarch64",
        "--cmake-define", "CANN_3RD_LIB_PATH=/path/to/3rd",
        "--reproducible",
        "--out-dir", str(tmp_path / "out"),
    ])
    assert cfg.repo_profile == "cann"
    assert cfg.cmake_root == cmake_dir
    assert cfg.formats == ["cyclonedx", "spdx"]
    assert cfg.collector_mode == "static"
    assert cfg.cmake_source_authority == "actual-build"
    assert cfg.network == "on"
    assert cfg.resolve_cmake_ref is True
    assert cfg.allow_input_fallback is True
    assert set(cfg.exclude_scopes) == {"experimental", "manual_example"}
    assert set(cfg.subjects or []) == {"ops_math", "npu_math_extension", "ascend_ops"}
    assert cfg.split_subjects is True
    assert cfg.profile_values == {"product_side": "device", "target_arch": "aarch64"}
    assert cfg.cmake_defines == {"CANN_3RD_LIB_PATH": "/path/to/3rd"}
    assert cfg.reproducible is True
    assert cfg.out_dir == tmp_path / "out"
