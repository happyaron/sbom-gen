"""CLI/config parsing for the SBOM generator.

Provides the :class:`Config` dataclass (the single configuration object that
flows through the pipeline), :func:`parse_args` (argparse → Config), and
:func:`load_config_file` (tomllib → raw dict).  CLI flags always override file
values.  :func:`resolve_exclude_scope` is the single bridge from a raw
``--exclude-scope`` token to the two enum axes (:class:`~sbom.models.SubjectRole`
and :class:`~sbom.models.UsageScope`).
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import SubjectRole, UsageScope


# ---------------------------------------------------------------------------
# Config dataclass — the frozen contract from INTERFACE.md
# ---------------------------------------------------------------------------


@dataclass
class Config:
    """Single configuration object passed to every pipeline stage.

    ``exclude_scopes`` holds the RAW ``--exclude-scope`` token strings, not
    resolved enums.  The role/scope bridge is :func:`resolve_exclude_scope`,
    called by ``discover_subjects``; this keeps the dataclass serialisable and
    lets callers reason about the raw tokens without re-importing models.

    ``source_date_epoch`` is populated from the ``SOURCE_DATE_EPOCH``
    environment variable when ``reproducible=True`` and the variable is set,
    overriding any explicit value.
    """

    repo_root: Path
    repo_profile: str | None = None               # None/"auto" → detect
    cmake_root: Path | None = None
    scope: str = "release"                        # release (default) | all
    detail: str = "compact"                       # compact (default) | full
    build_profile: str = "declared-all"
    formats: list[str] = field(default_factory=lambda: ["cyclonedx", "spdx"])
    collector_mode: str = "static"                # static | configured | both
    cmake_source_authority: str = "actual-build"  # actual-build | cmake-as-input
    network: str = "off"                          # off | on
    resolve_cmake_ref: bool = False               # implies network=on
    allow_input_fallback: bool = False
    exclude_scopes: list[str] = field(default_factory=list)   # raw tokens
    subjects: list[str] | None = None             # explicit subject id filter
    split_subjects: bool = False
    no_env_tools: bool = False                    # drop EnvironmentTool records
    guess_pypi_urls: bool = False                 # construct pypi.org download URLs
    repo_url: str | None = None                   # override/declare the repo VCS origin
    scancode: str | None = None                   # None | enrich | fallback | crosscheck | both
    scancode_path: str | None = None              # explicit scancode binary path
    deps_dir: str | None = None                   # --deps-dir: on-disk dep-source search root (offline license/copyright)
    depsdev_cache: str | None = None              # override path to the depsdev cache file
    refresh_data: str | None = None               # --refresh-data SOURCE: refresh a vendored data file and exit
    profile_values: dict[str, str] = field(default_factory=dict)
    cmake_defines: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)  # [aliases] spelling->canonical
    reproducible: bool = False
    source_date_epoch: int | None = None
    out_dir: Path = field(default_factory=lambda: Path("./out"))


# ---------------------------------------------------------------------------
# resolve_exclude_scope — the one bridge from raw token to the two enum axes
# ---------------------------------------------------------------------------

# Mapping from raw token → (SubjectRole | None, UsageScope | None).
# Authoritative table from INTERFACE.md §sbom/config.py.
_EXCLUDE_SCOPE_MAP: dict[str, tuple[SubjectRole | None, UsageScope | None]] = {
    "example":                 (SubjectRole.EXAMPLE,              UsageScope.EXAMPLE),
    "st_test":                 (SubjectRole.ST_TEST,              UsageScope.ST_TEST),
    "manual_example":          (SubjectRole.MANUAL_EXAMPLE,       UsageScope.MANUAL_EXAMPLE),
    "experimental":            (SubjectRole.EXPERIMENTAL,         UsageScope.EXPERIMENTAL),
    "non_distributable_test":  (SubjectRole.NON_DISTRIBUTABLE_TEST, None),
    "test":                    (None,                             UsageScope.TEST),
    "build":                   (None,                             UsageScope.BUILD),
    "runtime":                 (None,                             UsageScope.RUNTIME),
}


def resolve_exclude_scope(
    token: str,
) -> tuple[SubjectRole | None, UsageScope | None]:
    """Map a raw ``--exclude-scope`` token to (SubjectRole|None, UsageScope|None).

    A token that matches a :class:`~sbom.models.SubjectRole` is used by
    ``discover_subjects`` to drop roots (emitting an ``excluded_scope`` warning
    per dropped root).  A token that matches a :class:`~sbom.models.UsageScope`
    filters observations.  ``non_distributable_test`` has a role but NO usage
    scope.  An unrecognised token returns ``(None, None)``; the caller is
    responsible for emitting an ``excluded_scope`` warning noting the token was
    unrecognised.
    """
    return _EXCLUDE_SCOPE_MAP.get(token, (None, None))


def excluded_usage_scopes(config_or_tokens: "Config | list[str]") -> set[UsageScope]:
    """Resolve the ``UsageScope`` axis of ``--exclude-scope`` to a concrete set.

    Accepts either a :class:`Config` (reads ``config.exclude_scopes`` AND the
    ``scope`` preset) or a raw list of tokens, and maps each token through
    :func:`resolve_exclude_scope`, collecting the non-``None``
    :class:`~sbom.models.UsageScope` half. When a :class:`Config` is given, the
    ``release`` preset's usage-scope base (:func:`release_excluded_usage_scopes`)
    is UNIONed on top, so an explicit ``--exclude-scope`` still applies additively
    in both ``release`` and ``all`` modes. This is the usage-scope counterpart of
    the :class:`~sbom.models.SubjectRole` filtering already applied by
    ``discover_subjects``; reconcile uses it to drop observations/edges whose
    usage scope is excluded.
    """
    if isinstance(config_or_tokens, list):
        tokens: list[str] = config_or_tokens
        preset: set[UsageScope] = set()
    else:
        tokens = getattr(config_or_tokens, "exclude_scopes", []) or []
        preset = release_excluded_usage_scopes(config_or_tokens)
    scopes: set[UsageScope] = set(preset)
    for token in tokens:
        _, scope = resolve_exclude_scope(token)
        if scope is not None:
            scopes.add(scope)
    return scopes


# ---------------------------------------------------------------------------
# Scope preset — the "release" view (the new default) vs. the full "all" view
# ---------------------------------------------------------------------------

#: Every :class:`~sbom.models.UsageScope`. The release preset keeps only
#: ``RUNTIME`` and excludes the rest.
ALL_USAGE_SCOPES: frozenset[UsageScope] = frozenset(UsageScope)

#: The release preset's excluded usage scopes: everything except ``RUNTIME``.
#: ``{TEST, BUILD, EXAMPLE, ST_TEST, MANUAL_EXAMPLE, EXPERIMENTAL, ENVIRONMENT}``.
_RELEASE_EXCLUDED_USAGE_SCOPES: frozenset[UsageScope] = frozenset(
    ALL_USAGE_SCOPES - {UsageScope.RUNTIME}
)

#: The release preset's excluded subject roles: the non-distributable roots.
#: Keeps ``primary`` + ``sibling_artifact`` wheels + the primary
#: ``cmake_project``/``unclassified`` root.
_RELEASE_EXCLUDED_ROLES: frozenset[SubjectRole] = frozenset(
    {
        SubjectRole.EXAMPLE,
        SubjectRole.EXPERIMENTAL,
        SubjectRole.ST_TEST,
        SubjectRole.MANUAL_EXAMPLE,
        SubjectRole.NON_DISTRIBUTABLE_TEST,
    }
)


def _is_release_scope(config: "Config | None") -> bool:
    """True when ``config.scope`` selects the release preset (the default)."""
    return getattr(config, "scope", "release") == "release"


def release_excluded_usage_scopes(config: "Config | None") -> set[UsageScope]:
    """The release preset's excluded usage scopes for ``config`` (empty for ``all``).

    Under the ``release`` scope this is ``ALL_USAGE_SCOPES - {RUNTIME}`` — the
    runtime-only view; under ``--scope all`` it is empty (no preset filtering).
    This is one of the three additive inputs the preset expands into; the others
    are :func:`release_excluded_roles` and :func:`release_no_env_tools`.
    """
    return set(_RELEASE_EXCLUDED_USAGE_SCOPES) if _is_release_scope(config) else set()


def release_excluded_roles(config: "Config | None") -> set[SubjectRole]:
    """The release preset's excluded subject roles for ``config`` (empty for ``all``).

    Under ``release`` this drops the example/experimental/ST/manual/
    non-distributable-test roots; under ``--scope all`` it is empty.
    ``discover_subjects`` UNIONs this with ``profile.root_exclusion_policy()`` and
    the explicit ``--exclude-scope`` role tokens.
    """
    return set(_RELEASE_EXCLUDED_ROLES) if _is_release_scope(config) else set()


def release_no_env_tools(config: "Config | None") -> bool:
    """Whether the release preset omits environment tools for ``config``.

    True under ``release`` (the runtime view never carries host build tools);
    False under ``--scope all``. Composed with the explicit ``--no-env-tools``
    flag with OR semantics, so ``all`` + ``--no-env-tools`` still drops them.
    """
    return _is_release_scope(config)


def release_keep_usage_scopes(config: "Config | None") -> set[UsageScope] | None:
    """The release preset's KEEP-ONLY usage-scope set (``None`` under ``all``).

    Returns ``{RUNTIME}`` under ``--scope release`` and ``None`` under
    ``--scope all`` (no keep-only constraint). This is a stricter axis than
    :func:`release_excluded_usage_scopes`: the exclusion set drops only the
    explicitly-named non-runtime scopes and KEEPS ``usage_scope is None``, while
    the keep-only set survives an observation/edge IFF its ``usage_scope`` is in
    the set — so under release every unclassified (``None``) and every
    non-runtime observation is dropped. ``reconcile`` applies BOTH axes (drop if
    excluded OR not-in-keep-only); they compose with explicit ``--exclude-scope``
    tokens, which only widen the exclusion set.
    """
    return {UsageScope.RUNTIME} if _is_release_scope(config) else None


# ---------------------------------------------------------------------------
# load_config_file — pure tomllib load, no merge/precedence here
# ---------------------------------------------------------------------------


def load_config_file(path: Path) -> dict:
    """Load ``sbom.toml`` via ``tomllib`` and return the raw nested dict.

    Keys follow the same structure as the CLI flags but nested where
    appropriate, e.g. ``[cmake.defines]`` → ``cmake_defines``,
    ``[profile.values]`` → ``profile_values``.  Pure load; merge/precedence
    is handled by :func:`parse_args`.
    """
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        try:
            import tomllib  # type: ignore[no-redef]
        except ImportError as exc:
            raise ImportError(
                "tomllib is required for Python < 3.11; install 'tomli'."
            ) from exc

    with open(path, "rb") as fh:
        return tomllib.load(fh)


# ---------------------------------------------------------------------------
# _parse_key_value — shared helper for KEY=VALUE repeatable args
# ---------------------------------------------------------------------------


def _parse_key_value(raw: str) -> tuple[str, str]:
    """Split a ``KEY=VALUE`` string, raising ``argparse.ArgumentTypeError`` on malformed input."""
    if "=" not in raw:
        raise argparse.ArgumentTypeError(
            f"expected KEY=VALUE, got {raw!r}"
        )
    key, _, value = raw.partition("=")
    if not key:
        raise argparse.ArgumentTypeError(
            f"empty key in {raw!r}"
        )
    return key, value


# ---------------------------------------------------------------------------
# _merge_file_config — apply file values as defaults (CLI wins)
# ---------------------------------------------------------------------------

def _merge_file_config(
    file_cfg: dict,
    namespace: argparse.Namespace,
    _explicitly_set: set[str],
) -> None:
    """Write file-config values into *namespace* for keys not set on the CLI.

    ``_explicitly_set`` is the set of dest names the user provided on the
    command line so we never overwrite a CLI value.

    TOML layout (all optional):
    ```toml
    repo_root = "./ops-math"
    repo_profile = "cann"
    cmake_root = "./cmake"
    scope = "release"
    detail = "compact"
    build_profile = "declared-all"
    formats = ["cyclonedx", "spdx"]
    collector_mode = "static"
    cmake_source_authority = "actual-build"
    network = "off"
    resolve_cmake_ref = false
    allow_input_fallback = false
    exclude_scopes = ["experimental"]
    subjects = ["ops_math"]
    split_subjects = false
    guess_pypi_urls = false
    scancode = "enrich"        # off when absent: enrich | fallback | crosscheck | both
    scancode_path = "/path/to/scancode"
    reproducible = false
    out_dir = "./out"

    [cmake.defines]
    CANN_3RD_LIB_PATH = "/path/to/3rd"

    [profile.values]
    product_side = "device"
    ```
    """
    simple_keys = [
        "repo_root", "repo_profile", "cmake_root", "scope", "detail",
        "build_profile", "formats", "collector_mode", "cmake_source_authority",
        "network", "resolve_cmake_ref", "allow_input_fallback", "exclude_scopes",
        "subjects", "split_subjects", "no_env_tools", "guess_pypi_urls",
        "repo_url", "scancode", "scancode_path", "deps_dir", "depsdev_cache",
        "refresh_data", "reproducible", "out_dir",
    ]
    for key in simple_keys:
        if key not in _explicitly_set and key in file_cfg:
            setattr(namespace, key, file_cfg[key])

    # Nested [cmake.defines]: the file block is the BASE; a CLI --cmake-define
    # overrides PER KEY (a single CLI define no longer discards the whole file
    # block, which is what the dict-dest-in-explicitly-set check used to do).
    cmake_section = file_cfg.get("cmake", {})
    if "defines" in cmake_section:
        file_d = {str(k): str(v) for k, v in cmake_section["defines"].items()}
        cli_d = _coerce_kv(getattr(namespace, "cmake_defines", None))
        setattr(namespace, "cmake_defines", {**file_d, **cli_d})

    # Nested [profile.values]: same per-key merge (CLI --profile-value wins).
    profile_section = file_cfg.get("profile", {})
    if "values" in profile_section:
        file_v = {str(k): str(v) for k, v in profile_section["values"].items()}
        cli_v = _coerce_kv(getattr(namespace, "profile_values", None))
        setattr(namespace, "profile_values", {**file_v, **cli_v})

    # [aliases] — explicit spelling -> canonical overrides (highest alias layer)
    if "aliases" not in _explicitly_set and "aliases" in file_cfg:
        setattr(namespace, "aliases", {str(k): str(v) for k, v in file_cfg["aliases"].items()})


# ---------------------------------------------------------------------------
# parse_args — the main entry point
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> Config:
    """Parse the ``sbom`` CLI flags into a :class:`Config`.

    Precedence (highest to lowest):
    1. Explicit CLI flags.
    2. ``--config`` file (``sbom.toml``).
    3. Documented defaults.

    Flag relations enforced here:
    - ``--resolve-cmake-ref`` implies ``--network on``.

    Repeatable flags:
    - ``--cmake-define KEY=VALUE`` → ``cmake_defines`` dict.
    - ``--profile-value KEY=VALUE[,KEY=VALUE,…]`` → ``profile_values`` dict.
    - ``--exclude-scope TOKEN[,TOKEN,…]`` → ``exclude_scopes`` list (raw strings).
    - ``--format FMT[,FMT,…]`` → ``formats`` list.
    - ``--subjects ID[,ID,…]`` → ``subjects`` list.
    """
    parser = _build_parser()

    # Track which args were explicitly supplied so file-config values don't
    # overwrite them.  We parse twice: once with all defaults stripped (to find
    # explicitly-set options) and once normally.
    args = parser.parse_args(argv)
    explicitly_set: set[str] = _find_explicitly_set(parser, argv)

    # --config / file merge (before we coerce types). A bad config path / TOML or a
    # malformed --cmake-define inside the merge must exit as a clean CLI error
    # (usage + 'error:', code 2), not a raw traceback.
    if args.config is not None:
        try:
            file_cfg = load_config_file(Path(args.config))
            _merge_file_config(file_cfg, args, explicitly_set)
        except (OSError, ValueError, argparse.ArgumentTypeError) as exc:
            parser.error(str(exc))

    # --resolve-cmake-ref implies --network on
    if args.resolve_cmake_ref:
        args.network = "on"

    # Coerce Path fields
    repo_root: Path = Path(args.repo_root) if args.repo_root else Path(".")
    cmake_root: Path | None = Path(args.cmake_root) if args.cmake_root else None
    out_dir: Path = Path(args.out_dir) if args.out_dir else Path("./out")

    # Normalise list fields that may have arrived as comma-separated strings
    # from the config file or as repeated argparse actions.
    formats = _normalise_list(getattr(args, "formats", None)) or ["cyclonedx", "spdx"]
    exclude_scopes = _normalise_list(getattr(args, "exclude_scopes", None)) or []
    subjects_raw = _normalise_list(getattr(args, "subjects", None))
    subjects: list[str] | None = subjects_raw if subjects_raw else None

    # cmake_defines / profile_values: these come in as lists of (key, value)
    # tuples from argparse or as dicts from the config file. A malformed KEY=VALUE
    # exits as a clean CLI error rather than an uncaught ArgumentTypeError.
    try:
        cmake_defines = _coerce_kv(getattr(args, "cmake_defines", None))
        profile_values = _coerce_kv(getattr(args, "profile_values", None))
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    # SOURCE_DATE_EPOCH (reproducible builds)
    source_date_epoch: int | None = None
    if args.reproducible:
        sde = os.environ.get("SOURCE_DATE_EPOCH")
        if sde is not None:
            try:
                source_date_epoch = int(sde)
            except ValueError:
                pass
    if getattr(args, "source_date_epoch_val", None) is not None:
        source_date_epoch = args.source_date_epoch_val

    return Config(
        repo_root=repo_root,
        repo_profile=args.repo_profile or None,
        cmake_root=cmake_root,
        scope=args.scope,
        detail=args.detail,
        build_profile=args.build_profile,
        formats=formats,
        collector_mode=args.collector_mode,
        cmake_source_authority=args.cmake_source_authority,
        network=args.network,
        resolve_cmake_ref=args.resolve_cmake_ref,
        allow_input_fallback=args.allow_input_fallback,
        exclude_scopes=exclude_scopes,
        subjects=subjects,
        split_subjects=args.split_subjects,
        no_env_tools=args.no_env_tools,
        guess_pypi_urls=args.guess_pypi_urls,
        repo_url=getattr(args, "repo_url", None) or None,
        scancode=getattr(args, "scancode", None) or None,
        deps_dir=getattr(args, "deps_dir", None) or None,
        scancode_path=getattr(args, "scancode_path", None) or None,
        depsdev_cache=getattr(args, "depsdev_cache", None) or None,
        refresh_data=getattr(args, "refresh_data", None) or None,
        profile_values=profile_values,
        cmake_defines=cmake_defines,
        aliases=getattr(args, "aliases", None) or {},
        reproducible=args.reproducible,
        source_date_epoch=source_date_epoch,
        out_dir=out_dir,
    )


# ---------------------------------------------------------------------------
# Argparse builder
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sbom",
        description="Generate a Software Bill of Materials for a C++/CMake + Python repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required / primary
    p.add_argument(
        "--repo-root",
        dest="repo_root",
        default=".",
        metavar="PATH",
        help="Root of the repository to analyse (default: current directory).",
    )
    p.add_argument(
        "--repo-profile",
        dest="repo_profile",
        default=None,
        metavar="NAME",
        help="Repo profile plugin name (e.g. 'cann'). Auto-detected when omitted.",
    )
    p.add_argument(
        "--cmake-root",
        dest="cmake_root",
        default=None,
        metavar="PATH",
        help="Path to the cmake tree (e.g. ./cmake). "
             "Authority selection may override the effective cmake root.",
    )

    # Scope / build profile
    p.add_argument(
        "--scope",
        dest="scope",
        default="release",
        choices=["release", "all"],
        metavar="SCOPE",
        help=(
            "Output view (default: release). 'release' keeps only distributable "
            "subjects and their RUNTIME dependency closure: it excludes the "
            "example/experimental/st_test/manual_example/non_distributable_test "
            "roots, keeps only usage_scope=runtime (dropping test/build/example/"
            "environment deps), and omits environment tools. 'all' applies none "
            "of these base filters (the full view). Explicit --exclude-scope / "
            "--subjects / --no-env-tools still apply additively in both modes."
        ),
    )
    p.add_argument(
        "--detail",
        dest="detail",
        default="compact",
        choices=["compact", "full"],
        metavar="LEVEL",
        help=(
            "Output verbosity (default: compact). 'compact' omits the verbose "
            "per-observation provenance (sbomgen:obs:* properties / annotations) "
            "and the CycloneDX evidence.occurrences array, keeping the readable "
            "summary: component name/version/type/purl/licenses/copyright/hashes, "
            "the dependency graph + relationships, and the integrity/completeness/"
            "alias/subject/pedigree signals. 'full' restores the complete output "
            "(all sbomgen:obs:* properties/annotations + deduped occurrences). In "
            "both modes evidence.occurrences is deduped to one entry per unique "
            "source location."
        ),
    )
    p.add_argument(
        "--build-profile",
        dest="build_profile",
        default="declared-all",
        metavar="PROFILE",
        help="Build profile (default: declared-all).",
    )

    # Output format
    p.add_argument(
        "--format",
        dest="formats",
        default=None,
        metavar="FMT[,FMT]",
        help="Comma-separated output formats: cyclonedx, spdx (default: both).",
    )

    # Collector / authority
    p.add_argument(
        "--collector-mode",
        dest="collector_mode",
        default="static",
        choices=["static", "configured", "both"],
        help="Collector mode (default: static).",
    )
    p.add_argument(
        "--cmake-source-authority",
        dest="cmake_source_authority",
        default="actual-build",
        choices=["actual-build", "cmake-as-input"],
        help="CMake source authority (default: actual-build).",
    )

    # Network
    p.add_argument(
        "--network",
        dest="network",
        default="off",
        choices=["off", "on"],
        help="Enable network enrichment (default: off).",
    )
    p.add_argument(
        "--resolve-cmake-ref",
        dest="resolve_cmake_ref",
        action="store_true",
        default=False,
        help="Resolve the pinned cmake ref by checking it out (implies --network on).",
    )
    p.add_argument(
        "--depsdev-cache",
        dest="depsdev_cache",
        default=None,
        metavar="PATH",
        help=(
            "Override the depsdev cache file (default: the vendored generic "
            "+ profile snapshots). Consulted as a license layer on every run; "
            "written only by --refresh-data depsdev."
        ),
    )
    p.add_argument(
        "--refresh-data",
        dest="refresh_data",
        default=None,
        choices=[
            "depsdev",
            "clearlydefined",
            "deps-dir",
            "aliases",
            "first-party",
            "known-licenses",
            "all",
        ],
        metavar="SOURCE",
        help=(
            "Refresh a vendored data file and exit (no SBOM emitted). "
            "'depsdev' re-fetches licenses/versions from deps.dev/PyPI; "
            "'clearlydefined' re-fetches supplier/copyright from ClearlyDefined "
            "(both require --network on and rewrite their cache); 'deps-dir' scans "
            "the on-disk dependency SOURCES under --deps-dir (offline; uses ScanCode "
            "when --scancode is set) and rewrites the deps-dir license/copyright "
            "cache; 'aliases' derives suggestions to <aliases>.suggested.yaml; "
            "'first-party'/'known-licenses' validate + report (curated, never "
            "auto-rewritten); 'all' runs each (deps-dir excluded — needs --deps-dir)."
        ),
    )
    p.add_argument(
        "--allow-input-fallback",
        dest="allow_input_fallback",
        action="store_true",
        default=False,
        help="Fall back to --cmake-root when authority is unresolvable offline.",
    )

    # Scope filtering
    p.add_argument(
        "--exclude-scope",
        dest="exclude_scopes",
        action="append",
        default=None,
        metavar="TOKEN[,TOKEN]",
        help=(
            "Exclude a scope token from collection.  Repeatable; each value may "
            "be comma-separated.  Recognised tokens: example, st_test, "
            "manual_example, experimental, non_distributable_test, test, "
            "build, runtime."
        ),
    )

    # Subject selection / splitting
    p.add_argument(
        "--subjects",
        dest="subjects",
        default=None,
        metavar="ID[,ID]",
        help="Comma-separated explicit subject id filter.",
    )
    p.add_argument(
        "--split-subjects",
        dest="split_subjects",
        action="store_true",
        default=False,
        help="Emit one sub-BOM per subject.",
    )
    p.add_argument(
        "--no-env-tools",
        dest="no_env_tools",
        action="store_true",
        default=False,
        help="Omit environment tools (no sbomgen:envtool:* properties / annotations).",
    )
    p.add_argument(
        "--guess-pypi-urls",
        dest="guess_pypi_urls",
        action="store_true",
        default=False,
        help=(
            "Construct a canonical https://pypi.org/project/<name>/[<version>/] "
            "download URL for Python components (default: off). The URL is a "
            "guess derived from the name/version, not a verified artifact link: "
            "CycloneDX gets a DISTRIBUTION externalReference and SPDX uses it as "
            "the package downloadLocation. The pkg:pypi purl is always emitted "
            "regardless of this flag."
        ),
    )

    p.add_argument(
        "--repo-url",
        dest="repo_url",
        default=None,
        metavar="URL",
        help=(
            "Declare the repository's VCS origin (e.g. "
            "https://gitcode.com/cann/ops-math). Overrides .git/config "
            "auto-detection. Recorded honestly as a vcs_url purl qualifier on the "
            "pkg:generic subject purl plus native CycloneDX externalReferences and "
            "SPDX downloadLocation/homepage -- the purl TYPE stays 'generic' (an "
            "unregistered host type like gitcode would break downstream matching)."
        ),
    )

    # ScanCode license/copyright backend (opt-in)
    p.add_argument(
        "--scancode",
        dest="scancode",
        default=None,
        choices=["enrich", "fallback", "crosscheck", "both"],
        metavar="MODE",
        help=(
            "Opt-in ScanCode Toolkit license/copyright backend (default: off). "
            "'enrich' uses ScanCode as the highest-priority license layer "
            "(overrides the normal resolver with a confident on-disk detection); "
            "'fallback' is fill-only (sets license/copyright only where still "
            "unresolved, NEVER overriding curated/known/pre-seed) — pairs with "
            "--deps-dir for offline resolution from real sources; 'crosscheck' "
            "changes no license values but writes a license-crosscheck.json report "
            "+ warnings; 'both' does enrich then reports the displaced prior values. "
            "Needs on-disk source (see --deps-dir); ScanCode is a separate install "
            "(see --scancode-path). If unavailable a scancode_unavailable warning "
            "is emitted and the run continues with the normal resolver."
        ),
    )
    p.add_argument(
        "--scancode-path",
        dest="scancode_path",
        default=None,
        metavar="PATH",
        help=(
            "Path to the scancode binary. When omitted it is located via "
            "$SCANCODE_PATH, then 'scancode' on $PATH, then the running venv's bin "
            "(so `pip install scancode-toolkit` into the same venv is found without "
            "activation). ScanCode is NOT a dependency of sbom-gen; the tool shells "
            "out to it only when --scancode is set, and emits an actionable "
            "scancode_unavailable warning if it cannot be found."
        ),
    )
    p.add_argument(
        "--deps-dir",
        dest="deps_dir",
        default=None,
        metavar="PATH",
        help=(
            "Root directory holding dependency SOURCES on disk (e.g. a vendored "
            "deps tree, or the parent dir when deps sit next to the project). Each "
            "component is located under it by name / name-version / alias / archive "
            "stem; the offline cache_scan reads its LICENSE for the license, and "
            "ScanCode (when --scancode is set) reads it for copyright + a thorough "
            "license — fully offline, no pre-seed needed. Augments the legacy "
            "CANN_3RD_LIB_PATH cmake-define / env var."
        ),
    )

    # Profile / cmake defines
    p.add_argument(
        "--profile-value",
        dest="profile_values",
        action="append",
        default=None,
        metavar="KEY=VALUE[,KEY=VALUE]",
        help=(
            "Set a profile value (repeatable, also comma-separated). "
            "e.g. product_side=device,target_arch=aarch64"
        ),
    )
    p.add_argument(
        "--cmake-define",
        dest="cmake_defines",
        action="append",
        default=None,
        metavar="KEY=VALUE",
        help=(
            "Supply a proven pre-include CMake cache value (repeatable). "
            "e.g. --cmake-define CANN_3RD_LIB_PATH=/path/to/3rd"
        ),
    )

    # Reproducible
    p.add_argument(
        "--reproducible",
        dest="reproducible",
        action="store_true",
        default=False,
        help=(
            "Fixed timestamps; serialNumber/namespace from content hash. "
            "Honors SOURCE_DATE_EPOCH."
        ),
    )

    # Output directory
    p.add_argument(
        "--out-dir",
        dest="out_dir",
        default="./out",
        metavar="PATH",
        help="Output directory (default: ./out).",
    )

    # Config file
    p.add_argument(
        "--config",
        dest="config",
        default=None,
        metavar="PATH",
        help="Path to sbom.toml config file.",
    )

    return p


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _find_explicitly_set(
    parser: argparse.ArgumentParser, argv: list[str] | None
) -> set[str]:
    """Return the set of ``dest`` names that were explicitly passed on the CLI.

    We inject a side-effect action into a *copy* of the parser's action list
    that records the ``dest`` whenever a value is actually consumed from argv.
    This avoids the sentinel-vs-append problem: we never touch the default
    values.
    """
    explicitly_set: set[str] = set()

    class _Track(argparse.Action):
        """Wraps the original action, recording dest on use."""
        def __init__(self, wrapped: argparse.Action) -> None:
            # Fake init so super().__init__ is never called on _Track directly
            self.__dict__.update(wrapped.__dict__)
            self._wrapped = wrapped

        def __call__(self, p, ns, values, option_string=None):
            explicitly_set.add(self.dest)
            self._wrapped(p, ns, values, option_string)

    # Build a throw-away parser with the same spec but tracking actions.
    tracking_parser = argparse.ArgumentParser(
        parents=[],
        add_help=False,
        exit_on_error=False,
    )
    # Copy the namespace of the original parser (prog, description, etc.) –
    # we only care about it successfully parsing argv.
    tracking_parser._defaults = dict(parser._defaults)  # type: ignore[attr-defined]

    for action in parser._actions:  # type: ignore[attr-defined]
        if isinstance(action, argparse._HelpAction):  # type: ignore[attr-defined]
            continue
        tracker = _Track(action)
        tracking_parser._actions.append(tracker)  # type: ignore[attr-defined]
        tracking_parser._option_string_actions.update(  # type: ignore[attr-defined]
            {opt: tracker for opt in action.option_strings}
        )

    try:
        tracking_parser.parse_known_args(argv)
    except Exception:  # noqa: BLE001
        pass

    return explicitly_set


def _normalise_list(val: Any) -> list[str]:
    """Flatten/split a value that may be None, a list of strings (possibly
    comma-separated), or a plain string into a flat list of stripped tokens."""
    if val is None:
        return []
    if isinstance(val, str):
        return [t.strip() for t in val.split(",") if t.strip()]
    if isinstance(val, list):
        result: list[str] = []
        for item in val:
            if isinstance(item, str):
                result.extend(t.strip() for t in item.split(",") if t.strip())
            else:
                result.append(item)
        return result
    return [str(val)]


def _coerce_kv(val: Any) -> dict[str, str]:
    """Coerce a value that may be:
    - ``None`` → empty dict
    - a ``dict`` (already parsed from TOML) → return as-is
    - a list of ``KEY=VALUE`` strings (from argparse) → parse into dict
    - a list of ``KEY=VALUE[,KEY=VALUE]`` strings (comma-sep) → parse into dict
    """
    if val is None:
        return {}
    if isinstance(val, dict):
        return {str(k): str(v) for k, v in val.items()}
    result: dict[str, str] = {}
    if isinstance(val, list):
        for item in val:
            # item may itself be comma-separated "K=V,K2=V2"
            for part in item.split(","):
                part = part.strip()
                if not part:
                    continue
                k, v = _parse_key_value(part)
                result[k] = v
    return result


__all__ = [
    "Config",
    "parse_args",
    "load_config_file",
    "resolve_exclude_scope",
    "excluded_usage_scopes",
    "ALL_USAGE_SCOPES",
    "release_excluded_usage_scopes",
    "release_excluded_roles",
    "release_no_env_tools",
    "release_keep_usage_scopes",
]
