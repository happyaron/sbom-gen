# INTERFACE.md — Frozen module contract (rev. 1)

This is the **authoritative, frozen contract** for every module implemented
*after* the foundation. The foundation (already written) is:

- `src/sbom/models.py` — all dataclasses + enums (the data that flows everywhere).
- `src/sbom/graph.py` — shared dependency-graph helpers (edge identities +
  subject closure) used by collectors, reconcile, and emit so they share ONE
  definition. `semantic_edge_key(edge)` (endpoints/relation + usage_scope +
  reachability) is the collector dedup key; `exact_edge_key(edge)` adds
  source_file/source_revision for reconcile's exact-duplicate dedup;
  `dedup_edges(edges, *, key)` drops self-loops + dedups; `reachable_components(
  edges, subject_ids)` is the BFS closure shared by `--subjects` and `--split`.
- `src/sbom/profile.py` — the `Profile` ABC + registry/auto-detect.
- `src/sbom/__init__.py` — re-exports `__version__` and the public models.
- `src/sbom_profile_cann/__init__.py` — placeholder for `CannProfile`.
- `src/sbom/data/known_licenses.yaml` — EMPTY by default (content lives in the
  active profile's `known-licenses` data source).
- `pyproject.toml` — packaging, `sbom` console script, `sbom.profiles` group.

Parallel implementers MUST build against the signatures below. Every signature
references types from `sbom.models` (imported as `from .models import ...` or
`from ..models import ...` depending on package depth). Do not change a public
signature without updating this file.

## Data-flow contract (Collect → Reconcile → Emit)

```
            ┌─────────────── Collect ───────────────┐
repo_root ─▶│ subject.discover_subjects()           │─▶ list[Subject]
--cmake-root│ cpp.collect()  (uses CmakeAuthority)   │─▶ CollectResult
config      │ python.collect()                      │─▶ CollectResult
profile     │ profile hooks (package_metadata, …)   │─▶ Observations/Components/…
            └───────────────────────────────────────┘
                              │ (everything is lists of model records)
                              ▼
            ┌─────────────── Reconcile ─────────────┐
            │ reconcile.reconcile(inputs, profile)  │─▶ Document
            │   • alias de-dup (OSS + profile map)  │
            │   • union scopes/langs/integrity/prov │
            │   • attach observations to components │
            │   • derive Component.depends_on rollup│
            │   • run enrichers (license/cache/net) │
            └───────────────────────────────────────┘
                              │ (one Document)
                              ▼
            ┌─────────────── Emit ──────────────────┐
            │ cyclonedx.emit(document, opts) → str  │
            │ spdx.emit(document, opts) → str       │
            │ validate.validate_*(text) → [Warning] │
            └───────────────────────────────────────┘
```

**Invariants every implementer must honour:**

- Collectors return **lists of model records** (`Observation`, `Component`,
  `Subject`, `DependencyEdge`, `EnvironmentTool`, `Warning`) — never a partially
  emitted SBOM and never mutate global state.
- An `EnvironmentTool` is **never** turned into a `Component`. There is no
  `environment_tool` `SourceKind`.
- Every collector-produced `Observation`/`DependencyEdge` carries
  `root_artifact_id` so ownership is preserved through reconcile and emit.
- The two axes `declaration_reachability` and `usage_scope` are kept separate.
- `reconcile` is the **only** stage that produces a `Document`; emitters only
  read it.
- Emitters build via the official libraries' object models (`cyclonedx-python-lib`,
  `spdx-tools`); no hand-rolled JSON, no vendored schemas.
- All `add_cann_third_party()`-style resolution uses
  `CmakeAuthority.effective_cmake_root`, never the raw `--cmake-root`.

## Shared support types (defined where first needed, used across modules)

```python
# sbom/config.py
@dataclass
class Config:
    repo_root: Path
    repo_profile: str | None = None              # None/"auto" → detect
    cmake_root: Path | None = None
    scope: str = "release"                       # release (default) | all — view preset
    detail: str = "compact"                      # compact (default) | full — emit verbosity
    build_profile: str = "declared-all"
    formats: list[str] = field(default_factory=lambda: ["cyclonedx", "spdx"])
    collector_mode: str = "static"               # static | configured | both
    cmake_source_authority: str = "actual-build" # actual-build | cmake-as-input
    network: str = "off"                         # off | on
    resolve_cmake_ref: bool = False              # implies network=on
    allow_input_fallback: bool = False
    exclude_scopes: list[str] = field(default_factory=list)  # raw --exclude-scope tokens
    subjects: list[str] | None = None            # explicit subject id filter
    split_subjects: bool = False
    no_env_tools: bool = False                   # --no-env-tools: drop EnvironmentTools
    guess_pypi_urls: bool = False                # --guess-pypi-urls: construct pypi.org URLs
    repo_url: str | None = None                  # --repo-url: declare/override the repo VCS origin
    scancode: str | None = None                  # --scancode: None | enrich | fallback | crosscheck | both
    scancode_path: str | None = None             # --scancode-path: explicit scancode binary
    deps_dir: str | None = None                  # --deps-dir: on-disk dep-source search root (offline)
    depsdev_cache: str | None = None             # --depsdev-cache: override the depsdev cache file
    refresh_data: str | None = None              # --refresh-data: refresh a vendored data file and exit
    profile_values: dict[str, str] = field(default_factory=dict)  # product_side, …
    cmake_defines: dict[str, str] = field(default_factory=dict)   # proven pre-include
    aliases: dict[str, str] = field(default_factory=dict)         # [aliases] spelling->canonical
    reproducible: bool = False
    source_date_epoch: int | None = None
    out_dir: Path = Path("./out")

# sbom/collectors/__init__.py  (or collectors/base.py)
@dataclass
class CollectResult:
    """The uniform return of every collector. All lists default empty."""
    subjects: list[Subject] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)  # unattached
    edges: list[DependencyEdge] = field(default_factory=list)
    environment_tools: list[EnvironmentTool] = field(default_factory=list)
    warnings: list[Warning] = field(default_factory=list)

    def extend(self, other: "CollectResult") -> None: ...
```

`CollectResult.observations` holds observations not yet attached to a component
(collectors may also pre-attach observations onto `Component.observations`);
reconcile attaches/merges them by alias-resolved component name.

`EmitOptions` is the emit-side counterpart:

```python
# sbom/emit/__init__.py  (or emit/base.py)
@dataclass
class EmitOptions:
    reproducible: bool = False
    source_date_epoch: int | None = None
    split_subjects: bool = False
    subjects: list[str] | None = None    # which subject ids to emit
    tool_version: str = "0"              # stamped as the generator version
    guess_pypi_urls: bool = False        # construct pypi.org download URLs (Python)
    detail: str = "compact"              # compact (default) | full — emit verbosity
```

`detail` controls per-component verbosity, orthogonal to `Config.scope`.
`compact` (the default) OMITS the per-observation `sbomgen:obs:N:*` CycloneDX
properties / `sbomgen:obs:*` SPDX annotations AND the CycloneDX
`evidence.occurrences` array, keeping the readable summary
(name/version/type/purl/licenses/copyright/hashes, the dependency graph, and the
`integrity`/`completeness`/`alias`/`subject`/`pedigree`/`component:origin`
signals). `full` restores
all `sbomgen:obs:*` provenance plus the `evidence.occurrences` array. When
occurrences are emitted they are deduped to ONE entry per unique source location
(both modes); both modes pass the validators and are reproducible.

---

## sbom/cmake/parse.py — static CMake parsing (no build)

Pure static parser. Consumes `.cmake`/`CMakeLists.txt` text + the
`CmakeAuthority`; produces structured records the CppCollector turns into model
objects. **Mandatory for declared-all** (sees every conditional branch).

```python
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from ..models import (
    ActivationCondition, CmakeAuthority, CommandContext, EnvironmentTool,
    FindPackageInfo, IntegrityFinding, Patch, VcsRef,
)

@dataclass
class ExternalProject:
    name: str
    source_version: str | None          # from filename/URL
    set_version: str | None             # from set(*_VERSION ...)
    canonical_url: str | None
    resolved_url_or_path: str | None
    url_hash: str | None                # SHA256 from URL_HASH, else None
    tls_verify: bool | None             # None=unspecified; False ⇒ tls finding
    git_repository: str | None
    git_tag: str | None
    vcs_ref: VcsRef | None
    patches: list[Patch] = field(default_factory=list)
    depends: list[str] = field(default_factory=list)   # DEPENDS args (edges!)
    commands: dict[str, str] = field(default_factory=dict)  # ep_* command fields
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
    info: FindPackageInfo                # required/quiet/effective_required
    conditions: list[ActivationCondition] = field(default_factory=list)

@dataclass
class IncludeStmt:
    path: str                            # raw include() argument
    resolved: Path | None                # resolved against effective_cmake_root
    conditions: list[ActivationCondition] = field(default_factory=list)

@dataclass
class LinkLibraryToken:
    raw: str                             # one token from a link line
    target_property: str | None          # set()-var it was expanded from, if any
    conditions: list[ActivationCondition] = field(default_factory=list)

@dataclass
class AddDependenciesEdge:
    target: str
    depends_on: list[str]

@dataclass
class ProgramInvocation:
    """A raw program/tool invocation (one classifier routes these later).

    `name` is the resolved program/tool name (argv[0] basename, e.g. `protoc`,
    `perl`, `tar`); `path` is its resolved location if known (e.g. from
    find_program); `args` is the remaining argv after the program. `tokens` is
    the full tokenized command (shell-compound split) the args derive from.
    `command_context` is a raw `CommandContext` value string (see mapping
    below). `required` mirrors a `find_program(... REQUIRED)` (None ⇒ unknown).
    """
    name: str
    command_context: str                 # CommandContext value (see mapping)
    path: str | None = None
    args: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)  # full shell-compound split
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
    # (macro_name, args) — e.g. ("add_cann_third_party", ["eigen"])

def parse_file(path: Path) -> CMakeFile:
    """Statically parse ONE cmake file. Never follows include()."""

def parse_recursive(
    entry: Path,
    effective_cmake_root: Path,
    *,
    custom_macros: dict[str, object] | None = None,
) -> list[CMakeFile]:
    """Parse `entry`, then recursively follow include() (and custom-macro
    expansions) resolving paths against `effective_cmake_root`. Returns every
    visited CMakeFile (dedup by resolved path). Cycles are broken."""

def tokenize_command(raw: str) -> list[list[str]]:
    """Split a shell-compound command into sub-commands: split on `&&`/`;`/pipes,
    strip redirects and `VAR=val` prefixes, recognize `$(MAKE)` and `cmake -E`.
    Returns a list of token-lists (one per sub-command)."""

def classify_link_token(token: LinkLibraryToken, local_targets: set[str]) -> str:
    """Return one of: "drop" (flags `-Wl,*`, genexprs `$<…>`), "local" (a target
    defined in the project), or "external" (emit as component). The link-token
    classifier runs BEFORE reconcile; unmapped externals raise
    `unmapped_link_library` at reconcile time, not here."""

def classify_program(inv: ProgramInvocation, profile_tooling: set[str]) -> str:
    """Program/tool boundary classifier — the program/tool counterpart of
    `classify_link_token`. Returns one of:
      • "component"        — a domain/packaged build tool that IS an SBOM
                             component (or tooling observation on one), e.g.
                             `protoc`/`host_protoc`, `bisheng-compiler`,
                             `op_build`, plus any name in `profile_tooling`
                             (the profile's domain-tool allowlist);
      • "environment_tool" — a generic host tool (`perl`, `ccache`, `$(MAKE)`,
                             `cp`, `python3`, `bash`, `patch`, `tar`, `chmod`,
                             system `git`) → an `EnvironmentTool` record, NEVER a
                             component (use `program_to_environment_tool`);
      • "ignore"           — pure flags / `cmake -E …` internals / redirects.
    `profile_tooling` is the profile's set of domain-tool names that should be
    routed to "component" instead of "environment_tool"."""

def program_to_environment_tool(
    inv: ProgramInvocation,
    *,
    source_revision: str | None,
    source_authority: str | None,
    root_artifact_id: str | None,
) -> EnvironmentTool:
    """Build the `EnvironmentTool` record for an inv classified
    "environment_tool". Maps inv.name→name, inv.path→path, inv.required→required,
    inv.source_file→source_file, inv.conditions→activation_condition, and
    inv.command_context (a string) → the `CommandContext` enum member. The
    required `source_revision`/`source_authority` (many tools come from the
    `cann-cmake` tree, not the repo) and `root_artifact_id` are passed in by the
    CppCollector so host-tool provenance survives authority-branch changes.

    `ProgramInvocation.command_context: str` → `CommandContext` mapping
    (1:1 by value):
      "find_program"       → CommandContext.FIND_PROGRAM
      "execute_process"    → CommandContext.EXECUTE_PROCESS
      "add_custom_command" → CommandContext.ADD_CUSTOM_COMMAND
      "add_custom_target"  → CommandContext.ADD_CUSTOM_TARGET
      "ep_configure"       → CommandContext.EP_CONFIGURE   (CONFIGURE_COMMAND)
      "ep_build"           → CommandContext.EP_BUILD        (BUILD_COMMAND)
      "ep_install"         → CommandContext.EP_INSTALL      (INSTALL_COMMAND)
      "ep_download"        → CommandContext.EP_DOWNLOAD     (DOWNLOAD_COMMAND)
      "ep_update"          → CommandContext.EP_UPDATE       (UPDATE_COMMAND)
      "patch_command"      → CommandContext.PATCH_COMMAND   (PATCH_COMMAND)
    (The `ep_*` contexts are the ExternalProject_Add *_COMMAND fields.)"""

def discover_roots(repo_root: Path) -> list[Path]:
    """Find every directory whose CMakeLists.txt has BOTH cmake_minimum_required
    and project(). Returns root directories (standalone CMake roots). Pure
    discovery — classification into roles is profile policy, not done here."""
```

**Authority resolution** (the four `fetch_cann_cmake` outcomes) lives here too,
because it must run pre-collection and feeds every collector:

```python
def resolve_cmake_authority(
    repo_root: Path,
    cmake_root: Path | None,
    *,
    cmake_source_authority: str,            # actual-build | cmake-as-input
    cmake_defines: dict[str, str],          # proven pre-include values
    profile_values: dict[str, str],         # project_source_dir_predefined, …
    allow_input_fallback: bool,
    resolve_cmake_ref: bool,
    network: str,
) -> tuple[CmakeAuthority, list[Warning]]:
    """Resolve which fetch_cann_cmake branch wins using ONLY pre-project() state.

    Precedence for authority inputs: trace > explicit --cmake-define/config >
    bare cache > default. A bare cache value for CANN_3RD_LIB_PATH is AMBIGUOUS
    → assume Git branch + emit `cmake_authority_input_ambiguous`. Records
    authority_inputs.cann_3rd_lib_path={value, source: cli|cache|unset}.

    The returned `CmakeAuthority.effective_cmake_root` is a `Path | None` (a
    filesystem path every consumer resolves include()/macro fragments against),
    NOT a string; `ref`/`revision` stay `str | None` (VCS ref name + resolved
    commit).

    Branches: skipped_existing_project (gate project_source_dir_predefined,
    no cann-cmake component) | local_dir (effective_cmake_root=that dir;
    `cann_cmake_local_override`, version NOASSERTION) | tarball (master-016 +
    sha256) | git (ref + resolved commit). Under cmake-as-input,
    effective_cmake_root=--cmake-root by policy and cann-cmake is excluded
    (`cann_cmake_trusted_input`). Mismatch vs pin → `cann_cmake_tag_mismatch`.
    Offline-unresolvable actual-build → fail unless allow_input_fallback
    (then `cmake_acquisition_metadata_unresolved`)."""
```

## sbom/cmake/fileapi.py — configured graph (CMake File API)

Module exists + is unit-tested, but **NOT yet wired into the CLI**:
`--collector-mode configured|both` currently emits a `collector_mode_unimplemented`
warning and runs static (no dispatch invokes this module). When wired, it answers
the graph question (targets, compile/link, install), NOT acquisition metadata.

```python
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class FileApiTarget:
    name: str
    type: str                            # EXECUTABLE | STATIC_LIBRARY | …
    link_libraries: list[str] = field(default_factory=list)
    imported: bool = False

@dataclass
class FileApiGraph:
    targets: list[FileApiTarget] = field(default_factory=list)
    install_relationships: list[tuple[str, str]] = field(default_factory=list)

def configure_and_query(
    repo_root: Path, build_dir: Path, *, cmake_defines: dict[str, str],
) -> tuple[FileApiGraph, list[Warning]]:
    """Configure with the File API query stanza enabled and parse the reply.
    Side-effect-controlled (scratch build_dir). May not expose
    ExternalProject_Add URLs/patches/TLS_VERIFY — that is parse.py/trace.py."""

def read_reply(reply_dir: Path) -> FileApiGraph:
    """Parse an already-generated File API reply directory (no configure)."""
```

## sbom/cmake/trace.py — configure-trace acquisition metadata

Module exists + is unit-tested, but **NOT yet invoked** by the pipeline (no
collector dispatch runs it, and `--resolve-cmake-ref` resolves via `git ls-remote`,
not a trace). When wired, configures with `--trace`/`--trace-expand`
(download-disabled scratch dir) to capture acquisition metadata the static parse
may miss.

```python
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from .parse import CMakeFile

@dataclass
class TraceResult:
    files: list[CMakeFile]               # same shape parse.py produces
    warnings: list                       # list[Warning]

def trace_configure(
    repo_root: Path, scratch_dir: Path, *,
    cmake_defines: dict[str, str], effective_cmake_root: Path,
) -> TraceResult:
    """Run a side-effect-controlled trace configure and reconstruct CMakeFile
    records (URLs, hashes, patches, git refs, resolved branches). Download
    disabled by default."""
```

---

## sbom/collectors/subject.py — subject/root discovery

```python
from __future__ import annotations
from pathlib import Path
from ..config import Config
from ..models import Subject, Warning
from ..profile import Profile
from . import CollectResult

def discover_subjects(
    config: Config, profile: Profile,
) -> tuple[list[Subject], list[Warning]]:
    """Discover all distributable root artifacts:
      • the primary CANN/CMake/wheel subject (project()/version metadata),
      • a root-level Python package (setup.py/pyproject) — ALWAYS a python_wheel
        subject via py_metadata.resolve_package_metadata, even when the version is
        unresolved (becomes PRIMARY when there is no CMake primary),
      • sibling wheels (setup.py/pyproject in sub-dirs) — likewise ALWAYS created
        via the resolver and never dropped for unresolved metadata,
      • standalone CMake roots (via cmake.parse.discover_roots).
    Each discovered root gets a stable `id` and the neutral role
    `cmake_project`/`unclassified`. Then:
      • profile.classify_root(path, cmake_project, package_context) assigns the
        path-semantic role,
      • a GENERIC co-located merge runs first: a python_wheel and a cmake_project
        sharing the same source_path are the same artifact (e.g. pyasc's wheel
        `pyasc` + project(AscIR)); the wheel identity is canonical (inheriting the
        primary role when it absorbs the CMake primary), the CMake project becomes
        a Facet + build_graph_root_id,
      • profile.subject_facets(subjects) -> list[SubjectMerge] then drives the
        profile wheel↔CMake merge: each SubjectMerge collapses absorbed_subject_id
        into keep_subject_id, recording the absorbed identity on the kept subject's
        facets[] and setting build_graph_root_id to the cmake_project root that
        builds it (e.g. wheel ascend_ops absorbs CMake AscendOps). The generic and
        profile merges COMPOSE: merge application is idempotent (a pair already
        collapsed, or keep==absorb, is a no-op), so a primary already carrying its
        CMake identity as a facet is never double-merged. The two roots' deps then
        attach to the SAME subject. No merge ⇒ standalone subjects,
      • the CLI/config layer maps each --exclude-scope token to a SubjectRole
        (and, where applicable, a UsageScope — see Config.exclude_scopes below);
        profile.root_exclusion_policy() ∪ `release_excluded_roles(config)` (the
        release-preset base, empty under --scope all) ∪ those role tokens drop
        excluded roles, emitting an `excluded_scope` warning per dropped root.
    Sets emit_as_subject=False for non-distributable test/manual roots.
    Finally de-dups genuinely-identical roots (_dedup_identical_subjects: same
    id/identity/role/source_path) so a re-discovered root is not emitted twice;
    distinct roots that merely share an id/slug keep different source_paths and
    are retained (the emitters disambiguate their slug-colliding ids).
    Surfaces py_metadata's `subject_name_unresolved`/`subject_version_unresolved`
    warnings for packages whose identity could not be statically resolved."""
```

## sbom/collectors/py_metadata.py — static package-metadata resolver

```python
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from ..models import Warning

@dataclass
class PkgMetadata:
    name: str                       # always set (dir-basename fallback)
    version: str | None = None      # None when unresolvable (never fabricated)
    name_source: str | None = None
    version_source: str | None = None
    warnings: list[Warning] = field(default_factory=list)

def resolve_package_metadata(pkg_root: Path) -> PkgMetadata:
    """Resolve a Python package's name+version WITHOUT executing any code.
    Precedence:
      1. pyproject.toml [project].name/version (PEP 621); a dynamic version is
         resolved via [tool.setuptools.dynamic] (attr:/file:), a version file, or
         setuptools_scm;
      2. setup.cfg [metadata] name/version (incl. file:/attr: directives);
      3. setup.py AST — the setup(name=…, version=…) argument expressions are
         resolved by a SAFE static evaluator that handles: string literals;
         module-level constant refs (1–2 levels); os.getenv(k, default) /
         os.environ.get(k, default) → the default literal; `X or "lit"` → the
         literal operand; a zero-arg helper f() with a single resolvable return
         (literal/const/getenv-default, local vars included); version-file reads
         (_read_file('version.txt'), open('VERSION').read(), Path('…').read_text())
         → READ the small text file under pkg_root and strip; chained
         .strip()/.replace()/.splitlines() over a resolvable base;
      4. conventional fallbacks: version.txt/VERSION, <pkg>/_version.py or
         __init__.py __version__, PKG-INFO, setuptools_scm (git describe).
    Honesty: an unresolvable name → directory basename + Warning(
    'subject_name_unresolved'); an unresolvable version → None + Warning(
    'subject_version_unresolved'). name_source/version_source record which
    mechanism produced each value. Nothing in this module imports or runs the
    target package; the evaluator only reads literals and small co-located files."""
```

## sbom/collectors/cpp.py — C++/CMake collector

```python
from __future__ import annotations
from ..config import Config
from ..models import CmakeAuthority, Subject
from ..profile import Profile
from . import CollectResult

def collect(
    config: Config,
    profile: Profile,
    authority: CmakeAuthority,
    subjects: list[Subject],
) -> CollectResult:
    """Run the full C++ collection (design §Collectors → CppCollector):
      1. entry-point expansion: profile.custom_dep_macros() +
         local include(cmake/third_party/*.cmake), recording surrounding if()
         gates as activation_condition and usage_scope from path/curated hints;
      2. recursive include() walk → ExternalProject_Add/FetchContent_Declare;
      3. per-target source/effective version, canonical vs resolved URL,
         URL_HASH, git ref, PATCH_COMMAND patches(+sha256), TLS_VERIFY →
         integrity_findings;
      4. ALL find_package() with conditions + requiredness (FindPackageInfo);
      5. package deps via profile.package_metadata() (version.cmake set_cann_*);
      6. standalone-root discovery already done in subject.py — here attach each
         root's deps with the root's root_artifact_id; mark unreachable +
         unreachable_reason=dead_config_flag for dead config flags
         (ENABLE_TORCH_EXTENSION);
      7. raw link libraries: classify tokens (drop flags/genexprs, resolve local
         targets, emit externals), alias-normalize; unmapped → handled at
         reconcile (`unmapped_link_library`);
      8. program/tool classifier over the full command grammar → domain tools as
         components/observations, generic host tools as EnvironmentTool records;
      9. build tooling via profile.build_tooling() (cann-cmake).
    Every Observation/DependencyEdge carries root_artifact_id and source_revision.
    Edges built from DEPENDS args, add_dependencies(), and link/tooling relations.
    Uses authority.effective_cmake_root for ALL macro/include resolution."""
```

## sbom/collectors/python.py — Python collector

```python
from __future__ import annotations
from packaging.specifiers import SpecifierSet
from ..config import Config
from ..models import Subject
from ..profile import Profile
from . import CollectResult

def collect(
    config: Config, profile: Profile, subjects: list[Subject],
) -> CollectResult:
    """pip/packaging-faithful Python collection (design §Collectors → PyCollector):
      • requirements: follow -r recursively, apply -c constraints, record
        -e/URL/VCS as direct deps, parse extras/markers/--hash; index options
        (--extra-index-url/-i) kept as file-level source metadata, not packages;
      • runtime/install: setup.py install_requires (AST) / pyproject
        [project].dependencies → owning wheel subject;
      • build (scope=build, source_kind=python_build): pyproject
        [build-system].requires; legacy setup-time imports (setuptools/wheel) +
        external build tools (cmake/ninja); cmdclass build-method import scan
        (torch/torch_npu) → build-scope observations that MERGE with runtime
        (one component, {runtime,build});
      • file-level scope assigned by profile/config, not hard-coded;
      • version: the full PEP 508 specifier is recorded as
        Observation.version_constraint (None for a bare dep); an EXACT pin (a
        single `==`/`===` clause, no `*` wildcard — see `concrete_version`) sets
        the component's source_version = effective_version, so a pin carries a
        real component.version / `@version` purl. A range/bare/wildcard dep sets
        no version (reconcile then records the `unpinned` marker);
      • static mode: every entry direct-declared,
        completeness=python_transitives=unresolved.
    Returns components (with observations), edges (subject→component), warnings."""

def concrete_version(specifier: SpecifierSet) -> str | None:
    """The EXACT pin a specifier names, or None for a range/bare/wildcard.
    Concrete IFF the set is exactly ONE clause whose operator is `==`/`===` and
    whose version has no `*` wildcard (e.g. `==24.2.0`→'24.2.0', `x===1.2`→'1.2';
    `<2`/`==1.4.*`/`~=1.2`/`>=3.20,<4.0`/`==1.0,!=1.0.1`/`>=8.5`→None)."""
```

---

## sbom/enrich/* — license/integrity enrichers (layered, each optional)

Each enricher takes the in-progress `Document` (or its component list) and the
`Config`, mutates/annotates components in place, records `Provenance`, and
returns any `Warning`s. Layer order is enforced by reconcile (curated > known
map > cache scan > network > NOASSERTION).

```python
# sbom/enrich/known_licenses.py
from __future__ import annotations
from pathlib import Path
from ..models import Component, Provenance, Warning

def load_map(path: Path | None = None) -> dict[str, str]:
    """Load data/known_licenses.yaml (or an override path): {name: SPDX expr}."""

def apply(components: list[Component], license_map: dict[str, str]) -> list[Warning]:
    """Set component.license from the map when unset; alias-aware lookup by
    name/aliases; record Provenance(field="license", source="known_licenses.yaml").
    Does NOT override a curated value already present (curated wins)."""

# sbom/enrich/cache_scan.py
from ..config import Config

def apply(components: list[Component], config: Config) -> list[Warning]:
    """Offline: scan extracted dep dirs under CANN_3RD_LIB_PATH for
    LICENSE/COPYING, SPDX-match, set license + checksums when confident.
    integrity_findings.local_source_unverified stays when only a local source."""

# sbom/enrich/net.py
def apply(components: list[Component], config: Config) -> list[Warning]:
    """Opt-in (config.network=="on"). Python: deps.dev/PyPI; C++: download
    archive, scan license, compute sha256. A network-computed sha256 is recorded
    but NEVER equated to a checked-in URL_HASH. No-op when network is off.
    Only FILLS unset Python licenses."""

def resolve_pypi(name: str, version: str | None = None) -> dict | None:
    """Live deps.dev+PyPI lookup -> {"license","version","source"} or None. No
    component mutation, no 'already set' guard — the building block for
    --refresh-data depsdev (apply() is the normal fill-only path). Retries
    version-less when a supplied version misses (e.g. a C++ version on a
    name-colliding Python dep)."""

def pypi_supplier(name: str, version: str | None = None) -> str | None:
    """PyPI info.author/maintainer -> a clean NTIA Supplier, or None (sparse for
    modern packages). Stored in the depsdev cache by --refresh-data depsdev."""

# sbom/enrich/depsdev_cache.py — vendored deps.dev/PyPI snapshot (license layer)
def cache_key(name: str, ecosystem: str = "pypi") -> str: ...   # "pypi:<pep503>"
def load(paths) -> dict[str, dict]:
    """Merge cache JSON files (later wins); missing/corrupt skipped. File shape:
    {"schema":1,"entries":{"pypi:<name>":{"license","version","source","fetched"}}}."""
def apply(components: list[Component], cache: dict[str, dict]) -> list[Warning]:
    """Fill each still-unset PYTHON component's license from the cache (records
    Provenance(source="depsdev")). Runs ALWAYS (offline + online), just
    above live net. License only — the cached version stays informational."""
def dump(entries: dict[str, dict]) -> str:   # deterministic: sorted keys, schema 1

# sbom/enrich/clearlydefined.py — ClearlyDefined supplier/copyright snapshot
def component_key(component, purl_map=None) -> str | None:
    """"pypi:<pep503>" for Python; "<host>:<org>/<name>" for a C++ third-party whose
    name is in purl_map (third_party_purls.yaml pkg:github|gitlab coordinate); else None."""
def coordinates_for(component, version) -> str | None:  # PyPI: "pypi/pypi/-/<name>/<rev>"
def git_coordinates(coord_purl, version) -> str | None:
    """C++: resolve a curated pkg:github|gitlab coordinate + version TAG to a CD git
    coordinate "git/<host>/<org>/<name>/<sha>" via `git ls-remote` (v<v> then <v>)."""
def resolve(coordinates: str) -> dict | None:     # live API -> {supplier,copyright,source,license}
def load(paths) -> dict[str, dict]: ...
def apply(components, cache, purl_map=None) -> list[Warning]:
    """Fill THIRD-PARTY supplier + copyright (if unset) from the cache; license is
    NOT re-applied (the dedicated layers own it). Matches Python by name and C++ by
    its curated upstream coordinate (purl_map). `_extract` keeps ONLY clean signals —
    a git-org namespace as supplier, year-bearing 'Copyright …' lines — because CD
    attribution is noisy auto-scan."""
def dump(entries: dict[str, dict]) -> str:        # deterministic, schema 1

# sbom/enrich/licenseref.py
from ..models import Component, Subject

def synthesize(expr_or_text: str, name: str) -> tuple[str, str]:
    """For a non-SPDX license, return (licenseref_id, full_text) where
    licenseref_id is `LicenseRef-<slug>` (e.g.
    LicenseRef-CANN-Open-Software-License-2.0). Used by emitters so validators
    don't reject a bare string."""

def is_spdx_expression(expr: str) -> bool:
    """True if `expr` is a valid SPDX license expression (so it can be emitted
    as-is rather than as a LicenseRef)."""

# sbom/enrich/scancode.py  (opt-in; gated by Config.scancode)
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from ..models import Component, Document, Subject, Warning
from ..config import Config

CONFIDENCE_THRESHOLD: float          # = 80.0 — best-match score gate
DEFAULT_TIMEOUT: float               # = 120.0 — per-invocation subprocess timeout
CROSSCHECK_REPORT_NAME: str          # = "license-crosscheck.json"

@dataclass
class ScanResult:
    spdx_license_expression: str | None = None   # None ⇒ no confident detection
    score: float = 0.0
    copyrights: list[str] = field(default_factory=list)
    holders: list[str] = field(default_factory=list)
    detection_rules: list[str] = field(default_factory=list)
    license_text: str | None = None              # inline text for a LicenseRef-…
    def copyright_summary(self) -> str | None: ...

class ScancodeRunner:
    """Resolve + invoke the ScanCode binary. ScanCode is NOT a dependency — we shell
    out to its CLI. Discovery precedence: `--scancode-path` (must be executable; an
    invalid explicit path is a hard error) > $SCANCODE_PATH > $PATH (which) >
    Path(sys.executable).parent/'scancode' (the venv bin, found without activation)."""
    def __init__(self, scancode_path: str | None = None): ...
    def available(self) -> bool: ...
    @property
    def unavailable_detail(self) -> str: ...  # actionable reason for the warning
    def scan_paths(
        self, paths: list[Path], *, timeout: float = DEFAULT_TIMEOUT,
    ) -> dict[Path, ScanResult]:
        """Run `scancode -cl --json-pp <tmp> <one-input>` for EACH path in the
        bounded surface (ScanCode 32.5.0 rejects multiple absolute inputs in one
        call) and AGGREGATE per root by merging the per-file results. A root that
        times out / exits non-zero / yields malformed JSON is absent from the
        result (caller warns), never raised. Each scan is scoped to the
        LICENSE/COPYING/NOTICE/COPYRIGHT files + the target dir top-level (no
        full-tree walk)."""

def aggregate(scan_json: dict, *, threshold: float = CONFIDENCE_THRESHOLD) -> ScanResult:
    """Parse one ScanCode JSON doc → one ScanResult. Prefer the highest-score
    detection from a license/notice file; UNION copyrights/holders. An
    `unknown-license-reference` / `LicenseRef-scancode-unknown-license-reference`
    expression, or a best score < threshold ⇒ `spdx_license_expression = None`
    (never assert a guess). A non-SPDX `LicenseRef-scancode-*` ⇒ mapped through
    `licenseref.synthesize` to `LicenseRef-<slug>` + inline `license_text`."""

def target_dir_for(
    subject_or_component: Subject | Component, repo_root: Path | str | None = None,
) -> Path | None:
    """A Subject ⇒ its `source_path` (the empty string `""` ⇒ the repo root);
    a Component ⇒ a `resolved_url_or_path` observation that is an existing local
    directory, else None (ScanCode can only read on-disk source). A RELATIVE
    `source_path`/`resolved_url_or_path` is resolved against `repo_root` (mirrors
    collectors/python.py + cpp.py) so the scan hits the real source tree, not the
    process CWD."""

def crosscheck(
    document: Document, config: Config, out_dir: Path, profile: Profile | None = None,
) -> tuple[list[Warning], list[dict]]:
    """QA pass (mode b). `crosscheck` mode runs ScanCode live and compares its
    SPDX license vs each subject/component's resolved license (changing NOTHING);
    `both` mode reads the displaced prior values stashed by the enrich layer (no
    rescan). Each row is 3-WAY when `profile` exposes a curated Notice for the
    component: {name, ours, scancode, curated, score, agree} (`curated` = the
    Notice declared license, or None; `agree` is always ours-vs-scancode). Returns
    ([Warning(code='license_crosscheck_mismatch', subject, detail='ours=<x>
    scancode=<y> score=<s>'), …], [rows]). `cli.main` reads the profile stashed on
    the document by `cli.run` and writes the rows to <out_dir>/CROSSCHECK_REPORT_NAME."""
```

**Wiring.** `reconcile._resolve_licenses` runs the license layers in precedence
**scancode (if enrich) > curated (Notice/List) > known-map > deps-dir live
(`--deps-dir`) > deps-dir cache (seeded snapshot) > cache-scan > depsdev(file) >
live-network > NOASSERTION**; the deps-dir layers (all fill-only) sit above
cache-scan so an accurate real-source/manifest license beats the legacy
CANN_3RD_LIB_PATH scan and the network snapshots — the live resolver handles
new/unseeded deps when the tree is present, the seeded cache makes the same data
available offline without it; known-map is the (empty)
generic-core map merged with the profile's `known-licenses` source (which carries
the actual content); depsdev(file)
applies a vendored deps.dev/PyPI snapshot ALWAYS (offline + online) just above
live-network. The curated layer applies the profile's `curated_records` Notice —
the declared `License:` line to `comp.license` AND the `Copyright notice:` block
to `comp.copyright` (alias-resolved) — so a component with no concrete license
still gets the Notice's declared license/copyright. The ScanCode **enrich** layer
(`Config.scancode in {enrich, both}`) is the highest-priority license source for
components, and `reconcile.reconcile` runs the subject enrich pass; both stash the
displaced prior value (`Provenance(field="license_prior", …)` on components,
`__scancode_prior_license__` on subjects) and emit `scancode_scan_failed` when a
scan returns no result (component AND subject paths). `cli.main` runs the
**crosscheck** (`Config.scancode in {crosscheck, both}`) post-reconcile, around
emit, and writes the 3-way `license-crosscheck.json`. When ScanCode is unavailable
a `scancode_unavailable` warning is emitted and the run continues with the normal
resolver (never a hard fail). The **fallback** mode (`Config.scancode ==
"fallback"`) is FILL-ONLY: ScanCode sets `license`/`copyright` only where still
unset (never overriding curated/known/pre-seed, no prior stash) — it pairs with
`--deps-dir` for offline resolution of new deps from their real source.

```python
# sbom/enrich/deps_dir.py  (opt-in; gated by Config.deps_dir)
from ..config import Config
from ..models import Component, Provenance, Warning

def apply(components, config, profile=None) -> tuple[list[Warning], dict[str, Path], list[Callable]]:
    """Resolve each component's REAL source under config.deps_dir (offline) and
    FILL its license/copyright. Returns (warnings, source_map, cleanups):
    source_map {comp.name: scannable dir} is handed to the ScanCode enrich layer
    (so it reads copyright + a thorough license from the real tree even for
    components with no local observation); cleanups MUST be invoked after that
    layer to remove temp extractions. Fill-only: sets license/copyright only when
    unset; a manifest license disagreeing with an already-resolved one emits
    deps_dir_license_discrepancy (never a silent override)."""

def resolve_source(component, deps_root, *, tmp_parent=None) -> tuple[ResolvedSource | None, Warning | None]:
    """Locate + materialize a component's source. Three layouts auto-detected:
    (1) plain dir <deps-dir>/<name>/; (2) archive <deps-dir>/<name>-<ver>.tar.gz
    (extracted, BOUNDED surface only); (3) GIT MIRROR (the cann-src-third-party
    convention): <deps-dir>/<name>/ is a git repo whose DEFAULT/master branch is
    informational — its working-tree LICENSE is NEVER read — and whose real
    per-release source lives on a version-named branch (5.0.0.x / 1.1.16x /
    v9.12.x / 5.0.0.x-h0.trunk) holding a release ARCHIVE plus, when present, a
    Huawei `Readme.opensource` manifest (License: + Copyright Notice(s):).
    A mirror with NO matching version branch is SKIPPED with deps_dir_no_branch
    (NEVER falls back to the inaccurate default branch); a repo with no version
    branches at all is a normal clone whose working tree IS used."""

def select_branch(repo, version) -> tuple[str | None, list[str]]:
    """(chosen_ref, version_branch_labels). Picks the version-named branch by
    dotted-prefix score (exact > prefix), preferring a CLEAN branch over a
    `-suffix` variant (5.0.0.x over 5.0.0.x-h0.trunk) then the shortest label.
    chosen_ref is None when it IS a mirror but nothing matches (caller skips);
    labels == [] means a normal clone (caller may use the working tree)."""

def parse_manifest(text) -> Manifest:
    """Parse Readme.opensource: the FIRST (primary) License: token + its Full
    License Text, and the global Copyright Notice(s) block. Subsequent License:
    blocks are IGNORED (a manifest bundling sub-licenses lists the real one first).
    Manifest.resolved_license() prefers a precise License: token, falling back to a
    cache_scan heuristic on the full text for a vague token (bare BSD/GPL/…)."""

# sbom/enrich/deps_dir_cache.py — vendored deps-dir source snapshot (the SEEDED
# offline counterpart of the live --deps-dir resolver; data_source name "deps-dir")
def cache_key(name) -> str: ...                  # lowercased component name (ecosystem-agnostic)
def load(paths) -> dict[str, dict]: ...          # merge cache JSONs (later wins); corrupt skipped
def apply(components, cache) -> list[Warning]:
    """Fill each component's still-unset license + copyright from the cache,
    ALIAS-AWARE (securec ↔ libboundscheck). Fill-only; records
    Provenance(source="deps-dir-cache"). NOT Python-only — the primary offline
    license source for the seeded C++ long tail. File shape:
    {"schema":1,"entries":{"<name>":{"license","copyright","version","source","fetched"}}}."""
def dump(entries) -> str: ...                     # deterministic, schema 1
```

Seeded by `--refresh-data deps-dir --deps-dir <tree> [--scancode fallback]`
(`refresh._refresh_deps_dir_cache`): TREE-DRIVEN — walks every dependency dir
under `--deps-dir`, resolves each via `deps_dir.resolve_source` (latest version
branch for a mirror) + ScanCode for the hard cases, and rewrites the cache
(name-keyed; license is version-stable so one entry per dep). Offline; excluded
from `--refresh-data all` (it needs `--deps-dir`).

(`cache_scan._spdx_match` also recognizes **MulanPSL-1.0/2.0** — common in the
CANN ecosystem — via the coscl.org.cn URL marker and the Chinese title.)

---

## sbom/data_sources.py — vendored-data-file registry

```python
CURATED = "curated"; DERIVED = "derived"; NETWORK = "network"

@dataclass(frozen=True)
class DataSource:
    name: str         # "known-licenses" | "depsdev" | "aliases" | "first-party"
    kind: str         # CURATED | DERIVED | NETWORK
    path: Path        # vendored file (read; written for refreshable kinds)
    fmt: str = "yaml" # "yaml" | "json"
    description: str = ""

def core_data_sources() -> list[DataSource]:      # generic-core built-ins
    """known-licenses + depsdev + clearlydefined under src/sbom/data/ —
    all ship EMPTY; the active profile supplies the content (merged on top)."""

def build_data_sources(profile) -> list[DataSource]:
    """Core built-ins, THEN profile.data_sources() appended. A profile source
    reusing a core `name` is an override kept LAST so map merges (core→profile)
    let the profile win and the LAST entry is the refresh write target. Tolerant
    of a stub profile without the hook."""

def sources_named(sources, name) -> list[DataSource]:  # precedence order (core, …, profile)
```

The shared names live in BOTH layers (profile-override hybrid), but the generic
core files in `src/sbom/data/` SHIP EMPTY — the CANN copies in
`src/sbom_profile_cann/data/` carry the content (`known_licenses.yaml` is the OSS
map; `depsdev_cache.json` / `clearlydefined_cache.json` the snapshots). `aliases`,
`first-party` and `third-party-purls` (name -> upstream PURL coordinate, for C++
component ids) are CANN-only. The generic core NEVER imports profile data — the
profile pushes its sources through `Profile.data_sources()`; a non-CANN profile
supplies its own (or gets an empty known-map).

## sbom/refresh.py — `--refresh-data` actions (no SBOM emitted)

```python
def run_refresh(config: Config) -> int:
    """Dispatched by cli.main when config.refresh_data is set (a source name or
    "all"); returns an exit code (0 ok; nonzero on a validation issue/hard error).
      • depsdev (NETWORK): collect the repo's Python deps, (re-)fetch each
        via net.resolve_pypi, UPSERT into the cache JSON (sorted, `fetched`
        stamp) at config.depsdev_cache or the last depsdev source. The ONLY
        cache writer; requires --network on.
      • aliases (DERIVED): run reconcile._derive_aliases over the repo and write
        NEW raw→canonical suggestions to <aliases>.suggested.yaml (review, then
        merge by hand — never auto-merged).
      • first-party / known-licenses (CURATED): VALIDATE only (duplicate keys +
        invalid SPDX values). Not rewritten — curated section comments would be
        lost to an automated dump."""
```

---

## sbom/reconcile.py — merge collected records into one Document

```python
from __future__ import annotations
from .config import Config
from .models import Document, Warning
from .profile import Profile
from .collectors import CollectResult

def reconcile(
    results: list[CollectResult],
    subjects: list,            # list[Subject] (authoritative subject set)
    config: Config,
    profile: Profile,
) -> Document:
    """Merge all collector outputs into a single Document:
      • build the alias resolver: config `[aliases]` > profile.alias_map() >
        built-in OSS aliases (gtest≡googletest, json≡nlohmann-json) > on-the-fly
        derivation (canonical from a component's download-archive URL);
      • de-dup components by alias-resolved canonical name; UNION scopes,
        languages, integrity_findings, provenances; attach all observations;
      • keep source_version vs effective_version separate; flag mismatches as
        patched-build notes (protobuf 25.1 vs 3.13.0);
      • version pins: a Python `==`/`===` exact pin (set by the collector) is a
        concrete version; when two observations carry DIFFERENT concrete pins for
        one component, keep the lowest (PEP 440) and emit `version_pin_conflict`.
        When NO observation yields a concrete version (bare/range Python deps,
        CANN `>=8.5` package deps), set completeness["version"]="unpinned" — a
        component that already has a concrete source/effective version (eigen
        5.0.0, protobuf) is NEVER marked;
      • derive Component.depends_on rollup from edges (edges remain authority);
      • run the license layers in order (curated > known_licenses > cache_scan >
        depsdev(file) > net), recording Provenance and discrepancy warnings
        when layers disagree. The known_licenses map is the (empty) generic-core
        default MERGED with the active profile's `known-licenses` source, which
        carries the content (profile wins).
        The depsdev layer applies a vendored deps.dev/PyPI snapshot ALWAYS
        (offline + online), just above live `net`, so a cached hit avoids a call;
      • classify supply-chain provenance — stamp `Component.origin`
        (first-party | third-party | unknown): the profile's
        `component_provenance(comp)` verdict is authoritative; otherwise a published
        Python package, a real upstream `scheme://` download URL, or a concrete OSS
        license id (not NOASSERTION / not a `LicenseRef-*` placeholder) ⇒
        third-party, else unknown. Runs AFTER licenses/aliases settle;
      • resolve a PURL for NON-Python components (`Component.purl`, via
        `_resolve_component_purls`): curated upstream coordinate (profile
        `third-party-purls` -> `pkg:github`/`pkg:gitlab`) > mirror
        `pkg:generic?download_url=` > first-party `pkg:generic?vcs_url=` > none;
      • fill the NTIA Supplier element (`Component`/`Subject.supplier`): the
        ClearlyDefined snapshot (third-party git-org supplier + copyright) then
        `profile.first_party_supplier()` for subjects + first-party components;
        the depsdev layer also fills supplier from PyPI author. Unknown ->
        emitted as NOASSERTION (the honest known-unknown);
      • raise `unmapped_link_library` for any external link token not covered by
        an alias; carry every edge's root_artifact_id through unchanged.
    At the tail (still the only Document producer), apply the config-driven
    filters in order: (1) usage-scope filter — two composable axes: the EXCLUSION
    set `excluded_usage_scopes(config)` (drop when usage_scope is in it; None is
    KEPT) and the optional KEEP-ONLY set `release_keep_usage_scopes(config)`
    (when not None, survive IFF usage_scope is in it, so None and non-runtime are
    dropped); a record drops when (usage_scope in excluded) OR (keep_only is not
    None AND usage_scope not in keep_only). Recompute Component.scopes, drop
    now-empty components and any edge whose endpoint was dropped or that the filter
    drops, emitting one summarising `excluded_scope` Warning; (2) `--subjects`
    closure — keep only the named subjects + their BFS dependency closure + edges
    among kept nodes + EnvironmentTools rooted on a kept subject (promoting the
    lowest-role kept subject to root if the primary was dropped); (3)
    `--no-env-tools` — clear environment_tools.
    The `release` scope preset (the DEFAULT view) feeds these same inputs
    additively: `excluded_usage_scopes(config)` folds in its runtime-only
    exclusion base, `release_keep_usage_scopes(config)` adds the keep-only-runtime
    axis (so unclassified None observations are dropped under release), and
    `release_no_env_tools(config)` is ORed into (3); the role half is applied
    earlier in `discover_subjects`. `--scope all` contributes nothing, so only the
    user's explicit flags filter.
    Returns the Document (subjects, components, edges, environment_tools,
    warnings, metadata). This is the ONLY function that produces a Document."""

def build_alias_resolver(
    profile: Profile, config=None, components=None,
) -> "AliasResolver":
    """Combine every alias layer into a resolver mapping any spelling →
    (canonical_name, relation_type|None). Precedence (highest wins): config
    `[aliases]` > profile.alias_map() > built-in OSS aliases > on-the-fly
    derivation (canonical name read from a component's download-archive URL, e.g.
    `external_eigen_nn` → `eigen`). `config`/`components` are optional; passing only
    `profile` keeps the curated-only behaviour."""
```

`AliasResolver` is a small helper class defined in this module:

```python
class AliasResolver:
    def canonical(self, name: str) -> str: ...
    def relation(self, name: str) -> str | None: ...   # RelationType value or None
    def is_known(self, name: str) -> bool: ...
```

---

## sbom/emit/cyclonedx.py — CycloneDX 1.5 JSON

```python
from __future__ import annotations
from ..models import Document
from . import EmitOptions

def emit(document: Document, options: EmitOptions) -> str:
    """Build a CycloneDX 1.5 BOM via cyclonedx-python-lib's object model and
    serialize to JSON. Implements the design mapping table: subjects →
    metadata.component + components/separate BOMs; DependencyEdge → dependencies
    rooted at the owning subject/component; EnvironmentTool → properties
    `sbomgen:envtool:*` (never components); source/effective version + patches →
    pedigree; URLs → externalReferences (with options.guess_pypi_urls, a Python
    component also gets a constructed https://pypi.org/project/<name>/[<version>/]
    DISTRIBUTION externalReference); checksums → hashes; integrity_findings
    + observations + reachability + activation + usage_scope + root_artifact_id →
    `sbomgen:*` properties (+ scope for runtime/optional); `Component.origin` →
    `sbomgen:component:origin` (first-party|third-party|unknown, kept in compact);
    `supplier` → component `supplier` (OrganizationalEntity); copyright → component
    copyright; non-SPDX license →
    license.text + license.name. All custom property/annotation keys use the
    tool-owned namespace `sbomgen:` (PROP_NS; named after this tool, not any repo;
    used for all repos including generic ones).
    options.detail gates verbosity: 'compact' (default) OMITS the per-observation
    `sbomgen:obs:N:*` properties and the evidence.occurrences array; 'full'
    restores them. When emitted, evidence.occurrences is deduped to one entry per
    unique source location. Subject bom-refs are made unique via
    _common.disambiguate_subject_ids so distinct roots that share a Subject.id /
    slug never collide. With options.reproducible: fixed timestamp,
    serialNumber derived from a content hash, stable ordering.
    Returns the JSON string. When options.split_subjects, see emit_split()."""

def emit_split(document: Document, options: EmitOptions) -> dict[str, str]:
    """Emit one sub-BOM per subject (filtered by options.subjects if set).
    Returns {subject_id: json_string}."""
```

## sbom/emit/spdx.py — SPDX 2.3 JSON

```python
from __future__ import annotations
from ..models import Document
from . import EmitOptions

def emit(document: Document, options: EmitOptions) -> str:
    """Build an SPDX 2.3 document via spdx-tools' object model and serialize to
    JSON. Mapping table: each subject → a Package with a DESCRIBES relationship;
    DependencyEdge → RELATIONSHIP DEPENDS_ON / BUILD_DEPENDENCY_OF /
    GENERATED_FROM with the owning Package as endpoint; EnvironmentTool →
    annotations (never Packages); PURL → externalRef (PACKAGE-MANAGER/purl), not
    the SPDXID; checksums → Package.checksums; integrity_findings/observations/
    reachability/activation/usage_scope/root/alias → annotations; non-SPDX
    license → LicenseRef-… + hasExtractedLicensingInfos; completeness →
    per-component sbomgen:completeness:* annotations only (NOT the document comment);
    Component.origin → sbomgen:component:origin annotation (kept in compact);
    supplier → package supplier (Organization Actor; NOASSERTION when unknown).
    options.detail gates verbosity: 'compact' (default) OMITS the per-observation
    `sbomgen:obs:N:*` annotations; 'full' restores them (the summary
    integrity/completeness/alias/subject annotations stay in both modes). Subject
    SPDXRef ids are made unique via _common.disambiguate_subject_ids so distinct
    roots that share a Subject.id / slug never produce duplicate SPDXRef-Subject-*
    (invalid SPDX); DESCRIBES + edge endpoints use the disambiguated id.
    With options.guess_pypi_urls a Python component with no resolved URL gets a
    constructed https://pypi.org/project/<name>/[<version>/] downloadLocation.
    With options.reproducible: fixed created timestamp + documentNamespace
    derived from a content hash. Returns the JSON string."""

def emit_split(document: Document, options: EmitOptions) -> dict[str, str]:
    """One SPDX doc per subject. Returns {subject_id: json_string}."""
```

## sbom/emit/validate.py — schema validation via official libs

```python
from __future__ import annotations
from ..models import Warning

def validate_cyclonedx(json_text: str) -> list[Warning]:
    """Validate against CycloneDX 1.5 using cyclonedx-python-lib's own validator.
    Returns [] on success, else one Warning(code="cyclonedx_invalid", …) per
    issue. No vendored schema."""

def validate_spdx(json_text: str) -> list[Warning]:
    """Validate against SPDX 2.3 using spdx-tools' validator. Returns [] on
    success, else Warning(code="spdx_invalid", …) per issue."""
```

---

## sbom/config.py — CLI/config parsing

```python
from __future__ import annotations
from pathlib import Path
from dataclasses import dataclass, field
from .models import SubjectRole, UsageScope, Warning

@dataclass
class Config:   # full field list shown in "Shared support types" above
    ...        # exclude_scopes: list[str] — RAW --exclude-scope tokens, not enums

def parse_args(argv: list[str] | None = None) -> Config:
    """Parse the `sbom` CLI flags (design §CLI) into a Config. Honors --config
    sbom.toml (same keys; tomllib), with CLI flags overriding file values.
    Enforces flag relations: --resolve-cmake-ref implies --network on; default
    collector-mode=static, cmake-source-authority=actual-build. Repeatable
    --cmake-define KEY=VALUE → cmake_defines; --profile-value KEY=VALUE →
    profile_values; --exclude-scope csv → exclude_scopes (kept as RAW string
    tokens; the role/scope bridge is `resolve_exclude_scope`, not parse_args)."""

def load_config_file(path: Path) -> dict:
    """Load sbom.toml via tomllib and return the raw nested dict ([cmake.defines],
    [profile.values], …). Pure load; merge/precedence handled by parse_args."""

def resolve_exclude_scope(token: str) -> tuple[SubjectRole | None, UsageScope | None]:
    """THE one bridge from a raw `--exclude-scope` token to the two enum axes.

    `Config.exclude_scopes` holds raw string tokens because the two axes are NOT
    the same set: a token may name a SubjectRole (root/subject exclusion), a
    UsageScope (observation filtering), or both. This single helper maps a token
    so cli/config and the subject collector agree — stated here once:

      token                    SubjectRole                      UsageScope
      ----------------------   ------------------------------   ------------------
      "example"                SubjectRole.EXAMPLE              UsageScope.EXAMPLE
      "st_test"                SubjectRole.ST_TEST              UsageScope.ST_TEST
      "manual_example"         SubjectRole.MANUAL_EXAMPLE       UsageScope.MANUAL_EXAMPLE
      "experimental"           SubjectRole.EXPERIMENTAL         UsageScope.EXPERIMENTAL
      "non_distributable_test" SubjectRole.NON_DISTRIBUTABLE_TEST   None  ← role only
      "test"                   None                             UsageScope.TEST
      "build"                  None                             UsageScope.BUILD
      "runtime"                None                             UsageScope.RUNTIME

    Returns `(role|None, usage_scope|None)`. A token with a role is used by
    `discover_subjects` (∪ `profile.root_exclusion_policy()`) to DROP roots,
    emitting an `excluded_scope` Warning per dropped root. A token with a
    UsageScope filters observations. `non_distributable_test` is expressible as a
    SubjectRole with NO UsageScope. An unknown token → (None, None) and an
    `excluded_scope` Warning noting the token was unrecognized."""

def excluded_usage_scopes(config_or_tokens: Config | list[str]) -> set[UsageScope]:
    """Resolve the UsageScope half of `--exclude-scope` to a concrete set.

    Maps each raw token (from `config.exclude_scopes` or a bare token list)
    through `resolve_exclude_scope` and collects the non-None UsageScope halves.
    When given a Config, the `release` scope preset's runtime-only base
    (`release_excluded_usage_scopes`) is UNIONed in additively, so an explicit
    `--exclude-scope` still applies on top in both `release` and `all` modes.
    This is the usage-scope counterpart of the SubjectRole filtering already done
    by `discover_subjects`; `reconcile` calls it to drop observations/edges whose
    usage scope is excluded (the post-assembly Document transform). Role-only
    tokens (`non_distributable_test`) and unknown tokens contribute nothing."""

# --- The `--scope` view preset (release is the DEFAULT; all is the escape hatch).
# The preset is NOT a parallel filtering path: it expands ADDITIVELY into the same
# transform inputs the explicit flags feed (excluded usage scopes + excluded roles
# + no_env_tools + the keep-only runtime axis). `--scope all` returns empty/False/
# None from all of them, leaving only whatever the user requested explicitly.
ALL_USAGE_SCOPES: frozenset[UsageScope]   # = frozenset(UsageScope)

def release_excluded_usage_scopes(config: Config | None) -> set[UsageScope]:
    """release: `ALL_USAGE_SCOPES - {RUNTIME}` (the runtime-only view); all: empty.
    Folded into `excluded_usage_scopes(config)`. This is the EXCLUSION axis (keeps
    usage_scope=None); the stricter keep-only axis below drops None."""

def release_excluded_roles(config: Config | None) -> set[SubjectRole]:
    """release: `{EXAMPLE, EXPERIMENTAL, ST_TEST, MANUAL_EXAMPLE,
    NON_DISTRIBUTABLE_TEST}` (keep primary + sibling wheels + the primary
    cmake_project/unclassified root); all: empty. `discover_subjects` UNIONs this
    with `profile.root_exclusion_policy()` and the explicit role tokens."""

def release_no_env_tools(config: Config | None) -> bool:
    """release: True (the runtime view omits host build tools); all: False.
    ORed with the explicit `--no-env-tools` flag in reconcile's transform."""

def release_keep_usage_scopes(config: Config | None) -> set[UsageScope] | None:
    """release: `{RUNTIME}`; all: None. The KEEP-ONLY usage-scope axis: when not
    None an observation/edge survives reconcile's transform IFF its usage_scope is
    in the set — so usage_scope=None AND every non-runtime scope are dropped (keep
    only RUNTIME; unclassified/None observations are dropped under release). This
    is stricter than `release_excluded_usage_scopes` (which keeps None). reconcile
    applies BOTH axes: drop if (usage_scope in excluded) OR (keep_only is not None
    AND usage_scope not in keep_only); they compose with explicit --exclude-scope
    tokens (which only widen the exclusion set)."""
```

## sbom/cli.py — orchestration entry point

```python
from __future__ import annotations
from .config import Config

def main(argv: list[str] | None = None) -> int:
    """The `sbom` console script (≡ `python -m sbom`). Orchestrates the pipeline:
      1. config = parse_args(argv)
      2. profile, w = get_profile(config.repo_profile, config.repo_root)
         (w carries any `profile_load_failed` warnings — a broken profile entry
         point is surfaced, never a silent downgrade to generic)
      3. authority, w = resolve_cmake_authority(...)            # cmake.parse
      4. subjects, w = subject.discover_subjects(config, profile)
      5. results = [cpp.collect(...), python.collect(...)]
         (cpp.collect invokes the profile package_metadata/build_tooling hooks
         WITH root attribution + edges; they are NOT re-invoked at the cli level)
      6. document = reconcile(results, subjects, config, profile)
      7. for fmt in config.formats: emit + validate; write to out_dir
         (split per subject when config.split_subjects)
    Returns a process exit code (0 ok; non-zero on fatal/validation failure per
    policy). All warnings collected into document.warnings."""

def run(config: Config):   # -> Document
    """Programmatic entry (no argv parsing). Same pipeline as main, returns the
    Document so library callers/tests can inspect it without writing files."""
```

## sbom/__main__.py — `python -m sbom`

```python
from __future__ import annotations
import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

---

## sbom/profile.py — Profile ABC + registry/auto-detect

The `Profile` ABC and `GenericProfile` are foundation. The registry functions
return their warnings as first-class records (a broken profile entry point is
NEVER a silent downgrade to generic):

```python
def load_profiles() -> tuple[dict[str, type[Profile]], list[Warning]]:
    """{entry_point_name: Profile_subclass} (always incl. "generic") + warnings.
    An entry point that fails to import / isn't a Profile subclass is skipped
    AND recorded as Warning(code="profile_load_failed", subject=<ep name>,
    detail=<error>)."""

def detect_profile(repo_root: Path) -> tuple[str | None, list[Warning]]:
    """Auto-detect by calling each non-generic profile's classmethod
    detect(repo_root) -> bool (the registry's detection contract). Returns the
    first matching entry-point name (or None) + any load warnings."""

def get_profile(
    name: str | None, repo_root: Path | None = None
) -> tuple[Profile, list[Warning]]:
    """Resolve a profile instance ("auto"/None ⇒ detect_profile). Returns
    (profile, warnings); warnings carry profile_load_failed records."""
```

`Profile` adds a detection hook used by the registry:

```python
class Profile(ABC):
    name: str = "generic"

    @classmethod
    def detect(cls, repo_root: Path) -> bool:
        """True if this profile applies to repo_root. Base default: False
        (GenericProfile is the explicit fallback). Concrete profiles override."""

    def classify_root(
        self, path: Path, cmake_project: Subject, package_context: dict,
    ) -> SubjectRole: ...

    def subject_facets(self, subjects: list[Subject]) -> list[SubjectMerge]:
        """Drive the wheel↔CMake merge — see discover_subjects narration."""

    def repo_origin(self, repo_root: Path) -> "RepoOrigin | None":
        """Optional canonical VCS origin (sbom.origin.RepoOrigin). Base default:
        None — the core resolves it from --repo-url or .git/config instead."""

    def component_provenance(self, component: Component) -> str | None:
        """Declare a dependency's supply-chain provenance class, or None. Return
        "first-party" when the profile KNOWS the component is its own / a sibling
        org component; None lets the core classify it (third-party when it has a
        real upstream URL or is a published Python package, else unknown). The
        profile verdict is authoritative. Base default: None."""

    def first_party_supplier(self) -> str | None:
        """The supplier (publishing org) for the repo's OWN artifacts — fills the
        NTIA Supplier element for repo-owned subjects + first-party components
        (CANN -> "Huawei Technologies Co., Ltd."). Third-party suppliers come from
        the depsdev cache (PyPI author) / ClearlyDefined. Base default: None."""

    def data_sources(self) -> list:  # list[sbom.data_sources.DataSource]
        """Vendored data files this profile contributes. A source whose `name`
        matches a generic-core source ("known-licenses", "depsdev")
        OVERRIDES/EXTENDS it (merged on top, profile wins); a new name ("aliases",
        "first-party") adds a profile-only source. The core never imports profile
        data — the profile PUSHES its sources here. Drives map merges +
        --refresh-data. Base default: []."""
```

---

## sbom_profile_cann — the CANN profile (implemented later)

```python
from __future__ import annotations
from sbom.profile import Profile

class CannProfile(Profile):
    """Concrete Profile registered as `cann` in the `sbom.profiles` group.
    Implements (per the Profile ABC):
      • custom_dep_macros → {"add_cann_third_party": <resolver to
        <effective_cmake_root>/third_party/<name>.cmake>}
      • package_metadata → version.cmake set_cann_* deps with >= constraints
      • build_tooling → cann-cmake component for the acquiring fetch branches;
        none for skipped_existing_project / cmake-as-input
      • curated_enrichers → Third_Party_*_List.yaml + *_Notice parsers
      • alias_map → CANN canonical-name map w/ relation types (OPBASE≡opbase,
        tilingapi≡tiling_api, ASC≡asc-devkit, securec/c_sec, torch_npu, …)
      • subject_license_default → LicenseRef-CANN-Open-Software-License-2.0
        (subjects only); dependency_license_default → the license VALUE mapped in
        data/first_party_licenses.yaml for a recognized first-party name (CANN-Open
        for the open-sourced ones), else None — a null-valued (closed-source) entry
        returns None so its license stays NOASSERTION
      • component_provenance → "first-party" for a CANN-internal lib / sibling
        package (a KEY in first_party_licenses.yaml, by name or alias — including
        closed-source null-licensed entries like bisheng-compiler) OR a component
        fetched from the org namespace gitcode.com/cann/<repo>; None otherwise. The
        look-alike third-party mirrors (gitcode.com/cann-src-third-party/, the
        cann-3rd.obs.<region>.myhuaweicloud.com bucket) deliberately do NOT match.
        Provenance (who made it) is orthogonal to license (open vs closed)
      • condition_vocabulary → TOPLEVEL_PROJECT/ENABLE_*/PRODUCT_SIDE/…
      • classify_root → example/st_test/manual_example/experimental/
        non_distributable_test by path (a `sample`/`samples` path segment → example)
      • root_exclusion_policy → policy-driven excluded roles
      • subject_facets → bind ascend_ops≡AscendOps, ops_math≡math
    name = "cann". MUST NOT be imported by the generic core except via the
    entry-point registry (load_profiles)."""
    name = "cann"

    @classmethod
    def detect(cls, repo_root: Path) -> bool:
        """True when repo_root uses the CANN macro: an `add_cann_third_party(`
        usage in any CMakeLists.txt/*.cmake under repo_root, OR a sibling/
        --cmake-root `cmake/function/prepare.cmake` marker."""
```

The `cann` entry point is declared in `pyproject.toml`:
`[project.entry-points."sbom.profiles"] cann = "sbom_profile_cann:CannProfile"`.
A MINIMAL working stub now exists: `CannProfile` with `name = "cann"` and the
`detect` classmethod above; every other hook inherits the `Profile` ABC's
neutral default (the full CANN logic — macros, package_metadata, build_tooling,
enrichers, alias_map, license defaults, condition vocabulary, classify_root,
root_exclusion_policy, subject_facets — lands in a later phase). The package
imports cleanly and `CannProfile` is instantiable, so `load_profiles()` resolves
`cann` and auto-detect picks it on a CANN repo.
