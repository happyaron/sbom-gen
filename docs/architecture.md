# Architecture — data model & pipeline

This page describes the internal model the generator flows through and the three
stages that operate on it. It is the reference companion to the
[README](../README.md); the frozen module signatures live in
[`INTERFACE.md`](../INTERFACE.md), and the CMake-authority subtlety has its own
page, [docs/cmake-authority.md](cmake-authority.md). For the CLI flags that drive
all of this, see [docs/cli.md](cli.md); for writing a repo plugin, see
[docs/profiles.md](profiles.md).

The model lives in one dependency-free module, `src/sbom/models.py` (standard
library only). It is the single source of truth for the shapes that move through
**Collect → Reconcile → Emit**, and any field change has to be made there,
in `INTERFACE.md`, and in `src/sbom/profile.py` together.

## The pipeline at a glance

```
repo_root ─┐
--cmake-root├─▶ Collect ──▶ list[CollectResult]
config      │   • subject.discover_subjects() → list[Subject]
profile     │   • cpp.collect(...)            → CollectResult
            │   • python.collect(...)         → CollectResult
            └──────────────┬──────────────────┘
                           ▼
                    Reconcile  reconcile.reconcile(results, subjects, config, profile)
                           │   • alias de-dup + union scopes/langs/integrity/prov
                           │   • attach observations to components
                           │   • derive Component.depends_on rollup from edges
                           │   • layered license resolver
                           ▼
                      Document (the ONLY producer of one)
                           │
                           ▼
                      Emit
                       • cyclonedx.emit(document, options) → str   (CycloneDX 1.5)
                       • spdx.emit(document, options)       → str   (SPDX 2.3)
                       • validate.validate_*(text)          → [Warning]
```

The orchestration lives in `sbom.cli.main` / `sbom.cli.run`; the latter returns
the `Document` so callers and tests can inspect it without writing files.

### Invariants the stages must honour

These are enforced across the codebase and asserted by the drift suite:

- **Collectors return lists of model records** — a `CollectResult` of
  `Observation`/`Component`/`Subject`/`DependencyEdge`/`EnvironmentTool`/`Warning`.
  They never emit a partial SBOM and never mutate global state
  (`src/sbom/collectors/__init__.py`).
- **`reconcile` is the only stage that produces a `Document`.** Emitters only
  read it (`src/sbom/reconcile.py:612`).
- **An `EnvironmentTool` is never turned into a `Component`** — there is
  deliberately no `environment_tool` member of `SourceKind`
  (`src/sbom/models.py:35`).
- **`declaration_reachability` and `usage_scope` are kept separate** and never
  collapsed into one "scope".
- **Every collector-produced `Observation`/`DependencyEdge` carries
  `root_artifact_id`** so per-subject ownership survives reconcile and emit.
- **Emitters build via the official libraries' object models**
  (`cyclonedx-python-lib`, `spdx-tools`) — no hand-rolled JSON, no vendored
  schemas.

### What a real run produces

Running the generator on the reference repo gives a feel for the scale of the
model:

```bash
.venv/bin/python -m sbom \
  --repo-root ../ops-math --repo-profile cann --cmake-root ../cmake \
  --reproducible --scope all --out-dir ./out
```

```
sbom: generated SBOM
  subjects=11 components=53 edges=175 environment_tools=116
  wrote out/sbom.cdx.json
  wrote out/sbom.spdx.json
  warnings: 17
    license_unresolved: 5
    patched_build: 1
    unmapped_link_library: 11
```

(This is the full `--scope all` view; the default `--scope release` keeps only the
distributable subjects + their runtime closure and drops environment tools.)

The 11 subjects, 53 components, 175 typed edges, and 116 environment tools are
exactly the `Document` lists described below; the warning counts (sorted by code)
are the structured `Warning` records covered in [`Warning`](#warning).

---

## The data model

### `Subject` (a.k.a. `RootArtifact`)

A distributable root artifact — a thing the repo *builds*. The repo produces
several (the top-level CANN package, sibling Python wheels, standalone CMake
example/ST roots), each with its own identity and dependency set. `Subject` and
`RootArtifact` are the same class; `RootArtifact = Subject` is an alias
(`src/sbom/models.py:333`).

| Field | Type | Meaning |
|-------|------|---------|
| `id` | `str` | Stable subject id (e.g. `ops_math`); used as the edge `root_artifact_id`. |
| `identity` | `Identity` | `kind` (`cann_package`/`python_wheel`/`cmake_project`) + `name` + optional `version`. |
| `role` | `SubjectRole` | `primary`, `sibling_artifact`, the path-semantic roles (`example`/`st_test`/`manual_example`/`experimental`/`non_distributable_test`), or the generic-core `cmake_project`/`unclassified`. |
| `facets` | `list[Facet]` | Alternate identities of the **same** artifact (a wheel ≡ its CMake project). |
| `build_graph_root_id` | `str \| None` | The `cmake_project` root that builds this subject. |
| `emit_as_subject` | `bool` | `False` for ownership-only grouping roots (non-distributable test/manual): they group deps but are not emitted as their own subject. |
| `supplier`, `license`, `license_text` | `str \| None` | Subject-level provenance; `license_text` carries inline text for a non-SPDX license. |
| `source_path`, `repo_revision` | `str \| None` | Where the subject lives and at which revision. |
| `purl` | `str \| None` | Package URL when known. |
| `dependency_scopes` | `list[UsageScope]` | Which scopes' deps belong to **this** subject. |

`Facet` and `Identity` are the same shape (`kind`/`name`/`version`); a facet
records an *alternate* identity, an identity records the *primary* one. The
wheel↔CMake merge that produces facets is driven by `SubjectMerge` records
returned from `profile.subject_facets()` (see
[docs/profiles.md](profiles.md)): each merge folds `absorbed_subject_id` into
`keep_subject_id`, records the absorbed identity on the kept subject's `facets`,
and sets its `build_graph_root_id`.

`emit_as_subject=False` matters at emit time: both emitters skip such subjects as
top-level entries (`src/sbom/emit/spdx.py:113`, and the CycloneDX
`extra_subjects` filter at `src/sbom/emit/cyclonedx.py:127`), but their owned
edges still carry the grouping id.

### `Component`

A normalized dependency: a unioned scalar summary plus the per-site
`Observation`s it was seen through. Scalar fields stay `None`/`NOASSERTION` until
an enricher proves a value; the list fields are **unioned** across observations
during reconcile.

| Field | Type | Meaning |
|-------|------|---------|
| `name` | `str` | Canonical (alias-resolved) name. |
| `aliases` | `list[str]` | Every other spelling this component was seen under. |
| `type` | `str` | `library` or `application` (an `application` in any merge wins). |
| `languages` | `list[str]` | Unioned across observations. |
| `scopes` | `list[UsageScope]` | Unioned `usage_scope` values — a dep can be both `runtime` and `build`, or `test` and `build`. |
| `source_version` / `effective_version` | `str \| None` | Kept **separate**: the upstream/declared version vs. the version that actually ships after CANN build patches. A mismatch is a patched build, not an error. |
| `patches` | `list[Patch]` | Applied patches with their content `sha256`. |
| `supplier`, `license`, `copyright` | `str \| None` | Scalar summary; first proven value wins on merge. |
| `origin` | `str \| None` | Supply-chain provenance class **DERIVED by reconcile**: `first-party` (the repo's own / a sibling-org component) / `third-party` (fetched OSS / published package) / `unknown`. Emitted as `sbomgen:component:origin`. |
| `purl` | `str \| None` | A pre-resolved PURL for **non-Python** components **DERIVED by reconcile** (curated upstream coordinate > mirror `download_url` > first-party `vcs_url`); emitters serialize it verbatim. Python purls are derived at emit. |
| `checksums` | `dict` | e.g. `{"sha256": ...}`. |
| `vcs_ref` | `VcsRef \| None` | `requested` vs `resolved_commit`. |
| `integrity_findings` | `list[IntegrityFinding]` | Unioned: `no_hash`, `unpinned_git`, `tls_verification_disabled`, `local_source_unverified`. |
| `completeness` | `dict` | e.g. `{"python_transitives": "unresolved"}` in static mode. |
| `depends_on` | `list[str]` | **Derived rollup** from `component → component` edges; the edge list is the authority. |
| `observations` | `list[Observation]` | Every declaration site. |
| `provenance` | `list[Provenance]` | `(field, source)` records (e.g. where the license came from). |

The separation of `source_version` and `effective_version` is load-bearing: on
`ops-math`, protobuf keeps its CMake `source_version=25.1` and gains
`effective_version=3.13.0` from the curated Notice, producing exactly one
`patched_build` warning. `depends_on` is *derived* — reconcile reads only
`component → component` edges into it (`src/sbom/reconcile.py:399`); a
`subject → component` edge is never collapsed into a rollup because ownership
belongs on the edge.

### `Observation`

One declaration site / mechanism for a component. This is where the model's two
orthogonal axes live, and they are **never collapsed**:

- **`declaration_reachability`** — *is the declaration reached?* One of `reached`,
  `unresolved`, `unreachable` (`DeclarationReachability`). When `unreachable`,
  `unreachable_reason` says why (e.g. `dead_config_flag`).
- **`usage_scope`** — *what is it for?* One of `runtime`, `test`, `build`,
  `example`, `st_test`, `manual_example`, `experimental`, `environment`
  (`UsageScope`). The scope follows the **call site** (gtest declared in a test
  fragment is `test`), not the file where a third-party fragment is defined.

| Field | Type | Meaning |
|-------|------|---------|
| `source_kind` | `SourceKind` | The declaration mechanism (enum below). |
| `source_file` | `str \| None` | The file the declaration was read from. |
| `source_revision` | `str \| None` | Revision of that file's tree (the cmake tree's revision can differ from the repo's). |
| `root_artifact_id` | `str \| None` | Owning subject id — set on every collector observation. |
| `declaration_reachability` | `DeclarationReachability` | Default `reached`. |
| `unreachable_reason` | `str \| None` | Set when not reached. |
| `activation_condition` | `list[ActivationCondition]` | Raw `if()`/path/env gates, with an optional evaluated boolean. |
| `usage_scope` | `UsageScope \| None` | The intent axis. |
| `version_constraint` | `str \| None` | e.g. a `>=` specifier. |
| `canonical_url` / `resolved_url_or_path` | `str \| None` | Upstream vs. resolved acquisition location. |
| `find_package` | `FindPackageInfo \| None` | `find_package` requiredness (below). |
| `ecosystem_data` | `dict` | Extras, markers, hashes, link target, **and the resolvable component name** — see [the naming convention](#the-naming-convention-ecosystem_dataname). |

`SourceKind` enumerates exactly which mechanism produced an observation; note
there is **no** `environment_tool` member:

```
cmake_external_project   cmake_fetch_content      cmake_find_package
cmake_link_library       cmake_find_program       cmake_imported_executable
cmake_build_tooling      python_requirement       python_setup
python_build             cann_package             installed_binary
curated_notice
```

`FindPackageInfo` captures `find_package` requiredness for a
`cmake_find_package` site: `required`, `quiet`, and `effective_required`. The
last is derived from a nearby fatal check — a call may be `QUIET` yet fatal if
missing — and is `None` when static parsing can't decide. All three surface as
`sbomgen:obs:N:fp_*` properties / annotations.

### `DependencyEdge`

A first-class, per-root dependency relationship with **typed endpoints**. Keeping
edges separate from the component summary preserves *whose* dependency an edge is.

| Field | Type | Meaning |
|-------|------|---------|
| `root_artifact_id` | `str \| None` | The owning subject — a wheel's `torch` edge belongs to that wheel, not the top-level package. |
| `from_ref` / `to_ref` | `Ref` | Typed endpoints: `Ref.kind` is `subject` or `component`, `Ref.id` is a `Subject.id` or a `Component.name`. |
| `relation_type` | `RelationType` | `depends_on`, `build_dependency_of`, `link`, `tooling`. |
| `usage_scope` | `UsageScope \| None` | Optional scope on the edge. |
| `declaration_reachability` | `DeclarationReachability` | Default `reached`. |
| `source_file`, `source_revision` | `str \| None` | Provenance. |

Typed endpoints let the model express `subject → component` and
`component → component` edges without inventing hidden records (`Ref` is the
endpoint type, `RefKind` its tag). Reconcile canonicalizes component endpoints
through the alias resolver, drops self-loops and exact duplicates, but leaves
subject endpoints and `root_artifact_id` untouched (`src/sbom/reconcile.py:424`,
`:455`).

### `EnvironmentTool` — and why it is never a `Component`

A generic host tool used during the build — `perl`, `ccache`, `cp`, `python3`,
`bash`, `patch`, `tar`, `chmod`, `$(MAKE)`, system `git`, `cmake -E` internals.
These are *not* dependencies of the artifact; treating them as components would
pollute the dependency graph with the build host's contents. So they are a
**separate top-level record**, emitted only as metadata properties / annotations,
and the design forbids the round trip back into a component by simply not
providing an `environment_tool` `SourceKind`.

The program/tool boundary classifier (`cmake/parse.classify_program`) routes each
invocation to `"component"` (a domain/packaged build tool such as `protoc`,
`bisheng-compiler`, or anything in the profile's tooling allowlist),
`"environment_tool"` (the generic host tools above → an `EnvironmentTool` via
`program_to_environment_tool`), or `"ignore"`.

| Field | Type | Meaning |
|-------|------|---------|
| `name` | `str` | The tool name (argv[0] basename). |
| `path`, `version`, `required` | `str/str/bool \| None` | Resolved facts (`required` mirrors `find_program(... REQUIRED)`). |
| `source_file` | `str \| None` | Where it was found. |
| `source_revision`, `source_authority` | `str \| None` | **Required-by-design** provenance: many tools come from the authoritative `cann-cmake` tree, not the analyzed repo, so this survives an authority-branch change. |
| `command_context` | `CommandContext \| None` | Where the invocation lived: `find_program`, `execute_process`, `add_custom_command`/`_target`, the `ExternalProject_Add` `ep_*` command fields, `patch_command`. |
| `root_artifact_id` | `str \| None` | Owning subject. |
| `activation_condition` | `list[ActivationCondition]` | Gates around the invocation. |

### `CmakeAuthority`

The resolved `fetch_cann_cmake` authority, computed **pre-collection** from
pre-`project()` state, so every `add_cann_third_party()` resolution routes
through `effective_cmake_root` rather than the raw `--cmake-root`.

| Field | Type | Meaning |
|-------|------|---------|
| `branch` | `CmakeAuthorityBranch` | `skipped_existing_project`, `local_dir`, `tarball`, or `git`. |
| `effective_cmake_root` | `Path \| None` | The filesystem path every consumer (parse include resolution, trace, cpp macro resolution) resolves fragments against. |
| `ref` / `revision` | `str \| None` | VCS ref name and resolved commit. |
| `verified` | `bool` | Whether the branch selection was proven. |
| `authority_inputs` | `dict` | The proof inputs that drove branch selection, e.g. `{"cann_3rd_lib_path": {"value": ..., "source": "cli\|cache\|unset"}}`. |

The full subtlety (a bare `CMakeCache.txt` value is ambiguous, the four branches,
`cmake-as-input` policy, mismatch warnings) is documented in
[docs/cmake-authority.md](cmake-authority.md).

### `Warning`

A first-class, structured warning — asserted on by tests and surfaced in output.
`code` is a stable machine code; `subject` and `detail` are optional context.
Codes the pipeline emits include `patched_build`, `license_unresolved`,
`license_discrepancy`, `unmapped_link_library`, `unattached_observation`,
`excluded_scope`, `cyclonedx_invalid`, `spdx_invalid`, and the authority codes
documented separately. A representative real run reports, e.g.,
`license_unresolved` (one per still-NOASSERTION component), one `patched_build`
(protobuf), and a handful of `unmapped_link_library`.

### `Document`

The complete internal SBOM — the output of reconcile, the input to emit. Aliased
`Sbom = Document` (`src/sbom/models.py:492`).

```python
@dataclass
class Document:
    subjects: list[Subject]
    components: list[Component]
    edges: list[DependencyEdge]
    environment_tools: list[EnvironmentTool]
    warnings: list[Warning]
    metadata: dict
```

---

## The naming convention (`ecosystem_data['name']`)

An `Observation` only becomes part of a `Component` if
`reconcile._observation_name` can resolve a name for it
(`src/sbom/reconcile.py:210`). This is load-bearing and a real gotcha:
**any observation that should map to a component must carry its canonical name in
`ecosystem_data['name']`.**

`_observation_name` resolves, in order:

1. an explicit `name` attribute on the observation, if present;
2. `ecosystem_data` keys, in this priority order:
   `name`, `component`, `canonical_name`, `cann_package`, `program`,
   `link_target`, `target`;
3. `obs.find_package.name` for a `cmake_find_package` site.

The legacy keys (`cann_package`, `program`, …) are read defensively because some
producers stash the target spelling there rather than in `name`; without those
fallbacks the `version.cmake` package deps, `find_package` deps, and program/tool
observations would be dropped. An observation with no resolvable name produces an
`unattached_observation` warning and is dropped — so if a dependency "disappears"
from the output, check for that warning and confirm the producer set
`ecosystem_data['name']`.

---

## Reconcile in detail

`reconcile(results, subjects, config, profile)` (`src/sbom/reconcile.py:612`) is
the only `Document` producer. In order it:

1. **Builds the alias resolver** — the built-in OSS table
   (`googletest→gtest`, `nlohmann-json/nlohmann_json→json`,
   `makeself-fetch→makeself`) unioned with `profile.alias_map()`; lookups are
   case-insensitive (`OPBASE`/`opbase` collapse) (`src/sbom/reconcile.py:47`,
   `:60`).
2. **De-dups components** by alias-resolved canonical name, re-keying onto the
   canonical name and **unioning** `aliases`, `languages`, `scopes`,
   `integrity_findings`, `provenance`, `patches`, `depends_on`, and
   `observations`. Scalar fields keep the first proven value; `source_version`
   and `effective_version` stay separate (`src/sbom/reconcile.py:119`).
3. **Attaches observations** to their alias-resolved component (materializing a
   new component for an otherwise-unseen one). A `cmake_link_library` token that
   resolves to nothing and has no alias raises `unmapped_link_library`; any other
   unnamed observation raises `unattached_observation`
   (`src/sbom/reconcile.py:245`).
4. **Canonicalizes and de-dups edges**, then **derives `Component.depends_on`**
   from `component → component` edges only.
5. **Applies curated version records** (profile hook), then flags
   `source_version != effective_version` as `patched_build`.
6. **Runs the layered license resolver** in precedence order:
   ScanCode (when `--scancode enrich`/`both`) > curated (the profile's
   `dependency_license_default` **and** the curated Notice/List — CANN's
   `Third_Party_..._Notice` declared `License:` line) > the `known_licenses.yaml`
   map (empty core merged with the profile override) > **deps-dir** (the
   `--deps-dir` on-disk real-source resolver **and** the seeded
   `deps_dir_cache.json` snapshot — fill-only; real-source/`Readme.opensource`
   licenses for the C++ long tail) > `cache_scan` (offline scan of
   `CANN_3RD_LIB_PATH`/`--deps-dir`) > the vendored `depsdev_cache.json` snapshot
   (always consulted) > `net` (live deps.dev/PyPI, only when
   `config.network == "on"`) > `NOASSERTION`. The curated Notice also supplies
   **copyright** (the `Copyright notice:` block) at copyright precedence
   ScanCode > curated-Notice > deps-dir > none, so a component with no concrete license
   still gets the Notice's declared license/copyright when present (alias-resolved
   — e.g. `libboundscheck` → `securec`, `googletest` → `gtest`). Disagreement
   between the curated and known layers records both and emits
   `license_discrepancy`; a component still unresolved gets `NOASSERTION` and
   `license_unresolved` (`src/sbom/reconcile.py`).
7. **(opt-in) Runs the ScanCode enrich layer** as the **highest-priority**
   license source when `config.scancode in {enrich, both}` (the `fallback` mode
   runs the same scan but FILL-ONLY — it sets `.license`/`.copyright` only where
   still unset, never overriding, and stashes no prior; it pairs with `--deps-dir`
   to resolve new deps from real source). For each subject and
   each component with a local target dir (`scancode.target_dir_for`, plus the
   `--deps-dir` materialized sources), it scans
   the license/copyright surface and — for a *confident* SPDX detection (best
   match score ≥ `CONFIDENCE_THRESHOLD`, default 80; an `unknown-license-reference`
   or below-threshold result is left as NOASSERTION) — overrides `.license`,
   sets the component `copyright` from holders/copyrights, records
   `Provenance(field="license", source="scancode")`, and stashes the displaced
   prior value (`license_prior`) so the crosscheck pass can report what the normal
   resolver would have produced. A non-SPDX `LicenseRef-scancode-*` token is
   mapped through `enrich/licenseref.py` to a synthesized `LicenseRef-<slug>` +
   inline text. ScanCode is a separate install the tool shells out to — never a
   dependency; if it is unavailable, a `scancode_unavailable` warning is emitted
   and the normal resolver result stands (`src/sbom/enrich/scancode.py`).

### The ScanCode crosscheck (QA pass)

When `config.scancode in {crosscheck, both}`, `cli.main` runs a QA pass over the
**finished** `Document` (post-reconcile, around emit) via
`enrich.scancode.crosscheck`. In standalone `crosscheck` mode it changes no
license values: it runs ScanCode on the same subjects/components and compares
ScanCode's SPDX license against the resolved license, emitting a
`license_crosscheck_mismatch` warning per difference. In `both` mode the enrich
layer already applied ScanCode, so the comparison is built from the stashed
displaced-prior values (`ours=<prior> scancode=<applied>`) with no second scan.
Either way it writes `<out_dir>/license-crosscheck.json` =
`[{name, ours, scancode, curated, score, agree}, …]`. The report is **3-way**
where the profile exposes a curated Notice: `curated` is the Notice's declared
license for that component (or `null` when there is none/no profile). `agree`
always reflects the `ours` vs `scancode` comparison — the curated column is
informational and the `license_crosscheck_mismatch` warning semantics are
unchanged. Reconcile owns the enrich layer; the crosscheck is orchestrated in
`cli` because it is a QA pass over the assembled document, not part of producing
it. `cli.run` stashes the resolved profile on the document so the crosscheck can
ask it for curated licenses without re-resolving.

---

## Emit: the CycloneDX / SPDX field-mapping table

Both emitters build via the official object models and serialize to JSON, then
their own validators run (`emit/validate.py`: `validate_cyclonedx`,
`validate_spdx`). Every custom key is namespaced `sbomgen:` (`PROP_NS`,
`src/sbom/emit/_common.py:19`) — a tool-owned namespace (named after this tool,
not any repo), used for all repos including generic ones. CycloneDX uses **properties** + native fields;
SPDX uses **annotations** + native fields. The table below is the mapping as
actually implemented in `src/sbom/emit/cyclonedx.py` and `src/sbom/emit/spdx.py`.

| Model element | CycloneDX 1.5 (`cyclonedx.py`) | SPDX 2.3 (`spdx.py`) |
|---------------|--------------------------------|----------------------|
| **Primary subject** | `metadata.component` (type from identity kind), unique `subject:<id>` bom-ref | a `Package` + `SPDXRef-DOCUMENT DESCRIBES` it, unique `SPDXRef-Subject-<id>` |
| **Other subjects** (`emit_as_subject`) | extra `components` | extra `Package`s + `DESCRIBES` each |
| Subject `id`/`role`/`build_graph_root`/`repo_revision`/`facets`/`dependency_scopes` | `sbomgen:subject:*` properties | `sbomgen:subject:*` annotations |
| Subject `purl` | component `purl` | `externalRef` `PACKAGE-MANAGER`/`purl` (not the SPDXID) |
| **Component** identity + version | `component.name` + `version` (`effective_version or source_version`) | `Package.name` + `versionInfo` (`effective_version or source_version`) |
| `DependencyEdge` graph | `dependencies` via `bom.register_dependency`, rooted at the owning subject/component | `Relationship`: `DEPENDS_ON` / `BUILD_DEPENDENCY_OF` / `BUILD_TOOL_OF` (see relation map) |
| `relation_type` mapping | edge present (typed endpoints resolved to bom-refs) | `depends_on`→`DEPENDS_ON`, `link`→`DEPENDS_ON`, `build_dependency_of`→`BUILD_DEPENDENCY_OF`, `tooling`→`BUILD_TOOL_OF` |
| `source_version`/`effective_version` (mismatch) + `patches` | `component.pedigree` (ancestor + `Patch`/`Diff`, notes) | a `(source)` `Package` the component is `GENERATED_FROM`, plus `sbomgen:pedigree:*` annotations and a package `comment` |
| `canonical_url` / `resolved_url_or_path` | `externalReferences` (`DISTRIBUTION`, comment `canonical_url`/`resolved_url_or_path`); with `--guess-pypi-urls` a Python component also gets a constructed `https://pypi.org/project/<name>/[<version>/]` `DISTRIBUTION` ref + `sbomgen:python:download_url_source=guessed` | `externalRef` + `downloadLocation` (validated; falls back to `NOASSERTION` for non-URLs); with `--guess-pypi-urls` a Python component with no resolved URL uses the constructed `pypi.org/project/...` URL as `downloadLocation` |
| `vcs_ref` | `externalReference` (`VCS`) | — |
| `checksums.sha256` | `component.hashes` (`SHA-256`) | `Package.checksums` (`SHA256`) |
| `integrity_findings` | `sbomgen:integrity:<finding>` = `true` | `sbomgen:integrity:<finding>` annotation |
| `completeness` | `sbomgen:completeness:<key>` properties | per-component `sbomgen:completeness:<key>` annotations **only** (NOT the document `comment`) |
| `aliases` | `sbomgen:alias:name` properties | `sbomgen:alias:name` annotations |
| `languages` | `sbomgen:language` properties | `sbomgen:language` annotations |
| Component `scopes` (rollup) | `sbomgen:obs:usage_scope` properties + native `scope` (runtime→`required`, test/build/example/…→`optional`) | `sbomgen:obs:usage_scope` annotations |
| **Per-observation facts** (`--detail full` only) | `sbomgen:obs:N:*` properties (`source_kind`, `source_file`, `source_revision`, `root`, `reachability`, `unreachable_reason`, `usage_scope`, `version_constraint`, `activation`, `python_build`, `fp_required`/`fp_quiet`/`fp_effective_required`) + `evidence.occurrences` (deduped by location) | `sbomgen:obs:N:*` annotations (same fact set, plus `canonical_url`/`resolved_url_or_path`) |
| **`EnvironmentTool`** | BOM `metadata.properties` `sbomgen:envtool:N:*` (**never** a component) | document `annotations` `sbomgen:envtool:N:*` (**never** a `Package`) |
| Non-SPDX license | `license.name` + `license.text` (`DisjunctiveLicense`) | `LicenseRef-…` + `hasExtractedLicensingInfos` |
| SPDX-valid license | `LicenseExpression` | parsed expression on `licenseConcluded`/`licenseDeclared` |
| Document `metadata` | `sbomgen:doc:<key>` properties | (document-level) |

Notes that are easy to get wrong:

- **`usage_scope` → native scope is lossy by spec.** CycloneDX only has
  `required`/`optional`, so the emitter maps `runtime → required` and the rest of
  the scopes to `optional`; the full scope is always preserved in the
  `sbomgen:obs:*` facts (`src/sbom/emit/cyclonedx.py:84`, `:273`).
- **`BUILD_DEPENDENCY_OF` is inverted in SPDX.** It reads
  "*\<build-dep\> BUILD_DEPENDENCY_OF \<owner\>*", so the dependency is the
  `spdxElementId` and the owner is the `relatedSpdxElement` — the opposite
  direction from `DEPENDS_ON` (`src/sbom/emit/spdx.py:449`).
- **A non-SPDX SPDX download location falls back to `NOASSERTION`.** An
  unexpanded CMake variable like `${CANN_3RD_LIB_PATH}/...` is run through
  spdx-tools' own URI validator and rejected as a `downloadLocation`
  (`src/sbom/emit/spdx.py:595`).
- **Environment tools are filtered by the emitted subject set.** A tool whose
  `root_artifact_id` isn't among the emitted subjects is skipped
  (`src/sbom/emit/cyclonedx.py:493`, `src/sbom/emit/spdx.py:471`).

### Compact (default) vs. full detail

`EmitOptions.detail` (threaded from `Config.detail` / `--detail {compact,full}`)
controls per-component verbosity, orthogonally to the `--scope` view preset:

- **`compact` (the default)** OMITS the verbose per-observation provenance — the
  `sbomgen:obs:N:*` CycloneDX component properties and the `sbomgen:obs:*` SPDX
  annotations (one block per declaration site, the bulk of the file) — and OMITS
  the CycloneDX `evidence.occurrences` array. It KEEPS everything that makes the
  BOM readable and useful: each component's name/version/type/`purl`/licenses/
  copyright/hashes, the full dependency graph + relationships, and the summary
  signals `sbomgen:integrity:*`, `sbomgen:completeness:*`, `sbomgen:alias:*`,
  `sbomgen:subject:*`, `sbomgen:pedigree:*` (and the CycloneDX `pedigree` / SPDX
  `GENERATED_FROM`).
- **`full`** restores the complete output: all `sbomgen:obs:*` properties/
  annotations plus the `evidence.occurrences` array.

Both modes pass the official validators and are byte-identical under
`--reproducible`. The gate lives in `_add_component_properties`
(`src/sbom/emit/cyclonedx.py`) and `_annotate_component`
(`src/sbom/emit/spdx.py`); subject `sbomgen:subject:*` and the
integrity/completeness/alias/language summary are emitted in both modes.

**Occurrence dedup (both modes).** When `evidence.occurrences` is emitted (i.e.
in `full`), `_deduped_occurrences` (`src/sbom/emit/cyclonedx.py`) collapses
observations to **one occurrence per unique source location**. A dependency
declared by many roots at the SAME `source_file` (the real `cann_device` had 63
identical-location entries across the runtime repo's sample projects) yields a
single occurrence. The occurrence `bom-ref` is the per-component location index,
so the result is stable under `--reproducible`.

### Subject-id uniqueness (no duplicate `SPDXRef`/bom-ref)

Distinct discovered roots can share a `Subject.id` (e.g. ~62 same-named
`project(Runtime_Sample)` example roots in the runtime repo) or slugify to the
same id. Emitting them verbatim produced duplicate `SPDXRef-Subject-*` ids
(invalid SPDX, a `spdx_invalid` warning) and colliding CycloneDX subject
bom-refs. Two layers fix this:

1. **Source dedup.** `discover_subjects` drops *genuinely identical* roots (same
   id/identity/role/`source_path`) via `_dedup_identical_subjects` so a
   re-discovered root is never emitted twice. Distinct roots that merely share an
   id keep DIFFERENT `source_path`s and survive.
2. **Emitter disambiguation.** Both emitters call
   `disambiguate_subject_ids(subjects)` (`src/sbom/emit/_common.py`), which walks
   subjects in their stable discovery order and assigns each subject object a
   unique emitted id: the first claimant keeps the bare id, later collisions get a
   deterministic `-<n>` suffix (`Runtime_Sample`, `Runtime_Sample-2`, …). The
   SPDX `SPDXRef-Subject-*` / CycloneDX `subject:*` bom-ref derive from this
   unique id; `DESCRIBES` relationships and edge endpoints resolve through it. The
   result is deterministic (discovery order is stable) and reproducible.

### Reproducibility

With `options.reproducible` (the `--reproducible` flag, which honors
`SOURCE_DATE_EPOCH` via `source_date_epoch`):

- CycloneDX fixes `metadata.timestamp` and derives the `serialNumber` from a
  content hash of a first serialization pass, with stable ordering
  (`src/sbom/emit/cyclonedx.py:585`). Observation occurrences use deterministic
  `bom_ref`s instead of random UUIDs so the library's sorted ordering is stable.
- SPDX fixes the `created` timestamp, derives `documentNamespace` from a content
  fingerprint, and pins all annotation dates to the creation date
  (`src/sbom/emit/spdx.py:549`, `:615`).

Both run is byte-identical across invocations, which is what the golden/drift
tests rely on.

### Split emit

When `--split-subjects` is set, `emit_split` produces one sub-BOM per subject
(filtered by `--subjects` if given), returning `{subject_id: json_string}`. Only
emittable subjects get a sub-BOM (an ownership-only grouping root,
`emit_as_subject=False`, is skipped — it would yield packages with no `DESCRIBES`).

Each sub-BOM is restricted to that subject's **dependency closure**, not the whole
document: `_common.subject_closure_document` (shared with reconcile's `--subjects`
filter via `sbom.graph.reachable_components`) BFS-walks the edge graph from the
subject and keeps only the reachable components/edges. The walk is
**ownership-scoped** — it follows only edges whose `root_artifact_id` is the
subject (plus global `None` edges) — so a component shared by two subjects does
not leak the *other* subject's exclusive transitive deps into this sub-BOM.

Output filenames are derived with `_common.split_output_basenames`: subject ids
come from package/CMake metadata and are NOT trusted as filenames, so path
separators / `..` / absolute leaders are stripped (a sub-BOM can never escape the
output dir) and collisions are disambiguated with a stable hash.
