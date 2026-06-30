# Limitations

This page describes what each collection mode can and cannot surface, explains
behaviors that are correct by design rather than bugs, documents every integrity
finding code and its meaning, and covers the CANN profile's repo-specificity.

Cross-references: [CLI reference](cli.md) · [Architecture](architecture.md) ·
[Profiles](profiles.md) · [CMake authority](cmake-authority.md) · [README](../README.md#limitations)

---

## Default output view (`--scope release`)

By default the tool emits the **release view** (`--scope release`), not the full
inventory of everything it discovered. This is a deliberate scoping choice, not a
collection limitation — the static collectors still find every declaration; the
release view simply filters the assembled document down to what ships.

The release view keeps **only distributable subjects and their runtime dependency
closure**:

- subjects with the `example` / `experimental` / `st_test` / `manual_example` /
  `non_distributable_test` roles are dropped (keeping the primary package, the
  sibling wheels, and the primary CMake root);
- the view **keeps only `usage_scope == runtime`** observations and edges. This is
  a keep-only filter, so anything that is *not* runtime is dropped — test
  dependencies, build tools (cmake/ninja/makeself/protoc/…), example/
  experimental/environment dependencies, **and unclassified `usage_scope == None`
  observations** (which the explicit `--exclude-scope` axis would otherwise keep).
  A multi-scope dependency such as `torch {runtime, build}` survives via its
  runtime observation only. The main-product third-party (eigen/protobuf/json/
  opbase/…) is collected as `runtime` by the C++ collector, so it survives;
- environment tools are omitted entirely.

> The keep-only-runtime axis is what closes the leak where unclassified C++
> fragments (`gtest_shared_build`, a stray `find_package`, the `cann-cmake`
> FetchContent fragments) carried `usage_scope == None` and survived the runtime
> view. Under `release`, `None` is dropped. A Python dependency listed only in a
> `requirements-build.txt` is now `build`-scoped (so dropped), while a package
> that *also* appears in `install_requires` is genuinely `runtime` and survives.

If you need the complete inventory — every subject, every usage scope, and the
host environment tools — pass **`--scope all`**. The lower-level
[`--exclude-scope`](cli.md#--exclude-scope-tokentoken),
[`--subjects`](cli.md#--subjects-idid), and
[`--no-env-tools`](cli.md#--no-env-tools) flags apply additively on top of either
view. See the [`--scope`](cli.md#--scope-releaseall) reference for the exact
preset definition.

---

## Default output detail (`--detail compact`)

Orthogonally to *which* subjects/deps appear (`--scope`), `--detail` controls
*how much* per-component provenance each one carries. The default is
**`compact`**, which is a readability choice, not a collection limitation — the
omitted data is still discovered and is available with `--detail full`.

**`compact` (default) omits** the verbose per-observation provenance — the
`sbomgen:obs:N:*` CycloneDX component properties and the `sbomgen:obs:*` SPDX
annotations (one block per declaration site) — and the CycloneDX
`evidence.occurrences` array. On a repo with many same-shaped roots this is the
bulk of the file: a single shared dependency seen by 60+ roots otherwise emitted
60+ occurrence entries plus hundreds of `sbomgen:obs:*` properties.

**`compact` keeps** everything that makes the BOM useful: each component's
name/version/type/`purl`/licenses/copyright/hashes, the full dependency graph +
relationships, and the summary signals `sbomgen:integrity:*`,
`sbomgen:completeness:*`, `sbomgen:alias:*`, `sbomgen:subject:*`,
`sbomgen:pedigree:*` (plus the CycloneDX `pedigree` / SPDX `GENERATED_FROM`).

**`full`** restores today's complete output — every `sbomgen:obs:*` field plus
the `evidence.occurrences` array. **Occurrence dedup applies in both modes:**
whenever occurrences are emitted (i.e. in `full`), identical source locations
collapse to a single occurrence. Both modes pass the official validators and are
byte-identical under `--reproducible`. See the
[`--detail`](cli.md#--detail-compactfull) reference and
[architecture.md](architecture.md#compact-default-vs-full-detail).

---

## Duplicate / colliding subject ids

A repo can build many same-shaped roots whose `project()` names collide (e.g. a
runtime repo's ~62 example projects all named `Runtime_Sample` / `Memory_Sample`
/ …). Two roots sharing a `Subject.id` — or two ids that slugify to the same SPDX
id — would otherwise produce duplicate `SPDXRef-Subject-*` ids (invalid SPDX,
caught as a `spdx_invalid` validation warning) and colliding CycloneDX subject
bom-refs.

The tool guarantees unique emitted subject ids:

1. **Genuinely-identical roots are de-duped at the source.** `discover_subjects`
   drops a root re-discovered with an identical id/identity/role/`source_path`
   (`_dedup_identical_subjects`). Two *distinct* roots that merely share an id
   keep different `source_path`s and are both retained.
2. **Remaining slug collisions are disambiguated in the emitters.** Each subject
   object gets a unique emitted id — the first claimant keeps the bare id, later
   collisions get a deterministic `-<n>` suffix (`Runtime_Sample`,
   `Runtime_Sample-2`, …). `DESCRIBES` relationships and edge endpoints use the
   disambiguated id. The result is deterministic and reproducible. See
   [architecture.md](architecture.md#subject-id-uniqueness-no-duplicate-spdxrefbom-ref).

---

## Collection modes

The tool has three modes, selected with `--collector-mode`:

| Mode | How it runs | What it adds vs. static |
|---|---|---|
| `static` (default) | Parses source text; no configure, no build, no network | — |
| `configured` | **Not yet implemented** — accepted but warns (`collector_mode_unimplemented`) and runs static. *Planned:* configure with CMake File API | *Planned:* target graph, install relationships |
| `both` | **Not yet implemented** — warns and runs static. *Planned:* static + configured together | *Planned:* all of the above |

Network enrichment (`--network on`) is orthogonal to collector mode.

### Static mode

Static mode is the default and the most thoroughly tested path. The regression
suite (`tests/test_drift_ops_math.py`) exercises it end-to-end against the real
`ops-math` tree.

**What static mode surfaces:**

- Every `ExternalProject_Add` and `FetchContent_Declare` declaration found by
  following `include()` chains from each CMakeLists.txt root, including
  declarations inside conditionals (all branches are visited — the
  `declared-all` build profile).
- `URL_HASH` checksums, `TLS_VERIFY` settings, `GIT_REPOSITORY`/`GIT_TAG` refs,
  and `PATCH_COMMAND` patches (with SHA-256 when present) for each external
  project.
- All `find_package()` calls with their `REQUIRED`/`QUIET` flags and the
  surrounding CMake `if()` gates recorded as `activation_condition`.
- Raw link library tokens from `target_link_libraries`, classified and
  alias-resolved (see [The CANN profile's repo-specificity](#the-cann-profiles-repo-specificity)).
- Python direct dependencies from `requirements*.txt`, `pyproject.toml`
  `[project].dependencies`, `setup.py` `install_requires`, and
  `[build-system].requires`.
- CANN package dependencies from `version.cmake` `set_cann_*_dependencies` calls.

**What static mode cannot see:**

- Facts that only exist after a configure or build: resolved generator
  expressions, CMake variables set at configure time by logic that is not
  visible in the source text, ExternalProject URLs that are constructed by
  calling a CMake function with a variable that is only set at configure time.
- Python transitive dependencies. Every component's
  `completeness["python_transitives"]` is `"unresolved"` in static mode — only
  direct declarations are captured.
- The final installed artifact layout (which target ends up in which directory).
  A configured File-API collector would add this — but `--collector-mode
  configured` is **not yet wired in** (it warns and runs static; see below).

Because static mode visits every conditional branch, it may record a dependency
as `declaration_reachability=reached` even when a specific build configuration
would exclude it. The activation conditions are preserved for consumers to
filter; the default `--scope release` view (see above) and the lower-level
`--exclude-scope` flag drop subject roles and usage scopes from the output.

### Python package subject identification

A repo's Python wheel subject (its name and version) is resolved statically by
`collectors/py_metadata.py`, **without executing the package's code**. The
resolver handles the common dynamic-metadata patterns, in this precedence:

1. `pyproject.toml` `[project].name`/`version` (PEP 621), including `dynamic`
   versions via `[tool.setuptools.dynamic]` `attr:`/`file:` and setuptools-scm.
2. `setup.cfg` `[metadata]` (`file:`/`attr:` directives).
3. `setup.py` `setup(name=, version=)`, where the argument is evaluated by a
   small **safe AST evaluator** (no code runs): string literals, module-level
   constants, `os.getenv(k, default)` / `os.environ.get(k, default)`,
   `X or "literal"`, a zero-arg helper that returns a constant, reads of a
   co-located version file (`_read_file("version.txt")`, `open("VERSION").read()`,
   `Path(...).read_text()`), and chained `.strip()`/`.replace("\n","")`.
4. Conventional fallbacks: `version.txt`/`VERSION`, `<pkg>/_version.py` or
   `__init__.py` `__version__`, `PKG-INFO`, or `git describe` (setuptools-scm).

**Honest fallbacks — the wheel subject is never dropped.** When a value genuinely
cannot be resolved statically (e.g. `os.getenv("MS_PACKAGE_NAME")` with **no**
default, as in mindspore), the resolver does not guess:

- unresolved name → the repository directory basename, plus a structured
  `subject_name_unresolved` warning;
- unresolved version → `None`, plus a `subject_version_unresolved` warning.

The chosen source for each value is recorded (`name_source`/`version_source`) so
the provenance of a fallback is auditable.

**Co-located build roots merge.** When a Python wheel and a CMake `project()`
live in the same directory (a Python package built by a co-located
`CMakeLists.txt` — e.g. pyasc's `pyasc` wheel built by `project(AscIR)`), the
generic core folds them into **one** subject: the wheel identity is canonical and
the CMake project becomes a `cmake_project` facet / `build_graph_root_id`, rather
than the CMake project name leaking out as a separate top-level subject. (The
CANN profile's `subject_facets` hook composes on top of this for repo-specific
merges such as `ascend_ops`≡`AscendOps`.)

### Dependency version handling (concrete pin vs. constraint)

A declared dependency's *version constraint* is distinct from its *resolved
version*. Static mode does not run a resolver, so it records a concrete version
only when the declaration **names one exactly**; everything else is kept as a
recorded constraint plus an explicit "unpinned" marker.

**The concrete-pin rule.** For every Python requirement (`requirements*.txt`
lines, `setup.py` `install_requires`, `pyproject.toml` `[project].dependencies`
and `[build-system].requires`) the PEP 508 specifier is parsed with
`packaging`. The full specifier set is always recorded on the observation as
`version_constraint` (e.g. `==24.2.0`, `<2`, `>=3.20,<4.0`; empty for a bare
dep → `None`). The dependency is treated as a **concrete pin** — and that
version is set on the component (`source_version` = `effective_version`) — **iff
the specifier set is exactly one clause whose operator is `==` or `===` and the
version contains no `*` wildcard.** So:

| declaration            | `version_constraint` | concrete version |
| ---------------------- | -------------------- | ---------------- |
| `attrs==24.2.0`        | `==24.2.0`           | `24.2.0`         |
| `x===1.2`              | `===1.2`             | `1.2`            |
| `numpy<2`              | `<2`                 | — (unpinned)     |
| `numpy>=1.24.4,<=1.26.4` | `<=1.26.4,>=1.24.4` | — (unpinned)    |
| `foo==1.4.*`           | `==1.4.*`            | — (unpinned)     |
| `foo~=1.2`             | `~=1.2`              | — (unpinned)     |
| `foo==1.0,!=1.0.1`     | `!=1.0.1,==1.0`      | — (unpinned)     |
| `opbase` (`>=8.5`)     | `>=8.5`              | — (unpinned)     |
| `pyyaml` (bare)        | `None`               | — (unpinned)     |

Extras and PEP 508 markers are preserved in `ecosystem_data` regardless of
whether a concrete version was found.

**The unpinned marker.** When **none** of a component's observations yields a
concrete version — bare/range Python deps and CANN `version.cmake` package deps
that carry only a `>=8.5` constraint — reconcile sets
`Component.completeness["version"] = "unpinned"`. A component that already has a
concrete version from any layer (a Python `==` pin, a cmake source/effective
version such as eigen `5.0.0` or protobuf `25.1`→`3.13.0`) is **never** marked.
The marker surfaces as `sbomgen:completeness:version=unpinned` (CycloneDX property /
SPDX annotation). Completeness is emitted **per-component only** — as
`sbomgen:completeness:*` CycloneDX properties and per-component SPDX annotations. It
is deliberately **not** aggregated into the SPDX document-level `comment` (doing
so flooded the global comment with one entry per unpinned/unresolved dependency);
the SPDX document carries no completeness comment.

**Conflicting pins.** If two observations of the same component carry *different*
concrete pins, reconcile keeps one deterministically (the lowest PEP 440
version) and emits a `version_pin_conflict` warning. A pin competing with a mere
range is not a conflict — the pin simply wins.

**Emitted version + purl.** `component.version` (CycloneDX) / `Package.versionInfo`
(SPDX) is set only for a concrete version; an unpinned dep omits it (SPDX drops a
`None` version rather than emitting `NOASSERTION`). The CycloneDX purl for a
Python component includes `@version` only when concrete, so an unpinned dep gets
a **version-less purl** (`pkg:pypi/numpy`) while a pin gets
`pkg:pypi/attrs@24.2.0`. Both libraries' validators accept the version-less purl
and the omitted SPDX `versionInfo`.

### Configured mode (File API)

> **Not yet wired in (v0.1.0).** The `fileapi.py` / `trace.py` modules described
> below exist and are unit-tested in isolation, but the pipeline does **not** invoke
> them: `--collector-mode configured` / `both` currently emit a
> `collector_mode_unimplemented` warning and run the static collector only. The
> rest of this section documents the modules' intended design.

> **Security boundary — `configured` and `trace` modes execute the target repo.**
> Running `cmake <repo>` interprets the repository's `CMakeLists.txt`, which can run
> **arbitrary host commands** (`execute_process`, `file(DOWNLOAD)`, custom commands,
> generator scripts). These modes are **not** side-effect-free. They are opt-in —
> the default `--collector-mode static` never runs CMake — and should be run only
> against a **trusted** repository, ideally in a sandbox / container / throwaway
> user. The scratch build directory bounds *file writes*, not command execution,
> and `FETCHCONTENT_FULLY_DISCONNECTED` only best-effort-disables FetchContent
> network access.

When wired in, `--collector-mode configured` (or `both`) is designed to run
`cmake` against the repo with a
[File API](https://cmake.org/cmake/help/latest/manual/cmake-file-api.7.html)
query stanza and parse the reply directory, answering the *graph* question:
which targets exist, which libraries they link, and which targets are installed
to which destination.

**What configured mode does NOT add:**

`fileapi.py` is deliberately minimal. Per its module docstring and the
INTERFACE.md contract:

> This module answers the *graph* question (targets, link relationships,
> install relationships) and deliberately does NOT attempt to extract
> ExternalProject_Add URLs, patches or TLS_VERIFY — that is parse.py /
> trace.py territory.

So `ExternalProject_Add` acquisition metadata (URL, hash, TLS setting, git ref,
patch list) comes from static parsing or trace mode regardless of whether
`configured` is also active. Configured mode adds `FileApiTarget` records
(name, type, link libraries, imported flag) and `install_relationships`; it
does not change what is known about how a dependency was obtained.

**Failure handling:** if `cmake` is not found or the configure fails,
`configure_and_query` returns an empty `FileApiGraph` plus a warning
(`fileapi_cmake_not_found`, `fileapi_configure_failed`, etc.) and the rest of
the pipeline continues. (Configured mode is designed to be opt-in and gracefully
absent — but, again, it is not yet wired into the CLI.)

**Status:** the `fileapi.py` module exists and is unit-tested, but it is **not
wired into the pipeline** — `--collector-mode configured` does not run it (see the
note at the top of this section). Wiring it into the collector dispatch is planned.

### Configure-trace mode

`trace.py` runs `cmake --trace-format=json-v1` (falling back to
`--trace-expand` on older CMake) in a scratch directory with
`FETCHCONTENT_FULLY_DISCONNECTED=ON` to capture acquisition metadata that
complex variable indirection may hide from the static parser. It reconstructs
the same `CMakeFile` record shape that `parse.py` produces.

Like configured mode, a configure failure produces a warning and an empty result,
never a crash.

**Status:** the `trace.py` module exists and is unit-tested, but it is **not
invoked** anywhere in the pipeline. In particular, `--resolve-cmake-ref` now
resolves the cann-cmake ref directly via `git ls-remote` (not by running a CMake
trace). Wiring trace mode into collection is planned.

---

## Network enrichment (`--network on`)

The opt-in network layer fills a component's license from **deps.dev** (PyPI
ecosystem), falling back to the **PyPI JSON API**, for any component still
`None` after the offline layers. Hardening that bounds what it will assert:

- **Python-only.** Only components with a Python language/observation are
  queried. A C++/CANN component is **skipped**, never matched against the PyPI
  ecosystem by name — otherwise a same-named but unrelated PyPI package (e.g. the
  CANN `dlog` logging lib vs. a PyPI `dlog`) would supply a false license. Proper
  C++ ecosystem resolution is a future task; until then non-Python deps stay
  `NOASSERTION`.
- **No sentinels.** deps.dev returns `non-standard` when it can't reduce the
  upstream metadata to a clean SPDX id; that is treated as *not a license* and we
  fall through to the PyPI classifier path rather than emitting `non-standard`.
- **No license blobs.** PyPI's `license` field is often the full license *text*
  (e.g. scipy, numpy); it is never emitted as a license id — only OSI classifier
  ids are. A package with neither stays `NOASSERTION`.
- **Small-payload PyPI queries.** An *unpinned* dep would otherwise hit
  `/pypi/<name>/json`, which returns every release + file (multi-MB for
  scipy/numpy/tensorflow — slow and timeout-prone). Instead the version deps.dev
  resolved is borrowed to query the per-version `/pypi/<name>/<version>/json`
  endpoint (~90 KB, same classifiers), so large packages resolve reliably.
- **Still best-effort.** Results depend on live API success; a transient failure
  leaves that one component `NOASSERTION`. Do **not** expect byte-identical output
  from `--network on` runs — reserve `--reproducible` guarantees for offline mode.

**Status:** functional; the license-resolution gain is large (e.g. pyasc: 0 →
16 components licensed) but treat as preview (v0.1.0).

---

## Offline NOASSERTION

When the tool runs without network access (the default, `--network off`),
several fields are left `NOASSERTION` or unset rather than guessed.

### CANN-internal component licenses

CANN-internal dependencies (`opbase`, `runtime`, `metadef`, `ge-compiler`,
`asc-devkit`, `ge-executor`, `asc-tools`, `ops-legacy`, `bisheng-compiler`, and
others declared in `version.cmake`) are proprietary CANN packages. No license
is asserted for them in the absence of installed package metadata. The CANN
profile's `dependency_license_default` returns `None` — no default is injected.

From `src/sbom_profile_cann/__init__.py`:

```python
def dependency_license_default(self, component: Component) -> str | None:
    """CANN dependencies stay NOASSERTION unless curated/installed proves
    a license -- so this returns None (no profile default)."""
    return None
```

This is correct behavior: asserting an unknown license would be misleading.
The `NOASSERTION` value is propagated into the emitted SPDX and CycloneDX
output.

### Python download URLs are not asserted by default

By default a Python component carries its `pkg:pypi/<name>[@version]` purl but
**no** download URL: the SPDX `downloadLocation` stays `NOASSERTION` (no resolved
artifact URL was observed). The opt-in `--guess-pypi-urls` flag constructs a
canonical `https://pypi.org/project/<name>/[<version>/]` URL from the PEP 503
name and version and emits it as a CycloneDX `DISTRIBUTION` externalReference /
SPDX `downloadLocation`, marked `sbomgen:python:download_url_source=guessed`. The URL
is a **construction**, not a verified artifact link — it is not fetched or
checked, so it stays off by default. Non-Python components are never affected.

Third-party OSS components (eigen, protobuf, gtest, json, abseil-cpp) get
their licenses from the layered enrichment pipeline (highest priority first):

0. **ScanCode** — opt-in (`--scancode enrich`/`fallback`/`both`); `enrich`/`both`
   override everything below for a confident on-disk detection, `fallback` only
   fills gaps (see "ScanCode license/copyright backend").
1. **Curated layer** — `Third_Party_Open_Source_Software_List.yaml` and
   `Third_Party_Open_Source_Software_Notice` (present in `ops-math` at repo
   root). The Notice declares BOTH the per-third-party `License:` line and the
   `Copyright notice:` block, so this layer fills `component.license` **and**
   `component.copyright` (alias-resolved — `libboundscheck` → `securec`,
   `googletest` → `gtest`). A component with no concrete license still gets the
   Notice's declared license/copyright when present.
2. **Known-license map** — the bundled (empty) core map merged with the CANN
   profile's `known_licenses.yaml` (covers common OSS names like
   `gtest: BSD-3-Clause`, plus a MulanPSL floor for `securec`).
3. **deps-dir (on-disk real source)** — `--deps-dir` live resolution **and** the
   seeded `deps_dir_cache.json` snapshot (always consulted, fill-only): real
   source/`Readme.opensource`-manifest licenses + copyright for the C++ long tail
   (see `enrich/deps_dir*` in INTERFACE.md / CLAUDE.md).
4. **Cache scan** — offline scan of extracted dep directories under
   `CANN_3RD_LIB_PATH` (and `--deps-dir`) for `LICENSE`/`COPYING` files.
5. **depsdev cache** — the vendored deps.dev/PyPI license/supplier snapshot
   (`depsdev_cache.json`, always consulted, just above live network).
6. **Network** — live deps.dev and PyPI JSON API (opt-in, `--network on`).
7. **NOASSERTION** — if none of the above resolves a license.

Copyright precedence mirrors this: ScanCode > curated-Notice > deps-dir > none.

### Missing checksums in the cann-cmake local-dir branch

When `fetch_cann_cmake.cmake` resolves to the `local_dir` branch (an arbitrary
local checkout is the actual CMake source), the `cann-cmake` component's
`source_version` is `NOASSERTION`. The `master-016` tag is NOT assumed; only
the resolved git commit (when known) is recorded. See
[cmake-authority.md](cmake-authority.md) for the full authority resolution logic.

---

## By-design behaviors (not bugs)

The following observations appear in the SBOM output and may look surprising.
They are all correct.

### `build` appears as a PyPI component

`build` is a real [PyPI package](https://pypi.org/project/build/) listed in
`examples/fast_kernel_launch_example/requirements.txt`:

```
build
```

It is the PEP 517 build frontend. Its presence is not a parser artifact or a
leaked directory name — the Python collector correctly records it as a direct
dependency of that example root.

### eigen version 5.0.0

Eigen is listed with version `5.0.0` in
`Third_Party_Open_Source_Software_List.yaml`:

```yaml
eigen:
  version: 5.0.0
  type: run
```

The curated list is authoritative for this project. The known-license map and
the upstream Eigen release history use different version conventions; the
version surfaced in the SBOM is the one CANN's curated file declares.

### protobuf: source version 25.1, effective version 3.13.0

The CANN tree ships protobuf with a patch that rewrites
`protobuf_VERSION_STRING` from `4.25.1` to `3.13.0`. The curated files record
this split explicitly:

- `Third_Party_Open_Source_Software_List.yaml`: `version: v25.1` (the
  upstream/source tarball version).
- `Third_Party_Open_Source_Software_Notice`: `Software: protobuf v3.13.0` (the
  effective/patched version).

The CANN profile's `_merge_curated` logic detects the discrepancy and sets
`source_version = "25.1"` and `effective_version = "3.13.0"` on the component,
with a `patched_build` note. This is confirmed by the regression test:

```python
assert protobuf.source_version == "25.1"
assert protobuf.effective_version == "3.13.0"
assert protobuf.patches  # the version-rewrite patch must be present
```

(`tests/test_drift_ops_math.py:test_protobuf_patched_identity`)

### CANN-internal link libraries are real dependencies

`graph`, `mmpa`, `register`, `ascendcl`, `nnopbase`, `aicpu`, `tiling_api`,
`exe_graph`, `opapi`, and others appear in the SBOM as dependency components.
These are genuine CANN runtime/framework libraries that ops-math links against.
They are not noise — they are the link surface of the CANN SDK.

They are covered by the CANN alias map in
`src/sbom_profile_cann/__init__.py:_build_alias_map()`, for example:

```python
add("graph", "graph", _REL_LINK)
add("mmpa",  "mmpa",  _REL_LINK)
add("register", "register", _REL_LINK)
```

If any of them lacked an alias entry, reconcile would raise an
`unmapped_link_library` warning (see below). Their presence in the alias map is
what makes them appear as components rather than warnings.

### Unmapped link library tokens are reported, never dropped

When the link-token classifier finds an external library token not covered by
the alias map, reconcile raises an `unmapped_link_library` warning — the token
is recorded as a warning, not silently discarded. This is intentional: silent
drops would produce incomplete SBOMs. Adding the token to the profile alias map
promotes it from a warning to a proper component record.

---

## Integrity findings

Each component can carry a set of stackable `integrity_findings` (from
`sbom.models.IntegrityFinding`). These are unioned across observations for the
same component and emitted into both output formats.

### `no_hash`

The `ExternalProject_Add` (or `FetchContent_Declare`) declaration does not
include a `URL_HASH` field, so the downloaded archive cannot be verified
against a known checksum. The component is recorded but marked as
unverifiable. Adding a `URL_HASH SHA256=<value>` to the CMake declaration
would clear this finding.

Source: set by `src/sbom/cmake/parse.py` when `ExternalProject.url_hash is None`
and the project uses a URL (not git).

### `unpinned_git`

The dependency is fetched via `GIT_REPOSITORY` + `GIT_TAG`, but the tag
resolves to a branch name or an unannotated symbolic ref rather than a pinned
commit hash. A branch tag can silently advance between builds, so the exact
source cannot be reproduced. Pin `GIT_TAG` to a full commit SHA to clear
this finding.

Source: set when `CmakeAuthority.branch == GIT` and `authority.revision` is
absent (the git ref could not be resolved to a commit), or on the `cann-cmake`
component when `git` branch is used and the commit is unknown.

### `tls_verification_disabled`

The `ExternalProject_Add` declaration sets `TLS_VERIFY OFF`. The download is
not authenticated and is susceptible to man-in-the-middle interception. This
is surfaced because the tool's design principle is that integrity gaps are
reported, not hidden.

Source: set by `src/sbom/cmake/parse.py` when `ExternalProject.tls_verify is
False` (i.e., the CMake file explicitly sets `TLS_VERIFY OFF`). `tls_verify =
None` (unspecified) does not produce this finding.

### `local_source_unverified`

The component's source is a local filesystem path rather than a URL with a
checksum. There is no way to cryptographically verify what was actually used.
Two common causes:

- The `cann-cmake` authority resolves to the `local_dir` branch (an arbitrary
  local checkout is in use instead of the pinned tarball or git tag).
- A `find_package` dependency (`opbase`, etc.) is satisfied from a locally
  installed SDK whose provenance cannot be confirmed from source.

The `cache_scan` enricher (`src/sbom/enrich/cache_scan.py`) may resolve the
license from a local directory under `CANN_3RD_LIB_PATH`, but it explicitly
leaves `local_source_unverified` in place:

> When only a local source was available and it was unverified, the
> `IntegrityFinding.LOCAL_SOURCE_UNVERIFIED` flag is left on the component
> (not added here — it's a collector responsibility; we just don't remove it).

The regression test confirms this for `opbase`:

```python
assert IntegrityFinding.LOCAL_SOURCE_UNVERIFIED in opbase.integrity_findings
```

(`tests/test_drift_ops_math.py:test_opbase_local_source_unverified`)

---

## The CANN profile's repo-specificity

The `cann` profile (`src/sbom_profile_cann/__init__.py`) is tuned to the
`ops-math` repo. Specifically:

**Alias map coverage.** The `_build_alias_map()` function lists every raw
spelling (find_package module name, package dep name, raw link token) that
ops-math uses. A CANN repo with different link targets or package names will
produce `unmapped_link_library` warnings for any token not in that map.

**Curated file paths.** The enrichers look for
`Third_Party_Open_Source_Software_List.yaml` and
`Third_Party_Open_Source_Software_Notice` at the repo root. Different CANN
repos may use different filenames or paths.

**Root classification.** `classify_root` applies path-semantic rules for
`tests/`, `examples/`, `fast_kernel_launch_example/`, a `sample`/`samples`
segment (classified `EXAMPLE` so the release scope trims demo roots), and
`experimental/` directories. Other CANN repos with different directory layouts
may need additional rules.

**Subject facets.** The `subject_facets` hook merges
`ascend_ops`↔`AscendOps`, `ops_math`↔`math`, and `npu_math_extension` — names
specific to ops-math's wheel and CMake project layout.

### How to extend the alias map

When `unmapped_link_library` appears in the SBOM warnings:

1. Identify the raw token (the warning's `subject` field contains it).
2. Determine its canonical name, relation type (`link`, `depends_on`, or
   `tooling`), and whether it is an OSS third-party library, a CANN SDK
   library, or a build tool.
3. Add an entry to the alias map in your profile's `alias_map()` hook, or
   subclass `CannProfile` and extend `_build_alias_map()`.

Example: if a new raw link token `hccl` appears:

```python
# in your profile's alias_map():
add("hccl", "hccl", _REL_LINK)
```

If the token is an alternate spelling of an existing component:

```python
add("hccl_static", "hccl", _REL_LINK)
```

For a completely new repo that is not ops-math, write a new profile subclass
and register it under the `sbom.profiles` entry point. The generic core works
with no profile at all; the profile only needs to implement the hooks relevant
to that repo. See [docs/profiles.md](profiles.md) for the full guide.

---

## Network enrichment limitations

When `--network on` is active, `src/sbom/enrich/net.py` queries
[deps.dev](https://deps.dev) (PyPI ecosystem) and the
[PyPI JSON API](https://pypi.org/pypi) for license metadata.

**What it covers:** Python components and, as a best-effort fallback, C++
components whose names appear in the PyPI ecosystem (e.g., packages that also
publish Python bindings). The network enricher updates `component.license`
when unset and records `network_sha256` under `checksums`.

**What it does not cover:**

- C++ dependencies that have no PyPI presence. The module docstring notes:

  > proper C++ ecosystem support is a future task

  This means C++ components not resolvable via deps.dev/PyPI will still show
  `NOASSERTION` for license even with `--network on`.

- The archive-download path (download the tarball, scan its LICENSE file,
  compute sha256). This is referenced in the INTERFACE.md contract but is
  deferred:

  > C++ note: the design mentions downloading the archive and scanning its
  > license file when network is on. That behaviour is architecturally separate
  > from the deps.dev lookup and is deferred to the archive-download path (not
  > yet implemented); this module covers the metadata-API path.

- **A network-computed sha256 is never equated to a checked-in `URL_HASH`.**
  The two values serve different purposes: `URL_HASH` is what the CMake tree
  asserts; `network_sha256` is what the tool independently computed at run time.
  They are stored under separate keys and are never merged.

**Status:** functional but lightly tested in CI (network calls are mocked in
unit tests; a live network job is gated separately).

---

## ScanCode license/copyright backend

The opt-in `--scancode {enrich,fallback,crosscheck,both}` flag wires in
[ScanCode Toolkit](https://github.com/nexB/scancode-toolkit) as a license/copyright
source (`src/sbom/enrich/scancode.py`). It is **off by default** and carries
several caveats. (`fallback` is the fill-only mode that pairs with `--deps-dir`;
the other three are described in [docs/cli.md](cli.md).)

**It is a separate, heavyweight install.** ScanCode is *not* a dependency of
sbom-gen — the tool shells out to its CLI (`scancode -cl --json-pp`). You install
ScanCode yourself (typically in its own virtualenv) and point `--scancode-path`
at the binary, or have `scancode` on `PATH`. If no binary is found, the tool emits
a `scancode_unavailable` warning and **continues with the normal layered resolver**;
it never hard-fails the SBOM.

**It needs on-disk source.** ScanCode can only read files that exist locally, so
the backend applies only to:

- **subjects** — which always carry a local `source_path`; and
- **components** whose `resolved_url_or_path` is an **existing local directory**.

A subject's `source_path` (and a component's `resolved_url_or_path`) is **repo-
relative** — `scancode.target_dir_for(obj, repo_root)` resolves it against
`config.repo_root` (the empty string `""` means the repo root itself, the primary
subject), mirroring `collectors/python.py` and `collectors/cpp.py`. This is what
makes ScanCode scan the real source tree (e.g. the `pyasc` repo) rather than the
process CWD. A scan that returns no result emits `scancode_scan_failed` for both
the component **and** the subject path (no silent swallow).

In static offline mode most components have no local source (they are declared by
URL/git ref), so they are silently skipped and keep their normal resolver result.
This makes the backend most useful for the subjects themselves and for components
backed by an extracted local tree (e.g. under `CANN_3RD_LIB_PATH`).

**Weight / performance.** ScanCode has a ~1.2s cold start and scans ~10 files/sec.
The backend deliberately does **not** walk an entire dependency tree: each scan is
scoped to the license/copyright-bearing surface — the `LICENSE` / `COPYING` /
`NOTICE` / `COPYRIGHT*` files plus the **top level** of the target directory (no
recursion). A scan that times out or exits non-zero emits a `scancode_scan_failed`
warning and that target keeps the normal result. Even so, enabling it adds real
wall-clock time proportional to the number of distinct local directories scanned;
keep it off for fast routine runs.

**Confidence threshold (default 80).** ScanCode reports a per-match score. The
aggregator trusts only a detection whose best score is **at or above** the
threshold (`scancode.CONFIDENCE_THRESHOLD = 80.0`). Below that — or when ScanCode
returns its `unknown-license-reference` / `LicenseRef-scancode-unknown-license-reference`
placeholder — the result is treated as **NOASSERTION**: the backend never asserts a
low-confidence guess. (For reference, a clean Apache-2.0 `LICENSE` file scores ~92.)
A non-SPDX `LicenseRef-scancode-*` token is mapped through
`enrich/licenseref.py` to a synthesized `LicenseRef-<slug>` with inline text so the
SPDX validators accept it.

**Mode semantics.**

- `enrich` makes ScanCode the **highest-priority** license layer: a confident
  detection overrides the normal resolver and records
  `Provenance(field="license", source="scancode")`, stashing the displaced prior
  value so `both` can report it.
- `crosscheck` **changes no license values** — it is a QA pass that compares
  ScanCode against the resolved licenses, emits a `license_crosscheck_mismatch`
  warning per difference, and writes `license-crosscheck.json` to the output dir.
- `both` enriches and then writes the same report from the displaced prior values
  (`ours=<prior> scancode=<applied>`).

The report is **3-way** where a curated Notice exists: each row is
`{name, ours, scancode, curated, score, agree}` — `curated` is the Notice's
declared license for that component (or `null`). `agree` always reflects the
`ours` vs `scancode` comparison; the curated column is informational and the
`license_crosscheck_mismatch` semantics are unchanged.

**Single-input invocation.** ScanCode 32.5.0 rejects *multiple absolute* inputs
in one call (`all input paths must be relative when using multiple inputs`). The
runner therefore scans each path in the bounded surface as its own single-input
`scancode` invocation and merges the per-file results, so an absolute target
directory scans successfully instead of being silently dropped.
