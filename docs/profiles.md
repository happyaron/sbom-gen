# Repo profiles

A **profile** is a `Profile` subclass that isolates all repo-specific knowledge
behind a fixed set of hooks the generic core calls. The core works with no
profile at all — every hook has a no-op default — so a profile only overrides
the hooks it needs. The CANN profile (`src/sbom_profile_cann/__init__.py`) is
the worked example; the generic core (`src/sbom/`) never imports it directly.

Related pages: [docs/architecture.md](architecture.md) (pipeline & model),
[docs/cmake-authority.md](cmake-authority.md) (the `CmakeAuthority` object many
hooks receive), [docs/cli.md](cli.md) (`--repo-profile` flag).

---

## How profiles are discovered

Profiles register under the `sbom.profiles` entry-point group:

```toml
# pyproject.toml
[project.entry-points."sbom.profiles"]
cann = "sbom_profile_cann:CannProfile"
```

At startup, `sbom.profile.load_profiles()` walks every entry point in that
group and returns `{ep_name: ProfileClass}`. The built-in `GenericProfile` is
always present under `"generic"`.

A broken entry point (import error, or value that is not a `Profile` subclass)
is **never silently ignored**. It is recorded as a first-class
`Warning(code="profile_load_failed", subject=<ep_name>, detail=<error>)` in
the returned warning list, so the caller can surface it. Failing to load a
profile must not silently downgrade the run to generic with no signal.

```python
from sbom.profile import load_profiles
profiles, warnings = load_profiles()
# profiles == {"generic": GenericProfile, "cann": CannProfile, ...}
```

### Auto-detection

When `--repo-profile` is omitted (or set to `auto`), `detect_profile(repo_root)`
calls the `detect(repo_root)` classmethod on every non-generic registered
profile in turn and returns the name of the first one that returns `True`:

```python
from sbom.profile import detect_profile
name, warnings = detect_profile("/path/to/ops-math")
# name == "cann"
```

`GenericProfile` is the explicit fallback — its `detect` never returns `True`.
If no profile matches, `get_profile` returns a `GenericProfile` instance.

The full resolution path:

```
--repo-profile NAME   exact match by entry-point name
--repo-profile auto   detect_profile(repo_root) -> first match
(omitted)             same as "auto"
unknown name          falls back to GenericProfile
```

---

## The `Profile` ABC — every hook

All hooks live in `sbom.profile.Profile` (`src/sbom/profile.py`). A concrete
profile subclasses it and overrides only the hooks it needs; unhooks methods
that are not overridden return the empty/neutral value shown below.

### `detect(repo_root: Path) -> bool`  *(classmethod)*

Auto-detection contract. Return `True` when this profile should handle the
repo at `repo_root`. The base class always returns `False`.

No-op default: `return False`.

---

### `custom_dep_macros() -> dict[str, object]`

Return a mapping from macro name to a **resolver callable** for macros that
introduce dependencies. The `CppCollector` calls the resolver as
`resolver(args, effective_cmake_root)` and expects a `list[Path]` of `.cmake`
fragment files the macro `include()`s.

The resolver receives `effective_cmake_root` from the `CmakeAuthority` — this
is never the raw `--cmake-root`. When `effective_cmake_root` is `None` (the
root cannot be determined), the resolver should return `[]` rather than guess.

No-op default: `return {}`.

---

### `package_metadata(repo_root: Path, authority: CmakeAuthority) -> list[Observation]`

Return package-level dependency observations with version constraints — facts
that live outside the CMake include graph (e.g. a top-level manifest file).
Each `Observation` carries `source_kind`, `source_file`, `usage_scope`,
`version_constraint`, and `ecosystem_data`.

The `authority` argument provides `authority.revision` / `authority.ref` so
the observation can record the CMake revision it was read from.

No-op default: `return []`.

---

### `build_tooling(repo_root: Path, authority: CmakeAuthority) -> tuple[list[Component], list[Warning]]`

Return `Component` records for build tooling that is *acquired* at configure
time (e.g. a CMake helper library fetched by the build system). Also return any
`Warning` records for integrity or provenance concerns.

No-op default: `return ([], [])`.

---

### `curated_enrichers(repo_root: Path) -> list[object]`

Return a list of enricher objects. Each enricher must have:
- `exists() -> bool` — whether its backing file is present.
- `load() -> list[CuratedRecord]` — parse and return curated facts.

The core runs these enrichers during reconcile when their files exist. Curated
product data takes precedence over the generic known-license map.

No-op default: `return []`.

---

### `alias_map() -> dict[str, dict]`

Return a mapping from raw spelling to canonical name and relation type:

```python
{
    "OPBASE": {"canonical": "opbase", "relation": "depends_on"},
    "c_sec":  {"canonical": "securec", "relation": "link"},
}
```

This is one of four alias layers `reconcile` combines, in precedence order
(highest wins on a shared spelling):

1. **config `[aliases]`** — explicit `spelling = "canonical"` entries in the
   `--config` TOML (a per-repo override, no code change);
2. **`profile.alias_map()`** — this hook (curated, can carry a relation type);
3. **built-in OSS aliases** — the core's `gtest≡googletest`, `json≡nlohmann-json`;
4. **on-the-fly derivation** — for a third-party fetched via
   `ExternalProject`/`FetchContent`, the canonical name is read from the archive
   its `canonical_url` downloads (`…/eigen-5.0.0.tar.gz` → `eigen`), so a target
   named `external_eigen_nn` resolves to `eigen` with **no map entry at all**.
   The derived name is itself resolved through the curated layers, and it only
   fills spellings no curated layer already covers (a guess never overrides a
   human).

So the profile `alias_map()` is now mainly for entries derivation can't reach —
link tokens with no download (`Eigen3::EigenNn`), internal names, or relations.
Those can equally live in the config `[aliases]` table. An external link token
covered by none of the layers raises an `unmapped_link_library` warning rather
than silently duplicating or dropping the component.

No-op default: `return {}`.

---

### `subject_license_default(subject: Subject) -> str | None`

Return a default license expression for the repo's *own* subjects/files. This
applies only to the current repo's subjects; returning `None` leaves the
license to the generic resolver or `NOASSERTION`.

No-op default: `return None`.

---

### `dependency_license_default(component: Component) -> str | None`

Return a default license for an external dependency component. Profiles rarely
override this; dependencies stay `NOASSERTION` unless a curated file or
installed metadata proves a license.

No-op default: `return None`.

---

### `condition_vocabulary() -> dict[str, object]`

Return known condition tokens and their semantics for the `CppCollector` /
build-profile evaluator. Each token maps to a metadata dict with a `kind` key
(`"predicate"`, `"option"`, `"value"`) plus optional `default` / `values`.

No-op default: `return {}`.

---

### `classify_root(path: Path, cmake_project: Subject, package_context: dict) -> SubjectRole`

Classify a discovered standalone CMake root into a `SubjectRole`. The generic
core calls `discover_roots()` to find every directory whose `CMakeLists.txt`
has both `cmake_minimum_required` and `project()`, then assigns the neutral
`SubjectRole.CMAKE_PROJECT`. This hook reclassifies by path semantics
(`example`, `st_test`, `manual_example`, `experimental`,
`non_distributable_test`).

`package_context` may carry `repo_root` so the path can be made relative.
Return the existing `cmake_project.role` unchanged when no rule applies.

No-op default: `return cmake_project.role` (no reclassification).

---

### `root_exclusion_policy() -> set[SubjectRole]`

Return the set of `SubjectRole` values to exclude from emission. Under
`declared-all` all discovered roots are kept; the policy can drop roles and the
core emits an `excluded_scope` warning per dropped root so omissions are
explicit. The CLI `--exclude-scope` tokens are mapped via
`config.resolve_exclude_scope` and unioned with this set.

No-op default: `return set()`.

---

### `subject_facets(subjects: list[Subject]) -> list[SubjectMerge]`

Bind co-located wheel and CMake roots into facets of one subject. Return a
list of `SubjectMerge` records. Each `SubjectMerge` instructs
`discover_subjects` to fold `absorbed_subject_id` into `keep_subject_id`,
recording the absorbed identity on the kept subject's `facets` list and setting
`build_graph_root_id` to the CMake project root that builds the kept subject.
The merged subject receives both roots' dependency edges.

No-op default: `return []`.

---

## The CANN profile — a worked example

`CannProfile` (`src/sbom_profile_cann/__init__.py`) implements every hook above
for the `ops-math` repo. Here is what each hook does.

### Detection

```python
# profile name used with --repo-profile
CannProfile.name = "cann"
```

`CannProfile.detect(repo_root)` returns `True` on either kind of evidence:

1. **CANN CMake-framework markers** — the `cmake/function/prepare.cmake` or
   `cmake/fetch_cann_cmake.cmake` marker file, a `set_cann_package(` in
   `version.cmake` (fast paths), or any of the cann-cmake macro usages
   (`add_cann_third_party(`, `init_cann_project(`, `set_cann_package(`,
   `check_cann_pkg_build_deps(`, `fetch_cann_cmake`, …) in a `CMakeLists.txt` /
   `*.cmake` file.
2. **A git origin under the `cann` org** (`gitcode.com/cann/<repo>`, read from
   `.git/config`) — catches CANN repos that use no cann-cmake markers (Python/other
   builds, e.g. `pyasc`, `shmem`). Scoped to the `cann` org ONLY, NOT `Ascend`: an
   Ascend-org repo (e.g. MindIE-LLM) may carry a different license (a MulanPSL
   variant), so it must not inherit the CANN subject-license default.

Running on `ops-math` with the shared `cmake` tree alongside:

```bash
# auto-detection picks "cann" — --repo-profile can be omitted
.venv/bin/python -m sbom \
  --repo-root ../ops-math \
  --cmake-root ../cmake \
  --reproducible \
  --out-dir ./out
```

### `custom_dep_macros` — `add_cann_third_party`

Returns `{"add_cann_third_party": CannThirdPartyResolver()}`.

`CannThirdPartyResolver` is a callable that maps one `add_cann_third_party(<name>)`
invocation to the fragment it includes:

```
<effective_cmake_root>/third_party/<name>.cmake
```

The `CppCollector` hands it `(args, effective_cmake_root)`. When
`effective_cmake_root` is `None`, the resolver returns `[]` — it never falls
back to the raw `--cmake-root`.

The macro's body in `cmake/function/prepare.cmake` gates the include on
`TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD`. The resolver exposes this via
`CannThirdPartyResolver.activation_condition` (`"TOPLEVEL_PROJECT OR
ENABLE_UNIFIED_BUILD"`), which the collector records as an
`ActivationCondition` on each resulting observation.

Local `include(cmake/third_party/<x>.cmake)` invocations (the shorthand form
used in some files) are handled by the generic `include()` walker — they need
no custom resolver.

### `package_metadata` — `version.cmake`

Reads `<repo_root>/version.cmake` and parses three macros:

```cmake
set_cann_package(ops_math VERSION "9.0.0")
set_cann_build_dependencies(runtime ">=8.5")
set_cann_run_dependencies(asc-tools ">=8.5")
```

Returns one `Observation` per dependency line, with:
- `source_kind = SourceKind.CANN_PACKAGE`
- `source_file = "version.cmake"`
- `usage_scope = UsageScope.BUILD` (for `set_cann_build_dependencies`) or
  `UsageScope.RUNTIME` (for `set_cann_run_dependencies`)
- `version_constraint = ">=8.5"` (the declared constraint)
- `ecosystem_data = {"cann_package": <name>, "primary_package": "ops_math", "primary_version": "9.0.0"}`

For `ops-math` this produces 15 observations covering `runtime`, `opbase`,
`metadef`, `ge-compiler`, `bisheng-compiler`, `asc-devkit`, `ge-executor`,
`asc-tools`, and `ops-legacy`.

Note: `ecosystem_data["cann_package"]` is the key `reconcile._observation_name`
uses to attach the observation to its component. Any observation without a
resolvable name is silently dropped; see the naming-convention note in
[`CLAUDE.md`](../CLAUDE.md).

### `build_tooling` — `fetch_cann_cmake.cmake`

`cmake/fetch_cann_cmake.cmake` is wrapped in `if(NOT PROJECT_SOURCE_DIR)` and
picks one of four branches at configure time. `build_tooling` consults
`authority.branch` and returns accordingly:

| Branch | Component? | Warnings |
|--------|-----------|---------|
| `skipped_existing_project` | No | None |
| `local_dir` | Yes — `cann-cmake`, version `NOASSERTION`, `LOCAL_SOURCE_UNVERIFIED` | `cann_cmake_local_override` |
| `tarball` | Yes — `cann-cmake`, version `master-016`, sha256 pinned | None (unless tag mismatch) |
| `git` | Yes — `cann-cmake`, source = requested ref (`master-016`), effective = resolved commit (falls back to the ref when unresolved) | `cann_cmake_tag_mismatch` if ref ≠ `master-016`; `unpinned_git` when no resolved commit |

Under `--cmake-source-authority cmake-as-input`, the resolver short-circuits to a
`git`-branch authority with `effective_cmake_root = --cmake-root` and **sets
`authority_inputs["trusted_input"] = True`**. `build_tooling` gates the
`cann-cmake` exclusion on `authority.authority_inputs.get("trusted_input")`: it
drops the component and emits the single `cann_cmake_trusted_input` warning. (The
resolver no longer emits that warning itself — setting the marker is what drives
the exclusion, so the component is actually excluded rather than only flagged.)
See [docs/cmake-authority.md](cmake-authority.md#--cmake-source-authority-actual-build-vs-cmake-as-input).

The pinned values (`master-016`, sha256 `9167f7296590685b…`) come from
`fetch_cann_cmake.cmake` lines 17 and 22. When the resolved git ref differs
from the pin a `cann_cmake_tag_mismatch` warning is added regardless of branch.

See [docs/cmake-authority.md](cmake-authority.md) for how the authority
decision is made before collection begins.

### `curated_enrichers` — `Third_Party_*` files

Returns two `CuratedEnricher` objects pointing at:

1. `<repo_root>/Third_Party_Open_Source_Software_List.yaml` (`kind="list_yaml"`)
   — a flat YAML map of `name: {version, type}` providing source version and
   declared type (`run`, `test`, `build`).
2. `<repo_root>/Third_Party_Open_Source_Software_Notice` (`kind="notice"`)
   — a sequence of `Software: <name> <version>` blocks providing license,
   copyright, and (when it differs from the List.yaml) the *effective* version.

The Notice is authoritative for license and `effective_version`. When the two
files name the same component, `_merge_curated` folds them: the List.yaml
provides `source_version` and `declared_type`; the Notice provides `license`,
`copyright`, and `effective_version` when it differs. For protobuf in ops-math:

- List.yaml: `version: v25.1, type: run`
- Notice: `Software: protobuf v3.13.0, License: BSD 3-Clause License`
- Merged: `version=v25.1` (source), `effective_version=v3.13.0`, `license=BSD-3-Clause`

This `effective_version` difference is flagged by reconcile as a patched build.

Human-readable license strings in the Notice are normalized to SPDX identifiers
where recognized (`"BSD 3-Clause License"` → `BSD-3-Clause`,
`"MIT License"` → `MIT`, `"Apache License v2.0"` → `Apache-2.0`,
`"GPL V2.0"` → `GPL-2.0-only`, `"Mulan Permissive Software License version 2"` →
`MulanPSL-2.0`, `"BSL-1.0"` → `BSL-1.0`). Unrecognized strings are retained
as the raw value for `LicenseRef` handling.

### `alias_map` — canonical names and relation types

`alias_map()` loads `sbom_profile_cann/data/aliases.yaml` — a data file **carried
with the profile** — so coverage is extended by editing YAML, not Python. Each
entry maps a raw spelling (find_package module name, package-dep name, raw link
token) to `{"canonical": <name>, "relation": <type>}`:

```yaml
OPBASE:     {canonical: opbase, relation: depends_on}
c_sec:      {canonical: securec, relation: link}
```

Because the generic core now derives downloadable third-party identities from
their URL on the fly, this file is mainly the spellings derivation can't reach:
CANN-internal link targets (`ascendcl`, `graph`, `register`, …), spelling/case
variants (`OPBASE`≡`opbase`), cross-name aliases (`c_sec`≡`securec`), and build
sub-variants (`protobuf_host_build`→`protobuf`).

Relation values are string forms of `RelationType`:
- `"depends_on"` — CANN package dependencies
- `"link"` — raw link libraries and imported targets
- `"tooling"` — build tooling (e.g. `bisheng-compiler`)

Selected entries:

| Raw spelling | Canonical | Relation |
|---|---|---|
| `OPBASE`, `opbase` | `opbase` | `depends_on` |
| `tilingapi`, `tiling_api` | `tiling_api` | `link` |
| `ASC`, `asc-devkit` | `asc-devkit` | `depends_on` |
| `securec`, `c_sec`, `libboundscheck` | `securec` | `link` |
| `unified_dlog` | `dlog` | `link` |
| `ge_runner` | `ge-executor` | `link` |
| `bisheng-compiler` | `bisheng-compiler` | `tooling` |
| `torch_npu` | `torch-npu` | `link` |
| `external_eigen`, `Eigen3::Eigen` | `eigen` | `link` |
| `protobuf_src`, `protobuf_shared_build`, `protobuf_static_build`, `protobuf_host_build`, `protobuf_host_static_build` | `protobuf` | `link` |
| `third_party_gtest` | `gtest` | `link` |
| `cust_opapi` | `opapi` | `link` |

The raw-link surface (right column `link`) covers ExternalProject build-target
names that the CANN cmake tree uses — `protobuf_src`, `abseil_build`,
`external_eigen`, etc. — so they collapse onto one component per upstream
library during reconcile.

`torch_npu`'s canonical name `torch-npu` is the PEP 503-normalized form the
Python collector emits for `install_requires`, so the CMake link edge and the
Python runtime dep reconcile onto the same component.

An external link token not in this map (nor the core's built-in OSS aliases)
raises `unmapped_link_library` at reconcile time.

### `subject_license_default` and `dependency_license_default`

```python
CANN_OPEN_LICENSE = "LicenseRef-CANN-Open-Software-License-2.0"
```

`subject_license_default` returns `CANN_OPEN_LICENSE` for every repo-owned
subject *except* `NON_DISTRIBUTABLE_TEST` (those are ownership-only groupings
that ship nothing, so they get `None`).

`dependency_license_default` always returns `None` — CANN dependencies stay
`NOASSERTION` unless a curated file or installed toolkit metadata proves a
license. Profiles rarely override this.

### `classify_root` and `root_exclusion_policy`

`classify_root` maps path segments relative to `repo_root` to a `SubjectRole`:

| Path pattern | Role |
|---|---|
| `.../tests/st/...` | `SubjectRole.ST_TEST` |
| `.../tests/ut/...` or `.../tests/...` | `SubjectRole.NON_DISTRIBUTABLE_TEST` |
| `.../examples/...` | `SubjectRole.EXAMPLE` |
| `.../examples/fast_kernel_launch_example/...` | `SubjectRole.MANUAL_EXAMPLE` |
| `fast_kernel_launch_example/...` (top-level) | `SubjectRole.MANUAL_EXAMPLE` |
| `.../experimental/...` | `SubjectRole.EXPERIMENTAL` |

`fast_kernel_launch_example` is skipped in the normal build
(`examples/CMakeLists.txt:22–24`), so it becomes `MANUAL_EXAMPLE` — an opt-in
subject.

`root_exclusion_policy` returns `set()` — the CANN profile excludes nothing
automatically. Users opt into exclusion via `--exclude-scope`; non-distributable
test roots are kept in the document for ownership but have `emit_as_subject=False`
set by `discover_subjects`, which is distinct from exclusion.

### `subject_facets` — `ascend_ops ≡ AscendOps`, `ops_math ≡ math`

`subject_facets` drives three wheel↔CMake merges when both sides are present
in the discovered subject list:

1. Wheel `ascend_ops` (`PYTHON_WHEEL`) absorbs CMake `AscendOps`
   (`CMAKE_PROJECT`). The CMake project becomes `build_graph_root_id` and a
   `Facet(kind=cmake_project, name="AscendOps")` on the wheel. `torch`/`torch_npu`
   runtime deps and CMake link deps then attach to the same subject.

2. Primary `ops_math` (`CANN_PACKAGE`) absorbs CMake `math` (`CMAKE_PROJECT`)
   as a facet/build graph root.

3. Wheel `npu_math_extension` absorbs the matching `npu_math_extension` CMake
   root (from `scripts/torch_extension`) when present.

Each `SubjectMerge` carries `keep_subject_id`, `absorbed_subject_id`,
`build_graph_root_id`, and `facet`. `discover_subjects` applies the merges so
the two roots' dependency edges land on one subject.

---

## Writing a minimal new profile

The steps below give a profile that auto-detects and overrides two hooks. It
can be a separate Python package or live inside the same package as your repo.

### 1. Subclass `Profile`

```python
# src/sbom_profile_myrepo/__init__.py
from __future__ import annotations
from pathlib import Path
from sbom.profile import Profile
from sbom.models import CmakeAuthority, Observation, SourceKind, UsageScope

class MyRepoProfile(Profile):
    name = "myrepo"

    @classmethod
    def detect(cls, repo_root: Path) -> bool:
        # Auto-detect by a marker file specific to your repo.
        return (Path(repo_root) / "myrepo.cmake").is_file()

    def custom_dep_macros(self) -> dict[str, object]:
        # Teach the CppCollector about a custom dependency macro.
        return {"my_add_dep": MyDepResolver()}

    def package_metadata(
        self, repo_root: Path, authority: CmakeAuthority
    ) -> list[Observation]:
        # Read a top-level manifest and return Observation records.
        manifest = Path(repo_root) / "deps.cmake"
        if not manifest.is_file():
            return []
        # ... parse and return observations ...
        return []
```

Only the hooks you need override. Every other hook inherits `Profile`'s
no-op default and returns an empty/neutral value.

### 2. Write a resolver for your macro (if needed)

```python
from dataclasses import dataclass
from pathlib import Path

@dataclass
class MyDepResolver:
    def __call__(
        self, args: list[str], effective_cmake_root: Path | None
    ) -> list[Path]:
        if not args or effective_cmake_root is None:
            return []
        name = args[0].strip().strip('"')
        return [Path(effective_cmake_root) / "third_party" / f"{name}.cmake"]
```

The resolver receives the macro's positional args and `effective_cmake_root`
from the `CmakeAuthority`. Return `[]` when `effective_cmake_root` is `None`
rather than guessing. Reuse `sbom.cmake.parse` helpers (`parse_file`,
`parse_recursive`) for any CMake parsing — do not reimplement the parser in
the profile.

### 3. Register the entry point

```toml
# pyproject.toml
[project.entry-points."sbom.profiles"]
myrepo = "sbom_profile_myrepo:MyRepoProfile"
```

Install the package (editable or otherwise) so the entry point is registered:

```bash
pip install -e .
```

### 4. Verify detection and loading

```python
from sbom.profile import load_profiles, detect_profile
from pathlib import Path

profiles, warns = load_profiles()
assert "myrepo" in profiles, f"entry point not found: {warns}"

name, warns = detect_profile(Path("/path/to/your-repo"))
assert name == "myrepo"
```

Or pass it explicitly:

```bash
.venv/bin/python -m sbom \
  --repo-root /path/to/your-repo \
  --repo-profile myrepo \
  --out-dir ./out
```

---

## Key invariants

- **The core never imports a profile's internals.** All CANN-specific knowledge
  stays in `src/sbom_profile_cann/`; the generic core only calls hooks and
  consumes the plain model objects they return (`list`, `dict`, `Observation`,
  `Component`, `Warning`, `SubjectMerge` from `sbom.models`).

- **No-op defaults mean partial profiles are safe.** Any hook you do not
  override returns the empty/neutral default; the core behaves as if no profile
  is loaded for that hook.

- **Hooks must not raise on a repo that lacks the relevant feature.** Return the
  empty/neutral default when a file is absent or a feature is not used.

- **Reuse `sbom.cmake.parse`.** Use `parse_file`, `parse_recursive`, and the
  other helpers in `sbom.cmake.parse` for any CMake parsing the profile needs.
  Do not reimplement the CMake parser inside a profile.

- **Macro resolution uses `effective_cmake_root`, never the raw `--cmake-root`.**
  The `CmakeAuthority` decides which cmake tree is authoritative; all fragment
  path resolution must go through `authority.effective_cmake_root`. See
  [docs/cmake-authority.md](cmake-authority.md).
