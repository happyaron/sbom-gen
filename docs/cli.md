# CLI and config reference

This page documents every flag accepted by `sbom` (the console script and
`python -m sbom`), the `sbom.toml` config file format, precedence rules, and
end-to-end invocation examples.

See [README](../README.md) for installation and a quickstart. For the CMake
source-authority subtleties (when `--cmake-root` is not what the tool uses) see
[docs/cmake-authority.md](cmake-authority.md). For writing a repo profile plugin
see [docs/profiles.md](profiles.md).

---

## Invocation

```bash
# via the installed console script (active venv):
sbom [FLAGS]

# via the module (explicit venv, no activation required):
/path/to/.venv/bin/python -m sbom [FLAGS]
```

Both forms are identical. Examples below use `sbom`; substitute
`/home/aron/testing/cann/sbom-gen/.venv/bin/python -m sbom` if the venv is not
activated.

---

## Flags

### `--repo-root PATH`

**Default:** `.` (current working directory)

Root of the repository to analyse. The collectors scan this tree for CMake
files, Python packaging metadata, and profile markers.

```bash
sbom --repo-root ../ops-math
```

---

### `--repo-profile NAME`

**Default:** auto-detected

Name of the repo profile plugin to load (e.g. `cann`). When omitted (or set to
`auto`), every registered profile's `detect(repo_root)` classmethod is tried in
turn; the first match wins. A failed entry-point import surfaces as a
`profile_load_failed` warning rather than silently downgrading to generic.

The bundled profile name is `cann`. For any other C++/CMake + Python repo the
generic core runs with no profile.

```bash
sbom --repo-root ../ops-math --repo-profile cann
```

---

### `--cmake-root PATH`

**Default:** none

Path to a shared CMake tree. For CANN repos this is the `cmake/` sibling
directory that contains `function/`, `third_party/`, and
`fetch_cann_cmake.cmake`.

This value is the *input* to authority resolution, not necessarily the path the
tool uses for macro expansion. The resolved `effective_cmake_root` (which may
differ when the repo fetches its CMake tooling from a tarball or git ref at
configure time) is what every collector uses. Pass `--cmake-source-authority
cmake-as-input` to force the tool to treat `--cmake-root` as authoritative
without resolving the fetch.

```bash
sbom --repo-root ../ops-math --cmake-root ../cmake
```

---

### `--scope {release,all}`

**Default:** `release`

Selects the output **view preset**. This is the highest-level filtering control;
it composes additively with the lower-level [`--exclude-scope`](#--exclude-scope-tokentoken),
[`--subjects`](#--subjects-idid), and [`--no-env-tools`](#--no-env-tools) flags
(an explicit flag still applies on top, in either view).

| Value | View |
|---|---|
| `release` *(default)* | Distributable subjects + their **runtime** dependency closure only. |
| `all` | The full view — every subject, every usage scope, every environment tool. No base filtering. |

**The `release` preset.** It is not a separate filtering path — it expands into
the same three transform inputs the explicit flags feed, applied additively:

1. **Excluded subject roles** = `{example, experimental, st_test, manual_example,
   non_distributable_test}`. Keeps `primary` + the `sibling_artifact` wheels + the
   primary `cmake_project`/`unclassified` root. Dropped roots emit an
   `excluded_scope` warning, exactly as `--exclude-scope` role tokens do.
2. **Keep only `usage_scope == runtime`** (a *keep-only* axis, not just an
   exclusion). An observation/edge survives **iff** its `usage_scope` is
   `runtime`; everything else is dropped — including `usage_scope == None`
   (**unclassified/None observations are dropped under release**). This is
   stricter than the explicit `--exclude-scope` exclusion axis, which only drops
   the named non-runtime scopes and *keeps* `None`. A component with no surviving
   observation is dropped, and so are edges to it. (Dropping `None` is what closes
   the leak where unclassified C++ fragments such as `gtest_shared_build` or a
   stray `find_package` survived the runtime view.)
3. **Omit environment tools** (`no_env_tools = True`).

**Net effect.** Distributable subjects and their runtime dependency closure only:
test deps, build tools (cmake/ninja/makeself/protoc/…), example/experimental/ST
roots, unclassified (`None`) observations, and host environment tools are all
dropped. A **multi-scope** dependency survives iff it carries a runtime
observation — e.g. `torch {runtime, build}` stays (via runtime; its build
observation is stripped). The main-product third-party (eigen/protobuf/json/
opbase/…) is collected as `usage_scope=runtime` by the C++ collector (a
path-neutral fragment of a distributable root defaults to runtime), so it
survives the keep-only filter.

**`--scope all` applies none of the release base filters** — it is the full view
(on `ops-math`: 11 subjects, 55 components, 116 environment tools). The lower-level
flags still work in this mode, e.g. `--scope all --exclude-scope test` drops the
test scope from the otherwise-full view.

```bash
# Default release view (distributable + runtime closure):
sbom --repo-root ../ops-math --repo-profile cann --cmake-root ../cmake

# The full view (everything):
sbom --repo-root ../ops-math --repo-profile cann --cmake-root ../cmake --scope all

# Full view minus the test scope (additive):
sbom --repo-root ../ops-math --scope all --exclude-scope test
```

---

### `--detail {compact,full}`

**Default:** `compact`

Selects the output **verbosity**, orthogonal to [`--scope`](#--scope-releaseall)
(which selects *which* subjects/deps appear; `--detail` selects *how much*
per-component provenance each one carries).

| Value | Output |
|---|---|
| `compact` *(default)* | The readable summary. Omits the verbose per-observation provenance and the CycloneDX `evidence.occurrences` array. |
| `full` | Today's complete output — every per-observation field plus the (deduped) occurrences. |

**`compact` (default) omits** the per-observation `sbomgen:obs:N:*` CycloneDX
component properties and the `sbomgen:obs:*` SPDX annotations (one block per
declaration site — the bulk of the file), and the CycloneDX
`evidence.occurrences` array. On a repo with many same-shaped roots this is a
large reduction: a dependency seen by 60+ roots otherwise emitted 60+ occurrence
entries (all at one location) and hundreds of `sbomgen:obs:*` properties.

**`compact` keeps** everything that makes the BOM useful: each component's
name/version/type/`purl`/licenses/copyright/hashes, the full dependency graph +
relationships, and the summary signals — `sbomgen:integrity:*`,
`sbomgen:completeness:*`, `sbomgen:alias:*`, `sbomgen:subject:*`,
`sbomgen:pedigree:*`, and the CycloneDX `pedigree` / SPDX `GENERATED_FROM`.

**`full`** restores the per-observation `sbomgen:obs:*` properties/annotations
and the `evidence.occurrences` array.

**Occurrence dedup (both modes).** Whenever `evidence.occurrences` is emitted
(i.e. in `full`), it carries **one entry per unique source location** — identical
locations collapse to a single occurrence (so a dependency declared by 60+ roots
at the same `source_file` yields one occurrence, not 60). The occurrence
`bom-ref` is stable per component, so `--reproducible` output stays
byte-identical. Both modes pass the official CycloneDX 1.5 / SPDX 2.3 validators.

```bash
# Compact (default) — readable summary, no per-observation noise:
sbom --repo-root ../ops-math --cmake-root ../cmake

# Full — every per-observation field + deduped occurrences:
sbom --repo-root ../ops-math --cmake-root ../cmake --detail full
```

---

### `--build-profile PROFILE`

**Default:** `declared-all`

Build profile passed through to the collectors. `declared-all` means every
declaration is considered regardless of conditional branches (the static parser
follows all branches).

---

### `--format FMT[,FMT]`

**Default:** `cyclonedx,spdx` (both)

Comma-separated list of output formats to emit. Accepted values:

| Value | Output file (normal) | Output file (`--split-subjects`) |
|---|---|---|
| `cyclonedx` | `sbom.cdx.json` | `<subject_id>.cdx.json` |
| `spdx` | `sbom.spdx.json` | `<subject_id>.spdx.json` |

Both outputs pass their respective official validators (CycloneDX 1.5,
SPDX 2.3).

```bash
# only CycloneDX
sbom --repo-root ../ops-math --format cyclonedx
```

---

### `--collector-mode {static,configured,both}`

**Default:** `static`

Which collection strategy to run:

- `static` — parses CMake and Python sources without configuring or building.
  No build tree required. Sees every conditional branch (`declared-all`).
- `configured` — *intended to* run CMake File API and/or configure-trace to
  capture graph information that only exists after configuration (would require
  CMake available and configured). **Not yet implemented — see below.**
- `both` — *intended to* run static first, then configured, and merge the
  results. **Not yet implemented — see below.**

**Not yet implemented (v0.1.0):** `configured` and `both` are accepted for
forward compatibility but currently run the **static** collector only — the CMake
File API / configure-trace path is planned. Passing `configured` or `both` emits
a `collector_mode_unimplemented` warning so the fallback is not silent.

---

### `--cmake-source-authority {actual-build,cmake-as-input}`

**Default:** `actual-build`

Determines which CMake tree the tool treats as the authority for macro
resolution.

- `actual-build` — the tool reads the repo's `fetch_cann_cmake.cmake` (or
  equivalent) and resolves one of four branches: skipped (parent project),
  local-dir override, tarball (with sha256), or git ref. The resolved
  `effective_cmake_root` is what macro expansion uses, not necessarily
  `--cmake-root`. A mismatch between the pinned ref and the supplied
  `--cmake-root` emits a `cann_cmake_tag_mismatch` warning.
- `cmake-as-input` — the value of `--cmake-root` is accepted as-is without
  fetch resolution. The `cann-cmake` component is excluded from the SBOM
  (`cann_cmake_trusted_input`). Use when you already know which cmake tree was
  used and want to skip authority resolution.

See [docs/cmake-authority.md](cmake-authority.md) for the full decision tree.

---

### `--network {off,on}`

**Default:** `off`

Controls network enrichment:

- `off` — purely offline. License data comes from the curated Notice files, the
  bundled known-license map, and local cache scans.
- `on` — additionally queries deps.dev and PyPI for Python packages (license,
  version, supplier). Live ClearlyDefined and the C++ archive-download path
  (downloading an archive to compute a checksum / scan its license) are **not yet
  implemented**: clearlydefined is consulted only from its vendored cache, and a
  normal `--network on` run is effectively a deps.dev/PyPI fetch. Any
  network-computed sha256 would be recorded in provenance, never equated to a
  checked-in `URL_HASH`.

`--resolve-cmake-ref` implies `--network on` (see below).

---

### `--resolve-cmake-ref`

**Default:** off (flag absent)

When set, resolves the pinned CMake ref (the `fetch_cann_cmake.cmake` git tag,
`master-016`) to a commit via `git ls-remote` of `https://gitcode.com/cann/cmake.git`.
On success the `cann-cmake` component is **pinned**: the resolved commit populates
`CmakeAuthority.revision` and the component's `vcs_ref.resolved_commit`, and the
`UNPINNED_GIT` marker is dropped. Implies `--network on`; you do not need to pass
both.

If resolution fails (offline, `git` unavailable, or the ref is gone) the run
degrades gracefully: the component is left unpinned and a
`cmake_ref_resolution_failed` warning is emitted (rather than crashing).

```bash
sbom --repo-root ../ops-math --cmake-root ../cmake --resolve-cmake-ref
```

---

### `--allow-input-fallback`

**Default:** off (flag absent)

When `--cmake-source-authority actual-build` cannot resolve the authority
offline (no pinned tarball sha256, no network, ref unresolvable), the run
normally fails. With `--allow-input-fallback` it falls back to treating
`--cmake-root` as authoritative, emitting a
`cmake_acquisition_metadata_unresolved` warning instead of exiting.

Only meaningful when `actual-build` authority is used and network is off.

---

### `--exclude-scope TOKEN[,TOKEN]`

**Default:** none (nothing excluded beyond the active [`--scope`](#--scope-releaseall) preset)

Excludes subjects and/or observations matching the given scope token. Repeatable;
each use may itself be comma-separated. Tokens are kept as raw strings internally
and resolved to two orthogonal enum axes when the subject collector runs. This
flag is **additive over `--scope`**: its exclusions apply on top of the release
preset (or on top of the otherwise-unfiltered `--scope all` view).

**Recognised tokens and their effects:**

| Token | Drops roots with this `SubjectRole` | Filters observations with this `UsageScope` |
|---|---|---|
| `example` | `SubjectRole.EXAMPLE` | `UsageScope.EXAMPLE` |
| `st_test` | `SubjectRole.ST_TEST` | `UsageScope.ST_TEST` |
| `manual_example` | `SubjectRole.MANUAL_EXAMPLE` | `UsageScope.MANUAL_EXAMPLE` |
| `experimental` | `SubjectRole.EXPERIMENTAL` | `UsageScope.EXPERIMENTAL` |
| `non_distributable_test` | `SubjectRole.NON_DISTRIBUTABLE_TEST` | *(none — role only)* |
| `test` | *(none — scope only)* | `UsageScope.TEST` |
| `build` | *(none — scope only)* | `UsageScope.BUILD` |
| `runtime` | *(none — scope only)* | `UsageScope.RUNTIME` |

A token that has a `SubjectRole` causes `discover_subjects` to drop the matching
root and emit an `excluded_scope` warning per dropped root. A token that has a
`UsageScope` filters the assembled BOM during reconcile: every observation whose
`usage_scope` matches is removed, each affected `Component.scopes` is recomputed
from its surviving observations, any component left with zero observations is
dropped, and every dependency edge whose endpoint was dropped (or whose own
`usage_scope` matches) is removed. A single summarising `excluded_scope` warning
records the dropped counts. Some tokens (`example`, `st_test`, `manual_example`,
`experimental`) act on both axes simultaneously. `non_distributable_test` acts
only on the role axis (no `UsageScope` counterpart). `test`, `build`, and
`runtime` act only on the observation axis.

A component is dropped only when *all* of its observations are excluded: a
multi-scope dependency survives. For example `--exclude-scope test` removes a
test-only dependency (gtest) but keeps `torch` (which is also `runtime`/`build`);
`--exclude-scope build` removes a pure build-only dependency while keeping any
dependency that is also used at runtime or in examples/tests.

**`--exclude-scope` keeps `usage_scope == None`; the `release` preset does not.**
The explicit exclusion axis only drops observations whose `usage_scope` is one of
the named tokens — an unclassified (`None`) observation is always *kept*. The
`release` preset adds a separate **keep-only-`runtime`** axis on top, which drops
`None` (and every non-runtime scope). Composed, `--scope release --exclude-scope
runtime` drops everything (keep-only `{runtime}` minus the `runtime` exclusion
leaves nothing).

An unrecognised token also emits an `excluded_scope` warning noting it was
unrecognised.

```bash
# single token
sbom --repo-root ../ops-math --exclude-scope experimental

# two tokens, two flags
sbom --repo-root ../ops-math --exclude-scope experimental --exclude-scope manual_example

# two tokens, comma-separated in one flag
sbom --repo-root ../ops-math --exclude-scope experimental,manual_example
```

---

### `--subjects ID[,ID]`

**Default:** none (all subjects emitted)

Comma-separated list of subject IDs to include in the output. This restricts the
**combined** BOM to the named subjects and their dependency closure: only the
named subjects, the components reachable from them by following dependency edges
(subject→component and component→component), the edges among those kept nodes,
and the environment tools rooted on a kept subject are retained. Every other
subject, every component owned only by a dropped subject, and their edges/tools
are removed. If the dropped set includes the primary subject, the lowest-role
kept subject is promoted to the emitted root so `metadata.component` stays valid.

When combined with `--split-subjects`, only the listed subjects get their own
sub-BOM files.

Subject IDs are the stable identifiers assigned by `discover_subjects`
(e.g. `ops_math`, `ascend_ops`); a subject may also be named by its identity
name. For example `--subjects ops_math` yields only `ops_math` plus its
dependency closure — no `ascend_ops`/`npu_math_extension`/example roots, and no
`torch` (which belongs to a sibling subject).

```bash
sbom --repo-root ../ops-math --subjects ops_math
```

---

### `--split-subjects`

**Default:** off (flag absent)

When set, emits one sub-BOM file per discovered subject instead of a single
combined BOM. Each file is named `<subject_id>.<ext>` (e.g.
`ops_math.cdx.json`, `ops_math.spdx.json`). The full combined BOM is not
written.

Can be combined with `--subjects` to restrict which subjects get output files.

```bash
sbom --repo-root ../ops-math --split-subjects --out-dir ./out/split
```

---

### `--no-env-tools`

**Default:** off (flag absent)

When set, omits every environment tool from the output. Reconcile clears
`Document.environment_tools`, so the emitters produce zero `sbomgen:envtool:*`
CycloneDX properties and zero environment-tool SPDX annotations. Useful for a
leaner BOM focused on packaged components and subjects when host-tool provenance
is not needed.

```bash
sbom --repo-root ../ops-math --no-env-tools
```

---

### `--guess-pypi-urls`

**Default:** off (flag absent)

When set, constructs a canonical PyPI project URL for **Python components only**
(`languages` contains `Python`) and emits it as a download link:

- name is normalized PEP 503 (lowercase; runs of `[-_.]` collapsed to a single
  `-`);
- with a concrete version → `https://pypi.org/project/<name>/<version>/`,
  otherwise (unpinned) → `https://pypi.org/project/<name>/`;
- CycloneDX adds a `DISTRIBUTION` `externalReference` with that URL plus a
  `sbomgen:python:download_url_source=guessed` property;
- SPDX uses the URL as the package `downloadLocation` (when no resolved URL was
  already found) plus a `sbomgen:python:download_url_source=guessed` annotation.

The URL is a **construction**, not a verified artifact link — the flag name and
the `download_url_source=guessed` marker make that explicit. The `pkg:pypi/<name>`
purl is emitted regardless of this flag; only the download URL is gated. With the
flag absent (the default), Python components keep their purl but carry no PyPI
download URL (SPDX `downloadLocation` stays `NOASSERTION`). Non-Python components
are unaffected.

```bash
sbom --repo-root ../ops-math --guess-pypi-urls
```

---

### `--scancode {enrich,fallback,crosscheck,both}`

**Default:** off (flag absent)

Opt-in [ScanCode Toolkit](https://github.com/nexB/scancode-toolkit) license/copyright
backend. ScanCode is a heavyweight, **separately installed** scanner — it is *not*
a dependency of sbom-gen; the tool shells out to its CLI only when this flag is
set (see [`--scancode-path`](#--scancode-path-path)). It can only read **on-disk
source**: a subject (which always has a local `source_path`) or a component whose
`resolved_url_or_path` is an existing local directory. Components with no local
source — most of them in static offline mode — are skipped.

| Mode | What it does |
|---|---|
| `enrich` | Uses ScanCode as the **highest-priority** license layer. A confident on-disk detection overrides whatever the normal resolver produced: it sets `component.license` / `subject.license` and the component `copyright` from ScanCode's holders/copyrights, recording `Provenance(field="license", source="scancode")`. |
| `fallback` | **Fill-only.** Sets `license`/`copyright` only where still unset — it never overrides a curated/known/cached value and stashes no prior. Pairs with [`--deps-dir`](#--deps-dir-path) to resolve a new dependency's license + copyright from its real on-disk source when there is no pre-seeded data. |
| `crosscheck` | **Changes no license values.** After the document is built it runs ScanCode on the same subjects/components, compares ScanCode's SPDX license against the resolved license, emits a `license_crosscheck_mismatch` warning per difference, and writes a `license-crosscheck.json` report to the output dir. The report is **3-way** where a curated Notice exists: each row is `{name, ours, scancode, curated, score, agree}` (`curated` = the Notice's declared license, or `null`). |
| `both` | Runs `enrich` (applying ScanCode), then writes the same 3-way `license-crosscheck.json` report built from the **displaced prior values** (`ours=<what the resolver had> scancode=<applied> curated=<Notice declared>`) — no second scan. |

**Confidence threshold (default 80).** ScanCode reports a per-match score. A
detection whose best score is **below the threshold**, or whose expression is
ScanCode's `unknown-license-reference` placeholder, is treated as **NOASSERTION** —
the backend never asserts a low-confidence guess. A non-SPDX `LicenseRef-scancode-*`
token is mapped to a synthesized `LicenseRef-<slug>` with inline text so the SPDX
validators accept it.

**Graceful when ScanCode is missing.** If `--scancode` is set but no ScanCode
binary can be resolved, the tool emits a `scancode_unavailable` warning and
**continues with the normal resolver** — it does not hard-fail the SBOM. A
per-target scan that times out or errors emits a `scancode_scan_failed` warning
and that target keeps the normal result.

**Performance.** ScanCode has a ~1.2s cold start and scans ~10 files/sec, so the
backend does **not** walk giant trees. Each scan is scoped to the
license/copyright-bearing surface: the `LICENSE`/`COPYING`/`NOTICE`/`COPYRIGHT*`
files plus the **top level** of the target directory (no recursion).

```bash
# Enrich licenses from on-disk source (highest-priority layer):
sbom --repo-root ../ops-math --scancode enrich \
  --scancode-path /opt/scancode/scancode

# QA pass only — keep our licenses, write license-crosscheck.json:
sbom --repo-root ../ops-math --scancode crosscheck
```

---

### `--scancode-path PATH`

**Default:** none (use `scancode` on `PATH`)

Explicit path to the ScanCode binary. When omitted, `scancode` is resolved from
`PATH`. Only consulted when [`--scancode`](#--scancode-enrichfallbackcrosscheckboth) is
set. ScanCode is typically installed in its own virtualenv separate from
sbom-gen's; point this at that venv's `bin/scancode`.

```bash
sbom --repo-root ../ops-math --scancode both \
  --scancode-path /opt/scancode-venv/bin/scancode
```

---

### `--profile-value KEY=VALUE[,KEY=VALUE]`

**Default:** none

Passes profile-specific key/value pairs to the profile's hooks. Repeatable; each
use may itself be comma-separated. Multiple `KEY=VALUE` pairs in one flag value
are separated by commas.

Values flow into `Config.profile_values` (a `dict[str, str]`). The CANN profile
uses this for keys such as `product_side` and `target_arch`.

```bash
# single pair
sbom --repo-root ../ops-math --profile-value product_side=device

# two pairs, one flag
sbom --repo-root ../ops-math --profile-value product_side=device,target_arch=aarch64

# two pairs, two flags
sbom --repo-root ../ops-math \
  --profile-value product_side=device \
  --profile-value target_arch=aarch64
```

---

### `--cmake-define KEY=VALUE`

**Default:** none

Supplies a *proven* pre-`project()` CMake cache value. Repeatable; each flag
takes exactly one `KEY=VALUE` pair (no comma-separation within a single flag).

`--cmake-define` values are the only safe way to tell the authority resolver
that a CMake cache variable has a specific value without running CMake. A value
found only in `CMakeCache.txt` is considered ambiguous (it was set during a
previous configure, not proven to be a pre-include define) and emits
`cmake_authority_input_ambiguous`. Only `--cmake-define`/`--config` or a
configure-trace counts as proof.

The most common use is `CANN_3RD_LIB_PATH` which controls which branch of
`fetch_cann_cmake.cmake` the authority resolver follows.

```bash
sbom --repo-root ../ops-math \
  --cmake-root ../cmake \
  --cmake-define CANN_3RD_LIB_PATH=/path/to/3rd
```

---

### `--reproducible`

**Default:** off (flag absent)

Produces deterministic output:

- Timestamps in both emitters are fixed (not the current time).
- CycloneDX `serialNumber` and SPDX `documentNamespace` are derived from a
  content hash of the document rather than randomly generated.
- Field ordering is stable.

When the `SOURCE_DATE_EPOCH` environment variable is set and `--reproducible` is
active, that integer Unix timestamp is used as the fixed timestamp. This honours
the [reproducible-builds.org SOURCE_DATE_EPOCH convention](https://reproducible-builds.org/specs/source-date-epoch/).

```bash
SOURCE_DATE_EPOCH=1700000000 sbom --repo-root ../ops-math --reproducible
```

---

### `--out-dir PATH`

**Default:** `./out`

Directory where output files are written. Created (including parents) if it does
not exist. For a standard (non-split) run with both formats, the directory will
contain:

```
out/
  sbom.cdx.json    # CycloneDX 1.5 JSON
  sbom.spdx.json   # SPDX 2.3 JSON
```

With `--split-subjects` the files are named `<subject_id>.cdx.json` and
`<subject_id>.spdx.json`.

---

### `--config PATH`

**Default:** none

Path to an `sbom.toml` config file. All flags can be set in this file; CLI flags
always override file values (see [Precedence](#precedence)). See
[Config file](#config-file) below.

```bash
sbom --config ./sbom.toml
```

---

## Precedence

Configuration is resolved in this order (highest wins):

1. **Explicit CLI flags** — any flag passed on the command line.
2. **`--config` file** — values from `sbom.toml` for keys not set on the CLI.
3. **Documented defaults** — the defaults listed above.

Additionally: `--resolve-cmake-ref` forces `network = "on"` regardless of what
`--network` or the config file says.

---

## Config file

`sbom.toml` uses [TOML](https://toml.io/) syntax. Load it with `--config
sbom.toml`. Every key is optional; omitted keys fall back to CLI or defaults.

### Key reference

Top-level simple keys mirror the CLI flag names with hyphens replaced by
underscores:

```toml
repo_root    = "./ops-math"          # --repo-root
repo_profile = "cann"                # --repo-profile
cmake_root   = "./cmake"             # --cmake-root
scope        = "release"             # --scope (release | all; default release)
detail       = "compact"             # --detail (compact | full; default compact)
build_profile = "declared-all"       # --build-profile
formats      = ["cyclonedx", "spdx"] # --format (list)
collector_mode = "static"            # --collector-mode
cmake_source_authority = "actual-build"  # --cmake-source-authority
network      = "off"                 # --network
resolve_cmake_ref   = false          # --resolve-cmake-ref
allow_input_fallback = false         # --allow-input-fallback
exclude_scopes = ["experimental"]    # --exclude-scope (list of tokens)
subjects     = ["ops_math"]          # --subjects (list of IDs)
split_subjects = false               # --split-subjects
no_env_tools = false                 # --no-env-tools
guess_pypi_urls = false              # --guess-pypi-urls
scancode     = "fallback"            # --scancode (off when absent: enrich | fallback | crosscheck | both)
scancode_path = "/opt/scancode/bin/scancode"  # --scancode-path
deps_dir     = "../cann-src-third-party"       # --deps-dir
depsdev_cache = "./depsdev_cache.json"         # --depsdev-cache (override path)
refresh_data = "deps-dir"            # --refresh-data (action: refresh + exit; usually CLI-only)
reproducible = false                 # --reproducible
out_dir      = "./out"               # --out-dir
```

The two repeatable `KEY=VALUE` flags use nested TOML sections:

```toml
[cmake.defines]
# --cmake-define KEY=VALUE (one entry per define)
CANN_3RD_LIB_PATH = "/path/to/3rd"

[profile.values]
# --profile-value KEY=VALUE
product_side = "device"
target_arch  = "aarch64"
```

### Complete worked example

```toml
# sbom.toml — CANN ops-math project
repo_root    = "../ops-math"
repo_profile = "cann"
cmake_root   = "../cmake"
formats      = ["cyclonedx", "spdx"]
collector_mode = "static"
cmake_source_authority = "actual-build"
network      = "off"
exclude_scopes = ["experimental", "manual_example"]
reproducible = true
out_dir      = "./out"

[cmake.defines]
CANN_3RD_LIB_PATH = "/opt/cann/3rd"

[profile.values]
product_side = "device"
```

Invoke with:

```bash
sbom --config sbom.toml
```

Override a single key on the CLI; the file value is ignored for that key only:

```bash
sbom --config sbom.toml --out-dir ./ci-out --network on
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. All requested formats emitted and validated. |
| `1` | Validation failure. At least one emitted file failed its official schema validator (CycloneDX or SPDX). Files were still written. |
| `2` | Fatal error. An unhandled exception prevented the pipeline from completing (e.g. missing `--repo-root`, broken profile import). |

---

## Output files

All output is written to `--out-dir` (default `./out`). The directory is created
if it does not exist. Summary statistics (subjects, components, dependency edges,
environment tools, warning counts by code) are printed to stderr.

**Normal run (both formats):**

```
out/
  sbom.cdx.json     # CycloneDX 1.5 JSON, schema-valid
  sbom.spdx.json    # SPDX 2.3 JSON, schema-valid
```

**`--split-subjects` run:**

```
out/
  ops_math.cdx.json
  ops_math.spdx.json
  ascend_ops.cdx.json
  ascend_ops.spdx.json
  ...
```

**`--scancode crosscheck` / `--scancode both` run** also writes a QA report:

```
out/
  sbom.cdx.json
  sbom.spdx.json
  license-crosscheck.json   # [{name, ours, scancode, curated, score, agree}, ...]
```

(`--scancode enrich` alone writes no report — the ScanCode license is folded
directly into the emitted SBOM.)

---

## End-to-end examples

### ops-math default (CANN profile, both formats)

Generates a full SBOM for the CANN `ops-math` repo. The CANN profile is
auto-detected from cann-cmake markers (`add_cann_third_party(` /
`set_cann_package(` / …) or a `gitcode.com/cann/` git origin. Authority is
resolved via `fetch_cann_cmake.cmake` (the `actual-build` default).

```bash
sbom \
  --repo-root ../ops-math \
  --cmake-root ../cmake \
  --reproducible \
  --out-dir ./out
```

Outputs `out/sbom.cdx.json` and `out/sbom.spdx.json`.

---

### ops-math with profile named explicitly

```bash
sbom \
  --repo-root ../ops-math \
  --repo-profile cann \
  --cmake-root ../cmake \
  --reproducible \
  --out-dir ./out
```

Identical result to the above; `--repo-profile cann` is redundant when
auto-detect succeeds but is useful for clarity or if auto-detect is ambiguous.

---

### Generic repo (no profile, no CMake root)

Any C++/CMake + Python repo without a custom profile. The generic core runs the
static CMake and Python collectors with no profile hooks.

```bash
sbom --repo-root ../some-repo --out-dir ./out
```

---

### Split subjects

Emits one sub-BOM per discovered subject instead of a combined BOM.

```bash
sbom \
  --repo-root ../ops-math \
  --cmake-root ../cmake \
  --split-subjects \
  --out-dir ./out/split
```

Produces `out/split/ops_math.cdx.json`, `out/split/ops_math.spdx.json`, and one
pair per additional subject.

---

### Subject filter

Only emit the `ops_math` subject; ignore all others.

```bash
sbom \
  --repo-root ../ops-math \
  --cmake-root ../cmake \
  --subjects ops_math \
  --out-dir ./out
```

---

### Exclude experimental and manual-example roots

Drops roots the CANN profile classifies as `experimental` or `manual_example`
from both subject discovery and observation collection.

```bash
sbom \
  --repo-root ../ops-math \
  --cmake-root ../cmake \
  --exclude-scope experimental,manual_example \
  --out-dir ./out
```

---

### cmake-as-input authority

Trust `--cmake-root` directly; skip `fetch_cann_cmake.cmake` resolution. The
`cann-cmake` component is omitted from the SBOM.

```bash
sbom \
  --repo-root ../ops-math \
  --cmake-root ../cmake \
  --cmake-source-authority cmake-as-input \
  --out-dir ./out
```

---

### Network enrichment on

Enables deps.dev/PyPI queries for Python packages and archive scanning for C++
packages. Useful for filling in license data that is not available offline.

```bash
sbom \
  --repo-root ../ops-math \
  --cmake-root ../cmake \
  --network on \
  --out-dir ./out
```

---

### Network on with cmake-ref resolution

Resolves the pinned CMake git ref by fetching it. `--resolve-cmake-ref` already
implies `--network on`.

```bash
sbom \
  --repo-root ../ops-math \
  --cmake-root ../cmake \
  --resolve-cmake-ref \
  --out-dir ./out
```

---

### Reproducible output with SOURCE_DATE_EPOCH

Byte-identical output across runs; timestamps pinned to the epoch value.

```bash
SOURCE_DATE_EPOCH=1700000000 sbom \
  --repo-root ../ops-math \
  --cmake-root ../cmake \
  --reproducible \
  --out-dir ./out
```

---

### Config file driven

```bash
sbom --config ./sbom.toml
```

Where `sbom.toml` might contain:

```toml
repo_root    = "../ops-math"
cmake_root   = "../cmake"
reproducible = true
out_dir      = "./out"
exclude_scopes = ["experimental"]

[cmake.defines]
CANN_3RD_LIB_PATH = "/opt/cann/3rd"
```

---

### Proven CMake define to guide authority resolution

When the `fetch_cann_cmake.cmake` local-dir branch depends on
`CANN_3RD_LIB_PATH`, supply it as a proven pre-include define. A value only
present in `CMakeCache.txt` is ambiguous and would emit
`cmake_authority_input_ambiguous`; `--cmake-define` is the safe form.

```bash
sbom \
  --repo-root ../ops-math \
  --cmake-root ../cmake \
  --cmake-define CANN_3RD_LIB_PATH=/opt/cann/3rd \
  --out-dir ./out
```
