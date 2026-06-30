# CLAUDE.md — sbom-gen

Project guidance for working in this repository. Read alongside [`README.md`](README.md)
(user-facing) and [`INTERFACE.md`](INTERFACE.md) (the frozen module contract). The
full design rationale is in `../SBOM_DESIGN.md`.

## What this is

A standalone SBOM generator for C++/CMake + Python repos. **Generic core**
(`src/sbom/`) + **repo profile plugins** (`src/sbom_profile_cann/` is the only
one). It emits CycloneDX 1.5 and SPDX 2.3 via the official libraries. The
reference target is `../ops-math` (CANN), with `../cmake` as the shared CMake
tree.

## Environment & commands

- Python ≥ 3.11; a venv lives at `./.venv` (use it explicitly — `./.venv/bin/python`).
- Run tests: `./.venv/bin/python -m pytest tests -q` (should be all green).
- The regression lock: `./.venv/bin/python -m pytest tests/test_drift_ops_math.py -q`.
- End-to-end on the real repo (default `--scope release` view):
  ```
  ./.venv/bin/python -m sbom --repo-root ../ops-math --repo-profile cann \
      --cmake-root ../cmake --reproducible --out-dir ./out
  ```
  Add `--scope all` for the full view (every subject/scope + environment tools).
- Single format: `--format spdx` (or `--format cyclonedx`); `--format` takes a
  comma list, default both.
- Refresh a vendored data file (emits no SBOM): `--refresh-data
  {depsdev|aliases|first-party|known-licenses|all}`. `depsdev`
  re-fetches licenses from deps.dev/PyPI and rewrites the cache (requires
  `--network on`); `aliases` writes `aliases.suggested.yaml`; the curated files
  are validate-only. `--depsdev-cache PATH` overrides the cache location.
- After changing dependencies/packaging: `./.venv/bin/pip install -e '.[dev]' -q`.
- Outputs go to `./out` (and `./out2` for reproducibility diffs); both are
  scratch — don't commit them.

## Architecture invariants (do not violate)

1. **The contract is frozen.** `src/sbom/models.py`, `src/sbom/profile.py`, and
   `INTERFACE.md` define the shared shapes. Changing a public dataclass field or
   function signature means updating **all three** plus every dependent module
   and test — do it deliberately, never as a silent local tweak.
2. **Generic core stays generic.** No `ops-math`/CANN knowledge in `src/sbom/`.
   Anything CANN-specific (the `add_cann_third_party` macro, `version.cmake`
   parsing, `fetch_cann_cmake`, curated Notice/license files, the alias map, root
   path classification) belongs in `src/sbom_profile_cann/`.
3. **Pipeline direction.** Collectors return plain model records
   (`CollectResult`); **`reconcile.py` is the only stage that builds a
   `Document`**; emitters only read it. Don't emit from a collector or collect in
   an emitter.
4. **`EnvironmentTool` is never a `Component`.** Generic host tools (`patch`,
   `tar`, `git`, `ccache`, `perl`, `cmake -E`, …) become `EnvironmentTool`
   records → metadata properties / annotations. There is intentionally **no**
   `environment_tool` `SourceKind`. Domain tools that *are* dependencies
   (`protoc`/`host_protoc`, `cmake`, `ninja`) stay components/tooling.
5. **Two orthogonal scope axes.** `declaration_reachability` (is the declaration
   reached in a configure?) and `usage_scope` (runtime/test/build/example/…) are
   separate. Never collapse them into one "scope". `usage_scope` follows the
   **call site** (e.g. gtest is declared in `ut.cmake` → `test`), not the file
   where the third-party fragment is defined.
6. **Emit via the official libraries.** `cyclonedx-python-lib` and `spdx-tools`
   object models + writers, then their validators. No hand-rolled JSON, no
   vendored schemas. `cyclonedx-python-lib[json-validation]` is a hard dependency
   so CycloneDX validation never silently degrades.

## The naming convention (a real gotcha)

An `Observation` only becomes part of a `Component` if `reconcile._observation_name`
can resolve a name for it. **Any observation that should map to a component MUST
carry its canonical name in `ecosystem_data['name']`.** `_observation_name`
resolves, in order: an explicit `name`, then `ecosystem_data` keys
`['name','component','canonical_name','cann_package','program','link_target','target']`,
then `find_package.name`. Forgetting this silently drops observations (it once
dropped 54 — all the `version.cmake` package deps and `find_package` deps). If a
dep "disappears" from the output, check for an `unattached_observation` warning
and that the producer set `ecosystem_data['name']`.

## CMake source authority

`fetch_cann_cmake.cmake` is wrapped in `if(NOT PROJECT_SOURCE_DIR)` and picks one
of: local dir / pinned tarball / git tag — or is **skipped** when built under a
parent project. The generator computes one `CmakeAuthority{branch,
effective_cmake_root, ref, revision, ...}` from **pre-`project()`** state and
routes all `add_cann_third_party()` resolution through `effective_cmake_root` —
**never the raw `--cmake-root`**. A bare `CMakeCache.txt` value is *not* proof of
a pre-include define; only `--cmake-define`/config/trace counts (else →
`cmake_authority_input_ambiguous`, Git branch assumed). See `docs/cmake-authority.md`.

## Adding a repo profile

Subclass `Profile`, implement the hooks you need (others have safe no-op
defaults), add a `detect(repo_root)` classmethod, and register it under the
`sbom.profiles` entry point group in your `pyproject.toml`. The CANN profile in
`src/sbom_profile_cann/__init__.py` is the worked example. Reuse
`sbom.cmake.parse` helpers — do not reimplement CMake parsing in a profile.

## Testing conventions

- `tests/test_drift_ops_math.py` is the **regression lock** against real
  `ops-math`. Keep it green; add to it when you fix a correctness bug so it can't
  regress. Resolve names through aliases in assertions (e.g. `ASC` canonicalizes
  to `asc-devkit`).
- Use `--reproducible` for any golden/byte-identical comparison.
- Network enrichers (`enrich/net.py`) must be **mocked** in unit tests — no live
  calls in CI.
- Mirror real `../cmake/third_party/*.cmake` patterns in parser fixtures.

## Known by-design behaviors (don't "fix" these)

- **The default output is the `release` view** (`--scope release`): distributable
  subjects + their RUNTIME dependency closure only (no test deps, no build tools,
  no example/experimental/ST roots, no environment tools). On `ops-math` this is
  3 subjects / 36 components / 0 environment tools. `--scope all` is the escape
  hatch to the full view (11 / 55 / 116). The preset is NOT a parallel filter — it
  expands additively into the existing transform inputs (excluded usage scopes +
  excluded roles + `no_env_tools` + the **keep-only** runtime axis) via
  `config.release_excluded_usage_scopes` / `release_excluded_roles` /
  `release_no_env_tools` / `release_keep_usage_scopes`; an explicit
  `--exclude-scope` / `--subjects` / `--no-env-tools` still applies on top in both
  modes. **The release view keeps ONLY `usage_scope == runtime`: unclassified
  (`None`) observations are dropped under release** (the explicit `--exclude-scope`
  axis, by contrast, keeps `None`). The C++ collector scopes a path-neutral
  fragment of a distributable root as `runtime` so eigen/protobuf/json/opbase
  survive, while genuinely test/build fragments (gtest_shared, cann-cmake,
  protoc) carry their non-runtime scope and drop. Tests that assert the full view
  must pin `scope="all"`.
- **The default output detail is `compact`** (`--detail compact`; threads
  `Config.detail` → `EmitOptions.detail`). Orthogonal to `--scope`: it controls
  per-component verbosity, not which subjects/deps appear. **compact OMITS** the
  per-observation `sbomgen:obs:N:*` CycloneDX properties / `sbomgen:obs:*` SPDX
  annotations AND the CycloneDX `evidence.occurrences` array; it **KEEPS**
  name/version/type/purl/licenses/copyright/hashes, the dependency graph +
  relationships, and the summary signals `sbomgen:integrity:*` /
  `sbomgen:completeness:*` / `sbomgen:alias:*` / `sbomgen:subject:*` /
  `sbomgen:pedigree:*` (+ pedigree). **`--detail full`** restores the
  `sbomgen:obs:*` provenance + occurrences. The gate is in
  `cyclonedx._add_component_properties` / `spdx._annotate_component`. **Tests that
  assert `sbomgen:obs:*` in the output must use `EmitOptions(detail="full")`** (see
  `REPRO_FULL` in `tests/test_emit.py`). Both modes validate and are reproducible.
- **CycloneDX `evidence.occurrences` is deduped by location (both modes).** When
  emitted (i.e. `--detail full`), `cyclonedx._deduped_occurrences` keeps ONE
  occurrence per unique source location — a dep seen by 60+ roots at the same
  `source_file` collapses from 60+ entries to 1. The occurrence `bom-ref` is the
  per-component location index (stable under `--reproducible`).
- **Subject ids are made unique at emit.** Distinct roots can share a `Subject.id`
  / slugify to the same id (a runtime repo's ~62 `Runtime_Sample`/`Memory_Sample`
  example roots). `discover_subjects._dedup_identical_subjects` drops genuinely
  identical roots (same id/identity/role/`source_path`); the emitters then call
  `emit/_common.disambiguate_subject_ids` to give each remaining subject a unique
  emitted id (first claimant keeps the bare id, later collisions get `-<n>`), so
  `SPDXRef-Subject-*` / CycloneDX subject bom-refs never collide (was a
  `spdx_invalid`). `DESCRIBES` + edge endpoints use the disambiguated id. **Don't
  key the subject emit dicts so a later same-id subject overwrites an earlier one
  with `[k]=` — use `setdefault` so edges resolve to the first claimant.**
- `build` is a real PyPI package in an example `requirements.txt`, not a leaked
  directory.
- `eigen 5.0.0` is correct per the curated list (older design references were stale).
- protobuf shows effective `3.13.0` with upstream `25.1` in pedigree — the
  rewrite lives inside a patch, only surfaced via the curated Notice layer.
- **Static-mode version pins.** A Python dep sets a component version ONLY when
  it is an EXACT pin (`==`/`===`, no `*` — see `collectors.python.concrete_version`):
  `attrs==24.2.0` → `24.2.0`; `numpy<2`, `==1.4.*`, `~=1.2`, `>=3.20,<4.0`,
  `==1.0,!=1.0.1`, a bare dep, and CANN `>=8.5` package deps are constraint-only.
  The full specifier is always recorded as `Observation.version_constraint`. A
  component with NO concrete version gets `completeness["version"]="unpinned"`
  (reconcile); one with a concrete version (eigen/protobuf, a `==` pin) never is.
  Different concrete pins for one component → keep the lowest + a
  `version_pin_conflict` warning. Emit: `component.version`/`versionInfo` and the
  CycloneDX `@version` purl qualifier are present only for a concrete version; an
  unpinned Python dep emits a version-less purl (`pkg:pypi/numpy`) and SPDX omits
  `versionInfo`. **Don't "pin" a range** — the unpinned marker is honesty, not a bug.
- **Completeness is per-component, not a document comment.** `completeness` is
  emitted ONLY as per-component `sbomgen:completeness:*` (CycloneDX properties / SPDX
  per-package annotations via `emit/spdx.py:_annotate_component`). It is NOT
  aggregated into the SPDX document-level comment (`_document_comment` returns
  `None`) — aggregating it flooded the global comment with one entry per
  unpinned/unresolved dep. Don't reintroduce that.
- **`--guess-pypi-urls` is opt-in (default OFF).** Threads `Config.guess_pypi_urls`
  → `EmitOptions.guess_pypi_urls`. When ON, a Python component (`languages`
  contains `Python`) gets a constructed `https://pypi.org/project/<pep503-name>/
  [<version>/]` URL: CycloneDX as a `DISTRIBUTION` externalReference, SPDX as the
  package `downloadLocation` (replacing `NOASSERTION` only when no resolved URL was
  found), both marked `sbomgen:python:download_url_source=guessed`. The `pkg:pypi`
  purl is always emitted regardless of the flag — only the download URL is gated.
  The URL is a construction, not a verified link; OFF by default. See
  `emit/_common.py:guessed_pypi_url` / `pep503_name`.
- **`--scancode {enrich,fallback,crosscheck,both}` is opt-in (default OFF).** ScanCode
  Toolkit is a SEPARATE install the tool shells out to (`scancode -cl --json-pp`);
  it is NOT a sbom-gen dependency. `enrich` makes it the highest-priority license
  layer (runs in `reconcile._resolve_licenses` for components + a subject pass in
  `reconcile()`; overrides `.license`/`.copyright`, records
  `Provenance(field="license", source="scancode")`, stashes the displaced prior as
  `license_prior` provenance / `__scancode_prior_license__` on subjects).
  `crosscheck` changes NO license values — it is a QA pass orchestrated in
  `cli.main` (post-reconcile, around emit) that writes
  `<out_dir>/license-crosscheck.json` (rows `{name, ours, scancode, curated,
  score, agree}` — **3-way** when the profile exposes a curated Notice; `curated`
  is the Notice declared license or `null`, `agree` is still ours-vs-scancode) and
  emits `license_crosscheck_mismatch` warnings; `both` enriches then reports the
  displaced priors. `fallback` is FILL-ONLY (sets `.license`/`.copyright` only
  where unset — never overriding curated/known/pre-seed, no prior stash); it
  pairs with `--deps-dir` for offline resolution of new deps from real source.
  The full license precedence is **scancode (if enrich) >
  curated (Notice/List) > known-map > deps-dir > cache-scan > depsdev > network >
  NOASSERTION**; the
  curated Notice supplies copyright too (precedence scancode > curated-Notice >
  none), so a component with no concrete license still gets the Notice's declared
  license/copyright (alias-resolved). Only on-disk source is scannable
  (`scancode.target_dir_for(obj, repo_root)`: a subject's `source_path` or a
  component's `resolved_url_or_path`, each **resolved against `config.repo_root`**
  when relative — `""` means the repo root) — most static-mode components are
  skipped. ScanCode 32.5.0 rejects multiple absolute inputs in one call, so the
  runner scans ONE input path per invocation and merges. A None scan result emits
  `scancode_scan_failed` for BOTH the component and subject paths. CONFIDENCE
  THRESHOLD = 80: a below-threshold score or an
  `unknown-license-reference` → NOASSERTION (never assert a guess); a
  `LicenseRef-scancode-*` token is mapped via `enrich/licenseref.py`. The binary is
  located by `ScancodeRunner._resolve`: `--scancode-path` (must be executable; an
  invalid explicit path is a hard error, no fall-through) > `$SCANCODE_PATH` >
  `shutil.which("scancode")` ($PATH) > `Path(sys.executable).parent/"scancode"` (the
  venv bin, so a `pip install scancode-toolkit` into the same venv is found without
  activation). If unavailable → an ACTIONABLE `scancode_unavailable` warning
  (states where it looked + `pip install scancode-toolkit`) and the run continues
  with the normal resolver (never a hard fail). Scans are scoped to the
  LICENSE/COPYING/NOTICE/COPYRIGHT surface + the dir top-level (no full-tree walk;
  ~1.2s cold start, ~10 files/sec). Tests mock the runner; one gated LIVE test
  (`@pytest.mark.skipif`) runs the real binary.
- **`--deps-dir PATH` resolves dep licenses from REAL on-disk source (offline).**
  The "new dep, no pre-seed" fallback (`enrich/deps_dir.py`, fill-only license
  layer 2.5, above cache-scan). Per component it locates a source under PATH and
  materializes a scannable tree, auto-detecting three layouts: (1) plain dir
  `<deps-dir>/<name>/`; (2) archive `<name>-<ver>.tar.gz` (BOUNDED extraction —
  top-level + license files only, so or-tools-scale archives aren't unpacked in
  full); (3) **git mirror** (the `cann-src-third-party` convention) — a git repo
  whose DEFAULT/master branch is informational (**its working-tree LICENSE is
  KNOWN-INACCURATE and is NEVER read**) and whose real per-release source is on a
  version-named branch (`5.0.0.x` / `1.1.16x` / `v9.12.x` / `5.0.0.x-h0.trunk`)
  holding a release archive + optional Huawei `Readme.opensource` manifest
  (`License:` + `Copyright Notice(s):`). `select_branch` picks the branch by
  dotted-prefix score (exact > prefix), preferring a CLEAN branch over a
  `-suffix` variant; a mirror with NO matching version branch is SKIPPED with
  `deps_dir_no_branch` (never the inaccurate default branch), while a repo with no
  version branches is a normal clone whose working tree IS used. `parse_manifest`
  takes only the FIRST (primary) `License:` block — a manifest bundling
  sub-licenses (json: MIT + Apache-2.0 + BSD) lists the real one first.
  `apply()` returns a `source_map` handed to the ScanCode layer (so `--scancode
  fallback` reads copyright + a thorough license from the real tree) plus
  `cleanups` reconcile invokes after that layer; a manifest license disagreeing
  with an already-resolved one emits `deps_dir_license_discrepancy` (no silent
  override). `cache_scan._spdx_match` also recognizes **MulanPSL-1.0/2.0**
  (coscl.org.cn URL marker + Chinese title) — common in this ecosystem; and
  `cache_scan._find_license_files` matches license basenames case-insensitively by
  PREFIX (`LICENSE*`/`COPYING*`/…) so `LICENSE.TXT`/`LICENSE.MIT`/`LICENSE_1_0.txt`
  are found. SECURITY: a git-mirror with unreadable refs is SKIPPED
  (`deps_dir_git_unreadable`), `_is_git_repo` requires the dep be the repo ROOT
  (a plain dir inside an enclosing checkout is read as a plain dir, not the
  enclosing repo's branches), the lookup keys off `source_version` first then
  `effective_version` (patched deps resolve against the UPSTREAM branch), and
  extraction caps per-member/total/blob size (decompression-bomb guard).
- **`--deps-dir` data is SEEDED into a committed cache** (`enrich/deps_dir_cache.py`,
  data-source `deps-dir`: empty core + the CANN profile's
  `data/deps_dir_cache.json`). `reconcile._apply_deps_dir_cache` applies it ALWAYS
  (offline fill layer, just below the live `--deps-dir` resolution) so a default
  run gets accurate real-source C++ licenses **without** the `cann-src-third-party`
  tree present. Name-keyed (license is version-stable), alias-aware, fill-only.
  Regenerate with `--refresh-data deps-dir --deps-dir <tree> [--scancode fallback
  --scancode-path …]` (`refresh._refresh_deps_dir_cache`): TREE-DRIVEN — seeds
  every dep dir under the tree (latest version branch per mirror), ScanCode lifts
  the cases the offline heuristic misses. Excluded from `--refresh-data all`
  (needs `--deps-dir`).
- CANN-internal link libs (`graph`, `mmpa`, `register`, …) are real dependencies.
- Unmapped link tokens raise `unmapped_link_library` (reported, never silently
  dropped); add profile alias entries to resolve genuine ones.
- **Vendored data files go through `sbom/data_sources.py`.** Generic-core sources
  (`src/sbom/data/`): `known-licenses`, `depsdev`, `clearlydefined`, `deps-dir` —
  all **ship EMPTY** (the core has no built-in data). The CANN profile carries the
  actual content via `Profile.data_sources()`: `known_licenses.yaml` (the OSS
  license map — eigen/gtest/protobuf/…), `depsdev_cache.json`,
  `clearlydefined_cache.json`, `deps_dir_cache.json` (the seeded on-disk
  source license/copyright snapshot), plus CANN-only `aliases`, `first-party`,
  `third-party-purls`. This is the **profile-override hybrid**: the generic core
  never imports profile data, the profile *pushes* its sources, and merges go
  core→profile (profile wins). A non-CANN/`generic` profile therefore has NO known
  licenses unless it supplies its own. `--refresh-data` is the only cache writer
  (`depsdev`/`clearlydefined` re-fetch over the network; `deps-dir` re-scans
  on-disk sources offline; `aliases` suggests; curated files validate-only —
  never auto-rewritten, to preserve their section comments).
- **NTIA Supplier + copyright (orthogonal enrichers).** `Component`/`Subject` carry
  `supplier`; reconcile fills it (and the emitters map it → CDX `supplier`
  OrganizationalEntity / SPDX package `supplier`, NOASSERTION when unknown — the
  honest "known unknown"). Three clean sources, no guessing: (1)
  `profile.first_party_supplier()` for repo-owned subjects + `first-party`
  components (CANN → "Huawei Technologies Co., Ltd."); (2) the **depsdev cache**
  also stores a supplier from PyPI `info.author`/`maintainer` (sparse — modern
  packages omit it); (3) the **ClearlyDefined** enricher
  (`enrich/clearlydefined.py` + vendored `clearlydefined_cache.json`,
  `--refresh-data clearlydefined`) fills supplier + copyright. It covers BOTH
  **PyPI** (Python, keyed `pypi:<name>`) AND **C++ third-party**: a curated
  `third_party_purls.yaml` coordinate (`pkg:github|gitlab/org/name`) + version is
  resolved to a git commit SHA via `git ls-remote` (CD harvests C++ under a SHA,
  not a tag), keyed `<host>:<org>/<name>`. This gives C++ a copyright source
  INDEPENDENT of the optional repo Notice (the Notice wins when present; CD is the
  fallback). **CD attribution is auto-scanned and NOISY** — `_extract` keeps ONLY a
  git-provider namespace as supplier and year-bearing `Copyright <year> …` lines,
  and never applies license (the dedicated layers own that). boost-style tags
  (`boost-<v>`, not `v<v>`/`<v>`) don't resolve -> no CD copyright (license/supplier
  still come from known_licenses/the curated coordinate).
- **NTIA unique identifier for C++ components (`Component.purl`).** reconcile
  (`_resolve_component_purls`) stamps a PURL on every NON-Python component, most-
  specific first: (1) a **curated upstream coordinate** from the profile's
  `data/third_party_purls.yaml` (`protobuf`→`pkg:github/protocolbuffers/protobuf`,
  `eigen`→`pkg:gitlab/libeigen/eigen`, `protoc`→protobuf) — true, vuln-matchable
  ids for well-known OSS fetched from CANN's mirrors that hide the upstream org;
  (2) `pkg:generic/<name>@<v>?download_url=<url>[&checksum=…]` for a mirror-only
  third-party; (3) `pkg:generic/<name>?vcs_url=<repo origin>` for first-party CANN
  libs (gitcode is NOT a registered purl type, so they stay `pkg:generic`, never
  `pkg:gitcode`). System/no-locator components (Threads, protoc-less builds) stay
  purl-less — the name is the honest look-up key. Emit serializes
  `Component.purl` verbatim; Python deps still derive `pkg:pypi` at emit. The
  curated map uses ONLY registered PURL types (github/gitlab); add entries only
  for coordinates you're confident about. **CPE is intentionally NOT synthesized**
  (a guessed CPE causes false NVD matches) — a curated/opt-in CPE is a future add.
- **The depsdev cache (`depsdev_cache.json`) is a license layer**, applied
  ALWAYS (offline + online) just above live `net`, so the vendored deps.dev/PyPI
  snapshot resolves Python licenses offline. The CANN profile's cache is SEEDED
  (~24 entries: the Python deps of ops-math/ops-nn/pyasc/runtime); the generic
  core's cache (`src/sbom/data/depsdev_cache.json`) ships empty. Re-seed with
  `--refresh-data depsdev --network on` (run per repo; upserts; re-run to
  fill transient misses), then regenerate `out/`. Fills **license + supplier** (the
  latter from PyPI `info.author`/`maintainer`; the cached version stays
  informational); Python-only (same reason as `enrich/net.py`). `--refresh-
  data` collects at `scope="all"` so the cache captures build/test deps too, and
  `net.resolve_pypi` retries version-less when a supplied version misses (e.g. a
  C++ version on a name-colliding Python dep like `protobuf`). Tests don't pin
  these license VALUES, so re-seeding won't break them.
- **Supply-chain provenance (`Component.origin` → `sbomgen:component:origin`).**
  Reconcile stamps every component `first-party` | `third-party` | `unknown` (kept
  in compact). The profile's `component_provenance(comp)` verdict is authoritative;
  for CANN, first-party = a name in `data/first_party_licenses.yaml` (internal libs
  + sibling packages) OR a `gitcode.com/cann/<repo>` origin URL. The look-alike
  third-party mirrors (`gitcode.com/cann-src-third-party/`, the
  `cann-3rd.obs.<region>.myhuaweicloud.com` OBS bucket) deliberately do NOT match —
  they're matched on (host, first-path-segment), not a substring. Otherwise the
  generic core marks third-party when the component is a published Python package,
  has a real `scheme://` upstream URL, or a concrete OSS license id (not
  NOASSERTION / not a `LicenseRef-*`). **`unknown` is intentional honesty, not a
  bug** — `Threads`/`protoc`/`Torch`/`Python3` (NOASSERTION, no URL, origin
  unproven) stay `unknown`. **Provenance and license are orthogonal**: a
  closed-source first-party CANN tool (`bisheng-compiler`) is a KEY in
  `data/first_party_licenses.yaml` with a **null** license — membership ⇒
  `first-party`, but `dependency_license_default` returns None for a null value so
  its license stays `NOASSERTION` (never the CANN *Open* License). Subjects are the
  repo's own and aren't classified here (they carry `sbomgen:subject:*`).
- Python wheel subjects are resolved statically by `collectors/py_metadata.py`
  (`resolve_package_metadata`) — **no package code is executed**; it reads
  pyproject/setup.cfg/setup.py via a safe AST evaluator (literals, module
  constants, `os.getenv(k, default)`, `X or "lit"`, const-returning helpers,
  co-located version-file reads) plus setuptools-scm/`__version__` fallbacks. When
  a value truly can't be resolved (e.g. an env var with no default), it falls back
  to the repo dir basename / `version=None` and emits `subject_name_unresolved` /
  `subject_version_unresolved`. That fallback is **expected honesty, not a bug** —
  don't make it guess.
- A Python wheel + a co-located CMake `project()` (same dir) merge into ONE subject
  in the generic core (wheel canonical, CMake project as a `cmake_project` facet /
  `build_graph_root_id`); this runs before and composes idempotently with
  `profile.subject_facets`. Keep both passes idempotent so ops-math isn't
  double-merged.

## Style

- Match the existing module structure and the contract; prefer editing over
  adding files. Don't add comments that restate code.
- This directory is **not** a git repo; don't run git here. Keep `out/`, `.venv/`,
  `__pycache__/`, `*.egg-info/`, `.pytest_cache/` out of any future VCS (see
  `.gitignore`).
