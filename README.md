# sbom-gen

A standalone Software Bill of Materials (SBOM) generator for repositories that
mix **C++ (CMake)** and **Python**. It emits both **CycloneDX 1.5** and
**SPDX 2.3** from one internal model, validated by the official libraries.

The engine is generic; everything specific to a codebase lives in a **repo
profile plugin**. The reference target is Huawei CANN's `ops-math`, whose C++
third-party dependencies are declared through a custom CMake macro
`add_cann_third_party()` — handled by the bundled `cann` profile.

- **Two formats, one model** — CycloneDX 1.5 JSON + SPDX 2.3 JSON, built with
  `cyclonedx-python-lib` and `spdx-tools` (schema-valid by construction).
- **Static by default, no build required** — parses CMake/Python sources; an
  optional network mode enriches from deps.dev/PyPI. (A configured CMake
  File-API/trace path exists as modules but is not yet wired into
  `--collector-mode`.)
- **Reproducible** — `--reproducible` gives byte-identical output (honors
  `SOURCE_DATE_EPOCH`).
- **Honest provenance** — every fact records where it came from; integrity gaps
  (missing hash, unpinned git, TLS-verify-off, unverified local source) are
  surfaced, not hidden.
- **Extensible** — add a repo profile via a Python entry point; no core changes.

> Status: **v0.1.0**. The static collector, the CANN profile, and both emitters
> are exercised end-to-end against the real `ops-math` repo with a locked-in
> regression suite. The *configured* (`--collector-mode configured`) mode is **not
> yet implemented** — it emits a `collector_mode_unimplemented` warning and runs
> static. The *network* (`--network on`) mode covers the deps.dev/PyPI path; live
> ClearlyDefined and the C++ archive-download path are not yet wired up. See
> [Limitations](#limitations).

## Install

Requires Python ≥ 3.11. Use a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'      # dev extra adds pytest
```

This installs the `sbom` console script and registers the `cann` repo profile.

## Quickstart

Generate an SBOM for the CANN `ops-math` repo (C++ deps resolved via the shared
`cmake` tree):

```bash
sbom \
  --repo-root ../ops-math \
  --repo-profile cann \
  --cmake-root ../cmake \
  --reproducible \
  --out-dir ./out
```

You get `out/sbom.cdx.json` (CycloneDX 1.5) and `out/sbom.spdx.json` (SPDX 2.3),
each passing its official validator. `--repo-profile` can be omitted — the CANN
profile auto-detects from cann-cmake markers (e.g. `add_cann_third_party(` /
`set_cann_package(`) or a `gitcode.com/cann/` git origin.

By default this is the **release view** (`--scope release`): the distributable
subjects (the CANN package + its sibling wheels) and their **runtime** dependency
closure only. Test deps, build tooling (cmake/ninja/makeself/protoc/…),
example/experimental/ST roots, and host environment tools are dropped. Pass
`--scope all` for the full view (every subject, every scope, every environment
tool). Explicit `--exclude-scope` / `--subjects` / `--no-env-tools` still apply
on top of either view.

For any other C++/CMake + Python repo, the generic core runs with no profile:

```bash
sbom --repo-root ../some-repo --out-dir ./out
```

## Common commands

```bash
# 1. Offline SPDX only (default — no network; uses the vendored caches).
sbom --repo-root ../ops-math --format spdx --out-dir ./out
#    -> out/sbom.spdx.json   (drop --format to also get CycloneDX)

# 2. Online SPDX — adds LIVE deps.dev/PyPI license enrichment for Python deps
#    (everything else identical; C++ licenses still come from the vendored caches).
sbom --repo-root ../ops-math --format spdx --network on --out-dir ./out

# 3. Refresh the vendored data caches (writes the data files, emits NO SBOM).
#    The cache ACCUMULATES the named repo's dependencies — re-run across repos to
#    broaden it. depsdev/clearlydefined need --network on:
sbom --repo-root ../ops-math --network on --refresh-data depsdev        # deps.dev/PyPI license+version+supplier
sbom --repo-root ../ops-math --network on --refresh-data clearlydefined # supplier/copyright from ClearlyDefined
sbom --repo-root ../ops-math --network on --refresh-data all            # depsdev + clearlydefined + validates curated files

#    The on-disk deps-dir license/copyright cache is refreshed OFFLINE from real
#    sources (uses ScanCode when available); it is NOT part of `all`:
sbom --repo-root ../ops-math --refresh-data deps-dir --deps-dir ../cann-src-third-party --scancode fallback
```

## CLI overview

| Flag | Purpose |
|------|---------|
| `--repo-root PATH` | Repository to analyse (default: cwd) |
| `--repo-profile NAME` | Repo plugin (e.g. `cann`); auto-detected if omitted |
| `--cmake-root PATH` | Shared CMake tree (profile input) |
| `--format cyclonedx,spdx` | Output formats, comma-separated (default: both; e.g. `--format spdx` for one) |
| `--collector-mode static\|configured\|both` | Collection strategy (default: `static`) |
| `--cmake-source-authority actual-build\|cmake-as-input` | Which CMake tree is authoritative |
| `--network off\|on` | Enable deps.dev/PyPI license enrichment |
| `--depsdev-cache PATH` | Override the vendored depsdev cache (read on every run; written only by `--refresh-data depsdev`) |
| `--refresh-data SOURCE` | Refresh a vendored data file and exit (`depsdev`, `clearlydefined`, `deps-dir`, `aliases`, `first-party`, `known-licenses`, `all`); no SBOM emitted |
| `--deps-dir PATH` | On-disk dependency-source root for offline license/copyright resolution (and `--refresh-data deps-dir`) |
| `--network on` + nothing else | Online run = deps.dev/PyPI only (live ClearlyDefined / C++ archive download not yet wired) |
| `--repo-url URL` | Declare the repo VCS origin (else auto-detected from `.git/config`) |
| `--reproducible` | Deterministic output (fixed timestamps + derived ids) |
| `--scope release\|all` | View preset (default: `release` = distributable subjects + runtime closure; `all` = full view) |
| `--exclude-scope TOKEN,...` | Drop roots/scopes (e.g. `experimental,manual_example`); additive over `--scope` |
| `--subjects ID,...` / `--split-subjects` | Choose / split emitted subjects |
| `--cmake-define K=V` | Proven pre-include CMake cache value (e.g. `CANN_3RD_LIB_PATH`) |
| `--config sbom.toml` | Read all options from a config file |

Run `sbom --help` for the complete list. Full reference: [docs/cli.md](docs/cli.md).

## Output

Both formats describe the repo's **subjects** (the things it builds — a CANN
package, Python wheels, standalone CMake example roots) and their
**dependencies** (C++ third-party, CANN package/module deps, Python
requirements/build tools). Beyond names and versions, each component carries:

- typed **dependency edges** with per-subject ownership (a wheel's `torch` edge
  belongs to that wheel, not the top-level package);
- **patched-build identity** (e.g. protobuf upstream `25.1` → effective `3.13.0`
  via a checked-in patch);
- **integrity findings** (missing checksum, `TLS_VERIFY OFF`, unpinned git tag,
  unverified local source);
- **provenance** — the source file and revision each fact came from.

Each **subject** also records the repo's VCS origin — auto-detected from
`.git/config` (or set with `--repo-url`) and emitted honestly: the purl type
stays `pkg:generic` (so it never falsely claims an unregistered host type or that
a product version is a git ref) with the origin carried as a `vcs_url` qualifier,
plus native CycloneDX `externalReferences` (vcs/website) and SPDX
`downloadLocation`/`homepage` — e.g. `git+https://gitcode.com/cann/ops-math.git@<commit>`.

Generic host tools used during the build (`patch`, `tar`, `git`, `ccache`,
`perl`, …) are recorded as *environment tools* in metadata/annotations, never as
dependency components. See [docs/architecture.md](docs/architecture.md) for the
full model and the CycloneDX/SPDX field mapping.

All custom CycloneDX properties and SPDX annotation keys use the tool-owned
namespace `sbomgen:` (named after this tool, not any repo; used for all repos,
including generic ones).

## Architecture

```
repo + cmake tree ──▶ Collect ──▶ Reconcile ──▶ Emit ──▶ CycloneDX + SPDX
                       │             │            │
        cmake/python   │  alias      │  cyclonedx-python-lib
        collectors +   │  de-dup,    │  spdx-tools
        repo profile   │  observation│  (+ validators)
        hooks          │  union,     │
                       │  enrichers  │
```

- **Generic core** (`src/sbom/`): the model, the CMake/Python collectors,
  reconcile, the enrichers, and the emitters.
- **Repo profile plugin** (`src/sbom_profile_cann/`): all CANN-specific knowledge
  — the `add_cann_third_party()` macro, `version.cmake` package deps,
  `fetch_cann_cmake.cmake` authority, the curated Notice/license files, the CANN
  alias map, and root classification.

Collectors return plain model records; **reconcile is the only stage that
produces a `Document`**; emitters only read it. More:
[docs/architecture.md](docs/architecture.md).

## Repo profiles

A profile is a `Profile` subclass registered under the `sbom.profiles` entry
point group. It supplies hooks the core calls (custom dependency macros, package
metadata, build tooling, curated license sources, an alias map, root
classification, subject merging) and a `detect(repo_root)` classmethod for
auto-selection. The generic core works with no profile at all.

To add support for another codebase, write a profile and declare it in your
`pyproject.toml`:

```toml
[project.entry-points."sbom.profiles"]
myrepo = "sbom_profile_myrepo:MyRepoProfile"
```

Guide: [docs/profiles.md](docs/profiles.md).

## CMake source authority

When a repo *fetches* its CMake tooling at configure time (CANN's
`fetch_cann_cmake.cmake` pins a tag), the tree you pass as `--cmake-root` may not
be the one an actual build would use. The generator resolves a single
`CmakeAuthority` (branches: skipped / local-dir / tarball / git) and routes all
macro resolution through its `effective_cmake_root`, warning on mismatch. This is
subtle and documented separately: [docs/cmake-authority.md](docs/cmake-authority.md).

## Development & testing

```bash
.venv/bin/python -m pytest tests -q          # full suite
.venv/bin/python -m pytest tests/test_drift_ops_math.py -q   # the regression lock
```

`tests/test_drift_ops_math.py` pins the generator's behavior against the real
`ops-math` repo (recovered CANN deps, gtest's two scope axes, patched protobuf,
per-subject edge ownership, environment-tool boundary, …) so correctness can't
silently regress. The frozen module contract lives in
[`INTERFACE.md`](INTERFACE.md). Contributor notes are in
[`CLAUDE.md`](CLAUDE.md).

## Limitations

- **Static mode** (default) cannot see facts that only exist after a build or a
  network call. E.g. protobuf's effective version comes from the curated CANN
  Notice; CANN-internal component licenses stay `NOASSERTION` offline.
- **`--collector-mode configured`** is **not yet wired in** — the `fileapi.py` /
  `trace.py` modules exist but the CLI does not invoke them, so the flag emits a
  `collector_mode_unimplemented` warning and runs static. **`--network on`** covers
  the deps.dev/PyPI path only (live ClearlyDefined / C++ archive download are not
  wired up).
- The CANN profile is tuned to `ops-math`'s conventions; other CANN repos may
  need alias-map additions (unmapped link libraries are reported, never dropped).

## Layout

```
src/sbom/                generic core (models, profile, collectors, reconcile, emit, cli)
src/sbom_profile_cann/   the CANN repo profile plugin
src/sbom/data/           bundled known-license map
tests/                   unit + drift regression suite
docs/                    usage & reference docs
INTERFACE.md             frozen module contract
SBOM_DESIGN.md           full design (in the parent workspace)
```

## License

Apache-2.0.
