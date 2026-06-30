# CMake source authority

When a repo *fetches* its CMake tooling at configure time, the tree you pass as
`--cmake-root` may not be the one an actual build would use. CANN's
[`ops-math`](../../ops-math) does exactly this: its `cmake/fetch_cann_cmake.cmake`
pins a tag and pulls the `cann-cmake` tree from a tarball or git. The generator
resolves a single **`CmakeAuthority`** up front — *which* tree is authoritative,
*where* it lives, and *what* version it is — then routes **all** macro and
`include()` resolution through that decision, never the raw `--cmake-root`.

This page documents that model: the problem it solves, the four authority
branches, how `effective_cmake_root` is chosen, the proof requirement for
authority inputs, and every warning the resolver and the profile can emit.

See also: [docs/cli.md](cli.md) for the flags, the
[Repo profiles](../README.md#repo-profiles) guide for the profile hooks, and the
README's [CMake source authority](../README.md#cmake-source-authority) summary.

## The problem

`add_cann_third_party(eigen)` expands to
`include(<cann-cmake tree>/third_party/eigen.cmake)`. To follow that include the
generator must know where the `cann-cmake` tree is on disk. But that tree isn't
checked into `ops-math` — it's acquired at configure time by
`cmake/fetch_cann_cmake.cmake`:

```cmake
if(NOT PROJECT_SOURCE_DIR)
    if(CANN_3RD_LIB_PATH AND IS_DIRECTORY "${CANN_3RD_LIB_PATH}/cann-cmake")
        include("${CANN_3RD_LIB_PATH}/cann-cmake/function/prepare.cmake")
    else()
        include(FetchContent)
        set(CANN_CMAKE_TAG "master-016")
        if(CANN_3RD_LIB_PATH AND EXISTS "${CANN_3RD_LIB_PATH}/cmake-${CANN_CMAKE_TAG}.tar.gz")
            FetchContent_Declare(cann-cmake
                URL "${CANN_3RD_LIB_PATH}/cmake-${CANN_CMAKE_TAG}.tar.gz"
                URL_HASH SHA256=9167f7296590685b459d6abae6cc4b6e95db3db755af66b2c5b3c3f4908b3b39)
        else()
            FetchContent_Declare(cann-cmake
                GIT_REPOSITORY https://gitcode.com/cann/cmake.git
                GIT_TAG        ${CANN_CMAKE_TAG}
                GIT_SHALLOW    TRUE)
        endif()
        ...
    endif()
endif()
```

Two facts drop straight out of that script:

1. **The whole block is wrapped in `if(NOT PROJECT_SOURCE_DIR)`.** When
   `ops-math` is configured as a *sub-project* of a larger build, `PROJECT_SOURCE_DIR`
   is already set, the fetch never runs, and the `cann-cmake` macros come from
   the parent's already-included provider. There is no `cann-cmake` to model.
2. **The pin is `master-016`.** Whatever tree you point `--cmake-root` at may
   describe a *different* ref. In this workspace that is exactly the situation:
   [`../cmake`](../../cmake) describes `master-025` (see its `README.md`), while
   the `ops-math` pin is `master-016`. The convenient tree on disk is **not**
   the tree an actual build would fetch.

A further subtlety: `CANN_3RD_LIB_PATH` decides between the local-dir, tarball,
and git branches, but inside `ops-math` it defaults *later*, at
[`CMakeLists.txt:65`](../../ops-math/CMakeLists.txt):

```cmake
if(NOT CANN_3RD_LIB_PATH)
  set(CANN_3RD_LIB_PATH ${PROJECT_SOURCE_DIR}/third_party CACHE STRING "cann third party lib path")
endif()
```

That default runs *after* `fetch_cann_cmake.cmake` (line 12) has already read the
variable. So a `CANN_3RD_LIB_PATH` you find in a `CMakeCache.txt` might be that
late default, not a value that was set *before* the fetch — it cannot, on its
own, prove which branch the fetch took. The resolver treats only an explicit
pre-include define as proof (see [Authority inputs](#authority-inputs-the-proof-requirement)).

## The resolution: `resolve_cmake_authority`

`sbom.cmake.parse.resolve_cmake_authority` reads **only pre-`project()` state**
and returns a `(CmakeAuthority, list[Warning])` pair:

```python
def resolve_cmake_authority(
    repo_root, cmake_root, *,
    cmake_source_authority,   # "actual-build" | "cmake-as-input"
    cmake_defines,            # proven pre-include -D values (--cmake-define)
    profile_values,           # --profile-value / [profile.values]
    allow_input_fallback,     # --allow-input-fallback
    resolve_cmake_ref,        # --resolve-cmake-ref (network)
    network,                  # "off" | "on"
) -> tuple[CmakeAuthority, list[Warning]]
```

The `CmakeAuthority` it produces (`sbom.models`) carries the decision:

```python
@dataclass
class CmakeAuthority:
    branch: CmakeAuthorityBranch                 # skipped / local_dir / tarball / git
    effective_cmake_root: Path | None = None     # the ONE tree every consumer uses
    ref: str | None = None                       # requested VCS ref (e.g. master-016)
    revision: str | None = None                  # resolved commit, when known
    verified: bool = False
    authority_inputs: dict = field(default_factory=dict)
```

**`effective_cmake_root` is the load-bearing field.** Every downstream consumer
resolves against it and never against the raw `--cmake-root`:
`add_cann_third_party()` anchors `third_party/<name>.cmake` there
(`CannThirdPartyResolver.resolve`), `parse_recursive` resolves `include()` paths
there, and `IncludeStmt.resolved` is documented as "resolved against
`effective_cmake_root`". The whole point of the authority pass is to compute that
one path correctly before any parsing begins.

## The four branches

`CmakeAuthorityBranch` (`sbom.models`) has exactly four values, one per outcome
of the script above:

| Branch | When | `effective_cmake_root` | `ref` | `cann-cmake` component |
|--------|------|------------------------|-------|------------------------|
| `skipped_existing_project` | `project_source_dir_predefined` is truthy (built under a parent project; `if(NOT PROJECT_SOURCE_DIR)` is false) | `--cmake-root` | `None` | **none** — macros inherited from the parent |
| `local_dir` | a *proven* `CANN_3RD_LIB_PATH` contains a `cann-cmake/` directory | `<lib_path>/cann-cmake` | `None` | version `NOASSERTION` + `local_source_unverified` |
| `tarball` | a *proven* `CANN_3RD_LIB_PATH` contains `cmake-master-016.tar.gz` | `--cmake-root` | `master-016` | `master-016` + sha256 |
| `git` | everything else: no proof, ambiguous cache, or proven path with neither dir nor tarball | `--cmake-root` | `master-016` | `master-016`, resolved commit when known |

The `git` branch is the **default and the fallback** — the parser still needs an
on-disk tree to read fragments from, and that is `--cmake-root`, but the
identity it stamps on the `cann-cmake` component is the pinned git ref, not "the
tree you happened to pass."

### Branch selection in practice

You can drive the resolver directly to see each branch (assumes the venv from the
[README](../README.md#install) is active; otherwise prefix with `.venv/bin/python`):

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
from sbom.cmake.parse import resolve_cmake_authority

def run(label, **kw):
    base = dict(cmake_source_authority="actual-build", cmake_defines={},
                profile_values={}, allow_input_fallback=False,
                resolve_cmake_ref=False, network="off")
    base.update(kw)
    auth, warns = resolve_cmake_authority(Path("../ops-math"), Path("../cmake"), **base)
    print(f"{label:18} branch={auth.branch.value:26} ref={auth.ref} "
          f"warnings={[w.code for w in warns]}")

run("default")
run("cmake-as-input", cmake_source_authority="cmake-as-input")
run("skipped", profile_values={"project_source_dir_predefined": "true"})
PY
```

```
default            branch=git                        ref=master-016 warnings=[]
cmake-as-input     branch=git                        ref=master-016 warnings=['cann_cmake_trusted_input']
skipped            branch=skipped_existing_project    ref=None warnings=[]
```

To reach `local_dir` or `tarball` you need a *proven* `CANN_3RD_LIB_PATH` (a
`--cmake-define`) pointing at a directory that actually holds `cann-cmake/` or
`cmake-master-016.tar.gz`:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
from sbom.cmake.parse import resolve_cmake_authority
from sbom_profile_cann import CannProfile

def run(label, lib_path):
    auth, warns = resolve_cmake_authority(
        Path("../ops-math"), Path("../cmake"),
        cmake_source_authority="actual-build",
        cmake_defines={"CANN_3RD_LIB_PATH": lib_path},
        profile_values={}, allow_input_fallback=False,
        resolve_cmake_ref=False, network="off")
    comps, _ = CannProfile().build_tooling(Path("../ops-math"), auth)
    c = comps[0] if comps else None
    print(f"{label:10} branch={auth.branch.value:10} eff_root={auth.effective_cmake_root}")
    if c:
        print(f"           version={c.source_version} findings={[f.value for f in c.integrity_findings]}")
    print(f"           warnings={[w.code for w in warns]}")

run("local_dir", "/path/with/cann-cmake")   # dir containing cann-cmake/
run("tarball",   "/path/with/tarball")       # dir containing cmake-master-016.tar.gz
PY
```

```
local_dir  branch=local_dir  eff_root=/path/with/cann-cmake/cann-cmake
           version=None findings=['local_source_unverified']
           warnings=['cann_cmake_local_override']
tarball    branch=tarball    eff_root=../cmake
           version=master-016 findings=[]
           warnings=[]
```

Note the `local_dir` effective root is `<lib_path>/cann-cmake` — the arbitrary
checkout itself — while `tarball` and `git` keep `--cmake-root` as the on-disk
tree to read but stamp the pinned ref as identity.

## Authority inputs: the proof requirement

Branch selection hinges on `CANN_3RD_LIB_PATH`, and **not every source of that
value is trustworthy**. `resolve_cmake_authority` records its provenance in
`authority_inputs`:

```python
authority_inputs = {"cann_3rd_lib_path": {"value": ..., "source": "cli|config|cache|unset"}}
```

The precedence (`_resolve_authority_input`) is:

1. **`cli`** — `--cmake-define CANN_3RD_LIB_PATH=...`. Proof. You are asserting
   this value was a real pre-include `-D`.
2. **`config`** — `[profile.values]` / `--profile-value` equivalent in
   `sbom.toml`. Also treated as proof.
3. **`cache`** — a bare `CANN_3RD_LIB_PATH:...=` line scraped from
   `CMakeCache.txt` (or `build/CMakeCache.txt`). **Not proof** — as shown above,
   `ops-math` sets this variable as a *late default* at `CMakeLists.txt:65`,
   *after* the fetch already read it, so a cache value cannot prove what the
   fetch saw.
4. **`unset`** — nothing found.

Only `cli` and `config` actually select `local_dir`/`tarball`:

```python
if source in ("cli", "config") and value:
    ...   # inspect lib_path for cann-cmake/ or the tarball
elif source == "cache":
    warnings.append(Warning(code="cmake_authority_input_ambiguous", ...))
```

A bare cache value is **ambiguous**: the resolver refuses to trust it, emits
[`cmake_authority_input_ambiguous`](#warnings), and falls through to the `git`
branch (assume the pin). This is the safe default — it never silently believes a
cache line that might be the late `CMakeLists.txt:65` fallback.

## `--cmake-source-authority`: actual-build vs cmake-as-input

The `--cmake-source-authority` flag (default `actual-build`) answers a policy
question: *do we model the tree a real build would fetch, or do we trust the
`--cmake-root` you handed us as ground truth?*

- **`actual-build`** (default) — model what a configure would really do: run the
  branch selection above, and the `cann-cmake` tree is a first-class **build**
  component of the SBOM with its pinned/resolved identity.
- **`cmake-as-input`** — treat `--cmake-root` as a *trusted generator input*, not
  a dependency to inventory. The resolver short-circuits to a `git`-branch
  `CmakeAuthority` with `effective_cmake_root = --cmake-root` and **sets the
  `trusted_input` marker** in `authority_inputs`. The profile's `build_tooling()`
  gates on that marker: it **excludes** the `cann-cmake` component (you provided
  the tree, so it isn't a fetched dependency) and emits
  [`cann_cmake_trusted_input`](#warnings). A tag mismatch against the pin is still
  checked.

```python
if cmake_source_authority == "cmake-as-input":
    # Mark the tree as trusted input so build_tooling() excludes cann-cmake.
    authority_inputs["trusted_input"] = True
    auth = CmakeAuthority(branch=CmakeAuthorityBranch.GIT,
                          effective_cmake_root=cmake_root, ref=_CANN_CMAKE_TAG,
                          authority_inputs=authority_inputs)
    _maybe_tag_mismatch(auth, cmake_root, warnings)
    return auth, warnings   # build_tooling() emits cann_cmake_trusted_input on exclusion
```

The profile's `build_tooling` performs the exclusion, keyed on
`authority.authority_inputs.get("trusted_input")`. Under `cmake-as-input` the
resolver **sets `trusted_input = True`** (alongside `cann_3rd_lib_path`), so
`build_tooling` drops the `cann-cmake` component and emits the single
`cann_cmake_trusted_input` warning. (Previously the resolver only emitted the
warning and never set the key, so the component was flagged but still emitted —
that bug is fixed.)

## `--resolve-cmake-ref` and `--allow-input-fallback`

These two flags govern what happens on the `git` branch when the on-disk
`--cmake-root` doesn't demonstrably match the pin and the resolver would
otherwise have nothing concrete to anchor identity to.

- **`--resolve-cmake-ref`** — resolve the pinned ref to a commit via
  `git ls-remote` of the cann-cmake `GIT_REPOSITORY` (a **network** operation;
  **implies `--network on`**, set by the CLI). On success the resolved commit
  populates `CmakeAuthority.revision` and the component's `vcs_ref.resolved_commit`,
  and `UNPINNED_GIT` is dropped. On failure (offline / no `git` / ref gone) it
  degrades to the unpinned component with a `cmake_ref_resolution_failed` warning.
- **`--allow-input-fallback`** — when offline and the pin is unresolvable, permit
  *parsing `--cmake-root`* as a stand-in (explicitly flagged as "not actual-build
  evidence") rather than failing. Without it, an offline + unresolvable pin
  raises [`cmake_acquisition_metadata_unresolved`](#warnings) noting it cannot
  obtain `master-016`.

The relevant tail of the `git` branch:

```python
if not resolve_cmake_ref and not _root_matches_pin(cmake_root):
    if cmake_root is None or not allow_input_fallback:
        warnings.append(Warning(code="cmake_acquisition_metadata_unresolved",
            detail="offline and pin unresolvable; cannot obtain master-016."))
    else:
        warnings.append(Warning(code="cmake_acquisition_metadata_unresolved",
            detail="parsing --cmake-root as fallback (not actual-build evidence)."))
```

`_root_matches_pin` is best-effort: a present `--cmake-root` is assumed to match
*unless* a ref marker file in it (`CMAKE_REF`, `.cann_cmake_ref`, or `VERSION`)
records a different ref. The bundled `../cmake` tree has no such marker, so it is
*assumed* to match — which is why the default run above emits no mismatch even
though the tree's README describes `master-025`. Drop a `VERSION` file naming a
different ref and the mismatch fires (see below).

## Warnings

Every warning here is a first-class `Warning(code, subject, detail)` record,
surfaced in the output and asserted on by tests. Verified codes:

| Code | Emitted by | Meaning |
|------|------------|---------|
| `cann_cmake_tag_mismatch` | resolver (`_maybe_tag_mismatch`) and profile (`_tag_mismatch_warnings`) | the resolved/`--cmake-root` ref differs from the pinned `master-016` |
| `cann_cmake_local_override` | resolver and profile `build_tooling` | the `local_dir` branch won: an arbitrary local `cann-cmake` checkout is authoritative; `master-016` is **not** assumed and the version is `NOASSERTION` |
| `cann_cmake_trusted_input` | profile `build_tooling` (on the `trusted_input` marker the resolver sets under `cmake-as-input`) | `--cmake-root` is treated as a trusted generator input; the `cann-cmake` component is excluded from the inventory |
| `cmake_authority_input_ambiguous` | resolver | a *bare* `CMakeCache.txt` `CANN_3RD_LIB_PATH` cannot prove a pre-include `-D`; the resolver assumes the `git` branch (`master-016`) instead of trusting it |

Two adjacent codes are emitted on the `git` branch (see
[the previous section](#--resolve-cmake-ref-and---allow-input-fallback)):
`cmake_acquisition_metadata_unresolved` when offline and the pin can't be resolved,
and `cmake_ref_resolution_failed` when `--resolve-cmake-ref` is set but the
`git ls-remote` ref→commit resolution fails (the component is left unpinned).

To see `cann_cmake_tag_mismatch` against the real tree, give `--cmake-root` a
`VERSION` marker that disagrees with the pin:

```bash
mkdir -p /tmp/badref && printf 'master-099\n' > /tmp/badref/VERSION
.venv/bin/python - <<'PY'
from pathlib import Path
from sbom.cmake.parse import resolve_cmake_authority
auth, warns = resolve_cmake_authority(
    Path("../ops-math"), Path("/tmp/badref"),
    cmake_source_authority="actual-build", cmake_defines={},
    profile_values={}, allow_input_fallback=False,
    resolve_cmake_ref=False, network="off")
print(auth.branch.value, [w.code for w in warns])
PY
```

```
git ['cann_cmake_tag_mismatch', 'cmake_acquisition_metadata_unresolved']
```

## How the branch shapes the `cann-cmake` component

The profile's `build_tooling` turns the resolved authority into the `cann-cmake`
build component (or nothing). The mapping, verified against
`CannProfile.build_tooling` / `_cann_cmake_component`:

| Branch | Component emitted? | `source_version` / `effective_version` | integrity findings | identity |
|--------|--------------------|------------------------------------------|--------------------|----------|
| `skipped_existing_project` | no | — | — | macros inherited from parent project |
| `local_dir` | yes | `None` / `None` (NOASSERTION) | `local_source_unverified` | `vcs_ref.resolved_commit` when `authority.revision` known |
| `tarball` | yes | `master-016` / `master-016` | none | `checksums.sha256` = pinned tarball hash |
| `git` | yes | `ref` (`master-016`) / `revision or ref` | `unpinned_git` when no resolved commit | `vcs_ref{requested, resolved_commit}` |

Under `cmake-as-input`'s `trusted_input` gate the component is excluded outright
with `cann_cmake_trusted_input`. The `cann-cmake` component, when emitted, is a
**build-scope** `library` component with language `cmake`, wired to the primary
subject by a `TOOLING` edge in the C++ collector.

For the wider integrity-finding vocabulary (`no_hash`, `unpinned_git`,
`tls_verification_disabled`, `local_source_unverified`) and how findings surface
in CycloneDX/SPDX, see [docs/architecture.md](architecture.md). For the flags
referenced here, see [docs/cli.md](cli.md); for the parsing that consumes
`effective_cmake_root`, see `CannThirdPartyResolver` in
`src/sbom_profile_cann/__init__.py` and `parse_recursive` in
`src/sbom/cmake/parse.py`.
