"""Unit tests for sbom.collectors.subject — root/subject discovery.

Two layers of coverage:
  • synthetic table-driven cases (tmp_path) for merge/exclusion/classification
    policy in isolation;
  • a smoke pass over the real ops-math tree (skipped if absent) to confirm
    primary + sibling wheels + experimental CMake roots are discovered.

Mirrors the design's subject model:
  primary ops_math (CANN package, math CMake facet), sibling wheels
  npu_math_extension + ascend_ops, discovered experimental roots, the
  ascend_ops≡AscendOps facet merge, role-based exclusion + excluded_scope
  warnings, and emit_as_subject=False for non-distributable test roots.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import _cpp_stubs  # noqa: F401  (installs config/parse stubs if absent)

from sbom.config import Config
from sbom.collectors import subject as subject_mod
from sbom.models import (
    Facet,
    Identity,
    Subject,
    SubjectKind,
    SubjectMerge,
    SubjectRole,
)
from sbom.profile import GenericProfile, Profile


OPS_MATH = Path("/home/aron/testing/cann/ops-math")


# ---------------------------------------------------------------------------
# Synthetic repo builders
# ---------------------------------------------------------------------------


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# project() name resolution / build-variable sanitization
# ---------------------------------------------------------------------------


def test_resolve_project_name_never_emits_unexpanded_var(tmp_path):
    cmake = tmp_path / "CMakeLists.txt"

    # Plain literal names pass through untouched.
    _write(cmake, "project(ops_math)")
    assert subject_mod._resolve_project_name("ops_math", cmake) == "ops_math"

    # A fully-variable name defined by set() in the same file resolves (CANN style).
    _write(cmake, "set(PKG_NAME math)\nproject(${PKG_NAME})")
    assert subject_mod._resolve_project_name("${PKG_NAME}", cmake) == "math"

    # An unresolvable ${VAR} with a literal suffix drops the var, keeps the literal
    # (hs-fbb's project(${CHIP}_CFBB) where CHIP is a required build-time arg).
    _write(cmake, "if(NOT DEFINED CHIP)\nendif()\nproject(${CHIP}_CFBB C ASM)")
    assert subject_mod._resolve_project_name("${CHIP}_CFBB", cmake) == "CFBB"

    # A name that is ONLY an unresolvable var yields None -> caller uses basename.
    assert subject_mod._resolve_project_name("${NOPE}", cmake) is None


def test_resolve_project_version_sanitizes_unexpanded_var(tmp_path):
    cmake = tmp_path / "CMakeLists.txt"

    # Literal versions and None pass through.
    _write(cmake, "project(x VERSION 1.0.0)")
    assert subject_mod._resolve_project_version("1.0.0", cmake) == "1.0.0"
    assert subject_mod._resolve_project_version(None, cmake) is None

    # ${PROJECT_VERSION} resolves from a same-file set() (ops-fft/ops-tensor).
    _write(cmake, 'set(PROJECT_VERSION "1.0.0")\nproject(x VERSION ${PROJECT_VERSION})')
    assert subject_mod._resolve_project_version("${PROJECT_VERSION}", cmake) == "1.0.0"

    # An unresolvable version var is DROPPED (None) -> no @version in the purl,
    # never emitted raw as @%24%7B...%7D.
    _write(cmake, "project(x VERSION ${PROJECT_VERSION})")
    assert subject_mod._resolve_project_version("${PROJECT_VERSION}", cmake) is None


def _make_repo(tmp_path: Path) -> Path:
    """A miniature ops-math-shaped tree."""
    _write(
        tmp_path / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nset(PKG_NAME math)\nproject(${PKG_NAME} VERSION 1.0.0)\n",
    )
    _write(
        tmp_path / "version.cmake",
        'set_cann_package(ops_math VERSION "9.0.0")\n',
    )
    # sibling wheel: npu_math_extension
    _write(
        tmp_path / "scripts" / "torch_extension" / "setup.py",
        'PACKAGE_NAME = "npu_math_extension"\nVERSION = "1.0.0"\nsetup(name=PACKAGE_NAME)\n',
    )
    # co-located wheel + CMake root: ascend_ops / AscendOps
    _write(
        tmp_path / "examples" / "fast_kernel_launch_example" / "setup.py",
        'PACKAGE_NAME = "ascend_ops"\nVERSION = "1.0.0"\nsetup(name=PACKAGE_NAME)\n',
    )
    _write(
        tmp_path / "examples" / "fast_kernel_launch_example" / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(AscendOps VERSION 1.0.0)\n",
    )
    # experimental standalone roots
    _write(
        tmp_path / "experimental" / "math" / "bitwise_not" / "examples" / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(bitwise_not_examples CXX)\n",
    )
    _write(
        tmp_path
        / "experimental"
        / "math"
        / "fused_mul_add_n"
        / "tests"
        / "st"
        / "torch"
        / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.10)\nproject(aclnn_fused_mul_add_n_torch_test)\n",
    )
    return tmp_path


# ---------------------------------------------------------------------------
# Primary + sibling discovery
# ---------------------------------------------------------------------------


def test_primary_and_siblings_discovered(tmp_path):
    repo = _make_repo(tmp_path)
    config = Config(repo_root=repo)
    subjects, warnings = subject_mod.discover_subjects(config, GenericProfile())

    by_id = {s.id: s for s in subjects}
    # primary is the version.cmake package, math is a CMake facet
    assert "ops_math" in by_id
    primary = by_id["ops_math"]
    assert primary.role == SubjectRole.PRIMARY
    assert primary.identity.kind == SubjectKind.CANN_PACKAGE
    assert primary.identity.version == "9.0.0"
    facet_names = {f.name for f in primary.facets}
    assert "math" in facet_names

    # sibling wheels
    assert "npu_math_extension" in by_id
    assert by_id["npu_math_extension"].identity.kind == SubjectKind.PYTHON_WHEEL
    # ascend_ops is built by examples/fast_kernel_launch_example -> an example
    # wheel. A sub-dir wheel's default SIBLING_ARTIFACT role is never a profile
    # assertion, so the generic example-SEGMENT fallback demotes it to EXAMPLE and
    # the default release view drops it; it is only present under --scope all.
    assert "ascend_ops" not in by_id
    all_subjects, _ = subject_mod.discover_subjects(
        Config(repo_root=repo, scope="all"), GenericProfile()
    )
    ascend = {s.id: s for s in all_subjects}.get("ascend_ops")
    assert ascend is not None and ascend.role == SubjectRole.EXAMPLE


def test_experimental_roots_discovered_with_neutral_role(tmp_path):
    repo = _make_repo(tmp_path)
    # Full view so the generically-classified EXAMPLE root is still present.
    config = Config(repo_root=repo, scope="all")
    subjects, _ = subject_mod.discover_subjects(config, GenericProfile())
    by_id = {s.id: s for s in subjects}
    # The generic core's conservative fallback classifies an 'examples' SEGMENT
    # root as EXAMPLE (finer experimental/manual semantics remain profile policy).
    assert "bitwise_not_examples" in by_id
    assert by_id["bitwise_not_examples"].role == SubjectRole.EXAMPLE
    # A tests/ root is left neutral by the core (test-path semantics are profile
    # policy, not a generic-core concern).
    assert by_id["aclnn_fused_mul_add_n_torch_test"].role == SubjectRole.CMAKE_PROJECT


# ---------------------------------------------------------------------------
# Profile classify_root assigns path-semantic roles + emit_as_subject
# ---------------------------------------------------------------------------


def _parts(path) -> set[str]:
    return set(Path(str(path)).parts)


class _ClassifyProfile(Profile):
    name = "classify"

    def classify_root(self, path, cmake_project, package_context):
        parts = _parts(path)
        if "st" in parts and "tests" in parts:
            return SubjectRole.NON_DISTRIBUTABLE_TEST
        if "examples" in parts:
            return (
                SubjectRole.EXPERIMENTAL
                if "experimental" in parts
                else SubjectRole.EXAMPLE
            )
        return cmake_project.role


def test_classify_root_assigns_roles_and_emit_flag(tmp_path):
    repo = _make_repo(tmp_path)
    # Full view: this asserts the experimental/st_test roots are PRESENT with
    # their classified roles; the release preset would drop them before we look.
    config = Config(repo_root=repo, scope="all")
    subjects, _ = subject_mod.discover_subjects(config, _ClassifyProfile())
    by_id = {s.id: s for s in subjects}

    st = by_id["aclnn_fused_mul_add_n_torch_test"]
    assert st.role == SubjectRole.NON_DISTRIBUTABLE_TEST
    assert st.emit_as_subject is False  # ownership-only grouping

    ex = by_id["bitwise_not_examples"]
    assert ex.role == SubjectRole.EXPERIMENTAL


# ---------------------------------------------------------------------------
# subject_facets merge: ascend_ops absorbs AscendOps
# ---------------------------------------------------------------------------


class _MergeProfile(Profile):
    name = "merge"

    def subject_facets(self, subjects):
        ids = {s.id for s in subjects}
        if "ascend_ops" in ids and "AscendOps" in ids:
            return [
                SubjectMerge(
                    keep_subject_id="ascend_ops",
                    absorbed_subject_id="AscendOps",
                    build_graph_root_id="AscendOps",
                    facet=Facet(
                        kind=SubjectKind.CMAKE_PROJECT, name="AscendOps", version="1.0.0"
                    ),
                )
            ]
        return []


def test_subject_facet_merge_collapses_wheel_and_cmake(tmp_path):
    repo = _make_repo(tmp_path)
    # The CMake root project() name must be discoverable as "AscendOps" id.
    # ascend_ops is an example-dir wheel (EXAMPLE) the release preset trims, so the
    # full view is needed to observe the wheel<->CMake merge.
    config = Config(repo_root=repo, scope="all")
    subjects, _ = subject_mod.discover_subjects(config, _MergeProfile())
    ids = {s.id for s in subjects}
    assert "ascend_ops" in ids
    assert "AscendOps" not in ids, "AscendOps should be absorbed into ascend_ops"
    kept = next(s for s in subjects if s.id == "ascend_ops")
    assert kept.build_graph_root_id == "AscendOps"
    assert any(f.name == "AscendOps" for f in kept.facets)


def test_example_dir_wheel_trimmed_from_release(tmp_path):
    """A wheel built under an examples/ tree is an example, not a distributable.

    Regression lock: ascend_ops (examples/fast_kernel_launch_example/setup.py) was
    leaking into the default release view tagged sibling_artifact, because a sub-dir
    wheel's default role was assigned at discovery and never path-checked, so the
    example's CMake root folded into the wheel and the stale SIBLING_ARTIFACT
    survived. It must now classify EXAMPLE (generic core) and drop from release,
    while --scope all keeps it.
    """
    repo = _make_repo(tmp_path)
    # release (default): the example wheel is gone.
    rel, _ = subject_mod.discover_subjects(Config(repo_root=repo), GenericProfile())
    assert "ascend_ops" not in {s.id for s in rel}
    # --scope all: present and classified EXAMPLE (not the leaked SIBLING_ARTIFACT).
    allv, _ = subject_mod.discover_subjects(
        Config(repo_root=repo, scope="all"), GenericProfile()
    )
    by_id = {s.id: s for s in allv}
    assert "ascend_ops" in by_id
    assert by_id["ascend_ops"].role == SubjectRole.EXAMPLE


# ---------------------------------------------------------------------------
# Exclusion: profile policy + --exclude-scope tokens drop roots with warnings
# ---------------------------------------------------------------------------


class _ExcludePolicyProfile(Profile):
    name = "excl"

    def classify_root(self, path, cmake_project, package_context):
        parts = _parts(path)
        if "experimental" in parts and "examples" in parts:
            return SubjectRole.EXPERIMENTAL
        if "st" in parts and "tests" in parts:
            return SubjectRole.ST_TEST
        return cmake_project.role

    def root_exclusion_policy(self):
        return {SubjectRole.ST_TEST}


def test_exclusion_policy_and_scope_tokens(tmp_path):
    repo = _make_repo(tmp_path)
    # Full view + explicit --exclude-scope, so this exercises ONLY the policy +
    # token exclusion mechanism (not the release preset's broader role drop).
    config = Config(repo_root=repo, scope="all", exclude_scopes=["experimental"])
    subjects, warnings = subject_mod.discover_subjects(config, _ExcludePolicyProfile())
    ids = {s.id for s in subjects}
    # experimental example dropped via --exclude-scope token
    assert "bitwise_not_examples" not in ids
    # st_test dropped via profile root_exclusion_policy
    assert "aclnn_fused_mul_add_n_torch_test" not in ids
    codes = [w.code for w in warnings]
    assert codes.count("excluded_scope") >= 2
    dropped_subjects = {w.subject for w in warnings if w.code == "excluded_scope"}
    assert "bitwise_not_examples" in dropped_subjects
    assert "aclnn_fused_mul_add_n_torch_test" in dropped_subjects


def test_unknown_exclude_token_warns(tmp_path):
    repo = _make_repo(tmp_path)
    config = Config(repo_root=repo, exclude_scopes=["bogus_token"])
    subjects, warnings = subject_mod.discover_subjects(config, GenericProfile())
    unknown = [
        w for w in warnings if w.code == "excluded_scope" and w.subject == "bogus_token"
    ]
    assert unknown and "unrecognized" in (unknown[0].detail or "")


# ---------------------------------------------------------------------------
# Identity de-dup: genuinely-identical roots collapse; distinct same-id roots stay
# ---------------------------------------------------------------------------


def _cmake_subject(sid: str, source_path: str) -> Subject:
    return Subject(
        id=sid,
        identity=Identity(kind=SubjectKind.CMAKE_PROJECT, name=sid, version="1.0.0"),
        role=SubjectRole.CMAKE_PROJECT,
        source_path=source_path,
    )


def test_dedup_identical_subjects_collapses_true_duplicates():
    a = _cmake_subject("Kernel_Sample", "example/kernel/0")
    a_dup = _cmake_subject("Kernel_Sample", "example/kernel/0")  # same id + path
    b = _cmake_subject("Kernel_Sample", "example/kernel/1")  # same id, diff path
    out = subject_mod._dedup_identical_subjects([a, a_dup, b])
    # The exact duplicate is dropped; the distinct same-id root is KEPT (the
    # emitters disambiguate its slug-colliding id).
    assert len(out) == 2
    assert [s.source_path for s in out] == ["example/kernel/0", "example/kernel/1"]


# ---------------------------------------------------------------------------
# CANN profile: a 'samples/' standalone root classifies EXAMPLE + is trimmed
# under the default release scope.
# ---------------------------------------------------------------------------


def _make_repo_with_sample(tmp_path: Path) -> Path:
    _write(
        tmp_path / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(rts VERSION 1.0.0)\n",
    )
    _write(
        tmp_path / "samples" / "demo" / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(Runtime_Sample VERSION 1.0.0)\n",
    )
    return tmp_path


def test_cann_samples_root_classified_example_and_trimmed_under_release(tmp_path):
    from sbom_profile_cann import CannProfile

    repo = _make_repo_with_sample(tmp_path)

    # Full view: the samples/ root is discovered and classified EXAMPLE.
    subjects_all, _ = subject_mod.discover_subjects(
        Config(repo_root=repo, scope="all"), CannProfile()
    )
    by_id_all = {s.id: s for s in subjects_all}
    assert "Runtime_Sample" in by_id_all
    assert by_id_all["Runtime_Sample"].role == SubjectRole.EXAMPLE

    # Release view: the EXAMPLE root is trimmed (excluded_scope warning emitted).
    subjects_rel, warnings = subject_mod.discover_subjects(
        Config(repo_root=repo, scope="release"), CannProfile()
    )
    ids_rel = {s.id for s in subjects_rel}
    assert "Runtime_Sample" not in ids_rel
    assert any(
        w.code == "excluded_scope" and w.subject == "Runtime_Sample" for w in warnings
    )


# ---------------------------------------------------------------------------
# GENERIC example/sample fallback: a profile-less repo's example/sample/demo/
# tutorial roots classify EXAMPLE (whole-segment match); src/lib roots don't;
# a profile's definite classify_root role still wins over the fallback.
# ---------------------------------------------------------------------------


def _make_generic_example_repo(tmp_path: Path) -> Path:
    """A profile-less repo with example/ and samples/ standalone roots."""
    _write(
        tmp_path / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(rts VERSION 1.0.0)\n",
    )
    _write(
        tmp_path / "example" / "foo" / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(ExampleFoo VERSION 1.0.0)\n",
    )
    _write(
        tmp_path / "samples" / "bar" / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(SamplesBar VERSION 1.0.0)\n",
    )
    return tmp_path


def test_generic_example_segment_classifies_example(tmp_path):
    repo = _make_generic_example_repo(tmp_path)
    # Full view so the EXAMPLE roots are present (release would trim them).
    config = Config(repo_root=repo, scope="all")
    subjects, _ = subject_mod.discover_subjects(config, GenericProfile())
    by_id = {s.id: s for s in subjects}
    assert by_id["ExampleFoo"].role == SubjectRole.EXAMPLE
    assert by_id["SamplesBar"].role == SubjectRole.EXAMPLE


def test_generic_example_segment_trimmed_under_release(tmp_path):
    repo = _make_generic_example_repo(tmp_path)
    config = Config(repo_root=repo, scope="release")
    subjects, warnings = subject_mod.discover_subjects(config, GenericProfile())
    ids = {s.id for s in subjects}
    assert "ExampleFoo" not in ids
    assert "SamplesBar" not in ids
    dropped = {w.subject for w in warnings if w.code == "excluded_scope"}
    assert {"ExampleFoo", "SamplesBar"} <= dropped


def test_generic_fallback_only_matches_whole_segment(tmp_path):
    # src/lib roots and a substring like 'examples_helper' must NOT classify as
    # EXAMPLE -- they stay the neutral cmake_project role.
    _write(
        tmp_path / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(rts VERSION 1.0.0)\n",
    )
    _write(
        tmp_path / "src" / "foo" / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(SrcFoo VERSION 1.0.0)\n",
    )
    _write(
        tmp_path / "lib" / "foo" / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(LibFoo VERSION 1.0.0)\n",
    )
    _write(
        tmp_path / "examples_helper" / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(HelperRoot VERSION 1.0.0)\n",
    )
    config = Config(repo_root=tmp_path, scope="all")
    subjects, _ = subject_mod.discover_subjects(config, GenericProfile())
    by_id = {s.id: s for s in subjects}
    assert by_id["SrcFoo"].role == SubjectRole.CMAKE_PROJECT
    assert by_id["LibFoo"].role == SubjectRole.CMAKE_PROJECT
    assert by_id["HelperRoot"].role == SubjectRole.CMAKE_PROJECT


def test_profile_classify_root_wins_over_generic_fallback(tmp_path):
    # A profile that returns a DEFINITE role for an example/ root keeps that role;
    # the generic EXAMPLE fallback must not override it.
    repo = _make_generic_example_repo(tmp_path)

    class _ForceExperimentalProfile(Profile):
        name = "force_exp"

        def classify_root(self, path, cmake_project, package_context):
            if "example" in _parts(path):
                return SubjectRole.EXPERIMENTAL
            return cmake_project.role

    config = Config(repo_root=repo, scope="all")
    subjects, _ = subject_mod.discover_subjects(config, _ForceExperimentalProfile())
    by_id = {s.id: s for s in subjects}
    # profile wins for example/foo; samples/bar (untouched by profile) still falls
    # back to the generic EXAMPLE classification.
    assert by_id["ExampleFoo"].role == SubjectRole.EXPERIMENTAL
    assert by_id["SamplesBar"].role == SubjectRole.EXAMPLE


# ---------------------------------------------------------------------------
# Part B: a wheel subject is ALWAYS created (robust metadata, dynamic identity)
# ---------------------------------------------------------------------------


def test_sibling_wheel_with_dynamic_metadata_is_created(tmp_path):
    # A sibling package whose name/version are dynamic (os.getenv default + module
    # const) must still become a python_wheel subject with the resolved identity.
    _write(
        tmp_path / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(top VERSION 1.0.0)\n",
    )
    _write(
        tmp_path / "pkgs" / "dyn" / "setup.py",
        "import os\nfrom setuptools import setup\n"
        "VERSION = '4.2.0'\n"
        "setup(name=os.environ.get('DYN_NAME', 'dynwheel'), version=VERSION)\n",
    )
    config = Config(repo_root=tmp_path)
    subjects, _ = subject_mod.discover_subjects(config, GenericProfile())
    by_id = {s.id: s for s in subjects}
    assert "dynwheel" in by_id
    assert by_id["dynwheel"].identity.kind == SubjectKind.PYTHON_WHEEL
    assert by_id["dynwheel"].identity.version == "4.2.0"
    assert by_id["dynwheel"].role == SubjectRole.SIBLING_ARTIFACT


def test_wheel_created_even_when_version_unresolved(tmp_path):
    # Unresolved version must NOT drop the wheel — the subject is created with
    # version None and a warning is emitted (never fabricated, never lost).
    _write(
        tmp_path / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(top VERSION 1.0.0)\n",
    )
    _write(
        tmp_path / "pkgs" / "noversion" / "setup.py",
        "import os\nfrom setuptools import setup\n"
        "setup(name='noverwheel', version=os.environ['MUST_BE_SET'])\n",
    )
    config = Config(repo_root=tmp_path)
    subjects, warnings = subject_mod.discover_subjects(config, GenericProfile())
    by_id = {s.id: s for s in subjects}
    assert "noverwheel" in by_id, "wheel must be created despite unresolved version"
    assert by_id["noverwheel"].identity.version is None
    assert any(
        w.code == "subject_version_unresolved" for w in warnings
    ), "an unresolved-version warning must be surfaced"


def test_root_python_package_becomes_primary_without_cmake(tmp_path):
    # A repo whose ONLY root artifact is a Python package (no CMakeLists) makes
    # the root wheel the PRIMARY subject.
    _write(
        tmp_path / "setup.py",
        "from setuptools import setup\nsetup(name='solo', version='2.0.0')\n",
    )
    config = Config(repo_root=tmp_path)
    subjects, _ = subject_mod.discover_subjects(config, GenericProfile())
    by_id = {s.id: s for s in subjects}
    assert "solo" in by_id
    assert by_id["solo"].role == SubjectRole.PRIMARY
    assert by_id["solo"].identity.kind == SubjectKind.PYTHON_WHEEL


def test_tooling_only_pyproject_is_not_a_package(tmp_path):
    # A pyproject.toml with only tool config (no [project]/[build-system]) must
    # NOT be treated as a package root (mirrors MindIE-LLM's [tool.black] file).
    _write(
        tmp_path / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(top VERSION 1.0.0)\n",
    )
    _write(tmp_path / "sub" / "pyproject.toml", "[tool.black]\nline-length = 120\n")
    config = Config(repo_root=tmp_path)
    subjects, _ = subject_mod.discover_subjects(config, GenericProfile())
    kinds = {s.identity.kind for s in subjects}
    assert SubjectKind.PYTHON_WHEEL not in kinds


# ---------------------------------------------------------------------------
# Part C: GENERIC co-located wheel+CMake merge (no profile required)
# ---------------------------------------------------------------------------


def _make_colocated_repo(tmp_path: Path) -> Path:
    """A pyasc-shaped repo: root wheel 'colocatedwheel' + project(ColocatedNative)."""
    _write(
        tmp_path / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\n"
        "project(ColocatedNative LANGUAGES CXX VERSION 1.1.1)\n",
    )
    _write(
        tmp_path / "setup.py",
        "import os\nfrom setuptools import setup\n"
        "DEFAULT_VERSION = '1.1.1'\n"
        "setup(name=os.environ.get('PKG_NAME', 'colocatedwheel'), "
        "version=DEFAULT_VERSION)\n",
    )
    return tmp_path


def test_generic_colocated_merge_wheel_is_primary(tmp_path):
    # The wheel identity wins over the co-located CMake project (which would
    # otherwise be the primary subject); CMake becomes a facet + build root.
    repo = _make_colocated_repo(tmp_path)
    config = Config(repo_root=repo)
    subjects, _ = subject_mod.discover_subjects(config, GenericProfile())
    by_id = {s.id: s for s in subjects}

    assert "colocatedwheel" in by_id, "wheel must be the surviving subject"
    assert "ColocatedNative" not in by_id, "CMake project must be absorbed"
    kept = by_id["colocatedwheel"]
    assert kept.role == SubjectRole.PRIMARY, "wheel becomes the canonical primary"
    assert kept.identity.kind == SubjectKind.PYTHON_WHEEL
    assert kept.identity.version == "1.1.1"
    assert kept.build_graph_root_id == "ColocatedNative"
    facet_names = {(f.name, f.kind) for f in kept.facets}
    assert ("ColocatedNative", SubjectKind.CMAKE_PROJECT) in facet_names


def test_generic_colocated_merge_for_sibling_dir(tmp_path):
    # Co-located wheel+CMake under a sub-dir: the sibling wheel absorbs the
    # standalone CMake root that shares its directory.
    _write(
        tmp_path / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(top VERSION 1.0.0)\n",
    )
    _write(
        tmp_path / "ext" / "setup.py",
        "from setuptools import setup\nsetup(name='extwheel', version='1.0.0')\n",
    )
    _write(
        tmp_path / "ext" / "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(ExtNative VERSION 1.0.0)\n",
    )
    config = Config(repo_root=tmp_path)
    subjects, _ = subject_mod.discover_subjects(config, GenericProfile())
    by_id = {s.id: s for s in subjects}
    assert "extwheel" in by_id
    assert "ExtNative" not in by_id
    kept = by_id["extwheel"]
    assert kept.role == SubjectRole.SIBLING_ARTIFACT, "stays a sibling, not primary"
    assert kept.build_graph_root_id == "ExtNative"
    assert any(f.name == "ExtNative" for f in kept.facets)


def test_generic_merge_composes_with_profile_idempotently(tmp_path):
    # The generic merge runs first; a profile that ALSO returns the same merge
    # must not double-apply it (one facet, not two) and must not lose anything.
    repo = _make_colocated_repo(tmp_path)

    class _RedundantMergeProfile(Profile):
        name = "redundant"

        def subject_facets(self, subjects):
            ids = {s.id for s in subjects}
            # By the time the profile runs, ColocatedNative is already absorbed,
            # so this merge references a now-absent subject — must be a safe no-op.
            if "colocatedwheel" in ids and "ColocatedNative" in ids:
                return [
                    SubjectMerge(
                        keep_subject_id="colocatedwheel",
                        absorbed_subject_id="ColocatedNative",
                        build_graph_root_id="ColocatedNative",
                        facet=Facet(
                            kind=SubjectKind.CMAKE_PROJECT,
                            name="ColocatedNative",
                            version="1.1.1",
                        ),
                    )
                ]
            return []

    config = Config(repo_root=repo)
    subjects, _ = subject_mod.discover_subjects(config, _RedundantMergeProfile())
    by_id = {s.id: s for s in subjects}
    assert "colocatedwheel" in by_id
    assert "ColocatedNative" not in by_id
    facets = by_id["colocatedwheel"].facets
    native = [f for f in facets if f.name == "ColocatedNative"]
    assert len(native) == 1, f"facet duplicated by double merge: {facets}"


# ---------------------------------------------------------------------------
# Real ops-math tree smoke test
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not OPS_MATH.exists(), reason="ops-math tree not present")
def test_real_ops_math_discovery():
    # Full view so the generically-classified example roots are present (release
    # would trim them).
    config = Config(repo_root=OPS_MATH, scope="all")
    subjects, _ = subject_mod.discover_subjects(config, GenericProfile())
    by_id = {s.id: s for s in subjects}

    # primary CANN package ops_math 9.0.0 with math CMake facet
    assert "ops_math" in by_id
    primary = by_id["ops_math"]
    assert primary.role == SubjectRole.PRIMARY
    assert primary.identity.version == "9.0.0"
    assert any(f.name == "math" for f in primary.facets)

    # sibling wheels present
    assert "npu_math_extension" in by_id
    assert "ascend_ops" in by_id
    # ascend_ops absorbs its co-located AscendOps exactly once (no double-merge
    # from generic + profile passes). The co-located CMake root is NOT pre-
    # reclassified by the generic example fallback, so the merge still fires.
    assert "AscendOps" not in by_id
    ascend_native = [f for f in by_id["ascend_ops"].facets if f.name == "AscendOps"]
    assert len(ascend_native) == 1, f"AscendOps facet duplicated: {by_id['ascend_ops'].facets}"
    assert by_id["ascend_ops"].build_graph_root_id == "AscendOps"

    # discovered standalone experimental roots (project() + cmake_minimum_required).
    # Under the generic core, an 'examples' SEGMENT root classifies EXAMPLE.
    assert "bitwise_not_examples" in by_id
    assert by_id["bitwise_not_examples"].role == SubjectRole.EXAMPLE
    # Every CMake-discovered root keeps either the neutral cmake_project/primary
    # role or the generic EXAMPLE classification (no other role: finer
    # experimental/test semantics are profile policy, absent here).
    cmake_roots = [
        s for s in subjects if s.identity.kind == SubjectKind.CMAKE_PROJECT
    ]
    assert all(
        s.role
        in (SubjectRole.CMAKE_PROJECT, SubjectRole.PRIMARY, SubjectRole.EXAMPLE)
        for s in cmake_roots
    )
