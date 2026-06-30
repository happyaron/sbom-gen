"""Unit tests for sbom.cmake.parse — the static CMake parser.

Table-driven where practical. Snippets mirror the real CANN/CMake third_party
files (protobuf, abseil-cpp, json, eigen, gtest, makeself-fetch, openssl) and
ops-math/cmake/fetch_cann_cmake.cmake. All tests run offline and never invoke
cmake.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sbom.cmake import parse
from sbom.cmake.parse import (
    AddDependenciesEdge,
    CMakeFile,
    ExternalProject,
    FetchContentDecl,
    FindPackageCall,
    IncludeStmt,
    LinkLibraryToken,
    ProgramInvocation,
    classify_link_token,
    classify_program,
    discover_roots,
    parse_file,
    parse_recursive,
    program_to_environment_tool,
    resolve_cmake_authority,
    tokenize_command,
)
from sbom.models import (
    CmakeAuthorityBranch,
    CommandContext,
    IntegrityFinding,
)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ===========================================================================
# ExternalProject_Add: URL candidates, hash, TLS, patches, DEPENDS, commands
# ===========================================================================


def test_protobuf_external_project(tmp_path):
    """Mirror protobuf.cmake: no URL_HASH, TLS_VERIFY OFF, patch, DEPENDS edge."""
    patch = _write(tmp_path, "protobuf_25.1_change_version.patch", "patch-body\n")
    src = _write(
        tmp_path,
        "protobuf.cmake",
        """
        include(${CMAKE_CURRENT_LIST_DIR}/abseil-cpp.cmake)
        if (EXISTS ${CANN_3RD_LIB_PATH}/protobuf-25.1.tar.gz)
            set(PROTOBUF_PATH ${CANN_3RD_LIB_PATH}/protobuf-25.1.tar.gz)
        else()
            set(PROTOBUF_PATH "https://cann-3rd.example.com/protobuf/protobuf-25.1.tar.gz")
        endif()
        ExternalProject_Add(protobuf_src
            URL ${PROTOBUF_PATH}
            TLS_VERIFY OFF
            PATCH_COMMAND patch -p1 < ${CMAKE_CURRENT_LIST_DIR}/protobuf_25.1_change_version.patch
            CONFIGURE_COMMAND ""
            BUILD_COMMAND ""
            INSTALL_COMMAND ""
            DEPENDS abseil_build
        )
        """,
    )
    cf = parse_file(src)
    assert len(cf.external_projects) == 1
    ep = cf.external_projects[0]
    assert ep.name == "protobuf_src"
    assert ep.url_hash is None
    assert ep.tls_verify is False
    assert ep.source_version == "25.1"
    # canonical https vs resolved local-cache fallback
    assert ep.canonical_url == "https://cann-3rd.example.com/protobuf/protobuf-25.1.tar.gz"
    assert ep.resolved_url_or_path == "${CANN_3RD_LIB_PATH}/protobuf-25.1.tar.gz"
    # DEPENDS becomes an edge
    assert ep.depends == ["abseil_build"]
    # patch with sha256 computed from the real file
    assert len(ep.patches) == 1
    assert ep.patches[0].file == "protobuf_25.1_change_version.patch"
    assert ep.patches[0].sha256 == hashlib.sha256(patch.read_bytes()).hexdigest()
    # integrity findings stack: no_hash + tls disabled
    assert IntegrityFinding.NO_HASH in ep.integrity_findings
    assert IntegrityFinding.TLS_VERIFICATION_DISABLED in ep.integrity_findings
    # emptied commands captured
    assert ep.commands["configure"] == ""
    assert ep.commands["build"] == ""
    assert ep.commands["patch"].startswith("patch -p1")
    # include() of abseil-cpp captured (not followed by parse_file)
    assert any(i.path.endswith("abseil-cpp.cmake") for i in cf.includes)


def test_include_chain_propagates_call_site_scope(tmp_path):
    # A path-neutral fragment reached via a DEEP chain from a test entrypoint must
    # inherit the test scope (not leak to RUNTIME into the release view) — M1.
    from sbom.collectors.cpp import _call_site_scope
    from sbom.models import UsageScope

    (tmp_path / "CMakeLists.txt").write_text("include(build/ut/ut.cmake)\n")
    (tmp_path / "build/ut").mkdir(parents=True)
    (tmp_path / "neutral").mkdir()
    (tmp_path / "build/ut/ut.cmake").write_text(
        f"include({tmp_path / 'neutral/middle.cmake'})\n"
    )
    (tmp_path / "neutral/middle.cmake").write_text(
        f"include({tmp_path / 'neutral/leaf.cmake'})\n"
    )
    (tmp_path / "neutral/leaf.cmake").write_text("find_package(SomeTestDep REQUIRED)\n")

    files = parse.parse_recursive(tmp_path / "CMakeLists.txt", effective_cmake_root=tmp_path)
    by_name = {cf.path.name: cf for cf in files}
    # leaf is two path-neutral levels below the ut.cmake (test) entrypoint.
    assert [p.name for p in by_name["leaf.cmake"].include_chain] == [
        "CMakeLists.txt", "ut.cmake", "middle.cmake",
    ]
    assert _call_site_scope(by_name["leaf.cmake"], None) is UsageScope.TEST
    assert _call_site_scope(by_name["middle.cmake"], None) is UsageScope.TEST


def test_condition_stack_index_matches_nested_gates():
    # The one-pass cached condition index (C9) must yield the same nested if-gates
    # the old per-call re-parse produced.
    from sbom.cmake.parse import _condition_stack_at, _iter_commands

    text = (
        "if(A)\n"
        "  if(B)\n"
        "    find_package(Foo)\n"
        "  endif()\n"
        "  find_package(Bar)\n"
        "else()\n"
        "  find_package(Baz)\n"
        "endif()\n"
        "find_package(Qux)\n"
    )
    gates = {}
    for cmd in _iter_commands(text):
        if cmd.name == "find_package":
            gates[cmd.args[0]] = [c.expr for c in _condition_stack_at(text, cmd.start)]
    assert gates["Foo"] == ["A", "B"]
    assert gates["Bar"] == ["A"]
    assert gates["Baz"] == ["NOT (A)"]
    assert gates["Qux"] == []


def test_tls_verify_only_literal_off_disables():
    # An unresolved variable / unknown token must NOT read as disabled (a false
    # TLS_VERIFICATION_DISABLED security finding) — only explicit OFF — review C8.
    from sbom.cmake.parse import _tls_verify

    assert _tls_verify(["TLS_VERIFY", "${VAR}"]) is None
    assert _tls_verify(["TLS_VERIFY", "MAYBE"]) is None
    assert _tls_verify(["URL", "x"]) is None  # absent
    assert _tls_verify(["TLS_VERIFY", "OFF"]) is False
    assert _tls_verify(["TLS_VERIFY", "ON"]) is True


def test_json_url_hash_present(tmp_path):
    src = _write(
        tmp_path,
        "json.cmake",
        """
        if(EXISTS "${CANN_3RD_LIB_PATH}/json-3.11.3.tar.gz")
            set(REQ_URL ${CANN_3RD_LIB_PATH}/json-3.11.3.tar.gz)
        else()
            set(REQ_URL "https://cann-3rd.example.com/json/json-3.11.3.tar.gz")
        endif()
        ExternalProject_Add(third_party_json
            URL ${REQ_URL}
            URL_HASH SHA256=0d8ef5af7f9794e3263480193c491549b2ba6cc74bb018906202ada498a79406
            CONFIGURE_COMMAND ""
        )
        """,
    )
    ep = parse_file(src).external_projects[0]
    assert ep.url_hash == "0d8ef5af7f9794e3263480193c491549b2ba6cc74bb018906202ada498a79406"
    assert ep.source_version == "3.11.3"
    assert IntegrityFinding.NO_HASH not in ep.integrity_findings
    assert ep.tls_verify is None


def test_eigen_local_dir_fallback_no_hash(tmp_path):
    src = _write(
        tmp_path,
        "eigen.cmake",
        """
        if(EXISTS "${CANN_3RD_LIB_PATH}/eigen-5.0.0.tar.gz")
            set(REQ_URL "${CANN_3RD_LIB_PATH}/eigen-5.0.0.tar.gz")
        elseif(IS_DIRECTORY "${CANN_3RD_LIB_PATH}/eigen")
            set(REQ_URL "${CANN_3RD_LIB_PATH}/eigen")
        else()
            set(REQ_URL "https://gitcode.example.com/eigen/eigen-5.0.0.tar.gz")
        endif()
        ExternalProject_Add(external_eigen
            URL ${REQ_URL}
            INSTALL_COMMAND ""
            BUILD_COMMAND ""
        )
        """,
    )
    ep = parse_file(src).external_projects[0]
    assert ep.url_hash is None
    assert ep.canonical_url == "https://gitcode.example.com/eigen/eigen-5.0.0.tar.gz"
    # first candidate (highest priority) is the local tar.gz cache path
    assert ep.resolved_url_or_path == "${CANN_3RD_LIB_PATH}/eigen-5.0.0.tar.gz"
    assert ep.source_version == "5.0.0"
    assert IntegrityFinding.NO_HASH in ep.integrity_findings
    # local (non-url) source + no hash -> local_source_unverified
    assert IntegrityFinding.LOCAL_SOURCE_UNVERIFIED in ep.integrity_findings


def test_gtest_archive_filename_version(tmp_path):
    src = _write(
        tmp_path,
        "gtest.cmake",
        """
        set(GTEST_ARCHIVE ${CANN_3RD_LIB_PATH}/gtest/googletest-1.14.0.tar.gz)
        if(EXISTS "${GTEST_ARCHIVE}")
            set(GTEST_PROJECT_URL ${GTEST_ARCHIVE})
        else()
            set(GTEST_PROJECT_URL "https://cann-3rd.example.com/googletest/googletest-1.14.0.tar.gz")
        endif()
        ExternalProject_Add(third_party_gtest
            URL ${GTEST_PROJECT_URL}
            BUILD_COMMAND $(MAKE)
            INSTALL_COMMAND $(MAKE) install
        )
        """,
    )
    ep = parse_file(src).external_projects[0]
    assert ep.source_version == "1.14.0"
    assert ep.url_hash is None
    # $(MAKE) build/install commands captured
    assert ep.commands["build"] == "$(MAKE)"
    assert ep.commands["install"] == "$(MAKE) install"


def test_openssl_compound_configure_and_perl_program(tmp_path):
    src = _write(
        tmp_path,
        "openssl.cmake",
        """
        find_program(PERL_PATH perl REQUIRED)
        find_program(CCACHE_PROGRAM ccache)
        set(OPENSSL_CONFIGURE_COMMAND
            unset CROSS_COMPILE && export NO_OSSL_RENAME_VERSION=1 &&
            ${PERL_PATH} <SOURCE_DIR>/Configure linux-x86_64 no-tests
        )
        ExternalProject_Add(openssl_project
            URL ${REQ_URL}
            URL_HASH SHA256=2eec31f2ac0e126ff68d8107891ef534159c4fcfb095365d4cd4dc57d82616ee
            CONFIGURE_COMMAND ${OPENSSL_CONFIGURE_COMMAND} CC=${OPENSSL_CC}
            BUILD_COMMAND $(MAKE)
            INSTALL_COMMAND $(MAKE) install_dev
        )
        """,
    )
    cf = parse_file(src)
    ep = cf.external_projects[0]
    assert ep.url_hash.endswith("616ee")
    # find_program perl REQUIRED captured
    names = {(p.name, p.required) for p in cf.programs if p.command_context == "find_program"}
    assert ("perl", True) in names
    assert ("ccache", False) in names


# ===========================================================================
# FetchContent_Declare
# ===========================================================================


def test_makeself_fetch_content(tmp_path):
    src = _write(
        tmp_path,
        "makeself-fetch.cmake",
        """
        set(MAKESELF_NAME "makeself")
        set(MAKESELF_URL "https://gitcode.example.com/makeself/makeself.tar.gz")
        FetchContent_Declare(
            ${MAKESELF_NAME}
            URL ${MAKESELF_URL}
            URL_HASH SHA256=bfa730a5763cdb267904a130e02b2e48e464986909c0733ff1c96495f620369a
            SOURCE_DIR "${MAKESELF_PATH}"
        )
        execute_process(COMMAND tar xzf foo.tar.gz)
        execute_process(COMMAND chmod 700 makeself.sh)
        """,
    )
    cf = parse_file(src)
    assert len(cf.fetch_contents) == 1
    fc = cf.fetch_contents[0]
    assert fc.name == "makeself"  # ${MAKESELF_NAME} resolved
    assert fc.url_hash.endswith("0369a")
    assert fc.canonical_url == "https://gitcode.example.com/makeself/makeself.tar.gz"
    # tar / chmod become program invocations (later -> environment tools)
    progs = {p.name for p in cf.programs if p.command_context == "execute_process"}
    assert "tar" in progs
    assert "chmod" in progs


def test_fetch_content_git_unpinned(tmp_path):
    src = _write(
        tmp_path,
        "ots.cmake",
        """
        set(OPS_TEST_KIT_TAG_ID master)
        FetchContent_Declare(
            ops_test_kit
            GIT_REPOSITORY https://gitcode.example.com/cann/ops-test-kit.git
            GIT_TAG ${OPS_TEST_KIT_TAG_ID}
        )
        """,
    )
    fc = parse_file(src).fetch_contents[0]
    assert fc.git_repository == "https://gitcode.example.com/cann/ops-test-kit.git"
    assert fc.git_tag == "master"
    assert fc.vcs_ref is not None and fc.vcs_ref.requested == "master"
    assert IntegrityFinding.UNPINNED_GIT in fc.integrity_findings


def test_fetch_content_git_pinned_commit(tmp_path):
    src = _write(
        tmp_path,
        "opbase.cmake",
        """
        set(OPBASE_TAG_ID b92c2c8f3d999f315b0251cfb25edb111bb898d5)
        FetchContent_Declare(
            opbase
            GIT_REPOSITORY https://gitcode.example.com/cann/opbase.git
            GIT_TAG ${OPBASE_TAG_ID})
        """,
    )
    fc = parse_file(src).fetch_contents[0]
    assert fc.git_tag == "b92c2c8f3d999f315b0251cfb25edb111bb898d5"
    # a full commit sha is pinned -> no unpinned_git finding
    assert IntegrityFinding.UNPINNED_GIT not in fc.integrity_findings


def test_tarball_url_hash_in_fetch_content(tmp_path):
    """fetch_cann_cmake tarball branch: URL_HASH + master-016 in filename."""
    src = _write(
        tmp_path,
        "fetch_cann_cmake.cmake",
        """
        set(CANN_CMAKE_TAG "master-016")
        FetchContent_Declare(
            cann-cmake
            URL "${CANN_3RD_LIB_PATH}/cmake-master-016.tar.gz"
            URL_HASH SHA256=9167f7296590685b459d6abae6cc4b6e95db3db755af66b2c5b3c3f4908b3b39
        )
        """,
    )
    fc = parse_file(src).fetch_contents[0]
    assert fc.name == "cann-cmake"
    assert fc.url_hash.endswith("b3b39")


# ===========================================================================
# find_package: required / quiet / effective_required + conditions
# ===========================================================================


def test_find_package_requiredness_table(tmp_path):
    src = _write(
        tmp_path,
        "dependencies.cmake",
        """
        if(BUILD_WITH_INSTALLED_DEPENDENCY_CANN_PKG)
          find_package(ASC REQUIRED HINTS ${ASCEND_DIR})
          find_package(GenerateEsPackage MODULE QUIET)
          if(NOT GenerateEsPackage_FOUND)
              message(FATAL_ERROR "missing GenerateEsPackage")
          endif()
        endif()
        find_package(dlog MODULE REQUIRED)
        find_package(securec MODULE)
        if(ENABLE_TEST)
          find_package(tikicpulib REQUIRED)
        endif()
        """,
    )
    fps = {fp.name: fp for fp in parse_file(src).find_packages}
    # dlog REQUIRED
    assert fps["dlog"].info.required is True
    assert fps["dlog"].info.effective_required is True
    # securec non-REQUIRED -> required False, effective unknown (None)
    assert fps["securec"].info.required is False
    assert fps["securec"].info.effective_required is None
    # GenerateEsPackage QUIET yet fatal nearby -> effective_required True
    assert fps["GenerateEsPackage"].info.quiet is True
    assert fps["GenerateEsPackage"].info.required is False
    assert fps["GenerateEsPackage"].info.effective_required is True
    # ASC carries the BUILD_WITH... condition
    asc_conds = [c.expr for c in fps["ASC"].conditions]
    assert any("BUILD_WITH_INSTALLED_DEPENDENCY_CANN_PKG" in e for e in asc_conds)
    # tikicpulib carries ENABLE_TEST condition
    assert any("ENABLE_TEST" in c.expr for c in fps["tikicpulib"].conditions)


# ===========================================================================
# Recursive include() graph + custom-macro expansion
# ===========================================================================


def test_recursive_include_graph(tmp_path):
    root = tmp_path / "cmake"
    _write(root, "third_party/abseil-cpp.cmake", "# abseil leaf\n")
    _write(
        root,
        "third_party/protobuf.cmake",
        "include(${CMAKE_CURRENT_LIST_DIR}/abseil-cpp.cmake)\n",
    )
    entry = _write(
        root,
        "entry.cmake",
        "include(${CMAKE_CURRENT_LIST_DIR}/third_party/protobuf.cmake)\n",
    )
    files = parse_recursive(entry, root)
    visited = {f.path.name for f in files}
    assert "entry.cmake" in visited
    assert "protobuf.cmake" in visited
    assert "abseil-cpp.cmake" in visited


def test_recursive_include_cycle_broken(tmp_path):
    root = tmp_path / "cmake"
    a = _write(root, "a.cmake", "include(${CMAKE_CURRENT_LIST_DIR}/b.cmake)\n")
    _write(root, "b.cmake", "include(${CMAKE_CURRENT_LIST_DIR}/a.cmake)\n")
    files = parse_recursive(a, root)
    # each visited once, no infinite loop
    names = sorted(f.path.name for f in files)
    assert names == ["a.cmake", "b.cmake"]


def test_custom_macro_expansion(tmp_path):
    root = tmp_path / "cmake"
    _write(root, "third_party/eigen.cmake", "# eigen\n")
    entry = _write(root, "entry.cmake", "add_cann_third_party(eigen)\n")

    def resolver(args, eff_root):
        return eff_root / "third_party" / f"{args[0]}.cmake"

    files = parse_recursive(
        entry, root, custom_macros={"add_cann_third_party": resolver}
    )
    names = {f.path.name for f in files}
    assert "eigen.cmake" in names
    # the macro call was recorded on the entry file
    entry_cf = next(f for f in files if f.path.name == "entry.cmake")
    assert ("add_cann_third_party", ["eigen"]) in entry_cf.macro_calls


def test_custom_macro_default_convention(tmp_path):
    """Without a resolver, default <root>/third_party/<name>.cmake is followed."""
    root = tmp_path / "cmake"
    _write(root, "third_party/json.cmake", "# json\n")
    entry = _write(root, "entry.cmake", "add_cann_third_party(json)\n")
    files = parse_recursive(
        entry, root, custom_macros={"add_cann_third_party": None}
    )
    assert "json.cmake" in {f.path.name for f in files}


# ===========================================================================
# Version: archive filename vs set(*_VERSION)
# ===========================================================================


def test_set_version_attached(tmp_path):
    src = _write(
        tmp_path,
        "ver.cmake",
        """
        set(FOO_VERSION 3.13.0)
        ExternalProject_Add(foo URL https://x/foo-25.1.tar.gz)
        """,
    )
    ep = parse_file(src).external_projects[0]
    assert ep.source_version == "25.1"  # from filename
    assert ep.set_version == "3.13.0"  # from set()


# ===========================================================================
# Link tokens + classify_link_token
# ===========================================================================


def test_link_tokens_var_expansion_and_inline(tmp_path):
    src = _write(
        tmp_path,
        "torch_extension.cmake",
        """
        set(TORCH_EXTENSION_LINK_LIBS
            ${TORCH_LIBRARIES}
            torch_npu
            ascendcl
            platform
            tiling_api
            runtime
        )
        target_link_libraries(_C PRIVATE ${TORCH_EXTENSION_LINK_LIBS})
        """,
    )
    cf = parse_file(src)
    raws = {t.raw for t in cf.link_tokens}
    assert "torch_npu" in raws
    assert "tiling_api" in raws
    # variable-expanded tokens record the source var
    tn = next(t for t in cf.link_tokens if t.raw == "torch_npu")
    assert tn.target_property == "TORCH_EXTENSION_LINK_LIBS"


def test_link_tokens_symbol_flags_and_genexpr(tmp_path):
    src = _write(
        tmp_path,
        "symbol.cmake",
        """
        target_link_libraries(
            ophost
            PRIVATE $<BUILD_INTERFACE:intf_pub_cxx17>
                    c_sec
                    -Wl,--no-as-needed
                    register
                    -Wl,--whole-archive
                    rt2_registry_static
                    tiling_api
                    runtime
                    unified_dlog
                    mmpa
        )
        """,
    )
    cf = parse_file(src)
    local_targets = {"register"}
    by_class: dict[str, list[str]] = {"drop": [], "local": [], "external": []}
    for t in cf.link_tokens:
        by_class[classify_link_token(t, local_targets)].append(t.raw)
    # flags and genexprs dropped
    assert "-Wl,--no-as-needed" in by_class["drop"]
    assert any(r.startswith("$<") for r in by_class["drop"])
    # local target resolved separately
    assert "register" in by_class["local"]
    # external libs emitted
    for ext in ("c_sec", "rt2_registry_static", "tiling_api", "unified_dlog", "mmpa"):
        assert ext in by_class["external"]


@pytest.mark.parametrize(
    "raw,local,expected",
    [
        ("-Wl,-z,relro", set(), "drop"),
        ("$<TARGET_OBJECTS:foo>", set(), "drop"),
        ("${SOME_VAR}", set(), "drop"),
        # Unexpanded CMake variable references are never real deps. ${ARGN}
        # (macro varargs) leaked as a component named '${ARGN}' via
        # find_package/target_link_libraries(... ${ARGN}); an embedded reference
        # like 'foo${BAR}' is not a resolvable name either.
        ("${ARGN}", set(), "drop"),
        ("${CMAKE_AR}", set(), "drop"),
        ("foo${BAR}", set(), "drop"),
        ("mylib", set(), "external"),
        ("mytarget", {"mytarget"}, "local"),
        ("torch_npu", set(), "external"),
        ("ascendcl", {"other"}, "external"),
    ],
)
def test_classify_link_token_table(raw, local, expected):
    tok = LinkLibraryToken(raw=raw, target_property=None)
    assert classify_link_token(tok, local) == expected


# ===========================================================================
# add_dependencies edges
# ===========================================================================


def test_add_dependencies_edges(tmp_path):
    src = _write(
        tmp_path,
        "dep.cmake",
        """
        add_dependencies(ascend_protobuf protobuf_shared_build)
        add_dependencies(host_protoc protobuf_host_build)
        """,
    )
    cf = parse_file(src)
    edges = {(e.target, tuple(e.depends_on)) for e in cf.add_dependencies}
    assert ("ascend_protobuf", ("protobuf_shared_build",)) in edges
    assert ("host_protoc", ("protobuf_host_build",)) in edges


# ===========================================================================
# tokenize_command (shell-compound)
# ===========================================================================


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("$(MAKE)", [["$(MAKE)"]]),
        ("$(MAKE) install", [["$(MAKE)", "install"]]),
        ("patch -p1 < foo.patch", [["patch", "-p1"]]),
        (
            "unset CROSS_COMPILE && export X=1 && perl Configure",
            [["unset", "CROSS_COMPILE"], ["export", "X=1"], ["perl", "Configure"]],
        ),
        ("VAR=val cmake -E make_directory d", [["cmake", "-E", "make_directory", "d"]]),
        ("tar xzf a.tar.gz | grep foo", [["tar", "xzf", "a.tar.gz"], ["grep", "foo"]]),
        ("cmd1 ; cmd2", [["cmd1"], ["cmd2"]]),
        ("echo hi > out.txt", [["echo", "hi"]]),
        ("cmake -E copy <SOURCE_DIR>/a b", [["cmake", "-E", "copy", "<SOURCE_DIR>/a", "b"]]),
        ("", []),
        ("   ", []),
    ],
)
def test_tokenize_command_table(raw, expected):
    assert tokenize_command(raw) == expected


def test_tokenize_strips_leading_var_assignments():
    out = tokenize_command("CC=gcc CXX=g++ make all")
    assert out == [["make", "all"]]


# ===========================================================================
# classify_program + program_to_environment_tool
# ===========================================================================


@pytest.mark.parametrize(
    "name,args,profile_tooling,expected",
    [
        ("perl", [], set(), "environment_tool"),
        ("ccache", [], set(), "environment_tool"),
        ("$(MAKE)", [], set(), "environment_tool"),
        ("cp", [], set(), "environment_tool"),
        ("tar", [], set(), "environment_tool"),
        ("chmod", [], set(), "environment_tool"),
        ("git", [], set(), "environment_tool"),
        ("patch", [], set(), "environment_tool"),
        ("protoc", [], set(), "component"),
        ("host_protoc", [], set(), "component"),
        ("ninja", [], set(), "component"),
        ("cmake", ["-E", "make_directory", "d"], set(), "ignore"),
        ("cmake", ["<SOURCE_DIR>"], set(), "component"),
        ("-Wl,foo", [], set(), "ignore"),
        ("op_build", [], {"op_build"}, "component"),
        ("mytool", [], {"mytool"}, "component"),
        # (f) catch-all quarantines an unrecognized token (build-system cache
        # var garbage) as 'ignore', NOT 'environment_tool'.
        ("cmake_ar", [], set(), "ignore"),
        ("arm_cxx_compiler", [], set(), "ignore"),
        ("ascend_python_executable", [], set(), "ignore"),
        ("totally_unknown_tool", [], set(), "ignore"),
        # An unexpanded CMake variable reference is never a real program.
        ("${ARGN}", [], set(), "ignore"),
        ("${CMAKE_AR}", [], set(), "ignore"),
        ("foo${BAR}", [], set(), "ignore"),
    ],
)
def test_classify_program_table(name, args, profile_tooling, expected):
    inv = ProgramInvocation(name=name, command_context="execute_process", args=args)
    assert classify_program(inv, profile_tooling) == expected


# ===========================================================================
# (f) _program_basename: unresolved ${VAR} garbage is dropped (sentinel None)
# ===========================================================================


@pytest.mark.parametrize(
    "token,expected",
    [
        ("${CMAKE_AR}", None),
        ("${CMAKE_C_COMPILER}", None),
        ("${ARM_CXX_COMPILER}", None),
        ("${ASCEND_PYTHON_EXECUTABLE}", None),
        ("${PROTOBUF_PROTOC_EXECUTABLE}", "protoc"),  # (g) protoc domain tool
        ("${HOST_PROTOC}", "host_protoc"),
        ("${CMAKE_COMMAND}", "cmake"),
        ("$(MAKE)", "$(MAKE)"),
        ("/usr/bin/perl", "perl"),
        ("ccache", "ccache"),
    ],
)
def test_program_basename_drops_var_garbage(token, expected):
    assert parse._program_basename(token) == expected


def test_unresolved_var_find_program_dropped(tmp_path):
    """find_program whose resolved NAMES token is a bare cache var -> dropped."""
    src = _write(
        tmp_path,
        "tool.cmake",
        """
        find_program(MY_AR NAMES ${CMAKE_AR})
        find_program(CCACHE_PROGRAM ccache)
        """,
    )
    cf = parse_file(src)
    names = {p.name for p in cf.programs}
    assert "ccache" in names
    # the ${CMAKE_AR} find_program produced no garbage invocation
    assert not any(p.name and "cmake_ar" in p.name.lower() for p in cf.programs)


# ===========================================================================
# (g) protoc domain-tool vars map to the protoc/host_protoc tool
# ===========================================================================


def test_protoc_find_program_and_imported_executable(tmp_path):
    src = _write(
        tmp_path,
        "protobuf.cmake",
        """
        find_program(PROTOC_PROGRAM NAMES protoc PATHS ${PROTOBUF_HOST_PROTOC_DIR})
        add_executable(host_protoc IMPORTED GLOBAL)
        execute_process(COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} --version)
        """,
    )
    cf = parse_file(src)
    names = {p.name for p in cf.programs}
    assert "protoc" in names  # find_program NAMES protoc + ${...PROTOC_EXECUTABLE}
    assert "host_protoc" in names  # imported executable
    # all of them route to "component" (domain tool)
    for p in cf.programs:
        assert classify_program(p, set()) == "component"


def test_program_to_environment_tool_mapping():
    inv = ProgramInvocation(
        name="perl",
        command_context="find_program",
        required=True,
        source_file="/x/openssl.cmake",
    )
    et = program_to_environment_tool(
        inv,
        source_revision="master-016",
        source_authority="cann-cmake",
        root_artifact_id="ops_math",
    )
    assert et.name == "perl"
    assert et.required is True
    assert et.source_file == "/x/openssl.cmake"
    assert et.source_revision == "master-016"
    assert et.source_authority == "cann-cmake"
    assert et.root_artifact_id == "ops_math"
    assert et.command_context == CommandContext.FIND_PROGRAM


@pytest.mark.parametrize(
    "ctx_str,expected_enum",
    [
        ("find_program", CommandContext.FIND_PROGRAM),
        ("execute_process", CommandContext.EXECUTE_PROCESS),
        ("add_custom_command", CommandContext.ADD_CUSTOM_COMMAND),
        ("add_custom_target", CommandContext.ADD_CUSTOM_TARGET),
        ("ep_configure", CommandContext.EP_CONFIGURE),
        ("ep_build", CommandContext.EP_BUILD),
        ("ep_install", CommandContext.EP_INSTALL),
        ("ep_download", CommandContext.EP_DOWNLOAD),
        ("ep_update", CommandContext.EP_UPDATE),
        ("patch_command", CommandContext.PATCH_COMMAND),
    ],
)
def test_command_context_mapping_table(ctx_str, expected_enum):
    inv = ProgramInvocation(name="x", command_context=ctx_str)
    et = program_to_environment_tool(
        inv, source_revision=None, source_authority=None, root_artifact_id=None
    )
    assert et.command_context == expected_enum


def test_ep_command_fields_become_program_invocations(tmp_path):
    """patch/$(MAKE)/cp in EP command fields map to the right CommandContext."""
    src = _write(
        tmp_path,
        "ep.cmake",
        """
        ExternalProject_Add(foo
            URL https://x/foo-1.0.tar.gz
            PATCH_COMMAND patch -p1 < foo.patch
            BUILD_COMMAND $(MAKE)
            INSTALL_COMMAND ${CMAKE_COMMAND} -E make_directory d
                COMMAND cp src dst
        )
        """,
    )
    cf = parse_file(src)
    ctx_by_name = {p.name: p.command_context for p in cf.programs}
    assert ctx_by_name.get("patch") == "patch_command"
    assert ctx_by_name.get("$(MAKE)") == "ep_build"
    # the install command has two sub-commands: cmake -E ... && cp ...
    install_progs = [p for p in cf.programs if p.command_context == "ep_install"]
    install_names = {p.name for p in install_progs}
    assert "cmake" in install_names
    assert "cp" in install_names


# ===========================================================================
# discover_roots
# ===========================================================================


def test_discover_roots(tmp_path):
    # a real standalone root
    _write(
        tmp_path / "examples/fast_kernel",
        "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(AscendOps VERSION 1.0.0)\n",
    )
    # a fragment dir: project() but no minimum_required -> not a root
    _write(
        tmp_path / "frag",
        "CMakeLists.txt",
        "project(frag)\n",
    )
    # another standalone root
    _write(
        tmp_path / "experimental/math/sort",
        "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.14)\nproject(sort_test)\n",
    )
    roots = {p.name for p in discover_roots(tmp_path)}
    assert "fast_kernel" in roots
    assert "sort" in roots
    assert "frag" not in roots


def test_project_name_and_version(tmp_path):
    src = _write(
        tmp_path,
        "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.16)\nproject(math VERSION 1.0.0)\n",
    )
    cf = parse_file(src)
    assert cf.project_name == "math"
    assert cf.project_version == "1.0.0"
    assert cf.cmake_minimum_required == "3.16"


# ===========================================================================
# resolve_cmake_authority — all FOUR outcomes + ambiguity
# ===========================================================================


def _auth(repo_root, cmake_root=None, **kw):
    base = dict(
        cmake_source_authority="actual-build",
        cmake_defines={},
        profile_values={},
        allow_input_fallback=False,
        resolve_cmake_ref=False,
        network="off",
    )
    base.update(kw)
    return resolve_cmake_authority(repo_root, cmake_root, **base)


def test_authority_skipped_existing_project(tmp_path):
    auth, warns = _auth(
        tmp_path,
        cmake_root=tmp_path / "cmake",
        profile_values={"project_source_dir_predefined": "true"},
    )
    assert auth.branch == CmakeAuthorityBranch.SKIPPED_EXISTING_PROJECT
    # no cann-cmake acquisition; effective root is the passed cmake_root
    assert auth.effective_cmake_root == tmp_path / "cmake"


def test_authority_git_branch_default_unset(tmp_path):
    cmake_root = tmp_path / "cmake"
    cmake_root.mkdir()
    auth, warns = _auth(tmp_path, cmake_root=cmake_root)
    assert auth.branch == CmakeAuthorityBranch.GIT
    assert auth.ref == "master-016"
    assert auth.authority_inputs["cann_3rd_lib_path"]["source"] == "unset"


def test_authority_local_dir_branch_via_cmake_define(tmp_path):
    lib = tmp_path / "3rd"
    (lib / "cann-cmake").mkdir(parents=True)
    auth, warns = _auth(
        tmp_path,
        cmake_root=tmp_path / "cmake",
        cmake_defines={"CANN_3RD_LIB_PATH": str(lib)},
    )
    assert auth.branch == CmakeAuthorityBranch.LOCAL_DIR
    assert auth.effective_cmake_root == lib / "cann-cmake"
    # version NOASSERTION posture -> local override warning, ref not assumed
    assert auth.ref is None
    codes = {w.code for w in warns}
    assert "cann_cmake_local_override" in codes


def test_authority_tarball_branch_via_cmake_define(tmp_path):
    lib = tmp_path / "3rd"
    lib.mkdir()
    (lib / "cmake-master-016.tar.gz").write_bytes(b"tarball")
    auth, warns = _auth(
        tmp_path,
        cmake_root=tmp_path / "cmake",
        cmake_defines={"CANN_3RD_LIB_PATH": str(lib)},
    )
    assert auth.branch == CmakeAuthorityBranch.TARBALL
    assert auth.ref == "master-016"
    assert auth.verified is True


def test_authority_bare_cache_is_ambiguous(tmp_path):
    (tmp_path / "CMakeCache.txt").write_text(
        "CANN_3RD_LIB_PATH:STRING=/some/cache/path\n"
    )
    auth, warns = _auth(tmp_path, cmake_root=tmp_path / "cmake")
    # ambiguous bare cache -> Git branch assumed + warning
    assert auth.branch == CmakeAuthorityBranch.GIT
    assert auth.authority_inputs["cann_3rd_lib_path"]["source"] == "cache"
    assert "cmake_authority_input_ambiguous" in {w.code for w in warns}


def test_authority_cmake_as_input_excludes_cann_cmake(tmp_path):
    from sbom_profile_cann import CannProfile

    cmake_root = tmp_path / "cmake"
    cmake_root.mkdir()
    auth, warns = _auth(
        tmp_path,
        cmake_root=cmake_root,
        cmake_source_authority="cmake-as-input",
    )
    assert auth.effective_cmake_root == cmake_root
    # The resolver sets the trusted_input marker the profile's build_tooling gates
    # the cann-cmake EXCLUSION on (previously unset, so the component still leaked).
    assert auth.authority_inputs.get("trusted_input") is True
    # End-to-end: build_tooling now actually EXCLUDES the component (not just warns).
    components, tooling_warns = CannProfile().build_tooling(tmp_path, auth)
    assert components == []
    assert "cann_cmake_trusted_input" in {w.code for w in tooling_warns}


def test_authority_resolve_cmake_ref_resolves_commit(tmp_path, monkeypatch):
    # --resolve-cmake-ref resolves the pinned ref to a commit via git ls-remote
    # (mocked); the authority becomes PINNED (revision + verified), no warning.
    monkeypatch.setattr(parse, "_ls_remote_sha", lambda url, ref: "a" * 40)
    cmake_root = tmp_path / "cmake"
    cmake_root.mkdir()
    auth, warns = _auth(
        tmp_path, cmake_root=cmake_root, resolve_cmake_ref=True, network="on"
    )
    codes = {w.code for w in warns}
    assert auth.revision == "a" * 40
    assert auth.verified is True
    assert "cmake_ref_resolution_failed" not in codes
    assert "cmake_acquisition_metadata_unresolved" not in codes


def test_authority_resolve_cmake_ref_failure_degrades_unpinned(tmp_path, monkeypatch):
    # ls-remote fails (offline / git absent / ref gone) -> unpinned + a clear warning.
    monkeypatch.setattr(parse, "_ls_remote_sha", lambda url, ref: None)
    cmake_root = tmp_path / "cmake"
    cmake_root.mkdir()
    auth, warns = _auth(
        tmp_path, cmake_root=cmake_root, resolve_cmake_ref=True, network="on"
    )
    assert auth.revision is None
    assert "cmake_ref_resolution_failed" in {w.code for w in warns}


def test_ls_remote_sha_parses_first_field(monkeypatch):
    # The helper takes the first 40-hex field of `git ls-remote` output, else None.
    import subprocess as _sp

    class _R:
        def __init__(self, out):
            self.stdout = out

    monkeypatch.setattr(parse.subprocess, "run", lambda *a, **k: _R(b"deadbeef" * 5 + b"\trefs/heads/master-016\n"))
    assert parse._ls_remote_sha("u", "r") == "deadbeef" * 5

    def _boom(*a, **k):
        raise _sp.TimeoutExpired(cmd="git", timeout=1)

    monkeypatch.setattr(parse.subprocess, "run", _boom)
    assert parse._ls_remote_sha("u", "r") is None


def test_authority_tag_mismatch_warns(tmp_path):
    cmake_root = tmp_path / "cmake"
    cmake_root.mkdir()
    (cmake_root / "CMAKE_REF").write_text("master-029-deadbeef\n")
    auth, warns = _auth(tmp_path, cmake_root=cmake_root)
    assert "cann_cmake_tag_mismatch" in {w.code for w in warns}


def test_authority_explicit_define_outranks_cache(tmp_path):
    lib = tmp_path / "3rd"
    (lib / "cann-cmake").mkdir(parents=True)
    (tmp_path / "CMakeCache.txt").write_text(
        "CANN_3RD_LIB_PATH:STRING=/other/path\n"
    )
    auth, warns = _auth(
        tmp_path,
        cmake_root=tmp_path / "cmake",
        cmake_defines={"CANN_3RD_LIB_PATH": str(lib)},
    )
    # cli source wins -> local_dir branch (not the ambiguous cache)
    assert auth.branch == CmakeAuthorityBranch.LOCAL_DIR
    assert auth.authority_inputs["cann_3rd_lib_path"]["source"] == "cli"


# ===========================================================================
# Robustness: malformed input never raises
# ===========================================================================


def test_malformed_cmake_does_not_raise(tmp_path):
    src = _write(
        tmp_path,
        "broken.cmake",
        "ExternalProject_Add(foo URL\nfind_package(\n# unterminated",
    )
    cf = parse_file(src)  # must not raise
    assert isinstance(cf, CMakeFile)


def test_missing_file_returns_empty(tmp_path):
    cf = parse_file(tmp_path / "does-not-exist.cmake")
    assert cf.external_projects == []
    assert cf.includes == []


# ===========================================================================
# (e) opbase local-source-unverified pattern detection
# ===========================================================================


def test_opbase_local_source_unverified_detected(tmp_path):
    """Mirror opbase.cmake: local source dir guarded only by if(EXISTS ...) with
    the pinned tag applied only in the sibling cache/FetchContent branches."""
    src = _write(
        tmp_path,
        "opbase.cmake",
        """
        set(OPBASE_TAG_ID b92c2c8f3d999f315b0251cfb25edb111bb898d5)
        if(EXISTS "${PROJECT_SOURCE_DIR}/../../ops-base")
          get_filename_component(OPBASE_SOURCE_PATH
                                 ${PROJECT_SOURCE_DIR}/../../ops-base REALPATH)
        elseif(EXISTS "${CANN_3RD_LIB_PATH}/opbase")
          get_filename_component(OPBASE_SOURCE_PATH
                                 ${CANN_3RD_LIB_PATH}/opbase REALPATH)
          execute_process(COMMAND git checkout ${OPBASE_TAG_ID})
        else()
          include(FetchContent)
          FetchContent_Declare(
            opbase
            GIT_REPOSITORY https://gitcode.example.com/cann/opbase.git
            GIT_TAG ${OPBASE_TAG_ID}
            SOURCE_DIR ${CANN_3RD_LIB_PATH}/opbase)
        endif()
        """,
    )
    cf = parse_file(src)
    assert "opbase" in cf.integrity_findings
    assert IntegrityFinding.LOCAL_SOURCE_UNVERIFIED in cf.integrity_findings["opbase"]


def test_no_local_source_finding_when_all_branches_pin(tmp_path):
    """When every branch checks out the pinned tag, no finding is raised."""
    src = _write(
        tmp_path,
        "ok.cmake",
        """
        set(TAG abc123)
        if(EXISTS "${SRC}/foo")
          get_filename_component(SOURCE_PATH ${SRC}/foo REALPATH)
          execute_process(COMMAND git checkout ${TAG})
        else()
          FetchContent_Declare(foo GIT_TAG ${TAG})
        endif()
        """,
    )
    cf = parse_file(src)
    assert cf.integrity_findings == {}


# ===========================================================================
# (d) parse_recursive call-site context: included_by + call_site_conditions
# ===========================================================================


def test_include_chain_propagates_call_site_conditions(tmp_path):
    """A gated include() records the gate as the child's call_site_conditions
    and the including file as included_by."""
    root = tmp_path / "cmake"
    _write(root, "third_party/gtest.cmake", "# gtest leaf\n")
    _write(
        root,
        "ut.cmake",
        """
        if(ENABLE_TEST)
          include(${CMAKE_CURRENT_LIST_DIR}/third_party/gtest.cmake)
        endif()
        """,
    )
    entry = _write(root, "entry.cmake", "include(${CMAKE_CURRENT_LIST_DIR}/ut.cmake)\n")
    files = parse_recursive(entry, root)
    gtest = next(f for f in files if f.path.name == "gtest.cmake")
    assert gtest.included_by is not None and gtest.included_by.name == "ut.cmake"
    exprs = {c.expr for c in gtest.call_site_conditions}
    assert any("ENABLE_TEST" in e for e in exprs)


def test_macro_gate_propagates_to_fragment(tmp_path):
    """A custom-macro resolver exposing activation_condition propagates the
    macro gate onto the expanded fragment's call_site_conditions, and the
    including file becomes included_by (gtest two-axis, parser side)."""
    root = tmp_path / "cmake"
    _write(root, "third_party/gtest.cmake", "# gtest\n")
    _write(root, "ut.cmake", "add_cann_third_party(gtest)\n")
    entry = _write(root, "entry.cmake", "include(${CMAKE_CURRENT_LIST_DIR}/ut.cmake)\n")

    class _Resolver:
        activation_condition = "TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD"

        def __call__(self, args, eff_root):
            return [eff_root / "third_party" / f"{args[0]}.cmake"]

    files = parse_recursive(
        entry, root, custom_macros={"add_cann_third_party": _Resolver()}
    )
    gtest = next(f for f in files if f.path.name == "gtest.cmake")
    assert gtest.included_by is not None and gtest.included_by.name == "ut.cmake"
    exprs = {c.expr for c in gtest.call_site_conditions}
    assert "TOPLEVEL_PROJECT OR ENABLE_UNIFIED_BUILD" in exprs
