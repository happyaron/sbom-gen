"""Unit tests for sbom.cmake.trace — configure-trace acquisition metadata.

All tests run offline.  We feed synthetic trace logs (JSON-v1 and text format)
directly to the internal parsers and reconstruct CMakeFile records without
invoking cmake.
"""

from __future__ import annotations

import json

import pytest

from sbom.cmake.parse import (
    CMakeFile,
    ExternalProject,
    FetchContentDecl,
    FindPackageCall,
)
from sbom.cmake.trace import (
    TraceResult,
    _parse_json_trace,
    _parse_text_trace,
    _reconstruct_files,
    _split_cmake_args,
)


# ---------------------------------------------------------------------------
# Helper: build JSON-v1 trace event dicts
# ---------------------------------------------------------------------------


def _ep_event(
    src_file: str,
    name: str,
    *,
    url: str | None = None,
    url_hash: str | None = None,
    git_repo: str | None = None,
    git_tag: str | None = None,
    tls_verify: str | None = None,
    depends: list[str] | None = None,
) -> dict:
    args = [name]
    if url:
        args += ["URL", url]
    if url_hash:
        args += ["URL_HASH", url_hash]
    if git_repo:
        args += ["GIT_REPOSITORY", git_repo]
    if git_tag:
        args += ["GIT_TAG", git_tag]
    if tls_verify is not None:
        args += ["TLS_VERIFY", tls_verify]
    if depends:
        args += ["DEPENDS"] + depends
    return {"file": src_file, "line": 10, "cmd": "externalproject_add", "args": args}


def _fc_event(
    src_file: str,
    name: str,
    *,
    url: str | None = None,
    git_repo: str | None = None,
    git_tag: str | None = None,
) -> dict:
    args = [name]
    if url:
        args += ["URL", url]
    if git_repo:
        args += ["GIT_REPOSITORY", git_repo]
    if git_tag:
        args += ["GIT_TAG", git_tag]
    return {"file": src_file, "line": 20, "cmd": "fetchcontent_declare", "args": args}


def _fp_event(
    src_file: str, name: str, *, required: bool = False, quiet: bool = False
) -> dict:
    args = [name]
    if required:
        args.append("REQUIRED")
    if quiet:
        args.append("QUIET")
    return {"file": src_file, "line": 30, "cmd": "find_package", "args": args}


def _include_event(src_file: str, include_path: str) -> dict:
    return {"file": src_file, "line": 5, "cmd": "include", "args": [include_path]}


# ---------------------------------------------------------------------------
# Tests: _split_cmake_args
# ---------------------------------------------------------------------------


class TestSplitCmakeArgs:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("", []),
            ("foo", ["foo"]),
            ("foo bar baz", ["foo", "bar", "baz"]),
            ('"hello world" next', ["hello world", "next"]),
            ("  a  b  c  ", ["a", "b", "c"]),
            ('a "b c" d', ["a", "b c", "d"]),
        ],
    )
    def test_split(self, raw, expected):
        assert _split_cmake_args(raw) == expected


# ---------------------------------------------------------------------------
# Tests: _parse_json_trace
# ---------------------------------------------------------------------------


class TestParseJsonTrace:
    def test_empty_input(self):
        assert _parse_json_trace("") == []

    def test_single_valid_line(self):
        ev = {"file": "/path/CMakeLists.txt", "line": 1, "cmd": "project", "args": ["myproj"]}
        result = _parse_json_trace(json.dumps(ev))
        assert result == [ev]

    def test_multiple_lines(self):
        ev1 = {"file": "/f.cmake", "line": 1, "cmd": "foo", "args": []}
        ev2 = {"file": "/f.cmake", "line": 2, "cmd": "bar", "args": ["x"]}
        text = json.dumps(ev1) + "\n" + json.dumps(ev2) + "\n"
        result = _parse_json_trace(text)
        assert result == [ev1, ev2]

    def test_non_json_lines_skipped(self):
        good = json.dumps({"file": "/f.cmake", "line": 1, "cmd": "x", "args": []})
        text = "NOT JSON\n" + good + "\n-- more garbage\n"
        result = _parse_json_trace(text)
        assert len(result) == 1
        assert result[0]["cmd"] == "x"

    def test_blank_lines_ignored(self):
        ev = {"file": "/f.cmake", "line": 1, "cmd": "y", "args": []}
        text = "\n\n" + json.dumps(ev) + "\n\n"
        result = _parse_json_trace(text)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Tests: _parse_text_trace
# ---------------------------------------------------------------------------


class TestParseTextTrace:
    def test_empty_input(self):
        assert _parse_text_trace("") == []

    def test_basic_line(self):
        line = "/path/to/CMakeLists.txt(42):  project(MyProj)"
        result = _parse_text_trace(line)
        assert len(result) == 1
        ev = result[0]
        assert ev["file"] == "/path/to/CMakeLists.txt"
        assert ev["line"] == 42
        assert ev["cmd"] == "project"
        assert "MyProj" in ev["args"]

    def test_non_matching_lines_skipped(self):
        text = "-- some cmake output\n/f.cmake(1):  include(foo.cmake)\n"
        result = _parse_text_trace(text)
        assert len(result) == 1
        assert result[0]["cmd"] == "include"

    def test_command_lowercased(self):
        line = "/f.cmake(1):  ExternalProject_Add(mylib URL http://example.com)"
        result = _parse_text_trace(line)
        assert result[0]["cmd"] == "externalproject_add"


# ---------------------------------------------------------------------------
# Tests: _reconstruct_files — ExternalProject_Add
# ---------------------------------------------------------------------------


class TestReconstructExternalProject:
    def test_url_only(self):
        events = [_ep_event("/ep.cmake", "mylib", url="https://example.com/mylib.tar.gz")]
        files = _reconstruct_files(events)
        assert len(files) == 1
        f = files[0]
        assert len(f.external_projects) == 1
        ep = f.external_projects[0]
        assert ep.name == "mylib"
        assert ep.canonical_url == "https://example.com/mylib.tar.gz"
        assert ep.url_hash is None
        assert ep.tls_verify is None

    def test_url_hash_parsed(self):
        events = [
            _ep_event(
                "/ep.cmake",
                "mylib",
                url="https://example.com/mylib.tar.gz",
                url_hash="SHA256=deadbeef1234",
            )
        ]
        files = _reconstruct_files(events)
        ep = files[0].external_projects[0]
        assert ep.url_hash == "deadbeef1234"

    def test_tls_verify_off(self):
        events = [
            _ep_event(
                "/ep.cmake",
                "protobuf",
                url="https://example.com/proto.tar.gz",
                tls_verify="OFF",
            )
        ]
        files = _reconstruct_files(events)
        ep = files[0].external_projects[0]
        assert ep.tls_verify is False

    def test_tls_verify_on(self):
        events = [_ep_event("/ep.cmake", "ssl", url="https://x.com/s.tgz", tls_verify="ON")]
        ep = _reconstruct_files(events)[0].external_projects[0]
        assert ep.tls_verify is True

    def test_git_fields(self):
        events = [
            _ep_event(
                "/git.cmake",
                "abseil",
                git_repo="https://github.com/abseil/abseil-cpp.git",
                git_tag="20230802.1",
            )
        ]
        files = _reconstruct_files(events)
        ep = files[0].external_projects[0]
        assert ep.git_repository == "https://github.com/abseil/abseil-cpp.git"
        assert ep.git_tag == "20230802.1"
        assert ep.vcs_ref is not None
        assert ep.vcs_ref.requested == "20230802.1"

    def test_depends_captured(self):
        events = [
            _ep_event(
                "/proto.cmake",
                "protobuf",
                url="https://x.com/p.tgz",
                depends=["abseil_build"],
            )
        ]
        ep = _reconstruct_files(events)[0].external_projects[0]
        assert "abseil_build" in ep.depends

    def test_multiple_eps_same_file(self):
        events = [
            _ep_event("/third.cmake", "liba", url="https://a.com/a.tgz"),
            _ep_event("/third.cmake", "libb", url="https://b.com/b.tgz"),
        ]
        files = _reconstruct_files(events)
        assert len(files) == 1
        assert len(files[0].external_projects) == 2

    def test_eps_different_files(self):
        events = [
            _ep_event("/a.cmake", "liba", url="https://a.com/a.tgz"),
            _ep_event("/b.cmake", "libb", url="https://b.com/b.tgz"),
        ]
        files = _reconstruct_files(events)
        assert len(files) == 2
        paths = {str(f.path) for f in files}
        assert "/a.cmake" in paths
        assert "/b.cmake" in paths


# ---------------------------------------------------------------------------
# Tests: _reconstruct_files — FetchContent_Declare
# ---------------------------------------------------------------------------


class TestReconstructFetchContent:
    def test_url(self):
        events = [_fc_event("/fc.cmake", "googletest", url="https://github.com/g/g.tgz")]
        fc = _reconstruct_files(events)[0].fetch_contents[0]
        assert fc.name == "googletest"
        assert fc.canonical_url == "https://github.com/g/g.tgz"

    def test_git(self):
        events = [
            _fc_event(
                "/fc.cmake",
                "eigen",
                git_repo="https://gitlab.com/libeigen/eigen.git",
                git_tag="3.4.0",
            )
        ]
        fc = _reconstruct_files(events)[0].fetch_contents[0]
        assert fc.git_repository == "https://gitlab.com/libeigen/eigen.git"
        assert fc.git_tag == "3.4.0"
        assert fc.vcs_ref is not None
        assert fc.vcs_ref.requested == "3.4.0"


# ---------------------------------------------------------------------------
# Tests: _reconstruct_files — find_package
# ---------------------------------------------------------------------------


class TestReconstructFindPackage:
    def test_required(self):
        events = [_fp_event("/deps.cmake", "Eigen3", required=True)]
        fp = _reconstruct_files(events)[0].find_packages[0]
        assert fp.name == "Eigen3"
        assert fp.info.required is True
        assert fp.info.quiet is False

    def test_quiet(self):
        events = [_fp_event("/deps.cmake", "Boost", quiet=True)]
        fp = _reconstruct_files(events)[0].find_packages[0]
        assert fp.info.quiet is True
        assert fp.info.required is False

    def test_neither(self):
        events = [_fp_event("/deps.cmake", "ZLIB")]
        fp = _reconstruct_files(events)[0].find_packages[0]
        assert fp.info.required is False
        assert fp.info.quiet is False


# ---------------------------------------------------------------------------
# Tests: _reconstruct_files — include()
# ---------------------------------------------------------------------------


class TestReconstructInclude:
    def test_include_captured(self):
        events = [_include_event("/CMakeLists.txt", "cmake/third_party/eigen.cmake")]
        f = _reconstruct_files(events)[0]
        assert len(f.includes) == 1
        assert f.includes[0].path == "cmake/third_party/eigen.cmake"


# ---------------------------------------------------------------------------
# Tests: _reconstruct_files — project()
# ---------------------------------------------------------------------------


class TestReconstructProject:
    def test_project_name(self):
        events = [
            {"file": "/CMakeLists.txt", "line": 3, "cmd": "project",
             "args": ["MyProject", "VERSION", "2.1.0", "LANGUAGES", "CXX"]}
        ]
        f = _reconstruct_files(events)[0]
        assert f.project_name == "MyProject"
        assert f.project_version == "2.1.0"


# ---------------------------------------------------------------------------
# Tests: TraceResult dataclass
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Tests: integration — JSON-v1 round-trip via full pipeline
# ---------------------------------------------------------------------------


class TestJsonV1RoundTrip:
    """Feed JSON-v1 formatted events through the full parse pipeline."""

    def _make_json_trace(self, events: list[dict]) -> str:
        return "\n".join(json.dumps(ev) for ev in events) + "\n"

    def test_ep_via_json_trace(self):
        events = [
            _ep_event(
                "/cmake/third_party/protobuf.cmake",
                "protobuf",
                url="https://github.com/protocolbuffers/protobuf/archive/v25.1.tar.gz",
                url_hash="SHA256=9bd87b8280ef720d3240514f884e56a712f2218f0d693b48050c836028940a42",
                tls_verify="OFF",
                depends=["abseil_build"],
            )
        ]
        trace_text = self._make_json_trace(events)
        parsed_events = _parse_json_trace(trace_text)
        files = _reconstruct_files(parsed_events)

        assert len(files) == 1
        ep = files[0].external_projects[0]
        assert ep.name == "protobuf"
        assert "protobuf" in ep.canonical_url
        assert ep.url_hash == "9bd87b8280ef720d3240514f884e56a712f2218f0d693b48050c836028940a42"
        assert ep.tls_verify is False
        assert ep.depends == ["abseil_build"]

    def test_mixed_commands_multiple_files(self):
        events = [
            _ep_event("/ep.cmake", "eigen", url="https://example.com/eigen.tgz"),
            _fc_event("/fc.cmake", "googletest", git_repo="https://github.com/g/gt.git", git_tag="v1.14"),
            _fp_event("/deps.cmake", "OpenSSL", required=True),
        ]
        trace_text = self._make_json_trace(events)
        parsed_events = _parse_json_trace(trace_text)
        files = _reconstruct_files(parsed_events)

        # Three different source files
        paths = {str(f.path) for f in files}
        assert "/ep.cmake" in paths
        assert "/fc.cmake" in paths
        assert "/deps.cmake" in paths

        ep_file = next(f for f in files if "/ep.cmake" in str(f.path))
        assert ep_file.external_projects[0].name == "eigen"

        fc_file = next(f for f in files if "/fc.cmake" in str(f.path))
        assert fc_file.fetch_contents[0].name == "googletest"

        dep_file = next(f for f in files if "/deps.cmake" in str(f.path))
        assert dep_file.find_packages[0].name == "OpenSSL"
        assert dep_file.find_packages[0].info.required is True


# ---------------------------------------------------------------------------
# Tests: integration — text trace round-trip
# ---------------------------------------------------------------------------


class TestTextTraceRoundTrip:
    """Feed --trace-expand text-format lines through the full parse pipeline."""

    def _make_text_trace(self, lines: list[str]) -> str:
        return "\n".join(lines) + "\n"

    def test_ep_via_text_trace(self):
        lines = [
            "/cmake/ep.cmake(10):  ExternalProject_Add(abseil-cpp URL https://example.com/abseil.tgz GIT_TAG 20230802.1)"
        ]
        trace_text = self._make_text_trace(lines)
        events = _parse_text_trace(trace_text)
        files = _reconstruct_files(events)

        assert len(files) == 1
        ep = files[0].external_projects[0]
        assert ep.name == "abseil-cpp"
        assert ep.canonical_url == "https://example.com/abseil.tgz"
        assert ep.git_tag == "20230802.1"

    def test_find_package_via_text_trace(self):
        lines = [
            "/cmake/deps.cmake(30):  find_package(OPBASE REQUIRED)"
        ]
        trace_text = self._make_text_trace(lines)
        events = _parse_text_trace(trace_text)
        files = _reconstruct_files(events)

        assert len(files) == 1
        fp = files[0].find_packages[0]
        assert fp.name == "OPBASE"
        assert fp.info.required is True

    def test_include_via_text_trace(self):
        lines = [
            "/CMakeLists.txt(5):  include(cmake/third_party/eigen.cmake)"
        ]
        events = _parse_text_trace(lines[0])
        files = _reconstruct_files(events)
        assert files[0].includes[0].path == "cmake/third_party/eigen.cmake"
