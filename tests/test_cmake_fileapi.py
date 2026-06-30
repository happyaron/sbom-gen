"""Unit tests for sbom.cmake.fileapi — CMake File API reader.

All tests are fully offline.  We synthesize minimal File API reply directory
trees in tmp_path and feed them directly to read_reply().  No cmake binary is
invoked.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbom.cmake.fileapi import (
    FileApiGraph,
    FileApiTarget,
    read_reply,
)


# ---------------------------------------------------------------------------
# Helpers to build synthetic File API reply trees
# ---------------------------------------------------------------------------


def _write_reply(
    tmp_path: Path,
    *,
    targets: list[dict] | None = None,
    configurations: list[dict] | None = None,
) -> Path:
    """Write a minimal CMake File API reply tree and return the reply dir."""
    reply_dir = tmp_path / ".cmake" / "api" / "v1" / "reply"
    reply_dir.mkdir(parents=True)

    # Build target JSON files and collect their relative names
    target_files: list[dict] = []
    for i, t in enumerate(targets or []):
        fname = f"target-{t['name']}-{i}.json"
        (reply_dir / fname).write_text(json.dumps(t), encoding="utf-8")
        target_files.append(
            {
                "name": t["name"],
                "id": f"{t['name']}::{i}",
                "directoryIndex": 0,
                "projectIndex": 0,
                "jsonFile": fname,
            }
        )

    # Default: one configuration named "Release"
    config_section = configurations or [
        {
            "name": "Release",
            "targets": target_files,
            "directories": [{"source": ".", "build": ".", "project": 0}],
            "projects": [{"name": "TestProject", "parentIndex": -1, "childIndexes": [], "directoryIndexes": [0], "targetIndexes": list(range(len(target_files)))}],
        }
    ]

    codemodel_name = "codemodel-v2-abcdef.json"
    codemodel_data = {
        "kind": "codemodel",
        "version": {"major": 2, "minor": 6},
        "paths": {"source": str(tmp_path), "build": str(tmp_path / "build"), "cmake": ""},
        "configurations": config_section,
    }
    (reply_dir / codemodel_name).write_text(
        json.dumps(codemodel_data), encoding="utf-8"
    )

    index_data = {
        "cmake": {"version": {"major": 3, "minor": 28}},
        "objects": [{"kind": "codemodel", "version": {"major": 2}, "jsonFile": codemodel_name}],
        "reply": {
            "client-sbomgen": {
                "codemodel-v2": {
                    "kind": "codemodel",
                    "version": {"major": 2},
                    "jsonFile": codemodel_name,
                }
            }
        },
    }
    (reply_dir / "index-2024-01-01.json").write_text(
        json.dumps(index_data), encoding="utf-8"
    )

    return reply_dir


# ---------------------------------------------------------------------------
# Table-driven test cases
# ---------------------------------------------------------------------------


class TestReadReplyMissingDir:
    def test_absent_reply_dir_returns_empty_graph_and_warning(self, tmp_path):
        graph, warnings = read_reply(tmp_path / "nonexistent")
        assert isinstance(graph, FileApiGraph)
        assert graph.targets == []
        assert len(warnings) == 1
        assert warnings[0].code == "fileapi_reply_missing"

    def test_reply_dir_exists_but_no_index(self, tmp_path):
        reply_dir = tmp_path / "reply"
        reply_dir.mkdir()
        graph, warnings = read_reply(reply_dir)
        assert graph.targets == []
        assert any(w.code == "fileapi_reply_missing" for w in warnings)


class TestReadReplyBasicTargets:
    """Verify that read_reply extracts targets correctly from a synthetic reply."""

    @pytest.mark.parametrize(
        "target_data, expected_name, expected_type, expected_imported",
        [
            (
                {"name": "mylib", "type": "STATIC_LIBRARY", "isImported": False,
                 "link": {"commandFragments": [{"role": "libraries", "fragment": "-lm"}]}},
                "mylib", "STATIC_LIBRARY", False,
            ),
            (
                {"name": "myexe", "type": "EXECUTABLE", "isImported": False,
                 "link": {"commandFragments": [{"role": "flags", "fragment": "-O2"}]}},
                "myexe", "EXECUTABLE", False,
            ),
            (
                {"name": "imported_lib", "type": "SHARED_LIBRARY", "isImported": True,
                 "link": {}},
                "imported_lib", "SHARED_LIBRARY", True,
            ),
        ],
    )
    def test_target_fields(
        self, tmp_path, target_data, expected_name, expected_type, expected_imported
    ):
        reply_dir = _write_reply(tmp_path, targets=[target_data])
        graph, warnings = read_reply(reply_dir)

        assert warnings == [], f"Unexpected warnings: {warnings}"
        assert len(graph.targets) == 1
        t = graph.targets[0]
        assert t.name == expected_name
        assert t.type == expected_type
        assert t.imported is expected_imported

    def test_link_libraries_extracted(self, tmp_path):
        target_data = {
            "name": "myapp",
            "type": "EXECUTABLE",
            "isImported": False,
            "link": {
                "commandFragments": [
                    {"role": "libraries", "fragment": "libfoo.so"},
                    {"role": "libraries", "fragment": "libbar.a"},
                    {"role": "flags", "fragment": "-Wl,--as-needed"},
                ]
            },
        }
        reply_dir = _write_reply(tmp_path, targets=[target_data])
        graph, warnings = read_reply(reply_dir)

        assert warnings == []
        assert len(graph.targets) == 1
        t = graph.targets[0]
        assert "libfoo.so" in t.link_libraries
        assert "libbar.a" in t.link_libraries
        # Flag fragments should NOT be in link_libraries
        assert "-Wl,--as-needed" not in t.link_libraries

    def test_multiple_targets(self, tmp_path):
        targets = [
            {"name": "liba", "type": "STATIC_LIBRARY", "link": {}},
            {"name": "libb", "type": "SHARED_LIBRARY", "link": {}},
            {"name": "app", "type": "EXECUTABLE", "link": {}},
        ]
        reply_dir = _write_reply(tmp_path, targets=targets)
        graph, warnings = read_reply(reply_dir)

        assert warnings == []
        assert len(graph.targets) == 3
        names = {t.name for t in graph.targets}
        assert names == {"liba", "libb", "app"}

    def test_empty_targets_returns_empty_graph(self, tmp_path):
        reply_dir = _write_reply(tmp_path, targets=[])
        graph, warnings = read_reply(reply_dir)

        assert warnings == []
        assert graph.targets == []


class TestReadReplyMalformed:
    def test_malformed_index_returns_warning(self, tmp_path):
        reply_dir = tmp_path / "reply"
        reply_dir.mkdir()
        (reply_dir / "index-2024-01-01.json").write_text(
            "NOT JSON{{{", encoding="utf-8"
        )
        graph, warnings = read_reply(reply_dir)
        assert graph.targets == []
        assert any(w.code in ("fileapi_parse_error", "fileapi_reply_missing") for w in warnings)

    def test_missing_codemodel_in_index_returns_warning(self, tmp_path):
        reply_dir = tmp_path / "reply"
        reply_dir.mkdir()
        # Index with no reply section
        index_data = {"cmake": {}, "reply": {}, "objects": []}
        (reply_dir / "index-2024-01-01.json").write_text(
            json.dumps(index_data), encoding="utf-8"
        )
        graph, warnings = read_reply(reply_dir)
        assert graph.targets == []
        assert any(w.code == "fileapi_no_codemodel" for w in warnings)

    def test_target_file_missing_is_skipped(self, tmp_path):
        """A target entry whose jsonFile does not exist should be skipped gracefully."""
        reply_dir = tmp_path / ".cmake" / "api" / "v1" / "reply"
        reply_dir.mkdir(parents=True)

        codemodel_data = {
            "kind": "codemodel",
            "version": {"major": 2, "minor": 6},
            "paths": {},
            "configurations": [
                {
                    "name": "Release",
                    "targets": [
                        {"name": "ghost", "id": "ghost::0", "jsonFile": "ghost-MISSING.json"},
                    ],
                    "directories": [],
                    "projects": [],
                }
            ],
        }
        codemodel_name = "codemodel-v2.json"
        (reply_dir / codemodel_name).write_text(json.dumps(codemodel_data), encoding="utf-8")
        index_data = {
            "cmake": {},
            "reply": {"x": {"kind": "codemodel", "version": {"major": 2}, "jsonFile": codemodel_name}},
            "objects": [],
        }
        (reply_dir / "index-2024.json").write_text(json.dumps(index_data), encoding="utf-8")

        graph, warnings = read_reply(reply_dir)
        # Should return empty targets but no hard crash
        assert graph.targets == []
        assert isinstance(warnings, list)


class TestFileApiTargetDataclass:
    def test_defaults(self):
        t = FileApiTarget(name="foo", type="EXECUTABLE")
        assert t.link_libraries == []
        assert t.imported is False


class TestFileApiGraphDataclass:
    def test_defaults(self):
        g = FileApiGraph()
        assert g.targets == []
        assert g.install_relationships == []

