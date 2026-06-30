"""Unit tests for sbom.enrich.{known_licenses, cache_scan, net, licenseref}.

All tests are offline (no live network calls).  The net module's HTTP layer
is injected via ``net.set_http_get()`` so unit tests run fully mocked.
Table-driven patterns are used throughout.
"""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path
from dataclasses import dataclass, field

import pytest

from sbom.models import Component, Observation, SourceKind, UsageScope
from sbom.enrich import known_licenses, cache_scan, net, licenseref


# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------


@dataclass
class _Config:
    """Minimal stub for sbom.config.Config (only the fields enrich modules use)."""

    network: str = "off"
    cmake_defines: dict[str, str] = field(default_factory=dict)


def _comp(
    name: str,
    aliases: list[str] | None = None,
    license_: str | None = None,
    python: bool = False,
) -> Component:
    c = Component(name=name, aliases=aliases or [])
    c.license = license_
    if python:
        c.languages.append("Python")
    return c


# ===========================================================================
# known_licenses
# ===========================================================================


# The shipped core known-license map is now EMPTY (content lives in the active
# profile). Enricher unit tests use this explicit map instead of bundled content.
_FIXTURE_MAP = {
    "eigen": "MPL-2.0 AND BSD-3-Clause",
    "googletest": "BSD-3-Clause",
    "gtest": "BSD-3-Clause",
    "protobuf": "BSD-3-Clause",
    "nlohmann-json": "MIT",
    "json": "MIT",
    "abseil-cpp": "Apache-2.0",
}


class TestLoadMap:
    def test_bundled_core_map_is_empty(self):
        # The generic core ships an empty map; content moved to the profile layer.
        assert known_licenses.load_map() == {}

    def test_loads_override_path(self, tmp_path):
        custom = tmp_path / "custom.yaml"
        custom.write_text("mylib: Apache-2.0\n")
        m = known_licenses.load_map(custom)
        assert m == {"mylib": "Apache-2.0"}

    def test_keys_are_lowercased(self):
        m = known_licenses.load_map()
        for key in m:
            assert key == key.lower(), f"key {key!r} should be lowercase"

    def test_returns_empty_for_empty_yaml(self, tmp_path):
        empty = tmp_path / "empty.yaml"
        empty.write_text("")
        m = known_licenses.load_map(empty)
        assert m == {}


_KNOWN_APPLY_CASES = [
    # (comp_name, aliases, pre_set_license, expected_license, expect_provenance)
    ("eigen", [], None, "MPL-2.0 AND BSD-3-Clause", True),
    ("googletest", [], None, "BSD-3-Clause", True),
    ("gtest", [], None, "BSD-3-Clause", True),
    ("protobuf", [], None, "BSD-3-Clause", True),
    ("nlohmann-json", [], None, "MIT", True),
    ("json", [], None, "MIT", True),
    ("abseil-cpp", [], None, "Apache-2.0", True),
    # Pre-set license should NOT be overridden (curated wins)
    ("eigen", [], "LicenseRef-curated", "LicenseRef-curated", False),
    # Unknown component should stay None
    ("unknown-lib-xyz", [], None, None, False),
    # Alias lookup: component named 'nlohmann' with alias 'nlohmann-json'
    ("nlohmann", ["nlohmann-json"], None, "MIT", True),
    # Case-insensitive name lookup
    ("Eigen", [], None, "MPL-2.0 AND BSD-3-Clause", True),
]


@pytest.mark.parametrize(
    "comp_name,aliases,pre_license,expected_license,expect_prov",
    _KNOWN_APPLY_CASES,
    ids=[f"{c[0]}-pre={c[2]}" for c in _KNOWN_APPLY_CASES],
)
def test_known_licenses_apply(
    comp_name, aliases, pre_license, expected_license, expect_prov
):
    m = dict(_FIXTURE_MAP)
    comp = _comp(comp_name, aliases, pre_license)
    warnings = known_licenses.apply([comp], m)
    assert comp.license == expected_license
    if expect_prov:
        assert any(p.field == "license" for p in comp.provenance)
    else:
        assert not any(p.field == "license" and p.source == "known_licenses.yaml" for p in comp.provenance)
    assert warnings == []


def test_known_licenses_apply_only_first_alias_match():
    """When both name and alias match, name-match wins (first candidate)."""
    m = {"myname": "MIT", "myalias": "Apache-2.0"}
    comp = _comp("myname", ["myalias"])
    known_licenses.apply([comp], m)
    assert comp.license == "MIT"


def test_known_licenses_apply_empty_list():
    m = known_licenses.load_map()
    warnings = known_licenses.apply([], m)
    assert warnings == []


# ===========================================================================
# licenseref
# ===========================================================================


class TestIsSpdxExpression:
    @pytest.mark.parametrize(
        "expr,expected",
        [
            ("MIT", True),
            ("Apache-2.0", True),
            ("GPL-2.0-only", True),
            ("GPL-2.0-or-later", True),
            ("BSD-3-Clause", True),
            ("LicenseRef-CANN-Open-Software-License-2.0", True),
            ("MPL-2.0 AND BSD-3-Clause", True),
            ("MIT OR Apache-2.0", True),
            ("GPL-2.0-only WITH Classpath-exception-2.0", True),
            ("NOASSERTION", True),
            ("NONE", True),
            # Non-SPDX / invalid
            ("CANN Open Software License 2.0", False),  # spaces without operators
            ("", False),
            ("  ", False),
            ("GPL v2", False),  # space in identifier without AND/OR
            # Looks-like-an-id but is NOT a real SPDX license id -> route to
            # LicenseRef (otherwise the SPDX validator rejects it).
            ("MPL2", False),
            ("Foobar-9.9", False),
            ("MPL-2.0", True),  # the real id stays SPDX
            ("MPL-2.0 AND BSD-3-Clause", True),
        ],
    )
    def test_various(self, expr, expected):
        assert licenseref.is_spdx_expression(expr) == expected


class TestSynthesize:
    @pytest.mark.parametrize(
        "name,expected_prefix",
        [
            ("CANN Open Software License 2.0", "LicenseRef-CANN-Open-Software-License-2-0"),
            ("My Custom License v1", "LicenseRef-My-Custom-License-v1"),
            ("Apache 2.0", "LicenseRef-Apache-2-0"),
            ("GPL v2+", "LicenseRef-GPL-v2"),
        ],
    )
    def test_slug_format(self, name, expected_prefix):
        ref_id, text = licenseref.synthesize("full license text here", name)
        assert ref_id == expected_prefix, f"Expected {expected_prefix!r}, got {ref_id!r}"

    def test_full_text_preserved(self):
        full_text = "This is the full license text.\nClause 1: ..."
        ref_id, text = licenseref.synthesize(full_text, "My License")
        assert text == full_text

    def test_licenseref_prefix(self):
        ref_id, _ = licenseref.synthesize("text", "Some License 1.0")
        assert ref_id.startswith("LicenseRef-")

    def test_slug_no_double_hyphen(self):
        ref_id, _ = licenseref.synthesize("text", "A  B")
        assert "--" not in ref_id

    def test_slug_no_leading_trailing_hyphen(self):
        ref_id, _ = licenseref.synthesize("text", "  Leading space")
        slug = ref_id.removeprefix("LicenseRef-")
        assert not slug.startswith("-")
        assert not slug.endswith("-")


    def test_non_ascii_name_never_yields_bare_licenseref(self):
        # A name of only non-ASCII / punctuation slugs to empty -> must NOT become a
        # bare 'LicenseRef-' (invalid SPDX); distinct names stay distinct (review A1).
        rid1, _ = licenseref.synthesize("text", "中文许可证")
        rid2, _ = licenseref.synthesize("text", "另一个许可证")
        assert rid1 != "LicenseRef-" and rid1.startswith("LicenseRef-unknown-")
        assert rid1 != rid2


# ===========================================================================
# cache_scan
# ===========================================================================


class TestCacheScanSpdxMatch:
    """Test the internal SPDX matching heuristic directly."""

    @pytest.mark.parametrize(
        "text,expected",
        [
            # Apache 2.0
            ("Apache License\nVersion 2.0", "Apache-2.0"),
            # MIT
            ("Permission is hereby granted, free of charge", "MIT"),
            # BSD-3-Clause
            (
                "Neither the name of copyright holder nor the names of its contributors",
                "BSD-3-Clause",
            ),
            # MPL 2.0
            ("Mozilla Public License Version 2.0", "MPL-2.0"),
            # BSL 1.0
            ("Boost Software License - Version 1.0", "BSL-1.0"),
            # SPDX-License-Identifier header
            ("SPDX-License-Identifier: MIT\nSome other text", "MIT"),
            ("SPDX-License-Identifier: Apache-2.0", "Apache-2.0"),
            # Unrecognised
            ("This is just some random text with no license indicators.", None),
        ],
    )
    def test_spdx_match(self, text, expected):
        result = cache_scan._spdx_match(text)
        assert result == expected


class TestFindLicenseFiles:
    def test_finds_license_txt(self, tmp_path):
        (tmp_path / "LICENSE.txt").write_text("MIT")
        (tmp_path / "README.md").write_text("readme")
        found = cache_scan._find_license_files(tmp_path)
        assert any(f.name == "LICENSE.txt" for f in found)

    def test_does_not_recurse(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "LICENSE").write_text("MIT")
        found = cache_scan._find_license_files(tmp_path)
        assert not found  # no LICENSE at root level

    def test_finds_copying(self, tmp_path):
        (tmp_path / "COPYING").write_text("GPL")
        found = cache_scan._find_license_files(tmp_path)
        assert any(f.name == "COPYING" for f in found)

    def test_nonexistent_dir(self, tmp_path):
        found = cache_scan._find_license_files(tmp_path / "nonexistent")
        assert found == []


class TestCacheScanApply:
    def _make_cache(self, tmp_path: Path, entries: dict[str, str]) -> Path:
        """Create a fake CANN_3RD_LIB_PATH with dep dirs containing LICENSE files."""
        for dep_name, license_text in entries.items():
            dep_dir = tmp_path / dep_name
            dep_dir.mkdir()
            (dep_dir / "LICENSE").write_text(license_text)
        return tmp_path

    def test_applies_license_from_cache(self, tmp_path):
        cache = self._make_cache(tmp_path, {"eigen": "Apache License\nVersion 2.0"})
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(cache)})
        comp = _comp("eigen")
        warnings = cache_scan.apply([comp], config)
        assert comp.license == "Apache-2.0"
        assert any(p.field == "license" for p in comp.provenance)
        assert warnings == []

    def test_no_cache_dir_is_noop(self, tmp_path):
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(tmp_path / "nonexistent")})
        comp = _comp("eigen")
        warnings = cache_scan.apply([comp], config)
        assert comp.license is None
        assert warnings == []

    def test_no_cann_3rd_lib_path_is_noop(self):
        old = os.environ.pop("CANN_3RD_LIB_PATH", None)
        try:
            config = _Config()
            comp = _comp("eigen")
            warnings = cache_scan.apply([comp], config)
            assert comp.license is None
        finally:
            if old is not None:
                os.environ["CANN_3RD_LIB_PATH"] = old

    def test_cann_3rd_lib_path_from_env(self, tmp_path):
        cache = self._make_cache(tmp_path, {"protobuf": "BSD 3-Clause License\nNeither the name of copyright holder nor the names of its contributors"})
        old = os.environ.get("CANN_3RD_LIB_PATH")
        os.environ["CANN_3RD_LIB_PATH"] = str(cache)
        try:
            config = _Config()  # no cmake_defines
            comp = _comp("protobuf")
            warnings = cache_scan.apply([comp], config)
            assert comp.license == "BSD-3-Clause"
            # The env-var source must be SURFACED (not silently used), since the
            # CMake authority resolution deliberately ignores the environment.
            assert any(w.code == "cache_scan_env_source" for w in warnings)
        finally:
            if old is None:
                del os.environ["CANN_3RD_LIB_PATH"]
            else:
                os.environ["CANN_3RD_LIB_PATH"] = old

    def test_does_not_override_existing_license(self, tmp_path):
        cache = self._make_cache(tmp_path, {"eigen": "Apache License\nVersion 2.0"})
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(cache)})
        comp = _comp("eigen", license_="LicenseRef-curated")
        cache_scan.apply([comp], config)
        assert comp.license == "LicenseRef-curated"  # not overridden

    def test_alias_lookup(self, tmp_path):
        # Directory is named 'googletest', component is 'gtest' with alias
        cache = self._make_cache(tmp_path, {"googletest": "BSD 3-Clause\nNeither the name of copyright holder nor the names of its contributors"})
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(cache)})
        comp = _comp("gtest", aliases=["googletest"])
        cache_scan.apply([comp], config)
        assert comp.license == "BSD-3-Clause"

    def test_unrecognised_license_emits_warning(self, tmp_path):
        cache = self._make_cache(tmp_path, {"mystuff": "Proprietary license. All rights reserved."})
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(cache)})
        comp = _comp("mystuff")
        warnings = cache_scan.apply([comp], config)
        assert comp.license is None
        assert any(w.code == "license_unresolved" and w.subject == "mystuff" for w in warnings)

    def test_dep_not_in_cache_no_warning(self, tmp_path):
        cache = self._make_cache(tmp_path, {})
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(cache)})
        comp = _comp("not-in-cache")
        warnings = cache_scan.apply([comp], config)
        assert comp.license is None
        assert warnings == []

    def test_mit_license_detection(self, tmp_path):
        mit_text = textwrap.dedent("""\
            MIT License
            Permission is hereby granted, free of charge, to any person obtaining a copy
            of this software and associated documentation files (the "Software"), to deal
            in the Software without restriction.
        """)
        cache = self._make_cache(tmp_path, {"mylib": mit_text})
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(cache)})
        comp = _comp("mylib")
        cache_scan.apply([comp], config)
        assert comp.license == "MIT"

    def test_spdx_header_wins_over_heuristic(self, tmp_path):
        text = "SPDX-License-Identifier: ISC\nSome other license text about permission..."
        cache = self._make_cache(tmp_path, {"libx": text})
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(cache)})
        comp = _comp("libx")
        cache_scan.apply([comp], config)
        assert comp.license == "ISC"

    def test_checksum_recorded(self, tmp_path):
        cache = self._make_cache(tmp_path, {"eigen": "Apache License\nVersion 2.0"})
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(cache)})
        comp = _comp("eigen")
        cache_scan.apply([comp], config)
        assert "license_file_sha256" in comp.checksums

    def test_empty_components_list(self, tmp_path):
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(tmp_path)})
        warnings = cache_scan.apply([], config)
        assert warnings == []


# ===========================================================================
# net
# ===========================================================================

# -- Mock HTTP responses --

_DEPSDEV_PYPI_MIT = json.dumps({
    "version": {
        "versionKey": {"system": "PYPI", "name": "requests", "version": "2.31.0"},
        "licenses": ["MIT"],
    }
})

_DEPSDEV_PYPI_MULTI = json.dumps({
    "version": {
        "licenses": ["Apache-2.0", "MIT"],
    }
})

_PYPI_MIT = json.dumps({
    "info": {
        "name": "requests",
        "version": "2.31.0",
        "license": "Apache 2.0",
        "classifiers": [
            "License :: OSI Approved :: Apache Software License",
        ],
    }
})

_DEPSDEV_EMPTY = json.dumps({"version": {"licenses": []}})

_DEPSDEV_NO_LICENSES = json.dumps({"version": {}})

# deps.dev's sentinel for "couldn't reduce to a clean SPDX id" — NOT a license.
_DEPSDEV_NON_STANDARD = json.dumps({"version": {"licenses": ["non-standard"]}})

# scipy-shaped deps.dev: license is the 'non-standard' sentinel, but it DOES
# carry the resolved default version (so the PyPI fallback can go version-specific).
_DEPSDEV_NON_STANDARD_WITH_VERSION = json.dumps(
    {"defaultVersion": "1.18.0", "version": {"version": "1.18.0", "licenses": ["non-standard"]}}
)

# scipy-shaped PyPI: `license` is the full BSD text, but a classifier carries it.
_PYPI_BSD_VIA_CLASSIFIER = json.dumps({
    "info": {
        "name": "scipy",
        "license": "Copyright (c) 2001-2002 Enthought, Inc.\nRedistribution and "
                   "use in source and binary forms ... (full text)",
        "classifiers": ["License :: OSI Approved :: BSD License"],
    }
})

# PyPI with ONLY a full-text license and no usable classifier: the blob must not
# become a license id.
_PYPI_FULLTEXT_ONLY = json.dumps({
    "info": {
        "name": "weird",
        "license": "This software is provided as-is.\nSecond line of the text.",
        "classifiers": [],
    }
})


class TestNetApply:
    def setup_method(self):
        """Reset injection before each test."""
        net.set_http_get(None)

    def teardown_method(self):
        """Restore default after each test."""
        net.set_http_get(None)

    def test_noop_when_network_off(self):
        """No HTTP calls when network is off."""
        called = []

        def mock_get(url):
            called.append(url)
            return "{}"

        net.set_http_get(mock_get)
        config = _Config(network="off")
        comp = _comp("requests")
        warnings = net.apply([comp], config)
        assert not called
        assert comp.license is None
        assert warnings == []

    def test_applies_license_from_depsdev(self):
        def mock_get(url):
            if "deps.dev" in url:
                return _DEPSDEV_PYPI_MIT
            return "{}"

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("requests", python=True)
        warnings = net.apply([comp], config)
        assert comp.license == "MIT"
        assert any(p.field == "license" for p in comp.provenance)
        assert warnings == []

    def test_falls_back_to_pypi_for_python_component(self):
        """When deps.dev returns empty, falls back to PyPI for Python components."""
        def mock_get(url):
            if "deps.dev" in url:
                return _DEPSDEV_EMPTY
            if "pypi.org" in url:
                return _PYPI_MIT
            return "{}"

        net.set_http_get(mock_get)
        config = _Config(network="on")
        # Make it a Python component via observations
        obs = Observation(
            source_kind=SourceKind.PYTHON_REQUIREMENT,
            usage_scope=UsageScope.RUNTIME,
        )
        comp = _comp("requests")
        comp.observations.append(obs)
        warnings = net.apply([comp], config)
        assert comp.license is not None
        assert warnings == []

    def test_no_license_from_network_emits_warning(self):
        def mock_get(url):
            return _DEPSDEV_NO_LICENSES

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("obscure-lib", python=True)
        warnings = net.apply([comp], config)
        assert comp.license is None
        assert any(w.code == "license_unresolved" for w in warnings)

    def test_does_not_override_existing_license(self):
        called = []

        def mock_get(url):
            called.append(url)
            return _DEPSDEV_PYPI_MIT

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("requests", license_="LicenseRef-curated")
        net.apply([comp], config)
        assert comp.license == "LicenseRef-curated"
        assert not called  # Should not even make HTTP call for already-resolved comp

    def test_http_error_is_graceful(self):
        """A network error should not crash; produces warning."""
        import urllib.error

        def mock_get(url):
            raise urllib.error.URLError("connection refused")

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("requests", python=True)
        warnings = net.apply([comp], config)
        assert comp.license is None
        assert any(w.code == "license_unresolved" for w in warnings)

    def test_depsdev_url_format(self):
        """Verify deps.dev URL is constructed correctly."""
        urls = []

        def mock_get(url):
            urls.append(url)
            return _DEPSDEV_PYPI_MIT

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("requests", python=True)
        net.apply([comp], config)
        assert any("deps.dev" in u and "requests" in u for u in urls)


    def test_multi_license_joined_with_and(self):
        def mock_get(url):
            if "deps.dev" in url:
                return _DEPSDEV_PYPI_MULTI
            return "{}"

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("some-lib", python=True)
        net.apply([comp], config)
        assert comp.license == "Apache-2.0 AND MIT"

    def test_empty_components_list(self):
        called = []

        def mock_get(url):
            called.append(url)
            return "{}"

        net.set_http_get(mock_get)
        config = _Config(network="on")
        warnings = net.apply([], config)
        assert not called
        assert warnings == []

    def test_provenance_source_contains_name(self):
        def mock_get(url):
            return _DEPSDEV_PYPI_MIT

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("requests", python=True)
        net.apply([comp], config)
        assert any("requests" in p.source for p in comp.provenance)

    def test_host_allowed_restricts_to_https_allowed_hosts(self):
        # SSRF guard: only https to deps.dev/pypi.org (+ subdomains) is permitted.
        assert net._host_allowed("https://pypi.org/pypi/x/json")
        assert net._host_allowed("https://deps.dev/_/s/pypi/p/x")
        assert net._host_allowed("https://files.pypi.org/x")  # subdomain ok
        assert not net._host_allowed("http://pypi.org/x")  # not https
        assert not net._host_allowed("https://evil.example/x")  # off-host
        assert not net._host_allowed("https://pypi.org.evil.example/x")  # suffix trick
        import urllib.error
        import pytest as _pytest
        with _pytest.raises(urllib.error.URLError):
            net._default_http_get("http://pypi.org/insecure")  # refused before any I/O

    def test_extractors_survive_malformed_untrusted_json(self):
        # A malformed/redirected response must degrade to None, never raise
        # (an uncaught error would abort reconcile) — review D10.
        bad_inputs = [
            [], "a string", 42, None,
            {"version": "not-a-dict"}, {"version": ["x"]},
            {"info": "not-a-dict"}, {"info": {"classifiers": [1, None, "x"]}},
            {"package": {"versions": ["not-a-dict"]}},
            {"defaultVersion": ["nope"]},
        ]
        for bad in bad_inputs:
            assert net._extract_license_depsdev(bad) in (None,) or isinstance(
                net._extract_license_depsdev(bad), str
            )
            net._extract_license_pypi(bad)  # must not raise
            net._resolved_version_depsdev(bad)  # must not raise

    def test_skips_non_python_component_avoids_false_attribution(self):
        """A non-Python component (a CANN/C++ lib like 'dlog') must NOT be queried
        against the PyPI ecosystem, even though a same-named PyPI package exists --
        that would attribute an unrelated package's license. No call, no license."""
        called = []

        def mock_get(url):
            called.append(url)
            return _DEPSDEV_PYPI_MIT

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("dlog")  # not Python: no languages, no python observation
        warnings = net.apply([comp], config)
        assert not called, "must not query PyPI for a non-Python component"
        assert comp.license is None
        assert warnings == []

    def test_depsdev_non_standard_sentinel_falls_through_to_pypi(self):
        """deps.dev's 'non-standard' sentinel is not a license: fall through to the
        PyPI classifier path instead of labelling the component 'non-standard'."""
        def mock_get(url):
            if "deps.dev" in url:
                return _DEPSDEV_NON_STANDARD
            return _PYPI_BSD_VIA_CLASSIFIER

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("scipy", python=True)
        net.apply([comp], config)
        assert comp.license == "BSD-3-Clause"  # from the classifier, not 'non-standard'

    def test_unpinned_dep_uses_version_specific_pypi_endpoint(self):
        """For an UNPINNED dep, the PyPI fallback must reuse the version deps.dev
        resolved and query the small /pypi/<name>/<version>/json endpoint, not the
        multi-MB /pypi/<name>/json (scipy's full JSON is huge and times out)."""
        urls = []

        def mock_get(url):
            urls.append(url)
            if "deps.dev" in url:
                return _DEPSDEV_NON_STANDARD_WITH_VERSION
            return _PYPI_BSD_VIA_CLASSIFIER

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("scipy", python=True)  # unpinned: no source/effective version
        net.apply([comp], config)
        assert comp.license == "BSD-3-Clause"
        pypi_calls = [u for u in urls if "pypi.org" in u]
        assert pypi_calls and all("/scipy/1.18.0/json" in u for u in pypi_calls), (
            f"expected the version-specific endpoint, got {pypi_calls}"
        )

    def test_resolved_version_depsdev_shapes(self):
        assert net._resolved_version_depsdev({"defaultVersion": "1.18.0"}) == "1.18.0"
        assert net._resolved_version_depsdev(
            {"version": {"version": "2.0.0"}}
        ) == "2.0.0"
        assert net._resolved_version_depsdev(
            {"version": {"versionKey": {"version": "3.0"}}}
        ) == "3.0"
        assert net._resolved_version_depsdev({"version": {"licenses": ["x"]}}) is None

    def test_pypi_full_text_license_not_emitted_as_id(self):
        """A PyPI `license` that is a full text blob (no usable classifier) must not
        become a license id; the component stays unresolved."""
        def mock_get(url):
            if "deps.dev" in url:
                return _DEPSDEV_NON_STANDARD
            return _PYPI_FULLTEXT_ONLY

        net.set_http_get(mock_get)
        config = _Config(network="on")
        comp = _comp("weird", python=True)
        warnings = net.apply([comp], config)
        assert comp.license is None
        assert any(w.code == "license_unresolved" for w in warnings)


# ===========================================================================
# Integration: layered resolver order (curated > known-map > cache > net)
# ===========================================================================


class TestLayeredResolver:
    """Verify that higher layers take precedence over lower layers."""

    def test_curated_wins_over_known_map(self):
        m = known_licenses.load_map()
        comp = _comp("eigen", license_="LicenseRef-curated")
        known_licenses.apply([comp], m)
        assert comp.license == "LicenseRef-curated"

    def test_known_map_wins_over_cache(self, tmp_path):
        # known_map sets license first; cache should not override
        m = dict(_FIXTURE_MAP)
        comp = _comp("eigen")
        known_licenses.apply([comp], m)
        assert comp.license is not None

        apache_text = "Apache License\nVersion 2.0"
        dep_dir = tmp_path / "eigen"
        dep_dir.mkdir()
        (dep_dir / "LICENSE").write_text(apache_text)
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(tmp_path)})
        cache_scan.apply([comp], config)
        # License from known_map was already set; cache must not override
        assert comp.license == "MPL-2.0 AND BSD-3-Clause"

    def test_cache_wins_over_net(self, tmp_path):
        dep_dir = tmp_path / "mylib"
        dep_dir.mkdir()
        (dep_dir / "LICENSE").write_text("Apache License\nVersion 2.0")
        config = _Config(
            cmake_defines={"CANN_3RD_LIB_PATH": str(tmp_path)},
            network="on",
        )
        comp = _comp("mylib")
        cache_scan.apply([comp], config)
        assert comp.license == "Apache-2.0"

        # Net enricher should skip because license already set
        called = []

        def mock_get(url):
            called.append(url)
            return json.dumps({"version": {"licenses": ["MIT"]}})

        net.set_http_get(mock_get)
        try:
            net.apply([comp], config)
        finally:
            net.set_http_get(None)
        # License should remain from cache, not overridden by net
        assert comp.license == "Apache-2.0"
        assert not called  # no HTTP calls made

    def test_noassertion_when_all_layers_miss(self, tmp_path):
        # No known map match, no cache, network off
        m: dict[str, str] = {}  # empty map
        config = _Config(cmake_defines={"CANN_3RD_LIB_PATH": str(tmp_path)}, network="off")
        comp = _comp("totally-unknown-package")
        known_licenses.apply([comp], m)
        cache_scan.apply([comp], config)
        net.apply([comp], config)
        # Should remain None (caller sets NOASSERTION at emit time)
        assert comp.license is None


# ===========================================================================
# Regression: LicenseRef for the documented CANN case
# ===========================================================================


def test_is_spdx_expression_licenseref_is_valid():
    """A LicenseRef-* identifier should be accepted as a valid SPDX expression."""
    assert licenseref.is_spdx_expression("LicenseRef-CANN-Open-Software-License-2-0")


def test_is_spdx_expression_cann_name_is_not_valid():
    """The plain CANN license name should NOT be accepted as SPDX."""
    assert not licenseref.is_spdx_expression("CANN Open Software License 2.0")


# ===========================================================================
# Regression: direct/VCS Python deps must NOT receive PyPI enrichment
# ===========================================================================


def _direct_vcs_comp(name="private-lib"):
    return Component(
        name=name,
        languages=["Python"],
        observations=[Observation(
            source_kind=SourceKind.PYTHON_REQUIREMENT,
            ecosystem_data={"direct_reference": f"git+https://github.com/acme/{name}.git#egg={name}",
                            "vcs": "git"})],
    )


def _registry_comp(name="private-lib"):
    return Component(name=name, languages=["Python"],
                     observations=[Observation(source_kind=SourceKind.PYTHON_REQUIREMENT, ecosystem_data={})])


def test_depsdev_cache_skips_direct_vcs_reference():
    from sbom.enrich import depsdev_cache

    cache = {"pypi:private-lib": {"license": "MIT", "supplier": "PyPI Author"}}
    direct = _direct_vcs_comp()
    depsdev_cache.apply([direct], cache)
    assert direct.license is None and direct.supplier is None  # NOT enriched as PyPI

    reg = _registry_comp()
    depsdev_cache.apply([reg], cache)
    assert reg.license == "MIT" and reg.supplier == "PyPI Author"  # registry dep is

    # A direct-URL ref to an official wheel (no vcs scheme) IS registry-backed and
    # MUST still be enriched (torch @ download.pytorch.org case).
    wheel = Component(name="torch", languages=["Python"],
                      observations=[Observation(source_kind=SourceKind.PYTHON_REQUIREMENT,
                          ecosystem_data={"direct_reference": "https://download.pytorch.org/whl/cpu/torch-2.7.1.whl"})])
    depsdev_cache.apply([wheel], {"pypi:torch": {"license": "BSD-3-Clause"}})
    assert wheel.license == "BSD-3-Clause"


def test_net_skips_direct_vcs_reference(monkeypatch):
    from dataclasses import dataclass, field as _f

    @dataclass
    class _Cfg:
        network: str = "on"
        cmake_defines: dict = _f(default_factory=dict)

    # If net ever hit the network for a direct ref, this would raise.
    net.set_http_get(lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not fetch")))
    try:
        net.apply([_direct_vcs_comp()], _Cfg())  # no fetch, no enrichment
    finally:
        net.set_http_get(None)


def test_clearlydefined_key_none_for_direct_reference():
    from sbom.enrich import clearlydefined

    assert clearlydefined.component_key(_direct_vcs_comp()) is None
    assert clearlydefined.component_key(_registry_comp("numpy")) == "pypi:numpy"


def test_python_unverified_direct_url_host_distinction():
    from sbom.models import python_unverified_direct_url

    def comp(url, vcs=None):
        eco = {"direct_reference": url}
        if vcs:
            eco["vcs"] = vcs
        return Component(name="x", languages=["Python"],
                         observations=[Observation(source_kind=SourceKind.PYTHON_REQUIREMENT, ecosystem_data=eco)])

    # Recognized package indexes -> trusted silently (None).
    assert python_unverified_direct_url(comp("https://download.pytorch.org/whl/cpu/torch-2.7.1.whl")) is None
    assert python_unverified_direct_url(comp("https://files.pythonhosted.org/p/x/x-1.0.whl")) is None
    # Unrecognized host -> returns the url so a warning is raised.
    assert python_unverified_direct_url(comp("https://vendor.example/x-1.0.whl")) == "https://vendor.example/x-1.0.whl"
    assert python_unverified_direct_url(comp("https://gitcode.com/Ascend/x/x-1.0.whl")) is not None
    # VCS refs and plain registry requirements are handled elsewhere -> None.
    assert python_unverified_direct_url(comp("git+https://github.com/a/b.git", vcs="git")) is None
    assert python_unverified_direct_url(_registry_comp("x")) is None
