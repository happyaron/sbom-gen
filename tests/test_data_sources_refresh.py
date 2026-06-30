"""Tests for the DataSource registry, the network-result cache layer, the
profile-override merge, and the --refresh-data actions."""

from __future__ import annotations

import json
from pathlib import Path

from sbom.config import Config
from sbom.data_sources import (
    CURATED,
    NETWORK,
    DataSource,
    build_data_sources,
    core_data_sources,
    sources_named,
)
from sbom.enrich import depsdev_cache
from sbom.models import Component, Subject
from sbom.profile import GenericProfile, Profile


# ---------------------------------------------------------------------------
# DataSource registry
# ---------------------------------------------------------------------------


def test_core_sources_present():
    names = {s.name for s in core_data_sources()}
    assert names == {"known-licenses", "depsdev", "clearlydefined", "deps-dir"}


class _ExtraProfile(Profile):
    name = "extra"

    def __init__(self, path):
        self._path = path

    def data_sources(self):
        # overrides core known-licenses + adds a profile-only source
        return [
            DataSource("known-licenses", CURATED, self._path, "yaml"),
            DataSource("aliases", CURATED, self._path, "yaml"),
        ]


def test_build_sources_orders_core_then_profile(tmp_path):
    f = tmp_path / "x.yaml"
    f.write_text("")
    sources = build_data_sources(_ExtraProfile(f))
    kl = sources_named(sources, "known-licenses")
    # core entry first, profile override LAST (so a merge lets the profile win)
    assert len(kl) == 2 and kl[-1].path == f
    assert [s.name for s in sources_named(sources, "aliases")] == ["aliases"]


def test_build_sources_tolerates_stubprofile_without_hook():
    class _Stub:  # no data_sources attr
        pass

    assert {s.name for s in build_data_sources(_Stub())} == {
        "known-licenses",
        "depsdev",
        "clearlydefined",
        "deps-dir",
    }


# ---------------------------------------------------------------------------
# depsdev_cache module
# ---------------------------------------------------------------------------


def test_cache_key_pep503_normalizes():
    assert depsdev_cache.cache_key("PyYAML") == "pypi:pyyaml"
    assert depsdev_cache.cache_key("ruamel.yaml") == "pypi:ruamel-yaml"
    assert depsdev_cache.cache_key("a_b.c") == "pypi:a-b-c"


def test_cache_load_merges_in_order_later_wins(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"schema": 1, "entries": {"pypi:x": {"license": "MIT"}}}))
    b.write_text(json.dumps({"schema": 1, "entries": {"pypi:x": {"license": "BSD-3-Clause"}, "pypi:y": {"license": "Apache-2.0"}}}))
    merged = depsdev_cache.load([a, b])
    assert merged["pypi:x"]["license"] == "BSD-3-Clause"  # later wins
    assert merged["pypi:y"]["license"] == "Apache-2.0"


def test_cache_load_skips_missing_and_corrupt(tmp_path):
    good = tmp_path / "g.json"
    good.write_text(json.dumps({"entries": {"pypi:z": {"license": "MIT"}}}))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    merged = depsdev_cache.load([tmp_path / "nope.json", bad, good])
    assert merged == {"pypi:z": {"license": "MIT"}}


def test_cache_apply_python_only_fills_unset_with_provenance():
    cache = {"pypi:numpy": {"license": "BSD-3-Clause"}, "pypi:dlog": {"license": "MIT"}}
    py = Component(name="numpy", languages=["Python"])
    cpp = Component(name="dlog")  # same-name PyPI package must NOT be applied
    already = Component(name="attrs", languages=["Python"], license="MIT")
    depsdev_cache.apply([py, cpp, already], {**cache, "pypi:attrs": {"license": "GPL-3.0"}})
    assert py.license == "BSD-3-Clause"
    assert [p.source for p in py.provenance if p.field == "license"] == ["depsdev"]
    assert cpp.license is None  # non-Python skipped
    assert already.license == "MIT"  # pre-set license not overwritten


def test_cache_apply_fills_supplier_from_pypi_author():
    py = Component(name="pyyaml", languages=["Python"])
    depsdev_cache.apply([py], {"pypi:pyyaml": {"license": "MIT", "supplier": "Kirill Simonov"}})
    assert py.supplier == "Kirill Simonov"
    assert [p.source for p in py.provenance if p.field == "supplier"] == ["depsdev"]


def test_cache_dump_is_deterministic_and_sorted():
    entries = {"pypi:b": {"license": "MIT"}, "pypi:a": {"license": "BSD-3-Clause"}}
    out1 = depsdev_cache.dump(entries)
    out2 = depsdev_cache.dump(entries)
    assert out1 == out2
    assert out1.index('"pypi:a"') < out1.index('"pypi:b"')  # sorted keys
    assert json.loads(out1)["schema"] == 1


# ---------------------------------------------------------------------------
# known-licenses merge (core + profile override)
# ---------------------------------------------------------------------------


def test_known_map_profile_supplies_content_core_is_empty(tmp_path):
    from sbom.reconcile import _load_known_license_map

    # The core ships EMPTY; the profile's known-licenses source provides the map.
    override = tmp_path / "kl.yaml"
    override.write_text("eigen: Apache-2.0\nmycorp-lib: MIT\n")
    merged = _load_known_license_map(_ExtraProfile(override))
    assert merged["eigen"] == "Apache-2.0"
    assert merged["mycorp-lib"] == "MIT"


def test_known_map_no_profile_is_empty():
    from sbom.reconcile import _load_known_license_map

    # The generic core ships an empty known-license map (content lives in profiles).
    assert _load_known_license_map(None) == {}


def test_known_map_cann_profile_carries_oss_content():
    from sbom.reconcile import _load_known_license_map
    from sbom_profile_cann import CannProfile

    m = _load_known_license_map(CannProfile())
    assert m["eigen"] == "MPL-2.0 AND BSD-3-Clause" and m["boost"] == "BSL-1.0"
    # Notice-resilience floor: securec/makeself licenses are vendored so they
    # survive if the repo's (optional, may-disappear) Third_Party Notice is gone.
    assert m["securec"] == "MulanPSL-2.0" and m["makeself"] == "GPL-2.0-only"


def test_known_map_skips_corrupt_source_keeps_valid(tmp_path):
    from sbom.reconcile import _load_known_license_map

    good = tmp_path / "good.yaml"
    good.write_text("eigen: MPL-2.0\n")
    bad = tmp_path / "bad.yaml"
    bad.write_text("::: not a mapping :::\n")

    class _TwoSourceProfile(Profile):
        name = "two"

        def data_sources(self):
            return [
                DataSource("known-licenses", CURATED, good, "yaml"),
                DataSource("known-licenses", CURATED, bad, "yaml"),
            ]

    # A corrupt source is skipped (and logged); the valid one still loads — no crash.
    m = _load_known_license_map(_TwoSourceProfile())
    assert m["eigen"] == "MPL-2.0"


class _CacheProfile(Profile):
    """Profile exposing only a depsdev source at a given path."""

    name = "cacheprof"

    def __init__(self, cache_path):
        self._cache = cache_path

    def data_sources(self):
        return [DataSource("depsdev", NETWORK, self._cache, "json")]


def _write_cache(path, name, license_):
    path.write_text(json.dumps({"schema": 1, "entries": {f"pypi:{name}": {"license": license_}}}))


def test_apply_depsdev_cache_uses_profile_default_path(tmp_path):
    # No --depsdev-cache override: the profile's vendored cache is still consulted.
    from sbom.reconcile import _apply_depsdev_cache

    prof = tmp_path / "prof.json"
    _write_cache(prof, "numpy", "Apache-2.0")
    comp = Component(name="numpy", languages=["Python"])
    _apply_depsdev_cache([comp], Config(repo_root=Path(".")), _CacheProfile(prof))
    assert comp.license == "Apache-2.0"


def test_apply_depsdev_cache_config_override_wins(tmp_path):
    # config.depsdev_cache is appended last -> wins over the profile source.
    from sbom.reconcile import _apply_depsdev_cache

    prof = tmp_path / "prof.json"
    _write_cache(prof, "numpy", "Apache-2.0")
    override = tmp_path / "override.json"
    _write_cache(override, "numpy", "BSD-3-Clause")
    comp = Component(name="numpy", languages=["Python"])
    cfg = Config(repo_root=Path("."), depsdev_cache=str(override))
    _apply_depsdev_cache([comp], cfg, _CacheProfile(prof))
    assert comp.license == "BSD-3-Clause"


# ---------------------------------------------------------------------------
# depsdev layer through reconcile (offline)
# ---------------------------------------------------------------------------


def test_depsdev_cache_layer_applies_through_reconcile(tmp_path):
    from sbom.collectors import CollectResult
    from sbom.reconcile import reconcile

    cache = tmp_path / "nc.json"
    cache.write_text(json.dumps({"schema": 1, "entries": {"pypi:numpy": {"license": "BSD-3-Clause"}}}))
    comp = Component(name="numpy", languages=["Python"])
    cfg = Config(repo_root=Path("."), network="off", depsdev_cache=str(cache), scope="all")
    doc = reconcile([CollectResult(components=[comp])], [], cfg, GenericProfile())
    out = next(c for c in doc.components if c.name == "numpy")
    assert out.license == "BSD-3-Clause"
    assert any(p.source == "depsdev" for p in out.provenance)


# ---------------------------------------------------------------------------
# --refresh-data actions
# ---------------------------------------------------------------------------


def test_resolve_pypi_retries_versionless_on_miss(monkeypatch):
    # A Python component carrying a C++/wrong version (e.g. protobuf 25.1, no PyPI
    # release) must fall back to a version-less lookup rather than reporting a miss.
    from sbom.enrich import net

    calls = []

    def fake_once(name, version):
        calls.append(version)
        return None if version is not None else {"license": "BSD-3-Clause", "version": "7.0", "source": "deps.dev/pypi/protobuf"}

    monkeypatch.setattr(net, "_resolve_pypi_once", fake_once)
    result = net.resolve_pypi("protobuf", "25.1")
    assert result and result["license"] == "BSD-3-Clause"
    assert calls == ["25.1", None]  # version first, then version-less fallback


def test_resolve_pypi_no_double_call_when_versionless(monkeypatch):
    from sbom.enrich import net

    calls = []
    monkeypatch.setattr(net, "_resolve_pypi_once", lambda n, v: calls.append(v) or None)
    assert net.resolve_pypi("missing", None) is None
    assert calls == [None]  # no redundant retry when already version-less


def test_collect_components_forces_full_scope(monkeypatch):
    # The cache must capture EVERY dep (build/test included), not just the release
    # runtime closure — so collection is forced to scope="all" regardless of input.
    from types import SimpleNamespace

    from sbom import refresh

    seen = {}

    def fake_run(cfg):
        seen["scope"] = cfg.scope
        seen["network"] = cfg.network
        return SimpleNamespace(components=[])

    monkeypatch.setattr("sbom.cli.run", fake_run)
    refresh._collect_components(Config(repo_root=Path("."), scope="release", network="on"))
    assert seen == {"scope": "all", "network": "off"}


def test_refresh_depsdev_cache_requires_network_on(tmp_path):
    from sbom import refresh

    cfg = Config(repo_root=Path("."), refresh_data="depsdev", network="off")
    assert refresh.run_refresh(cfg) == 1  # guard: needs --network on


def test_refresh_depsdev_cache_rejects_non_json_target(tmp_path):
    # A typo'd --depsdev-cache pointing at a curated YAML must be refused, not
    # overwritten with JSON (would destroy the file). Guard fires before collection.
    from sbom import refresh

    curated = tmp_path / "first_party.yaml"
    curated.write_text("opbase: ~\n")
    cfg = Config(
        repo_root=Path("."),
        repo_profile="generic",
        network="on",
        depsdev_cache=str(curated),
        refresh_data="depsdev",
    )
    assert refresh.run_refresh(cfg) == 1
    assert curated.read_text() == "opbase: ~\n"  # untouched


def test_refresh_depsdev_cache_writes_sorted_json(tmp_path, monkeypatch):
    from sbom import refresh
    from sbom.enrich import net

    monkeypatch.setattr(
        refresh,
        "_collect_components",
        lambda cfg: [
            Component(name="numpy", languages=["Python"]),
            Component(name="cpp_lib"),  # non-Python -> skipped
            Component(name="mystery", languages=["Python"]),  # resolve_pypi -> None
        ],
    )
    monkeypatch.setattr(
        net,
        "resolve_pypi",
        lambda name, version=None: (
            {"license": "BSD-3-Clause", "version": "2.0", "source": "test"}
            if name == "numpy"
            else None
        ),
    )
    cache = tmp_path / "nc.json"
    cfg = Config(
        repo_root=Path("."),
        repo_profile="generic",
        network="on",
        depsdev_cache=str(cache),
        refresh_data="depsdev",
    )
    assert refresh.run_refresh(cfg) == 0
    data = json.loads(cache.read_text())
    assert data["entries"]["pypi:numpy"]["license"] == "BSD-3-Clause"
    assert data["entries"]["pypi:numpy"]["fetched"]  # stamped
    assert "pypi:cpp_lib" not in data["entries"]  # non-Python skipped
    assert "pypi:mystery" not in data["entries"]  # unresolved skipped


def test_refresh_aliases_writes_suggestions(tmp_path, monkeypatch):
    from sbom import refresh
    from sbom.models import Observation, SourceKind

    obs = Observation(
        source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
        ecosystem_data={},
        canonical_url="https://example.com/zlib-1.3.tar.gz",
    )
    comp = Component(name="external_zlib_lib", observations=[obs])
    monkeypatch.setattr(refresh, "_collect_components", lambda cfg: [comp])

    suggested = tmp_path / "aliases.suggested.yaml"
    profile = _ExtraProfile(tmp_path / "aliases.yaml")
    (tmp_path / "aliases.yaml").write_text("")
    sources = build_data_sources(profile)
    cfg = Config(repo_root=Path("."), refresh_data="aliases")
    rc = refresh._refresh_aliases(cfg, profile, sources)
    assert rc == 0
    assert suggested.exists()
    assert "external_zlib_lib" in suggested.read_text()
    assert "zlib" in suggested.read_text()


def test_refresh_curated_validate_ok_and_detects_bad_spdx(tmp_path):
    from sbom import refresh

    good = tmp_path / "good.yaml"
    good.write_text("opbase: ~\nmetadef: LicenseRef-CANN-Open-Software-License-2.0\nzlib: Zlib\n")
    src_ok = [DataSource("first-party", CURATED, good, "yaml")]
    assert refresh._validate_curated("first-party", src_ok) == 0

    bad = tmp_path / "bad.yaml"
    bad.write_text("foo: Not-A-Real-SPDX-ID\nbar: MIT\n")
    src_bad = [DataSource("known-licenses", CURATED, bad, "yaml")]
    assert refresh._validate_curated("known-licenses", src_bad) == 1  # invalid SPDX flagged


def test_refresh_curated_detects_duplicate_keys(tmp_path):
    from sbom import refresh

    dup = tmp_path / "dup.yaml"
    # YAML keeps the last duplicate, but our reader sees them via round-trip? PyYAML
    # collapses duplicates, so emulate a case-collision instead (Foo vs foo).
    dup.write_text("Foo: MIT\nfoo: MIT\n")
    src = [DataSource("known-licenses", CURATED, dup, "yaml")]
    assert refresh._validate_curated("known-licenses", src) == 1


# ---------------------------------------------------------------------------
# CLI: --format single + --refresh-data dispatch
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# ClearlyDefined enricher + NTIA supplier
# ---------------------------------------------------------------------------

_CD_JSON = {
    "coordinates": {"type": "pypi", "provider": "pypi", "name": "numpy", "revision": "2.1.0"},
    "licensed": {
        "declared": "BSD-3-Clause",
        "facets": {"core": {"attribution": {"parties": ["Copyright (c) 2005 NumPy Developers", "NumFOCUS"]}}},
    },
    "described": {
        "sourceLocation": {"provider": "github", "namespace": "numpy", "name": "numpy", "url": "https://github.com/numpy/numpy"},
        "projectWebsite": "https://numpy.org",
    },
}


def test_cd_extract_pulls_clean_supplier_copyright_source_license():
    from sbom.enrich import clearlydefined

    out = clearlydefined._extract(_CD_JSON)
    assert out["supplier"] == "numpy"  # github org namespace (a real VCS provider)
    # Only the well-formed 'Copyright <year> ...' line survives; "NumFOCUS" (no year)
    # is noise and is dropped.
    assert out["copyright"] == "Copyright (c) 2005 NumPy Developers"
    assert out["source"] == "https://github.com/numpy/numpy"
    assert out["license"] == "BSD-3-Clause"


def test_cd_extract_skips_registry_namespace_and_noisy_parties():
    from sbom.enrich import clearlydefined

    # A real PyPI definition: provider=pypi (no org namespace), noisy auto-scan
    # parties -> NO supplier, NO copyright (only the declared license survives).
    pypi_def = {
        "licensed": {"declared": "MIT", "facets": {"core": {"attribution": {"parties": ["(c) N Revealed", "Stone Tickle"]}}}},
        "described": {"sourceLocation": {"provider": "pypi", "namespace": None, "name": "attrs", "url": "https://pypi.org/project/attrs/"}},
    }
    out = clearlydefined._extract(pypi_def)
    assert "supplier" not in out and "copyright" not in out
    assert out["license"] == "MIT"


def test_cd_extract_empty_returns_none():
    from sbom.enrich import clearlydefined

    assert clearlydefined._extract({}) is None


def test_cd_component_key_and_coordinates():
    from sbom.enrich import clearlydefined

    py = Component(name="NumPy", languages=["Python"], effective_version="2.1.0")
    cpp = Component(name="dlog")
    assert clearlydefined.component_key(py) == "pypi:numpy"
    assert clearlydefined.component_key(cpp) is None
    assert clearlydefined.coordinates_for(py, "2.1.0") == "pypi/pypi/-/numpy/2.1.0"
    assert clearlydefined.coordinates_for(py, None) is None  # needs a revision
    assert clearlydefined.coordinates_for(cpp, "1.0") is None  # non-PyPI


def test_cd_apply_fills_supplier_and_copyright_python_only():
    from sbom.enrich import clearlydefined

    cache = {"pypi:numpy": {"supplier": "numpy", "copyright": "(c) NumPy"}, "pypi:dlog": {"supplier": "x"}}
    py = Component(name="numpy", languages=["Python"])
    cpp = Component(name="dlog")  # same-name PyPI must NOT apply to a C++ comp
    preset = Component(name="attrs", languages=["Python"], supplier="ExistingCorp")
    clearlydefined.apply([py, cpp, preset], {**cache, "pypi:attrs": {"supplier": "Other"}})
    assert py.supplier == "numpy" and py.copyright == "(c) NumPy"
    assert [p.source for p in py.provenance if p.field == "supplier"] == ["clearlydefined"]
    assert cpp.supplier is None  # non-Python skipped (no purl_map)
    assert preset.supplier == "ExistingCorp"  # not overwritten


def test_cd_cpp_key_and_apply_via_purl_map():
    from sbom.enrich import clearlydefined

    pm = {"protobuf": "pkg:github/protocolbuffers/protobuf", "eigen": "pkg:gitlab/libeigen/eigen"}
    cpp = Component(name="protobuf")  # C++ (no Python language)
    assert clearlydefined.component_key(cpp, pm) == "github:protocolbuffers/protobuf"
    # without the purl_map a C++ component has no key (the old behavior)
    assert clearlydefined.component_key(cpp) is None
    # apply fills C++ copyright + supplier from the git-coordinate-keyed entry
    cache = {"github:protocolbuffers/protobuf": {"copyright": "Copyright 2016 Google", "supplier": "protocolbuffers"}}
    clearlydefined.apply([cpp], cache, pm)
    assert cpp.copyright == "Copyright 2016 Google" and cpp.supplier == "protocolbuffers"


def test_cd_git_coordinates_resolves_tag_to_sha(monkeypatch):
    import subprocess

    from sbom.enrich import clearlydefined

    class _R:
        def __init__(self, out):
            self.stdout = out

    def fake_run(args, **kw):
        ref = args[-1]  # only the v-prefixed tag exists
        return _R("abc123def\trefs/tags/v3.13.0\n" if ref == "refs/tags/v3.13.0" else "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert (
        clearlydefined.git_coordinates("pkg:github/protocolbuffers/protobuf", "3.13.0")
        == "git/github/protocolbuffers/protobuf/abc123def"
    )


def test_cd_git_coordinates_none_for_non_git_or_unversioned():
    from sbom.enrich import clearlydefined

    assert clearlydefined.git_coordinates("pkg:generic/foo", "1.0") is None  # not a git host
    assert clearlydefined.git_coordinates("pkg:github/o/r", None) is None  # no version


class _SupplierProfile(Profile):
    name = "sup"

    def first_party_supplier(self):
        return "Acme Corp"

    def component_provenance(self, component):
        return "first-party" if component.name == "internal" else None


def test_resolve_suppliers_fills_first_party_and_subjects():
    from sbom.collectors import CollectResult
    from sbom.models import Identity, SubjectKind, SubjectRole
    from sbom.reconcile import reconcile

    internal = Component(name="internal")  # provenance -> first-party
    external = Component(name="boost", license="BSL-1.0")  # third-party
    subj = Subject(id="pkg", identity=Identity(SubjectKind.PYTHON_WHEEL, "pkg", "1.0"), role=SubjectRole.PRIMARY)
    doc = reconcile([CollectResult(components=[internal, external])], [subj], Config(repo_root=Path("."), scope="all"), _SupplierProfile())
    assert next(c for c in doc.components if c.name == "internal").supplier == "Acme Corp"
    assert next(c for c in doc.components if c.name == "boost").supplier is None  # third-party left for CD
    assert doc.subjects[0].supplier == "Acme Corp"  # repo-owned subject


def test_first_party_supplier_overrides_depsdev_cache_author(tmp_path):
    # Regression: a first-party Python component on PyPI must get the PROFILE org,
    # not the depsdev PyPI author (which the license layer sets first). The
    # profile supplier is authoritative and runs LAST.
    from sbom.collectors import CollectResult
    from sbom.reconcile import reconcile

    cache = tmp_path / "nc.json"
    cache.write_text(json.dumps({"schema": 1, "entries": {"pypi:mylib": {"license": "MIT", "supplier": "Some PyPI Author"}}}))

    class _P(Profile):
        def first_party_supplier(self):
            return "Acme Corp"

        def component_provenance(self, component):
            return "first-party" if component.name == "mylib" else None

    mylib = Component(name="mylib", languages=["Python"])
    cfg = Config(repo_root=Path("."), network="off", depsdev_cache=str(cache), scope="all")
    doc = reconcile([CollectResult(components=[mylib])], [], cfg, _P())
    assert next(c for c in doc.components if c.name == "mylib").supplier == "Acme Corp"


def test_cd_extract_drops_entityless_copyright():
    from sbom.enrich import clearlydefined

    # "Copyright 2026" (year, no entity) is noise -> dropped; a real holder is kept.
    d = {
        "licensed": {"declared": "MIT", "facets": {"core": {"attribution": {"parties": ["Copyright 2026", "Copyright 2017 The Abseil Authors"]}}}},
        "described": {},
    }
    out = clearlydefined._extract(d)
    assert out["copyright"] == "Copyright 2017 The Abseil Authors"


def test_supplier_whitespace_treated_as_unknown(tmp_path):
    from sbom.emit import EmitOptions, cyclonedx, spdx, validate
    from sbom.models import Document, Identity, SubjectKind, SubjectRole

    opts = EmitOptions(reproducible=True)
    primary = Subject(id="pkg", identity=Identity(SubjectKind.PYTHON_WHEEL, "pkg", "1.0.0"), role=SubjectRole.PRIMARY)
    doc = Document(subjects=[primary], components=[Component(name="x", languages=["Python"], supplier="   ")], edges=[], environment_tools=[], metadata={})
    cdx = json.loads(cyclonedx.emit(doc, opts))
    assert validate.validate_cyclonedx(json.dumps(cdx)) == []
    assert next(c for c in cdx["components"] if c["name"] == "x").get("supplier") is None
    sp = json.loads(spdx.emit(doc, opts))
    assert next(p for p in sp["packages"] if p["name"] == "x")["supplier"] == "NOASSERTION"


def test_refresh_clearlydefined_writes_supplier(tmp_path, monkeypatch):
    from sbom import refresh
    from sbom.enrich import clearlydefined

    monkeypatch.setattr(
        refresh, "_collect_components",
        lambda cfg: [Component(name="numpy", languages=["Python"], effective_version="2.1.0"), Component(name="cpp_lib")],
    )
    monkeypatch.setattr(clearlydefined, "resolve", lambda coords: {"supplier": "numpy", "copyright": "(c) NumPy", "license": "BSD-3-Clause"})
    cache = tmp_path / "cd.json"

    class _Prof(Profile):
        def data_sources(self):
            return [DataSource("clearlydefined", NETWORK, cache, "json")]

    cfg = Config(repo_root=Path("."), network="on", refresh_data="clearlydefined")
    from sbom.data_sources import build_data_sources

    assert refresh._refresh_clearlydefined(cfg, _Prof(), build_data_sources(_Prof())) == 0
    data = json.loads(cache.read_text())
    assert data["entries"]["pypi:numpy"]["supplier"] == "numpy"
    assert data["entries"]["pypi:numpy"]["coordinates"] == "pypi/pypi/-/numpy/2.1.0"
    assert "pypi:cpp_lib" not in data["entries"]


def test_refresh_clearlydefined_requires_network_on(tmp_path):
    from sbom import refresh
    from sbom.data_sources import build_data_sources

    cfg = Config(repo_root=Path("."), repo_profile="generic", refresh_data="clearlydefined", network="off")
    assert refresh._refresh_clearlydefined(cfg, GenericProfile(), build_data_sources(GenericProfile())) == 1


def test_supplier_emitted_in_both_formats(tmp_path):
    from sbom.emit import EmitOptions, cyclonedx, spdx, validate
    from sbom.models import Document, Identity, SubjectKind, SubjectRole

    opts = EmitOptions(reproducible=True)
    primary = Subject(id="pkg", identity=Identity(SubjectKind.PYTHON_WHEEL, "pkg", "1.0.0"), role=SubjectRole.PRIMARY, supplier="Huawei")
    doc = Document(subjects=[primary], components=[Component(name="numpy", languages=["Python"], supplier="NumFOCUS"), Component(name="x")], edges=[], environment_tools=[], metadata={})

    cdx = json.loads(cyclonedx.emit(doc, opts))
    assert validate.validate_cyclonedx(json.dumps(cdx)) == []
    sup = {c["name"]: (c.get("supplier") or {}).get("name") for c in cdx["components"]}
    assert sup["numpy"] == "NumFOCUS" and sup["x"] is None
    assert cdx["metadata"]["component"]["supplier"]["name"] == "Huawei"

    sp = json.loads(spdx.emit(doc, opts))
    assert validate.validate_spdx(json.dumps(sp)) == []
    spd = {p["name"]: p.get("supplier") for p in sp["packages"]}
    assert spd["numpy"] == "Organization: NumFOCUS"
    assert spd["x"] == "NOASSERTION"  # known-unknown, present (NTIA)


# ---------------------------------------------------------------------------
# C++ component PURLs (curated upstream > download_url > first-party vcs_url)
# ---------------------------------------------------------------------------


class _PurlProfile(Profile):
    name = "purl"

    def __init__(self, purl_yaml):
        self._p = purl_yaml

    def data_sources(self):
        return [DataSource("third-party-purls", CURATED, self._p, "yaml")]


def test_component_purl_curated_upstream(tmp_path):
    from sbom.reconcile import _resolve_component_purls

    pmap = tmp_path / "tpp.yaml"
    pmap.write_text("protobuf: pkg:github/protocolbuffers/protobuf\neigen: pkg:gitlab/libeigen/eigen\n")
    protobuf = Component(name="protobuf", effective_version="3.13.0")
    eigen = Component(name="eigen", source_version="5.0.0")
    _resolve_component_purls([protobuf, eigen], [], _PurlProfile(pmap))
    assert protobuf.purl == "pkg:github/protocolbuffers/protobuf@3.13.0"
    assert eigen.purl == "pkg:gitlab/libeigen/eigen@5.0.0"


def test_component_purl_curated_upstream_sets_supplier_from_namespace(tmp_path):
    # The curated coordinate's org (namespace) becomes the NTIA supplier for a C++
    # third-party (ClearlyDefined can't reach these — keyed by git SHA we lack).
    from sbom.reconcile import _resolve_component_purls

    pmap = tmp_path / "tpp.yaml"
    pmap.write_text("protobuf: pkg:github/protocolbuffers/protobuf\n")
    comp = Component(name="protobuf", effective_version="3.13.0")
    _resolve_component_purls([comp], [], _PurlProfile(pmap))
    assert comp.supplier == "protocolbuffers"
    assert [p.source for p in comp.provenance if p.field == "supplier"] == ["upstream-purl"]


def test_component_purl_does_not_override_existing_supplier(tmp_path):
    from sbom.reconcile import _resolve_component_purls

    pmap = tmp_path / "tpp.yaml"
    pmap.write_text("protobuf: pkg:github/protocolbuffers/protobuf\n")
    comp = Component(name="protobuf", effective_version="3.13.0", supplier="Already Set")
    _resolve_component_purls([comp], [], _PurlProfile(pmap))
    assert comp.supplier == "Already Set"  # an existing supplier wins


def test_component_purl_download_url_fallback(tmp_path):
    from sbom.models import Observation, SourceKind
    from sbom.reconcile import _resolve_component_purls

    pmap = tmp_path / "tpp.yaml"
    pmap.write_text("")
    obs = Observation(
        source_kind=SourceKind.CMAKE_EXTERNAL_PROJECT,
        ecosystem_data={},
        canonical_url="https://mirror.example.com/x/mockcpp-2.7.tar.gz",
    )
    comp = Component(name="mockcpp", effective_version="2.7", observations=[obs], checksums={"sha256": "abc123"})
    _resolve_component_purls([comp], [], _PurlProfile(pmap))
    assert comp.purl.startswith("pkg:generic/mockcpp@2.7?")
    assert "download_url=" in comp.purl and "checksum=" in comp.purl


def test_component_purl_first_party_vcs(tmp_path):
    from sbom.models import Identity, SubjectKind, SubjectRole
    from sbom.reconcile import _resolve_component_purls

    pmap = tmp_path / "tpp.yaml"
    pmap.write_text("")
    subj = Subject(id="pkg", identity=Identity(SubjectKind.PYTHON_WHEEL, "pkg", "1.0"), role=SubjectRole.PRIMARY)
    subj.vcs_url = "git+https://gitcode.com/cann/ops-math.git@abc123"
    comp = Component(name="platform")
    comp.origin = "first-party"
    _resolve_component_purls([comp], [subj], _PurlProfile(pmap))
    assert comp.purl.startswith("pkg:generic/platform?")
    assert "vcs_url=" in comp.purl


def test_component_purl_system_left_none_and_python_untouched(tmp_path):
    from sbom.reconcile import _resolve_component_purls

    pmap = tmp_path / "tpp.yaml"
    pmap.write_text("")
    system = Component(name="Threads")
    system.origin = "unknown"
    py = Component(name="numpy", languages=["Python"])
    _resolve_component_purls([system, py], [], _PurlProfile(pmap))
    assert system.purl is None  # no curated/url/first-party -> honest, name is the key
    assert py.purl is None  # Python purl is derived at emit, not stamped here


def test_cpp_component_purl_emitted_in_both_formats(tmp_path):
    from sbom.emit import EmitOptions, cyclonedx, spdx, validate
    from sbom.models import Document, Identity, SubjectKind, SubjectRole

    opts = EmitOptions(reproducible=True)
    primary = Subject(id="pkg", identity=Identity(SubjectKind.PYTHON_WHEEL, "pkg", "1.0.0"), role=SubjectRole.PRIMARY)
    comp = Component(name="protobuf")
    comp.purl = "pkg:github/protocolbuffers/protobuf@3.13.0"
    doc = Document(subjects=[primary], components=[comp], edges=[], environment_tools=[], metadata={})

    cdx = json.loads(cyclonedx.emit(doc, opts))
    assert validate.validate_cyclonedx(json.dumps(cdx)) == []
    assert next(c for c in cdx["components"] if c["name"] == "protobuf")["purl"] == "pkg:github/protocolbuffers/protobuf@3.13.0"

    sp = json.loads(spdx.emit(doc, opts))
    assert validate.validate_spdx(json.dumps(sp)) == []
    p = next(p for p in sp["packages"] if p["name"] == "protobuf")
    purls = [r["referenceLocator"] for r in p.get("externalRefs", []) if r["referenceType"] == "purl"]
    assert purls == ["pkg:github/protocolbuffers/protobuf@3.13.0"]


def test_cli_format_single_emits_only_one(tmp_path):
    from sbom import cli

    rc = cli.main(
        [
            "--repo-root", ".",
            "--repo-profile", "generic",
            "--format", "spdx",
            "--reproducible",
            "--out-dir", str(tmp_path),
        ]
    )
    written = {p.name for p in tmp_path.iterdir()}
    assert any(n.endswith(".spdx.json") for n in written)
    assert not any(n.endswith(".cdx.json") for n in written)
    assert rc in (0, 2)  # 0 ok, 2 validation (env-dependent), never fatal


def test_cli_refresh_data_dispatches_and_skips_emit(tmp_path, monkeypatch):
    from sbom import cli, refresh

    called = {}

    def fake_refresh(config):
        called["source"] = config.refresh_data
        return 0

    monkeypatch.setattr(refresh, "run_refresh", fake_refresh)
    rc = cli.main(["--repo-root", ".", "--repo-profile", "generic", "--refresh-data", "first-party"])
    assert rc == 0 and called["source"] == "first-party"
    # no SBOM written
    assert not list(tmp_path.iterdir())
