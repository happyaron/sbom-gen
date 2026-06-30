"""``--refresh-data`` actions — regenerate / validate the vendored data files.

Dispatched from :func:`sbom.cli.main` when ``config.refresh_data`` is set; emits
no SBOM. Per data-source kind:

* ``depsdev`` (network) — collect the repo's Python deps, (re-)fetch each
  license/version live from deps.dev/PyPI, and rewrite the cache JSON. The ONLY
  writer of the cache (normal runs read it). Requires ``--network on``.
* ``aliases`` (derived) — run the URL-based derivation and write any NEW
  ``raw -> canonical`` suggestions to ``<aliases>.suggested.yaml`` for human
  review (never auto-merged into the curated map).
* ``first-party`` / ``known-licenses`` (curated) — validate only: report
  duplicate keys and invalid SPDX values. NOT rewritten — these carry curated
  section comments that an automated dump would destroy.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config

_ALL = ["depsdev", "clearlydefined", "aliases", "first-party", "known-licenses"]


def run_refresh(config: "Config") -> int:
    """Run ``config.refresh_data`` (a source name or ``"all"``) and return an exit
    code (0 ok; non-zero if a validation issue or a hard error was found)."""
    from .data_sources import build_data_sources
    from .profile import get_profile

    profile, _ = get_profile(config.repo_profile, config.repo_root)
    sources = build_data_sources(profile)

    target = config.refresh_data
    names = _ALL if target == "all" else [target]

    rc = 0
    for name in names:
        if name == "depsdev":
            rc |= _refresh_depsdev_cache(config, profile, sources)
        elif name == "clearlydefined":
            rc |= _refresh_clearlydefined(config, profile, sources)
        elif name == "deps-dir":
            rc |= _refresh_deps_dir_cache(config, profile, sources)
        elif name == "aliases":
            rc |= _refresh_aliases(config, profile, sources)
        else:  # first-party | known-licenses
            rc |= _validate_curated(name, sources)
    return rc


def _collect_components(config: "Config"):
    """Run the pipeline (network OFF, FULL scope) to enumerate every component.

    Forces ``scope="all"`` so the cache/derivation sees EVERY dependency — build,
    test and example Python deps included — not just the release-view runtime
    closure. The cache is scope-agnostic knowledge: a later release-view run still
    only consults entries for deps it actually has."""
    from .cli import run

    return run(replace(config, refresh_data=None, network="off", scope="all")).components


# ---------------------------------------------------------------------------
# depsdev — re-fetch live and rewrite the JSON
# ---------------------------------------------------------------------------


def _refresh_depsdev_cache(config: "Config", profile, sources) -> int:
    from .data_sources import sources_named
    from .enrich import net, depsdev_cache

    if getattr(config, "network", "off") != "on":
        print(
            "sbom: --refresh-data depsdev requires --network on",
            file=sys.stderr,
        )
        return 1

    nc_sources = sources_named(sources, "depsdev")
    if config.depsdev_cache:
        write_path = Path(config.depsdev_cache)
    elif nc_sources:
        write_path = nc_sources[-1].path  # profile override if present, else core
    else:
        print("sbom: no depsdev data source to write", file=sys.stderr)
        return 1

    # Guard against a typo'd --depsdev-cache clobbering a curated YAML data file:
    # the cache is JSON, so refuse any non-.json target.
    if write_path.suffix != ".json":
        print(
            f"sbom: --refresh-data depsdev target must be a .json file, "
            f"got {write_path} (refusing to overwrite a non-cache file)",
            file=sys.stderr,
        )
        return 1

    components = _collect_components(config)
    entries = depsdev_cache.load([write_path])  # preserve existing, upsert below
    today = date.today().isoformat()
    resolved = unresolved = 0
    for comp in components:
        if "Python" not in (comp.languages or []):
            continue
        version = comp.effective_version or comp.source_version
        res = net.resolve_pypi(comp.name, version)
        if res is None:
            unresolved += 1
            continue
        supplier = net.pypi_supplier(comp.name, res.get("version") or version)
        entry = {**res, "fetched": today}
        if supplier:
            entry["supplier"] = supplier
        entries[depsdev_cache.cache_key(comp.name)] = entry
        resolved += 1

    write_path.parent.mkdir(parents=True, exist_ok=True)
    write_path.write_text(depsdev_cache.dump(entries), encoding="utf-8")
    print(
        f"sbom: depsdev refreshed: {resolved} resolved, {unresolved} "
        f"unresolved, {len(entries)} total -> {write_path}"
    )
    if unresolved:
        # A transient network failure is indistinguishable from a genuinely
        # missing license here; re-running merges (upsert preserves prior hits).
        print(
            f"sbom: note: {unresolved} dep(s) unresolved — if the network was "
            "flaky, re-run to fill them (existing entries are preserved)."
        )
    return 0


# ---------------------------------------------------------------------------
# clearlydefined — re-fetch supplier/copyright and rewrite the JSON
# ---------------------------------------------------------------------------


def _refresh_clearlydefined(config: "Config", profile, sources) -> int:
    from .data_sources import sources_named
    from .enrich import clearlydefined, net

    if getattr(config, "network", "off") != "on":
        print(
            "sbom: --refresh-data clearlydefined requires --network on",
            file=sys.stderr,
        )
        return 1

    cd_sources = sources_named(sources, "clearlydefined")
    if not cd_sources:
        print("sbom: no clearlydefined data source to write", file=sys.stderr)
        return 1
    write_path = cd_sources[-1].path
    if write_path.suffix != ".json":
        print(
            f"sbom: clearlydefined cache target must be a .json file, got {write_path}",
            file=sys.stderr,
        )
        return 1

    from .reconcile import _load_third_party_purls

    purl_map = _load_third_party_purls(profile)
    components = _collect_components(config)
    entries = clearlydefined.load([write_path])
    today = date.today().isoformat()
    resolved = unresolved = skipped = 0
    for comp in components:
        key = clearlydefined.component_key(comp, purl_map)
        if key is None:  # neither a PyPI dep nor a curated-coordinate C++ third-party
            skipped += 1
            continue
        version = comp.effective_version or comp.source_version
        if key.startswith("pypi:"):
            if version is None:
                # CD coordinates need a revision; borrow the version a live PyPI
                # lookup resolves (latest) when the dep is unpinned.
                net_res = net.resolve_pypi(comp.name)
                version = net_res.get("version") if net_res else None
            coords = clearlydefined.coordinates_for(comp, version)
        else:
            # C++ third-party: resolve the curated coordinate's version tag -> git
            # SHA (the form CD harvests under).
            coord = next(
                (purl_map.get(n.lower()) for n in (comp.name, *comp.aliases) if purl_map.get(n.lower())),
                None,
            )
            coords = clearlydefined.git_coordinates(coord, version) if coord else None
        if coords is None:
            unresolved += 1
            continue
        data = clearlydefined.resolve(coords)
        if not data:
            unresolved += 1
            continue
        entries[key] = {**data, "coordinates": coords, "fetched": today}
        resolved += 1

    write_path.parent.mkdir(parents=True, exist_ok=True)
    write_path.write_text(clearlydefined.dump(entries), encoding="utf-8")
    print(
        f"sbom: clearlydefined refreshed: {resolved} resolved, {unresolved} "
        f"unresolved, {len(entries)} total -> {write_path}"
    )
    if unresolved:
        print(
            f"sbom: note: {unresolved} dep(s) unresolved — ClearlyDefined may not "
            "have harvested them yet, or the network was flaky; re-run to retry."
        )
    return 0


# ---------------------------------------------------------------------------
# deps-dir — scan on-disk dependency sources and rewrite the JSON
# ---------------------------------------------------------------------------


def _refresh_deps_dir_cache(config: "Config", profile, sources) -> int:
    """Walk the ``--deps-dir`` tree, resolve each dependency's license + copyright
    from its REAL source on disk (manifest / LICENSE scan, plus ScanCode when
    ``--scancode`` is set for the hard cases), and rewrite the deps-dir cache.

    TREE-DRIVEN: every dependency directory under ``--deps-dir`` is seeded (not just
    one repo's subset), keyed by directory name. For a git mirror the LATEST version
    branch is scanned (license is version-stable; the version is recorded for
    provenance). Offline — no network required."""
    from .data_sources import sources_named
    from .enrich import deps_dir, deps_dir_cache
    from .models import Component

    deps_root_str = getattr(config, "deps_dir", None)
    if not deps_root_str:
        print("sbom: --refresh-data deps-dir requires --deps-dir PATH", file=sys.stderr)
        return 1
    deps_root = Path(deps_root_str)
    if not deps_root.is_dir():
        print(f"sbom: --deps-dir {deps_root} is not a directory", file=sys.stderr)
        return 1

    dd_sources = sources_named(sources, "deps-dir")
    if not dd_sources:
        print("sbom: no deps-dir data source to write", file=sys.stderr)
        return 1
    write_path = dd_sources[-1].path  # profile override if present, else core
    if write_path.suffix != ".json":
        print(f"sbom: deps-dir cache target must be a .json file, got {write_path}", file=sys.stderr)
        return 1

    runner = None
    if getattr(config, "scancode", None) in ("enrich", "fallback", "both"):
        from .enrich import scancode as sc

        runner = sc.ScancodeRunner(getattr(config, "scancode_path", None))
        if not runner.available():
            print(f"sbom: note: {runner.unavailable_detail}; seeding without ScanCode")
            runner = None

    entries = deps_dir_cache.load([write_path])
    resolved = 0
    unresolved: list[str] = []
    today = date.today().isoformat()

    for child in sorted(deps_root.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        version = deps_dir.latest_version(child)
        comp = Component(name=child.name, effective_version=version)
        rs, _warn = deps_dir.resolve_source(comp, deps_root)
        if rs is None:
            unresolved.append(child.name)
            continue
        # License precedence at SEED time: upstream declaration (Readme.opensource
        # manifest) > the conflict-aware heuristic > ScanCode. The heuristic sits
        # ABOVE ScanCode deliberately: for a MULTI-license dir (eigen ships a bare
        # LICENSE=MPL-2.0 plus COPYING.APACHE/BSD/…) ScanCode's aggregate picks the
        # highest-score license FILE, which is order-dependent and may land on a
        # BUNDLED license; the heuristic deterministically prefers the bare canonical
        # LICENSE (the declared primary) and returns None when genuinely ambiguous.
        # ScanCode is the FALLBACK that resolves the deps whose license the heuristic
        # cannot recognize (unusual text, license nested below the surface). Copyright
        # prefers the curated manifest holders, then ScanCode's detected holders.
        license_id = None
        copyright_txt = None
        if rs.manifest is not None:
            license_id = rs.manifest.resolved_license()
            copyright_txt = rs.manifest.copyright_text()
        if license_id is None and rs.path is not None:
            license_id = deps_dir._scan_license_dir(rs.path)[0]
        if rs.path is not None and (license_id is None or not copyright_txt) and runner is not None:
            # One recursive invocation over the already-bounded materialized dir
            # (per-file scan_paths is far too slow across dozens of deps).
            res = runner.scan_tree(rs.path)
            if res is not None:
                if license_id is None and res.spdx_license_expression:
                    license_id = res.spdx_license_expression
                if not copyright_txt and res.copyright_summary():
                    copyright_txt = res.copyright_summary()
        rs.cleanup()

        if not (license_id or copyright_txt):
            unresolved.append(child.name)
            continue
        entry = {
            k: v
            for k, v in {
                "license": license_id,
                "copyright": copyright_txt,
                "version": version,
                "source": rs.origin,
                "fetched": today,
            }.items()
            if v
        }
        entries[deps_dir_cache.cache_key(child.name)] = entry
        resolved += 1

    write_path.parent.mkdir(parents=True, exist_ok=True)
    write_path.write_text(deps_dir_cache.dump(entries), encoding="utf-8")
    print(
        f"sbom: deps-dir refreshed: {resolved} resolved, {len(unresolved)} "
        f"unresolved, {len(entries)} total -> {write_path}"
    )
    if unresolved:
        print(f"sbom: note: unresolved (no license/copyright found): {unresolved}")
    return 0


# ---------------------------------------------------------------------------
# aliases — derive suggestions for review
# ---------------------------------------------------------------------------


def _refresh_aliases(config: "Config", profile, sources) -> int:
    from .data_sources import sources_named
    from .reconcile import _derive_aliases

    al_sources = sources_named(sources, "aliases")
    if not al_sources:
        print("sbom: profile exposes no 'aliases' data source", file=sys.stderr)
        return 1

    components = _collect_components(config)
    derived = _derive_aliases(components)  # raw spelling -> upstream canonical

    try:
        existing = {k.lower() for k in profile.alias_map()}
    except Exception:  # noqa: BLE001
        existing = set()

    suggestions = {
        spelling: upstream
        for spelling, upstream in sorted(derived.items())
        if spelling != upstream and spelling.lower() not in existing
    }

    out_path = al_sources[-1].path.with_suffix(".suggested.yaml")
    if not suggestions:
        print("sbom: aliases: no new suggestions (derivation matched the curated map)")
        return 0
    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Auto-derived alias suggestions -- REVIEW, then merge into aliases.yaml.",
        "# Generated by: sbom --refresh-data aliases  (relation guessed as 'link').",
        "",
    ]
    lines += [
        f"{spelling}: {{canonical: {upstream}, relation: link}}"
        for spelling, upstream in suggestions.items()
    ]
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"sbom: aliases: {len(suggestions)} suggestion(s) -> {out_path}")
    return 0


# ---------------------------------------------------------------------------
# curated — validate only (never rewrite: would destroy curated comments)
# ---------------------------------------------------------------------------


def _validate_curated(name: str, sources) -> int:
    import yaml

    from .data_sources import sources_named
    from .enrich.licenseref import is_spdx_expression

    srcs = [s for s in sources_named(sources, name) if s.path.exists()]
    if not srcs:
        print(f"sbom: {name}: no data source present")
        return 0

    issues = 0
    for s in srcs:
        try:
            raw = yaml.safe_load(s.path.read_text(encoding="utf-8")) or {}
        except Exception as exc:  # noqa: BLE001
            print(f"sbom: {name}: cannot parse {s.path}: {exc}", file=sys.stderr)
            issues += 1
            continue
        if not isinstance(raw, dict):
            continue

        seen: dict[str, str] = {}
        for key in raw:
            lk = str(key).lower()
            if lk in seen:
                print(f"sbom: {name}: {s.path.name}: duplicate key {key!r} (vs {seen[lk]!r})")
                issues += 1
            seen[lk] = str(key)

        for key, value in raw.items():
            if value is None:
                continue  # null = first-party-but-unlicensed (intentional)
            val = str(value)
            if val == "NOASSERTION" or val.startswith("LicenseRef-"):
                continue
            if not is_spdx_expression(val):
                print(f"sbom: {name}: {s.path.name}: {key!r} -> invalid SPDX: {val!r}")
                issues += 1

    if issues == 0:
        print(f"sbom: {name}: OK ({len(srcs)} file(s) validated)")
    return 1 if issues else 0
