"""Known-license map enricher (layer 2 of the layered resolver).

Loads ``data/known_licenses.yaml`` (or an override path) and resolves
component names (plus aliases) to SPDX expressions. Does NOT override a
curated value already present on a component (curated wins — layer 1).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from ..models import Component, Provenance, Warning

#: Default path to the bundled map, relative to this file.
_DEFAULT_MAP_PATH = Path(__file__).parent.parent / "data" / "known_licenses.yaml"


def load_map(path: Path | None = None) -> dict[str, str]:
    """Load ``data/known_licenses.yaml`` (or an override path).

    Returns a mapping of lowercased component name (or alias) to SPDX
    expression string.  Keys from the YAML file are lowercased so lookups
    are case-insensitive.
    """
    target = path if path is not None else _DEFAULT_MAP_PATH
    with open(target, encoding="utf-8") as fh:
        raw: dict = yaml.safe_load(fh) or {}
    # Normalize keys to lowercase for case-insensitive lookup.
    return {k.lower(): v for k, v in raw.items()}


def apply(components: list[Component], license_map: dict[str, str]) -> list[Warning]:
    """Set ``component.license`` from the map when not already curated.

    Alias-aware: checks ``component.name`` first, then each alias in
    ``component.aliases`` (all lowercased).  Records a
    ``Provenance(field="license", source="known_licenses.yaml")`` when a
    value is set.  Returns any diagnostic :class:`~sbom.models.Warning`
    records (currently none — missing is handled upstream as NOASSERTION).
    """
    warnings: list[Warning] = []
    for comp in components:
        # Curated layer (layer 1) has already run — if license is set, skip.
        if comp.license is not None:
            continue

        # Build the candidate lookup keys: canonical name + all aliases.
        candidates = [comp.name.lower()] + [a.lower() for a in comp.aliases]
        for key in candidates:
            spdx_expr = license_map.get(key)
            if spdx_expr is not None:
                comp.license = spdx_expr
                comp.provenance.append(
                    Provenance(field="license", source="known_licenses.yaml")
                )
                break  # first match wins; stop checking aliases

    return warnings
