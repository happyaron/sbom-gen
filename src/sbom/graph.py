"""Dependency-graph helpers shared by the collectors, reconcile, and emit.

Centralizes the edge-identity and subject-closure logic that was previously
duplicated — and drifted — across ``collectors/cpp.py``, ``reconcile.py`` and the
emitters (the F1/F3 review findings were both "two places computing the same
thing slightly differently"). Keeping the definitions here means the collector,
reconcile and emit share ONE source of truth and cannot diverge again.

Two edge identities are exposed, intentionally DISTINCT:

* :func:`semantic_edge_key` — "is this the same dependency *relationship*?" Keys on
  the endpoints + relation + the SEMANTIC axes (``usage_scope`` and
  ``declaration_reachability``). A collector dedups on this to collapse
  provenance-only duplicates (the same edge declared in two ``.cmake`` files) into
  one clean graph edge, WITHOUT collapsing a runtime vs. build/test variant.
* :func:`exact_edge_key` — the semantic key PLUS ``source_file`` /
  ``source_revision``. Reconcile dedups on this to drop byte-identical edges while
  preserving distinct evidence sites for provenance.
"""

from __future__ import annotations

from typing import Callable, Iterable

from .models import DependencyEdge, RefKind


def semantic_edge_key(edge: DependencyEdge) -> tuple:
    """Identity of an edge's MEANING: endpoints + relation + scope + reachability.

    Two edges with this same key are the same dependency relationship and differ
    only in provenance — a collector collapses them to one graph edge."""
    return (
        edge.root_artifact_id,
        edge.from_ref.kind,
        edge.from_ref.id,
        edge.to_ref.kind,
        edge.to_ref.id,
        edge.relation_type,
        edge.usage_scope,
        edge.declaration_reachability,
    )


def exact_edge_key(edge: DependencyEdge) -> tuple:
    """Byte-identity of an edge: :func:`semantic_edge_key` PLUS provenance
    (``source_file`` + ``source_revision``), so two distinct evidence sites for the
    same relationship both survive reconcile's exact-duplicate dedup."""
    return semantic_edge_key(edge) + (edge.source_file, edge.source_revision)


def _is_self_loop(edge: DependencyEdge) -> bool:
    return edge.from_ref.kind is edge.to_ref.kind and edge.from_ref.id == edge.to_ref.id


def dedup_edges(
    edges: Iterable[DependencyEdge],
    *,
    key: Callable[[DependencyEdge], tuple],
) -> list[DependencyEdge]:
    """Drop self-loops and edges duplicate under ``key``; first wins, order kept.

    A self-loop (``from_ref == to_ref``) is never a real relationship — it arises
    when an alias collapses an endpoint onto its own owner — so it is removed. Pass
    :func:`semantic_edge_key` for collector dedup or :func:`exact_edge_key` for
    reconcile's exact-duplicate dedup."""
    seen: set[tuple] = set()
    out: list[DependencyEdge] = []
    for edge in edges:
        if _is_self_loop(edge):
            continue
        identity = key(edge)
        if identity in seen:
            continue
        seen.add(identity)
        out.append(edge)
    return out


def reachable_components(
    edges: Iterable[DependencyEdge], subject_ids: Iterable[str]
) -> set[str]:
    """BFS over ``edges`` from the given subject ids; return the set of reachable
    COMPONENT names (the ``Ref.id`` of every reachable component-kind node).

    The dependency-closure core shared by ``--subjects`` (reconcile) and
    ``--split-subjects`` (emit) so both compute the SAME closure: a per-subject
    split BOM and a ``--subjects`` filter keep exactly the components reachable
    from their subject(s) over the edge graph.

    OWNERSHIP-SCOPED: only edges OWNED by the selected subjects
    (``root_artifact_id`` in ``subject_ids``) plus GLOBAL edges
    (``root_artifact_id is None``) are traversed. ``root_artifact_id`` records
    *whose* dependency an edge is, so a component ``shared`` used by two subjects
    does not leak ``app2``'s exclusive ``shared -> app2-only`` edge into ``app1``'s
    closure — that edge is owned by ``app2``."""
    owned = set(subject_ids)
    adjacency: dict[tuple[RefKind, str], list[tuple[RefKind, str]]] = {}
    for edge in edges:
        if edge.root_artifact_id is not None and edge.root_artifact_id not in owned:
            continue  # another subject's dependency — not part of this closure
        adjacency.setdefault((edge.from_ref.kind, edge.from_ref.id), []).append(
            (edge.to_ref.kind, edge.to_ref.id)
        )
    reachable: set[str] = set()
    seen: set[tuple[RefKind, str]] = set()
    frontier: list[tuple[RefKind, str]] = [(RefKind.SUBJECT, sid) for sid in subject_ids]
    while frontier:
        node = frontier.pop()
        if node in seen:
            continue
        seen.add(node)
        if node[0] is RefKind.COMPONENT:
            reachable.add(node[1])
        for neighbour in adjacency.get(node, ()):
            if neighbour not in seen:
                frontier.append(neighbour)
    return reachable


__all__ = [
    "semantic_edge_key",
    "exact_edge_key",
    "dedup_edges",
    "reachable_components",
]
