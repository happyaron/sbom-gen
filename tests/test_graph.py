"""Unit tests for sbom.graph — the shared edge-identity + closure helpers.

Pins the two DISTINCT edge identities (semantic vs. exact) and the dependency
closure in one place, so the collector/reconcile/emit callers that now share them
cannot drift apart again (the F1/F3 review findings).
"""

from __future__ import annotations

from sbom import graph
from sbom.models import DependencyEdge, Ref, RefKind, RelationType, UsageScope


def _edge(to="dep", *, scope=UsageScope.RUNTIME, source_file="a.cmake", frm=("m", RefKind.SUBJECT)):
    return DependencyEdge(
        root_artifact_id="m",
        from_ref=Ref(frm[1], frm[0]),
        to_ref=Ref(RefKind.COMPONENT, to),
        relation_type=RelationType.LINK,
        usage_scope=scope,
        source_file=source_file,
    )


# --- edge identities --------------------------------------------------------


def test_semantic_key_ignores_provenance_exact_key_does_not():
    a = _edge(source_file="a.cmake")
    b = _edge(source_file="b.cmake")  # same relationship, different evidence site
    assert graph.semantic_edge_key(a) == graph.semantic_edge_key(b)
    assert graph.exact_edge_key(a) != graph.exact_edge_key(b)


def test_usage_scope_changes_both_keys():
    runtime = _edge(scope=UsageScope.RUNTIME)
    build = _edge(scope=UsageScope.BUILD)
    assert graph.semantic_edge_key(runtime) != graph.semantic_edge_key(build)
    assert graph.exact_edge_key(runtime) != graph.exact_edge_key(build)


# --- dedup ------------------------------------------------------------------


def test_dedup_semantic_collapses_provenance_keeps_scope_variants():
    edges = [
        _edge(source_file="a.cmake", scope=UsageScope.RUNTIME),
        _edge(source_file="b.cmake", scope=UsageScope.RUNTIME),  # provenance-only dup
        _edge(source_file="a.cmake", scope=UsageScope.BUILD),    # scope variant
    ]
    out = graph.dedup_edges(edges, key=graph.semantic_edge_key)
    assert len(out) == 2
    assert {e.usage_scope for e in out} == {UsageScope.RUNTIME, UsageScope.BUILD}


def test_dedup_exact_keeps_distinct_evidence_sites():
    edges = [_edge(source_file="a.cmake"), _edge(source_file="b.cmake"), _edge(source_file="a.cmake")]
    out = graph.dedup_edges(edges, key=graph.exact_edge_key)
    assert len(out) == 2  # a + b kept; the second a.cmake (byte-identical) dropped
    assert {e.source_file for e in out} == {"a.cmake", "b.cmake"}


def test_dedup_drops_self_loops():
    loop = DependencyEdge(
        root_artifact_id="m",
        from_ref=Ref(RefKind.COMPONENT, "x"),
        to_ref=Ref(RefKind.COMPONENT, "x"),
        relation_type=RelationType.LINK,
    )
    out = graph.dedup_edges([loop, _edge("y")], key=graph.semantic_edge_key)
    assert [e.to_ref.id for e in out] == ["y"]


# --- closure ----------------------------------------------------------------


def test_reachable_components_is_transitive_and_isolated():
    # m -> depA -> depB ; other -> depC
    edges = [
        DependencyEdge(root_artifact_id="m", from_ref=Ref(RefKind.SUBJECT, "m"),
                       to_ref=Ref(RefKind.COMPONENT, "depA"), relation_type=RelationType.DEPENDS_ON),
        DependencyEdge(root_artifact_id="m", from_ref=Ref(RefKind.COMPONENT, "depA"),
                       to_ref=Ref(RefKind.COMPONENT, "depB"), relation_type=RelationType.DEPENDS_ON),
        DependencyEdge(root_artifact_id="other", from_ref=Ref(RefKind.SUBJECT, "other"),
                       to_ref=Ref(RefKind.COMPONENT, "depC"), relation_type=RelationType.DEPENDS_ON),
    ]
    assert graph.reachable_components(edges, ["m"]) == {"depA", "depB"}
    assert graph.reachable_components(edges, ["other"]) == {"depC"}
    assert graph.reachable_components(edges, ["m", "other"]) == {"depA", "depB", "depC"}
    assert graph.reachable_components(edges, ["missing"]) == set()


def _dep_edge(root, frm_kind, frm, to):
    return DependencyEdge(
        root_artifact_id=root,
        from_ref=Ref(frm_kind, frm),
        to_ref=Ref(RefKind.COMPONENT, to),
        relation_type=RelationType.DEPENDS_ON,
    )


def test_reachable_components_respects_edge_ownership():
    # `shared` is used by BOTH apps; app2 OWNS `shared -> app2_only`. app1's
    # closure must NOT leak app2_only by walking app2's edge through the shared node.
    edges = [
        _dep_edge("app1", RefKind.SUBJECT, "app1", "shared"),
        _dep_edge("app2", RefKind.SUBJECT, "app2", "shared"),
        _dep_edge("app2", RefKind.COMPONENT, "shared", "app2_only"),
    ]
    assert graph.reachable_components(edges, ["app1"]) == {"shared"}
    assert graph.reachable_components(edges, ["app2"]) == {"shared", "app2_only"}


def test_reachable_components_follows_global_none_edges():
    # A root_artifact_id=None edge is global and is traversed by every closure.
    edges = [
        _dep_edge("app1", RefKind.SUBJECT, "app1", "shared"),
        _dep_edge(None, RefKind.COMPONENT, "shared", "global_dep"),
    ]
    assert graph.reachable_components(edges, ["app1"]) == {"shared", "global_dep"}
