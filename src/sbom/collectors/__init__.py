"""Collectors: turn a repo's CMake/Python sources into model records.

Every collector returns a :class:`CollectResult` (lists of model records) and
never mutates global state or emits a partial SBOM. ``reconcile`` is the only
stage that produces a :class:`~sbom.models.Document`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import (
    Component,
    DependencyEdge,
    EnvironmentTool,
    Observation,
    Subject,
    Warning,
)


@dataclass
class CollectResult:
    """Uniform return of every collector. All lists default empty.

    ``observations`` holds observations not yet attached to a component;
    reconcile attaches/merges them by alias-resolved component name. Collectors
    may also pre-attach observations onto ``Component.observations``.
    """

    subjects: list[Subject] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    edges: list[DependencyEdge] = field(default_factory=list)
    environment_tools: list[EnvironmentTool] = field(default_factory=list)
    warnings: list[Warning] = field(default_factory=list)

    def extend(self, other: "CollectResult") -> None:
        """Merge ``other`` into this result in place."""
        self.subjects.extend(other.subjects)
        self.components.extend(other.components)
        self.observations.extend(other.observations)
        self.edges.extend(other.edges)
        self.environment_tools.extend(other.environment_tools)
        self.warnings.extend(other.warnings)
