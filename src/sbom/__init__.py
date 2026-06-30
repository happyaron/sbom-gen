"""sbom -- a standalone SBOM generator for C++/CMake + Python repositories.

Generic core; repo-specific knowledge lives in profile plugins (see
:mod:`sbom.profile`). The public model lives in :mod:`sbom.models`.
"""

from __future__ import annotations

from .models import (
    ActivationCondition,
    CmakeAuthority,
    CmakeAuthorityBranch,
    CommandContext,
    Component,
    DeclarationReachability,
    DependencyEdge,
    Document,
    EnvironmentTool,
    Facet,
    FindPackageInfo,
    Identity,
    IntegrityFinding,
    Observation,
    Patch,
    Provenance,
    Ref,
    RefKind,
    RelationType,
    RootArtifact,
    Sbom,
    SourceKind,
    Subject,
    SubjectKind,
    SubjectMerge,
    SubjectRole,
    UsageScope,
    VcsRef,
    Warning,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # enums
    "SourceKind",
    "UsageScope",
    "DeclarationReachability",
    "IntegrityFinding",
    "RelationType",
    "RefKind",
    "SubjectKind",
    "SubjectRole",
    "CmakeAuthorityBranch",
    "CommandContext",
    # value objects
    "Identity",
    "Facet",
    "SubjectMerge",
    "Ref",
    "Patch",
    "VcsRef",
    "FindPackageInfo",
    "ActivationCondition",
    "Provenance",
    # records
    "Observation",
    "Subject",
    "RootArtifact",
    "Component",
    "DependencyEdge",
    "EnvironmentTool",
    "CmakeAuthority",
    "Warning",
    # container
    "Document",
    "Sbom",
]
