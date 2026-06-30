"""Profile ABC + registry/auto-detect.

A ``Profile`` isolates all repo-specific knowledge (CANN/ops-math behaviour is
one profile) behind hooks the generic core calls. The core must work with NO
profile, so every hook has a no-op default that returns an empty/neutral value;
the :class:`GenericProfile` simply inherits those defaults.

The core never imports a profile's internals -- it only calls these hooks and
consumes the plain data they return (lists/dicts/model objects from
``sbom.models``). Profiles are discovered via the ``sbom.profiles`` entry-point
group and selected with ``--repo-profile`` (or auto-detected from marker files).
"""

from __future__ import annotations

import logging
from abc import ABC
from importlib import metadata
from pathlib import Path

from .models import (
    CmakeAuthority,
    Component,
    Observation,
    Subject,
    SubjectMerge,
    SubjectRole,
    Warning,
)

logger = logging.getLogger(__name__)


class Profile(ABC):
    """Repo profile plugin contract.

    Every hook has a no-op default so the generic core runs unchanged when no
    profile matches. Concrete profiles override only the hooks they need. None
    of these methods may raise on a repo that lacks the relevant feature; they
    should return the empty/neutral default instead.
    """

    #: Stable profile name, matched by ``--repo-profile`` and the registry.
    name: str = "generic"

    # -- Auto-detection ---------------------------------------------------

    @classmethod
    def detect(cls, repo_root: Path) -> bool:
        """Return ``True`` if this profile applies to ``repo_root``.

        The registry's auto-detect (:func:`detect_profile`) calls this on every
        non-generic profile to pick a match from marker files/usages. The base
        default never matches (:class:`GenericProfile` is the explicit
        fallback), so concrete profiles override it.
        """
        return False

    # -- CMake macros -----------------------------------------------------

    def custom_dep_macros(self) -> dict[str, object]:
        """Return custom CMake dependency-introducing macros.

        Maps a macro name (e.g. ``add_cann_third_party``) to a resolver the
        CppCollector calls to expand a macro invocation into the ``.cmake``
        fragment(s) it includes, resolved relative to
        :attr:`CmakeAuthority.effective_cmake_root` (never the raw
        ``--cmake-root``). Default: no custom macros.
        """
        return {}

    # -- Package metadata -------------------------------------------------

    def package_metadata(
        self, repo_root: Path, authority: CmakeAuthority
    ) -> list[Observation]:
        """Return package-level dependency observations with version constraints.

        e.g. CANN ``version.cmake`` ``set_cann_*`` package/build/run
        dependencies with constraints (``>=8.5``). Default: none.
        """
        return []

    # -- Build tooling ----------------------------------------------------

    def build_tooling(
        self, repo_root: Path, authority: CmakeAuthority
    ) -> tuple[list[Component], list[Warning]]:
        """Return build-tooling components acquired at configure time.

        e.g. ``fetch_cann_cmake.cmake`` -> a ``cann-cmake`` build-scope
        component, but ONLY when a fetch branch actually acquires it. The
        ``skipped_existing_project`` and ``cmake-as-input`` cases deliberately
        emit no acquired component (and may emit a warning instead). Default:
        no components, no warnings.
        """
        return ([], [])

    # -- Curated enrichers ------------------------------------------------

    def curated_enrichers(self, repo_root: Path) -> list[object]:
        """Return curated-file enrichers (parsers) to run if their files exist.

        e.g. ``Third_Party_..._List.yaml`` / ``..._Notice`` parsers that
        contribute license/version/copyright facts. Curated product data takes
        precedence over the generic known-license map. Default: none.
        """
        return []

    # -- Alias map --------------------------------------------------------

    def alias_map(self) -> dict[str, dict]:
        """Return canonical-name aliases with relation types.

        Maps a raw spelling (``OPBASE``, ``tiling_api``, ``gtest`` ...) to a
        record ``{"canonical": str, "relation": str}`` so reconcile can de-dup
        the same component seen under different mechanisms. Used in addition to
        the core's built-in OSS aliases. An unmapped raw link token raises
        ``unmapped_link_library`` rather than duplicating/dropping a component.
        Default: no profile aliases.
        """
        return {}

    # -- License defaults (subject vs dependency are separate) ------------

    def subject_license_default(self, subject: Subject) -> str | None:
        """Default license for the repo's OWN subjects/files.

        e.g. ``LicenseRef-CANN-Open-Software-License-2.0`` for ops-math's own
        artifacts. Applies only to the current repo's subjects. Default:
        ``None`` (leave to the generic resolver / ``NOASSERTION``).
        """
        return None

    def dependency_license_default(self, component: Component) -> str | None:
        """Default license for a dependency component.

        CANN dependencies stay ``NOASSERTION`` unless curated or installed
        toolkit metadata proves the license, so this returns ``None`` by
        default and profiles rarely override it.
        """
        return None

    # -- Supplier (NTIA) --------------------------------------------------

    def first_party_supplier(self) -> str | None:
        """The supplier (publishing organization) for the repo's OWN artifacts.

        Used to fill the NTIA Supplier element for repo-owned subjects and
        ``first-party`` components (a CANN profile returns its org, e.g. "Huawei
        Technologies Co., Ltd."). Third-party suppliers come from an enricher
        (ClearlyDefined). Default: ``None`` (no supplier asserted)."""
        return None

    # -- Supply-chain provenance ------------------------------------------

    def component_provenance(self, component: Component) -> str | None:
        """Declare a dependency's supply-chain provenance class, or ``None``.

        Return ``"first-party"`` when the profile KNOWS this component belongs to
        the repo's own first-party surface -- a repo-internal library or a sibling
        component from the same publishing org (for CANN: a ``gitcode.com/cann/*``
        project, distinct from the look-alike third-party mirrors) -- so the SBOM
        can mark it apart from fetched third-party deps. Return ``None`` to let the
        generic core classify it: ``"third-party"`` when it has a real upstream
        download URL or is a published Python package, else ``"unknown"``. The
        profile is authoritative -- any non-``None`` value it returns
        (``"first-party"``, or directly ``"third-party"``/``"unknown"``) is used
        verbatim and wins over the core derivation. Default: ``None`` (core decides).
        """
        return None

    # -- Condition vocabulary --------------------------------------------

    def condition_vocabulary(self) -> dict[str, object]:
        """Return known condition tokens and their semantics.

        e.g. ``TOPLEVEL_PROJECT``, ``ENABLE_*``, ``PRODUCT_SIDE`` -> metadata
        the collector/build-profile evaluator uses to interpret activation
        gates. Default: empty vocabulary.
        """
        return {}

    # -- Root classification (profile/config policy, not core) ------------

    def classify_root(
        self,
        path: Path,
        cmake_project: Subject,
        package_context: dict,
    ) -> SubjectRole:
        """Classify a discovered standalone CMake root into a role.

        The path semantics ``example``/``st_test``/``manual_example``/
        ``experimental`` are profile policy; the generic core only discovers
        roots and assigns ``cmake_project``/``unclassified``. Default: return
        the root's existing role unchanged (no reclassification).
        """
        return cmake_project.role

    def root_exclusion_policy(self) -> set[SubjectRole]:
        """Return the set of roles to EXCLUDE from emission.

        ``declared-all`` includes discovered roots; a policy can exclude roles,
        and the core emits an ``excluded_scope`` warning per dropped root so
        omissions are explicit. Default: exclude nothing.
        """
        return set()

    # -- Repo origin ------------------------------------------------------

    def repo_origin(self, repo_root: Path):
        """Optional: a profile that KNOWS its canonical VCS origin returns a
        :class:`sbom.origin.RepoOrigin`.

        Most repos need no override -- the core auto-detects the origin from
        ``.git/config`` and honors an explicit ``--repo-url``. This hook is for a
        profile whose canonical URL is fixed and not always derivable from the
        checkout. Default: ``None`` (use the core's detection).
        """
        return None

    # -- Vendored data files ----------------------------------------------

    def data_sources(self) -> list:
        """Return the vendored data files this profile contributes.

        Each item is a :class:`sbom.data_sources.DataSource` (the core never
        imports profile data — the profile *pushes* its sources here). A source
        whose ``name`` matches a generic-core source (``"known-licenses"``,
        ``"depsdev"``) OVERRIDES/EXTENDS it (merged on top, profile wins);
        a new ``name`` (``"aliases"``, ``"first-party"``) adds a profile-only
        source. Drives map merges and ``--refresh-data``. Default: none.
        """
        return []

    # -- Subject facets ---------------------------------------------------

    def subject_facets(self, subjects: list[Subject]) -> list[SubjectMerge]:
        """Bind co-located wheel/CMake roots into facets of one subject.

        Drives the wheel↔CMake merge: e.g. wheel ``ascend_ops`` ≡ CMake
        ``AscendOps`` (and ``ops_math`` ≡ ``math``). Each returned
        :class:`~sbom.models.SubjectMerge` names the subject to keep
        (``keep_subject_id``), the subject to absorb (``absorbed_subject_id``),
        the ``cmake_project`` root that builds the kept subject
        (``build_graph_root_id``), and the absorbed identity as a ``facet`` --
        so ``discover_subjects`` can collapse the two roots into one subject
        (Python runtime deps + CMake build/link deps attach to the SAME subject)
        unless the user explicitly requests a standalone CMake subject. Default:
        no merges.
        """
        return []


class GenericProfile(Profile):
    """Fallback profile: the generic core with every hook at its default."""

    name = "generic"


# ---------------------------------------------------------------------------
# Registry / auto-detect
# ---------------------------------------------------------------------------

#: Entry-point group profiles register under.
ENTRY_POINT_GROUP = "sbom.profiles"


def load_profiles() -> tuple[dict[str, type[Profile]], list[Warning]]:
    """Discover installed profile classes via the ``sbom.profiles`` group.

    Returns ``({entry_point_name: Profile_subclass}, warnings)``. The built-in
    :class:`GenericProfile` is always present under ``"generic"``.

    An entry point that fails to import (or doesn't resolve to a ``Profile``
    subclass) is skipped, but NEVER silently: the failure is recorded as a
    first-class ``Warning(code="profile_load_failed", subject=<ep name>,
    detail=<error>)`` in the returned list so the caller can surface it. A
    broken profile must not silently downgrade the run to ``generic`` with no
    signal.
    """
    profiles: dict[str, type[Profile]] = {"generic": GenericProfile}
    warnings: list[Warning] = []
    eps = metadata.entry_points(group=ENTRY_POINT_GROUP)
    for ep in eps:
        try:
            cls = ep.load()
        except Exception as exc:  # noqa: BLE001 -- any load failure is reported
            detail = f"{type(exc).__name__}: {exc}"
            logger.warning("profile entry point %r failed to load: %s", ep.name, detail)
            warnings.append(
                Warning(code="profile_load_failed", subject=ep.name, detail=detail)
            )
            continue
        if isinstance(cls, type) and issubclass(cls, Profile):
            profiles[ep.name] = cls
        else:
            detail = f"entry point did not resolve to a Profile subclass: {cls!r}"
            logger.warning("profile entry point %r invalid: %s", ep.name, detail)
            warnings.append(
                Warning(code="profile_load_failed", subject=ep.name, detail=detail)
            )
    return profiles, warnings


def detect_profile(repo_root: Path) -> tuple[str | None, list[Warning]]:
    """Auto-detect the repo profile name, or ``None``.

    Calls every non-generic registered profile's :meth:`Profile.detect` against
    ``repo_root`` (the registry's detection contract -- e.g. ``CannProfile``
    matches a CANN cmake-framework marker like ``add_cann_third_party(`` /
    ``cmake/function/prepare.cmake``, OR a git origin under the ``cann`` org for
    CANN repos with no cmake markers). Returns the first matching entry-point name
    (and any profile-load warnings), else ``(None, warnings)`` so the caller falls
    back to the generic core.
    """
    registry, warnings = load_profiles()
    for ep_name, cls in registry.items():
        if ep_name == "generic":
            continue
        if cls.detect(repo_root):
            return ep_name, warnings
    return None, warnings


def get_profile(
    name: str | None, repo_root: Path | None = None
) -> tuple[Profile, list[Warning]]:
    """Resolve a profile instance by name, with ``"auto"``/``None`` detection.

    * ``name`` is an explicit entry-point name (``"cann"``) -> that profile.
    * ``name`` is ``None`` or ``"auto"`` -> :func:`detect_profile` against
      ``repo_root`` (if given), else the generic fallback.
    * An unknown/undetected name yields :class:`GenericProfile`.

    Returns ``(profile, warnings)``; ``warnings`` carries any
    ``profile_load_failed`` records so a broken entry point is never an
    invisible downgrade.
    """
    registry, warnings = load_profiles()

    resolved = name
    if resolved in (None, "auto"):
        if repo_root is not None:
            resolved, detect_warnings = detect_profile(repo_root)
            # detect_profile re-loads the registry; keep one warning per failure.
            warnings = detect_warnings
        else:
            resolved = None

    cls = registry.get(resolved or "generic", GenericProfile)
    # An EXPLICIT --repo-profile name that is not registered must not be an
    # invisible downgrade to the generic core (it would silently drop the whole
    # profile layer: aliases, curated licenses, root classification). Surface it.
    if name not in (None, "auto") and name not in registry:
        warnings = [
            *warnings,
            Warning(
                code="profile_not_found",
                subject=name,
                detail=(
                    f"requested profile {name!r} is not registered; "
                    "falling back to the generic core"
                ),
            ),
        ]
    return cls(), warnings


__all__ = [
    "Profile",
    "GenericProfile",
    "ENTRY_POINT_GROUP",
    "load_profiles",
    "detect_profile",
    "get_profile",
]
