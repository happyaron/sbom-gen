"""Contract-faithful stand-ins for the cpp/subject collectors' sibling deps.

``sbom.config`` and ``sbom.cmake.parse`` are implemented in parallel under the
same frozen INTERFACE.  This helper installs minimal, contract-faithful stubs
into ``sys.modules`` ONLY when the real module is not importable, so this
slice's tests run in isolation without ever shadowing a real module.  Import
this module (``import _cpp_stubs  # noqa``) at the top of cpp/subject tests,
before importing the collectors.

The stubs implement exactly the surface the collectors call, as documented in
INTERFACE.md.  ``make_*`` factories build parse-record instances regardless of
whether the real or stub parse module is active.
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass, field
from pathlib import Path

from sbom.models import (
    CommandContext,
    EnvironmentTool,
    FindPackageInfo,
    SubjectRole,
    UsageScope,
    VcsRef,
)


def _install_config_stub() -> None:
    try:
        import sbom.config  # noqa: F401

        return
    except Exception:
        pass

    mod = types.ModuleType("sbom.config")

    @dataclass
    class Config:
        repo_root: Path
        repo_profile: str | None = None
        cmake_root: Path | None = None
        scope: str = "all"
        build_profile: str = "declared-all"
        formats: list = field(default_factory=lambda: ["cyclonedx", "spdx"])
        collector_mode: str = "static"
        cmake_source_authority: str = "actual-build"
        network: str = "off"
        resolve_cmake_ref: bool = False
        allow_input_fallback: bool = False
        exclude_scopes: list = field(default_factory=list)
        subjects: list | None = None
        split_subjects: bool = False
        profile_values: dict = field(default_factory=dict)
        cmake_defines: dict = field(default_factory=dict)
        reproducible: bool = False
        source_date_epoch: int | None = None
        out_dir: Path = Path("./out")

    _bridge = {
        "example": (SubjectRole.EXAMPLE, UsageScope.EXAMPLE),
        "st_test": (SubjectRole.ST_TEST, UsageScope.ST_TEST),
        "manual_example": (SubjectRole.MANUAL_EXAMPLE, UsageScope.MANUAL_EXAMPLE),
        "experimental": (SubjectRole.EXPERIMENTAL, UsageScope.EXPERIMENTAL),
        "non_distributable_test": (SubjectRole.NON_DISTRIBUTABLE_TEST, None),
        "test": (None, UsageScope.TEST),
        "build": (None, UsageScope.BUILD),
        "runtime": (None, UsageScope.RUNTIME),
    }

    def resolve_exclude_scope(token):
        return _bridge.get(token, (None, None))

    mod.Config = Config
    mod.resolve_exclude_scope = resolve_exclude_scope
    sys.modules["sbom.config"] = mod


def _install_parse_stub() -> None:
    try:
        import sbom.cmake.parse  # noqa: F401

        return
    except Exception:
        pass

    mod = types.ModuleType("sbom.cmake.parse")

    @dataclass
    class ExternalProject:
        name: str
        source_version: str | None = None
        set_version: str | None = None
        canonical_url: str | None = None
        resolved_url_or_path: str | None = None
        url_hash: str | None = None
        tls_verify: bool | None = None
        git_repository: str | None = None
        git_tag: str | None = None
        vcs_ref: VcsRef | None = None
        patches: list = field(default_factory=list)
        depends: list = field(default_factory=list)
        commands: dict = field(default_factory=dict)
        integrity_findings: list = field(default_factory=list)

    @dataclass
    class FetchContentDecl:
        name: str
        canonical_url: str | None = None
        resolved_url_or_path: str | None = None
        url_hash: str | None = None
        git_repository: str | None = None
        git_tag: str | None = None
        vcs_ref: VcsRef | None = None
        patches: list = field(default_factory=list)
        integrity_findings: list = field(default_factory=list)

    @dataclass
    class FindPackageCall:
        name: str
        info: FindPackageInfo
        conditions: list = field(default_factory=list)

    @dataclass
    class IncludeStmt:
        path: str
        resolved: Path | None = None
        conditions: list = field(default_factory=list)

    @dataclass
    class LinkLibraryToken:
        raw: str
        target_property: str | None = None
        conditions: list = field(default_factory=list)

    @dataclass
    class AddDependenciesEdge:
        target: str
        depends_on: list = field(default_factory=list)

    @dataclass
    class ProgramInvocation:
        name: str
        command_context: str
        path: str | None = None
        args: list = field(default_factory=list)
        tokens: list = field(default_factory=list)
        required: bool | None = None
        conditions: list = field(default_factory=list)
        source_file: str | None = None

    @dataclass
    class CMakeFile:
        path: Path
        includes: list = field(default_factory=list)
        external_projects: list = field(default_factory=list)
        fetch_contents: list = field(default_factory=list)
        find_packages: list = field(default_factory=list)
        link_tokens: list = field(default_factory=list)
        add_dependencies: list = field(default_factory=list)
        programs: list = field(default_factory=list)
        project_name: str | None = None
        project_version: str | None = None
        cmake_minimum_required: str | None = None
        macro_calls: list = field(default_factory=list)
        included_by: Path | None = None
        call_site_conditions: list = field(default_factory=list)
        integrity_findings: dict = field(default_factory=dict)
        macro_call_conditions: list = field(default_factory=list)

    def parse_file(path):
        return CMakeFile(path=Path(path))

    def parse_recursive(entry, effective_cmake_root, *, custom_macros=None):
        return [parse_file(entry)]

    def tokenize_command(raw):
        return [raw.split()]

    _DROP_PREFIXES = ("-Wl,", "$<")
    _GENERIC_TOOLS = {
        "perl", "ccache", "$(MAKE)", "make", "cp", "python3", "bash",
        "patch", "tar", "chmod", "git", "sh", "mkdir", "rm",
    }
    _DOMAIN_TOOLS = {"protoc", "host_protoc", "bisheng-compiler", "op_build"}

    def classify_link_token(token, local_targets):
        raw = token.raw
        if raw.startswith(_DROP_PREFIXES) or raw.startswith("-"):
            return "drop"
        if raw in local_targets:
            return "local"
        return "external"

    def classify_program(inv, profile_tooling):
        name = inv.name
        if name in _DOMAIN_TOOLS or name in (profile_tooling or set()):
            return "component"
        if name in _GENERIC_TOOLS:
            return "environment_tool"
        if name.startswith("cmake") or name.startswith("-"):
            return "ignore"
        return "environment_tool"

    _CTX_MAP = {
        "find_program": CommandContext.FIND_PROGRAM,
        "execute_process": CommandContext.EXECUTE_PROCESS,
        "add_custom_command": CommandContext.ADD_CUSTOM_COMMAND,
        "add_custom_target": CommandContext.ADD_CUSTOM_TARGET,
        "ep_configure": CommandContext.EP_CONFIGURE,
        "ep_build": CommandContext.EP_BUILD,
        "ep_install": CommandContext.EP_INSTALL,
        "ep_download": CommandContext.EP_DOWNLOAD,
        "ep_update": CommandContext.EP_UPDATE,
        "patch_command": CommandContext.PATCH_COMMAND,
    }

    def program_to_environment_tool(
        inv, *, source_revision, source_authority, root_artifact_id
    ):
        return EnvironmentTool(
            name=inv.name,
            path=inv.path,
            required=inv.required,
            source_file=inv.source_file,
            source_revision=source_revision,
            source_authority=source_authority,
            command_context=_CTX_MAP.get(inv.command_context),
            root_artifact_id=root_artifact_id,
            activation_condition=list(inv.conditions),
        )

    def discover_roots(repo_root):
        roots = []
        repo_root = Path(repo_root)
        for cml in repo_root.rglob("CMakeLists.txt"):
            try:
                text = cml.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "cmake_minimum_required" in text and "project(" in text:
                roots.append(cml.parent)
        return roots

    for obj in (
        ExternalProject, FetchContentDecl, FindPackageCall, IncludeStmt,
        LinkLibraryToken, AddDependenciesEdge, ProgramInvocation, CMakeFile,
    ):
        setattr(mod, obj.__name__, obj)
    mod.parse_file = parse_file
    mod.parse_recursive = parse_recursive
    mod.tokenize_command = tokenize_command
    mod.classify_link_token = classify_link_token
    mod.classify_program = classify_program
    mod.program_to_environment_tool = program_to_environment_tool
    mod.discover_roots = discover_roots
    sys.modules["sbom.cmake.parse"] = mod


_install_config_stub()
_install_parse_stub()
