"""Static Python package-metadata resolver (name + version, no code execution).

A Python distribution's *subject identity* (the wheel name/version) is frequently
NOT a literal in ``setup.py``. Real repos compute it from environment variables
with defaults, module-level constants, helper functions, version files, or
``setuptools_scm``. The generic CORE must identify those subjects honestly and
generally — never run the build, never fabricate a value.

:func:`resolve_package_metadata` resolves a package directory's name+version with
this precedence:

1. ``pyproject.toml`` ``[project].name``/``version`` (PEP 621). If ``version`` is
   declared dynamic, resolve via ``[tool.setuptools.dynamic]`` (``attr:``/
   ``file:``), a conventional version file, or ``setuptools_scm``.
2. ``setup.cfg`` ``[metadata]`` ``name``/``version`` (incl. ``file:``/``attr:``).
3. ``setup.py`` AST — the ``setup(name=…, version=…)`` argument expressions are
   resolved by a small, SAFE static evaluator (see :class:`_Evaluator`) that
   understands string literals, module-level constant references, ``os.getenv``/
   ``os.environ.get`` defaults, ``X or "lit"`` fallbacks, single-``return``
   helper functions, version-file reads, and chained ``.strip()``/``.replace``.
4. Conventional fallbacks: ``version.txt`` / ``VERSION`` / ``<pkg>/_version.py`` /
   ``<pkg>/__init__.py`` ``__version__`` / ``PKG-INFO`` / ``setuptools_scm``
   (``git describe``).

When name cannot be resolved it falls back to the package directory basename and
records ``Warning(code="subject_name_unresolved")``; when version cannot be
resolved it stays ``None`` with ``Warning(code="subject_version_unresolved")``.
Every resolved value records which source produced it (``name_source`` /
``version_source``) so downstream consumers know how strong the identity is.

NOTHING in this module imports or runs the target package. The AST evaluator only
reads literals and small co-located text files under ``pkg_root``.
"""

from __future__ import annotations

import ast
import re
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Warning

# Cap on version/text files we are willing to read while resolving (a version
# file is a few bytes; this guards against pointing at a giant data blob).
_MAX_VERSION_FILE_BYTES = 64 * 1024

# Recursion depth cap for the evaluator (e.g. const -> getenv-default -> literal).
_MAX_EVAL_DEPTH = 6

_VERSION_FILE_NAMES = ("version.txt", "VERSION", "version", "VERSION.txt")

_DUNDER_VERSION_RE = re.compile(
    r"""__version__\s*=\s*["']([^"']+)["']""", re.MULTILINE
)


@dataclass
class PkgMetadata:
    """Resolved package identity plus provenance and any honesty warnings.

    ``name`` is always set (falls back to the directory basename). ``version`` is
    ``None`` when it could not be resolved without executing code. ``name_source``/
    ``version_source`` name the mechanism that produced each value (e.g.
    ``"pyproject_project"``, ``"setup_py:os.getenv_default"``, ``"version_file"``,
    ``"dir_basename"``). ``warnings`` carries ``subject_name_unresolved`` /
    ``subject_version_unresolved`` records when a value could not be proven.
    """

    name: str
    version: str | None = None
    name_source: str | None = None
    version_source: str | None = None
    warnings: list[Warning] = field(default_factory=list)


def resolve_package_metadata(pkg_root: Path) -> PkgMetadata:
    """Resolve name+version for the Python package rooted at ``pkg_root``.

    See module docstring for the precedence. Always returns a :class:`PkgMetadata`
    with a concrete ``name`` (dir basename fallback) and ``version`` that is either
    a string or ``None`` (never a fabricated guess).
    """
    pkg_root = Path(pkg_root)

    name: str | None = None
    name_source: str | None = None
    version: str | None = None
    version_source: str | None = None

    # 1. pyproject.toml [project]
    proj = _read_pyproject(pkg_root)
    if proj is not None:
        p_name, p_ver, p_ver_src = proj
        if p_name:
            name, name_source = p_name, "pyproject_project"
        if p_ver:
            version, version_source = p_ver, p_ver_src

    # 2. setup.cfg [metadata]
    if name is None or version is None:
        cfg = _read_setup_cfg(pkg_root)
        if cfg is not None:
            c_name, c_ver = cfg
            if name is None and c_name:
                name, name_source = c_name, "setup_cfg"
            if version is None and c_ver:
                version, version_source = c_ver, "setup_cfg"

    # 3. setup.py AST evaluation
    if name is None or version is None:
        sp = _read_setup_py(pkg_root)
        if sp is not None:
            s_name, s_name_src, s_ver, s_ver_src = sp
            if name is None and s_name:
                name, name_source = s_name, s_name_src
            if version is None and s_ver:
                version, version_source = s_ver, s_ver_src

    # 4. Conventional version fallbacks.
    if version is None:
        fb = _fallback_version(pkg_root, name)
        if fb is not None:
            version, version_source = fb

    warnings: list[Warning] = []
    if name is None:
        name = pkg_root.name
        name_source = "dir_basename"
        warnings.append(
            Warning(
                code="subject_name_unresolved",
                subject=str(pkg_root),
                detail=(
                    "package name could not be resolved statically "
                    f"(no literal name in metadata); using directory basename {name!r}"
                ),
            )
        )
    if version is None:
        warnings.append(
            Warning(
                code="subject_version_unresolved",
                subject=name,
                detail=(
                    "package version could not be resolved statically "
                    f"for {str(pkg_root)!r}"
                ),
            )
        )

    return PkgMetadata(
        name=name,
        version=version,
        name_source=name_source,
        version_source=version_source,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# 1. pyproject.toml [project]
# ---------------------------------------------------------------------------


def _read_pyproject(pkg_root: Path) -> tuple[str | None, str | None, str | None] | None:
    """Return ``(name, version, version_source)`` from ``[project]`` or ``None``.

    Resolves a dynamic version through ``[tool.setuptools.dynamic]`` (``attr:``/
    ``file:``), conventional version files, or ``setuptools_scm``.
    """
    path = pkg_root / "pyproject.toml"
    if not path.is_file():
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None

    project = data.get("project")
    if not isinstance(project, dict):
        return None

    name = project.get("name") if isinstance(project.get("name"), str) else None

    version: str | None = None
    version_source: str | None = None
    raw_ver = project.get("version")
    if isinstance(raw_ver, str) and raw_ver:
        version, version_source = raw_ver, "pyproject_project"
    else:
        dynamic = project.get("dynamic") or []
        if isinstance(dynamic, list) and "version" in dynamic:
            resolved = _resolve_dynamic_version(pkg_root, data)
            if resolved is not None:
                version, version_source = resolved

    return name, version, version_source


def _resolve_dynamic_version(
    pkg_root: Path, data: dict
) -> tuple[str, str] | None:
    """Resolve a ``[project] dynamic = ["version"]`` declaration statically."""
    tool = data.get("tool") or {}
    setuptools_cfg = tool.get("setuptools") or {}
    dynamic_cfg = setuptools_cfg.get("dynamic") or {}
    ver_directive = dynamic_cfg.get("version")

    if isinstance(ver_directive, dict):
        attr = ver_directive.get("attr")
        if isinstance(attr, str):
            val = _resolve_attr_directive(pkg_root, attr, setuptools_cfg)
            if val is not None:
                return val, "pyproject_dynamic:attr"
        file_ref = ver_directive.get("file")
        files = [file_ref] if isinstance(file_ref, str) else file_ref
        if isinstance(files, list):
            for f in files:
                if not isinstance(f, str):
                    continue
                val = _read_text_file(pkg_root / f, confine_to=pkg_root)
                if val:
                    return val, "pyproject_dynamic:file"

    # setuptools_scm declared as the version backend.
    if "setuptools_scm" in tool or _has_scm_build_requires(data):
        val = _setuptools_scm_version(pkg_root)
        if val is not None:
            return val, "setuptools_scm"

    # Last resort: a conventional version file alongside the package.
    val = _read_conventional_version_file(pkg_root)
    if val is not None:
        return val, "version_file"
    return None


def _has_scm_build_requires(data: dict) -> bool:
    build = data.get("build-system") or {}
    requires = build.get("requires") or []
    return any(
        isinstance(r, str) and "setuptools_scm" in r.replace("-", "_").lower()
        for r in requires
    )


def _resolve_attr_directive(
    pkg_root: Path, attr: str, setuptools_cfg: dict
) -> str | None:
    """Resolve ``attr: pkg.module.__version__`` by reading the module's AST."""
    module_path = ".".join(attr.split(".")[:-1])
    var_name = attr.split(".")[-1]
    package_dir = _package_dir_map(setuptools_cfg)
    candidate = _module_file_for(pkg_root, module_path, package_dir)
    if candidate is None:
        return None
    return _read_dunder_from_module(candidate, var_name)


def _package_dir_map(setuptools_cfg: dict) -> dict:
    pdir = setuptools_cfg.get("package-dir") or setuptools_cfg.get("package_dir") or {}
    return pdir if isinstance(pdir, dict) else {}


def _module_file_for(
    pkg_root: Path, module_path: str, package_dir: dict
) -> Path | None:
    """Map a dotted module path to a file under ``pkg_root`` honoring package-dir."""
    parts = module_path.split(".") if module_path else []
    roots = ["."]
    # A package-dir {"" : "src"} remaps the import root.
    base = package_dir.get("")
    if isinstance(base, str):
        roots.insert(0, base)
    for root in roots:
        base_dir = pkg_root / root if root != "." else pkg_root
        as_module = base_dir.joinpath(*parts).with_suffix(".py")
        if as_module.is_file():
            return as_module
        as_pkg = base_dir.joinpath(*parts) / "__init__.py"
        if as_pkg.is_file():
            return as_pkg
    return None


def _read_dunder_from_module(path: Path, var_name: str) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text, filename=str(path))
    except (OSError, SyntaxError):
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ):
                        return node.value.value
    return None


# ---------------------------------------------------------------------------
# 2. setup.cfg [metadata]
# ---------------------------------------------------------------------------


def _read_setup_cfg(pkg_root: Path) -> tuple[str | None, str | None] | None:
    path = pkg_root / "setup.cfg"
    if not path.is_file():
        return None
    import configparser

    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error):
        return None
    if not parser.has_section("metadata"):
        return None
    md = parser["metadata"]
    name = md.get("name") or None
    version = _resolve_cfg_value(md.get("version"), pkg_root)
    if name is not None:
        name = name.strip() or None
    return name, version


def _resolve_cfg_value(raw: str | None, pkg_root: Path) -> str | None:
    """Resolve a setup.cfg metadata value, handling ``file:``/``attr:``."""
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("file:"):
        rel = raw[len("file:"):].strip().split(",")[0].strip()
        return _read_text_file(pkg_root / rel, confine_to=pkg_root)
    if raw.startswith("attr:"):
        attr = raw[len("attr:"):].strip()
        return _resolve_attr_directive(pkg_root, attr, {})
    return raw or None


# ---------------------------------------------------------------------------
# 3. setup.py AST
# ---------------------------------------------------------------------------


def _read_setup_py(
    pkg_root: Path,
) -> tuple[str | None, str | None, str | None, str | None] | None:
    """Return ``(name, name_source, version, version_source)`` from setup.py AST."""
    path = pkg_root / "setup.py"
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text, filename=str(path))
    except (OSError, SyntaxError):
        return None

    call = _find_setup_call(tree)
    if call is None:
        return None

    evaluator = _Evaluator(tree, pkg_root)
    name_node = _keyword_value(call, "name")
    ver_node = _keyword_value(call, "version")

    name = name_src = version = ver_src = None
    if name_node is not None:
        res = evaluator.eval(name_node)
        if res is not None:
            name, name_src = res.value, f"setup_py:{res.source}"
    if ver_node is not None:
        res = evaluator.eval(ver_node)
        if res is not None:
            version, ver_src = res.value, f"setup_py:{res.source}"

    return name, name_src, version, ver_src


def _find_setup_call(tree: ast.Module) -> ast.Call | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_setup_call(node):
            # Prefer a call that actually carries name/version kwargs.
            args = {kw.arg for kw in node.keywords}
            if "name" in args or "version" in args:
                return node
    return None


def _is_setup_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "setup"
    if isinstance(func, ast.Attribute):
        return func.attr == "setup"
    return False


def _keyword_value(call: ast.Call, arg: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == arg:
            return kw.value
    return None


# ---------------------------------------------------------------------------
# The safe static evaluator
# ---------------------------------------------------------------------------


@dataclass
class _EvalResult:
    value: str
    source: str  # e.g. "literal", "module_const", "os.getenv_default", ...


class _Evaluator:
    """Resolve a ``name=``/``version=`` argument expression WITHOUT executing it.

    Handles (per the design): string literals; module-level constant references
    (1-2 levels deep); ``os.getenv(k, default)`` / ``os.environ.get(k, default)``
    -> the default literal; ``X or "lit"`` -> the literal operand; ``f()`` where a
    module-level ``def f()`` has a single resolvable ``return``; version-file
    reads (``_read_file('version.txt')``, ``open('VERSION').read()``,
    ``Path('…').read_text()``) -> the file content under ``pkg_root``; and chained
    ``.strip()``/``.replace('\\n','')`` on a resolvable base.
    """

    def __init__(self, tree: ast.Module, pkg_root: Path) -> None:
        self.tree = tree
        self.pkg_root = pkg_root
        self._consts = _collect_module_assignments(tree)
        self._funcs = _collect_module_functions(tree)

    def eval(
        self,
        node: ast.AST,
        depth: int = 0,
        locals_: dict[str, ast.AST] | None = None,
    ) -> _EvalResult | None:
        if depth > _MAX_EVAL_DEPTH:
            return None

        # 1. String literal.
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _EvalResult(node.value, "literal")

        # 2. Name reference: local (function-scope) assignment first, then a
        #    module-level constant.
        if isinstance(node, ast.Name):
            if locals_ is not None and node.id in locals_:
                inner = self.eval(locals_[node.id], depth + 1, locals_)
                if inner is not None:
                    return inner
            assigned = self._consts.get(node.id)
            if assigned is not None:
                inner = self.eval(assigned, depth + 1, locals_)
                if inner is not None:
                    src = inner.source
                    if src == "literal":
                        src = "module_const"
                    return _EvalResult(inner.value, src)
            return None

        # 3. Boolean OR: ``X or "lit"`` -> first resolvable operand.
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            for operand in node.values:
                inner = self.eval(operand, depth + 1, locals_)
                if inner is not None:
                    return _EvalResult(inner.value, "or_fallback")
            return None

        # 4 & 5 & 6. Call expressions: os.getenv default / helper f() / file read.
        if isinstance(node, ast.Call):
            return self._eval_call(node, depth, locals_)

        return None

    def _eval_call(
        self, node: ast.Call, depth: int, locals_: dict[str, ast.AST] | None
    ) -> _EvalResult | None:
        func = node.func

        # os.getenv(key, default) / os.environ.get(key, default)
        if _is_getenv_call(func):
            if len(node.args) >= 2:
                inner = self.eval(node.args[1], depth + 1, locals_)
                if inner is not None:
                    return _EvalResult(inner.value, "os.getenv_default")
            return None

        # Chained methods: .strip(...) / .replace(...) / .read()/.read_text() / .decode()
        if isinstance(func, ast.Attribute):
            return self._eval_method(func, node, depth, locals_)

        # Bare helper call f(): resolve via a single-return module-level def.
        if isinstance(func, ast.Name):
            fn = self._funcs.get(func.id)
            if fn is None:
                return None
            # File-reader helper: f('version.txt') where the one-arg helper opens
            # and reads its filename argument (e.g. mindspore's _read_file).
            if len(node.args) == 1:
                rel = _const_str(node.args[0])
                if rel is not None and _is_file_reader_helper(fn):
                    content = _read_text_file(self.pkg_root / rel, confine_to=self.pkg_root)
                    if content is not None:
                        return _EvalResult(content, "version_file")
            return self._eval_function_return(fn, depth)

        return None

    def _eval_method(
        self,
        func: ast.Attribute,
        node: ast.Call,
        depth: int,
        locals_: dict[str, ast.AST] | None,
    ) -> _EvalResult | None:
        method = func.attr

        # Pure string transforms over a resolvable base: keep the base value
        # (strip/replace of trailing newlines never changes a clean version).
        if method in ("strip", "replace", "rstrip", "lstrip", "decode", "splitlines"):
            base = self.eval(func.value, depth + 1, locals_)
            if base is None:
                return None
            value = base.value
            if method == "replace" and len(node.args) == 2:
                a = _const_str(node.args[0])
                b = _const_str(node.args[1])
                if a is not None and b is not None:
                    value = value.replace(a, b)
            elif method in ("strip", "rstrip", "lstrip"):
                value = getattr(value, method)()
            elif method == "splitlines":
                first = value.splitlines()
                value = first[0] if first else value
            return _EvalResult(value, base.source)

        # File reads: open('VERSION').read() / Path('…').read_text()
        if method in ("read", "read_text"):
            rel = self._file_target_of(func.value)
            if rel is not None:
                content = _read_text_file(self.pkg_root / rel, confine_to=self.pkg_root)
                if content is not None:
                    return _EvalResult(content, "version_file")
            return None

        return None

    def _file_target_of(self, node: ast.AST) -> str | None:
        """Extract a relative file path from ``open('x')`` / ``Path('x')``."""
        if isinstance(node, ast.Call):
            func = node.func
            # open('x') / Path('x')
            target_name = None
            if isinstance(func, ast.Name):
                target_name = func.id
            elif isinstance(func, ast.Attribute):
                target_name = func.attr
            if target_name in ("open", "Path") and node.args:
                return _const_str(node.args[0])
        return None

    def _eval_function_return(
        self, fn: ast.FunctionDef, depth: int
    ) -> _EvalResult | None:
        """Resolve a helper with a single resolvable ``return`` (literal/const/getenv).

        Local ``var = <expr>`` assignments in the function body are available to
        the return expression (so ``v = os.getenv(K, "1.0"); return v`` resolves).
        When the function has multiple returns (e.g. try setuptools_scm / except
        DEFAULT), the first return that resolves to a literal/const/getenv default
        wins — the static, build-independent value the author chose as baseline.
        """
        if fn.args.args or fn.args.kwonlyargs or fn.args.vararg or fn.args.kwarg:
            # Only resolve zero-arg helpers (name=/version= helpers take no args).
            return None
        locals_ = _collect_function_locals(fn)
        returns = [
            n.value
            for n in ast.walk(fn)
            if isinstance(n, ast.Return) and n.value is not None
        ]
        # Resolve in source order; keep the first that yields a value.
        for ret in returns:
            inner = self.eval(ret, depth + 1, locals_)
            if inner is not None:
                return _EvalResult(inner.value, "function_return")
        return None


def _is_file_reader_helper(fn: ast.FunctionDef) -> bool:
    """True for a 1-arg helper that opens its argument and returns the contents.

    Matches mindspore's ``def _read_file(filename): with open(... filename ...)
    as f: return f.read()`` shape: exactly one positional parameter, an ``open``
    call somewhere in the body that references that parameter, and a ``return``
    of a ``.read()``/``.read_text()`` (or the open's read).
    """
    params = fn.args.args
    if len(params) != 1 or fn.args.vararg or fn.args.kwarg or fn.args.kwonlyargs:
        return False
    param = params[0].arg
    opens_param = False
    reads = False
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            f = sub.func
            fname = f.id if isinstance(f, ast.Name) else (
                f.attr if isinstance(f, ast.Attribute) else None
            )
            if fname == "open":
                # The param must be referenced among the open() arguments.
                for arg in ast.walk(sub):
                    if isinstance(arg, ast.Name) and arg.id == param:
                        opens_param = True
            if fname in ("read", "read_text"):
                reads = True
    return opens_param and reads


def _is_getenv_call(func: ast.AST) -> bool:
    if isinstance(func, ast.Attribute):
        if func.attr == "getenv":
            # os.getenv / getenv
            return True
        if func.attr == "get":
            # os.environ.get(...)
            val = func.value
            if isinstance(val, ast.Attribute) and val.attr == "environ":
                return True
            if isinstance(val, ast.Name) and val.id == "environ":
                return True
    if isinstance(func, ast.Name) and func.id == "getenv":
        return True
    return False


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _collect_module_assignments(tree: ast.Module) -> dict[str, ast.AST]:
    """Module-level ``NAME = <expr>`` mapping (nearest assignment wins)."""
    out: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                out[target.id] = node.value
    return out


def _collect_module_functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    out: dict[str, ast.FunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            out[node.name] = node
    return out


def _collect_function_locals(fn: ast.FunctionDef) -> dict[str, ast.AST]:
    """Top-level ``NAME = <expr>`` assignments in a function body (last wins)."""
    out: dict[str, ast.AST] = {}
    for node in fn.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                out[target.id] = node.value
    return out


# ---------------------------------------------------------------------------
# 4. Conventional fallbacks
# ---------------------------------------------------------------------------


def _fallback_version(pkg_root: Path, name: str | None) -> tuple[str, str] | None:
    """Version conventions: version file, ``__version__``, PKG-INFO, scm."""
    val = _read_conventional_version_file(pkg_root)
    if val is not None:
        return val, "version_file"

    # <pkg>/_version.py or <pkg>/__init__.py __version__ — try package dirs.
    for module_name in _candidate_package_dirs(pkg_root, name):
        for fname in ("_version.py", "version.py", "__init__.py"):
            cand = pkg_root / module_name / fname
            if cand.is_file():
                v = _dunder_version(cand)
                if v is not None:
                    return v, "dunder_version"

    pkg_info = _read_pkg_info_version(pkg_root)
    if pkg_info is not None:
        return pkg_info, "pkg_info"

    scm = _setuptools_scm_version(pkg_root)
    if scm is not None:
        return scm, "setuptools_scm"
    return None


def _candidate_package_dirs(pkg_root: Path, name: str | None) -> list[str]:
    candidates: list[str] = []
    if name:
        candidates.append(name.replace("-", "_"))
        candidates.append(name)
    # Common layout: a single top-level package directory under src/ or root.
    for parent in (pkg_root, pkg_root / "src", pkg_root / "python"):
        if not parent.is_dir():
            continue
        for child in sorted(parent.iterdir()):
            if child.is_dir() and (child / "__init__.py").is_file():
                rel = child.relative_to(pkg_root)
                candidates.append(str(rel))
    # De-dup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _read_conventional_version_file(pkg_root: Path) -> str | None:
    for fname in _VERSION_FILE_NAMES:
        val = _read_text_file(pkg_root / fname)
        if val:
            return val
    return None


def _dunder_version(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _DUNDER_VERSION_RE.search(text)
    return m.group(1) if m else None


def _read_pkg_info_version(pkg_root: Path) -> str | None:
    # ``glob`` yields filesystem (readdir) order; sort so two egg-info dirs with
    # divergent Version lines pick the SAME one every run (--reproducible).
    egg_infos = sorted(pkg_root.glob("*.egg-info/PKG-INFO"))
    for cand in (pkg_root / "PKG-INFO", *egg_infos):
        try:
            text = cand.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if line.startswith("Version:"):
                v = line[len("Version:"):].strip()
                if v:
                    return v
    return None


def _setuptools_scm_version(pkg_root: Path) -> str | None:
    """A best-effort ``git describe`` style version (no setuptools_scm import).

    We deliberately do not import setuptools_scm (it would execute build logic).
    Instead we read a tag via ``git`` if ``pkg_root`` is inside a work tree. This
    is read-only and returns ``None`` whenever git is unavailable or unhelpful.
    """
    if not (pkg_root / ".git").exists() and not _in_git_worktree(pkg_root):
        return None
    # Only trust a tag when ``pkg_root`` IS the git work-tree root. A subdir wheel in
    # a monorepo would otherwise inherit the PARENT repo's top-level ``git describe``
    # tag as its own version -- wrong identity / purl / SPDX namespace for every
    # scm-backed subject in the tree. If it is not the root, stay unresolved.
    if not _is_git_toplevel(pkg_root):
        return None
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            cwd=str(pkg_root),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    tag = out.stdout.strip()
    if not tag:
        return None
    return tag.lstrip("vV") or None


def _in_git_worktree(pkg_root: Path) -> bool:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(pkg_root),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and out.stdout.strip() == "true"


def _is_git_toplevel(pkg_root: Path) -> bool:
    """True when ``pkg_root`` is itself the git work-tree root (not a subdir)."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(pkg_root),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if out.returncode != 0 or not out.stdout.strip():
        return False
    try:
        return Path(out.stdout.strip()).resolve() == pkg_root.resolve()
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Small-file reader
# ---------------------------------------------------------------------------


def _read_text_file(path: Path, confine_to: Path | None = None) -> str | None:
    """Read a small text file and strip it.

    When ``confine_to`` is given (for a directive-supplied path -- a ``file:`` /
    ``attr:`` / version-file directive that an untrusted ``setup.cfg`` / ``pyproject``
    controls), the resolved path MUST stay within ``confine_to``: a crafted
    ``file: /etc/passwd`` or ``../secret`` must NOT read an arbitrary host file into
    the emitted version. Mirrors the scancode ``..`` confinement. Returns ``None``
    if the file is absent, escapes the boundary, is unreadable, too large, or empty.
    """
    if confine_to is not None:
        try:
            resolved = path.resolve()
            root = confine_to.resolve()
        except OSError:
            return None
        if resolved != root and root not in resolved.parents:
            return None
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > _MAX_VERSION_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    stripped = text.strip()
    return stripped or None
