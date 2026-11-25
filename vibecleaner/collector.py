"""Repo walker, diff filter, auth-context header, and function-level slices."""

from __future__ import annotations

import logging
import os
import re
import stat
import subprocess
import warnings
from pathlib import Path, PurePosixPath

import pathspec
from tree_sitter import Node

from vibecleaner.models import CodeUnit, Language, ScanContext, SourceFile
from vibecleaner.ts_parse import callee_name as _callee_name
from vibecleaner.ts_parse import decorator_leaf as _decorator_leaf
from vibecleaner.ts_parse import line_text as _line_text
from vibecleaner.ts_parse import node_text as _text
from vibecleaner.ts_parse import parse_root
from vibecleaner.ts_parse import python_string as _python_string
from vibecleaner.ts_parse import script_string as _script_string
from vibecleaner.ts_parse import walk_tree as _walk

__all__ = [
    "CollectorError",
    "changed_lines",
    "collect",
    "extract_auth_context",
    "extract_units",
    "walk_repo",
]

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".vibecleaner",
        "node_modules",
        "dist",
        "build",
        ".next",
        "out",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "coverage",
        ".turbo",
        ".vercel",
        ".mypy_cache",
        ".pytest_cache",
        "site-packages",
    }
)
_SKIPPED_FILES = frozenset(
    {
        "VIBECLEANER_REPORT.md",
        "VIBECLEANER_STATES.md",
        "VIBECLEANER_DESLOP.md",
        "VIBECLEANER_PREFLIGHT.md",
        ".vibecleaner_cache.json",
        ".vibecleaner_cache.json.lock",
        "vibecleaner.sarif",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "bun.lockb",
    }
)
_ENV_EXAMPLE_NAMES = frozenset({".env.example", ".env.sample", ".env.template"})
_EXT_LANGUAGE = {
    ".py": Language.PYTHON,
    ".ts": Language.TYPESCRIPT,
    ".mts": Language.TYPESCRIPT,
    ".cts": Language.TYPESCRIPT,
    ".tsx": Language.TSX,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".cs": Language.CSHARP,
    ".sql": Language.SQL,
}
_MAX_BYTES = 1024 * 1024
_BINARY_PROBE = 8192
_AUTH_LIMIT = 2400
_UNIT_LIMIT = 12000
_MIN_BODY_LINES = 3
_ROUTE_VERBS = frozenset({"get", "post", "put", "patch", "delete", "api_route", "websocket"})
_HTTP_EXPORTS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_EXPRESS_OBJECTS = frozenset({"app", "router", "server", "api"})
_EXPRESS_METHODS = frozenset({"get", "post", "put", "patch", "delete", "all"})
_APP_ROUTE_NAMES = frozenset(
    {"route.ts", "route.tsx", "route.js", "route.jsx", "route.mjs", "route.cjs"}
)
_IO_NEEDLES = (
    "db",
    "session",
    "cursor",
    "execute",
    "query",
    "insert",
    "update",
    "delete",
    "commit",
    "supabase",
    ".from_(",
    "prisma",
    "requests.",
    "httpx",
    "aiohttp",
    "fetch",
    "openai",
    "anthropic",
    "llm",
    "chat",
    "invoke",
    "tool",
    "subprocess",
    "os.system",
    "open(",
)
_AUTH_NAME = re.compile(
    r"(auth|session|current_user|currentuser|require_?user|require_?auth|verify_?token|get_?user|login_required|protect)",
    re.IGNORECASE,
)
_AUTHISH = re.compile(
    r"(auth|session|jwt|clerk|oauth|passport|protect|login|credential|supabase|gate|gatekeeper|guard|verify|require|member|token|pin|principal|role|admin)",
    re.IGNORECASE,
)
_EMPTY_AUTH = "No global auth middleware or router-level dependencies detected."
_MW_CALLS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("clerkMiddleware", re.compile(r"\bclerkMiddleware\s*\(")),
    ("withAuth", re.compile(r"\bwithAuth\s*\(")),
    ("createMiddlewareClient", re.compile(r"\bcreateMiddlewareClient\s*\(")),
    ("createServerClient", re.compile(r"\bcreateServerClient\s*\(")),
    ("getToken", re.compile(r"\bgetToken\s*\(")),
    ("getSession", re.compile(r"\bgetSession\s*\(")),
    ("supabase.auth.getUser", re.compile(r"\bsupabase\s*\.\s*auth\s*\.\s*getUser\s*\(")),
    ("auth", re.compile(r"\bauth\s*\(")),
)
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_SOURCE_SUFFIXES = frozenset(_EXT_LANGUAGE) | frozenset({".pyi", ".pyw"})
_PROCESS_EXEC = frozenset(
    {
        "execFile",
        "execFileSync",
        "execSync",
        "execv",
        "execl",
        "execve",
        "execvp",
        "execlp",
        "execvpe",
    }
)
_EXEC_OWNERS = frozenset({"child_process", "cp", "os", "process"})
_WRITE_MODE = frozenset({"w", "a", "x"})

log = logging.getLogger("vibecleaner")


class CollectorError(Exception):
    """Git metadata needed for a diff scan is missing or unusable."""


def walk_repo(root: Path) -> list[SourceFile]:
    """Return scannable text files under ``root``, repo-relative and sorted."""
    given = Path(root)
    if not given.is_dir():
        raise CollectorError(f"{given} is not a directory")
    root = given.resolve()
    base_specs = _ancestor_gitignores(root)
    tracked_env = _tracked_env_files(root)
    specs_by_dir: dict[Path, list[tuple[Path, pathspec.PathSpec]]] = {root: base_specs}
    found: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        rel_dir = current.relative_to(root)
        specs = specs_by_dir.pop(current) + _ignore_specs(current)
        kept_dirs: list[str] = []
        for name in sorted(dirnames):
            if name in _SKIP_DIRS:
                continue
            sub_path = current / name
            rel = name if rel_dir == Path(".") else (rel_dir / name).as_posix()
            if _skip_dir(root, sub_path, rel):
                continue
            if _is_ignored(specs, sub_path, is_dir=True):
                continue
            kept_dirs.append(name)
            specs_by_dir[sub_path] = specs
        dirnames[:] = kept_dirs
        for name in sorted(filenames):
            source = _consider_file(root, current, rel_dir, name, specs, tracked_env)
            if source is not None:
                found.append(source)
    found.sort(key=lambda item: item.path)
    return found


def changed_lines(root: Path, base: str) -> dict[str, set[int] | None]:
    """Map changed repo-relative paths to added/modified 1-based lines.

    ``None`` means an untracked file (the whole file is in scope). Deleted
    paths are omitted. ``git diff -U0 --merge-base`` is the working tree
    compared with the merge base of ``base``; older git falls back to
    ``base...HEAD`` plus the unstaged/staged diff against ``HEAD``.
    """
    root = Path(root).resolve()
    _require_work_tree(root)
    if _git(root, ["rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"]).returncode != 0:
        raise CollectorError(f"unknown git ref {base!r}")
    prefix = _scan_prefix(root)
    diff_text, diff_error = _diff_against_base(root, base)
    if diff_error is not None:
        raise CollectorError(diff_error)
    changed = _remap_diff(_parse_unified_diff(diff_text), prefix)
    others = _git(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    if others.returncode != 0:
        raise CollectorError(f"git ls-files failed: {others.stderr.strip()}")
    for path in others.stdout.split("\0"):
        if path:
            changed[path.replace("\\", "/")] = None
    return changed


def extract_auth_context(files: list[SourceFile]) -> str:
    """Build the global auth header (middleware, router deps, helper signatures)."""
    hits: list[tuple[str, int, str]] = []
    for source in files:
        hits.extend(_auth_hits(source))
    if not hits:
        return _EMPTY_AUTH
    hits.sort()
    lines: list[str] = []
    seen: set[tuple[str, int, str]] = set()
    for path, line, text in hits:
        key = (path, line, text)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"{path}:{line}: {text}")
    from vibecleaner.deterministic import mask_secrets

    return _cap_text(mask_secrets("\n".join(lines)), _AUTH_LIMIT, "\n…[truncated]")


def extract_units(files: list[SourceFile]) -> list[CodeUnit]:
    """Slice route handlers and I/O functions for Layer 2."""
    units: list[CodeUnit] = []
    for source in files:
        if _is_test_unit_path(source.path):
            continue
        if source.language == Language.PYTHON:
            units.extend(_extract_python(source))
        elif source.language in {Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT}:
            units.extend(_extract_script(source))
    return _dedupe_units(units)


def collect(root: Path, diff_base: str | None = None) -> ScanContext:
    """Walk ``root`` and, when ``diff_base`` is set, keep only changed slices.

    Auth context is always built from the full walk, including unchanged files.
    """
    root = Path(root).resolve()
    files = walk_repo(root)
    auth_context = extract_auth_context(files)
    if diff_base is None:
        return ScanContext(
            root=root,
            files=files,
            units=extract_units(files),
            auth_context=auth_context,
            diff_base=None,
            changed_files=None,
        )
    changed = changed_lines(root, diff_base)
    selected = [source for source in files if source.path in changed]
    units: list[CodeUnit] = []
    for source in selected:
        touched = changed[source.path]
        for unit in extract_units([source]):
            if touched is None or any(unit.contains_line(line) for line in touched):
                units.append(unit)
    return ScanContext(
        root=root,
        files=selected,
        units=units,
        auth_context=auth_context,
        diff_base=diff_base,
        changed_files=sorted(source.path for source in selected),
    )


def _language_for(path: Path) -> Language:
    name = path.name
    if name in _ENV_EXAMPLE_NAMES:
        return Language.OTHER
    if name == ".env" or name.startswith(".env."):
        return Language.ENV
    return _EXT_LANGUAGE.get(path.suffix.lower(), Language.OTHER)


def _is_env_name(name: str) -> bool:
    if name in _ENV_EXAMPLE_NAMES:
        return False
    return name == ".env" or name.startswith(".env.")


def _git_toplevel(root: Path) -> Path | None:
    try:
        proc = _git(root, ["rev-parse", "--show-toplevel"])
    except CollectorError:
        return None
    if proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    if not raw:
        return None
    top = Path(raw).resolve()
    if not root.is_relative_to(top):
        return None
    return top


def _ancestor_gitignores(root: Path) -> list[tuple[Path, pathspec.PathSpec]]:
    git_root = _git_toplevel(root)
    if git_root is None or git_root == root:
        return []
    specs: list[tuple[Path, pathspec.PathSpec]] = []
    current = git_root
    for part in root.relative_to(git_root).parts[:-1]:
        specs.extend(_ignore_specs(current, (".gitignore",)))
        current = current / part
    specs.extend(_ignore_specs(current, (".gitignore",)))
    return specs


def _ignore_specs(
    directory: Path,
    names: tuple[str, ...] = (".gitignore", ".vibecleanerignore"),
) -> list[tuple[Path, pathspec.PathSpec]]:
    specs: list[tuple[Path, pathspec.PathSpec]] = []
    for name in names:
        path = directory / name
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        # pathspec still accepts the gitwildmatch id; it warns that the name moved.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="GitWildMatchPattern", category=DeprecationWarning)
            specs.append((directory, pathspec.PathSpec.from_lines("gitwildmatch", lines)))
    return specs


def _is_ignored(specs: list[tuple[Path, pathspec.PathSpec]], target: Path, *, is_dir: bool) -> bool:
    if not specs:
        return False
    for base_dir, spec in specs:
        if not target.is_relative_to(base_dir):
            continue
        rel = target.relative_to(base_dir).as_posix()
        if not rel or rel == ".":
            continue
        candidates = (rel, rel + "/") if is_dir and not rel.endswith("/") else (rel,)
        if any(spec.match_file(candidate) for candidate in candidates):
            return True
    return False


def _tracked_env_files(root: Path) -> set[str] | None:
    """Tracked ``.env*`` paths, or ``None`` when ``root`` is not a work tree.

    A committed ``.env`` is often still matched by ``.gitignore`` (it was force-added).
    Those tracked paths stay in the scan; untracked ignored env files do not.
    """
    try:
        probe = _git(root, ["rev-parse", "--is-inside-work-tree"])
    except CollectorError:
        return None
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        return None
    listed = _git(root, ["ls-files", "-z"])
    if listed.returncode != 0:
        raise CollectorError(f"git ls-files failed: {listed.stderr.strip()}")
    tracked: set[str] = set()
    for path in listed.stdout.split("\0"):
        if path and _is_env_name(PurePosixPath(path.replace("\\", "/")).name):
            tracked.add(path.replace("\\", "/"))
    return tracked


def _consider_file(
    root: Path,
    current: Path,
    rel_dir: Path,
    name: str,
    specs: list[tuple[Path, pathspec.PathSpec]],
    tracked_env: set[str] | None,
) -> SourceFile | None:
    if name in _SKIPPED_FILES or name.lower().endswith(".min.js"):
        return None
    rel = name if rel_dir == Path(".") else (rel_dir / name).as_posix()
    abs_path = current / name
    language = _language_for(Path(name))
    ignored = _is_ignored(specs, abs_path, is_dir=False)
    if language == Language.ENV and tracked_env is not None:
        if rel not in tracked_env and ignored:
            return None
    elif ignored:
        return None
    try:
        info = abs_path.lstat()
    except OSError as exc:
        log.debug("skipping %s (%s)", rel, exc)
        return None
    if stat.S_ISLNK(info.st_mode):
        log.debug("skipping symlink %s", rel)
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    if info.st_size > _MAX_BYTES:
        _log_skip(rel, "oversized")
        return None
    try:
        resolved = abs_path.resolve()
    except OSError as exc:
        log.debug("skipping %s (%s)", rel, exc)
        return None
    if not _within_root(root, resolved):
        log.debug("skipping %s (resolves outside scan root)", rel)
        return None
    try:
        data = abs_path.read_bytes()
    except OSError as exc:
        log.debug("skipping %s (%s)", rel, exc)
        return None
    if b"\0" in data[:_BINARY_PROBE]:
        _log_skip(rel, "binary")
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _log_skip(rel, "undecodable")
        return None
    return SourceFile(path=rel, abs_path=abs_path, language=language, text=text)


def _git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "--no-pager", "-C", str(root), *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise CollectorError("git is not installed") from exc


def _require_work_tree(root: Path) -> None:
    proc = _git(root, ["rev-parse", "--is-inside-work-tree"])
    if proc.returncode != 0 or proc.stdout.strip() != "true":
        raise CollectorError(f"{root} is not a git repository")


def _scan_prefix(root: Path) -> str:
    """Path of ``root`` relative to the work-tree root, with a trailing slash.

    ``git diff`` prints paths from the work-tree root, while ``git ls-files``
    prints paths from ``-C``. The prefix lines those two views up with the walk.
    """
    proc = _git(root, ["rev-parse", "--show-prefix"])
    if proc.returncode != 0:
        raise CollectorError(f"git rev-parse failed: {proc.stderr.strip()}")
    prefix = proc.stdout.strip().replace("\\", "/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return prefix


def _diff_against_base(root: Path, base: str) -> tuple[str, str | None]:
    merged = _git(root, ["diff", "-U0", "--merge-base", base])
    if merged.returncode == 0:
        return merged.stdout, None
    err = merged.stderr.lower()
    if "unknown option" in err or "unrecognized" in err or "usage:" in err:
        mb = _git(root, ["merge-base", base, "HEAD"])
        if mb.returncode == 0 and mb.stdout.strip():
            fallback = _git(root, ["diff", "-U0", mb.stdout.strip()])
            if fallback.returncode != 0:
                return "", f"git diff failed for base {base!r}: {fallback.stderr.strip()}"
            return fallback.stdout, None
        committed = _git(root, ["diff", "-U0", f"{base}...HEAD"])
        worktree = _git(root, ["diff", "-U0", "HEAD"])
        if committed.returncode != 0 or worktree.returncode != 0:
            detail = (committed.stderr or worktree.stderr).strip()
            return "", f"git diff failed for base {base!r}: {detail}"
        return committed.stdout + worktree.stdout, None
    return "", f"git diff failed for base {base!r}: {merged.stderr.strip()}"


def _parse_unified_diff(diff_text: str) -> dict[str, set[int]]:
    parsed: dict[str, set[int]] = {}
    current: str | None = None
    deleted = False
    in_hunk = False
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current = None
            deleted = False
            in_hunk = False
            continue
        if not in_hunk:
            if line.startswith("deleted file mode"):
                deleted = True
                current = None
                continue
            if line.startswith("+++ "):
                path = _normalize_diff_path(line[4:])
                if deleted or path == "/dev/null":
                    current = None
                else:
                    current = path
                    parsed.setdefault(current, set())
                continue
        if line.startswith("@@"):
            in_hunk = True
            if current is None:
                continue
            match = _HUNK_RE.match(line)
            if match is None:
                continue
            start = int(match.group(1))
            count = int(match.group(2)) if match.group(2) is not None else 1
            if count == 0:
                for line_no in (max(start, 1), start + 1):
                    if line_no > 0:
                        parsed[current].add(line_no)
            elif count > 0 and start > 0:
                parsed[current].update(range(start, start + count))
    return parsed


def _normalize_diff_path(raw: str) -> str:
    path = raw.strip()
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        inner = path[1:-1]
        try:
            path = bytes(inner, "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            path = inner
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return path.replace("\\", "/")


def _remap_diff(parsed: dict[str, set[int]], prefix: str) -> dict[str, set[int] | None]:
    remapped: dict[str, set[int] | None] = {}
    for path, lines in parsed.items():
        relative = _relative_to_scan(path, prefix)
        if relative is None:
            continue
        remapped[relative] = set(lines)
    return remapped


def _relative_to_scan(path: str, prefix: str) -> str | None:
    path = path.replace("\\", "/")
    if prefix:
        if not path.startswith(prefix):
            return None
        path = path[len(prefix) :]
    if not path or path.endswith("/"):
        return None
    return path


def _auth_hits(source: SourceFile) -> list[tuple[str, int, str]]:
    if source.language not in {Language.PYTHON, Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT}:
        return []
    hits: list[tuple[str, int, str]] = []
    if _is_middleware_path(source.path):
        hits.extend(_middleware_hits(source))
    if source.language == Language.PYTHON:
        hits.extend(_fastapi_hits(source))
    else:
        hits.extend(_express_hits(source))
    hits.extend(_signature_hits(source))
    return hits


def _is_middleware_path(path: str) -> bool:
    return re.fullmatch(r"(?:src/)?middleware\.(?:js|mjs|cjs|ts|tsx)", path) is not None


def _middleware_hits(source: SourceFile) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    text = source.text
    match = re.search(r"export\s+const\s+config\s*=\s*\{", text)
    if match is not None:
        brace = text.find("{", match.start())
        block = _span_delimited(text, brace, "{", "}") if brace >= 0 else None
        if block is not None and "matcher" in block:
            snippet = _oneline(text[match.start() : brace] + block)
            hits.append((source.path, text.count("\n", 0, match.start()) + 1, snippet))
    names: list[str] = []
    first_line: int | None = None
    for label, pattern in _MW_CALLS:
        found = pattern.search(text)
        if found is None or label in names:
            continue
        names.append(label)
        line = text.count("\n", 0, found.start()) + 1
        first_line = line if first_line is None else min(first_line, line)
    redirect = re.search(r"\bNextResponse\s*\.\s*redirect\s*\(", text)
    if redirect is not None:
        paren = text.find("(", redirect.start())
        call = _span_delimited(text, paren, "(", ")") if paren >= 0 else None
        if call is not None and re.search(r"login", call, re.IGNORECASE):
            names.append("NextResponse.redirect")
            line = text.count("\n", 0, redirect.start()) + 1
            first_line = line if first_line is None else min(first_line, line)
    if names and first_line is not None:
        hits.append((source.path, first_line, "auth calls: " + ", ".join(names)))
    return hits


def _fastapi_hits(source: SourceFile) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    text = source.text
    for match in re.finditer(r"\bFastAPI\s*\(", text):
        call = _call_at(text, match.end() - 1)
        if call is not None and re.search(r"\bdependencies\s*=", call):
            hits.append(_stmt_hit(source.path, text, match.start(), match.end() - 1))
    for match in re.finditer(r"(?m)^[ \t]*([A-Za-z_][\w]*)\s*=\s*APIRouter\s*\(", text):
        call = _call_at(text, match.end() - 1)
        if call is not None and re.search(r"\bdependencies\s*=", call):
            hits.append(_stmt_hit(source.path, text, match.start(), match.end() - 1))
    for match in re.finditer(r"\binclude_router\s*\(", text):
        call = _call_at(text, match.end() - 1)
        if call is not None and re.search(r"\bdependencies\s*=", call):
            hits.append(_stmt_hit(source.path, text, match.start(), match.end() - 1))
    for match in re.finditer(r"\badd_middleware\s*\(", text):
        call = _call_at(text, match.end() - 1)
        if call is not None and _AUTHISH.search(call):
            hits.append(_stmt_hit(source.path, text, match.start(), match.end() - 1))
    return hits


def _express_hits(source: SourceFile) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    text = source.text
    for match in re.finditer(r"\b([A-Za-z_][\w]*)\.use\s*\(", text):
        call = _call_at(text, match.end() - 1)
        if call is not None and _AUTHISH.search(call):
            hits.append(_stmt_hit(source.path, text, match.start(), match.end() - 1))
    return hits


def _stmt_hit(path: str, text: str, start: int, paren: int) -> tuple[str, int, str]:
    call = _call_at(text, paren) or ""
    snippet = _oneline(text[start:paren] + call)
    return path, text.count("\n", 0, start) + 1, snippet


def _signature_hits(source: SourceFile) -> list[tuple[str, int, str]]:
    root = parse_root(source)
    if root is None:
        return []
    hits: list[tuple[str, int, str]] = []
    for node in _walk(root):
        name: str | None = None
        line = node.start_point[0] + 1
        if source.language == Language.PYTHON and node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            name = _text(name_node) if name_node is not None else None
        elif node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            name = _text(name_node) if name_node is not None else None
        elif node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            name = _text(name_node) if name_node is not None else None
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            name_node = node.child_by_field_name("name")
            if value is not None and value.type in {"arrow_function", "function_expression"} and name_node is not None:
                name = _text(name_node)
                line = name_node.start_point[0] + 1
        if name and _AUTH_NAME.search(name):
            signature = _line_text(source.text, line)
            if signature:
                hits.append((source.path, line, _oneline(signature, limit=300)))
    return hits


def _call_at(text: str, open_paren: int) -> str | None:
    if open_paren < 0 or open_paren >= len(text) or text[open_paren] != "(":
        return None
    return _span_delimited(text, open_paren, "(", ")")


def _span_delimited(text: str, open_idx: int, open_ch: str, close_ch: str) -> str | None:
    depth = 0
    index = open_idx
    limit = len(text)
    while index < limit:
        char = text[index]
        if char in {"'", '"', "`"}:
            index = _skip_string(text, index)
            continue
        if char == open_ch:
            depth += 1
        elif char == close_ch:
            depth -= 1
            if depth == 0:
                return text[open_idx : index + 1]
        index += 1
    return None


def _skip_string(text: str, index: int) -> int:
    quote = text[index]
    if text.startswith(quote * 3, index):
        quote = quote * 3
    index += len(quote)
    limit = len(text)
    while index < limit:
        if text[index] == "\\" and len(quote) == 1:
            index += 2
            continue
        if text.startswith(quote, index):
            return index + len(quote)
        index += 1
    return limit


def _oneline(text: str, limit: int = 500) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "…"


def _cap_text(text: str, limit: int, note: str) -> str:
    if len(text) <= limit:
        return text
    keep = limit - len(note)
    if keep < 1:
        return note[:limit]
    return text[:keep].rstrip() + note


def _is_test_unit_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(part in {"tests", "test", "__tests__"} for part in parts):
        return True
    name = parts[-1] if parts else path
    if name == "conftest.py" or name.endswith("_test.py"):
        return True
    if name.startswith("test_") and name.endswith(".py"):
        return True
    return re.search(r"\.(test|spec)\.(tsx|ts|jsx|js|mjs|cjs)$", name) is not None


def _extract_python(source: SourceFile) -> list[CodeUnit]:
    root = parse_root(source)
    if root is None:
        return []
    units: list[CodeUnit] = []
    _visit_python(root, source, units)
    return units


def _visit_python(node: Node, source: SourceFile, units: list[CodeUnit]) -> None:
    for child in node.named_children:
        span_node = child
        target = child
        if child.type == "decorated_definition":
            definition = child.child_by_field_name("definition")
            if definition is None:
                continue
            target = definition
        if target.type == "function_definition":
            unit = _python_function_unit(source, span_node, target)
            if unit is not None:
                units.append(unit)
        elif target.type == "class_definition":
            body = target.child_by_field_name("body")
            if body is not None:
                _visit_python(body, source, units)


def _python_function_unit(source: SourceFile, span_node: Node, func: Node) -> CodeUnit | None:
    name_node = func.child_by_field_name("name")
    name = _text(name_node) if name_node is not None else "<anonymous>"
    route = _python_route(span_node) if span_node.type == "decorated_definition" else None
    if route is not None:
        method, route_path = route
        return _make_unit(source, span_node, name=name, kind="route", http_method=method, route_path=route_path)
    if _calls_sink(func):
        return _make_unit(source, span_node, name=name, kind="function")
    if _body_lines(func) < _MIN_BODY_LINES:
        return None
    start, end = _span(span_node)
    body = _slice(source.text, start, end)
    if not _mentions_io(body):
        return None
    return _make_unit(source, span_node, name=name, kind="function")


def _python_route(decorated: Node) -> tuple[str, str | None] | None:
    http: tuple[str, str | None] | None = None
    saw_tool = False
    for decorator in decorated.named_children:
        if decorator.type != "decorator":
            continue
        leaf = _decorator_leaf(decorator)
        inner = decorator.named_children[0] if decorator.named_children else None
        if leaf in _ROUTE_VERBS and inner is not None and inner.type == "call":
            http = (leaf.upper(), _first_string_arg(inner))
        elif leaf == "tool":
            saw_tool = True
    if http is not None:
        return http
    if saw_tool:
        return "TOOL", None
    return None


def _first_string_arg(call: Node) -> str | None:
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    for child in args.named_children:
        if child.type == "keyword_argument":
            break
        if child.type == "string":
            return _python_string(child)
    return None


def _extract_script(source: SourceFile) -> list[CodeUnit]:
    root = parse_root(source)
    if root is None:
        return []
    use_server = _is_use_server(root)
    app_path = _app_route_path(source.path)
    pages_path = _pages_api_route(source.path)
    units: list[CodeUnit] = []
    for node in _walk(root):
        if node.type == "export_statement":
            units.extend(_units_from_export(source, node, use_server, app_path, pages_path))
        elif node.type == "call_expression":
            unit = _express_unit(source, node)
            if unit is not None:
                units.append(unit)
    return units


def _units_from_export(
    source: SourceFile,
    node: Node,
    use_server: bool,
    app_path: str | None,
    pages_path: str | None,
) -> list[CodeUnit]:
    target = _export_target(node)
    if target is None:
        return []
    name, func, is_async, is_default = target
    if is_default and pages_path is not None:
        return [_make_unit(source, node, name=name or "handler", kind="route", http_method="ANY", route_path=pages_path)]
    if app_path is not None and name in _HTTP_EXPORTS:
        return [_make_unit(source, node, name=name, kind="route", http_method=name, route_path=app_path)]
    if use_server and is_async and name:
        return [_make_unit(source, node, name=name, kind="route", http_method="ACTION")]
    if not name:
        return []
    start, end = _span(node)
    body = _slice(source.text, start, end)
    if _calls_sink(func) or (_body_lines(func) >= _MIN_BODY_LINES and _mentions_io(body)):
        return [_make_unit(source, node, name=name, kind="function")]
    return []


def _export_target(node: Node) -> tuple[str | None, Node, bool, bool] | None:
    is_default = any(child.type == "default" for child in node.children)
    for child in node.named_children:
        if child.type == "function_declaration":
            name_node = child.child_by_field_name("name")
            name = _text(name_node) if name_node is not None else None
            return name, child, _is_async(child), is_default
        if child.type != "lexical_declaration":
            continue
        for declarator in child.named_children:
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name_node is None or value is None:
                continue
            if value.type not in {"arrow_function", "function_expression"}:
                continue
            return _text(name_node), value, _is_async(value), is_default
    return None


def _express_unit(source: SourceFile, call: Node) -> CodeUnit | None:
    func = call.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return None
    obj = func.child_by_field_name("object")
    prop = func.child_by_field_name("property")
    if obj is None or prop is None or obj.type != "identifier":
        return None
    method = _text(prop).lower()
    if method not in _EXPRESS_METHODS:
        return None
    args = call.child_by_field_name("arguments")
    if args is None or not args.named_children:
        return None
    route_path = _script_string(args.named_children[0])
    if route_path is None:
        return None
    if _text(obj) not in _EXPRESS_OBJECTS:
        if not route_path.startswith("/"):
            return None
        if len(args.named_children) < 2 or args.named_children[-1].type not in {
            "arrow_function",
            "function_expression",
        }:
            return None
    http_method = method.upper()
    name = _express_name(http_method, route_path, args)
    return _make_unit(source, call, name=name, kind="route", http_method=http_method, route_path=route_path)


def _express_name(method: str, route_path: str, args: Node) -> str:
    if len(args.named_children) >= 2:
        last = args.named_children[-1]
        if last.type == "identifier":
            return _text(last)
        if last.type in {"function_expression", "function_declaration"}:
            name_node = last.child_by_field_name("name")
            if name_node is not None:
                return _text(name_node)
    return f"{method} {route_path}"


def _is_use_server(root: Node) -> bool:
    for child in root.named_children:
        if child.type == "comment":
            continue
        if child.type != "expression_statement" or not child.named_children:
            return False
        expr = child.named_children[0]
        return expr.type == "string" and _script_string(expr) == "use server"
    return False


def _app_route_path(path: str) -> str | None:
    parts = list(PurePosixPath(path).parts)
    if not parts or parts[-1] not in _APP_ROUTE_NAMES or "app" not in parts[:-1]:
        return None
    index = parts.index("app")
    segments = [
        segment
        for segment in parts[index + 1 : -1]
        if not (segment.startswith("(") and segment.endswith(")"))
    ]
    if not segments:
        return "/"
    return "/" + "/".join(segments)


def _pages_api_route(path: str) -> str | None:
    parts = list(PurePosixPath(path).parts)
    if "pages" not in parts:
        return None
    index = parts.index("pages")
    rest = parts[index + 1 :]
    if len(rest) < 2 or rest[0] != "api":
        return None
    if not rest[-1].endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        return None
    leaf = re.sub(r"\.(tsx|ts|jsx|js|mjs|cjs)$", "", rest[-1])
    segments = list(rest[:-1])
    if leaf != "index":
        segments.append(leaf)
    if not segments:
        return "/"
    return "/" + "/".join(segments)


def _is_async(node: Node) -> bool:
    return any(child.type == "async" for child in node.children)


def _mentions_io(source: str) -> bool:
    return any(needle in source for needle in _IO_NEEDLES)


def _calls_sink(func: Node) -> bool:
    for node in _walk(func):
        if node.type not in {"call", "call_expression"}:
            continue
        callee = node.child_by_field_name("function")
        if callee is None:
            continue
        if _callee_is_sink(callee) or _open_writes(node, callee):
            return True
    return False


def _callee_is_sink(callee: Node) -> bool:
    parts = [part for part in _callee_name(callee).split(".") if part]
    if not parts:
        return False
    leaf = parts[-1]
    if _dotted_owner(parts, "requests") or _dotted_owner(parts, "httpx"):
        return True
    if any(part == "aiohttp" for part in parts):
        return True
    if leaf == "fetch" or any(part == "axios" for part in parts):
        return True
    if any(part == "urllib" or part.startswith("urllib") for part in parts):
        return True
    if any(part == "subprocess" for part in parts):
        return True
    if _is_os_system(parts) or _is_process_exec(parts) or leaf in {"spawn", "spawnSync"}:
        return True
    return "fs" in parts[:-1] and leaf.startswith("writeFile")


def _dotted_owner(parts: list[str], name: str) -> bool:
    return len(parts) >= 2 and name in parts[:-1]


def _is_os_system(parts: list[str]) -> bool:
    return len(parts) >= 2 and parts[-2] == "os" and parts[-1] == "system"


def _is_process_exec(parts: list[str]) -> bool:
    leaf = parts[-1]
    if leaf in _PROCESS_EXEC:
        return True
    if leaf.startswith("execut"):
        return False
    if leaf == "exec":
        return len(parts) == 1 or parts[-2] in _EXEC_OWNERS
    return len(parts) >= 2 and parts[-2] == "os" and leaf.startswith("exec")


def _open_writes(call: Node, callee: Node) -> bool:
    parts = [part for part in _callee_name(callee).split(".") if part]
    if not parts or parts[-1] != "open":
        return False
    mode = _open_mode(call)
    return mode is not None and mode[:1] in _WRITE_MODE


def _open_mode(call: Node) -> str | None:
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    positional: list[Node] = []
    for child in args.named_children:
        if child.type != "keyword_argument":
            positional.append(child)
            continue
        key = child.child_by_field_name("name")
        value = child.child_by_field_name("value")
        if key is not None and value is not None and _text(key) == "mode":
            return _literal_text(value)
    if len(positional) >= 2:
        return _literal_text(positional[1])
    return None


def _literal_text(node: Node) -> str | None:
    python = _python_string(node)
    if python:
        return python
    return _script_string(node)


def _body_lines(node: Node) -> int:
    body = node.child_by_field_name("body")
    if body is None:
        for child in node.named_children:
            if child.type in {"block", "statement_block"}:
                body = child
                break
    if body is None:
        return 0
    start, end = _span(body)
    return end - start + 1


def _make_unit(
    source: SourceFile,
    node: Node,
    *,
    name: str,
    kind: str,
    http_method: str | None = None,
    route_path: str | None = None,
) -> CodeUnit:
    start, end = _span(node)
    text = _cap_source(_slice(source.text, start, end), source.language)
    return CodeUnit(
        file=source.path,
        language=source.language,
        name=name,
        kind=kind,
        start_line=start,
        end_line=end,
        source=text,
        http_method=http_method,
        route_path=route_path,
    )


def _span(node: Node) -> tuple[int, int]:
    start0 = node.start_point[0]
    end0 = node.end_point[0]
    if node.end_point[1] == 0 and end0 > start0:
        last0 = end0 - 1
    else:
        last0 = end0
    if last0 < start0:
        last0 = start0
    return start0 + 1, last0 + 1


def _slice(text: str, start: int, end: int) -> str:
    rows = text.splitlines()
    if not rows:
        return ""
    start = max(1, start)
    end = min(len(rows), max(start, end))
    return "\n".join(rows[start - 1 : end])


def _cap_source(source: str, language: Language) -> str:
    if len(source) <= _UNIT_LIMIT:
        return source
    marker = "\n# …[truncated]\n" if language == Language.PYTHON else "\n/* …[truncated] */\n"
    keep = _UNIT_LIMIT - len(marker)
    if keep < 1:
        return marker[:_UNIT_LIMIT]
    return source[:keep] + marker


def _dedupe_units(units: list[CodeUnit]) -> list[CodeUnit]:
    routes = _keep_outermost([unit for unit in units if unit.kind == "route"])
    functions: list[CodeUnit] = []
    for unit in _keep_outermost([unit for unit in units if unit.kind != "route"]):
        if any(_overlaps(unit, route) for route in routes):
            continue
        functions.append(unit)
    return sorted([*routes, *functions], key=lambda unit: (unit.file, unit.start_line, unit.end_line, unit.name))


def _keep_outermost(units: list[CodeUnit]) -> list[CodeUnit]:
    ordered = sorted(units, key=lambda unit: (unit.file, unit.start_line, -(unit.end_line - unit.start_line)))
    kept: list[CodeUnit] = []
    for unit in ordered:
        if any(_overlaps(unit, previous) for previous in kept):
            continue
        kept.append(unit)
    return kept


def _overlaps(left: CodeUnit, right: CodeUnit) -> bool:
    return left.file == right.file and left.start_line <= right.end_line and right.start_line <= left.end_line


def _skip_dir(root: Path, path: Path, rel: str) -> bool:
    if path.is_symlink():
        log.debug("skipping symlink %s", rel)
        return True
    try:
        resolved = path.resolve()
    except OSError as exc:
        log.debug("skipping %s (%s)", rel, exc)
        return True
    if not _within_root(root, resolved):
        log.debug("skipping %s (resolves outside scan root)", rel)
        return True
    return False


def _within_root(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _source_like(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.suffix.lower() in _SOURCE_SUFFIXES:
        return True
    name = pure.name
    return name == ".env" or name.startswith(".env.")


def _log_skip(path: str, reason: str) -> None:
    level = logging.WARNING if _source_like(path) else logging.DEBUG
    log.log(level, "skipping %s (%s)", path, reason)
