"""Section D: races, pagination, time, backups, tests, and account deletion."""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from vibeguard.models import SourceFile
from vibeguard.preflight.code_text import comments_blanked, is_blankable, is_sql_path, sql_statements
from vibeguard.preflight.patterns import (
    _ACCOUNTS,
    _CI_TEST,
    _D7A,
    _DELETE_ACCOUNT,
    _DOWN_MIGRATION,
    _HTTP,
    _INVENTORY,
    _NAIVE_JS,
    _NAIVE_PY,
    _NAIVE_SQL,
    _SCHEDULING,
    _STOCK_SAFE,
)
from vibeguard.preflight.results import CheckResult, Status, _evidence, _make, _uniq
from vibeguard.preflight.signals import _accounts, _database, _has_ui, _http
from vibeguard.preflight.view import RepoView, _is_comment, _is_prose_path, _is_test_path

_DISK_SKIP = frozenset({"node_modules", ".git", ".venv", "dist", "build"})
_DISK_LIMIT = 4000
_TEST_DIRS = frozenset({"tests", "test", "__tests__"})


def _inventory_hit(source: SourceFile, view: RepoView) -> tuple[str | None, bool]:
    usable = view.code_only(source) if is_blankable(source) else source.text
    statements = sql_statements(source) if is_blankable(source) else []
    loc: str | None = None
    for number, line in enumerate(usable.splitlines(), start=1):
        if _is_comment(line):
            continue
        if _INVENTORY.search(line):
            loc = f"{source.path}:{number}"
            break
    if loc is None:
        for line_no, text in statements:
            if _INVENTORY.search(text):
                loc = f"{source.path}:{line_no}"
                break
    if loc is None:
        return None, False
    guarded = _STOCK_SAFE.search(usable) is not None or any(
        _STOCK_SAFE.search(text) for _line, text in statements
    )
    return loc, guarded


def check_25(view: RepoView) -> CheckResult:
    unsafe: list[str] = []
    safe: list[str] = []
    for source in view.files:
        if _is_test_path(source.path) or _is_prose_path(source.path):
            continue
        if not is_blankable(source) and not is_sql_path(source.path):
            continue
        loc, guarded = _inventory_hit(source, view)
        if loc is None:
            continue
        if guarded:
            safe.append(loc)
        else:
            unsafe.append(loc)
    if not safe and not unsafe:
        return _make(
            25,
            Status.NOT_APPLICABLE,
            "No stock balance, booking, or reservation code was found.",
            "reason: no stock balance or booking",
            "There is no last item or slot for two people to claim.",
        )
    if unsafe:
        return _make(
            25,
            Status.PROBLEM,
            "Stock or booking code is present without SELECT ... FOR UPDATE, an atomic stock decrement that checks remaining quantity, or a unique constraint on the slot.",
            _evidence(unsafe, "not run"),
            "Two people can buy the last item or book the same slot.",
            "Decrement stock in one conditional update (or lock the row) and put a unique constraint on the slot. Success: two simultaneous attempts leave exactly one success.",
            unsafe,
        )
    return _make(
        25,
        Status.OK,
        "Inventory or booking code uses a row lock, a conditional decrement, or a unique slot constraint.",
        _evidence(safe, "not run"),
        "A path that does not use that statement can still oversell.",
        "From two accounts at once, buy the last item or book the same slot. Success: exactly one succeeds and stock or the slot decreases once.",
        safe,
    )


_SQL_FROM = re.compile(
    r"(?i)\b(?:from|join)\s+(?:only\s+)?(?:[\w]+\.)?[\"'`]?([A-Za-z_][\w]*)"
)
_SELECT_CHUNK = re.compile(r"(?is)\bselect\b(?:(?!\bselect\b)[^;]){0,900}")
_POINT_LIMIT = re.compile(r"(?i)\blimit\s+1\b")
_OFFSET = re.compile(r"(?i)\boffset\b")
_AGGREGATE = re.compile(r"(?i)\bselect\s+(?:distinct\s+)?(?:count|sum|avg|min|max)\s*\(")
_EXISTENCE = re.compile(r"(?i)\bselect\s+1\b")
_PAGE_IN_STMT = re.compile(r"(?i)\boffset\b|\blimit\s+(?!1\b)\S")
_POINT_EQ = re.compile(r"(?i)\b(?:token|uuid|email|slug|id)\s*=")
_ORDER_BY = re.compile(r"(?i)\border\s+by\b")
_IMPORT_TAIL = re.compile(r"(?:\s*\.\w+)+\s+import\b|\s+import\b")
_SQL_TAIL = re.compile(
    r"(?is)\s*(?:(?:as\s+)?[A-Za-z_][\w]*\s+)?"
    r"(?:where\b|join\b|order\b|group\b|limit\b|offset\b|union\b|having\b|on\b|,|\)|;|['\"`]|$)"
)
_ONE_ROW = re.compile(r"(?i)\.fetchone\s*\(|\.maybeSingle\s*\(|\.single\s*\(")
_PAGINATION = re.compile(
    r"(?i)(?:\boffset\b|\.range\s*\(|\.skip\s*\(|\.take\s*\(|"
    r"\bLIMIT\s+(?!1\b)\S|\.limit\s*\(\s*(?!1\s*\))|"
    r"\b(?:page_size|pageSize|per_page|perPage)\b)"
)
_INDEX_ON = re.compile(
    r"(?i)\bCREATE\s+(?:UNIQUE\s+)?INDEX\b[^;]{0,300}?\bON\s+(?:ONLY\s+)?"
    r"(?:[\w]+\.)?[\"'`]?([A-Za-z_][\w]*)"
)
_FIND_MANY = re.compile(r"(?i)\b(\w+)\.findMany\s*\(")
_SUPA_FROM = re.compile(r"""(?i)\.from\(\s*['"]([A-Za-z_][\w.]*)['"]\s*\)""")
_DRIZZLE_FROM = re.compile(r"(?i)\.select\s*\(\s*\)\s*\.from\s*\(\s*([A-Za-z_][\w]*)\s*\)")
_CHAIN_POINT = re.compile(r"(?i)\.limit\s*\(\s*1\s*\)|\.maybeSingle\s*\(|\.single\s*\(")
_CHAIN_PAGE = re.compile(r"(?i)\.range\s*\(|\.offset\s*\(|\.skip\s*\(|\.take\s*\(")


class _ListFile(NamedTuple):
    lines: tuple[str, ...]
    groups: tuple[frozenset[str], ...]
    paginated: bool
    page_locs: tuple[str, ...]


def _table_keys(name: str) -> set[str]:
    token = name.strip("\"'`")
    if "." in token:
        token = token.rsplit(".", 1)[-1]
    key = token.lower()
    keys = {key}
    if len(key) > 3 and key.endswith("s"):
        keys.add(key[:-1])
    elif len(key) > 2:
        keys.add(key + "s")
    return keys


def _sql_from_names(statement: str) -> list[str]:
    names: list[str] = []
    for match in _SQL_FROM.finditer(statement):
        rest = statement[match.end() : match.end() + 60]
        if _IMPORT_TAIL.match(rest) or _SQL_TAIL.match(rest) is None:
            continue
        names.append(match.group(1))
    return names


def _is_list_select(statement: str) -> bool:
    if not _sql_from_names(statement):
        return False
    if _AGGREGATE.search(statement) or _EXISTENCE.search(statement) or _ONE_ROW.search(statement):
        return False
    if _POINT_LIMIT.search(statement) and not _OFFSET.search(statement):
        return False
    if _PAGE_IN_STMT.search(statement) or _ORDER_BY.search(statement):
        return True
    if _POINT_EQ.search(statement):
        return False
    return True


def _select_lists(text: str) -> list[tuple[int, frozenset[str]]]:
    found: list[tuple[int, frozenset[str]]] = []
    for match in _SELECT_CHUNK.finditer(text):
        statement = match.group(0)
        if not _is_list_select(statement):
            continue
        tables: set[str] = set()
        for name in _sql_from_names(statement):
            tables.update(_table_keys(name))
        line = text.count("\n", 0, match.start()) + 1
        found.append((line, frozenset(tables)))
    return found


def _chain_is_point(window: str) -> bool:
    return _CHAIN_POINT.search(window) is not None and _CHAIN_PAGE.search(window) is None


def _orm_lists(text: str) -> list[tuple[int, frozenset[str]]]:
    found: list[tuple[int, frozenset[str]]] = []
    for match in _FIND_MANY.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        found.append((line, frozenset(_table_keys(match.group(1)))))
    for match in _DRIZZLE_FROM.finditer(text):
        window = text[match.end() : match.end() + 400]
        if _chain_is_point(window):
            continue
        line = text.count("\n", 0, match.start()) + 1
        found.append((line, frozenset(_table_keys(match.group(1)))))
    for match in _SUPA_FROM.finditer(text):
        window = text[match.end() : match.end() + 400]
        if re.search(r"(?i)\.(?:insert|update|delete|upsert)\s*\(", window[:160]):
            continue
        if not re.search(r"(?i)\.select\s*\(", window):
            continue
        if _chain_is_point(window):
            continue
        line = text.count("\n", 0, match.start()) + 1
        found.append((line, frozenset(_table_keys(match.group(1)))))
    return found


def _page_locs(path: str, text: str) -> tuple[str, ...]:
    found: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if _PAGINATION.search(line):
            found.append(f"{path}:{number}")
        if len(found) >= 3:
            break
    return tuple(found)


def _list_files(view: RepoView) -> list[_ListFile]:
    files: list[_ListFile] = []
    for source in view.files:
        if _is_test_path(source.path) or _is_prose_path(source.path):
            continue
        text = comments_blanked(source)
        hits = _select_lists(text) + _orm_lists(text)
        if not hits:
            continue
        lines = _uniq(f"{source.path}:{line}" for line, _tables in hits)
        files.append(
            _ListFile(
                lines=tuple(lines[:6]),
                groups=tuple(tables for _line, tables in hits),
                paginated=_PAGINATION.search(text) is not None,
                page_locs=_page_locs(source.path, text),
            )
        )
    return files


def _index_map(view: RepoView) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for source in view.files:
        if _is_test_path(source.path) or _is_prose_path(source.path):
            continue
        text = comments_blanked(source)
        for match in _INDEX_ON.finditer(text):
            loc = f"{source.path}:{text.count(chr(10), 0, match.start()) + 1}"
            for key in _table_keys(match.group(1)):
                bucket = found.setdefault(key, [])
                if loc not in bucket:
                    bucket.append(loc)
    return found


def _group_indexed(tables: frozenset[str], indexes: dict[str, list[str]]) -> bool:
    return bool(tables) and all(name in indexes for name in tables)


def _list_covered(item: _ListFile, indexes: dict[str, list[str]]) -> bool:
    if item.paginated:
        return True
    return all(_group_indexed(tables, indexes) for tables in item.groups)


def _coverage_locs(files: list[_ListFile], indexes: dict[str, list[str]]) -> list[str]:
    locs: list[str] = []
    for item in files:
        locs.extend(item.lines[:2])
        if item.paginated:
            locs.extend(item.page_locs[:2])
            continue
        for tables in item.groups:
            for name in tables:
                locs.extend(indexes.get(name, [])[:1])
    return _uniq(locs)


def check_26(view: RepoView) -> CheckResult:
    unbounded = view.locs_for(_D7A)
    if unbounded:
        return _make(
            26,
            Status.PROBLEM,
            "An N+1 or unbounded-query finding (D7a.n_plus_one_loop) is present.",
            _evidence(unbounded, "not run"),
            "A long list can time out or skip and repeat rows.",
            "Batch the lookups and add LIMIT plus an index for the filter and sort. Success: 1001 rows still reach the last page through pagination and search with no gaps or duplicates.",
            unbounded,
        )
    files = _list_files(view)
    indexes = _index_map(view)
    if not files and not _database(view) and not indexes:
        return _make(
            26,
            Status.NOT_APPLICABLE,
            "No database query or migration was found.",
            "reason: no database queries",
            "There is no list query to page or index.",
        )
    covered = [item for item in files if _list_covered(item, indexes)]
    uncovered = [item for item in files if item not in covered]
    if files and not uncovered:
        locs = _coverage_locs(covered, indexes)
        return _make(
            26,
            Status.OK,
            "Each list query has LIMIT, offset, or another page bound in its file, or an index on the table it reads.",
            _evidence(locs, "not run"),
            "The page size can still be unbounded on a path this pattern did not see.",
            "Create 1001 test rows and open the last page via pagination and search. Success: no gaps or duplicates, and the filter and sort columns are indexed.",
            locs,
        )
    if uncovered:
        locs = _uniq(line for item in uncovered for line in item.lines)
        return _make(
            26,
            Status.WARNING,
            "A list query has no LIMIT, offset, or other page bound in its file, and its table has no index.",
            _evidence(locs, "not run"),
            "A long list can time out or skip and repeat rows.",
            "Add LIMIT or offset in that file, or an index on the filtered and sorted columns, then load 1001 rows and open the last page. Success: no gaps or duplicates.",
            locs,
        )
    return _make(
        26,
        Status.NOT_CHECKED,
        "Database code is present. No list query with pagination in its file, or an index on that table, was found. A 1001-row page was not loaded.",
        "not run",
        "A long list can omit rows, repeat rows, or scan the whole table.",
        "Create 1001 test records and find the last via pagination and search. Success: no gaps or duplicates, and the filter and sort columns are indexed.",
    )


def check_27(view: RepoView) -> CheckResult:
    scheduling = view.search_usage(_SCHEDULING, skip_tests=True, limit=5)
    if not scheduling:
        return _make(
            27,
            Status.NOT_APPLICABLE,
            "No booking, appointment, reservation, calendar, or time-zone code was found.",
            "reason: no scheduling code",
            "There is no booking time to show in the wrong zone.",
        )
    naive: list[str] = []
    for path, number, line in view.iter_usage_lines(skip_tests=True):
        if _is_comment(line):
            continue
        if _NAIVE_PY.search(line) or _NAIVE_JS.search(line):
            naive.append(f"{path}:{number}")
    for path, number, line in view.iter_lines(skip_tests=True, suffixes=frozenset({".sql"})):
        if _is_comment(line):
            continue
        if _NAIVE_SQL.search(line):
            naive.append(f"{path}:{number}")
    if naive:
        return _make(
            27,
            Status.WARNING,
            "Scheduling code is present and a naive datetime.now()/utcnow(), a parsed new Date(...), or a timestamp without time zone was found.",
            _evidence(_uniq(naive), "not run"),
            "Two people in different time zones can see the wrong local time or miss the slot.",
            "Store instants as timezone-aware UTC (timestamptz) and render local time in the UI. Success: two test users in different zones see the correct local time for the same booking.",
            _uniq(naive[:12]),
        )
    return _make(
        27,
        Status.NOT_CHECKED,
        "Scheduling code is present and no naive datetime.now(), parsed new Date(), or bare SQL timestamp was found. The UI clock was not compared across zones.",
        _evidence(scheduling, "not run"),
        "The screen can still format UTC as if it were local time.",
        "Create one booking and view it as two users in different time zones. Success: both see the correct local time and the stored value is UTC.",
        scheduling,
    )


def check_28(view: RepoView) -> CheckResult:
    if not _database(view):
        return _make(
            28,
            Status.NOT_APPLICABLE,
            "No database client, SQL table, or DATABASE_URL was found, so there is no data store to back up.",
            "reason: no database",
            "There is no stored record this scan can ask you to restore.",
        )
    return _make(
        28,
        Status.NOT_CHECKED,
        "A database is present. Backup schedule, failure alerts, and a restore were not checked. Look in the database host (for example the Supabase, RDS, or Neon backup panel), not only in this repo.",
        "not run",
        "A bad deploy or a deleted row can be unrecoverable.",
        "Read the backup schedule and who is alerted when a backup fails. Restore a test backup into a fresh database. Success: row counts match the source and a failed backup notifies a person.",
    )


def check_29(view: RepoView) -> CheckResult:
    downs = _uniq(
        view.search_usage(_DOWN_MIGRATION, skip_tests=True, limit=5)
        + view.search(_DOWN_MIGRATION, skip_tests=True, skip_comments=False, suffixes=frozenset({".sql"}), limit=5)
    )
    if downs:
        return _make(
            29,
            Status.WARNING,
            "A down or rollback migration is present. Compatibility of the previous release with the new schema was not rehearsed.",
            _evidence(downs, "not run"),
            "Rolling back the app or the migration can drop rows or fail to boot.",
            "Deploy the previous version against a copy of the new schema, or run the down migration on a copy. Success: the old version still serves traffic and user data is still there.",
            downs,
        )
    return _make(
        29,
        Status.NOT_CHECKED,
        "No down migration (alembic downgrade, goose Down, or migrate:down) was found. Rollback was not rehearsed.",
        "not run",
        "A bad deploy can leave the service down, or a rollback can delete data.",
        "Look in the migrations directory and the deploy workflow. Success: you can redeploy the previous version, the previous version tolerates the new schema, and a rollback does not drop user data.",
    )


def _raise_walk_error(error: OSError) -> None:
    raise error


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _config_is_tests(path: Path) -> bool:
    name = path.name.lower()
    if name in {"pytest.ini", "pytest.toml"}:
        return True
    if name.startswith(("vitest.config.", "jest.config.")):
        return True
    if name != "pyproject.toml":
        return False
    return "[tool.pytest" in _read_text(path)


def _workflow_ci(path: Path, rel: str) -> str | None:
    if not rel.startswith(".github/workflows/"):
        return None
    if PurePosixPath(rel).suffix.lower() not in {".yml", ".yaml"}:
        return None
    if not _CI_TEST.search(_read_text(path)):
        return None
    return f"{rel}:1"


def _disk_tests(root: Path) -> tuple[list[str], list[str]]:
    """Test and CI paths on disk. Ignores scan scope and ``.vibeguardignore``."""
    tests: list[str] = []
    ci: list[str] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=_raise_walk_error):
        dirnames[:] = [name for name in dirnames if name not in _DISK_SKIP]
        base = Path(dirpath)
        for dirname in dirnames:
            if dirname in _TEST_DIRS:
                tests.append((base / dirname).relative_to(root).as_posix())
        for name in filenames:
            seen += 1
            if seen > _DISK_LIMIT:
                return _uniq(tests), _uniq(ci)
            path = base / name
            rel = path.relative_to(root).as_posix()
            if _is_test_path(rel) or _config_is_tests(path):
                tests.append(rel)
            hit = _workflow_ci(path, rel)
            if hit is not None:
                ci.append(hit)
    return _uniq(tests), _uniq(ci)


def _test_anchor(paths: list[str]) -> str:
    preferred = {".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
    for path in paths:
        if PurePosixPath(path).suffix.lower() in preferred:
            return path
    for path in paths:
        if PurePosixPath(path).suffix:
            return path
    return paths[0]


def _page_locations(view: RepoView, limit: int = 3) -> list[str]:
    found: list[str] = []
    for source in view.files:
        if _is_test_path(source.path):
            continue
        path = source.path
        suffix = PurePosixPath(path).suffix.lower()
        name = PurePosixPath(path).name
        is_page = name.startswith("page.") or name in {"index.html", "index.htm"}
        is_markup = suffix in {".html", ".htm", ".vue"}
        is_component = suffix in {".tsx", ".jsx"} and "/api/" not in f"/{path}"
        if not (is_page or is_markup or is_component):
            continue
        found.append(f"{path}:1")
        if len(found) >= limit:
            break
    return found


def _route_locations(view: RepoView) -> list[str]:
    found = view.search(_HTTP, skip_tests=True, limit=3)
    if found:
        return found
    pages = _page_locations(view)
    if pages:
        return pages
    for path, number, line in view.iter_lines(skip_tests=True):
        if _HTTP.search(line):
            return [f"{path}:{number}"]
    return []


def check_30(view: RepoView) -> CheckResult:
    root = view.root_dir()
    tests, ci = _disk_tests(root) if root is not None else ([], [])
    if tests and ci:
        locs = [f"{_test_anchor(tests)}:1", ci[0]]
        return _make(
            30,
            Status.OK,
            "Test files and a CI workflow that runs them are present. This scan did not execute the suite.",
            _evidence(locs, "not run"),
            "The suite can still be red on the revision you ship.",
            "Run the suite locally and confirm CI runs it on every deploy. Success: the main-flow tests pass in CI before the deploy.",
            locs,
        )
    if tests:
        loc = [f"{_test_anchor(tests)}:1"]
        return _make(
            30,
            Status.WARNING,
            "Test files are present and no CI workflow that runs pytest, npm test, vitest, or jest was found.",
            _evidence(loc, "not run"),
            "A broken main flow can deploy because nothing runs the tests first.",
            "Add a CI job that runs the suite before deploy. Success: a failing test blocks the release.",
            loc,
        )
    if _http(view) or _has_ui(view):
        where = _route_locations(view)
        return _make(
            30,
            Status.PROBLEM,
            "HTTP routes or pages are present and no test file (tests/, *.test.ts, *.spec.ts, or test_*.py) was found.",
            _evidence(where, "reason: no test files"),
            "The main flow can break on the next change and still deploy.",
            "Add tests for the main flow and run them in CI before every deploy. Success: CI fails when those tests fail.",
            where,
        )
    if not view.files:
        return _make(
            30,
            Status.NOT_CHECKED,
            "No files were scanned, so tests could not be judged.",
            "not run",
            "A main flow without tests can ship broken.",
            "Add tests for the main flow and run them before every deploy. Success: CI fails when they fail.",
        )
    return _make(
        30,
        Status.WARNING,
        "No test files and no CI test job were found. No HTTP route was found either, so this may be a library rather than the product flow.",
        "reason: no test files",
        "A behavior this code is responsible for can change without a failing test.",
        "Add tests for the public behavior and run them in CI. Success: CI fails when they fail.",
    )


def check_31(view: RepoView) -> CheckResult:
    if not _accounts(view):
        return _make(
            31,
            Status.NOT_APPLICABLE,
            "No user account, sign-up, or auth.users reference was found, so there is no account to delete.",
            "reason: no user accounts",
            "There is no account whose personal data must be erased.",
        )
    deletion = view.search(_DELETE_ACCOUNT, skip_tests=True, limit=5)
    if deletion:
        return _make(
            31,
            Status.NOT_CHECKED,
            "An account-deletion route or helper is present. What it removes was not compared with a privacy policy.",
            _evidence(deletion, "not run"),
            "The product can delete less than the privacy policy promises, or keep data with no stated limit.",
            "Delete a test account and list what is removed, what is kept, and for how long. Success: that list matches the privacy policy's erasure terms (GDPR/CCPA).",
            deletion,
        )
    where = view.search_usage(_ACCOUNTS, skip_tests=True, limit=3)
    return _make(
        31,
        Status.PROBLEM,
        "User accounts are present and no account-deletion endpoint (delete account, delete user, or DELETE /users/me) was found.",
        _evidence(where, "reason: no account-deletion route"),
        "A person cannot erase their account, which GDPR and CCPA require you to offer when you hold their data.",
        "Add a deletion path and delete a test account. Success: what is removed, what is kept, and the retention period match the privacy policy.",
        where,
    )
