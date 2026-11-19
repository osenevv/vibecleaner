"""Layer 1 walker, diff filter, and deterministic rules."""

from __future__ import annotations

import base64
import logging
import subprocess
from pathlib import Path, PurePosixPath

import pytest

from vibecleaner.collector import (
    CollectorError,
    changed_lines,
    collect,
    extract_auth_context,
    extract_units,
    walk_repo,
)
from vibecleaner.deterministic import (
    detect_cors,
    detect_deprecated_sdk,
    detect_god_file,
    detect_passthrough_wrappers,
    detect_prose_tics,
    detect_secrets,
    detect_silent_exceptions,
    detect_supabase_rls,
    detect_supabase_rls_all,
    mask_secrets,
    run_deterministic,
    shannon_entropy,
)
from vibecleaner.models import Finding, Language, ScanContext, SourceFile

_HIGH = "aB3xQ9mZ2pL7vN4kR8tY6wC1dF5hJ0"
_MB = 1024 * 1024


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _init_repo(repo: Path) -> None:
    from gitutil import init_git

    init_git(repo)
    _git(repo, "config", "user.email", "dev@example.com")
    _git(repo, "config", "user.name", "Dev")


def _sf(path: str, text: str, language: Language | None = None) -> SourceFile:
    if language is None:
        language = _guess(path)
    return SourceFile(path=path, abs_path=Path(path), language=language, text=text)


def _guess(path: str) -> Language:
    name = PurePosixPath(path).name
    if name in {".env.example", ".env.sample", ".env.template"}:
        return Language.OTHER
    if name == ".env" or name.startswith(".env."):
        return Language.ENV
    return {
        ".py": Language.PYTHON,
        ".ts": Language.TYPESCRIPT,
        ".tsx": Language.TSX,
        ".js": Language.JAVASCRIPT,
        ".sql": Language.SQL,
    }.get(PurePosixPath(path).suffix, Language.OTHER)


def _of(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.rule_id == rule_id]


def _line(text: str, needle: str, occurrence: int = 1) -> int:
    seen = 0
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            seen += 1
            if seen == occurrence:
                return index
    raise AssertionError(f"{needle!r} occurrence {occurrence} not in text")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _assert_secret_hidden(secret: str, *texts: str | None) -> None:
    for text in texts:
        assert text is not None
        if len(secret) < 4:
            assert secret not in text
            continue
        for index in range(len(secret) - 3):
            fragment = secret[index : index + 4]
            assert fragment not in text


def test_shannon_entropy_empty_and_varied() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy(_HIGH) > 4.3


def test_walk_repo_honors_gitignore_vibecleanerignore_and_skips_noise(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("secret.txt\nignored_dir/\n")
    (tmp_path / ".vibecleanerignore").write_text("skipme.py\n")
    (tmp_path / "secret.txt").write_text("nope\n")
    (tmp_path / "skipme.py").write_text("x = 1\n")
    (tmp_path / "keep.py").write_text("x = 1\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("y = 2\n")
    nested = tmp_path / "ignored_dir"
    nested.mkdir()
    (nested / "hidden.py").write_text("z = 3\n")
    modules = tmp_path / "node_modules"
    modules.mkdir()
    (modules / "pkg.js").write_text("module.exports = {}\n")
    (tmp_path / "package-lock.json").write_text("{}\n")
    (tmp_path / "app.min.js").write_text("var a=1;\n")
    (tmp_path / "config.json").write_text('{"ok": true}\n')
    (tmp_path / "notes.md").write_text("hello\n")
    (tmp_path / "bin.dat").write_bytes(b"hello\0world")
    (tmp_path / "exact.py").write_bytes(b"a" * _MB)
    (tmp_path / "big.py").write_bytes(b"b" * (_MB + 1))

    files = walk_repo(tmp_path)
    paths = [item.path for item in files]
    assert paths == sorted(paths)
    assert "keep.py" in paths
    assert "src/app.py" in paths
    assert "config.json" in paths
    assert "notes.md" in paths
    assert "exact.py" in paths
    assert ".gitignore" in paths
    assert "secret.txt" not in paths
    assert "skipme.py" not in paths
    assert "ignored_dir/hidden.py" not in paths
    assert "node_modules/pkg.js" not in paths
    assert "package-lock.json" not in paths
    assert "app.min.js" not in paths
    assert "bin.dat" not in paths
    assert "big.py" not in paths
    config = next(item for item in files if item.path == "config.json")
    assert config.language == Language.OTHER
    kept = next(item for item in files if item.path == "keep.py")
    assert kept.language == Language.PYTHON
    assert kept.path == "keep.py"


def test_walk_repo_tracked_env_included_and_untracked_ignored_env_excluded(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / ".gitignore").write_text(".env\n.env.local\n.env.production\n")
    (tmp_path / ".env").write_text("OPENAI_API_KEY=present\n")
    (tmp_path / ".env.local").write_text("LOCAL=1\n")
    (tmp_path / ".env.production").write_text("PROD=1\n")
    (tmp_path / ".env.shared").write_text("SHARED=1\n")
    (tmp_path / ".env.example").write_text("OPENAI_API_KEY=\n")
    (tmp_path / "main.py").write_text("x = 1\n")
    _git(tmp_path, "add", "-f", ".env")
    _git(tmp_path, "add", ".gitignore", "main.py", ".env.example")

    files = walk_repo(tmp_path)
    by_path = {item.path: item for item in files}
    assert ".env" in by_path
    assert by_path[".env"].language == Language.ENV
    assert ".env.example" in by_path
    assert by_path[".env.example"].language == Language.OTHER
    assert ".env.shared" in by_path
    assert by_path[".env.shared"].language == Language.ENV
    assert ".env.local" not in by_path
    assert ".env.production" not in by_path
    assert "main.py" in by_path


def test_walk_repo_skips_vibecleaner_outputs(tmp_path: Path) -> None:
    (tmp_path / "VIBECLEANER_REPORT.md").write_text("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\n")
    (tmp_path / "VIBECLEANER_STATES.md").write_text("while True\n")
    (tmp_path / ".vibecleaner_cache.json").write_text("{}\n")
    (tmp_path / ".vibecleaner_cache.json.lock").write_text("\n")
    (tmp_path / "vibecleaner.sarif").write_text("{}\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    assert [item.path for item in walk_repo(tmp_path)] == ["app.py"]


def test_walk_repo_outside_git_env_follows_gitignore(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text("A=1\n")
    (tmp_path / ".env.local").write_text("B=2\n")
    paths = {item.path: item.language for item in walk_repo(tmp_path)}
    assert ".env" not in paths
    assert paths[".env.local"] == Language.ENV


def test_changed_lines_and_collect_diff_base(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "deps.py").write_text("def get_current_user():\n    return {'id': 1}\n")
    (tmp_path / "gone.py").write_text("x = 1\n")
    app = "\n".join(
        [
            "def keep():",
            "    db.execute('select 1')",
            "    x = 1",
            "    return x",
            "",
            "def change():",
            "    db.execute('select 2')",
            "    y = 2",
            "    return y",
            "",
        ]
    )
    (tmp_path / "app.py").write_text(app)
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    (tmp_path / "app.py").write_text(app.replace("    return y", "    return y + 1"))
    (tmp_path / "new_mod.py").write_text(
        "\n".join(
            [
                "def extra():",
                "    db.execute('select 3')",
                "    z = 3",
                "    return z",
                "",
            ]
        )
    )
    _git(tmp_path, "rm", "gone.py")

    changed = changed_lines(tmp_path, "HEAD")
    assert "gone.py" not in changed
    assert "pkg/deps.py" not in changed
    assert changed["new_mod.py"] is None
    current = (tmp_path / "app.py").read_text()
    assert _line(current, "return y + 1") in changed["app.py"]
    assert _line(current, "return x") not in changed["app.py"]

    ctx = collect(tmp_path, "HEAD")
    assert ctx.diff_base == "HEAD"
    assert ctx.changed_files == ["app.py", "new_mod.py"]
    assert [item.path for item in ctx.files] == ["app.py", "new_mod.py"]
    assert [unit.name for unit in ctx.units] == ["change", "extra"]
    assert all(unit.kind == "function" for unit in ctx.units)
    assert "get_current_user" in ctx.auth_context
    assert "pkg/deps.py" in ctx.auth_context
    assert all(item.path != "pkg/deps.py" for item in ctx.files)


def test_changed_lines_paths_are_relative_to_scan_root(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    sub = tmp_path / "svc"
    sub.mkdir()
    (sub / "app.py").write_text("x = 1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    (sub / "app.py").write_text("x = 2\n")
    (sub / "new.py").write_text("y = 3\n")
    changed = changed_lines(sub, "HEAD")
    assert set(changed) == {"app.py", "new.py"}
    assert changed["new.py"] is None
    assert 1 in (changed["app.py"] or set())


def test_changed_lines_errors_for_missing_repo_or_ref(tmp_path: Path) -> None:
    with pytest.raises(CollectorError, match="not a git"):
        changed_lines(tmp_path, "HEAD")
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "a.txt").write_text("a\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    with pytest.raises(CollectorError, match="unknown git ref"):
        changed_lines(repo, "no-such-ref-xyz")


def test_extract_auth_context_router_dependencies_and_next_middleware() -> None:
    api = "\n".join(
        [
            "from fastapi import APIRouter, Depends, FastAPI",
            "from starlette.middleware.authentication import AuthenticationMiddleware",
            "from starlette.middleware.cors import CORSMiddleware",
            "app = FastAPI(dependencies=[Depends(get_current_user)])",
            "router = APIRouter(prefix='/orders', dependencies=[Depends(get_current_user)])",
            "app.include_router(router, dependencies=[Depends(get_current_user)])",
            "app.add_middleware(AuthenticationMiddleware)",
            "app.add_middleware(CORSMiddleware)",
            "",
            "def get_current_user(token: str) -> dict:",
            "    return {'token': token}",
        ]
    )
    middleware = "\n".join(
        [
            "import { auth } from '@/auth'",
            "export function middleware(req: NextRequest) {",
            "  return auth()",
            "}",
            "export const config = { matcher: ['/dashboard/:path*'] }",
        ]
    )
    express = "\n".join(
        [
            "app.use(authMiddleware)",
            "app.use(express.json())",
        ]
    )
    text = extract_auth_context(
        [
            _sf("api.py", api),
            _sf("src/middleware.ts", middleware),
            _sf("server.js", express),
        ]
    )
    assert "APIRouter" in text
    assert "prefix='/orders'" in text or 'prefix="/orders"' in text or "prefix=" in text
    assert "get_current_user" in text
    assert "dependencies=" in text
    assert "AuthenticationMiddleware" in text
    assert "CORSMiddleware" not in text
    assert "src/middleware.ts" in text
    assert "matcher:" in text
    assert "auth calls: auth" in text
    assert "authMiddleware" in text
    assert "express.json" not in text
    assert "def get_current_user(token: str) -> dict:" in text


def test_extract_auth_context_empty_and_capped() -> None:
    assert extract_auth_context([]) == "No global auth middleware or router-level dependencies detected."
    assert (
        extract_auth_context([_sf("readme.md", "hello\n")])
        == "No global auth middleware or router-level dependencies detected."
    )
    body = "\n".join(f"def get_user_{index}():\n    return {index}" for index in range(200))
    capped = extract_auth_context([_sf("auth.py", body)])
    assert len(capped) <= 2400
    assert "truncated" in capped


def test_extract_units_fastapi_routes_tools_and_io_functions() -> None:
    text = "\n".join(
        [
            "from fastapi import APIRouter",
            "router = APIRouter()",
            "@router.get('/orders/{order_id}')",
            "async def get_order(order_id: str):",
            "    return {'id': order_id}",
            "",
            "@tool",
            "def search(q: str):",
            "    return q",
            "",
            "def load(db):",
            "    row = db.execute('select 1')",
            "    row = row",
            "    return row",
            "",
            "def add(a, b):",
            "    return a + b",
        ]
    )
    units = extract_units([_sf("api.py", text)])
    by_name = {unit.name: unit for unit in units}
    assert set(by_name) == {"get_order", "search", "load"}
    route = by_name["get_order"]
    assert route.kind == "route"
    assert route.http_method == "GET"
    assert route.route_path == "/orders/{order_id}"
    assert route.start_line == _line(text, "@router.get")
    assert "@router.get" in route.source
    assert by_name["search"].kind == "route"
    assert by_name["search"].http_method == "TOOL"
    assert by_name["load"].kind == "function"
    assert by_name["load"].http_method is None
    assert extract_units([_sf("tests/test_api.py", text)]) == []
    assert extract_units([_sf("conftest.py", text)]) == []


def test_extract_units_next_express_pages_and_server_actions() -> None:
    route_text = "\n".join(
        [
            "export async function POST(req: Request) {",
            "  const body = await req.json()",
            "  return Response.json(body)",
            "}",
            "export const GET = async (req: Request) => {",
            "  return Response.json({ ok: true })",
            "}",
        ]
    )
    route_units = extract_units([_sf("app/(shop)/api/orders/[id]/route.ts", route_text)])
    by_method = {unit.http_method: unit for unit in route_units}
    assert set(by_method) == {"POST", "GET"}
    assert by_method["POST"].kind == "route"
    assert by_method["POST"].route_path == "/api/orders/[id]"
    assert by_method["POST"].name == "POST"
    assert by_method["GET"].route_path == "/api/orders/[id]"

    express = "\n".join(
        [
            "export function register(app) {",
            "  app.post('/orders', (req, res) => {",
            "    db.insert(req.body)",
            "    return res.send('ok')",
            "  })",
            "}",
        ]
    )
    express_units = extract_units([_sf("server.js", express)])
    assert len(express_units) == 1
    handler = express_units[0]
    assert handler.kind == "route"
    assert handler.http_method == "POST"
    assert handler.route_path == "/orders"
    assert handler.name == "POST /orders"
    assert "register" not in {unit.name for unit in express_units}

    action = "\n".join(
        [
            '"use server"',
            "export async function createOrder(data: FormData) {",
            "  await db.insert(data)",
            "  return { ok: true }",
            "}",
            "async function hidden(data: FormData) {",
            "  await db.insert(data)",
            "  return data",
            "  return data",
            "}",
        ]
    )
    action_units = extract_units([_sf("app/actions.ts", action)])
    assert len(action_units) == 1
    assert action_units[0].name == "createOrder"
    assert action_units[0].kind == "route"
    assert action_units[0].http_method == "ACTION"

    pages = "\n".join(
        [
            "export default function handler(req, res) {",
            "  return db.query('select 1')",
            "}",
        ]
    )
    pages_units = extract_units([_sf("pages/api/orders/[id].ts", pages)])
    assert len(pages_units) == 1
    assert pages_units[0].kind == "route"
    assert pages_units[0].http_method == "ANY"
    assert pages_units[0].route_path == "/api/orders/[id]"


def test_env_file_committed_lists_keys_without_values() -> None:
    secret = "super" + "secret-value"
    text = "\n".join(
        [
            f"OPENAI_API_KEY={secret}",
            "EMPTY=",
            "TOKEN=zzz",
            'QUOTED=""',
            "export OTHER=1",
            "FOUR=abcd",
            "FIVE=efgh",
            "SIX=ijkl",
        ]
    )
    findings = detect_secrets(_sf(".env", text))
    assert [item.rule_id for item in findings] == ["D1.env_file_committed"]
    finding = findings[0]
    assert finding.line == 1
    assert "OPENAI_API_KEY" in finding.message
    assert "TOKEN" in finding.message
    assert "SIX" not in finding.message
    assert "(+1 more)" in finding.message
    assert secret not in finding.message
    assert finding.snippet is not None
    assert f"<redacted:{len(secret)} chars>" in finding.snippet
    assert "OPENAI_API_KEY=" in finding.snippet
    _assert_secret_hidden(secret, finding.snippet, finding.message)
    empty = detect_secrets(_sf(".env", "EMPTY=\n# comment\nQUOTED=\"\"\n"))
    assert empty == []


def test_next_public_secret_ignores_anon_and_publishable_keys() -> None:
    text = "\n".join(
        [
            "const a = process.env.NEXT_PUBLIC_STRIPE_SECRET",
            "const b = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY",
            "const c = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
            "NEXT_PUBLIC_OPENAI_API_KEY=hidden",
            "const d = NEXT_PUBLIC_SITE_KEY",
            "const e = NEXT_PUBLIC_SERVICE_ROLE_KEY",
        ]
    )
    findings = _of(detect_secrets(_sf("config.ts", text)), "D1.next_public_secret")
    assert [item.line for item in findings] == [1, 4, 6]
    assert all("ANON_KEY" not in item.message for item in findings)
    assert all("PUBLISHABLE" not in item.message for item in findings)
    assert all("SITE_KEY" not in item.message for item in findings)


def test_hardcoded_secret_known_patterns_entropy_and_negatives() -> None:
    openai = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0"
    anthropic = "sk-" + "ant-" + ("b" * 20)
    stripe = "sk_" + "live_" + "1A2b3C4d5E6f7G8h"
    restricted = "rk_" + "live_" + "1A2b3C4d5E6f7G8h"
    aws = "AKIA" + "0123456789ABCDEF"
    github = "ghp_" + ("a" * 36)
    slack = "xoxb-" + "1a2b3c4d5e6f"
    google = "AIza" + ("A" * 35)
    pem = "-----BEGIN " + "PRIVATE KEY-----"
    service = ".".join(
        [
            _b64(b'{"alg":"HS256","typ":"JWT"}'),
            _b64(b'{"role":"service_role","iss":"supabase"}'),
            _b64(b"abcdefghijklmnopqrstuvwxyz012345"),
        ]
    )
    authenticated = ".".join(
        [
            _b64(b'{"alg":"HS256","typ":"JWT"}'),
            _b64(b'{"role":"authenticated","iss":"supabase"}'),
            _b64(b"abcdefghijklmnopqrstuvwxyz012345"),
        ]
    )
    placeholder = "example_" + _HIGH
    lines = [
        f"print({openai!r})",
        f"print({anthropic!r})",
        f"print({stripe!r})",
        f"print({restricted!r})",
        f"print({aws!r})",
        f"print({github!r})",
        f"print({slack!r})",
        f"print({google!r})",
        f"key = {pem!r}",
        f"print({service!r})",
        f"samples = [{authenticated!r}]",
        f"api_key = {_HIGH!r}",
        f"label = {_HIGH!r}",
        f"api_key = {placeholder!r}",
        f"token = {'https://cdn.cloudfront.net/' + _HIGH!r}",
        f"password = {_HIGH!r}",
        "cfg = {'password': " + repr(_HIGH) + "}",
        f"x = os.getenv('SECRET', {_HIGH!r})",
        "checksum = '" + ("0123456789abcdef" * 4) + "'",
    ]
    text = "\n".join(lines) + "\n"
    findings = _of(detect_secrets(_sf("settings.py", text)), "D1.hardcoded_secret")
    flagged = {item.line for item in findings}
    for needle in (openai, anthropic, stripe, restricted, aws, github, slack, google, pem, service):
        assert _line(text, needle) in flagged
        finding = next(item for item in findings if item.line == _line(text, needle))
        assert finding.snippet is not None
        assert f"<redacted:{len(needle)} chars>" in finding.snippet
        _assert_secret_hidden(needle, finding.snippet, finding.message)
    assert _line(text, "samples") not in flagged
    assert _line(text, "label =") not in flagged
    assert _line(text, "example_") not in flagged
    assert _line(text, "https://cdn.cloudfront.net/") not in flagged
    assert _line(text, "checksum") not in flagged
    assert _line(text, "api_key = ") in flagged
    assert _line(text, "os.getenv") in flagged
    assert _line(text, "cfg = ") in flagged

    doubled = f"token = {openai!r} {openai!r}\n"
    once = _of(detect_secrets(_sf("one.py", doubled)), "D1.hardcoded_secret")
    assert len(once) == 1

    leaked = detect_secrets(_sf("tests/test_app.py", f"token = {openai!r}\n"))
    assert _of(leaked, "D1.hardcoded_secret") == []
    env = detect_secrets(_sf(".env", f"OPENAI_API_KEY={openai}\n"))
    assert [item.rule_id for item in env] == ["D1.env_file_committed"]
    assert openai not in env[0].message

    script = "\n".join(
        [
            f"const fallback = process.env.API_KEY ?? {_HIGH!r}",
            f"const noise = process.env.REGION ?? {_HIGH!r}",
        ]
    )
    script_findings = _of(detect_secrets(_sf("env.ts", script)), "D1.hardcoded_secret")
    assert [item.line for item in script_findings] == [1]

    blob = '{"api_key": "' + _HIGH + '"}\n'
    json_findings = _of(detect_secrets(_sf("config.json", blob)), "D1.hardcoded_secret")
    assert len(json_findings) == 1
    assert _HIGH not in (json_findings[0].snippet or "")


def test_supabase_missing_rls_and_policy() -> None:
    missing = "\n".join(
        [
            "-- CREATE TABLE commented (id int);",
            "CREATE TABLE IF NOT EXISTS public.orders (",
            "  id int",
            ");",
            "CREATE TABLE auth.users (",
            "  id uuid",
            ");",
            "/* CREATE TABLE hidden (id int); */",
        ]
    )
    findings = detect_supabase_rls(_sf("supabase/migrations/001_init.sql", missing))
    assert [item.rule_id for item in findings] == ["D2.supabase_missing_rls"]
    assert findings[0].line == _line(missing, "CREATE TABLE IF NOT EXISTS public.orders")
    assert findings[0].symbol == "orders"
    assert "commented" not in findings[0].message
    assert "users" not in findings[0].message

    policy = "\n".join(
        [
            "create table notes (",
            "  id int",
            ");",
            "alter table notes enable row level security;",
        ]
    )
    policy_findings = detect_supabase_rls(_sf("migrations/002_notes.sql", policy))
    assert [item.rule_id for item in policy_findings] == ["D2.supabase_missing_policy"]
    assert policy_findings[0].symbol == "notes"

    ignored = detect_supabase_rls(_sf("schema.sql", "create table notes (id int);\n"))
    assert ignored == []
    mentioned = detect_supabase_rls(
        _sf("extra.sql", "select auth.uid();\ncreate table notes (id int);\n")
    )
    assert [item.rule_id for item in mentioned] == ["D2.supabase_missing_rls"]


def test_supabase_rls_in_later_migration_not_flagged() -> None:
    early = "\n".join(
        [
            'CREATE TABLE IF NOT EXISTS "public"."Orders" (',
            "  id int",
            ");",
        ]
    )
    later = "\n".join(
        [
            'ALTER TABLE "Orders" ENABLE ROW LEVEL SECURITY;',
            'CREATE POLICY "own" ON public.orders FOR SELECT USING (auth.uid() = user_id);',
        ]
    )
    files = [
        _sf("supabase/migrations/001_init.sql", early),
        _sf("supabase/migrations/002_rls.sql", later),
    ]
    assert detect_supabase_rls_all(files) == []
    ctx = ScanContext(root=Path("."), files=files, units=[], auth_context="")
    assert _of(run_deterministic(ctx), "D2.supabase_missing_rls") == []
    assert _of(run_deterministic(ctx), "D2.supabase_missing_policy") == []


def test_cors_wildcard_credentials_flagged() -> None:
    python = "\n".join(
        [
            "from fastapi.middleware.cors import CORSMiddleware",
            "app.add_middleware(",
            "    CORSMiddleware,",
            '    allow_origins=["*"],',
            "    allow_credentials=True,",
            ")",
            'CORS(app, allow_origin_regex=".*", supports_credentials=True)',
        ]
    )
    py_findings = detect_cors(_sf("main.py", python))
    assert [item.line for item in py_findings] == [
        _line(python, "app.add_middleware"),
        _line(python, "CORS(app"),
    ]

    script = "\n".join(
        [
            "import cors from 'cors'",
            "app.use(cors({",
            "  origin: '*',",
            "  credentials: true,",
            "}))",
            "cors({ origin: true, credentials: true })",
        ]
    )
    script_findings = detect_cors(_sf("server.ts", script))
    assert [item.line for item in script_findings] == [
        _line(script, "app.use(cors"),
        _line(script, "cors({ origin: true"),
    ]

    headers = "\n".join(
        [
            'res.setHeader("Access-Control-Allow-Origin", "*")',
            'res.setHeader("Access-Control-Allow-Credentials", "true")',
        ]
    )
    header_findings = detect_cors(_sf("headers.js", headers))
    assert [item.line for item in header_findings] == [1]
    assert header_findings[0].rule_id == "D2.cors_wildcard_credentials"


def test_cors_explicit_origins_not_flagged() -> None:
    python = "\n".join(
        [
            "app.add_middleware(",
            "    CORSMiddleware,",
            '    allow_origins=["https://app.example.com"],',
            "    allow_credentials=True,",
            ")",
        ]
    )
    assert detect_cors(_sf("main.py", python)) == []
    script = "\n".join(
        [
            "app.use(cors({ origin: ['https://app.example.com'], credentials: true }))",
            "cors({ origin: '*', credentials: false })",
        ]
    )
    assert detect_cors(_sf("server.ts", script)) == []


def test_silent_exception_broad_empty_not_logged_or_narrow() -> None:
    python = "\n".join(
        [
            "def run():",
            "    try:",
            "        risky()",
            "    except Exception:",
            "        pass",
            "    try:",
            "        risky()",
            "    except ValueError:",
            "        pass",
            "    try:",
            "        risky()",
            "    except Exception:",
            "        logger.exception('boom')",
            "    try:",
            "        risky()",
            "    except:",
            "        return None",
            "    try:",
            "        risky()",
            "    except (OSError, Exception):",
            "        continue",
            "    try:",
            "        risky()",
            "    except Exception:",
            "        raise",
        ]
    )
    findings = detect_silent_exceptions(_sf("app.py", python))
    assert [item.line for item in findings] == [
        _line(python, "except Exception:"),
        _line(python, "except:"),
        _line(python, "except (OSError, Exception)"),
    ]
    assert all(item.rule_id == "D6a.silent_exception" for item in findings)

    script = "\n".join(
        [
            "try {",
            "  boom()",
            "} catch (e) {",
            "}",
            "try {",
            "  boom()",
            "} catch (e) {",
            "  // ignore",
            "}",
            "try {",
            "  boom()",
            "} catch (e) {",
            "  console.error(e)",
            "}",
            "promise.catch(() => {})",
            "promise.catch(() => null)",
            "promise.catch(() => undefined)",
            "promise.catch(() => { console.log('x') })",
            "promise.catch((err) => { throw err })",
        ]
    )
    script_findings = detect_silent_exceptions(_sf("app.ts", script))
    assert [item.line for item in script_findings] == [
        _line(script, "} catch (e) {"),
        _line(script, "} catch (e) {", 2),
        _line(script, "promise.catch(() => {})"),
        _line(script, "promise.catch(() => null)"),
        _line(script, "promise.catch(() => undefined)"),
    ]


def test_god_file_requires_all_three_signals_and_size() -> None:
    def build(*, http: bool, functions: int, pad: int) -> str:
        rows = ["value = 1"]
        if http:
            rows.extend(["@app.get('/x')", "def route():", "    return 1"])
        for index in range(functions):
            rows.extend(
                [
                    f"def business_{index}(db):",
                    "    row = db.execute('SELECT 1')",
                    "    row = row",
                    "    return row",
                ]
            )
        rows.extend(f"pad_{index} = {index}" for index in range(pad))
        return "\n".join(rows) + "\n"

    positive = detect_god_file(_sf("big.py", build(http=True, functions=8, pad=520)))
    assert len(positive) == 1
    assert positive[0].line == 1
    assert positive[0].rule_id == "D6a.god_file"
    assert "non-blank" in positive[0].message
    assert "8 non-route" in positive[0].message or "non-route functions" in positive[0].message

    assert detect_god_file(_sf("short.py", build(http=True, functions=8, pad=0))) == []
    assert detect_god_file(_sf("nodb.py", build(http=False, functions=8, pad=520))) == []


def _long_module(rows: list[str]) -> str:
    body = list(rows)
    for index in range(8):
        body.extend(
            [
                f"def helper_{index}(value):",
                "    value = value",
                "    return value",
                "",
            ]
        )
    body.extend(f"pad_{index} = {index}" for index in range(520))
    return "\n".join(body) + "\n"


def test_god_file_ignores_identifiers_and_string_text() -> None:
    identifier = _long_module(
        [
            "@app.get('/orders')",
            "def route():",
            "    return 1",
            "_UNBOUNDED_SELECT = 1",
        ]
    )
    assert detect_god_file(_sf("identifier.py", identifier)) == []

    strings = _long_module(
        [
            'note = "SELECT id FROM users WHERE id = 1"',
            'pattern = re.compile(r"NextResponse\\.json|Request")',
            '_UNBOUNDED_SELECT = "UPDATE"',
        ]
    )
    assert detect_god_file(_sf("strings.py", strings)) == []

    real = _long_module(
        [
            'query = "SELECT id FROM users WHERE id = %s"',
            "def handle(request: Request) -> Response:",
            "    return query",
        ]
    )
    found = detect_god_file(_sf("real.py", real))
    assert len(found) == 1
    assert found[0].rule_id == "D6a.god_file"


def test_deprecated_sdk_flags_legacy_calls_not_current_apis() -> None:
    legacy = "\n".join(
        [
            "import openai",
            "from pydantic import BaseModel, validator",
            "openai.ChatCompletion.create(model='gpt-4')",
            "openai.api_key = 'set-elsewhere'",
            "from langchain.llms import OpenAI",
            "from langchain.chat_models import ChatOpenAI",
            "LLMChain(llm=None)",
            "initialize_agent(tools, llm)",
            "",
            "class User(BaseModel):",
            "    name: str",
            "    class Config:",
            "        orm_mode = True",
            "    @validator('name')",
            "    def check(cls, v):",
            "        return v",
            "",
            "print(user.dict())",
            "print(user.parse_obj({}))",
            "print(response.json())",
        ]
    )
    findings = detect_deprecated_sdk(_sf("legacy.py", legacy))
    flagged = {item.line for item in findings}
    for needle in (
        "openai.ChatCompletion.create",
        "openai.api_key",
        "from langchain.llms import",
        "from langchain.chat_models import",
        "LLMChain(",
        "initialize_agent(",
        "class Config:",
        "@validator('name')",
        "user.dict()",
        "user.parse_obj",
    ):
        assert _line(legacy, needle) in flagged
    assert _line(legacy, "response.json()") not in flagged
    assert all(item.rule_id == "D6a.deprecated_sdk" for item in findings)

    current = "\n".join(
        [
            "from pydantic import BaseModel, field_validator",
            "class User(BaseModel):",
            "    name: str",
            "    @field_validator('name')",
            "    def check(cls, v):",
            "        return v",
            "print(user.model_dump())",
            "client.chat.completions.create(model='gpt-4')",
            "response.json()",
        ]
    )
    assert detect_deprecated_sdk(_sf("current.py", current)) == []

    javascript = "\n".join(
        [
            "import { Configuration, OpenAIApi } from 'openai'",
            "const api = new OpenAIApi(new Configuration({}))",
            "await api.createChatCompletion({})",
            "await api.createCompletion({})",
        ]
    )
    js_findings = detect_deprecated_sdk(_sf("openai.ts", javascript))
    js_lines = {item.line for item in js_findings}
    assert _line(javascript, "import { Configuration") in js_lines
    assert _line(javascript, "new OpenAIApi") in js_lines
    assert _line(javascript, "createChatCompletion") in js_lines
    assert _line(javascript, "createCompletion") in js_lines

    modern = "\n".join(
        [
            "import OpenAI from 'openai'",
            "const client = new OpenAI()",
            "await client.chat.completions.create({})",
        ]
    )
    assert detect_deprecated_sdk(_sf("modern.ts", modern)) == []


def test_passthrough_wrapper_flags_forwarders_only() -> None:
    python = "\n".join(
        [
            "def relay(*args, **kwargs):",
            '    """delegate"""',
            "    return real(*args, **kwargs)",
            "",
            "def logged(*args, **kwargs):",
            "    print('x')",
            "    return real(*args, **kwargs)",
            "",
            "class Box:",
            "    @property",
            "    def value(self, *args, **kwargs):",
            "        return self._v(*args, **kwargs)",
            "",
            "    def __call__(self, *args, **kwargs):",
            "        return self._v(*args, **kwargs)",
            "",
            "    def forward(self, *args, **kwargs):",
            "        return self.impl(*args, **kwargs)",
            "",
            "def extra(a, *args, **kwargs):",
            "    return real(*args, **kwargs)",
            "",
            "async def async_relay(*args, **kwargs):",
            "    return await target(*args, **kwargs)",
        ]
    )
    findings = detect_passthrough_wrappers(_sf("wrap.py", python))
    assert {(item.symbol, item.line) for item in findings} == {
        ("relay", _line(python, "def relay")),
        ("forward", _line(python, "def forward")),
        ("async_relay", _line(python, "async def async_relay")),
    }
    assert all(item.rule_id == "D6a.passthrough_wrapper" for item in findings)

    script = "\n".join(
        [
            "function wrap(...args) {",
            "  return f(...args)",
            "}",
            "const wrap2 = (...args) => f(...args)",
            "function no(...args) {",
            "  console.log('x')",
            "  return f(...args)",
            "}",
            "function named(a, ...args) {",
            "  return f(...args)",
            "}",
        ]
    )
    script_findings = detect_passthrough_wrappers(_sf("wrap.ts", script))
    assert {item.symbol for item in script_findings} == {"wrap", "wrap2"}


def test_run_deterministic_sorts_and_dedupes_by_file_and_line() -> None:
    openai = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0"
    first = _sf("b.py", f"token = {_HIGH!r}\n")
    second = _sf("a.py", f"token = {openai!r} {openai!r}\n")
    ctx = ScanContext(root=Path("."), files=[first, second], units=[], auth_context="none")
    findings = run_deterministic(ctx)
    assert [item.file for item in findings] == ["a.py", "b.py"]
    assert len(_of(findings, "D1.hardcoded_secret")) == 2
    assert findings[0].line == 1
    assert openai not in (findings[0].snippet or "")
    _assert_secret_hidden(openai, findings[0].snippet, findings[0].message)


def test_walk_repo_rejects_missing_or_file_root(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-root"
    with pytest.raises(CollectorError) as missing_exc:
        walk_repo(missing)
    assert str(missing) in str(missing_exc.value)
    source = tmp_path / "file.py"
    source.write_text("x = 1\n")
    with pytest.raises(CollectorError) as file_exc:
        walk_repo(source)
    assert str(source) in str(file_exc.value)
    with pytest.raises(CollectorError) as collect_exc:
        collect(missing)
    assert str(missing) in str(collect_exc.value)


def test_deletion_only_hunk_selects_enclosing_route(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    original = "\n".join(
        [
            "from fastapi import FastAPI, HTTPException",
            "app = FastAPI()",
            "",
            "@app.post('/orders')",
            "def create_order():",
            "    if not session:",
            "        raise HTTPException(status_code=401)",
            "    db.execute('insert into orders values (1)')",
            "    return {'ok': True}",
            "",
        ]
    )
    (tmp_path / "routes.py").write_text(original)
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    (tmp_path / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import FastAPI, HTTPException",
                "app = FastAPI()",
                "",
                "@app.post('/orders')",
                "def create_order():",
                "    db.execute('insert into orders values (1)')",
                "    return {'ok': True}",
                "",
            ]
        )
    )
    ctx = collect(tmp_path, "HEAD")
    routes = [unit for unit in ctx.units if unit.name == "create_order"]
    assert len(routes) == 1
    assert routes[0].kind == "route"
    assert routes[0].http_method == "POST"
    assert routes[0].route_path == "/orders"


def test_snippets_redact_entire_secret_value() -> None:
    secret = "super" + "secret-value"
    quoted = detect_secrets(_sf(".env", f'OPENAI_API_KEY="{secret}"\n'))
    assert quoted[0].snippet is not None
    assert f"<redacted:{len(secret)} chars>" in quoted[0].snippet
    _assert_secret_hidden(secret, quoted[0].snippet, quoted[0].message)

    openai = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0"
    prefixed = f"TOKEN=pre-{openai}\n"
    prefixed_findings = _of(detect_secrets(_sf("settings.py", prefixed)), "D1.hardcoded_secret")
    assert len(prefixed_findings) == 1
    assert prefixed_findings[0].snippet is not None
    assert "pre-" not in prefixed_findings[0].snippet
    assert openai[:4] not in prefixed_findings[0].snippet
    _assert_secret_hidden(openai, prefixed_findings[0].snippet, prefixed_findings[0].message)

    blob = '{"api_key": "pre-' + openai + '"}\n'
    json_findings = _of(detect_secrets(_sf("config.json", blob)), "D1.hardcoded_secret")
    assert len(json_findings) == 1
    assert json_findings[0].snippet is not None
    assert "pre-" not in json_findings[0].snippet
    _assert_secret_hidden(openai, json_findings[0].snippet, json_findings[0].message)

    yaml = "api_key: " + openai + "\n"
    yaml_findings = _of(detect_secrets(_sf("config.yaml", yaml)), "D1.hardcoded_secret")
    assert len(yaml_findings) == 1
    assert yaml_findings[0].snippet is not None
    assert f"<redacted:{len(openai)} chars>" in yaml_findings[0].snippet
    _assert_secret_hidden(openai, yaml_findings[0].snippet, yaml_findings[0].message)

    logged = f'logger.info("token %s", "{openai}")\n'
    logged_findings = _of(detect_secrets(_sf("log.py", logged)), "D1.hardcoded_secret")
    assert len(logged_findings) == 1
    assert logged_findings[0].snippet is not None
    assert f"<redacted:{len(openai)} chars>" in logged_findings[0].snippet
    _assert_secret_hidden(openai, logged_findings[0].snippet, logged_findings[0].message)

    excerpt = "\n".join(
        [
            f"    TOKEN={openai}",
            '    data = {"api_key": "' + secret + '"}',
            "    note = 'untouched'",
        ]
    )
    masked = mask_secrets(excerpt)
    assert masked.startswith("    TOKEN=")
    assert 'note = \'untouched\'' in masked
    _assert_secret_hidden(openai, masked)
    _assert_secret_hidden(secret, masked)


def test_walk_repo_skips_symlinks(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("secret = 1\n")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "keep.py").write_text("x = 1\n")
    (root / "inner.py").write_text("y = 2\n")
    (root / "link.py").symlink_to(outside)
    (root / "alias.py").symlink_to(root / "inner.py")
    (root / "linked").symlink_to(tmp_path, target_is_directory=True)
    with caplog.at_level(logging.DEBUG, logger="vibecleaner"):
        files = walk_repo(root)
    assert [item.path for item in files] == ["inner.py", "keep.py"]
    messages = [record.message for record in caplog.records]
    assert any("symlink" in message and "link.py" in message for message in messages)
    assert any("symlink" in message and "alias.py" in message for message in messages)
    assert all(record.levelno == logging.DEBUG for record in caplog.records if "link.py" in record.message)


def test_walk_repo_logs_skipped_files(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    (tmp_path / "big.py").write_bytes(b"a" * (_MB + 1))
    (tmp_path / "blob.dat").write_bytes(b"\0\x01\x02")
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe not utf-8\n")
    (tmp_path / "notes.bin").write_bytes(b"\xff\xfe")
    with caplog.at_level(logging.DEBUG, logger="vibecleaner"):
        paths = [item.path for item in walk_repo(tmp_path)]
    assert "big.py" not in paths
    assert "bad.py" not in paths
    assert "blob.dat" not in paths
    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    debugs = [record for record in caplog.records if record.levelno == logging.DEBUG]
    assert any("big.py" in record.message and "oversized" in record.message for record in warnings)
    assert any("bad.py" in record.message and "undecodable" in record.message for record in warnings)
    assert any("blob.dat" in record.message and "binary" in record.message for record in debugs)
    assert not any("blob.dat" in record.message for record in warnings)
    assert any("notes.bin" in record.message for record in debugs)
    assert not any("notes.bin" in record.message for record in warnings)


def test_extract_units_keeps_short_sink_helpers() -> None:
    python = "\n".join(
        [
            "def page_bridge(target, msg): return requests.post(target, json=msg)",
            "def probe(url):",
            "    return httpx.get(url)",
            "def write_log(path, data):",
            "    open(path, 'w').write(data)",
            "def read_log(path):",
            "    return open(path).read()",
            "def run_query(db):",
            "    return db.execute('select 1')",
            "def add(a, b):",
            "    return a + b",
        ]
    )
    units = extract_units([_sf("bridge.py", python)])
    by_name = {unit.name: unit for unit in units}
    assert set(by_name) == {"page_bridge", "probe", "write_log"}
    assert all(unit.kind == "function" for unit in by_name.values())

    script = "\n".join(
        [
            "export function pageBridge(target) { return fetch(target) }",
            "export const send = (url) => axios.post(url)",
            "export function save(path, data) { return fs.writeFile(path, data) }",
            "export function add(a, b) { return a + b }",
            "function hidden(url) { return fetch(url) }",
        ]
    )
    script_units = extract_units([_sf("bridge.ts", script)])
    assert {unit.name for unit in script_units} == {"pageBridge", "send", "save"}
    assert all(unit.kind == "function" for unit in script_units)


def test_redaction_keeps_neutral_keys_and_hides_env_secrets() -> None:
    openai = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0"
    preserved = "\n".join(
        [
            "PORT=8080",
            "DEBUG=false",
            "author=hello-world-name",
            "max_tokens=8192",
            "token_count=123456",
            "tokenizer=wordpiece-model",
        ]
    )
    assert mask_secrets(preserved) == preserved

    database = "postgres://u:p@h/db"
    assigned = "\n".join(
        [
            f"OPENAI_API_KEY={openai}",
            f"DATABASE_URL={database}",
            f"NOTE=pre-{openai}",
        ]
    )
    masked = mask_secrets(assigned)
    assert "OPENAI_API_KEY=" in masked
    assert "DATABASE_URL=" in masked
    assert "NOTE=" in masked
    assert openai not in masked
    assert database not in masked
    assert "pre-" not in masked
    assert f"<redacted:{len(openai)} chars>" in masked
    assert f"<redacted:{len(database)} chars>" in masked

    neutral = _HIGH
    assert len(neutral) >= 16
    assert shannon_entropy(neutral) > 3.5
    entropy = detect_secrets(_sf(".env", f"CACHE_BUSTER={neutral}\nPORT=8080\n"))
    assert entropy[0].rule_id == "D1.env_file_committed"
    assert entropy[0].snippet is not None
    assert neutral not in entropy[0].snippet
    assert "<redacted:" in entropy[0].snippet

    api = detect_secrets(_sf(".env", f"OPENAI_API_KEY={openai}\nDEBUG=false\n"))
    assert api[0].snippet is not None
    assert openai not in api[0].snippet
    assert "OPENAI_API_KEY=" in api[0].snippet

    url = detect_secrets(_sf(".env", f"DATABASE_URL={database}\n"))
    assert url[0].snippet is not None
    assert database not in url[0].snippet
    assert "u:p@" not in url[0].snippet

    port = detect_secrets(_sf(".env", "PORT=8080\n"))
    assert port[0].snippet is not None
    assert "PORT=8080" in port[0].snippet
    debug = detect_secrets(_sf(".env", "DEBUG=false\n"))
    assert debug[0].snippet is not None
    assert "DEBUG=false" in debug[0].snippet

    large_plain = "b" * 80_000
    assert mask_secrets(large_plain) == large_plain

    dotted_secret = ".a" * 40_000 + "; secret_key=super_secret_1234"
    dotted_masked = mask_secrets(dotted_secret)
    assert "super_secret_1234" not in dotted_masked
    assert f"<redacted:{len('super_secret_1234')} chars>" in dotted_masked

    indexed = mask_secrets('foo[0].secret = "my_secret_1234"')
    assert "my_secret_1234" not in indexed
    assert f"<redacted:{len('my_secret_1234')} chars>" in indexed

    optional = mask_secrets('foo?.api_key = "my_secret_1234"')
    assert "my_secret_1234" not in optional
    assert f"<redacted:{len('my_secret_1234')} chars>" in optional


def test_prose_tics_flag_model_residue_and_skip_technical_writing() -> None:
    drafted = "\n".join(
        [
            "# Checkout",
            "",
            "I hope this helps! Let me know if you'd like me to expand on refunds.",
            "As of my last training, the route delves into the tapestry of payments.",
            "The handler serves as a gateway and it's worth noting that it can potentially fail.",
            "Let's be honest: this was added to replace the previous approach.",
            "One factual note, not fixed: the webhook has no signature check.",
        ]
    )
    hits = detect_prose_tics(_sf("docs/checkout.md", drafted))
    assert {finding.line for finding in hits} == {3, 4, 5, 6, 7}
    assert all(finding.rule_id == "D6c.llm_prose" for finding in hits)
    assert all(finding.severity.value == "low" for finding in hits)
    assert "chatbot" in hits[0].message

    technical = "\n".join(
        [
            "## GitHub Action",
            "",
            "Scan the diff, not the whole tree.",
            "",
            "- **Layer 1:** tree-sitter, not a model.",
            "- **Cache:** unchanged functions cost nothing.",
            "",
            "The gate fails closed. It does not trust a missing path.",
            "Use `delve` only as an example inside code.",
        ]
    )
    assert detect_prose_tics(_sf("README.md", technical)) == []
    assert detect_prose_tics(_sf("api/orders.py", "def f():\n    # I hope this helps\n    return 1\n")) == []
    assert detect_prose_tics(_sf("CHANGELOG.md", "I hope this helps!\n")) == []

    slop_doc = "\n".join(
        [
            "This cutting-edge game-changer will supercharge your workflow.",
            "The release marks a pivotal moment, ushering in a new era of deploys.",
            "Let that sink in. Here's what nobody tells you about caching.",
            "In today's ever-evolving digital landscape, latency matters.",
            "Experts agree this is widely regarded as the best pattern.",
            "Plot twist: let me walk you through the schema.",
        ]
    )
    slop_hits = detect_prose_tics(_sf("docs/launch.md", slop_doc))
    assert {finding.line for finding in slop_hits} == {1, 2, 3, 4, 5, 6}


def test_extract_auth_context_masks_secret_literals() -> None:
    stripe_key = "sk_" + "live_" + "0123456789abcdef01234567"
    code = f"def require_auth(api_key: str = {stripe_key!r}):\n    return api_key\n"
    text = extract_auth_context([_sf("auth.py", code)])
    assert "require_auth" in text
    assert stripe_key not in text
    assert "<redacted:" in text


def test_extract_custom_express_routers_and_gatekeeper_middleware() -> None:
    js = "\n".join(
        [
            "donorNotes.use(gatekeeper)",
            "donorNotes.post('/notes', async (req, res) => {",
            "  await db.insert(req.body)",
            "  return res.json({ ok: true })",
            "})",
            "listingRoutes.patch('/:id', function updateListing(req, res) {",
            "  return db.update(req.params.id)",
            "})",
            "const cached = cache.get('session:1')",
            "const fallback = cache.get('/session', defaultObj)",
        ]
    )
    source = _sf("routes/notes.js", js)
    auth_ctx = extract_auth_context([source])
    assert "donorNotes.use(gatekeeper)" in auth_ctx

    units = extract_units([source])
    by_name = {unit.name: unit for unit in units}
    assert "POST /notes" in by_name
    assert by_name["POST /notes"].kind == "route"
    assert by_name["POST /notes"].http_method == "POST"
    assert by_name["POST /notes"].route_path == "/notes"
    assert "updateListing" in by_name
    assert by_name["updateListing"].kind == "route"
    assert by_name["updateListing"].http_method == "PATCH"
    assert by_name["updateListing"].route_path == "/:id"
    assert len(units) == 2


def test_walk_repo_nested_and_parent_gitignore_scoping(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / ".gitignore").write_text("*.ignored\n", encoding="utf-8")
    (tmp_path / ".vibecleanerignore").write_text("sub/\n", encoding="utf-8")

    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / ".gitignore").write_text("local_secret.py\nignored_sub/\n", encoding="utf-8")
    (sub / "keep.py").write_text("x = 1\n", encoding="utf-8")
    (sub / "parent.ignored").write_text("nope = 1\n", encoding="utf-8")
    (sub / "local_secret.py").write_text("nope = 2\n", encoding="utf-8")
    (sub / "ignored_sub").mkdir()
    (sub / "ignored_sub" / "hidden.py").write_text("nope = 3\n", encoding="utf-8")

    sibling = tmp_path / "other"
    sibling.mkdir()
    (sibling / "local_secret.py").write_text("ok = 1\n", encoding="utf-8")

    # Scanning repo root ignores sub/ via root .vibecleanerignore and sibling/*.ignored via .gitignore.
    root_paths = {item.path for item in walk_repo(tmp_path)}
    assert "other/local_secret.py" in root_paths
    assert "sub/keep.py" not in root_paths

    # Scanning sub directly ignores parent *.ignored and sub-local ignores,
    # while NOT applying ancestor .vibecleanerignore (which contains sub/).
    sub_paths = {item.path for item in walk_repo(sub)}
    assert "keep.py" in sub_paths
    assert "parent.ignored" not in sub_paths
    assert "local_secret.py" not in sub_paths
    assert "ignored_sub/hidden.py" not in sub_paths
