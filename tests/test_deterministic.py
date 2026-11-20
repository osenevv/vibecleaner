"""Layer 1 walker, diff filter, and deterministic rules."""

from __future__ import annotations

import base64
import subprocess
from pathlib import Path, PurePosixPath

import pytest

from vibeguard.collector import (
    CollectorError,
    changed_lines,
    collect,
    extract_auth_context,
    extract_units,
    walk_repo,
)
from vibeguard.deterministic import (
    detect_cors,
    detect_deprecated_sdk,
    detect_god_file,
    detect_passthrough_wrappers,
    detect_secrets,
    detect_silent_exceptions,
    detect_supabase_rls,
    detect_supabase_rls_all,
    run_deterministic,
    shannon_entropy,
)
from vibeguard.models import Finding, Language, ScanContext, SourceFile

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
    _git(repo, "init")
    _git(repo, "config", "user.email", "dev@example.com")
    _git(repo, "config", "user.name", "Dev")
    _git(repo, "config", "commit.gpgsign", "false")


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


def test_shannon_entropy_empty_and_varied() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy(_HIGH) > 4.3


def test_walk_repo_honors_gitignore_vibeguardignore_and_skips_noise(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("secret.txt\nignored_dir/\n")
    (tmp_path / ".vibeguardignore").write_text("skipme.py\n")
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
    assert secret not in finding.snippet
    assert "supe…" in finding.snippet
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
        assert needle not in finding.snippet
        assert needle[:4] + "…" in finding.snippet
        assert str(len(needle)) in finding.snippet
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
