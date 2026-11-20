"""Launch preflight: 42 checks, no network, no secret values in the report."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

import pytest

from vibeguard.collector import collect
from vibeguard.deterministic import run_deterministic
from vibeguard.models import Language, ScanContext, SourceFile
from vibeguard.preflight import (
    CheckResult,
    PreflightReport,
    Status,
    preflight_to_json,
    render_preflight_markdown,
    run_preflight,
)

_ROOT = Path(__file__).resolve().parents[1]
_BENCH = _ROOT / "benchmarks"
_MODULE = "\n".join(
    path.read_text(encoding="utf-8")
    for path in sorted((_ROOT / "vibeguard" / "preflight").glob("*.py"))
)
_BANNED = ("54-FZ", "152-FZ", "168-FZ", "149-FZ", "Roskomnadzor", "Роскомнадзор")
_SECRET_LEAK = re.compile(
    r"sk-proj-[A-Za-z0-9]|sk_(?:live|test)_[0-9A-Za-z]|pk_(?:live|test)_[0-9A-Za-z]|eyJ[A-Za-z0-9_-]{8,}"
)
# Problems that would be detector misfires on the safe benchmarks, not missing product pieces.
_NEVER_PROBLEM = frozenset({7, 8, 9, 10, 12, 14, 15, 16, 17, 22, 25})


def _language(path: str) -> Language:
    pure = PurePosixPath(path)
    if pure.name in {".env.example", ".env.sample", ".env.template"}:
        return Language.OTHER
    if pure.name == ".env" or pure.name.startswith(".env."):
        return Language.ENV
    return {
        ".py": Language.PYTHON,
        ".ts": Language.TYPESCRIPT,
        ".tsx": Language.TSX,
        ".js": Language.JAVASCRIPT,
        ".sql": Language.SQL,
    }.get(pure.suffix, Language.OTHER)


def _file(path: str, text: str) -> SourceFile:
    return SourceFile(path=path, abs_path=Path(path), language=_language(path), text=text)


def _ctx(files: list[SourceFile], root: Path | None = None) -> ScanContext:
    return ScanContext(
        root=root or Path("/nonexistent/vibeguard-preflight"),
        files=files,
        units=[],
        auth_context="",
    )


def _by_id(report: PreflightReport) -> dict[int, CheckResult]:
    return {check.id: check for check in report.checks}


def _assert_no_banned(text: str) -> None:
    for name in _BANNED:
        assert name not in text


def _assert_no_secret(text: str) -> None:
    assert _SECRET_LEAK.search(text) is None


def test_status_values() -> None:
    assert Status.OK == "ok"
    assert Status.WARNING == "warning"
    assert Status.PROBLEM == "problem"
    assert Status.NOT_CHECKED == "not checked"
    assert Status.NOT_APPLICABLE == "not applicable"


def test_forty_two_checks_in_order() -> None:
    report = run_preflight(_ctx([_file("app/main.py", "def hello() -> str:\n    return 'hi'\n")]), [])
    assert [check.id for check in report.checks] == list(range(1, 43))
    sections = ["A"] * 5 + ["B"] * 12 + ["C"] * 7 + ["D"] * 7 + ["E"] * 11
    assert [check.section for check in report.checks] == sections
    assert len(report.first_actions) == 3
    assert all(action.strip() for action in report.first_actions)
    assert "inferred" in report.summary.lower()
    for check in report.checks:
        assert check.title.strip()
        assert check.found.strip()
        assert check.evidence.strip()
        assert check.consequence.strip()
        if check.status == Status.NOT_CHECKED:
            assert check.verify.strip()
    payload = preflight_to_json(report)
    assert list(payload) == ["summary", "stack", "checks", "blockers", "can_wait", "first_actions"]
    assert len(payload["checks"]) == 42
    assert payload["checks"][0]["status"] in {item.value for item in Status}
    _assert_no_banned(json.dumps(payload))


def test_no_payments_are_not_applicable() -> None:
    report = run_preflight(_ctx([_file("app/main.py", "def hello() -> str:\n    return 'hi'\n")]), [])
    for check_id in range(18, 25):
        check = report.checks[check_id - 1]
        assert check.status == Status.NOT_APPLICABLE
        assert "payment" in check.found.lower()
        assert check.evidence.startswith("reason:")


def test_stripe_webhook_without_signature_is_a_problem() -> None:
    source = _file(
        "api/billing.py",
        "import stripe\n"
        "from fastapi import APIRouter, Request\n"
        "router = APIRouter()\n"
        "@router.post('/stripe/webhook')\n"
        "async def stripe_webhook(request: Request):\n"
        "    payload = await request.body()\n"
        "    event = stripe.Event.construct_from(payload, stripe.api_key)\n"
        "    return {'type': event['type']}\n",
    )
    report = run_preflight(_ctx([source]), [])
    check = _by_id(report)[22]
    assert check.status == Status.PROBLEM
    assert check.locations
    assert "api/billing.py:" in check.evidence
    assert "construct_from" not in check.evidence or "construct_event" not in check.found


def test_stripe_webhook_with_construct_event_is_not_a_problem() -> None:
    source = _file(
        "api/billing.py",
        "import stripe\n"
        "from fastapi import APIRouter, Request\n"
        "router = APIRouter()\n"
        "@router.post('/stripe/webhook')\n"
        "async def stripe_webhook(request: Request):\n"
        "    payload = await request.body()\n"
        "    signature = request.headers.get('stripe-signature', '')\n"
        "    event = stripe.Webhook.construct_event(payload, signature, 'whsec_example')\n"
        "    return {'type': event['type']}\n",
    )
    report = run_preflight(_ctx([source]), [])
    check = _by_id(report)[22]
    assert check.status != Status.PROBLEM
    assert check.status == Status.WARNING
    rendered = render_preflight_markdown(report)
    assert "whsec_example" not in rendered


def test_md5_password_is_a_problem_and_bcrypt_is_ok() -> None:
    weak = _file(
        "app/passwords.py",
        "import hashlib\n"
        "def store(password: str) -> str:\n"
        "    return hashlib.md5(password.encode()).hexdigest()\n",
    )
    weak_report = run_preflight(_ctx([weak]), [])
    assert _by_id(weak_report)[12].status == Status.PROBLEM
    assert "app/passwords.py:" in _by_id(weak_report)[12].evidence

    strong = _file(
        "app/passwords.py",
        "import bcrypt\n"
        "def store(password: str) -> bytes:\n"
        "    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n",
    )
    strong_report = run_preflight(_ctx([strong]), [])
    assert _by_id(strong_report)[12].status == Status.OK


def test_dangerously_set_inner_html_is_flagged() -> None:
    source = _file(
        "app/bio.tsx",
        "export function Bio({ html }: { html: string }) {\n"
        "  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n"
        "}\n",
    )
    report = run_preflight(_ctx([source]), [])
    check = _by_id(report)[9]
    assert check.status in {Status.WARNING, Status.PROBLEM}
    assert any(item.startswith("app/bio.tsx:") for item in check.locations)


def test_debug_true_is_a_problem() -> None:
    source = _file("app/settings_runtime.py", "DEBUG = True\napp_name = 'billing'\n")
    report = run_preflight(_ctx([source]), [])
    check = _by_id(report)[16]
    assert check.status == Status.PROBLEM
    assert "app/settings_runtime.py:" in check.evidence
    assert 16 in report.blockers


def test_committed_env_without_gitignore_is_a_problem_and_value_is_hidden() -> None:
    secret = "sk_" + "live_" + "SHOULDNOTPRINT1234567890"
    env = _file(".env", f"STRIPE_SECRET={secret}\n")
    ignore = _file(".gitignore", "node_modules/\n__pycache__/\n")
    report = run_preflight(_ctx([env, ignore]), [])
    check = _by_id(report)[10]
    assert check.status == Status.PROBLEM
    assert ".env:1" in check.locations
    rendered = render_preflight_markdown(report)
    encoded = json.dumps(preflight_to_json(report))
    assert secret not in rendered
    assert secret not in encoded
    _assert_no_secret(rendered)


def test_rate_limiter_is_not_a_problem() -> None:
    source = _file(
        "api/auth.py",
        "from slowapi import Limiter\n"
        "from fastapi import APIRouter\n"
        "limiter = Limiter(key_func=lambda: 'ip')\n"
        "router = APIRouter()\n"
        "@router.post('/login')\n"
        "def login() -> dict[str, bool]:\n"
        "    return {'ok': True}\n",
    )
    report = run_preflight(_ctx([source]), [])
    assert _by_id(report)[13].status != Status.PROBLEM


def test_markdown_has_table_and_closing_sections() -> None:
    report = run_preflight(_ctx([_file("app/main.py", "def hello() -> str:\n    return 'hi'\n")]), [])
    rendered = render_preflight_markdown(report)
    assert rendered.startswith("# VibeGuard launch preflight")
    rows = [line for line in rendered.splitlines() if line.startswith("| ") and line[2].isdigit()]
    assert len(rows) == 42
    assert "| # | Section | Check | Status | Found | Evidence | Consequence | Verify |" in rendered
    assert "\n## Blocks launch\n" in rendered
    assert "\n## Can wait\n" in rendered
    assert "\n## First three actions\n" in rendered
    assert "\n## Agent rules\n" in rendered
    _assert_no_banned(rendered)
    _assert_no_banned(_MODULE)
    for row in rows:
        assert row.count("|") >= 9


def test_module_output_has_no_russian_law_names() -> None:
    _assert_no_banned(_MODULE)
    report = run_preflight(
        _ctx(
            [
                _file(
                    "api/auth.py",
                    "from fastapi import APIRouter\n"
                    "router = APIRouter()\n"
                    "@router.post('/login')\n"
                    "def login() -> dict[str, str]:\n"
                    "    return {'status': 'ok'}\n",
                )
            ]
        ),
        [],
    )
    _assert_no_banned(render_preflight_markdown(report))
    _assert_no_banned(json.dumps(preflight_to_json(report)))


def _case_dirs(kind: str) -> list[Path]:
    base = _BENCH / kind
    return sorted(path for path in base.iterdir() if path.is_dir())


@pytest.mark.parametrize("kind", ["positive", "negative"])
def test_benchmarks_do_not_crash(kind: str) -> None:
    for case in _case_dirs(kind):
        ctx = collect(case)
        findings = run_deterministic(ctx)
        report = run_preflight(ctx, findings)
        assert [check.id for check in report.checks] == list(range(1, 43))
        rendered = render_preflight_markdown(report)
        _assert_no_banned(rendered)
        _assert_no_secret(rendered)
        _assert_no_secret(json.dumps(preflight_to_json(report)))


def test_negative_benchmarks_have_no_false_problems() -> None:
    """Safe fixtures must not trip injection, secrets, cookies, debug, or webhook checks."""
    missed: list[str] = []
    for case in _case_dirs("negative"):
        ctx = collect(case)
        findings = run_deterministic(ctx)
        report = run_preflight(ctx, findings)
        problems = {check.id for check in report.checks if check.status == Status.PROBLEM}
        bad = sorted(problems & _NEVER_PROBLEM)
        if bad:
            details = []
            for check in report.checks:
                if check.id in bad:
                    details.append(f"#{check.id} {check.found} [{check.evidence}]")
            missed.append(f"{case.name}: " + "; ".join(details))
        text = "\n".join(source.text for source in ctx.files)
        if _payment(text) is False:
            money = sorted(problems & set(range(18, 25)))
            if money:
                missed.append(f"{case.name}: money {money}")
    assert missed == []


def _payment(text: str) -> bool:
    return re.search(
        r"(?i)(?:\bstripe\b|@stripe/|\bSTRIPE_|loadStripe|api\.stripe\.com|\bpaddle\b|\bpaypal\b)",
        text,
    ) is not None


def test_negative_spot_checks() -> None:
    orders = collect(_BENCH / "negative" / "n01_router_level_auth")
    orders_report = run_preflight(orders, run_deterministic(orders))
    for check_id in range(18, 25):
        assert orders_report.checks[check_id - 1].status == Status.NOT_APPLICABLE

    cors = collect(_BENCH / "negative" / "n08_cors_allowlist")
    cors_report = run_preflight(cors, run_deterministic(cors))
    assert _by_id(cors_report)[17].status != Status.PROBLEM

    agent = collect(_BENCH / "negative" / "n11_guarded_agent")
    agent_report = run_preflight(agent, run_deterministic(agent))
    assert _by_id(agent_report)[15].status != Status.PROBLEM
    assert _by_id(agent_report)[9].status != Status.PROBLEM

    env_example = collect(_BENCH / "negative" / "n06_env_example")
    env_report = run_preflight(env_example, run_deterministic(env_example))
    assert _by_id(env_report)[10].status != Status.PROBLEM


def test_sink_text_in_a_string_or_comment_is_not_xss() -> None:
    source = _file(
        "app/patterns.py",
        'SINK = "dangerouslySetInnerHTML"\n'
        "# mark_safe(user_html)\n"
        'note = "innerHTML = value"\n'
        'doc = """document.write(user)"""\n',
    )
    report = run_preflight(_ctx([source]), [])
    assert _by_id(report)[9].status != Status.PROBLEM


def test_tsx_dynamic_html_sink_is_a_problem() -> None:
    source = _file(
        "app/bio.tsx",
        "export function Bio({ html }: { html: string }) {\n"
        "  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n"
        "}\n",
    )
    report = run_preflight(_ctx([source]), [])
    check = _by_id(report)[9]
    assert check.status == Status.PROBLEM
    assert any(item.startswith("app/bio.tsx:") for item in check.locations)


def test_debug_true_inside_a_regex_is_not_a_problem() -> None:
    source = _file(
        "app/patterns.py",
        "import re\n"
        'FLAG = re.compile(r"DEBUG = True")\n'
        'other = re.compile(r"debug = True")\n',
    )
    report = run_preflight(_ctx([source]), [])
    assert _by_id(report)[16].status != Status.PROBLEM


def test_inventory_prose_is_not_a_race_but_unguarded_sql_is() -> None:
    readme = _file("README.md", "Talks about inventory, stock, and booking.\n")
    copy = _file(
        "app/copy.py",
        'NOTE = "inventory remaining"\n'
        'MSG = "booking confirmed"\n',
    )
    report = run_preflight(_ctx([readme, copy]), [])
    assert _by_id(report)[25].status != Status.PROBLEM

    unsafe = _file(
        "app/stock.py",
        "def sell(db):\n"
        '    db.execute("UPDATE products SET stock = stock - 1")\n',
    )
    unsafe_report = run_preflight(_ctx([unsafe]), [])
    assert _by_id(unsafe_report)[25].status == Status.PROBLEM

    guarded = _file(
        "app/stock.py",
        "def sell(db):\n"
        '    db.execute("UPDATE products SET stock = stock - 1 WHERE stock > 0")\n',
    )
    guarded_report = run_preflight(_ctx([guarded]), [])
    assert _by_id(guarded_report)[25].status != Status.PROBLEM


def test_tests_on_disk_count_when_ignore_hides_them(tmp_path: Path) -> None:
    suite = tmp_path / "tests"
    suite.mkdir()
    (suite / "test_app.py").write_text("def test_ok() -> None:\n    assert True\n", encoding="utf-8")
    (tmp_path / ".vibeguardignore").write_text("tests/\n", encoding="utf-8")
    app = _file(
        "app/main.py",
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/health')\n"
        "def health() -> dict[str, bool]:\n"
        "    return {'ok': True}\n",
    )
    report = run_preflight(_ctx([app], root=tmp_path), [])
    assert _by_id(report)[30].status != Status.PROBLEM


def test_skip_list_words_are_not_account_or_payment_code() -> None:
    source = _file(
        "pkg/collector.py",
        "NAMES = (\n"
        '    ("clerkMiddleware", re.compile(r"\\bclerkMiddleware\\s*\\(")),\n'
        '    ("createServerClient", re.compile(r"\\bcreateServerClient\\s*\\(")),\n'
        '    ("getSession", re.compile(r"\\bgetSession\\s*\\(")),\n'
        '    ("auth.users", re.compile(r"auth\\.users")),\n'
        ")\n"
        'note = "stripe paypal"\n',
    )
    report = run_preflight(_ctx([source]), [])
    assert _by_id(report)[32].status == Status.NOT_APPLICABLE
    assert _by_id(report)[31].status == Status.NOT_APPLICABLE
    assert _by_id(report)[18].status == Status.NOT_APPLICABLE


def test_request_built_sql_is_a_problem() -> None:
    interpolated = _file(
        "app/query.py",
        "def find(request):\n"
        "    cursor.execute(f\"SELECT id FROM users WHERE name = '{request.args['name']}'\")\n",
    )
    interpolated_report = run_preflight(_ctx([interpolated]), [])
    assert _by_id(interpolated_report)[9].status == Status.PROBLEM

    concatenated = _file(
        "app/query.py",
        "def find(request):\n"
        "    cursor.execute(\"SELECT id FROM users WHERE name = '\" + request.args['name'] + \"'\")\n",
    )
    concatenated_report = run_preflight(_ctx([concatenated]), [])
    assert _by_id(concatenated_report)[9].status == Status.PROBLEM


def test_order_idempotency_must_belong_to_the_order() -> None:
    orders = _file(
        "app/orders.py",
        "import stripe\n"
        "def create_order():\n"
        "    return stripe.PaymentIntent.create(amount=100)\n",
    )
    migration = _file(
        "db/migrate.sql",
        "CREATE TABLE notes (id int);\n"
        "CREATE INDEX notes_id ON notes (id);\n"
        "INSERT INTO notes SELECT id FROM other ON CONFLICT DO NOTHING;\n",
    )
    page = _file("app/page.tsx", "export default function Page(){ return <h1>Hi</h1> }\n")
    report = run_preflight(_ctx([orders, migration, page]), [])
    assert _by_id(report)[21].status == Status.PROBLEM
    assert any(item.startswith("app/orders.py:") for item in _by_id(report)[21].locations)

    keyed = _file(
        "app/orders.py",
        "import stripe\n"
        "def create_order(key: str):\n"
        "    return stripe.PaymentIntent.create(amount=100, idempotency_key=key)\n",
    )
    keyed_report = run_preflight(_ctx([keyed]), [])
    assert _by_id(keyed_report)[21].status == Status.OK
    assert any(item.startswith("app/orders.py:") for item in _by_id(keyed_report)[21].locations)

    unique = _file(
        "db/migrate.sql",
        "CREATE TABLE orders (\n"
        "  id int PRIMARY KEY,\n"
        "  idempotency_key text UNIQUE\n"
        ");\n",
    )
    unique_report = run_preflight(_ctx([orders, unique]), [])
    assert _by_id(unique_report)[21].status == Status.OK
    assert any(item.startswith("db/migrate.sql:") for item in _by_id(unique_report)[21].locations)


def test_list_pagination_must_belong_to_the_list() -> None:
    ping = _file("app/ping.py", "def ping(q):\n    return q.limit(1)\n")
    index = _file("db/m.sql", "CREATE INDEX users_email ON users (email);\n")
    unrelated = run_preflight(_ctx([ping, index]), [])
    assert _by_id(unrelated)[26].status != Status.OK

    listed = _file(
        "app/orders.py",
        "def page(cur):\n"
        "    cur.execute('SELECT id FROM orders ORDER BY id LIMIT 50')\n",
    )
    paged = run_preflight(_ctx([listed]), [])
    assert _by_id(paged)[26].status == Status.OK
    assert any(item.startswith("app/orders.py:") for item in _by_id(paged)[26].locations)

    bare = _file("app/orders.py", "def all_rows(cur):\n    cur.execute('SELECT id FROM orders')\n")
    indexed = _file("db/m.sql", "CREATE INDEX orders_id ON orders (id);\n")
    indexed_report = run_preflight(_ctx([bare, indexed]), [])
    assert _by_id(indexed_report)[26].status == Status.OK
    assert any(item.startswith("db/m.sql:") for item in _by_id(indexed_report)[26].locations)


def test_empty_public_dir_is_not_an_image_pass(tmp_path: Path) -> None:
    public = tmp_path / "public"
    public.mkdir()
    (public / ".gitkeep").write_text("", encoding="utf-8")
    page = _file("app/page.tsx", "export default function Page(){ return null }\n")
    report = run_preflight(_ctx([page], root=tmp_path), [])
    check = _by_id(report)[39]
    assert check.status == Status.NOT_APPLICABLE
    assert check.locations == []

    (public / "icon.png").write_bytes(b"\x89PNG" + b"x" * 32)
    weighed = run_preflight(_ctx([page], root=tmp_path), [])
    ok = _by_id(weighed)[39]
    assert ok.status == Status.OK
    assert any(item.startswith("public/icon.png:") for item in ok.locations)


def test_missing_tests_cite_the_page(tmp_path: Path) -> None:
    button = _file(
        "components/Button.tsx",
        "export function Button(){ return <button>Go</button> }\n",
    )
    report = run_preflight(_ctx([button], root=tmp_path), [])
    check = _by_id(report)[30]
    assert check.status == Status.PROBLEM
    assert any(item.startswith("components/Button.tsx:") for item in check.locations)


def test_positive_dotenv_does_not_print_the_secret() -> None:
    case = _BENCH / "positive" / "p01_dotenv_secrets"
    ctx = collect(case)
    report = run_preflight(ctx, run_deterministic(ctx))
    assert _by_id(report)[10].status == Status.PROBLEM
    rendered = render_preflight_markdown(report)
    for source in ctx.files:
        if not source.path.endswith(".env"):
            continue
        for line in source.text.splitlines():
            if "=" not in line or line.strip().startswith("#"):
                continue
            value = line.split("=", 1)[1].strip()
            if len(value) >= 12:
                assert value not in rendered


def test_self_preflight_does_not_hallucinate_stack_or_false_oks_from_detector_regexes() -> None:
    ctx = collect(_ROOT)
    report = run_preflight(ctx, run_deterministic(ctx))
    assert "Stripe" not in report.stack
    assert "Next.js" not in report.stack
    assert "SendGrid" not in report.stack
    assert "/summarize" not in report.summary
    checks = _by_id(report)
    assert checks[12].status == Status.NOT_APPLICABLE
    assert checks[17].status == Status.NOT_APPLICABLE
    assert checks[41].status == Status.NOT_APPLICABLE
    assert "js.stripe.com" not in checks[40].found


def test_preflight_detects_string_security_headers_and_vendor_urls(tmp_path: Path) -> None:
    (tmp_path / "next.config.ts").write_text(
        'export default {\n'
        '  async headers() {\n'
        '    return [{ source: "/(.*)", headers: [\n'
        '      { key: "Strict-Transport-Security", value: "max-age=63072000" },\n'
        '      { key: "Content-Security-Policy", value: "default-src \'self\'" },\n'
        '    ]}];\n'
        '  },\n'
        '};\n',
        encoding="utf-8",
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "layout.tsx").write_text(
        'import Script from "next/script";\n'
        'export default function Layout({ children }: { children: any }) {\n'
        '  return (\n'
        '    <html><body>\n'
        '      <Script src="https://js.stripe.com/v3" />\n'
        '      {children}\n'
        '    </body></html>\n'
        '  );\n'
        '}\n',
        encoding="utf-8",
    )
    (tmp_path / "app" / "analytics.py").write_text(
        'def track(event: str) -> None:\n'
        '    url = "https://mixpanel.com/track"\n'
        '    _ = (event, url)\n',
        encoding="utf-8",
    )
    (tmp_path / "app" / "auth.ts").write_text(
        'import { NextResponse } from "next/server";\n'
        'import { getServerSession } from "next-auth";\n'
        'export async function POST(req: Request) {\n'
        '  const session = await getServerSession();\n'
        '  const { email } = await req.json();\n'
        '  return NextResponse.json({ ok: Boolean(email && session) });\n'
        '}\n',
        encoding="utf-8",
    )
    ctx = collect(tmp_path)
    report = run_preflight(ctx, run_deterministic(ctx))
    checks = _by_id(report)
    assert checks[17].status == Status.OK
    assert "js.stripe.com" in checks[34].found
    assert "mixpanel.com" in checks[34].found
    assert "js.stripe.com" in checks[40].found
    assert "mixpanel.com" in checks[40].found
