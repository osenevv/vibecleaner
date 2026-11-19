"""Risk tiers and the four review gates."""

from __future__ import annotations

from pathlib import Path

from vibecleaner.models import Finding, Language, RiskTier, SourceFile
from vibecleaner.risk import classify_file, route_review


def _file(path: str, text: str = "export const ready = true;\n") -> SourceFile:
    suffix = Path(path).suffix
    language = {
        ".py": Language.PYTHON,
        ".ts": Language.TYPESCRIPT,
        ".tsx": Language.TSX,
        ".js": Language.JAVASCRIPT,
        ".sql": Language.SQL,
    }.get(suffix, Language.OTHER)
    return SourceFile(path=path, abs_path=Path(path), language=language, text=text)


def _finding(rule_id: str, path: str, line: int = 1) -> Finding:
    return Finding(rule_id=rule_id, file=path, line=line, message=rule_id)


def test_classify_paths_and_code_signals() -> None:
    assert classify_file("app/api/billing/route.ts", "export function POST() {}\n") == RiskTier.HIGH
    assert classify_file("app/api/webhooks/stripe/route.ts", "export {}\n") == RiskTier.HIGH
    assert classify_file("app/api/checkout/route.ts", "export {}\n") == RiskTier.HIGH
    assert classify_file("src/middleware.ts", "export function middleware() {}\n") == RiskTier.HIGH
    assert classify_file("supabase/migrations/001_init.sql", "create table users ();\n") == RiskTier.HIGH
    assert classify_file("app/auth/login.ts", "export const ok = 1;\n") == RiskTier.HIGH

    assert classify_file("README.md", "# Hello\n") == RiskTier.LOW
    assert classify_file("docs/auth.md", "Auth is documented here.\n") == RiskTier.LOW
    assert classify_file("tests/test_widget.py", "def test_ok():\n    assert True\n") == RiskTier.LOW
    assert classify_file("tests/test_billing.py", "def test_pay():\n    assert True\n") == RiskTier.LOW
    assert classify_file("src/widget.test.ts", "it('ok', () => {});\n") == RiskTier.LOW
    assert classify_file("components/Button.stories.tsx", "export default {}\n") == RiskTier.LOW
    assert classify_file("app/globals.css", "body { color: red; }\n") == RiskTier.LOW
    assert classify_file("scripts/build.py", "print('ok')\n") == RiskTier.LOW
    assert classify_file("vite.config.ts", "export default {}\n") == RiskTier.LOW
    assert classify_file("components/Button.tsx", "export function Button() { return null }\n") == RiskTier.LOW
    assert classify_file("components/AuthButton.tsx", "export function AuthButton(){ return null }\n") == RiskTier.HIGH
    assert classify_file("components/PaymentForm.tsx", "export function PaymentForm(){ return null }\n") == RiskTier.HIGH
    assert classify_file("components/auth-button.tsx", "export function AuthButton(){ return null }\n") == RiskTier.HIGH
    assert classify_file("components/session.tsx", "export function Session(){ return null }\n") == RiskTier.HIGH
    assert classify_file("app/page.tsx", "export default function Page() { return null }\n") == RiskTier.LOW

    assert classify_file("app/api/users/route.ts", "export function GET() { return [] }\n") == RiskTier.MEDIUM
    assert classify_file("jobs/send_email.py", "def run():\n    return None\n") == RiskTier.MEDIUM
    assert classify_file("utils/format.ts", "export const trim = (s: string) => s.trim();\n") == RiskTier.MEDIUM
    assert classify_file(
        "components/Button.tsx",
        "export function Button() { return fetch('/api') }\n",
    ) == RiskTier.MEDIUM

    assert classify_file("utils/format.ts", "export const bill = stripe.charges;\n") == RiskTier.HIGH
    assert classify_file("utils/tokens.ts", "import jwt from 'jsonwebtoken'\n") == RiskTier.HIGH
    assert classify_file("lib/notes.py", "# do not use jwt here\n\ndef note():\n    return 1\n") == RiskTier.MEDIUM
    assert classify_file("lib/notes.py", 'note = "do not use jwt here"\n') == RiskTier.MEDIUM
    assert classify_file("lib/notes.py", "# DROP TABLE users\n\ndef note():\n    return 1\n") == RiskTier.MEDIUM
    assert classify_file("utils/format.ts", 'export const note = "stripe.charges";\n') == RiskTier.MEDIUM
    assert classify_file("utils/hash.ts", "bcrypt.hash(pw, 12)\n") == RiskTier.HIGH
    assert classify_file("lib/cleanup.sql", "DELETE FROM users WHERE id = 1;\n") == RiskTier.HIGH
    assert classify_file("scripts/wipe.py", "stmt = 'DROP TABLE accounts'\n") == RiskTier.HIGH
    assert classify_file("db/rls.sql", "CREATE POLICY read_own ON notes;\n") == RiskTier.HIGH
    server = "export const auth = () => createServerClient(url, key, { cookies })\n"
    assert classify_file("utils/supabase.ts", "createServerClient(url, key)\n") == RiskTier.MEDIUM
    assert classify_file("utils/supabase.ts", server) == RiskTier.HIGH
    assert classify_file("app/api/billing/route.ts", "export const ready = true;\n") == RiskTier.HIGH


def test_route_review_tiers() -> None:
    readme = _file("README.md", "# Notes\n")
    tests = _file("tests/test_widget.py", "def test_ok():\n    assert True\n")
    api = _file("app/api/users/route.ts", "export function POST() { return 1 }\n")
    checkout = _file("app/api/checkout/route.ts", "export function POST() { return 1 }\n")
    login = _file("app/auth/login.ts", "export const ok = 1;\n")

    clean = route_review([readme, tests], [], None)
    assert clean.tier == 1
    assert clean.human_review == []
    assert clean.file_risk == {"README.md": RiskTier.LOW, "tests/test_widget.py": RiskTier.LOW}
    assert "safe to auto-approve" in clean.reason
    assert "\n" not in clean.reason

    medium = route_review([api, readme], [], None)
    assert medium.tier == 2
    assert medium.human_review == []
    assert "app/api/users/route.ts" in medium.reason
    assert "automated semantic review" in medium.reason

    low_finding = route_review(
        [readme],
        [_finding("D9.debug_leftover", "README.md")],
        None,
    )
    assert low_finding.tier == 2
    assert low_finding.human_review == []

    high_only = route_review([checkout, readme], [], ["app/api/checkout/route.ts"])
    assert high_only.tier == 3
    assert high_only.human_review == ["app/api/checkout/route.ts"]
    assert high_only.reason == (
        "payments code changed: app/api/checkout/route.ts; a person should read it."
    )

    critical_medium = route_review(
        [api],
        [_finding("D1.hardcoded_secret", "app/api/users/route.ts")],
        None,
    )
    assert critical_medium.tier == 3
    assert critical_medium.human_review == ["app/api/users/route.ts"]
    assert "critical finding" in critical_medium.reason

    critical_low = route_review(
        [readme],
        [_finding("D1.hardcoded_secret", "README.md")],
        None,
    )
    assert critical_low.tier == 3
    assert critical_low.human_review == ["README.md"]

    not_critical = route_review(
        [login],
        [_finding("D6a.deprecated_sdk", "app/auth/login.ts")],
        None,
    )
    assert not_critical.tier == 3

    security = route_review(
        [checkout, login, readme],
        [_finding("D1.hardcoded_secret", "app/api/checkout/route.ts")],
        None,
    )
    assert security.tier == 4
    assert security.human_review[0] == "app/api/checkout/route.ts"
    assert "app/auth/login.ts" in security.human_review
    assert "README.md" not in security.human_review
    assert "critical finding" in security.reason
    assert "app/api/checkout/route.ts" in security.reason
    assert security.file_risk["README.md"] == RiskTier.LOW

    mixed = route_review(
        [login, api, readme],
        [_finding("D1.hardcoded_secret", "app/api/users/route.ts")],
        None,
    )
    assert mixed.tier == 3
    assert mixed.human_review == ["app/auth/login.ts", "app/api/users/route.ts"]
    assert "critical finding" in mixed.reason
    assert "app/auth/login.ts" in mixed.reason
    assert "app/api/users/route.ts" in mixed.reason


def test_route_review_honors_diff_scope() -> None:
    readme = _file("README.md", "# Notes\n")
    billing = _file("app/api/billing/route.ts", "export function POST() {}\n")
    findings = [_finding("D1.hardcoded_secret", "app/api/billing/route.ts")]

    docs_only = route_review([readme, billing], findings, ["README.md"])
    assert docs_only.tier == 1
    assert set(docs_only.file_risk) == {"README.md"}
    assert docs_only.human_review == []

    billing_only = route_review([readme, billing], findings, ["app\\api\\billing\\route.ts"])
    assert billing_only.tier == 4
    assert set(billing_only.file_risk) == {"app/api/billing/route.ts"}
    assert billing_only.human_review == ["app/api/billing/route.ts"]

    high_without_the_finding = route_review(
        [readme, billing],
        findings,
        ["README.md", "app/api/billing/route.ts"],
    )
    assert high_without_the_finding.tier == 4

    outside_critical = route_review(
        [readme, billing],
        [_finding("D1.hardcoded_secret", "README.md")],
        ["app/api/billing/route.ts"],
    )
    assert outside_critical.tier == 3
    assert outside_critical.human_review == ["app/api/billing/route.ts"]

    empty = route_review([readme, billing], findings, [])
    assert empty.tier == 1
    assert empty.file_risk == {}


def test_route_review_caps_human_list_on_full_scan() -> None:
    files = [_file(f"app/billing/f{index:02d}.ts") for index in range(30)]
    findings = [
        _finding("D9.debug_leftover", "app/billing/f29.ts", 1),
        _finding("D6a.silent_exception", "app/billing/f29.ts", 2),
    ]
    routing = route_review(files, findings, None)
    assert routing.tier == 3
    assert len(routing.file_risk) == 30
    assert len(routing.human_review) == 25
    assert routing.human_review[0] == "app/billing/f29.ts"
    assert routing.human_review[1] == "app/billing/f00.ts"
    assert "app/billing/f23.ts" in routing.human_review
    assert "app/billing/f24.ts" not in routing.human_review
    assert "5 more" in routing.reason
    assert "\n" not in routing.reason

    diff = route_review(files, [], [source.path for source in files])
    assert diff.tier == 3
    assert len(diff.human_review) == 30

    high = [_file(f"app/billing/h{index:02d}.ts") for index in range(24)]
    util = _file("lib/util.py", "def util():\n    return 1\n")
    mixed = route_review(high + [util], [_finding("D1.hardcoded_secret", "lib/util.py")], None)
    assert mixed.tier == 3
    assert "lib/util.py" in mixed.human_review
    assert mixed.human_review[0].startswith("app/billing/")
    assert "critical finding in lib/util.py" in mixed.reason
    assert "app/billing/" in mixed.reason
