"""Tests for macOS certifi TLS, ratchet baseline, D9.expired_ttl, triage/CODEOWNERS, and money-path flows."""

from __future__ import annotations

import json
import ssl
import sys
import threading
from datetime import date
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from vibecleaner.agents.transport import _ssl_context
from vibecleaner.cli import main
from vibecleaner.deterministic import detect_expired_ttls
from vibecleaner.fix_contract import Verdict
from vibecleaner.flows import FlowsError, load_flows, run_flows, to_check_result
from vibecleaner.models import Language, SourceFile
from vibecleaner.triage import generate_codeowners, render_triage_markdown, run_triage


def test_transport_ssl_context_loads_ca_certs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    ctx = _ssl_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.cert_store_stats()["x509_ca"] > 0


def test_expired_ttl_rule_and_clean_lookalikes() -> None:
    today = date(2026, 11, 25)
    expired_py = SourceFile(
        path="app/shim.py",
        abs_path=Path("app/shim.py"),
        language=Language.PYTHON,
        text="# vibecleaner-ttl: 2026-10-01 remove legacy adapter\nx = 1\n",
    )
    hits = detect_expired_ttls(expired_py, today=today)
    assert len(hits) == 1
    assert hits[0].rule_id == "D9.expired_ttl"
    assert "2026-10-01" in hits[0].message
    assert "remove legacy adapter" in hits[0].message

    expired_ts = SourceFile(
        path="src/shim.ts",
        abs_path=Path("src/shim.ts"),
        language=Language.TYPESCRIPT,
        text="// @vibecleaner-ttl=2025-01-15 drop fallback\nexport const ok = true;\n",
    )
    assert len(detect_expired_ttls(expired_ts, today=today)) == 1

    # Clean lookalikes: future TTL, invalid date, test file, markdown doc.
    future_py = SourceFile("app/ok.py", Path("app/ok.py"), Language.PYTHON, "# vibecleaner-ttl: 2099-01-01\nx = 1\n")
    bad_date = SourceFile("app/bad.py", Path("app/bad.py"), Language.PYTHON, "# vibecleaner-ttl: 2020-99-99\nx = 1\n")
    test_file = SourceFile("tests/test_x.py", Path("tests/test_x.py"), Language.PYTHON, "# vibecleaner-ttl: 2020-01-01\n")
    doc_file = SourceFile("README.md", Path("README.md"), Language.OTHER, "# vibecleaner-ttl: 2020-01-01\n")
    assert detect_expired_ttls(future_py, today=today) == []
    assert detect_expired_ttls(bad_date, today=today) == []
    assert detect_expired_ttls(test_file, today=today) == []
    assert detect_expired_ttls(doc_file, today=today) == []


def test_scan_baseline_ratchet_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        "# vibecleaner-ttl: 2020-01-01 old shim\n"
        "def run() -> int:\n"
        "    return 1\n",
        encoding="utf-8",
    )
    # Without baseline, expired TTL (HIGH) fails scan with exit 1.
    assert main(["scan", str(tmp_path), "--mode", "offline", "--no-cache", "--no-report", "--quiet"]) == 1

    # Save baseline, then re-run with --baseline -> passes (exit 0) because nothing regressed.
    main(["scan", str(tmp_path), "--mode", "offline", "--no-cache", "--no-report", "--quiet", "--save-baseline"])
    capsys.readouterr()
    assert (tmp_path / ".vibecleaner" / "baseline.json").is_file()
    assert main(["scan", str(tmp_path), "--mode", "offline", "--no-cache", "--no-report", "--baseline", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["baseline"]["regressed"] is False
    assert payload["baseline"]["new_findings_count"] == 0

    # Add a second expired shim -> ratchet catches the regression and exits 1.
    (tmp_path / "other.py").write_text("# vibecleaner-ttl: 2020-02-02 second shim\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--mode", "offline", "--no-cache", "--no-report", "--baseline", "--json"]) == 1
    regressed = json.loads(capsys.readouterr().out)
    assert regressed["baseline"]["regressed"] is True
    assert regressed["baseline"]["new_findings_count"] == 1

    # Missing explicit baseline file -> exit 2.
    assert main(["scan", str(tmp_path), "--mode", "offline", "--no-cache", "--no-report", "--baseline", str(tmp_path / "missing.json")]) == 2


def test_triage_keep_fix_rebuild_and_codeowners(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "clean.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    (tmp_path / "messy.py").write_text(
        "# vibecleaner-ttl: 2020-01-01 old\n"
        "def run() -> int:\n"
        "    return 1\n",
        encoding="utf-8",
    )
    # High-risk auth module with >= 300 LOC and critical hardcoded secret -> REBUILD.
    fake_secret = "sk_" + "live_" + "1234567890abcdef1234567890abcdef"
    big_auth = f'API_KEY = "{fake_secret}"\n' + "".join(f"x_{i} = {i}\n" for i in range(310))
    (tmp_path / "auth_service.py").write_text(big_auth, encoding="utf-8")
    # 3 high-risk files in billing/ to test directory collapsing in CODEOWNERS.
    billing = tmp_path / "billing"
    billing.mkdir()
    for name in ("checkout.py", "stripe_sync.py", "webhook.py"):
        (billing / name).write_text("def ok() -> bool:\n    return True\n", encoding="utf-8")

    rc = main(["triage", str(tmp_path), "--write-codeowners", "@security-team", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    by_path = {m["path"]: m for m in data["modules"]}
    assert by_path["clean.py"]["decision"] == "keep"
    assert by_path["messy.py"]["decision"] == "fix"
    assert by_path["auth_service.py"]["decision"] == "rebuild"

    codeowners = (tmp_path / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    assert "/billing/ @security-team" in codeowners
    assert "/auth_service.py @security-team" in codeowners

    report = run_triage(tmp_path)
    md = render_triage_markdown(report)
    assert "# Keep / Fix / Rebuild Triage" in md
    assert "`auth_service.py`" in md
    assert generate_codeowners(report, "@sec").startswith("# Generated by VibeCleaner triage")


def test_flows_command_http_and_error_handling(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # No flows configured -> exits 0 cleanly.
    assert main(["flows", str(tmp_path)]) == 0
    capsys.readouterr()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"boom")

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        vc = tmp_path / ".vibecleaner"
        vc.mkdir()
        (vc / "flows.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "flows": [
                        {
                            "name": "cli-ok",
                            "kind": "command",
                            "command": [sys.executable, "-c", "print('checkout ok')"],
                            "expect_exit": 0,
                            "expect_stdout": ["checkout ok"],
                            "forbid_stdout": ["Traceback"],
                        },
                        {
                            "name": "http-health",
                            "kind": "http",
                            "url": f"http://127.0.0.1:{port}/health",
                            "expect_status": 200,
                            "expect_body": ['"ok"'],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert main(["flows", str(tmp_path), "--json"]) == 0
        ok_data = json.loads(capsys.readouterr().out)
        assert ok_data["ok"] is True and ok_data["passed"] == 2

        # Failing HTTP flow -> exit 1 and Verdict.REVISE.
        (vc / "flows.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "flows": [
                        {
                            "name": "http-broken",
                            "kind": "http",
                            "url": f"http://127.0.0.1:{port}/fail",
                            "expect_status": 200,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert main(["flows", str(tmp_path)]) == 1
        specs = load_flows(tmp_path)
        check = to_check_result(run_flows(tmp_path, specs))
        assert check.verdict is Verdict.REVISE
        assert "http-broken" in check.evidence[0].summary
    finally:
        server.shutdown()
        server.server_close()

    # Broken flows.json -> exit 2.
    (tmp_path / ".vibecleaner" / "flows.json").write_text('{"version": 99, "flows": []}', encoding="utf-8")
    assert main(["flows", str(tmp_path)]) == 2
    with pytest.raises(FlowsError):
        load_flows(tmp_path)
