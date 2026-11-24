from __future__ import annotations

import json
from pathlib import Path

from vibecleaner.cli import main


def _build_fullstack_repo(root: Path) -> None:
    (root / ".gitignore").write_text(".env\nnode_modules/\n__pycache__/\n", encoding="utf-8")
    (root / ".env.example").write_text("STRIPE_SECRET_KEY=placeholder\n", encoding="utf-8")
    (root / "api").mkdir()
    (root / "api" / "routes.py").write_text(
        "from fastapi import APIRouter, Depends\n\n"
        "router = APIRouter()\n\n"
        "def require_user() -> str:\n"
        "    return 'user_1'\n\n"
        "@router.post('/orders')\n"
        "def create_order(item_id: str, user: str = Depends(require_user)) -> dict[str, str]:\n"
        "    return {'item_id': item_id, 'user': user}\n",
        encoding="utf-8",
    )
    (root / "web").mkdir()
    (root / "web" / "health.ts").write_text(
        "export function healthCheck(): { ok: boolean } {\n"
        "  return { ok: true };\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "supabase").mkdir()
    (root / "supabase" / "001_init.sql").write_text(
        "CREATE TABLE orders (id uuid primary key, user_id uuid not null);\n"
        "ALTER TABLE orders ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY orders_owner ON orders USING (auth.uid() = user_id);\n",
        encoding="utf-8",
    )
    (root / "tests").mkdir()
    (root / "tests" / "test_api.py").write_text(
        "from api.routes import create_order\n\n"
        "def test_create_order() -> None:\n"
        "    assert create_order('sku_1', 'user_1') == {'item_id': 'sku_1', 'user': 'user_1'}\n",
        encoding="utf-8",
    )


def test_e2e_fullstack_repo_scan_sarif_deslop_states_preflight(tmp_path: Path, capsys) -> None:
    _build_fullstack_repo(tmp_path)
    sarif_path = tmp_path / "out.sarif"
    report_path = tmp_path / "REPORT.md"

    scan_code = main(
        [
            "scan",
            str(tmp_path),
            "--mode",
            "offline",
            "--no-cache",
            "--json",
            "--sarif",
            str(sarif_path),
            "--report",
            str(report_path),
        ]
    )
    scan_out = json.loads(capsys.readouterr().out)
    assert scan_code == 0
    assert scan_out["files_scanned"] >= 3
    assert sarif_path.is_file()
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert report_path.is_file()

    deslop_code = main(["deslop", str(tmp_path), "--out", str(tmp_path / "DESLOP.md")])
    capsys.readouterr()
    assert deslop_code == 0
    assert (tmp_path / "DESLOP.md").is_file()

    states_code = main(["states", str(tmp_path), "--out", str(tmp_path / "STATES.md")])
    capsys.readouterr()
    assert states_code == 0
    assert (tmp_path / "STATES.md").is_file()

    preflight_code = main(["preflight", str(tmp_path), "--out", str(tmp_path / "PREFLIGHT.md")])
    capsys.readouterr()
    assert preflight_code in {0, 1}
    assert (tmp_path / "PREFLIGHT.md").is_file()
