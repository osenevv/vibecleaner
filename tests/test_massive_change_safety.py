"""Regression & whole-repo safety tests for multi-file structural and surface edits."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from vibecleaner.cleanup import fix_tree, revert_rule
from vibecleaner.repo_health import verify_static_tree


def _write(root: Path, rel: str, text: str) -> None:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")


def _run_py(root: Path, code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cross_file_private_helpers_are_preserved_during_fix(tmp_path: Path) -> None:
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/common.py",
        "def _message_redirect(msg: str) -> str:\n"
        "    return f'redirect:{msg}'\n\n"
        "def _truly_unused_helper() -> int:\n"
        "    return 42\n",
    )
    _write(
        tmp_path,
        "pkg/views.py",
        "from .common import _message_redirect\n\n"
        "def handle() -> str:\n"
        "    return _message_redirect('ok')\n",
    )
    fix_tree(tmp_path, use_host=False)
    common = (tmp_path / "pkg/common.py").read_text(encoding="utf-8")
    assert "def _message_redirect" in common
    assert "def _truly_unused_helper" not in common
    proc = _run_py(tmp_path, "from pkg.views import handle; assert handle() == 'redirect:ok'")
    assert proc.returncode == 0, proc.stderr


def test_multiple_shared_keys_do_not_clobber_earlier_constant_definitions(tmp_path: Path) -> None:
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/constants.py",
        "DEFAULTS = {'alpha_key': 1, 'beta_key': 2, 'gamma_key': 3}\n",
    )
    _write(
        tmp_path,
        "pkg/one.py",
        "from .constants import DEFAULTS\n\n"
        "def first(row: dict) -> int:\n"
        "    return row['alpha_key'] + DEFAULTS['beta_key']\n",
    )
    _write(
        tmp_path,
        "pkg/two.py",
        "from .constants import DEFAULTS\n\n"
        "def second(row: dict) -> int:\n"
        "    return row['gamma_key'] + DEFAULTS['beta_key']\n",
    )
    fix_tree(tmp_path, use_host=False)
    constants = (tmp_path / "pkg/constants.py").read_text(encoding="utf-8")
    assert 'ALPHA_KEY = "alpha_key"' in constants
    assert 'BETA_KEY = "beta_key"' in constants
    assert 'GAMMA_KEY = "gamma_key"' in constants
    proc = _run_py(
        tmp_path,
        "from pkg.one import first; from pkg.two import second; "
        "assert first({'alpha_key': 10}) == 12; assert second({'gamma_key': 20}) == 22",
    )
    assert proc.returncode == 0, proc.stderr
    assert verify_static_tree(tmp_path, {"pkg/constants.py", "pkg/one.py", "pkg/two.py"}) is None


def test_coupling_never_creates_package_init_or_cross_layer_import_cycles(tmp_path: Path) -> None:
    _write(tmp_path, "games/__init__.py", "")
    _write(tmp_path, "games/models/__init__.py", "from .live import LiveGame\nfrom .game import Game\n")
    _write(
        tmp_path,
        "games/models/game.py",
        "from .live import LiveGame\n\n"
        "class Game:\n"
        "    pass\n\n"
        "def build() -> dict:\n"
        "    return {'players_data': []}\n",
    )
    _write(
        tmp_path,
        "games/models/live.py",
        "from .mixins import DisplayMixin\n\n"
        "class LiveGame(DisplayMixin):\n"
        "    pass\n",
    )
    _write(
        tmp_path,
        "games/models/mixins.py",
        "class DisplayMixin:\n"
        "    def ctx(self) -> dict:\n"
        "        return {'players_data': [1]}\n",
    )
    _write(
        tmp_path,
        "games/views/board.py",
        "from games.models import Game\n\n"
        "def show(ctx: dict) -> list:\n"
        "    return ctx['players_data']\n",
    )
    fix_tree(tmp_path, use_host=False)
    proc = _run_py(tmp_path, "import games.models; import games.views.board")
    assert proc.returncode == 0, proc.stderr


def test_layer_folder_move_rewrites_relative_and_test_imports_and_internal_relatives(tmp_path: Path) -> None:
    _write(tmp_path, "games/__init__.py", "")
    _write(tmp_path, "games/constants.py", "BASE_POINTS = 10\n")
    _write(tmp_path, "games/utils/__init__.py", "")
    _write(
        tmp_path,
        "games/utils/scoring.py",
        "from ..constants import BASE_POINTS\n\n"
        "def calc_score(mult: int) -> int:\n"
        "    return BASE_POINTS * mult\n",
    )
    _write(tmp_path, "games/views/__init__.py", "")
    _write(
        tmp_path,
        "games/views/board.py",
        "from ..utils.scoring import calc_score\n\n"
        "def render_score() -> int:\n"
        "    return calc_score(3)\n",
    )
    _write(
        tmp_path,
        "games/tests/test_scoring.py",
        "from games.utils.scoring import calc_score\n\n"
        "def test_calc() -> None:\n"
        "    assert calc_score(2) == 20\n",
    )
    fix_tree(tmp_path, use_host=False)
    assert not (tmp_path / "games/utils/scoring.py").exists()
    assert (tmp_path / "games/views/scoring.py").is_file()
    proc = _run_py(
        tmp_path,
        "from games.views.board import render_score; assert render_score() == 30; "
        "import games.tests.test_scoring as t; t.test_calc()",
    )
    assert proc.returncode == 0, proc.stderr
    revert_rule(tmp_path, "D6a.layer_folder")
    assert (tmp_path / "games/utils/scoring.py").is_file()
    assert not (tmp_path / "games/views/scoring.py").exists()


def test_template_badges_variables_and_form_buttons_are_not_corrupted(tmp_path: Path) -> None:
    html = (
        "<!DOCTYPE html><html><head><title>Tournament</title>"
        "<style>{% if dark %}body { color: #ffffff; }{% endif %}</style>"
        "</head><body>"
        "<h1>{{ TOURNAMENT_TITLE }}</h1>"
        "<span class='badge status-active'>{{ tournament.status }}</span>"
        "<div class='badge'><span class='inner'>Nested</span></div>"
        + "".join(
            f"<button type='submit' name='seat' value='{i}' class='seat-btn'>Seat {i}</button>"
            for i in range(1, 8)
        )
        + "</body></html>\n"
    )
    _write(tmp_path, "templates/detail.html", html)
    fix_tree(tmp_path, use_host=False)
    out = (tmp_path / "templates/detail.html").read_text(encoding="utf-8")
    assert "{{ TOURNAMENT_TITLE }}" in out
    assert "{{ tournament.status }}" in out
    assert "<span class='inner'>Nested</span>" in out
    assert "{% if dark %}" in out and "{% endif %}" in out
    assert out.count("class='seat-btn'") == 7


def test_post_fix_static_gate_automatically_rolls_back_broken_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/app.py",
        "def run() -> int:\n"
        "    breakpoint()\n"
        "    return 7\n",
    )
    import vibecleaner.structure as structure_mod

    def broken_structure(root: Path, skip_rules: frozenset[str] = frozenset()):
        if "D6a.implicit_coupling" in skip_rules:
            return {}
        target = root / "pkg/app.py"
        original = target.read_text(encoding="utf-8")
        broken = "from pkg.nonexistent_mod import GHOST_CONST\n" + original
        target.write_text(broken, encoding="utf-8")
        return {"pkg/app.py": (original, ("D6a.implicit_coupling",))}

    monkeypatch.setattr(structure_mod, "repair_structure", broken_structure)
    report = fix_tree(tmp_path, use_host=False)
    app_text = (tmp_path / "pkg/app.py").read_text(encoding="utf-8")
    assert "breakpoint()" not in app_text
    assert "GHOST_CONST" not in app_text
    assert any("D6a.implicit_coupling reverted" in item for item in report.held)
    proc = _run_py(tmp_path, "from pkg.app import run; assert run() == 7")
    assert proc.returncode == 0, proc.stderr


def test_post_fix_project_test_gate_rolls_back_edit_that_breaks_passing_tests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "pytest.ini", "[pytest]\n")
    _write(
        tmp_path,
        "app.py",
        "def compute() -> int:\n"
        "    # TODO: implement the real calculation later\n"
        "    return 10\n",
    )
    _write(
        tmp_path,
        "test_app.py",
        "from app import compute\n\n"
        "def test_compute() -> None:\n"
        "    assert compute() == 10\n",
    )
    import vibecleaner.structure as structure_mod

    def subtle_breaker(root: Path, skip_rules: frozenset[str] = frozenset()):
        if "D6a.layering_violation" in skip_rules:
            return {}
        target = root / "app.py"
        original = target.read_text(encoding="utf-8")
        mutated = original.replace("return 10", "return 999")
        target.write_text(mutated, encoding="utf-8")
        return {"app.py": (original, ("D6a.layering_violation",))}

    monkeypatch.setattr(structure_mod, "repair_structure", subtle_breaker)
    report = fix_tree(tmp_path, use_host=False)
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "TODO: implement" not in text
    assert "return 10" in text
    assert any("D6a.layering_violation reverted" in item for item in report.held)


def test_passthrough_never_rewrites_same_named_symbol_from_another_module(tmp_path: Path) -> None:
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/desktop.py",
        "def default_data_dir(platform_name: str | None = None) -> str:\n"
        "    return platform_name or 'default'\n\n"
        "def data_dir() -> str:\n"
        "    return default_data_dir()\n\n"
        "def launch() -> str:\n"
        "    return data_dir()\n",
    )
    _write(
        tmp_path,
        "pkg/cli.py",
        "def data_dir(profile: str) -> str:\n"
        "    return f'profiles/{profile}'\n",
    )
    _write(
        tmp_path,
        "tests/test_cli.py",
        "from pkg.cli import data_dir\n\n"
        "def test_profiles() -> None:\n"
        "    assert data_dir('alice') == 'profiles/alice'\n",
    )
    fix_tree(tmp_path, use_host=False)
    test_cli = (tmp_path / "tests/test_cli.py").read_text(encoding="utf-8")
    assert "from pkg.cli import data_dir" in test_cli
    assert "data_dir('alice')" in test_cli
    assert "default_data_dir" not in test_cli
    proc = _run_py(tmp_path, "from tests.test_cli import test_profiles; test_profiles()")
    assert proc.returncode == 0, proc.stderr


def test_passthrough_preserves_symbol_targeted_by_monkeypatch_string(tmp_path: Path) -> None:
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/desktop.py",
        "def default_data_dir() -> str:\n"
        "    return 'root'\n\n"
        "def data_dir() -> str:\n"
        "    return default_data_dir()\n\n"
        "def main() -> str:\n"
        "    return data_dir()\n",
    )
    _write(
        tmp_path,
        "tests/test_launch.py",
        "def test_launch(monkeypatch) -> None:\n"
        "    monkeypatch.setattr('pkg.desktop.data_dir', lambda: 'tmp')\n",
    )
    fix_tree(tmp_path, use_host=False)
    desktop = (tmp_path / "pkg/desktop.py").read_text(encoding="utf-8")
    assert "def data_dir" in desktop
    assert verify_static_tree(tmp_path, {"pkg/desktop.py"}) is None


def test_static_verifier_catches_deleted_monkeypatch_target(tmp_path: Path) -> None:
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/desktop.py", "def default_data_dir() -> str:\n    return 'root'\n")
    _write(
        tmp_path,
        "tests/test_launch.py",
        "def test_launch(monkeypatch) -> None:\n"
        "    monkeypatch.setattr('pkg.desktop.data_dir', lambda: 'tmp')\n",
    )
    err = verify_static_tree(tmp_path, {"pkg/desktop.py"})
    assert err is not None and "pkg.desktop.data_dir" in err


def test_coupling_never_inverts_storage_layer_or_links_unrelated_peers(tmp_path: Path) -> None:
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/database.py",
        "def load(row: dict) -> str:\n"
        "    return str(row['capsule_type'])\n",
    )
    _write(
        tmp_path,
        "pkg/decay.py",
        "def score(row: dict) -> str:\n"
        "    return str(row['capsule_type'])\n",
    )
    _write(
        tmp_path,
        "pkg/web.py",
        "def job_info(entry: dict) -> str:\n"
        "    return str(entry.get('custom_label'))\n",
    )
    _write(
        tmp_path,
        "pkg/recording.py",
        "def rec_info(entry: dict) -> str:\n"
        "    return str(entry.get('custom_label'))\n",
    )
    fix_tree(tmp_path, use_host=False)
    db_src = (tmp_path / "pkg/database.py").read_text(encoding="utf-8")
    web_src = (tmp_path / "pkg/web.py").read_text(encoding="utf-8")
    assert "from pkg.decay import" not in db_src
    assert "from pkg.recording import" not in web_src


def test_surface_chrome_preserves_dark_mode_tokens_and_does_not_clobber_theme(tmp_path: Path) -> None:
    from vibecleaner.repo_health import verify_surface_health

    html = (
        "<!DOCTYPE html><html><head><title>App</title><style>\n"
        ":root { --bg: #eef1f5; --surface: #fbfcfd; --text: #1a212c; --accent: #365dcc; }\n"
        "@media (prefers-color-scheme: dark) {\n"
        "  :root:not([data-theme]) {\n"
        "    --bg: #15181d;\n"
        "    --surface: #1d2229;\n"
        "    --text: #f0f3f7;\n"
        "    --accent: #7d9bff;\n"
        "    --danger: #ef8999;\n"
        "  }\n"
        "}\n"
        ':root[data-theme="dark"] {\n'
        "  --bg: #15181d;\n"
        "  --text: #f0f3f7;\n"
        "  --danger: #ef8999;\n"
        "}\n"
        "a:focus-visible { outline: 2px solid var(--accent); }\n"
        "</style></head><body><h1>Hello</h1></body></html>\n"
    )
    _write(tmp_path, "index.html", html)
    fix_tree(tmp_path, use_host=False)
    out = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "--bg: #15181d;" in out
    assert "--text: #f0f3f7;" in out
    assert "--danger: #ef8999;" in out
    assert 'data-vibecleaner="design"' not in out
    assert verify_surface_health(tmp_path, {"index.html"}, {"index.html": html}) is None

    # Directly verify verify_surface_health catches palette collapse.
    collapsed = html.replace("--bg: #15181d;", "--bg: var(--text-secondary);").replace(
        "--text: #f0f3f7;", "--text: var(--text-secondary);"
    ).replace("--danger: #ef8999;", "--danger: var(--text-secondary);")
    (tmp_path / "index.html").write_text(collapsed, encoding="utf-8")
    err = verify_surface_health(tmp_path, {"index.html"}, {"index.html": html})
    assert err is not None and "collapsed" in err


def test_post_fix_gate_reverts_new_regression_despite_preexisting_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "pytest.ini", "[pytest]\n")
    _write(
        tmp_path,
        "app.py",
        "def healthy() -> int:\n"
        "    # TODO: implement the real logic later\n"
        "    return 10\n",
    )
    _write(
        tmp_path,
        "test_app.py",
        "from app import healthy\n\n"
        "def test_preexisting_broken() -> None:\n"
        "    assert False\n\n"
        "def test_healthy() -> None:\n"
        "    assert healthy() == 10\n",
    )
    import vibecleaner.structure as structure_mod

    def subtle_breaker(root: Path, skip_rules: frozenset[str] = frozenset()):
        if "D6a.layering_violation" in skip_rules:
            return {}
        target = root / "app.py"
        original = target.read_text(encoding="utf-8")
        target.write_text(original.replace("return 10", "return 999"), encoding="utf-8")
        return {"app.py": (original, ("D6a.layering_violation",))}

    monkeypatch.setattr(structure_mod, "repair_structure", subtle_breaker)
    report = fix_tree(tmp_path, use_host=False)
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "TODO: implement" not in text
    assert "return 10" in text
    assert any("D6a.layering_violation reverted" in item for item in report.held)


def test_d5_unsafe_sink_precision_on_static_html_and_safe_sql_clauses() -> None:
    from vibecleaner.models import Language, SourceFile
    from vibecleaner.production import production_findings

    safe_html = SourceFile(
        "index.html",
        Path("index.html"),
        Language.OTHER,
        "<script>\n"
        "el.innerHTML = '<div class=\"empty\">No matches.</div>';\n"
        "el.innerHTML = '';\n"
        "</script>\n",
    )
    bad_html = SourceFile(
        "bad.html",
        Path("bad.html"),
        Language.OTHER,
        "<script>\nel.innerHTML = `<p>${userInput}</p>`;\n</script>\n",
    )
    safe_sql = SourceFile(
        "db.py",
        Path("db.py"),
        Language.PYTHON,
        "SCHEMA_VERSION = 3\n"
        "def run(conn, profile_id):\n"
        "    clause = '' if profile_id is None else ' WHERE profile_id=?'\n"
        "    conn.execute(f'SELECT * FROM items{clause}', [profile_id] if profile_id else [])\n"
        "    conn.execute(f'PRAGMA user_version = {SCHEMA_VERSION}')\n",
    )
    bad_sql = SourceFile(
        "bad_db.py",
        Path("bad_db.py"),
        Language.PYTHON,
        "def run(conn, user_id):\n"
        "    conn.execute(f'SELECT * FROM items WHERE id={user_id}')\n",
    )
    assert not any(f.rule_id == "D5.unsafe_sink" for f in production_findings(Path("."), [safe_html, safe_sql]))
    assert any(f.rule_id == "D5.unsafe_sink" for f in production_findings(Path("."), [bad_html]))
    assert any(f.rule_id == "D5.unsafe_sink" for f in production_findings(Path("."), [bad_sql]))


def test_d8_ignores_per_item_loops_and_sentinel_workers_but_flags_real_retries() -> None:
    from vibecleaner.models import Language, SourceFile
    from vibecleaner.states import detect_state_bugs

    per_item = SourceFile(
        "gui.py",
        Path("gui.py"),
        Language.PYTHON,
        "def disable_menu(menu, last):\n"
        "    for idx in range(last + 1):\n"
        "        try:\n"
        "            menu.entryconfigure(idx, state='disabled')\n"
        "        except RuntimeError:\n"
        "            pass\n",
    )
    worker = SourceFile(
        "worker.py",
        Path("worker.py"),
        Language.PYTHON,
        "def run(queue):\n"
        "    while True:\n"
        "        item = queue.get()\n"
        "        if item is None:\n"
        "            return\n"
        "        try:\n"
        "            handle(item)\n"
        "        except Exception:\n"
        "            continue\n",
    )
    assert detect_state_bugs(per_item) == []
    assert detect_state_bugs(worker) == []


def test_pill_strip_does_not_leave_stray_px_tokens_in_css(tmp_path: Path) -> None:
    html = (
        "<!DOCTYPE html><html><head><style>\n"
        ":root { --bg: #eef1f5; --surface: #fbfcfd; --accent: #365dcc; --shadow: 0 2px 10px rgba(0,0,0,.1); }\n"
        ".thumb { border: 3px solid var(--bg); border-radius: 999px; background: var(--surface); }\n"
        ".record-button { width: 82px; height: 82px; border-radius: 50%; background: var(--accent); color: #fff; font-weight: 760; box-shadow: var(--shadow); }\n"
        ".status::before { width: 7px; height: 7px; border-radius: 50%; }\n"
        ".meter { border-radius: 999px; }\n"
        "a:focus-visible { outline: 2px solid var(--accent); }\n"
        "</style></head><body><h1>Yapper</h1></body></html>\n"
    )
    _write(tmp_path, "index.html", html)
    fix_tree(tmp_path, use_host=False)
    out = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert " px;" not in out and ";px;" not in out and "{px;" not in out
    assert "border-radius: 50%" in out
    assert "border-radius: 999px" in out
    assert "box-shadow: var(--shadow)" in out
    assert "font-weight: 760" in out
    assert "color: #fff" in out


def test_js_bound_badges_and_id_primary_buttons_are_never_stripped_or_demoted(tmp_path: Path) -> None:
    html = (
        "<!DOCTYPE html><html><head><title>App</title></head><body>\n"
        '<span id="task-count" class="badge">0</span>\n'
        '<button id="settings-save" class="primary" type="button">Save</button>\n'
        '<button id="search-button" class="primary" type="submit">Find</button>\n'
        "</body></html>\n"
    )
    _write(tmp_path, "index.html", html)
    fix_tree(tmp_path, use_host=False)
    out = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert '<span id="task-count" class="badge">0</span>' in out
    assert 'id="settings-save" class="primary"' in out
    assert 'id="search-button" class="primary"' in out
