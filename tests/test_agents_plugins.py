"""Claude Code hook, Start skills, and init install targets."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_http import Bench, base_url, serve  # noqa: E402

from gitutil import init_git
from vibeguard.init_cmd import run_init

_ROOT = Path(__file__).resolve().parents[1]
_HOOK = _ROOT / "integrations" / "claude-code" / "vibeguard" / "hooks" / "vibeguard-hook.sh"


def _git_with_main(repo: Path) -> None:
    init_git(repo)
    subprocess.run(["git", "commit", "--allow-empty", "-m", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "branch", "-M", "main"], cwd=repo, check=True)


def _tool_bin(bin_dir: Path) -> None:
    for name in ("git", "python3", "mktemp", "rm", "cat", "tr", "dirname"):
        source = shutil.which(name)
        assert source is not None
        link = bin_dir / name
        if not link.exists():
            link.symlink_to(source)


def _fake_vibeguard(bin_dir: Path, record: Path, *, code: int, stdout: str = "", stderr: str = "") -> None:
    script = bin_dir / "vibeguard"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        f"pathlib.Path({str(record)!r}).write_text(json.dumps(sys.argv[1:]), encoding='utf-8')\n"
        f"sys.stdout.write({stdout!r})\n"
        f"sys.stderr.write({stderr!r})\n"
        f"raise SystemExit({code})\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)


def _run_hook(repo: Path, bin_dir: Path, event: str, payload: str = "{}") -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PATH"] = str(bin_dir)
    env["VIBEGUARD_BASE"] = "main"
    env["VIBEGUARD_FAIL_ON"] = "critical"
    bash = shutil.which("bash")
    assert bash is not None
    return subprocess.run(
        [bash, str(_HOOK), event],
        cwd=repo,
        input=payload,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_stop_hook_blocks_on_findings_and_fails_closed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_with_main(repo)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _tool_bin(bin_dir)
    record = tmp_path / "argv.json"
    _fake_vibeguard(bin_dir, record, code=1, stdout="critical: app.py:1\n")

    blocked = _run_hook(repo, bin_dir, "stop", json.dumps({"cwd": str(repo)}))
    assert blocked.returncode == 0
    payload = json.loads(blocked.stdout)
    assert payload["decision"] == "block"
    assert "critical: app.py:1" in payload["reason"]
    assert json.loads(record.read_text(encoding="utf-8")) == [
        "scan",
        ".",
        "--quiet",
        "--no-report",
        "--no-cache",
        "--fail-on",
        "critical",
        "--diff",
        "main",
    ]

    _fake_vibeguard(bin_dir, record, code=0, stdout="VIBEGUARD: PASS\n")
    clean = _run_hook(repo, bin_dir, "post-tool")
    assert clean.returncode == 0
    assert clean.stdout.strip() == "{}"
    posted = json.loads(record.read_text(encoding="utf-8"))
    assert "--mode" in posted and "off" in posted
    assert "--diff" in posted

    _fake_vibeguard(bin_dir, record, code=2, stderr="scanner broke\n")
    failed = _run_hook(repo, bin_dir, "stop")
    assert failed.returncode == 2
    assert json.loads(failed.stdout)["decision"] == "block"
    assert "exit 2" in json.loads(failed.stdout)["reason"]

    hidden = tmp_path / "no-cli"
    hidden.mkdir()
    _tool_bin(hidden)
    missing = _run_hook(repo, hidden, "stop")
    assert missing.returncode == 2
    assert json.loads(missing.stdout)["decision"] == "block"
    open_edit = _run_hook(repo, hidden, "post-tool")
    assert open_edit.returncode == 0
    assert open_edit.stdout.strip() == "{}"


def test_init_installs_plugins_and_records_a_local_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "CLAUDE.md").write_text("# Notes\n", encoding="utf-8")
    (tmp_path / ".codex").mkdir()
    monkeypatch.delenv("VIBEGUARD_LOCAL_URL", raising=False)
    monkeypatch.delenv("VIBEGUARD_LOCAL_MODEL", raising=False)
    report = run_init(tmp_path, install_hook=False)
    actions = {action.target: action for action in report.actions}
    claude_installed = _plugin_installed(
        actions[".claude/plugins/vibeguard"],
        tmp_path,
        "VIBEGUARD_HOST=claude-code vibeguard",
    )
    _plugin_installed(
        actions[".codex/plugins/vibeguard"],
        tmp_path,
        "VIBEGUARD_HOST=codex vibeguard",
    )
    again = run_init(tmp_path, install_hook=False)
    again_status = {action.target: action.status for action in again.actions}
    assert again_status[".claude/plugins/vibeguard"] == ("up_to_date" if claude_installed else "skipped")
    assert again_status[".codex/plugins/vibeguard"] == "up_to_date"

    with serve(Bench([{"id": "qwen2.5-coder"}])) as httpd:
        url = base_url(httpd)
        monkeypatch.setenv("VIBEGUARD_LOCAL_URL", url)
        recorded = tmp_path / "with-local"
        recorded.mkdir()
        config = recorded / ".vibeguard" / "config.json"
        config.parent.mkdir()
        config.write_text('{"keep": true}\n', encoding="utf-8")
        local_report = run_init(recorded, install_hook=False)
        saved = json.loads(config.read_text(encoding="utf-8"))
    assert saved["keep"] is True
    assert saved["local"] == {"url": url, "model": "qwen2.5-coder"}
    assert any(action.target == ".vibeguard/config.json" and action.status == "updated" for action in local_report.actions)


def _plugin_installed(action, root: Path, needle: str) -> bool:
    if action.status == "created":
        skill = root / action.target / "skills" / "start" / "SKILL.md"
        assert needle in skill.read_text(encoding="utf-8")
        hook = root / action.target / "hooks" / "vibeguard-hook.sh"
        if hook.is_file():
            assert hook.stat().st_mode & stat.S_IXUSR
        return True
    assert action.status == "skipped"
    assert "not permitted" in action.detail
    return False
