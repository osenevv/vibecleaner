"""The runtime check skips a library and does not pass a detected server."""

from pathlib import Path

from vibeguard.fix_contract import FixContext, Team, Verdict
from vibeguard.runtime import runtime_check
from vibeguard.verify.sandbox import HostSandbox


def _ctx(root: Path) -> FixContext:
    return FixContext(root=root, sandbox=HostSandbox(root), team=Team(host=None))


def test_library_passes(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("library\n", encoding="utf-8")
    result = runtime_check(_ctx(tmp_path), tmp_path)
    assert result.verdict is Verdict.PASS
    assert result.notes


def test_detected_server_is_not_a_pass(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"scripts": {"dev": "next dev"}}\n',
        encoding="utf-8",
    )
    result = runtime_check(_ctx(tmp_path), tmp_path)
    assert result.verdict is Verdict.ESCALATE
    assert "next" in result.notes[0].summary
