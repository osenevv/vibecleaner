from __future__ import annotations

from pathlib import Path

from archive.notes import save_note


def test_missing_parent_is_created(tmp_path: Path) -> None:
    dest = save_note(tmp_path / "box", "n1.txt", "hello")
    assert dest.read_text(encoding="utf-8") == "hello"


def test_valid_input_overwrites_a_file(tmp_path: Path) -> None:
    folder = tmp_path / "box"
    folder.mkdir()
    (folder / "n1.txt").write_text("old", encoding="utf-8")
    dest = save_note(folder, "n1.txt", "hello")
    assert dest.read_text(encoding="utf-8") == "hello"
