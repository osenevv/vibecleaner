from __future__ import annotations

from pathlib import Path

import pytest

from archive.notes import save_note


def test_parent_that_is_a_file_raises(tmp_path: Path) -> None:
    blocker = tmp_path / "box"
    blocker.write_text("not a directory", encoding="utf-8")
    with pytest.raises(OSError):
        save_note(blocker, "n1.txt", "hello")


def test_empty_body_is_stored(tmp_path: Path) -> None:
    dest = save_note(tmp_path / "box", "n1.txt", "")
    assert dest.is_file()
    assert dest.read_text(encoding="utf-8") == ""
