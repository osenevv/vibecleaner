"""PATH commands that start on Windows and on Unix."""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path


def install_path_command(directory: Path, name: str, python_source: str) -> None:
    """Install ``name`` on ``directory`` so ``subprocess`` can run the Python source."""
    directory.mkdir(parents=True, exist_ok=True)
    program = directory / f"{name}-impl.py"
    program.write_text(python_source, encoding="utf-8")
    if os.name == "nt":
        launcher = directory / f"{name}.cmd"
        launcher.write_text(
            f'@echo off\r\n"{sys.executable}" "{program}" %*\r\n',
            encoding="utf-8",
        )
        return
    launcher = directory / name
    launcher.write_text(f"#!{sys.executable}\n{python_source}", encoding="utf-8")
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def find_bash() -> str:
    """bash on PATH, or Git for Windows when the runner does not put it on PATH."""
    found = shutil.which("bash")
    if found:
        return found
    for candidate in (
        Path(r"C:\Program Files\Git\bin\bash.exe"),
        Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
    ):
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError("bash")


def assert_user_executable(path: Path) -> None:
    """The file exists. Unix also keeps the user execute bit; Windows does not."""
    assert path.is_file()
    if os.name != "nt":
        assert path.stat().st_mode & stat.S_IXUSR
