"""Read-only view of the scanned files and the findings the caller already computed."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from vibecleaner.models import Finding, ScanContext, SourceFile
from vibecleaner.preflight.code_text import (
    code_only_text,
    comments_blanked,
    is_blankable,
    is_data_config_path,
    is_markup_path,
    is_prose_path,
    is_sql_path,
)
from vibecleaner.preflight.patterns import _ENV_EXAMPLES, _STRING_LIT
from vibecleaner.preflight.results import _uniq

__all__ = ["_code_text", "_is_env_file", "_is_example_env", "_is_prose_path", "_strip_strings"]


def _is_comment(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if stripped.startswith(("#", "//", "--", "/*", "<!--")):
        return True
    if stripped.startswith("* ") or stripped == "*/" or stripped.startswith("*/"):
        return True
    return False


def _is_prose_path(path: str) -> bool:
    return is_prose_path(path)


def _is_scannable_source(source: SourceFile) -> bool:
    name = PurePosixPath(source.path).name
    if name == ".gitignore" or name.lower() == "robots.txt":
        return True
    return _is_usage_source(source)


def _is_usage_source(source: SourceFile) -> bool:
    if _is_prose_path(source.path):
        return False
    return (
        is_blankable(source)
        or is_sql_path(source.path)
        or is_data_config_path(source.path)
        or is_markup_path(source.path)
    )


def _is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    parts = set(pure.parts)
    if parts & {"tests", "test", "__tests__", "spec"}:
        return True
    name = pure.name
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    if ".test." in name or ".spec." in name:
        return True
    return False


def _is_config_path(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if name.startswith(".env"):
        return True
    if name in {
        "settings.py",
        "config.py",
        "config.ts",
        "config.js",
        "next.config.js",
        "next.config.ts",
        "next.config.mjs",
        "docker-compose.yml",
        "docker-compose.yaml",
        "dockerfile",
    }:
        return True
    return name.endswith((".config.js", ".config.ts", ".config.mjs", ".config.cjs"))


def _is_example_env(path: str) -> bool:
    return PurePosixPath(path).name in _ENV_EXAMPLES


def _is_env_file(path: str) -> bool:
    name = PurePosixPath(path).name
    if name in _ENV_EXAMPLES:
        return False
    return name == ".env" or name.startswith(".env.")


def _code_text(source: SourceFile) -> str:
    if is_blankable(source) or is_sql_path(source.path):
        return comments_blanked(source)
    kept: list[str] = []
    for line in source.text.splitlines():
        kept.append("" if _is_comment(line) else line)
    return "\n".join(kept)


def _strip_strings(line: str) -> str:
    return _STRING_LIT.sub("''", line)


class RepoView:
    """Read-only scan plus the findings the caller already computed."""

    def __init__(self, ctx: ScanContext, findings: list[Finding]) -> None:
        self.ctx = ctx
        self.findings = list(findings)
        self.files = list(ctx.files)
        self._code_only: dict[int, str] = {}
        self._comments_blanked: dict[int, str] = {}

    def root_dir(self) -> Path | None:
        try:
            root = self.ctx.root
            if root.is_dir():
                return root
        except OSError:
            return None
        return None

    def comments_only_blanked(self, source: SourceFile) -> str:
        cached = self._comments_blanked.get(id(source))
        if cached is None:
            cached = (
                comments_blanked(source)
                if is_blankable(source) or is_sql_path(source.path)
                else source.text
            )
            self._comments_blanked[id(source)] = cached
        return cached

    def iter_lines(
        self,
        *,
        skip_tests: bool = False,
        skip_config: bool = False,
        suffixes: frozenset[str] | None = None,
        blank_comments: bool = True,
    ) -> Iterator[tuple[str, int, str]]:
        for source in self.files:
            if not _is_scannable_source(source):
                continue
            if skip_tests and _is_test_path(source.path):
                continue
            if skip_config and _is_config_path(source.path):
                continue
            if suffixes is not None and PurePosixPath(source.path).suffix.lower() not in suffixes:
                continue
            text = self.comments_only_blanked(source) if blank_comments else source.text
            for number, line in enumerate(text.splitlines(), start=1):
                yield source.path, number, line

    def code_only(self, source: SourceFile) -> str:
        cached = self._code_only.get(id(source))
        if cached is None:
            cached = code_only_text(source)
            self._code_only[id(source)] = cached
        return cached

    def iter_usage_lines(
        self,
        *,
        skip_tests: bool = False,
        skip_config: bool = False,
        suffixes: frozenset[str] | None = None,
    ) -> Iterator[tuple[str, int, str]]:
        """Lines used for code-usage checks. String contents in code files are blank."""
        for source in self.files:
            if not _is_usage_source(source):
                continue
            if skip_tests and _is_test_path(source.path):
                continue
            if skip_config and _is_config_path(source.path):
                continue
            if suffixes is not None and PurePosixPath(source.path).suffix.lower() not in suffixes:
                continue
            text = self.code_only(source) if is_blankable(source) else source.text
            for number, line in enumerate(text.splitlines(), start=1):
                yield source.path, number, line

    def search_usage(
        self,
        pattern: re.Pattern[str],
        *,
        skip_tests: bool = False,
        skip_config: bool = False,
        suffixes: frozenset[str] | None = None,
        limit: int = 30,
    ) -> list[str]:
        found: list[str] = []
        for path, number, line in self.iter_usage_lines(
            skip_tests=skip_tests, skip_config=skip_config, suffixes=suffixes
        ):
            if _is_comment(line):
                continue
            if pattern.search(line):
                found.append(f"{path}:{number}")
                if len(found) >= limit:
                    break
        return _uniq(found)

    def search(
        self,
        pattern: re.Pattern[str],
        *,
        skip_tests: bool = False,
        skip_config: bool = False,
        suffixes: frozenset[str] | None = None,
        skip_comments: bool = True,
        limit: int = 30,
    ) -> list[str]:
        found: list[str] = []
        for path, number, line in self.iter_lines(
            skip_tests=skip_tests,
            skip_config=skip_config,
            suffixes=suffixes,
            blank_comments=skip_comments,
        ):
            if skip_comments and _is_comment(line):
                continue
            if pattern.search(line):
                found.append(f"{path}:{number}")
                if len(found) >= limit:
                    break
        return _uniq(found)

    def first(
        self,
        pattern: re.Pattern[str],
        *,
        skip_tests: bool = False,
        skip_config: bool = False,
    ) -> str | None:
        hits = self.search(pattern, skip_tests=skip_tests, skip_config=skip_config, limit=1)
        return hits[0] if hits else None

    def blob(self, *, skip_tests: bool = False) -> str:
        parts: list[str] = []
        for source in self.files:
            if not _is_scannable_source(source):
                continue
            if skip_tests and _is_test_path(source.path):
                continue
            parts.append(self.comments_only_blanked(source))
        return "\n".join(parts)

    def usage_blob(self, *, skip_tests: bool = False) -> str:
        parts: list[str] = []
        for source in self.files:
            if not _is_scannable_source(source):
                continue
            if skip_tests and _is_test_path(source.path):
                continue
            if is_blankable(source):
                parts.append(self.code_only(source))
            elif is_sql_path(source.path):
                parts.append(self.comments_only_blanked(source))
            else:
                parts.append(source.text)
        return "\n".join(parts)

    def locs_for(self, rule_ids: frozenset[str]) -> list[str]:
        return _uniq(
            f"{item.file}:{item.line}" for item in self.findings if item.rule_id in rule_ids
        )

    def named(self, names: frozenset[str]) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for source in self.files:
            name = PurePosixPath(source.path).name
            if name in names and name not in seen:
                seen.add(name)
                found.append(source.path)
        root = self.root_dir()
        if root is None:
            return found
        for name in sorted(names):
            if name in seen:
                continue
            try:
                if (root / name).is_file():
                    found.append(name)
            except OSError:
                continue
        return found
