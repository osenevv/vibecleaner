"""Tests that mock a module this repository actually contains."""

from __future__ import annotations

from pathlib import PurePosixPath

from vibecleaner.deslop import _is_test_path
from vibecleaner.models import Finding, SourceFile
from vibecleaner.verify.checks import _mock_sites

__all__ = ["production_mocks"]


def production_mocks(files: list[SourceFile]) -> list[Finding]:
    """Return one finding per test that patches a production module in this tree.

    A mock of a third-party library is left alone. A mock of a module that
    lives in the tree is the test checking its own substitute.
    """
    sources = {source.path: source.text for source in files}
    production = _production_names(sources)
    found: list[Finding] = []
    for source in files:
        if not _is_test_path(source.path):
            continue
        for target, line in _mock_sites(source.path, source.text, sources):
            if not _targets_production(target, production):
                continue
            found.append(
                Finding(
                    rule_id="D9.mocked_production",
                    file=source.path,
                    line=line,
                    message=f"Test mocks production module {target}",
                    symbol=target,
                    snippet=target,
                )
            )
    return found


def _production_names(sources: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for path in sources:
        if _is_test_path(path):
            continue
        pure = PurePosixPath(path)
        if pure.suffix.lower() not in {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}:
            continue
        names.add(pure.stem)
        names.add(_dotted(pure))
    names.discard("__init__")
    return {name for name in names if name}


def _dotted(path: PurePosixPath) -> str:
    parts = list(path.with_suffix("").parts)
    if parts and parts[0] in {"src", "lib"}:
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _targets_production(target: str, production: set[str]) -> bool:
    if target in production:
        return True
    parts = target.replace("/", ".").split(".")
    return any(".".join(parts[:end]) in production for end in range(len(parts), 0, -1))
