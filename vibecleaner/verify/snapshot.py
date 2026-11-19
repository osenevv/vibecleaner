"""Snapshot of tests, config, and public signatures taken before a fix."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from vibecleaner.verify.files import is_code_path, is_config_path, is_test_path, iter_files, read_text
from vibecleaner.verify.signatures import signature_index


@dataclass(frozen=True)
class TamperSnapshot:
    tests: Mapping[str, str]
    configs: Mapping[str, str]
    sources: Mapping[str, str]
    signatures: Mapping[str, str]


def snapshot(tree: Path) -> TamperSnapshot:
    root = Path(tree)
    tests: dict[str, str] = {}
    configs: dict[str, str] = {}
    sources: dict[str, str] = {}
    signatures: dict[str, str] = {}
    if not root.is_dir():
        return _freeze(tests, configs, sources, signatures)
    for rel, path in iter_files(root):
        text = read_text(path)
        if text is None:
            continue
        if is_test_path(rel):
            tests[rel] = text
            continue
        if is_config_path(rel):
            configs[rel] = text
            continue
        if not is_code_path(rel):
            continue
        sources[rel] = text
        for key, (encoded, _line) in signature_index(rel, text).items():
            signatures[key] = encoded
    return _freeze(tests, configs, sources, signatures)


def _freeze(
    tests: dict[str, str],
    configs: dict[str, str],
    sources: dict[str, str],
    signatures: dict[str, str],
) -> TamperSnapshot:
    return TamperSnapshot(
        tests=MappingProxyType(tests),
        configs=MappingProxyType(configs),
        sources=MappingProxyType(sources),
        signatures=MappingProxyType(signatures),
    )
