"""Content-addressed cache for Layer 2 decision scores."""

from __future__ import annotations

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]
import hashlib
import json
import logging
import math
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from vibecleaner.models import (
    LAYER2_RULE_IDS,
    RULES,
    SEVERITY_QUESTION_CRITERIA,
    CodeUnit,
)
MODULE_RISK = "module_risk"

log = logging.getLogger(__name__)

CACHE_VERSION = 1
GEMINI_MODEL = "gemini-decision-1"
OFFLINE_MODEL = "offline-heuristic"


@dataclass
class ChunkVerdict:
    scores: dict[str, dict[str, float]]
    severity: dict[str, float]
    input_tokens: int


def question_set_version(model: str) -> str:
    """Short hash of the Layer 2 question text plus the backend model id.

    Editing a question or switching backends changes the hash, so stale scores
    cannot be reused.
    """
    hasher = hashlib.sha256()
    hasher.update(model.encode("utf-8"))
    hasher.update(b"\0")
    if model == OFFLINE_MODEL:
        from vibecleaner.offline_heuristics import OFFLINE_HEURISTIC_VERSION

        hasher.update(str(OFFLINE_HEURISTIC_VERSION).encode("utf-8"))
        hasher.update(b"\0")
    for rule_id in LAYER2_RULE_IDS:
        spec = RULES[rule_id]
        for part in (spec.question, spec.true_description, spec.false_description):
            hasher.update((part or "").encode("utf-8"))
            hasher.update(b"\0")
    for line in SEVERITY_QUESTION_CRITERIA:
        hasher.update(line.encode("utf-8"))
        hasher.update(b"\0")
    return hasher.hexdigest()[:16]


def cache_key(model: str, unit: CodeUnit, auth_context: str) -> str:
    material = question_set_version(model) + unit.content_hash(auth_context)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class DecisionCache:
    """SHA-256 cache of rule_id -> noul, persisted at ``path``.

    Entries are namespaced by backend model name (``gemini-decision-1`` vs
    ``offline-heuristic``) so offline scores are never served as live ones.
    """

    def __init__(self, path: Path, enabled: bool = True, model: str = GEMINI_MODEL) -> None:
        self.path = Path(path)
        self.enabled = enabled
        self.model = model
        self._hits = 0
        self._dirty = False
        self._entries: dict[str, dict[str, object]] = {}
        if self.enabled:
            self._load()

    @property
    def hits(self) -> int:
        return self._hits

    def get(self, unit: CodeUnit, auth_context: str) -> dict[str, float] | None:
        if not self.enabled:
            return None
        key = cache_key(self.model, unit, auth_context)
        entry = self._entries.get(key)
        if entry is None:
            return None
        scores = _scores_for_model(entry, self.model)
        if scores is None:
            if isinstance(entry, dict) and entry.get("model") == self.model:
                log.warning(
                    "Ignoring invalid decision cache entry %s: every Layer-2 score must be a finite float in [0, 1]",
                    key[:12],
                )
            return None
        self._hits += 1
        return scores

    def module_risk(self, unit: CodeUnit, auth_context: str) -> float | None:
        if not self.enabled:
            return None
        entry = self._entries.get(cache_key(self.model, unit, auth_context))
        if not isinstance(entry, dict) or entry.get("model") != self.model:
            return None
        return _bounded_risk(entry.get(MODULE_RISK))

    def put(
        self,
        unit: CodeUnit,
        auth_context: str,
        scores: dict[str, float],
        module_risk: float | None = None,
    ) -> None:
        if not self.enabled:
            return
        stored = _validated_scores(scores)
        if stored is None:
            log.warning("Refusing to cache Layer-2 scores that are not finite floats in [0, 1]")
            return
        key = cache_key(self.model, unit, auth_context)
        entry: dict[str, object] = {"scores": stored, "model": self.model}
        risk = _bounded_risk(module_risk)
        if risk is not None:
            entry[MODULE_RISK] = risk
        if self._entries.get(key) == entry:
            return
        self._entries[key] = entry
        self._dirty = True

    def save(self) -> None:
        if not self.enabled or not self._dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(self.path.name + ".lock")
        with lock_path.open("a+", encoding="utf-8") as lock:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                self._merge_disk_entries()
                self._write_atomic()
            finally:
                if fcntl is not None:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        self._dirty = False

    def _write_atomic(self) -> None:
        payload = {"version": CACHE_VERSION, "entries": self._entries}
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(
            prefix=".vibecleaner_cache.",
            suffix=".tmp",
            dir=self.path.parent,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            log.warning("Ignoring unreadable decision cache %s: %s", self.path, exc)
            self._entries = {}
            return
        if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
            log.warning(
                "Ignoring decision cache %s with unsupported version %r",
                self.path,
                data.get("version") if isinstance(data, dict) else type(data).__name__,
            )
            self._entries = {}
            return
        raw_entries = data.get("entries", {})
        if not isinstance(raw_entries, dict):
            log.warning("Ignoring decision cache %s: entries is not an object", self.path)
            self._entries = {}
            return
        cleaned, dropped = _collect_entries(raw_entries)
        if dropped:
            log.warning("Dropped %s invalid cache entries in %s", dropped, self.path)
            # A later save rewrites the file without the rejected entries.
            self._dirty = True
        self._entries = cleaned

    def _merge_disk_entries(self) -> None:
        """Keep keys another process stored after this cache was loaded.

        Called only while the cache lock is held. Keys already in memory win,
        because they are the scores this process just computed.
        """
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            log.warning("Not merging unreadable decision cache %s: %s", self.path, exc)
            return
        if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
            return
        raw_entries = data.get("entries", {})
        if not isinstance(raw_entries, dict):
            return
        disk_entries, _dropped = _collect_entries(raw_entries)
        for key, entry in disk_entries.items():
            self._entries.setdefault(key, entry)


def _collect_entries(raw_entries: dict[object, object]) -> tuple[dict[str, dict[str, object]], int]:
    cleaned: dict[str, dict[str, object]] = {}
    dropped = 0
    for key, entry in raw_entries.items():
        parsed = _parse_entry(entry)
        if parsed is None:
            dropped += 1
            continue
        cleaned[str(key)] = parsed
    return cleaned, dropped


def _parse_entry(entry: object) -> dict[str, object] | None:
    if not isinstance(entry, dict):
        return None
    model = entry.get("model")
    if not isinstance(model, str):
        return None
    scores = _validated_scores(entry.get("scores"))
    if scores is None:
        return None
    parsed: dict[str, object] = {"scores": scores, "model": model}
    risk = _bounded_risk(entry.get(MODULE_RISK))
    if risk is not None:
        parsed[MODULE_RISK] = risk
    return parsed


def _scores_for_model(entry: object, model: str) -> dict[str, float] | None:
    if not isinstance(entry, dict) or entry.get("model") != model:
        return None
    return _validated_scores(entry.get("scores"))


def _validated_scores(scores: object) -> dict[str, float] | None:
    """Accept an entry only when every Layer-2 rule id is a finite probability."""
    if not isinstance(scores, dict):
        return None
    out: dict[str, float] = {}
    for rule_id in LAYER2_RULE_IDS:
        if rule_id not in scores:
            return None
        number = _unit_interval(scores[rule_id])
        if number is None:
            return None
        out[rule_id] = number
    return out


def _finite_number(value: object) -> float | None:
    """Finite float from an int or float. Bool, nan, and inf are rejected."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def _closed_range(value: object, upper: float) -> float | None:
    number = _finite_number(value)
    if number is None or not 0.0 <= number <= upper:
        return None
    return number


def _unit_interval(value: object) -> float | None:
    return _closed_range(value, 1.0)


def _bounded_risk(value: object) -> float | None:
    """Keep a severity-question score only when it lies on the 0..2 rubric."""
    return _closed_range(value, 2.0)
