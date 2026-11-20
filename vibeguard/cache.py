"""Content-addressed cache for Layer 2 decision scores."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import tempfile
from pathlib import Path

from vibeguard.models import (
    LAYER2_RULE_IDS,
    RULES,
    SEVERITY_QUESTION_CRITERIA,
    CodeUnit,
)

log = logging.getLogger(__name__)

CACHE_VERSION = 1
GEMINI_MODEL = "gemini-decision-1"
OFFLINE_MODEL = "offline-heuristic"


def question_set_version(model: str) -> str:
    """Short hash of the Layer 2 question text plus the backend model id.

    Editing a question or switching backends changes the hash, so stale scores
    cannot be reused.
    """
    hasher = hashlib.sha256()
    hasher.update(model.encode("utf-8"))
    hasher.update(b"\0")
    if model == OFFLINE_MODEL:
        from vibeguard.offline_heuristics import OFFLINE_HEURISTIC_VERSION

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
        self._misses = 0
        self._dirty = False
        self._entries: dict[str, dict[str, object]] = {}
        if self.enabled:
            self._load()

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    def get(self, unit: CodeUnit, auth_context: str) -> dict[str, float] | None:
        if not self.enabled:
            return None
        key = cache_key(self.model, unit, auth_context)
        entry = self._entries.get(key)
        if entry is None:
            self._misses += 1
            return None
        scores = _scores_for_model(entry, self.model)
        if scores is None:
            self._misses += 1
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
        return _optional_risk(entry.get("module_risk"))

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
        risk = _optional_risk(module_risk)
        if risk is not None:
            entry["module_risk"] = risk
        if self._entries.get(key) == entry:
            return
        self._entries[key] = entry
        self._dirty = True

    def save(self) -> None:
        if not self.enabled or not self._dirty:
            return
        payload = {"version": CACHE_VERSION, "entries": self._entries}
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".vibeguard_cache.",
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
        self._dirty = False

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
        cleaned: dict[str, dict[str, object]] = {}
        dropped = 0
        for key, entry in raw_entries.items():
            parsed = _parse_entry(entry)
            if parsed is None:
                dropped += 1
                continue
            cleaned[str(key)] = parsed
        if dropped:
            log.warning("Dropped %s unreadable cache entries in %s", dropped, self.path)
        self._entries = cleaned


def _parse_entry(entry: object) -> dict[str, object] | None:
    if not isinstance(entry, dict):
        return None
    model = entry.get("model")
    scores = entry.get("scores")
    if not isinstance(model, str) or not isinstance(scores, dict) or not scores:
        return None
    try:
        parsed = {str(rule_id): float(value) for rule_id, value in scores.items()}
    except (TypeError, ValueError):
        return None
    return {"scores": parsed, "model": model}


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


def _unit_interval(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        return None
    return number


def _optional_risk(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number
