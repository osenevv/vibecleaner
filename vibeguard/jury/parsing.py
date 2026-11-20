"""Extract JSON objects from model replies."""

from __future__ import annotations

import json
import logging
import re

log = logging.getLogger("vibeguard.jury")

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def parse_model_json(text: str) -> object | None:
    body = text.strip()
    fenced = _FENCE.search(body)
    if fenced is not None:
        body = fenced.group(1).strip()
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        pass
    start_object = body.find("{")
    start_array = body.find("[")
    starts = [index for index in (start_object, start_array) if index >= 0]
    if not starts:
        log.warning("model reply had no JSON")
        return None
    start = min(starts)
    opener = body[start]
    closer = "}" if opener == "{" else "]"
    end = body.rfind(closer)
    if end <= start:
        log.warning("model reply had an unfinished JSON value")
        return None
    try:
        return json.loads(body[start : end + 1])
    except json.JSONDecodeError as exc:
        log.warning("model reply was not JSON: %s", exc)
        return None
