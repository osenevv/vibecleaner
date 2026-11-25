"""Lexical LLM-prose tells in reader-facing docs.

Combines high-precision deterministic rules from declauding, stop-slop,
no-ai-slop, and anti-slop copywriting while skipping ordinary technical writing
(bold-label lists, "X, not Y", Title Case, short paragraphs, and code spans).
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from vibecleaner.models import Finding, SourceFile

_PROSE_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".html", ".htm"})
_SKIP_NAMES = frozenset(
    {
        "changelog.md",
        "changelog.mdx",
        "changelog.rst",
        "history.md",
        "news.md",
        "news.rst",
        "license.md",
        "licence.md",
        "copying.md",
        "papercuts.md",
    }
)

# (category, pattern, note). Case-insensitive. Patterns are the declauding
# rules that name a construction, narrowed where that file's own notes say the
# wider form walks over human technical prose.
_RULES: tuple[tuple[str, str, str], ...] = (
    ("chatbot", r"\b(?:great|excellent|good)\s+question\b", "chatbot residue"),
    ("chatbot", r"\byou'?re\s+absolutely\s+right\b", "chatbot residue"),
    ("chatbot", r"\bI\s+hope\s+this\s+helps\b", "chatbot residue"),
    ("chatbot", r"\blet\s+me\s+know\s+if\s+you'?d\b", "chatbot residue"),
    ("chatbot", r"\b(?:would|do)\s+you\s+(?:like|want)\s+me\s+to\b", "chatbot residue"),
    ("chatbot", r"\bwant\s+me\s+to\s+(?:give|show|expand|continue|explain)\b", "chatbot residue"),
    ("chatbot", r"\b(?:should|shall)\s+I\s+continue\b", "chatbot residue"),
    ("chatbot", r"^\s*(?:Certainly|Of course|Absolutely)[!,]", "chatbot residue"),
    ("chatbot", r"\bhere\s+is\s+an\s+overview\s+of\b", "chatbot residue"),
    ("gap-fill", r"\bas\s+of\s+my\s+last\s+(?:update|training)\b", "knowledge-cutoff disclaimer"),
    ("gap-fill", r"\bit\s+is\s+believed\s+that\b", "unsourced guess"),
    ("gap-fill", r"\bbased\s+on\s+(?:the\s+)?available\s+information\b", "meta-sentence about the search, not the subject"),
    ("gap-fill", r"\bmaintains?\s+a\s+low\s+profile\b", "stock filler for an absent source"),
    ("gap-fill", r"\bdetails\s+(?:about|are)[^.]{0,50}\b(?:limited|scarce|not\s+extensively)\b", "meta-sentence about the search"),
    ("throat-clearing", r"\b(?:in this (?:post|article|piece),?\s*(?:I|we)'?ll|I want to talk about|let me explain|first,? some background|before I get into)\b", "preamble"),
    ("throat-clearing", r"\b(?:let me|I'?ll)\s+(?:consult|check|search|pull up|recall)\s+my\b", "AI self-narration"),
    (
        "slop",
        r"\b(?:delve|tapestry|testament to|navigate the complexities|in today'?s fast[- ]paced|realm of|seamless|plethora|myriad|unlock the|harness the|embark|dive deep|at the end of the day|game[- ]changer|cutting[- ]edge|paradigm\s+shift|ever[- ]evolving|supercharge|multifaceted|next[- ]level|this\s+changes\s+everything)\b",
        "slop vocabulary",
    ),
    (
        "puffery",
        r"\b(?:ushering\s+in\s+a\s+new\s+era|marks?\s+a\s+pivotal\s+moment|plays?\s+a\s+vital\s+role|solidif(?:y|ies)\s+(?:its|their)\s+position|underscores?\s+(?:its|their)\s+significance)\b",
        "significance inflation",
    ),
    (
        "crutch",
        r"\b(?:let\s+that\s+sink\s+in|make\s+no\s+mistake|here'?s\s+why\s+that\s+matters|the\s+uncomfortable\s+truth\s+is|what\s+most\s+people\s+get\s+wrong|here'?s\s+what\s+nobody\s+tells\s+you|the\s+part\s+everyone\s+misses|without\s+further\s+ado|let'?s\s+dive\s+in(?:to)?)\b",
        "emphasis crutch or faux-insight setup",
    ),
    (
        "runway",
        r"\b(?:in\s+today'?s\s+(?:ever[- ]evolving|digital|modern|rapidly\s+changing)\s+(?:world|landscape|era)|in\s+an\s+era\s+of\s+rapid)\b",
        "temporal runway cliché",
    ),
    (
        "weasel",
        r"\b(?:(?:experts|analysts)\s+agree|industry\s+(?:reports|observers)\s+(?:suggest|believe)|widely\s+regarded\s+as|trusted\s+by\s+thousands\s+of\s+teams|loved\s+by\s+customers\s+everywhere)\b",
        "unsourced weasel attribution",
    ),
    (
        "meta",
        r"(?:^\s*(?:plot\s+twist|spoiler\s+alert|real\s+talk)\s*:|\b(?:let\s+me\s+walk\s+you\s+through|in\s+this\s+section,?\s*we'?ll)\b)",
        "meta-commentary or theatrical pause",
    ),
    ("filler", r"\bdue\s+to\s+the\s+fact\s+that\b", "due to the fact that — use because"),
    ("filler", r"\bat\s+this\s+point\s+in\s+time\b", "at this point in time — use now"),
    ("filler", r"\bin\s+the\s+event\s+that\b", "in the event that — use if"),
    ("filler", r"\bhas\s+the\s+ability\s+to\b", "has the ability to — use can"),
    ("filler", r"\bit\s+is\s+important\s+to\s+note\s+that\b", "delete the frame, keep the claim"),
    ("filler", r"\b(?:could|might|may|can)\s+(?:potentially|possibly|arguably|conceivably)\b", "stacked hedges — one carries the uncertainty"),
    ("significance", r"\b(?:here'?s|this is)\s+(?:the thing|where it gets interesting)\b", "here's the thing"),
    ("significance", r"\bhere(?:'?s|\s+is)\s+(?:the|a|my|one)\s+(?:twist|catch|kicker|rub)\b", "staged reveal"),
    ("significance", r"\b(?:that|this|it)(?:'?s|\s+(?:is|was))\s+the\s+part\b", "that's the part"),
    ("significance", r"\bmy\s+favou?rite\s+part\s+of\b", "gesturing at a favoured detail instead of stating it"),
    ("staging", r"\b(?:but\s+)?here'?s\s+where\s+it\s+gets\b", "here's where it gets"),
    ("staging", r"\bthis\s+is\s+the\s+story\s+of\b", "trailer opener"),
    ("staging", r"\bwhat\s+(?:I|we|you)\s+(?:didn't|did not)\s+(?:realize|know|expect)\b", "movie-trailer voiceover"),
    ("copula", r"\b(?:serves?|stands?|acts?)\s+as\s+(?:a|an|the)\b", "serves as — use is"),
    ("copula", r"\bboasts?\s+(?:a|an|the|over|more than|some|\d)", "boasts — use has"),
    ("self-grading", r"\b(?:it'?s|it is)\s+(?:worth|important)\s+(?:noting|mentioning|pointing out)\b", "worth noting"),
    ("self-grading", r"\b(?:that|this)\s+is\s+what\s+the\s+(?:data|numbers?|table|evidence)\s+shows?\b", "that is what the data shows"),
    ("candour", r"\bI\s+(?:will\s+not|won'?t)\s+pretend\b", "announced sincerity"),
    ("candour", r"\b(?:I'?ll|let'?s|to)\s+be\s+(?:honest|clear|blunt|real)\b", "announced sincerity"),
    ("candour", r"(?:^|[.!?]\s+)(?:honestly|look|truthfully|frankly)\s*,", "confiding opener"),
    ("diff-anchored", r"\b(?:was|were)\s+added\s+to\s+(?:replace|fix|handle|support)\b", "documents the change, not the thing"),
    ("diff-anchored", r"\bthe\s+(?:previous|old|former)\s+(?:approach|implementation|version|behaviour|behavior|method)\b", "documents the change, not the thing"),
    ("diff-anchored", r"\bhas\s+(?:since\s+)?been\s+(?:updated|changed|replaced|refactored)\s+to\b", "documents the change, not the thing"),
    ("diff-anchored", r"\bwe\s+now\s+(?:use|do|call|store|write)\b", "documents the change, not the thing"),
    ("announce", r"^(?:One|Two|Three|Four|A single|The one)\s+[a-z][\w -]{2,30},\s+(?:not|un\w+|left|stated|worth|flagged|still|so far)\b", "counted label announcing the content it precedes"),
    ("rtfm", r"\b(?:hidden|buried)\s+in\s+the\s+(?:docs|documentation|api|source)\b", "RTFM as revelation"),
    ("aphorism", r"\bthe\s+kind\s+of\s+\w+\s+that\b[^.]{0,60}\band\s+is\s+not\b", "X that looks like Y and is not"),
)

_COMPILED = tuple((cat, re.compile(pat, re.I | re.M), note) for cat, pat, note in _RULES)
_FENCE = re.compile(r"```.*?```", re.S)
_INLINE_CODE = re.compile(r"`[^`\n]+`")
_HTML_SKIP = re.compile(r"<(script|style|pre|code)\b.*?</\1>", re.S | re.I)
_HTML_TAG = re.compile(r"<[^>]+>")


def detect_prose_tics(source: SourceFile) -> list[Finding]:
    """Flag declauding tells in a reader-facing doc. Code and changelogs are skipped."""
    if not _is_prose(source.path):
        return []
    text = _visible(source.text, source.path)
    findings: list[Finding] = []
    seen: set[int] = set()
    for index, line in enumerate(text.splitlines(), start=1):
        if index in seen or not line.strip():
            continue
        for category, pattern, note in _COMPILED:
            match = pattern.search(line)
            if match is None:
                continue
            seen.add(index)
            findings.append(
                Finding(
                    rule_id="D6c.llm_prose",
                    file=source.path,
                    line=index,
                    message=f"LLM prose tic ({category}): {note}",
                    snippet=match.group(0).strip()[:120],
                )
            )
            break
    return findings


def _is_prose(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.suffix.lower() not in _PROSE_SUFFIXES:
        return False
    if pure.name.lower() in _SKIP_NAMES:
        return False
    return "changelog" not in {part.lower() for part in pure.parts}


def _visible(text: str, path: str) -> str:
    """Drop fenced and inline code, and tags in HTML, without moving line numbers."""
    text = _blank_spans(_FENCE, text)
    if PurePosixPath(path).suffix.lower() in {".html", ".htm"}:
        text = _blank_spans(_HTML_SKIP, text)
        text = "\n".join(_HTML_TAG.sub(" ", line) for line in text.splitlines())
    return _blank_spans(_INLINE_CODE, text)


def _blank_spans(pattern: re.Pattern[str], text: str) -> str:
    def blank(match: re.Match[str]) -> str:
        return "\n" * match.group(0).count("\n")

    return pattern.sub(blank, text)
