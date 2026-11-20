"""Offline tests for Layer 2 judging, cache, reporting, and the CLI."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from gitutil import init_git
from rich.console import Console

from vibeguard.cache import (
    GEMINI_MODEL,
    OFFLINE_MODEL,
    DecisionCache,
    cache_key,
    question_set_version,
)
from vibeguard.cli import main
from vibeguard.decision_judge import (
    ChunkVerdict,
    DecisionAPIError,
    GeminiDecisionBackend,
    build_payload,
    chunk_units,
    estimate_tokens,
    format_module,
    judge,
    select_backend,
    units_to_skip,
)
from vibeguard.offline_heuristics import OFFLINE_HEURISTIC_VERSION, OfflineHeuristicBackend
from vibeguard.models import (
    LAYER2_KEY_SUFFIX,
    LAYER2_RULE_IDS,
    RULES,
    SEVERITY_QUESTION_CRITERIA,
    Category,
    CodeUnit,
    Finding,
    JudgeStats,
    Language,
    ScanContext,
    ScanResult,
)
from vibeguard.patcher import generate_fixes
from vibeguard.pipeline import run_scan
from vibeguard.reporter import (
    compute_scores,
    render_terminal,
    to_json,
    to_markdown,
    to_sarif,
    write_markdown,
    write_sarif,
)

_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _unit(source: str, **overrides: object) -> CodeUnit:
    end = source.count("\n") + (0 if source.endswith("\n") or not source else 1)
    values: dict[str, object] = {
        "file": "app.py",
        "language": Language.PYTHON,
        "name": "handler",
        "kind": "route",
        "start_line": 4,
        "end_line": 4 + max(end - 1, 0),
        "source": source,
        "http_method": "POST",
        "route_path": "/api/orders",
    }
    values.update(overrides)
    return CodeUnit(**values)  # type: ignore[arg-type]


def _ctx(units: list[CodeUnit], auth: str = "", root: Path | None = None) -> ScanContext:
    return ScanContext(
        root=root or Path("."),
        files=[],
        units=units,
        auth_context=auth,
    )


class _RecordingDecisions:
    def __init__(self, responder):
        self.responder = responder
        self.calls = 0
        self.kwargs: list[dict] = []

    async def create(self, *, model, input, questions):
        self.calls += 1
        self.kwargs.append({"model": model, "input": input, "questions": questions})
        return await self.responder(model, input, questions)


def _client(decisions: _RecordingDecisions) -> SimpleNamespace:
    return SimpleNamespace(aio=SimpleNamespace(decisions=decisions))


def _answers_for(questions: dict, auth_noul: float = 0.91, other: float = 0.1, style: str = "attr"):
    answers = {}
    for key, spec in questions.items():
        if spec["type"] == "score":
            payload = {"score": 1.4, "probabilities": {"0": 0.2, "1": 0.2, "2": 0.6}}
        elif key.endswith("__missing_auth"):
            payload = {"noul": auth_noul, "confidence": 0.9}
        else:
            payload = {"noul": other, "confidence": 0.8}
        if style == "attr":
            answers[key] = SimpleNamespace(**payload)
        else:
            answers[key] = payload
    if style == "attr":
        return SimpleNamespace(answers=answers, usage=SimpleNamespace(total_input_tokens=42))
    return {"answers": answers, "usage": {"total_input_tokens": 42}}


class _FixedBackend:
    name = "offline-heuristic"

    def __init__(self, scores: dict[str, float], tokens: int = 0):
        self.scores = scores
        self.calls = 0
        self.tokens = tokens

    async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
        self.calls += 1
        mapped = {unit.unit_id: dict(self.scores) for unit in units}
        return ChunkVerdict(scores=mapped, severity={}, input_tokens=self.tokens)


def test_estimate_tokens_and_format_module() -> None:
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("abc") == 0
    unit = _unit(
        "return 1\n",
        file="app/api/orders/route.ts",
        language=Language.TYPESCRIPT,
        start_line=4,
        end_line=31,
    )
    unit.label = "MOD_03"
    text = format_module(unit)
    assert text.startswith(
        "[MOD_03] file=app/api/orders/route.ts lines=4-31 kind=route method=POST path=/api/orders\n<source>\n"
    )
    assert "<source>\nreturn 1\n\n</source>\n[/MOD_03]" in text


def test_chunk_units_respects_module_cap_and_restarts_labels() -> None:
    units = [_unit(f"def f{i}():\n    return {i}\n", name=f"f{i}", file=f"f{i}.py", start_line=i + 1) for i in range(5)]
    chunks = chunk_units(units, "auth context", max_tokens=10**9, max_modules=2)
    assert [len(chunk) for chunk in chunks] == [2, 2, 1]
    assert [[unit.name for unit in chunk] for chunk in chunks] == [["f0", "f1"], ["f2", "f3"], ["f4"]]
    assert [unit.label for unit in chunks[0]] == ["MOD_01", "MOD_02"]
    assert [unit.label for unit in chunks[1]] == ["MOD_01", "MOD_02"]
    assert chunks[2][0].label == "MOD_01"


def test_chunk_units_token_cap_keeps_oversized_unit() -> None:
    units = [
        _unit("a" * 50, name="a", file="a.py"),
        _unit("b" * 80_000, name="b", file="b.py"),
        _unit("c" * 50, name="c", file="c.py"),
    ]
    chunks = chunk_units(units, "", max_tokens=1, max_modules=30)
    assert [chunk[0].name for chunk in chunks] == ["a", "b", "c"]
    assert all(len(chunk) == 1 and chunk[0].label == "MOD_01" for chunk in chunks)
    assert chunk_units([], "auth") == []


def test_build_payload_question_contract() -> None:
    units = [
        _unit("def create():\n    return 1\n", name="create_order"),
        _unit("export async function POST(){ return 1 }\n", name="post", file="app/api/orders/route.ts", language=Language.TYPESCRIPT, start_line=10),
    ]
    chunk_units(units, "middleware allows /health", max_tokens=10**9, max_modules=10)
    payload = build_payload("middleware allows /health", units)
    assert set(payload) == {"model", "input", "questions"}
    assert payload["model"] == "gemini-decision-1"
    assert payload["input"].startswith("[GLOBAL_AUTH_CONTEXT]\nmiddleware allows /health\n\n")
    assert "def create():" in payload["input"]
    assert "[/MOD_01]" in payload["input"] and "[/MOD_02]" in payload["input"]
    assert len(payload["questions"]) == 7 * len(units)
    for unit in units:
        noul_keys = []
        for rule_id in LAYER2_RULE_IDS:
            key = f"{unit.label}__{LAYER2_KEY_SUFFIX[rule_id]}"
            noul_keys.append(key)
            assert _KEY_RE.fullmatch(key)
            question = payload["questions"][key]
            assert question["type"] == "noul"
            assert question["instructions"] == RULES[rule_id].question.format(module=unit.label)
            assert unit.label in question["instructions"]
            assert question["criteria"]["true_description"] == RULES[rule_id].true_description
            assert question["criteria"]["false_description"] == RULES[rule_id].false_description
        severity_key = f"{unit.label}__severity"
        assert _KEY_RE.fullmatch(severity_key)
        severity = payload["questions"][severity_key]
        assert severity["type"] == "score"
        assert severity["instructions"] == f"Rate the overall production risk of {unit.label}."
        assert severity["criteria"] == list(SEVERITY_QUESTION_CRITERIA)
        assert len(noul_keys) + 1 == 7


def test_gemini_backend_maps_attribute_answers_and_threshold() -> None:
    async def respond(model, model_input, questions):
        return _answers_for(questions, style="attr")

    decisions = _RecordingDecisions(respond)
    backend = GeminiDecisionBackend("test-key", client=_client(decisions), base_delay=0)
    unit = _unit("def create_order():\n    ...\n", name="create_order")
    ctx = _ctx([unit])
    cache = DecisionCache(Path("/tmp/does-not-matter-disabled.json"), enabled=False)
    findings, stats = judge(ctx, backend, cache, threshold=0.75)
    assert decisions.calls == 1
    assert decisions.kwargs[0]["model"] == "gemini-decision-1"
    assert stats.mode == "live"
    assert stats.requests == 1
    assert stats.input_tokens == 42
    assert stats.errors == []
    assert [finding.rule_id for finding in findings] == ["D3.missing_auth"]
    finding = findings[0]
    assert finding.file == "app.py"
    assert finding.line == unit.start_line
    assert finding.end_line == unit.end_line
    assert finding.symbol == "create_order"
    assert finding.probability == pytest.approx(0.91)
    assert finding.module_risk == pytest.approx(1.4)
    assert "Missing authentication on mutating route" in finding.message
    assert "POST" in finding.message and "/api/orders" in finding.message


def test_gemini_retries_429_then_succeeds_and_does_not_retry_400() -> None:
    state = {"calls": 0}

    async def flaky(model, model_input, questions):
        state["calls"] += 1
        if state["calls"] == 1:
            error = RuntimeError("rate limited")
            setattr(error, "status_code", 429)
            raise error
        return _answers_for(questions, style="dict")

    decisions = _RecordingDecisions(flaky)
    backend = GeminiDecisionBackend("k", client=_client(decisions), base_delay=0)
    findings, stats = judge(_ctx([_unit("x = 1\n")]), backend, DecisionCache(Path("unused"), enabled=False))
    assert state["calls"] == 2
    assert findings and findings[0].rule_id == "D3.missing_auth"
    assert stats.errors == []

    class _Boom:
        def __init__(self):
            self.calls = 0

        async def create(self, *, model, input, questions):
            self.calls += 1
            error = RuntimeError("safety block")
            setattr(error, "status_code", 400)
            setattr(error, "body", '{"error": {"code": "SAFETY"}}')
            raise error

    boom = _Boom()
    backend = GeminiDecisionBackend("k", client=SimpleNamespace(aio=SimpleNamespace(decisions=boom)), base_delay=0)
    findings, stats = judge(_ctx([_unit("x = 1\n", name="other")]), backend, DecisionCache(Path("unused"), enabled=False))
    assert boom.calls == 1
    assert findings == []
    assert stats.errors
    assert "SAFETY" in stats.errors[0] or "400" in stats.errors[0]


def test_failed_chunk_does_not_drop_the_rest() -> None:
    class _Partial:
        name = "gemini-decision-1"

        async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
            if any(unit.name == "bad" for unit in units):
                raise DecisionAPIError("chunk exploded")
            scores = {
                unit.unit_id: {rule_id: (0.9 if rule_id == "D3.missing_auth" else 0.05) for rule_id in LAYER2_RULE_IDS}
                for unit in units
            }
            return ChunkVerdict(scores=scores, severity={}, input_tokens=5)

    bad = _unit("z" * 200_000, name="bad", file="bad.py")
    good = _unit("return 1\n", name="good", file="good.py")
    findings, stats = judge(
        _ctx([bad, good]),
        _Partial(),
        DecisionCache(Path("unused"), enabled=False),
    )
    assert [finding.file for finding in findings] == ["good.py"]
    assert stats.requests == 2
    assert stats.input_tokens == 5
    assert any("chunk exploded" in error for error in stats.errors)
    assert stats.mode == "live"


def test_cache_hit_miss_and_source_invalidation(tmp_path: Path) -> None:
    path = tmp_path / ".vibeguard_cache.json"
    cache = DecisionCache(path, model=OFFLINE_MODEL)
    backend = _FixedBackend({rule_id: 0.2 for rule_id in LAYER2_RULE_IDS}, tokens=9)
    unit = _unit("def create():\n    return 1\n", name="create")
    ctx = _ctx([unit])
    findings, stats = judge(ctx, backend, cache, threshold=0.75)
    assert findings == []
    assert backend.calls == 1
    assert stats.cache_hits == 0
    assert stats.units_judged == 1
    cache.save()
    assert path.is_file()
    assert list(tmp_path.glob(".vibeguard_cache.*.tmp")) == []
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["version"] == 1
    entry = next(iter(stored["entries"].values()))
    assert entry["model"] == OFFLINE_MODEL
    assert set(entry["scores"]) == set(LAYER2_RULE_IDS)

    backend.calls = 0
    _findings, stats = judge(ctx, backend, cache, threshold=0.75)
    assert backend.calls == 0
    assert stats.cache_hits == 1
    assert cache.hits >= 1

    reloaded = DecisionCache(path, model=OFFLINE_MODEL)
    backend.calls = 0
    _findings, stats = judge(ctx, backend, reloaded, threshold=0.75)
    assert backend.calls == 0
    assert stats.cache_hits == 1

    original = _unit("def create():\n    return 1\n", name="create")
    unit.source += "\nchanged = True\n"
    backend.calls = 0
    _findings, stats = judge(ctx, backend, reloaded, threshold=0.75)
    assert backend.calls == 1
    assert stats.cache_hits == 0

    isolated = DecisionCache(path, model=GEMINI_MODEL)
    assert isolated.get(original, "") is None
    offline_again = DecisionCache(path, model=OFFLINE_MODEL)
    assert offline_again.get(original, "")["D3.missing_auth"] == pytest.approx(0.2)
    assert cache_key(GEMINI_MODEL, original, "") != cache_key(OFFLINE_MODEL, original, "")
    assert question_set_version(GEMINI_MODEL) != question_set_version(OFFLINE_MODEL)


def test_cache_disabled_corrupt_and_bad_version(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / ".vibeguard_cache.json"
    disabled = DecisionCache(path, enabled=False)
    unit = _unit("x = 1\n")
    disabled.put(unit, "", {"D3.missing_auth": 0.9})
    assert disabled.get(unit, "") is None
    disabled.save()
    assert not path.exists()

    path.write_text("{not json", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        broken = DecisionCache(path)
    assert broken.get(unit, "") is None
    assert "cache" in caplog.text.lower()

    caplog.clear()
    path.write_text(json.dumps({"version": 99, "entries": {}}), encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        old = DecisionCache(path)
    assert old.get(unit, "") is None
    assert "version" in caplog.text.lower()


def test_units_to_skip_uses_layer1_line_inside_unit() -> None:
    unit = _unit("x = 1\n", file="a.py", start_line=10, end_line=20, name="create")
    inside_start = Finding("D1.hardcoded_secret", "a.py", 10, "secret")
    inside_end = Finding("D1.env_file_committed", "a.py", 20, "env")
    outside = Finding("D1.hardcoded_secret", "a.py", 21, "nope")
    other_file = Finding("D1.hardcoded_secret", "b.py", 12, "nope")
    layer2 = Finding("D3.missing_auth", "a.py", 12, "auth", probability=0.95)
    skipped = units_to_skip([unit], [inside_start, outside, other_file, layer2])
    assert skipped == {unit.unit_id}
    assert units_to_skip([unit], [outside, other_file, layer2]) == set()
    assert inside_end.line == 20
    assert units_to_skip([unit], [inside_end]) == {unit.unit_id}

    cache = DecisionCache(Path("unused"), enabled=False)
    findings, stats = judge(
        _ctx([unit]),
        _FixedBackend({rule_id: 0.99 for rule_id in LAYER2_RULE_IDS}),
        cache,
        skip_unit_ids=skipped,
    )
    assert findings == []
    assert stats.units_skipped_layer1 == 1
    assert stats.units_judged == 0


def test_threshold_is_inclusive() -> None:
    scores = {rule_id: 0.1 for rule_id in LAYER2_RULE_IDS}
    scores["D3.missing_auth"] = 0.75
    scores["D4.idor_or_price_trust"] = 0.74
    findings, _stats = judge(
        _ctx([_unit("x = 1\n")]),
        _FixedBackend(scores),
        DecisionCache(Path("unused"), enabled=False),
        threshold=0.75,
    )
    assert [finding.rule_id for finding in findings] == ["D3.missing_auth"]


def test_offline_backend_obvious_positives_and_negatives() -> None:
    backend = OfflineHeuristicBackend()

    fastapi_bad = _unit(
        '''
@app.post("/api/orders")
async def create_order(request: Request):
    body = await request.json()
    user_id = body["user_id"]
    price = body["price"]
    supabase.table("orders").insert({"user_id": user_id, "amount": price}).execute()
''',
        name="create_order",
        file="app/orders.py",
    )
    scores = _offline_scores(backend, fastapi_bad, "")
    assert scores["D3.missing_auth"] >= 0.9
    assert scores["D4.idor_or_price_trust"] >= 0.9
    assert scores["D7b.missing_boundary_schema"] >= 0.8
    assert scores["D5.prompt_injection"] < 0.2
    assert scores["D6b.hardcoded_mock_stub"] < 0.2
    assert scores["D7a.n_plus_one_loop"] < 0.2

    next_bad = _unit(
        """
export async function POST(req: Request) {
  const body = await req.json()
  const userId = body.userId
  const price = body.price
  await supabase.from("orders").insert({ user_id: userId, amount: price })
}
""",
        name="POST",
        file="app/api/orders/route.ts",
        language=Language.TYPESCRIPT,
        http_method="POST",
        route_path="/api/orders",
    )
    scores = _offline_scores(backend, next_bad, "")
    assert scores["D3.missing_auth"] >= 0.9
    assert scores["D4.idor_or_price_trust"] >= 0.9
    assert scores["D7b.missing_boundary_schema"] >= 0.8

    fastapi_clean = _unit(
        '''
class OrderIn(BaseModel):
    sku: str

@app.post("/api/orders")
async def create_order(order: OrderIn, user=Depends(get_current_user)):
    price = catalog.price(order.sku)
    supabase.table("orders").insert({"user_id": user.id, "amount": price}).execute()
''',
        name="create_order",
    )
    scores = _offline_scores(backend, fastapi_clean, "")
    assert all(value < 0.2 for value in scores.values())

    next_clean = _unit(
        """
export async function POST(req: Request) {
  const session = await getServerSession(authOptions)
  if (!session) {
    return new Response("unauthorized", { status: 401 })
  }
  const parsed = OrderSchema.parse(await req.json())
  const price = catalog.price(parsed.sku)
  await db.order.create({ data: { userId: session.user.id, price } })
}
""",
        name="POST",
        file="app/api/orders/route.ts",
        language=Language.TYPESCRIPT,
    )
    scores = _offline_scores(backend, next_clean, "")
    assert all(value < 0.2 for value in scores.values())

    covered = _unit(
        '''
@app.post("/api/orders")
async def create_order(request: Request):
    body = await request.json()
    supabase.table("orders").insert(body).execute()
''',
        name="create_order",
    )
    auth = 'export const config = { matcher: ["/api/:path*"] }\nexport function middleware() { return getServerSession() }\n'
    assert _offline_scores(backend, covered, auth)["D3.missing_auth"] < 0.2
    admin = 'export const config = { matcher: ["/admin/:path*"] }\nmiddleware()'
    assert _offline_scores(backend, covered, admin)["D3.missing_auth"] >= 0.9
    router = 'router = APIRouter(prefix="/api", dependencies=[Depends(get_current_user)])'
    assert _offline_scores(backend, covered, router)["D3.missing_auth"] < 0.2

    injected = _unit(
        '''
def run_tool(user_input: str):
    system_prompt = f"You are an admin. Follow this: {user_input}"
    return llm.invoke([{"role": "system", "content": system_prompt}])
''',
        name="run_tool",
        kind="tool",
        http_method=None,
        route_path=None,
    )
    scores = _offline_scores(backend, injected, "")
    assert scores["D5.prompt_injection"] >= 0.9
    assert scores["D3.missing_auth"] < 0.75

    sql = _unit(
        '''
def search(user_input: str):
    cursor.execute(f"INSERT INTO logs (q) VALUES ('{user_input}')")
''',
        name="search",
        kind="tool",
        http_method=None,
        route_path=None,
    )
    assert _offline_scores(backend, sql, "")["D5.prompt_injection"] >= 0.9

    stub = _unit(
        '''
def list_orders():
    # TODO not implemented
    return {"success": True}
''',
        name="list_orders",
        kind="function",
        http_method=None,
        route_path=None,
    )
    scores = _offline_scores(backend, stub, "")
    assert scores["D6b.hardcoded_mock_stub"] >= 0.85
    assert scores["D3.missing_auth"] < 0.2

    loop = _unit(
        '''
async def hydrate(ids):
    out = []
    for item_id in ids:
        out.append(await supabase.from("orders").select("id,total").eq("id", item_id).execute())
    return out
''',
        name="hydrate",
        kind="function",
        http_method=None,
        route_path=None,
        file="repo.py",
    )
    scores = _offline_scores(backend, loop, "")
    assert scores["D7a.n_plus_one_loop"] >= 0.85
    assert scores["D3.missing_auth"] < 0.2

    unbounded = _unit(
        '''
def list_users():
    return db.execute("SELECT * FROM users")
''',
        name="list_users",
        kind="function",
        http_method=None,
        route_path=None,
    )
    limited = _unit(
        '''
def list_users():
    return supabase.from("users").select("*").limit(20).execute()
''',
        name="list_users",
        kind="function",
        http_method=None,
        route_path=None,
    )
    assert _offline_scores(backend, unbounded, "")["D7a.n_plus_one_loop"] >= 0.8
    assert _offline_scores(backend, limited, "")["D7a.n_plus_one_loop"] < 0.2

    for scores in (
        _offline_scores(backend, fastapi_bad, ""),
        _offline_scores(backend, next_clean, ""),
        _offline_scores(backend, stub, ""),
    ):
        assert set(scores) == set(LAYER2_RULE_IDS)
        assert all(0.01 <= value <= 0.99 for value in scores.values())


def _offline_scores(backend: OfflineHeuristicBackend, unit: CodeUnit, auth: str) -> dict[str, float]:
    import asyncio

    verdict = asyncio.run(backend.judge_chunk(auth, [unit]))
    assert verdict.input_tokens == 0
    return verdict.scores[unit.unit_id]


def test_offline_judge_filters_and_reports_mode() -> None:
    unit = _unit(
        '''
def list_orders():
    return {"success": True}
''',
        name="list_orders",
        kind="function",
        http_method=None,
        route_path=None,
    )
    findings, stats = judge(
        _ctx([unit]),
        OfflineHeuristicBackend(),
        DecisionCache(Path("unused"), enabled=False),
    )
    assert stats.mode == "offline"
    assert stats.input_tokens == 0
    assert [finding.rule_id for finding in findings] == ["D6b.hardcoded_mock_stub"]
    findings, stats = judge(_ctx([unit]), None, DecisionCache(Path("unused"), enabled=False))
    assert findings == []
    assert stats.mode == "disabled"


def test_select_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assert select_backend("off") is None
    assert select_backend("auto").name == OFFLINE_MODEL
    assert select_backend("offline").name == OFFLINE_MODEL
    with pytest.raises(DecisionAPIError, match="GEMINI_API_KEY"):
        select_backend("live")
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    assert select_backend("auto").name == GEMINI_MODEL
    assert select_backend("live").name == GEMINI_MODEL
    with pytest.raises(DecisionAPIError):
        select_backend("sometimes")


def test_compute_scores_scale_layer2_and_clamp() -> None:
    critical = Finding("D1.hardcoded_secret", "a.py", 1, "secret")
    security, slop = compute_scores([critical])
    assert (security, slop) == (75, 100)
    slop_high = Finding("D6a.deprecated_sdk", "a.py", 2, "old")
    assert compute_scores([slop_high]) == (100, 85)
    layer2 = Finding("D7a.n_plus_one_loop", "a.py", 3, "loop", probability=0.5)
    assert compute_scores([layer2]) == (100, 96)
    assert layer2.category == Category.SLOP
    many = [Finding("D1.hardcoded_secret", "a.py", i, "secret") for i in range(1, 6)]
    assert compute_scores(many) == (0, 100)


def _scan_result(findings: list[Finding], **judge_overrides: object) -> ScanResult:
    stats = JudgeStats(mode="offline", units_judged=4, cache_hits=2, requests=1, input_tokens=1_000_000)
    for key, value in judge_overrides.items():
        setattr(stats, key, value)
    return ScanResult(
        root=Path("/repo"),
        findings=findings,
        files_scanned=6,
        judge=stats,
        duration_s=1.25,
        diff_base="main",
    )


def test_reporter_quiet_pass_and_findings() -> None:
    console = Console(record=True, width=200)
    render_terminal(_scan_result([]), console, quiet=True)
    assert console.export_text().strip() == "VIBEGUARD: PASS"

    finding = Finding(
        "D3.missing_auth",
        "app.py",
        4,
        "Missing authentication on mutating route in route POST /api/orders (create_order).",
        end_line=12,
        symbol="create_order",
        probability=0.91,
    )
    console = Console(record=True, width=240)
    render_terminal(_scan_result([finding], errors=["chunk failed"]), console, quiet=True)
    lines = [line.strip() for line in console.export_text().splitlines() if line.strip()]
    assert lines[0].startswith(
        "CRITICAL D3.missing_auth app.py:4 (p=0.91) Missing authentication"
    )
    assert lines[-1] == "VIBEGUARD: ERROR 1 Layer-2 chunk(s) failed: chunk failed"
    assert "VIBEGUARD: PASS" not in console.export_text()
    assert "│" not in console.export_text()

    console = Console(record=True, width=200)
    render_terminal(_scan_result([finding]), console, quiet=False)
    text = console.export_text()
    assert "security=" in text and "slop=" in text
    assert "mode=offline" in text
    assert "files scanned: 6" in text
    assert "units judged: 4" in text
    assert "cache hits: 2" in text
    assert "input tokens: 1000000" in text
    assert "$0.10/1M" in text
    assert "D3.missing_auth" in text
    assert "Severity" in text and "Finding" in text
    console = Console(record=True, width=200)
    render_terminal(_scan_result([finding], errors=["boom [app.py:4:create]"]), console, quiet=False)
    assert "boom [app.py:4:create]" in console.export_text()


def test_markdown_sarif_and_json(tmp_path: Path) -> None:
    finding = Finding(
        "D1.hardcoded_secret",
        "app\\api\\route.ts",
        8,
        "Hardcoded secret literal in route.",
        end_line=11,
        probability=None,
        fix_patch="--- a/app/api/route.ts\n+++ b/app/api/route.ts\n@@ -8 +8 @@\n-password = 'x'\n+password = os.environ['PASSWORD']\n",
    )
    medium = Finding("D7b.missing_boundary_schema", "web.py", 3, "raw body", probability=0.8)
    low = Finding("D6a.passthrough_wrapper", "web.py", 9, "wrapper")
    result = _scan_result([finding, medium, low], errors=["partial scores"])
    markdown = to_markdown(result)
    assert "Security score:" in markdown
    assert "Mode: offline" in markdown
    assert RULES["D1.hardcoded_secret"].remediation in markdown
    assert "```diff" in markdown
    assert "--- a/app/api/route.ts" in markdown
    assert "partial scores" in markdown
    assert "### critical" in markdown and "### medium" in markdown and "### low" in markdown
    report = tmp_path / "VIBEGUARD_REPORT.md"
    write_markdown(result, report)
    assert report.read_text(encoding="utf-8") == markdown

    sarif = to_sarif(result)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "VibeGuard"
    assert driver["version"]
    assert driver["informationUri"].startswith("https://")
    rule_ids = {rule["id"] for rule in driver["rules"]}
    assert "D1.hardcoded_secret" in rule_ids and "D3.missing_auth" in rule_ids
    sample = next(rule for rule in driver["rules"] if rule["id"] == "D1.hardcoded_secret")
    assert sample["shortDescription"]["text"]
    assert sample["help"]["text"] == RULES["D1.hardcoded_secret"].remediation
    assert sample["properties"]["category"] == "security"
    assert sample["properties"]["layer"] == 1
    levels = {item["ruleId"]: item["level"] for item in sarif["runs"][0]["results"]}
    assert levels == {
        "D1.hardcoded_secret": "error",
        "D7b.missing_boundary_schema": "warning",
        "D6a.passthrough_wrapper": "note",
    }
    secret = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "D1.hardcoded_secret")
    location = secret["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app/api/route.ts"
    assert location["region"] == {"startLine": 8, "endLine": 11}
    assert secret["properties"]["layer"] == 1
    assert "probability" in secret["properties"]
    assert "module_risk" in secret["properties"]
    assert "| Risk |" in markdown
    high = Finding("D2.cors_wildcard_credentials", "main.py", 2, "cors")
    high_level = to_sarif(_scan_result([high]))["runs"][0]["results"][0]["level"]
    assert high_level == "error"
    destination = tmp_path / "out.sarif"
    write_sarif(result, destination)
    assert json.loads(destination.read_text(encoding="utf-8"))["version"] == "2.1.0"

    payload = to_json(result)
    assert payload["security_score"] == compute_scores(result.findings)[0]
    assert payload["judge"]["mode"] == "offline"
    assert payload["judge"]["input_tokens"] == 1_000_000
    assert payload["judge"]["estimated_cost_usd"] == pytest.approx(0.10)
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["module_risk"] is None
    assert "module_risk" in payload["findings"][0]
    assert payload["diff_base"] == "main"


def test_generate_fixes_eligibility_and_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    ctx = ScanContext(root=tmp_path, files=[], units=[], auth_context="")
    secret = Finding("D1.hardcoded_secret", "app.py", 3, "secret", snippet="password = 'x'")
    with caplog.at_level(logging.WARNING):
        assert generate_fixes([secret], ctx) == 0
    assert secret.fix_patch is None
    assert "GEMINI_API_KEY" in caplog.text

    diff = "--- a/app.py\n+++ b/app.py\n@@ -3 +3 @@\n-password = 'x'\n+password = os.environ['PASSWORD']\n"
    models = _FixModels("```diff\n" + diff + "```\n")
    critical_layer2 = Finding("D3.missing_auth", "app.py", 4, "auth", probability=0.9)
    below = Finding("D4.idor_or_price_trust", "app.py", 5, "idor", probability=0.8)
    high_layer1 = Finding("D2.cors_wildcard_credentials", "app.py", 6, "cors")
    medium = Finding("D7a.n_plus_one_loop", "app.py", 7, "loop", probability=0.95)
    drafted = generate_fixes(
        [secret, critical_layer2, below, high_layer1, medium],
        ctx,
        model="gemini-2.5-flash",
        client=SimpleNamespace(aio=SimpleNamespace(models=models)),
    )
    assert drafted == 2
    assert models.calls == 2
    assert models.model == "gemini-2.5-flash"
    assert secret.fix_patch is not None and secret.fix_patch.startswith("--- a/app.py")
    assert "@@" in secret.fix_patch
    assert critical_layer2.fix_patch is not None
    assert below.fix_patch is None
    assert high_layer1.fix_patch is None
    assert medium.fix_patch is None
    blob = "\n".join(models.contents)
    assert "Hardcoded secret literal" in blob
    assert "Missing authentication on mutating route" in blob

    prose = _FixModels("I would add authentication.")
    lonely = Finding("D5.prompt_injection", "app.py", 9, "inject", probability=0.99)
    assert generate_fixes([lonely], ctx, client=SimpleNamespace(aio=SimpleNamespace(models=prose))) == 0
    assert lonely.fix_patch is None

    broken = _FixModels(exc=RuntimeError("model down"))
    another = Finding("D1.next_public_secret", "app.py", 2, "public")
    with caplog.at_level(logging.WARNING):
        assert generate_fixes([another], ctx, client=SimpleNamespace(aio=SimpleNamespace(models=broken))) == 0
    assert "model down" in caplog.text
    assert another.fix_patch is None


class _FixModels:
    def __init__(self, text: str = "", exc: BaseException | None = None):
        self.text = text
        self.exc = exc
        self.calls = 0
        self.model: str | None = None
        self.contents: list[str] = []

    async def generate_content(self, *, model: str, contents: str):
        self.calls += 1
        self.model = model
        self.contents.append(contents)
        if self.exc is not None:
            raise self.exc
        return {"text": self.text}


def test_pipeline_module_exposes_run_scan() -> None:
    assert callable(run_scan)


def test_cli_exit_codes_quiet_json_and_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    clean_repo = tmp_path / "clean"
    clean_repo.mkdir()
    (clean_repo / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")

    assert main(["scan", str(clean_repo), "--no-report", "--mode", "offline"]) == 0
    assert "VibeGuard" in capsys.readouterr().out
    assert not (clean_repo / "VIBEGUARD_REPORT.md").exists()

    assert main(["scan", str(clean_repo), "--quiet", "--mode", "off"]) == 0
    assert capsys.readouterr().out.strip() == "VIBEGUARD: PASS"
    assert not (clean_repo / "VIBEGUARD_REPORT.md").exists()

    report = tmp_path / "custom.md"
    assert main(["scan", str(clean_repo), "--quiet", "--report", str(report), "--mode", "offline"]) == 0
    assert report.is_file()
    assert report.read_text(encoding="utf-8").startswith("# VibeGuard report")
    capsys.readouterr()

    crit_repo = tmp_path / "crit"
    crit_repo.mkdir()
    fake_key = "sk_" + "live_" + "0123456789abcdef01234567"
    (crit_repo / "a.py").write_text(f'STRIPE_KEY = "{fake_key}"\n', encoding="utf-8")

    assert main(["scan", str(crit_repo), "--quiet", "--no-report", "--mode", "offline"]) == 1
    quiet_out = capsys.readouterr().out
    assert quiet_out.startswith("CRITICAL D1.hardcoded_secret a.py:1 (p=1.00) ")
    assert "VIBEGUARD: FAIL" in quiet_out

    assert main(["scan", str(crit_repo), "--quiet", "--no-report", "--mode", "offline", "--fail-on", "none"]) == 0
    capsys.readouterr()

    assert main(["scan", str(crit_repo), "--json", "--no-report", "--quiet", "--mode", "offline"]) == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["findings"][0]["rule_id"] == "D1.hardcoded_secret"
    assert payload["security_score"] == 75
    assert "VIBEGUARD" not in captured.out
    assert "Traceback" not in captured.err

    low_repo = tmp_path / "low"
    low_repo.mkdir()
    (low_repo / "b.py").write_text(
        "def target(x: int) -> int:\n"
        "    return x + 1\n\n"
        "def wrap(*args, **kwargs):\n"
        "    return target(*args, **kwargs)\n",
        encoding="utf-8",
    )
    assert main(["scan", str(low_repo), "--quiet", "--no-report", "--mode", "offline"]) == 0
    assert main(["scan", str(low_repo), "--quiet", "--no-report", "--mode", "offline", "--fail-on", "low"]) == 1
    capsys.readouterr()

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assert main(["scan", str(clean_repo), "--mode", "live", "--no-report"]) == 2
    error_out = capsys.readouterr()
    assert "GEMINI_API_KEY" in error_out.err
    assert "Traceback" not in error_out.err

    diff_repo = tmp_path / "diff_repo"
    diff_repo.mkdir()
    init_git(diff_repo)
    (diff_repo / "old_bad.py").write_text(f'STRIPE_KEY = "{fake_key}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=diff_repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=diff_repo, check=True)
    (diff_repo / "new_clean.py").write_text("VALUE = 42\n", encoding="utf-8")

    assert (
        main(
            [
                "scan",
                str(diff_repo),
                "--diff",
                "HEAD",
                "--mode",
                "offline",
                "--threshold",
                "0.5",
                "--no-cache",
                "--no-report",
                "--quiet",
            ]
        )
        == 0
    )
    assert not (diff_repo / ".vibeguard_cache.json").exists()
    capsys.readouterr()

    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == "0.1.0"
    assert main(["nope"]) == 2
    assert main(["scan", str(clean_repo), "--threshold", "2", "--no-report"]) == 2
    assert main(["scan", str(clean_repo), "--report", str(report), "--no-report"]) == 2


def test_offline_auth_trust_prompt_and_stub_heuristics() -> None:
    backend = OfflineHeuristicBackend()

    empty_path = _unit(
        '''
@router.post("", response_model=OrderOut)
def create_order(body: OrderIn, request: Request) -> OrderOut:
    user = request.state.user
    conn.execute("INSERT INTO orders (user_id) VALUES (%s)", (user.id,))
    conn.commit()
    return OrderOut(id="1")
''',
        file="api/routes/orders.py",
        route_path="",
    )
    router_auth = (
        'api/routes/orders.py:48: router = APIRouter(prefix="/orders", '
        "dependencies=[Depends(get_current_user)])"
    )
    assert _offline_scores(backend, empty_path, router_auth)["D3.missing_auth"] < 0.2
    other_file = _unit(empty_path.source, file="api/routes/other.py", route_path="")
    assert _offline_scores(backend, other_file, router_auth)["D3.missing_auth"] >= 0.9

    no_prefix = _unit(
        '''
@router.patch("/notes")
def update_note(body: NoteUpdate, request: Request):
    conn.execute("UPDATE notes SET body = %s WHERE id = %s", (body.text, body.note_id))
    conn.commit()
''',
        file="api/routes/notes.py",
        http_method="PATCH",
        route_path="/notes",
    )
    assert (
        _offline_scores(
            backend,
            no_prefix,
            "api/routes/notes.py:12: router = APIRouter(dependencies=[Depends(get_current_user)])",
        )["D3.missing_auth"]
        < 0.2
    )

    app_route = _unit(
        '''
@app.post("/refunds")
def create_refund(body: RefundIn):
    conn.execute("INSERT INTO refunds (order_id) VALUES (%s)", (body.order_id,))
    conn.commit()
''',
        route_path="/refunds",
    )
    assert (
        _offline_scores(
            backend,
            app_route,
            "app.py:3: app = FastAPI(dependencies=[Depends(require_user)])",
        )["D3.missing_auth"]
        < 0.2
    )
    assert (
        _offline_scores(
            backend,
            _unit(
                '''
@router.post("/refunds")
def create_refund(body: RefundIn):
    conn.execute("INSERT INTO refunds (order_id) VALUES (%s)", (body.order_id,))
    conn.commit()
''',
                route_path="/refunds",
            ),
            "app.py:9: app.include_router(router, dependencies=[Depends(get_current_user)])",
        )["D3.missing_auth"]
        < 0.2
    )

    for source in (
        '''
@app.post("/x")
def create(user: User = Depends(get_current_user), body: Item):
    conn.execute("INSERT INTO t (owner_id, sku) VALUES (%s, %s)", (user.id, body.sku))
''',
        '''
@app.post("/x")
def create(user: Annotated[User, Depends(get_current_user)], body: Item):
    conn.execute("INSERT INTO t (owner_id, sku) VALUES (%s, %s)", (user.id, body.sku))
''',
        '''
@app.post("/x")
def create(current_user=Depends(load_principal), body: Item):
    conn.execute("INSERT INTO t (owner_id, sku) VALUES (%s, %s)", (current_user.id, body.sku))
''',
    ):
        assert _offline_scores(backend, _unit(source), "")["D3.missing_auth"] < 0.2

    helper = _unit(
        '''
def insert_refund(order_id: str, amount_cents: int) -> str:
    with connection() as conn:
        row = conn.execute(
            "INSERT INTO refunds (order_id, amount_cents) VALUES (%s, %s) RETURNING id",
            (order_id, amount_cents),
        ).fetchone()
        conn.commit()
    return str(row[0])
''',
        kind="function",
        http_method=None,
        route_path=None,
    )
    assert _offline_scores(backend, helper, "")["D3.missing_auth"] < 0.2

    tool_write = _unit(
        '''
@tool
def refund(reason: str):
    conn.execute("INSERT INTO refunds (reason) VALUES (%s)", (reason,))
    conn.commit()
''',
        kind="route",
        http_method="TOOL",
        route_path=None,
    )
    tool_read = _unit(
        '''
@tool
def search(q: str):
    rows = conn.execute("SELECT id FROM docs WHERE q = %s LIMIT 10", (q,)).fetchall()
    return [str(row[0]) for row in rows]
''',
        kind="route",
        http_method="TOOL",
        route_path=None,
    )
    assert _offline_scores(backend, tool_write, "")["D3.missing_auth"] >= 0.9
    assert _offline_scores(backend, tool_read, "")["D3.missing_auth"] < 0.2

    open_refund = _unit(
        '''
@app.post("/refunds")
def create_refund(body: RefundIn):
    conn.execute("INSERT INTO refunds (order_id) VALUES (%s)", (body.order_id,))
    conn.commit()
''',
        file="api/main.py",
        route_path="/refunds",
    )
    cors_star = (
        'api/main.py:14: add_middleware( CORSMiddleware, allow_origins=["*"], '
        'allow_credentials=True, allow_headers=["Authorization"] )'
    )
    assert _offline_scores(backend, open_refund, cors_star)["D3.missing_auth"] >= 0.9

    express = _unit(
        '''
router.post("/orders", async (req, res) => {
  await db.insert({ sku: req.body.sku })
})
''',
        file="server.js",
        language=Language.JAVASCRIPT,
        route_path="/orders",
    )
    assert (
        _offline_scores(backend, express, "server.js:4: router.use(requireAuth)")["D3.missing_auth"]
        < 0.2
    )
    assert (
        _offline_scores(backend, express, 'server.js:4: router.use("/admin", requireAuth)')[
            "D3.missing_auth"
        ]
        >= 0.9
    )

    idor = _unit(
        '''
@router.post("/payouts/release")
def release(body: ReleasePayout, request: Request):
    actor = request.state.user
    logger.info("actor %s", actor.id)
    credit_wallet(body.user_id, body.payout_id)
    return ReleaseOut(credited_user=body.user_id)
'''
    )
    assert _offline_scores(backend, idor, "")["D4.idor_or_price_trust"] >= 0.9

    destructured = _unit(
        """
export async function POST(req: Request) {
  const { userId, price } = await req.json()
  await db.insert({ user_id: userId, amount: price })
}
""",
        file="app/api/orders/route.ts",
        language=Language.TYPESCRIPT,
    )
    assert _offline_scores(backend, destructured, "")["D4.idor_or_price_trust"] >= 0.9

    from_body = _unit(
        """
export async function POST(req: Request) {
  await pool.query("UPDATE accounts SET owner = $1 WHERE org_id = $2", [req.body.userId, req.body.orgId])
}
""",
        file="app/api/accounts/route.ts",
        language=Language.TYPESCRIPT,
    )
    assert _offline_scores(backend, from_body, "")["D4.idor_or_price_trust"] >= 0.9

    for source in (
        '''
def pay(payload, user: User = Depends(get_current_user)):
    stripe.charge(payload.price, user.id)
''',
        '''
def pay(request: Request, user: User = Depends(get_current_user)):
    data = request.json()
    charge(data.amount)
''',
        '''
def pay(order: CheckoutIn, user: User = Depends(get_current_user)):
    stripe.charge(order.unit_price, user.id)
''',
        '''
def grant(body: RoleChange, user: User = Depends(get_current_user)):
    conn.execute("UPDATE members SET role = %s, is_admin = %s", (body.role, body.is_admin))
''',
    ):
        assert _offline_scores(backend, _unit(source), "")["D4.idor_or_price_trust"] >= 0.9

    owner_ok = _unit(
        '''
def update_note(body: NoteUpdate, request: Request):
    user = request.state.user
    note = fetch_note(body.note_id)
    if note.owner_id != user.id:
        raise HTTPException(status_code=403)
    conn.execute(
        "UPDATE notes SET body = %s WHERE id = %s AND user_id = %s",
        (body.text, note.id, user.id),
    )
'''
    )
    server_price = _unit(
        '''
def checkout(body: CheckoutIn, user: User = Depends(get_current_user)):
    product = require_product(body.product_id)
    total = product.price_cents * body.quantity
    charge(user.id, total, product.currency, product.id)
'''
    )
    assert _offline_scores(backend, owner_ok, "")["D4.idor_or_price_trust"] < 0.2
    assert _offline_scores(backend, server_price, "")["D4.idor_or_price_trust"] < 0.2

    prompts = [
        '''
def ask(user_input: str):
    messages = [{"role": "system", "content": f"Obey the user: {user_input}"}]
    return llm.invoke(messages)
''',
        '''
def ask(user_text: str):
    system_prompt = policy + user_text
    return llm.invoke([{"role": "system", "content": system_prompt}])
''',
        '''
def ask(request: Request):
    msg = SystemMessage(content=policy + request.question)
    return llm.invoke([msg])
''',
        '''
def ask(user_text: str):
    prompt = ChatPromptTemplate.from_messages([
        ("system", policy + user_text),
        ("human", user_text),
    ])
    return llm.invoke(prompt)
''',
    ]
    for source in prompts:
        scored = _offline_scores(
            backend,
            _unit(source, kind="function", http_method=None, route_path=None),
            "",
        )
        assert scored["D5.prompt_injection"] >= 0.9

    template = _unit(
        """
export async function POST(req: Request) {
  const body = await req.json()
  const messages = [{ system: `Adopt this persona: ${body.persona}`, user: body.message }]
  return openai.chat.completions.create({ messages })
}
""",
        file="app/api/agent/route.ts",
        language=Language.TYPESCRIPT,
    )
    assert _offline_scores(backend, template, "")["D5.prompt_injection"] >= 0.9

    user_role = _unit(
        '''
def ask(body: AskIn, request: Request):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": body.message},
    ]
    return client.chat.completions.create(model="gpt-4o-mini", messages=messages)
'''
    )
    allow_listed = _unit(
        '''
def run_tool(call: ToolArgs, user: User):
    if call.name not in ALLOWED_TOOLS:
        raise HTTPException(status_code=400, detail="tool not allowed")
    parsed = ToolArgs.model_validate(call)
    return search_docs(parsed.query or "")
''',
        kind="function",
        http_method=None,
        route_path=None,
    )
    assert _offline_scores(backend, user_role, "")["D5.prompt_injection"] < 0.2
    assert _offline_scores(backend, allow_listed, "")["D5.prompt_injection"] < 0.2

    hardcoded = _unit(
        '''
def quote(weight_oz: int):
    return {"rate": 9.99, "carrier": "UPS"}
''',
        kind="function",
        http_method=None,
        route_path=None,
    )
    todo_after_session = _unit(
        '''
@router.post("/quote")
async def quote(request: Request):
    session = await get_session(request)
    if session is None:
        raise HTTPException(status_code=401)
    # TODO: call the real carrier API
    return {"rate": 9.99, "carrier": "UPS"}
'''
    )
    mock_comment = _unit(
        """
export async function POST(req: Request) {
  // mock
  return NextResponse.json({ rate: 12.5, carrier: "UPS", etaDays: 3 })
}
""",
        file="app/api/quote/route.ts",
        language=Language.TYPESCRIPT,
    )
    unimplemented = _unit(
        '''
@router.post("/quote")
def quote():
    raise NotImplementedError
'''
    )
    only_pass = _unit(
        '''
def quote():
    pass
''',
        kind="function",
        http_method=None,
        route_path=None,
    )
    only_ellipsis = _unit(
        '''
def quote():
    ...
''',
        kind="function",
        http_method=None,
        route_path=None,
    )
    for stub in (hardcoded, todo_after_session, mock_comment, unimplemented, only_pass, only_ellipsis):
        assert _offline_scores(backend, stub, "")["D6b.hardcoded_mock_stub"] >= 0.85

    health = _unit(
        '''
@app.get("/health")
def health():
    return {"status": "ok"}
''',
        http_method="GET",
        route_path="/health",
    )
    real_query = _unit(
        '''
def load(user_id: str):
    with connection() as conn:
        rows = conn.execute(
            "SELECT id, total_cents FROM orders WHERE user_id = %s LIMIT 20",
            (user_id,),
        ).fetchall()
    return [{"id": str(row[0]), "total_cents": int(row[1])} for row in rows]
''',
        kind="function",
        http_method=None,
        route_path=None,
    )
    assert _offline_scores(backend, health, "")["D6b.hardcoded_mock_stub"] < 0.2
    assert _offline_scores(backend, real_query, "")["D6b.hardcoded_mock_stub"] < 0.2

    raw_body = _unit(
        '''
@router.post("/notes")
async def create(request: Request, user: User = Depends(get_current_user)):
    payload = await request.json()
    title = str(payload["title"])
    db.execute("INSERT INTO notes (owner_id, title) VALUES (%s, %s)", (user.id, title))
'''
    )
    raw_scores = _offline_scores(backend, raw_body, "")
    assert raw_scores["D7b.missing_boundary_schema"] >= 0.8
    assert raw_scores["D3.missing_auth"] < 0.2
    validated = _unit(
        '''
@router.post("/notes")
async def create(request: Request, user: User = Depends(get_current_user)):
    payload = await request.json()
    body = NoteIn.model_validate(payload)
    db.execute("INSERT INTO notes (owner_id, title) VALUES (%s, %s)", (user.id, body.title))
'''
    )
    assert _offline_scores(backend, validated, "")["D7b.missing_boundary_schema"] < 0.2


def test_units_to_skip_only_when_layer1_is_critical() -> None:
    unit = _unit("x = 1\n", file="a.py", start_line=10, end_line=20, name="create")
    medium = Finding("D6a.silent_exception", "a.py", 12, "swallowed")
    high = Finding("D6a.deprecated_sdk", "a.py", 14, "old")
    critical = Finding("D1.hardcoded_secret", "a.py", 16, "secret")
    assert medium.severity.value == "medium"
    assert units_to_skip([unit], [medium, high]) == set()
    assert units_to_skip([unit], [medium, critical]) == {unit.unit_id}


def test_unauthenticated_post_with_silent_except_reports_both(tmp_path: Path) -> None:
    (tmp_path / "orders.py").write_text(
        "from fastapi import FastAPI, Request\n"
        "\n"
        "app = FastAPI()\n"
        "\n"
        "@app.post('/orders')\n"
        "async def create_order(request: Request):\n"
        "    try:\n"
        "        body = await request.json()\n"
        "    except Exception:\n"
        "        pass\n"
        "    db.execute('INSERT INTO orders (sku) VALUES (%s)', (body['sku'],))\n",
        encoding="utf-8",
    )
    result, _ctx = run_scan(tmp_path, mode="offline", use_cache=False)
    rules = {finding.rule_id for finding in result.findings}
    assert "D6a.silent_exception" in rules
    assert "D3.missing_auth" in rules


def test_judge_errors_exit_2_and_quiet_never_passes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _ErrorHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)
            body = b'{"error":{"code":400,"message":"chunk exploded","status":"INVALID_ARGUMENT"}}'
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return None

    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/pay')\n"
        "def pay(body: dict):\n"
        "    return body\n",
        encoding="utf-8",
    )

    server = HTTPServer(("127.0.0.1", 0), _ErrorHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    try:
        assert main(["scan", str(tmp_path), "--mode", "live", "--quiet", "--no-report", "--no-cache"]) == 2
        quiet = capsys.readouterr().out
        assert "VIBEGUARD: PASS" not in quiet
        assert "VIBEGUARD: ERROR 1 Layer-2 chunk(s) failed:" in quiet
        assert "chunk exploded" in quiet

        assert main(["scan", str(tmp_path), "--mode", "live", "--no-report", "--no-cache"]) == 2
        full = capsys.readouterr().out
        assert "VIBEGUARD: PASS" not in full
        assert "ERROR" in full
        assert "chunk exploded" in full
    finally:
        server.shutdown()
        server.server_close()


def test_malformed_decision_response_fails_chunk() -> None:
    class _BadAnswers:
        def items(self):
            raise RuntimeError("malformed answers")

    async def respond(model, model_input, questions):
        return SimpleNamespace(answers=_BadAnswers(), usage=None)

    decisions = _RecordingDecisions(respond)
    backend = GeminiDecisionBackend("k", client=_client(decisions), base_delay=0)
    findings, stats = judge(
        _ctx([_unit("x = 1\n")]),
        backend,
        DecisionCache(Path("unused"), enabled=False),
    )
    assert findings == []
    assert any("malformed answers" in error for error in stats.errors)


def test_cache_rejects_scores_outside_unit_interval(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / ".vibeguard_cache.json"
    unit = _unit("x = 1\n")
    scores = {rule_id: 0.2 for rule_id in LAYER2_RULE_IDS}
    scores["D3.missing_auth"] = 5.0
    key = cache_key(OFFLINE_MODEL, unit, "")
    path.write_text(
        json.dumps({"version": 1, "entries": {key: {"model": OFFLINE_MODEL, "scores": scores}}}),
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        cache = DecisionCache(path, model=OFFLINE_MODEL)
    assert cache.get(unit, "") is None
    assert "invalid cache" in caplog.text.lower()
    cache.save()
    assert key not in json.loads(path.read_text(encoding="utf-8"))["entries"]

    scores["D3.missing_auth"] = 0.4
    del scores["D4.idor_or_price_trust"]
    path.write_text(
        json.dumps({"version": 1, "entries": {key: {"model": OFFLINE_MODEL, "scores": scores}}}),
        encoding="utf-8",
    )
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        reloaded = DecisionCache(path, model=OFFLINE_MODEL)
    assert reloaded.get(unit, "") is None
    assert "invalid cache" in caplog.text.lower()


def test_cache_keeps_module_risk_across_reload(tmp_path: Path) -> None:
    class _RiskBackend:
        name = OFFLINE_MODEL

        def __init__(self) -> None:
            self.calls = 0

        async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
            self.calls += 1
            scores = {
                unit.unit_id: {
                    rule_id: (0.9 if rule_id == "D3.missing_auth" else 0.05) for rule_id in LAYER2_RULE_IDS
                }
                for unit in units
            }
            return ChunkVerdict(
                scores=scores,
                severity={unit.unit_id: 0.4 for unit in units},
                input_tokens=3,
            )

    path = tmp_path / ".vibeguard_cache.json"
    backend = _RiskBackend()
    unit = _unit("def create():\n    return 1\n", name="create")
    ctx = _ctx([unit])
    cache = DecisionCache(path, model=OFFLINE_MODEL)
    findings, _stats = judge(ctx, backend, cache, threshold=0.75)
    assert findings[0].module_risk == pytest.approx(0.4)
    cache.save()

    backend.calls = 0
    reloaded = DecisionCache(path, model=OFFLINE_MODEL)
    findings, stats = judge(ctx, backend, reloaded, threshold=0.75)
    assert backend.calls == 0
    assert stats.cache_hits == 1
    # Peak noul is 0.9, so the offline fallback would report 2.0. The cached
    # severity answer has to survive the reload instead.
    assert findings[0].module_risk == pytest.approx(0.4)


def test_cache_save_merges_entries_from_a_stale_snapshot(tmp_path: Path) -> None:
    path = tmp_path / ".vibeguard_cache.json"
    first = DecisionCache(path, model=OFFLINE_MODEL)
    second = DecisionCache(path, model=OFFLINE_MODEL)
    unit_a = _unit("def alpha():\n    return 1\n", name="alpha")
    unit_b = _unit("def beta():\n    return 2\n", name="beta")
    scores = {rule_id: 0.2 for rule_id in LAYER2_RULE_IDS}
    first.put(unit_a, "", scores, module_risk=0.4)
    second.put(unit_b, "", scores, module_risk=1.0)
    first.save()
    second.save()
    merged = DecisionCache(path, model=OFFLINE_MODEL)
    assert merged.get(unit_a, "")["D3.missing_auth"] == pytest.approx(0.2)
    assert merged.get(unit_b, "")["D3.missing_auth"] == pytest.approx(0.2)
    assert merged.module_risk(unit_a, "") == pytest.approx(0.4)
    assert merged.module_risk(unit_b, "") == pytest.approx(1.0)


def test_threshold_outside_noul_range_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(tmp_path), "--threshold", "1", "--no-report", "--mode", "offline"]) == 2
    assert main(["scan", str(tmp_path), "--threshold", "0", "--no-report", "--mode", "offline"]) == 2
    assert "0.01" in capsys.readouterr().err
    with pytest.raises(DecisionAPIError, match="0.01"):
        judge(
            _ctx([_unit("x = 1\n")]),
            _FixedBackend({rule_id: 0.99 for rule_id in LAYER2_RULE_IDS}),
            DecisionCache(tmp_path / "unused.json", enabled=False),
            threshold=1,
        )


def test_offline_cache_key_includes_heuristic_version(monkeypatch: pytest.MonkeyPatch) -> None:
    import vibeguard.offline_heuristics as heuristics

    unit = _unit("x = 1\n")
    before = cache_key(OFFLINE_MODEL, unit, "auth")
    monkeypatch.setattr(heuristics, "OFFLINE_HEURISTIC_VERSION", OFFLINE_HEURISTIC_VERSION + "-next")
    assert cache_key(OFFLINE_MODEL, unit, "auth") != before
    gemini = question_set_version(GEMINI_MODEL)
    monkeypatch.setattr(heuristics, "OFFLINE_HEURISTIC_VERSION", "unrelated")
    assert question_set_version(GEMINI_MODEL) == gemini


def test_quiet_help_mentions_pass_token(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--help"]) == 0
    assert "VIBEGUARD: PASS" in capsys.readouterr().out


def test_parameter_named_args_is_not_taint_but_tool_params_are() -> None:
    backend = OfflineHeuristicBackend()
    git = _unit(
        '''
def _git(args):
    return subprocess.run(["git", *args], check=False, capture_output=True)
''',
        name="_git",
        kind="function",
        http_method=None,
        route_path=None,
    )
    assert _offline_scores(backend, git, "")["D5.prompt_injection"] < 0.2

    tool = _unit(
        '''
@tool
def run(command: str):
    subprocess.run(command, shell=True, check=False)
''',
        name="run",
        kind="tool",
        http_method="TOOL",
        route_path=None,
    )
    assert _offline_scores(backend, tool, "")["D5.prompt_injection"] >= 0.9

    allowed = _unit(
        '''
@tool
def notify(url: str, text: str):
    if url not in ALLOWED_WEBHOOKS:
        raise ValueError("url not allowed")
    requests.post(url, json={"text": text}, timeout=5)
''',
        name="notify",
        kind="tool",
        http_method="TOOL",
        route_path=None,
    )
    assert _offline_scores(backend, allowed, "")["D5.prompt_injection"] < 0.2


def test_tool_arguments_passed_to_sink_helper_are_d5() -> None:
    helper = _unit(
        '''
def page_bridge(target, msg):
    return requests.post(target, json={"text": msg}, timeout=8)
''',
        name="page_bridge",
        kind="function",
        http_method=None,
        route_path=None,
        file="agent.py",
    )
    caller = _unit(
        '''
@app.post("/pages")
def page(body: Note, operator_id: str = Depends(current_operator)):
    calls = message.tool_calls or []
    if calls:
        page_bridge(calls[0].function.arguments, body.ticket)
''',
        name="page",
        file="agent.py",
    )
    backend = OfflineHeuristicBackend()
    backend.bind_catalog([helper, caller])
    scores = _offline_scores(backend, caller, "")
    assert scores["D5.prompt_injection"] >= 0.9
    assert scores["D3.missing_auth"] < 0.2


def test_generic_auth_and_resource_dependencies_and_rejection() -> None:
    backend = OfflineHeuristicBackend()
    clinician = _unit(
        '''
@app.post("/visits")
def create(body: VisitIn, actor=Depends(current_clinician)):
    db.execute("INSERT INTO visits (actor) VALUES (%s)", (actor,))
'''
    )
    assert _offline_scores(backend, clinician, "")["D3.missing_auth"] < 0.2

    database = _unit(
        '''
@app.post("/visits")
def create(body: VisitIn, db=Depends(get_db)):
    db.execute("INSERT INTO visits (name) VALUES (%s)", (body.name,))
'''
    )
    assert _offline_scores(backend, database, "")["D3.missing_auth"] >= 0.9

    settings_dep = _unit(
        '''
@app.post("/visits")
def create(body: VisitIn, settings=Depends(get_settings)):
    db.execute("INSERT INTO visits (name) VALUES (%s)", (body.name,))
''',
        file="app.py",
    )
    assert (
        _offline_scores(
            backend,
            settings_dep,
            "app.py:3: app = FastAPI(dependencies=[Depends(get_redis)])",
        )["D3.missing_auth"]
        >= 0.9
    )
    assert (
        _offline_scores(
            backend,
            settings_dep,
            "app.py:3: app = FastAPI(dependencies=[Depends(verify_api_key)])",
        )["D3.missing_auth"]
        < 0.2
    )
    unnamed = _unit(
        '''
@app.post("/receipts")
def record(body: ScanIn):
    db.execute("INSERT INTO receipts (code) VALUES (%s)", (body.code,))
''',
        file="gate.py",
        route_path="/receipts",
    )
    assert (
        _offline_scores(
            backend,
            unnamed,
            "gate.py:4: FastAPI(dependencies=[Depends(verify_api_key)])",
        )["D3.missing_auth"]
        < 0.2
    )
    assert (
        _offline_scores(
            backend,
            unnamed,
            "gate.py:4: FastAPI(dependencies=[Depends(get_db)])",
        )["D3.missing_auth"]
        >= 0.9
    )
    other_file = _unit(unnamed.source, file="other.py", route_path="/receipts")
    assert (
        _offline_scores(
            backend,
            other_file,
            "gate.py:4: FastAPI(dependencies=[Depends(verify_api_key)])",
        )["D3.missing_auth"]
        >= 0.9
    )

    header = _unit(
        '''
@app.post("/ops")
def create(request: Request):
    token = request.headers.get("x-ops-session")
    if not token:
        raise HTTPException(status_code=401, detail="sign in")
    db.execute("INSERT INTO ops (token) VALUES (%s)", (token,))
'''
    )
    assert _offline_scores(backend, header, "")["D3.missing_auth"] < 0.2

    rejection = _unit(
        """
export async function POST(req: Request) {
  const body = await req.json()
  if (body.userId !== session.user.id) {
    return NextResponse.json({ error: "no" }, { status: 403 })
  }
  await db.insert({ author_id: session.user.id, text: body.text })
}
""",
        file="app/api/replies/route.ts",
        language=Language.TYPESCRIPT,
    )
    assert _offline_scores(backend, rejection, "")["D4.idor_or_price_trust"] < 0.2


def test_raw_payload_passed_to_database_scores_at_least_085() -> None:
    backend = OfflineHeuristicBackend()
    raw = _unit(
        '''
@app.post("/notes")
async def create(request: Request, user=Depends(get_current_user)):
    payload = await request.json()
    db.execute("INSERT INTO notes (data) VALUES (%s)", (payload,))
'''
    )
    assert _offline_scores(backend, raw, "")["D7b.missing_boundary_schema"] >= 0.85


def test_offline_module_risk_bands() -> None:
    import asyncio

    backend = OfflineHeuristicBackend()
    open_post = _unit(
        '''
@app.post("/orders")
async def create_order(request: Request):
    db.execute("INSERT INTO orders (sku) VALUES (%s)", ("sku",))
'''
    )
    open_verdict = asyncio.run(backend.judge_chunk("", [open_post]))
    assert open_verdict.severity[open_post.unit_id] == pytest.approx(2.0)

    boundary = _unit(
        '''
@app.post("/notes")
async def create(request: Request, user=Depends(get_current_user)):
    payload = await request.json()
    return {"echo": True}
'''
    )
    boundary_verdict = asyncio.run(backend.judge_chunk("", [boundary]))
    assert boundary_verdict.scores[boundary.unit_id]["D7b.missing_boundary_schema"] >= 0.6
    assert boundary_verdict.scores[boundary.unit_id]["D7b.missing_boundary_schema"] < 0.85
    assert boundary_verdict.severity[boundary.unit_id] == pytest.approx(1.0)

    clean = _unit(
        '''
@app.post("/orders")
async def create_order(order: OrderIn, user=Depends(get_current_user)):
    price = catalog.price(order.sku)
    supabase.table("orders").insert({"user_id": user.id, "amount": price}).execute()
'''
    )
    clean_verdict = asyncio.run(backend.judge_chunk("", [clean]))
    assert clean_verdict.severity[clean.unit_id] == pytest.approx(0.0)

    findings, _stats = judge(
        _ctx([open_post]),
        backend,
        DecisionCache(Path("unused"), enabled=False),
    )
    assert findings
    assert all(finding.module_risk == pytest.approx(2.0) for finding in findings)


def test_fix_excerpt_and_patch_are_redacted(tmp_path: Path) -> None:
    from vibeguard.redact import redact_secrets

    secret = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K2"
    assert secret not in redact_secrets(f'TOKEN = "{secret}"')
    assert "supersecretvalue1234" not in redact_secrets(
        "NEXT_PUBLIC_SECRET_TOKEN=supersecretvalue1234"
    )

    source = f'TOKEN = "{secret}"\n'
    unit = _unit(source, name="load", kind="function", http_method=None, route_path=None, start_line=1)
    ctx = ScanContext(root=tmp_path, files=[], units=[unit], auth_context="")
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n"
        f'-TOKEN = "{secret}"\n'
        "+TOKEN = os.environ['TOKEN']\n"
    )
    models = _FixModels(diff)
    finding = Finding("D1.hardcoded_secret", "app.py", 1, "secret", symbol="load", snippet=source)
    assert generate_fixes([finding], ctx, client=SimpleNamespace(aio=SimpleNamespace(models=models))) == 1
    assert secret not in models.contents[0]
    assert finding.fix_patch is not None and secret not in finding.fix_patch
    assert "<redacted:" in finding.fix_patch


def test_antigravity_hook_blocks_only_on_critical(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    init_git(repo, branch="trunk")
    (repo / "slop.py").write_text(
        "def load():\n    try:\n        work()\n    except Exception:\n        pass\n",
        encoding="utf-8",
    )
    hook = (
        Path(__file__).resolve().parents[1]
        / "integrations"
        / "antigravity"
        / "vibeguard"
        / "scripts"
        / "vibeguard-hook.sh"
    )
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join(
        [
            str(Path(sys.executable).resolve().parent),
            str(Path(__file__).resolve().parents[1] / ".venv" / "bin"),
            env.get("PATH", ""),
        ]
    )
    env.pop("VIBEGUARD_FAIL_ON", None)
    payload = json.dumps({"workspacePaths": [str(repo)]})

    medium = subprocess.run(
        ["bash", str(hook), "stop"],
        input=payload,
        text=True,
        capture_output=True,
        env=env,
        cwd=repo,
    )
    assert medium.returncode == 0, medium.stderr
    assert json.loads(medium.stdout) == {}

    (repo / "slop.py").unlink()
    token = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0"
    (repo / "keys.py").write_text("TOKEN = " + repr(token) + "\n", encoding="utf-8")
    critical = subprocess.run(
        ["bash", str(hook), "stop"],
        input=payload,
        text=True,
        capture_output=True,
        env=env,
        cwd=repo,
    )
    assert critical.returncode == 0, critical.stderr
    blocked = json.loads(critical.stdout)
    assert blocked["decision"] == "continue"
    assert "CRITICAL" in blocked["reason"]


def test_build_payload_and_layer2_snippets_redact_secrets() -> None:
    secret_a = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K2"
    secret_b = "sk-" + "proj-" + "Z9y8X7w6V5u4T3s2R1q0P9"
    auth_ctx = f'AUTH_TOKEN = "{secret_a}"'
    source = f'TOKEN = "{secret_b}"\ndef create():\n    return TOKEN\n'
    unit = _unit(source, name="create_order")
    chunk_units([unit], auth_ctx, max_tokens=10**9, max_modules=10)

    payload = build_payload(auth_ctx, [unit])
    assert secret_a not in payload["input"]
    assert secret_b not in payload["input"]
    assert "<redacted:" in payload["input"]

    scores = {
        rule_id: (0.95 if rule_id == "D3.missing_auth" else 0.05)
        for rule_id in LAYER2_RULE_IDS
    }
    findings, stats = judge(
        _ctx([unit], auth=auth_ctx),
        _FixedBackend(scores),
        DecisionCache(Path("unused"), enabled=False),
    )
    assert not stats.errors
    assert len(findings) == 1
    assert secret_b not in findings[0].snippet
    assert "<redacted:" in findings[0].snippet


def test_antigravity_hook_fails_closed_on_exit_2_broken_rules(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    init_git(repo, branch="trunk")
    (repo / ".vibeguard").mkdir()
    (repo / ".vibeguard" / "rules.json").write_text("{", encoding="utf-8")
    hook = (
        Path(__file__).resolve().parents[1]
        / "integrations"
        / "antigravity"
        / "vibeguard"
        / "scripts"
        / "vibeguard-hook.sh"
    )
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join(
        [
            str(Path(sys.executable).resolve().parent),
            str(Path(__file__).resolve().parents[1] / ".venv" / "bin"),
            env.get("PATH", ""),
        ]
    )
    payload = json.dumps({"workspacePaths": [str(repo)]})

    stop_run = subprocess.run(
        ["bash", str(hook), "stop"],
        input=payload,
        text=True,
        capture_output=True,
        env=env,
        cwd=repo,
    )
    assert stop_run.returncode == 0, stop_run.stderr
    stop_data = json.loads(stop_run.stdout)
    assert stop_data["decision"] == "continue"
    assert "exit 2" in stop_data["reason"]

    post_run = subprocess.run(
        ["bash", str(hook), "post-tool"],
        input=payload,
        text=True,
        capture_output=True,
        env=env,
        cwd=repo,
    )
    assert post_run.returncode == 0, post_run.stderr
    assert json.loads(post_run.stdout) == {}


def test_antigravity_hook_fails_closed_when_vibeguard_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").symlink_to(Path(sys.executable).resolve())
    hook = (
        Path(__file__).resolve().parents[1]
        / "integrations"
        / "antigravity"
        / "vibeguard"
        / "scripts"
        / "vibeguard-hook.sh"
    )
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([str(bin_dir), "/usr/bin", "/bin"])
    assert shutil.which("vibeguard", path=env["PATH"]) is None
    payload = json.dumps({"workspacePaths": [str(repo)]})

    stop_run = subprocess.run(
        ["bash", str(hook), "stop"],
        input=payload,
        text=True,
        capture_output=True,
        env=env,
        cwd=repo,
    )
    assert stop_run.returncode == 0, stop_run.stderr
    stop_data = json.loads(stop_run.stdout)
    assert stop_data["decision"] == "continue"
    assert "not on PATH" in stop_data["reason"]

    post_run = subprocess.run(
        ["bash", str(hook), "post-tool"],
        input=payload,
        text=True,
        capture_output=True,
        env=env,
        cwd=repo,
    )
    assert post_run.returncode == 0, post_run.stderr
    assert json.loads(post_run.stdout) == {}


def _auth_score(source: str, auth: str = "", **overrides: object) -> float:
    backend = OfflineHeuristicBackend()
    return _offline_scores(backend, _unit(source, **overrides), auth)["D3.missing_auth"]


def test_dependency_auth_uses_word_parts_and_ignores_comments() -> None:
    def handler(dep: str) -> str:
        return f'''
@app.post("/items")
def create(body: Item, db=Depends({dep})):
    db.execute("INSERT INTO items (sku) VALUES (%s)", (body.sku,))
'''

    assert _auth_score(handler("pagination")) >= 0.9
    assert _auth_score(handler("get_db")) >= 0.9
    assert _auth_score(handler("get_session")) >= 0.9
    assert _auth_score(handler("ensure_staff")) < 0.2
    assert _auth_score(handler("verify_pin_session")) < 0.2
    assert _auth_score(handler("get_current_session_user")) < 0.2
    secured = '''
@app.post("/items")
def create(body: Item, cred=Security(oauth2_scheme)):
    db.execute("INSERT INTO items (sku) VALUES (%s)", (body.sku,))
'''
    assert _auth_score(secured) < 0.2
    security_resource = '''
@app.post("/items")
def create(body: Item, cred=Security(pagination)):
    db.execute("INSERT INTO items (sku) VALUES (%s)", (body.sku,))
'''
    assert _auth_score(security_resource) < 0.2

    commented = '''
@app.post("/items")
def create(body: Item):
    # see Depends(require_user)
    note = "Depends(require_user)"
    db.execute("INSERT INTO items (sku) VALUES (%s)", (body.sku,))
'''
    assert _auth_score(commented) >= 0.9
    js_comment = """
router.post("/orders", async (req, res) => {
  // Depends(require_user)
  await db.insert({ sku: req.body.sku })
})
"""
    assert _auth_score(js_comment, file="server.js", language=Language.JAVASCRIPT, route_path="/orders") >= 0.9

    open_insert = '''
@app.post("/items")
def create(body: Item):
    db.execute("INSERT INTO items (sku) VALUES (%s)", (body.sku,))
'''
    assert (
        _auth_score(open_insert, "app.py:3: FastAPI(dependencies=[Depends(pagination)])") >= 0.9
    )
    assert (
        _auth_score(open_insert, "app.py:3: FastAPI(dependencies=[Depends(get_db)])") >= 0.9
    )
    assert (
        _auth_score(open_insert, "app.py:3: FastAPI(dependencies=[Depends(ensure_staff)])") < 0.2
    )

    express = '''
router.post("/orders", async (req, res) => {
  await db.insert({ sku: req.body.sku })
})
'''
    express_kwargs = {"file": "server.js", "language": Language.JAVASCRIPT, "route_path": "/orders"}
    assert _auth_score(express, "server.js:4: router.use(ensureStaff)", **express_kwargs) < 0.2
    assert _auth_score(express, "server.js:4: router.use(pagination)", **express_kwargs) >= 0.9
    wrapped = '''
router.post("/orders", async (req, res) => {
  await withMember()
  await db.insert({ sku: req.body.sku })
})
'''
    assert _auth_score(wrapped, **express_kwargs) < 0.2
    timed = '''
router.post("/orders", async (req, res) => {
  await withTimeout()
  await db.insert({ sku: req.body.sku })
})
'''
    assert _auth_score(timed, **express_kwargs) >= 0.9


def test_unauth_rejection_requires_a_credential_condition() -> None:
    bare = '''
@app.post("/items")
def create(body: Item):
    raise HTTPException(status_code=401, detail="unknown sku")
    db.execute("INSERT INTO items (sku) VALUES (%s)", (body.sku,))
'''
    assert _auth_score(bare) >= 0.9
    metrics = '''
@app.post("/items")
def create(body: Item):
    metrics.record(status_code=401)
    db.execute("INSERT INTO items (sku) VALUES (%s)", (body.sku,))
'''
    assert _auth_score(metrics) >= 0.9
    signed = '''
@app.post("/items")
def create(request: Request, body: Item):
    if not request.headers.get("x-signature"):
        raise HTTPException(401)
    db.execute("INSERT INTO items (sku) VALUES (%s)", (body.sku,))
'''
    assert _auth_score(signed) < 0.2
    one_line = '''
@app.post("/items")
def create(request: Request, body: Item):
    if not request.headers.get('x-signature'): raise HTTPException(401)
    db.execute("INSERT INTO items (sku) VALUES (%s)", (body.sku,))
'''
    assert _auth_score(one_line) < 0.2
    unrelated = '''
@app.post("/items")
def create(body: Item):
    if not body.sku:
        raise HTTPException(status_code=401, detail="unknown sku")
    db.execute("INSERT INTO items (sku) VALUES (%s)", (body.sku,))
'''
    assert _auth_score(unrelated) >= 0.9
