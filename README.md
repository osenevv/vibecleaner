# VibeGuard

Pre-ship security & anti-slop harness for AI-generated apps.

VibeGuard audits Python (FastAPI / LangGraph / agent repos), TypeScript (Next.js App Router / Express / server actions) and Supabase SQL before you ship. It pairs a free, exact **tree-sitter gate** with Google's **`gemini-decision-1`** Decisions API, which answers atomic yes/no questions with calibrated probabilities and **zero output tokens**.

```
[repo | local path | --diff main]
        │  .gitignore-aware walker (skips node_modules, dist, lockfiles, symlinks, own reports)
        ▼
Layer 1  Deterministic gate — tree-sitter AST + regex, $0, < 1 s
         D1 secrets · D2 Supabase RLS / wildcard CORS · D6a AST slop
         + GLOBAL_AUTH_CONTEXT extractor + function-level route slicer
        │  only changed functions (with --diff), ≤ 30 modules / 30K tokens per request
        ▼
Layer 2  gemini-decision-1 — 1 atomic defect = 1 `noul` question per module
         D3 missing auth · D4 IDOR / price trust · D5 prompt injection
         D6b fake/stubbed logic · D7a N+1 / unbounded query · D7b missing schema
        │  findings with noul ≥ 0.75
        ▼
Layer 3  Terminal · VIBEGUARD_REPORT.md · SARIF 2.1.0 · JSON
         Security score + Anti-Slop score (0–100), file:line, rule id, probability
         optional --fix: generative unified diffs for critical findings only
```

## Install

```bash
pip install git+https://origin.cursor.com/git/osenevvova/tmp-6a743823052b442f.git
# or, from a checkout
pip install -e ".[dev]"
```

Python ≥ 3.10. Live Layer 2 needs a Gemini API key (`GEMINI_API_KEY` or `GOOGLE_API_KEY`). Without one, `--mode auto` falls back to an offline heuristic judge, so the tool always works and costs nothing.

## Usage

```bash
vibeguard scan .                          # full scan, writes VIBEGUARD_REPORT.md
vibeguard scan . --diff main              # only functions changed since main (PRs, hooks)
vibeguard scan . --sarif vibeguard.sarif  # SARIF for GitHub code scanning
vibeguard scan . --quiet                  # agent hooks: prints only `VIBEGUARD: PASS` when clean
vibeguard scan . --json                   # machine-readable output only
vibeguard scan . --fix                    # draft patches for critical findings (noul ≥ 0.85)
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--mode auto\|live\|offline\|off` | `auto` | `live` = gemini-decision-1, `offline` = heuristic judge, `off` = Layer 1 only, `auto` = live if a key is set |
| `--threshold` | `0.75` | `noul` cut-off for Layer 2 findings |
| `--fail-on critical\|high\|medium\|low\|none` | `high` | lowest severity that fails the run |
| `--report PATH` / `--no-report` | `<root>/VIBEGUARD_REPORT.md` | markdown report |
| `--no-cache` | off | ignore `.vibeguard_cache.json` |

Exit codes: `0` pass, `1` a finding at or above `--fail-on`, `2` usage, collector or API error. VibeGuard **fails closed**: a missing path, an unknown base ref or a failed Layer 2 request is an error, never a pass.

Add `.vibeguard_cache.json` and `VIBEGUARD_REPORT.md` to your `.gitignore`. Put paths you never want scanned in `.vibeguardignore` (gitignore syntax).

## Detectors

| Id | Layer | What it catches |
| --- | --- | --- |
| D1 | 1 | Committed `.env*` files, `NEXT_PUBLIC_*` variables holding private keys (service role, OpenAI, Stripe secret), known key formats, high-entropy literals (Shannon > 4.3) bound to secret-like names. Values are always redacted in output. |
| D2 | 1 | `CREATE TABLE` in Supabase migrations without `ENABLE ROW LEVEL SECURITY` or without `CREATE POLICY` (checked across all migrations); `allow_origins=["*"]` / `origin: '*'` combined with credentials. |
| D6a | 1 | `except Exception: pass`, bare `except:`, empty `catch {}`; god files (> 500 LOC mixing SQL, HTTP and business logic); deprecated SDK calls (`openai.ChatCompletion.create`, Pydantic v1 `@validator` / `.dict()`, `new OpenAIApi`); `*args, **kwargs` pass-through wrappers. |
| D6c | 1 | LLM prose tics in `.md`, `.mdx`, `.rst`, and `.html` docs. A high-precision slice of the [declauding](https://github.com/oaustegard/claude-skills/releases/tag/declauding-v0.13.0) register: chatbot residue, knowledge-cutoff disclaimers, stock vocabulary, copula avoidance, staged reveals, and docs that describe the change instead of the behavior. Low severity. Changelogs are skipped, and so are the declauding shapes that ordinary technical writing uses (bold-label lists, contrasts, short paragraphs, absolute negatives). |
| D3 | 2 | An unauthenticated caller can trigger a write or paid API call, considering middleware matchers and router-level dependencies. |
| D4 | 2 | Handler trusts `user_id`, `org_id`, `role`, `is_admin`, `price` or `amount` from the client. |
| D5 | 2 | User text in LLM system instructions, or untrusted input reaching shell, SQL, file-write or webhook tools without validation. |
| D6b | 2 | Production path returns hardcoded mock data or a TODO stub. |
| D7a | 2 | Queries or HTTP calls inside loops, unbounded selects without `LIMIT` or pagination. |
| D7b | 2 | Raw `dict` / `any` / `req.body` payloads instead of Pydantic or Zod at the boundary. |

### The Decisions API payload

Each Layer 2 request carries `[GLOBAL_AUTH_CONTEXT]` (~500 tokens: middleware matchers, `APIRouter(dependencies=...)`, auth helper signatures) plus up to 30 sliced modules. Every module gets six atomic `noul` questions plus one `score` question for overall risk:

```python
client.aio.decisions.create(
    model="gemini-decision-1",
    input="[GLOBAL_AUTH_CONTEXT]\n...\n\n[MOD_01] file=app/api/orders/route.ts lines=4-31 kind=route method=POST ...",
    questions={
        "MOD_01__missing_auth": {"type": "noul", "instructions": "Considering GLOBAL_AUTH_CONTEXT ... in MOD_01?",
                                 "criteria": {"true_description": "...", "false_description": "..."}},
        # ... idor_or_price_trust, prompt_injection, hardcoded_mock_stub, n_plus_one_loop, missing_boundary_schema
        "MOD_01__severity": {"type": "score", "instructions": "Rate the overall production risk of MOD_01.",
                             "criteria": ["Clean: ...", "Medium: ...", "Critical: ..."]},
    },
)
```

Question keys use `MOD_01__missing_auth` rather than `MOD_01::missing_auth` because the API only accepts `[A-Za-z0-9_-]+` keys. The model never sees the keys, so every instruction names its module.

### Token and cost controls

- **Function-level slicing:** only route handlers, server actions, tools and I/O functions are sent, never whole files. With `--diff`, only functions overlapping changed or deleted lines are sent.
- **Content-hash cache:** `sha256(question set + auth context + function source)`, with live and offline scores in separate namespaces. Unchanged functions cost 0 tokens.
- **Layer 1 → Layer 2 short-circuit:** a function with a critical Layer 1 hit (e.g. a leaked key) is not sent until that is fixed. Lower-severity hits never suppress Layer 2.
- **Silent on pass:** `--quiet` prints `VIBEGUARD: PASS` (~2 tokens) so agent context stays clean.
- Pricing is $0.10 per 1M input tokens and $0 output, so a typical PR diff costs well under $0.001.

## GitHub Action

```yaml
on: pull_request
permissions:
  contents: read
  security-events: write
jobs:
  vibeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: <owner>/vibeguard@main
        with:
          gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
          fail-on: high
```

On pull requests the action scans `--diff origin/<base_ref>`, appends the report to the job summary, uploads SARIF to code scanning, and fails the job on findings or errors. See `action.yml` for all inputs and `.github/workflows/vibeguard-example.yml` for a full example.

## Antigravity plugin

`integrations/antigravity/vibeguard/` is a plugin in Antigravity's documented layout (`plugin.json`, `hooks.json`, `rules/`, `skills/audit-code/SKILL.md`).

```bash
scripts/install_antigravity_plugin.sh                  # ~/.gemini/config/plugins/vibeguard
scripts/install_antigravity_plugin.sh --workspace .    # ./.agents/plugins/vibeguard
```

- **Stop hook:** at the end of each agent turn it runs `vibeguard scan . --diff $VIBEGUARD_BASE --quiet --fail-on $VIBEGUARD_FAIL_ON` (defaults `main` and `critical`). On a pass it returns `{}`, so nothing is injected into the context. On failure it returns `{"decision": "continue", "reason": ...}`, which keeps the agent working with the findings in its context. Scanner errors fail open with a message on stderr.
- **PostToolUse hook:** after file edits it runs Layer 1 only (`--mode off`, no API calls, no mid-edit Layer 2).
- **Rule:** the agent may not declare a task complete while critical findings remain.
- **Skill:** `/audit-code` runs a diff scan, reads the report and fixes findings by severity.

## Benchmarks

`benchmarks/run_eval.py` measures case-level precision, recall, F1, false positive rate (share of clean cases with any finding) and latency per detector and per layer. Each case is a small realistic app slice with detector-level labels.

```bash
python benchmarks/run_eval.py --mode offline                                   # 30-case dev set
python benchmarks/run_eval.py --labels benchmarks/blind_labels.json --mode live \
    --sweep 0.70,0.75,0.80,0.85 --write-results benchmarks/RESULTS_live_blind.md
```

There are three case sets, used differently to keep the numbers honest:

| Set | Cases | How it was used |
| --- | --- | --- |
| `positive/` + `negative/` | 15 + 15 | Dev set. Offline heuristics were tuned on it. |
| `holdout/` | 10 + 10 | Written blind. Measured once, then used to fix bugs, so it is no longer held out. |
| `blind/` | 12 + 12 | Written after the code was frozen, by an agent that never saw the scanner. Never used for tuning. |

Offline results at threshold 0.75 (no API key, $0, mean latency ~10 ms per case):

| Set | Precision | Recall | F1 | FPR | Layer 1 F1 | Layer 2 F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Dev (tuned on) | 1.000 | 1.000 | 1.000 | 0.00 | 1.000 | 1.000 |
| Holdout, first blind measurement | 0.600 | 0.900 | 0.720 | 0.30 | 1.000 | 0.632 |
| Holdout, after fixes | 1.000 | 1.000 | 1.000 | 0.00 | 1.000 | 1.000 |
| **Blind (honest number)** | **0.692** | **0.750** | **0.720** | **0.17** | **1.000** | **0.632** |

Takeaways: the deterministic layer is exact on every set. The offline Layer 2 heuristic generalizes to about 0.7 precision and recall on unseen code, which is why it is only the fallback. The real Layer 2 is `gemini-decision-1`, and those runs need a key: run the blind set with `--mode live --sweep 0.70,0.75,0.80,0.85` and pick the lowest threshold that keeps FPR under 5%. Full tables, including per-case results, are in `benchmarks/RESULTS_*.md`.

## Development

```bash
pip install -e ".[dev]"
pytest -q                                   # 69 tests, < 1 s, no network
python benchmarks/run_eval.py --mode offline
vibeguard scan . --mode offline             # VibeGuard passes its own gate
scripts/demo.sh                             # ~40 s terminal demo on a throwaway vibe-coded app
```

| Module | Responsibility |
| --- | --- |
| `models.py` | Shared contract: rule registry, Layer 2 questions, `CodeUnit`, `Finding`, `ScanResult` |
| `collector.py`, `ts_parse.py` | Walker, `--diff` hunks, auth-context extraction, function-level slicing (tree-sitter) |
| `deterministic.py` | Layer 1 detectors and secret masking |
| `decision_judge.py`, `cache.py` | Layer 2 chunking, payloads, async Gemini backend, cache |
| `offline_heuristics.py` | Zero-network fallback judge |
| `reporter.py`, `patcher.py`, `redact.py` | Terminal, Markdown, SARIF and JSON output, `--fix` diffs, redaction |
| `pipeline.py`, `cli.py`, `settings.py` | Orchestration and CLI |

### How it was built

The plan's multi-agent build protocol was followed. Claude Opus 5.5 orchestrated: it wrote the shared schema contract (`models.py`), split the work, integrated it and verified the results. Grok 4.7 subagents did the building:

1. **Parallel builders:** A wrote Layer 1 and the parser, B wrote Layer 2, the cache, the CLI and the reporter, and C wrote the eval harness and fixtures. They worked at the same time against the contract.
2. **Calibration, holdout and packaging:** three more parallel agents.
3. **Adversarial cold critic:** found 18 verified defects, including fail-open paths, secret leaks in JSON output and overfit auth heuristics. Two fixers resolved them, and a critic verification pass caught 3 regressions, which were then fixed.
4. **Frozen blind set:** written by a fresh agent after the code was frozen, for the honest number above.

## Limitations

- Offline heuristics are regex and indentation based; use live mode for real audits.
- Auth defined in another file and applied by path prefix is resolved only through the global auth context, not full import resolution.
- `--fix` uses a generative Gemini model (`VIBEGUARD_FIX_MODEL`, default `gemini-2.5-flash`). It drafts diffs for review and never applies them.
- Live `gemini-decision-1` accuracy has not been measured in this repo yet (no API key during the build).
- D6c reports lexical prose candidates only. Declauding's rewrite, embedding ranker, structural review of headers and closers, and newcomer-read hook are not part of the scan.
