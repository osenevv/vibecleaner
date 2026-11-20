# VibeCleaner (`vibeguard`)

Pre-ship security and anti-slop checks for AI-generated Python, TypeScript, and Supabase apps.

VibeCleaner catches leaked keys, missing Supabase Row Level Security, unauthenticated write routes, client-trusted prices, prompt injection, and AI code slop before you deploy. It runs a fast local tree-sitter gate ($0, < 1 s) followed by `gemini-decision-1` semantic checks (or a zero-network offline fallback when no API key is set).

## Quick start

```bash
pip install vibecleaner
# or, from a local checkout
pip install -e ".[dev]"

vibecleaner init        # updates .gitignore, installs pre-push hook and detected editor rules
vibecleaner             # scans the repo, explains risks in plain English, prints a Fix Prompt
vibecleaner --autofix   # hands the Fix Prompt to claude/codex/gemini/agy (or clipboard) and re-scans
```

(`vibeguard` is also installed as an alias for all commands.)

Requires Python 3.10+. Export `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) to enable live `gemini-decision-1` checks. Without a key, `--mode auto` uses the offline heuristic judge at $0.

## How it works

```
[repo | path | --diff main]
        |  .gitignore-aware walker (skips node_modules, dist, lockfiles, symlinks, own reports)
        v
Layer 1  Deterministic gate (tree-sitter AST + regex, $0, < 1 s)
         D1 secrets, D2 Supabase RLS / wildcard CORS, D6a AST slop
         D6c prose tics, D8 state transitions, D9 deslop, project rules P.*
         + GLOBAL_AUTH_CONTEXT extractor and function-level route slicer
        |  with --diff: Layer 1 on changed files, Layer 2 on changed functions
        |  <= 30 modules / 30K tokens per request
        v
Layer 2  gemini-decision-1 (one yes/no question per defect, zero output tokens)
         D3 missing auth, D4 IDOR / price trust, D5 prompt injection
         D6b fake/stubbed logic, D7a N+1 / unbounded query, D7b missing schema
        |  findings at probability >= 0.75
        v
Layer 3  Terminal (plain-English summary + Fix Prompt), VIBEGUARD_REPORT.md, SARIF 2.1.0, JSON
         Security and Anti-Slop scores (0-100), review tier 1-4, optional --fix diffs
```

## Commands

```bash
vibeguard init                            # set up .gitignore, pre-push hook, and editor rules
vibeguard                                 # default: runs `vibeguard scan .`
vibeguard --autofix                       # run installed agent CLI (or copy prompt to clipboard) and re-scan
vibeguard --prompt                        # print only the plain-English AI Fix Prompt
vibeguard --copy                          # scan and copy the Fix Prompt to your clipboard
vibeguard scan . --diff main              # Layer 1 on changed files; Layer 2 on changed functions
vibeguard scan . --sarif vibeguard.sarif  # SARIF output for GitHub code scanning
vibeguard scan . --quiet                  # agent hooks: prints only `VIBEGUARD: PASS` when clean
vibeguard scan . --json                   # machine-readable output, including `review`
vibeguard scan . --fix                    # draft unified diffs for critical findings (p >= 0.85)
vibeguard deslop .                        # group slop into 8 cleanup lanes (VIBEGUARD_DESLOP.md)
vibeguard preflight .                     # 42 read-only launch checks (VIBEGUARD_PREFLIGHT.md)
vibeguard states .                        # state machines and stuck transitions (VIBEGUARD_STATES.md)
vibeguard rule list                       # list project rules from .vibeguard/rules.json
vibeguard rule add-pattern ID --pattern 'REGEX' --message 'MSG' --lane ai-slop --preview
vibeguard rule add-boundary ID --from 'GLOB' --forbid 'PKG' --message 'MSG' --preview
```

Key `scan` flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--mode auto\|live\|offline\|off` | `auto` | `live` = `gemini-decision-1`, `offline` = heuristic judge, `off` = Layer 1 only, `auto` = live if a key is set |
| `--threshold` | `0.75` | probability cut-off (`0.01` to `0.99`) |
| `--fail-on critical\|high\|medium\|low\|none` | `high` | lowest severity that exits 1 (`deslop` defaults to `medium`) |
| `--report PATH` / `--no-report` | `<root>/VIBEGUARD_REPORT.md` | markdown report path |
| `--no-cache` | off | bypass `.vibeguard_cache.json` |
| `--autofix` / `--agent CMD` / `--max-fix-rounds N` | off / auto / `1` | invoke an agent CLI (`claude`, `codex`, `gemini`, `agy`, or custom command) and re-scan |

Exit codes: `0` pass, `1` finding at or above `--fail-on` (or a preflight blocker), `2` usage, collector, API, or rules-file error. VibeGuard fails closed: a missing path, unknown base ref, failed Layer 2 request, or broken `.vibeguard/rules.json` exits `2`, never `0`.

`vibeguard init` adds `.vibeguard_cache.json` and `VIBEGUARD_*.md` to `.gitignore`. Put paths you never want scanned in `.vibeguardignore` (gitignore syntax).

## Detectors

| Id | Layer | What it catches |
| --- | --- | --- |
| D1 | 1 | Committed `.env*` files, `NEXT_PUBLIC_*` private keys, known key formats, and high-entropy literals (Shannon > 4.3) bound to secret-like names. VibeGuard redacts secret values in all output and model payloads. |
| D2 | 1 | `CREATE TABLE` in Supabase migrations without `ENABLE ROW LEVEL SECURITY` or without `CREATE POLICY` (checked across all migrations); wildcard CORS combined with credentials. |
| D6a | 1 | Silent exception handlers (`except Exception: pass`, bare `except:`, empty `catch {}`); god files (> 500 LOC mixing SQL, HTTP, and business logic); deprecated SDK calls (`openai.ChatCompletion.create`, Pydantic v1 `@validator`/`.dict()`, `new OpenAIApi`); `*args, **kwargs` pass-through wrappers. |
| D6c | 1 | AI prose slop in `.md`, `.mdx`, `.rst`, and `.html` docs: chatbot residue, cutoff disclaimers, buzzwords, significance puffery, emphasis crutches, temporal clichés, weasel attribution, and meta-commentary. Low severity; skips changelogs and ordinary technical writing. |
| D8 | 1 | Stuck state transitions: unbounded `while True` / `while (true)` retries whose try block never exits, bounded retries that fall through after failure, and `acquire`/`lock` calls missing `with`/`using`/`finally` release on the same receiver. |
| D9 | 1 | Deslop: weak types (`any`, `as any`, `as unknown as`, bare `# type: ignore`, whole-annotation `Any`), debug leftovers (`debugger`, `breakpoint()`, `console.log` outside tests/scripts), AI comment slop (in-progress narration, banner dividers, `Step N:` walkthroughs, empty labels, decorative emoji, block end-markers), `_old`/`_legacy`/`_v1` copies, rethrow-only catches, unused privates, duplicate function bodies, circular imports. |
| D3 | 2 | Unauthenticated write or paid API endpoints, accounting for middleware matchers and router-level dependencies. |
| D4 | 2 | Handlers trusting client-supplied `user_id`, `org_id`, `role`, `is_admin`, `price`, or `amount`. |
| D5 | 2 | User input concatenated into LLM system instructions, or untrusted input reaching shell, SQL, file-write, or webhook tools without validation. |
| D6b | 2 | Production paths returning hardcoded mock data or TODO stubs. |
| D7a | 2 | Database or HTTP calls inside loops, or unbounded selects missing `LIMIT`/pagination. |
| D7b | 2 | Raw unvalidated `dict`/`any`/`req.body` payloads instead of Pydantic or Zod at the boundary. |

### Token and cost controls

- **Function-level slicing:** VibeGuard sends only route handlers, server actions, tools, and I/O functions to Layer 2. With `--diff`, Layer 2 checks only functions overlapping changed lines while keeping global auth context from the full repo.
- **Content-hash cache:** `sha256(question set + auth context + function source)` with separate live and offline namespaces. Unchanged functions cost 0 tokens.
- **Short-circuit:** VibeGuard skips Layer 2 for any function that already has a critical Layer 1 hit (such as a leaked key).
- **Low token cost:** `gemini-decision-1` uses $0.10 per 1M input tokens and $0 output tokens (a typical PR diff costs under $0.001).

## Deslop

`vibeguard deslop` groups Layer 1 slop findings (`D6a`, `D6c`, `D8`, `D9`, and `P.*`) into eight cleanup lanes (`dedupe`, `types`, `dead-code`, `cycles`, `weak-types`, `defensive-code`, `legacy`, `ai-slop`) and writes `VIBEGUARD_DESLOP.md`. Score runs from `0` to `100` (`100` = no slop findings; weights: low 1, medium 3, high 6, budget 10 points per file). Default `--fail-on` is `medium`.

## Launch preflight

`vibeguard preflight .` runs 42 read-only launch checks and writes `VIBEGUARD_PREFLIGHT.md` (inferred summary, detected stack, and per-check status, evidence, consequence, and manual verification steps). It exits `1` when a blocker appears in section B or C, or on check 25 (stock/booking races) or check 30 (automated tests).

Static checks inspect code with comments and string literals stripped, plus Layer 1 findings. Checks that require a running environment (sign-in flows, two-account isolation, test payments, backup restores, DNS/SPF/DKIM, vendor dashboards) stay `Not checked` with the exact manual check to run.

Measured runs:

| Tree | Summary line | Exit |
| --- | --- | --- |
| This repository | `1 ok, 2 warning, 6 not checked, 33 not applicable; 0 blocker(s)` | 0 |
| `benchmarks/positive/p08_client_price_checkout` | `3 warning, 5 problem, 16 not checked, 18 not applicable; 3 blocker(s)` | 1 |
| `benchmarks/blind/positive/b12_donor_note_rawbody` | `3 warning, 1 problem, 10 not checked, 28 not applicable; 1 blocker(s)` | 1 |

## Project rules

Turn recurring review corrections into deterministic Layer 1 rules in `.vibeguard/rules.json` (reported as `P.<id>`). Pattern rules match regexes against comment- and string-blanked lines; boundary rules block forbidden imports across directory globs (supporting Python dotted paths and TypeScript `@/` aliases). Use `--preview` to test before saving. Invalid rules files exit `2`.

```bash
vibeguard rule add-pattern useeffect-internal \
  --pattern 'useEffect\s*\(' \
  --include '**/*.ts' --include '**/*.tsx' \
  --exclude 'framework/**' \
  --message 'useEffect is restricted to framework internals' \
  --learned-from 'A component used useEffect to load data.' \
  --preview

vibeguard rule add-boundary ui-no-db \
  --from 'components/**' \
  --forbid '../lib/db' --forbid 'lib/db' \
  --message 'UI components may not import the database layer' \
  --learned-from 'A component imported the database client.' \
  --preview
```

## Review routing

Full terminal scans print `review tier N: reason` (and JSON exposes `review.tier`, `review.reason`, `review.human_review`, `review.file_risk`):

| Tier | Trigger | Action |
| --- | --- | --- |
| 1 | Only low-risk files, static checks clean | Auto-approve |
| 2 | Medium-risk files (API, data, jobs) or low-risk findings | Automated review and tests |
| 3 | Any high-risk file (auth, billing, crypto, migrations), or a critical finding in a non-high-risk file | Human review of listed files |
| 4 | Critical finding in a high-risk file | Security review required |

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
      - uses: osenevv/vibecleaner@v0.1.0
        with:
          gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
          fail-on: high
```

Scans `--diff origin/<base_ref>`, writes the job summary, uploads SARIF, and fails closed on findings or errors. See `action.yml`, `.github/workflows/vibeguard-example.yml`, and `.github/workflows/vibeguard-weekly.yml`.

## Antigravity plugin

`integrations/antigravity/vibeguard/` provides Stop and PostToolUse hooks, rules, and skills (`audit-code`, `deslop`, `preflight`, `correct`). Install into your workspace with `vibeguard init --antigravity`, or globally with `scripts/install_antigravity_plugin.sh`.

- **Stop hook:** runs `vibeguard scan . --diff $VIBEGUARD_BASE --quiet --fail-on $VIBEGUARD_FAIL_ON` at the end of each turn. Passes silently (`{}`); on findings or scanner errors (`exit 2`), returns `{"decision": "continue", "reason": ...}` so the agent fixes them before stopping.
- **PostToolUse hook:** runs Layer 1 only (`--mode off`) after file edits.

## Benchmarks

`benchmarks/run_eval.py` evaluates case-level precision, recall, F1, false positive rate (FPR), and latency across three labeled sets (D1, D2, D3, D4, D5, D6a, D6b, D7a, D7b). Unscored detectors (`D6c`, `D8`, `D9`, `P.*`) are reported separately. Offline runs block outbound sockets and fail closed on judge errors or mode mismatches.

```bash
python benchmarks/run_eval.py --mode offline                                   # 30-case dev set
python benchmarks/run_eval.py --labels benchmarks/holdout_labels.json --mode offline
python benchmarks/run_eval.py --labels benchmarks/blind_labels.json --mode offline
```

Offline results at threshold `0.75` ($0, no API key):

| Set | Cases | Precision | Recall | F1 | FPR | Layer 1 F1 | Layer 2 F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Dev | 15 + 15 | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 |
| Holdout (first blind run) | 10 + 10 | 0.600 | 0.900 | 0.720 | 0.300 | 1.000 | 0.632 |
| Holdout (after fixes) | 10 + 10 | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 |
| Blind (first run, `RESULTS_offline_blind.md`) | 12 + 12 | 0.600 | 0.750 | 0.667 | 0.250 | 1.000 | 0.571 |
| **Blind (`RESULTS_offline_blind_v2.md`)** | 12 + 12 | **1.000** | **1.000** | **1.000** | **0.000** | **1.000** | **1.000** |

The offline heuristic is the zero-network fallback. For live audits, run with `GEMINI_API_KEY` and `--mode live --sweep 0.70,0.75,0.80,0.85` to pick the lowest threshold under 5% FPR. Full per-case tables are in `benchmarks/RESULTS_*.md`.

## Development

```bash
pip install -e ".[dev]"
pytest -q
python benchmarks/run_eval.py --mode offline
vibeguard scan . --mode offline --no-cache --quiet
vibeguard deslop .
```

## Data & Privacy

- **`--mode offline` and `--mode off`:** 100% local. No network requests are made and no source code leaves your machine.
- **`--mode live` (or `--mode auto` with an API key set):** Sends redacted function slices (with detected secrets masked) and the global auth-context summary to the configured Decisions API (`gemini-decision-1`). Results are cached locally in `.vibeguard_cache.json` by content hash.
- **`--fix`:** Sends flagged function bodies to `VIBEGUARD_FIX_MODEL` (default `gemini-2.5-flash`) to draft diffs for review.
- **`--autofix`:** Runs your locally installed coding agent CLI (`claude`, `codex`, `gemini`, or `agy`) in the repository and rejects edits that weaken or delete tests.

## Limitations

- Offline heuristics use regex and indentation rules; use live mode for production security audits.
- VibeCleaner resolves cross-file path-prefix auth through the global auth context, not a full import graph.
- `--fix` uses a generative Gemini model (`VIBEGUARD_FIX_MODEL`, default `gemini-2.5-flash`) to draft diffs for review and never applies them directly.
- We have not benchmarked live `gemini-decision-1` accuracy in this repository because live runs require an API key.
