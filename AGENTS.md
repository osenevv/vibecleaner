# Agents working on VibeCleaner

This file is the map for agents changing VibeCleaner itself. VibeCleaner scans Python (FastAPI, LangGraph), TypeScript (Next.js, Express, server actions), and Supabase SQL for security holes and slop.

## Checks

Run these from the repository root. The scan command must print `VIBECLEANER: PASS`.

Active work happens on feature branches off `main` (which includes `init`, `--autofix`, the landmines tests, and the fixer groundwork).

A sandboxed shell cannot create `.git/config`, `.git/hooks`, `.cursor`, or `.claude`. Tests initialize git through `tests/gitutil.py`, which falls back to `git init --separate-git-dir`. `vibecleaner init` records a skipped action when an editor directory cannot be written, and the command still exits 0.

Colima's Docker socket is outside the workspace, so the sandbox cannot open it. Run `python scripts/ensure_docker.py` outside the sandbox (it starts Colima when the socket is missing) and export the `DOCKER_HOST` line it prints. Sandboxed `docker` commands then use that TCP address.

```bash
.venv/bin/pytest -q
.venv/bin/python benchmarks/run_eval.py --mode offline
.venv/bin/python benchmarks/run_eval.py --labels benchmarks/holdout_labels.json --mode offline
.venv/bin/python benchmarks/run_eval.py --labels benchmarks/blind_labels.json --mode offline
.venv/bin/vibecleaner scan . --mode offline --no-cache --quiet
.venv/bin/vibecleaner deslop .
```

`deslop` writes `VIBECLEANER_DESLOP.md`. Its default `--fail-on` is `medium`, so a medium slop finding exits 1. `states` writes `VIBECLEANER_STATES.md` and defaults to `--fail-on high`.

## Architecture

`models.py` is the contract every layer shares: `RULES` (`RuleSpec`), `CodeUnit`, `Finding`, `ScanResult`, `ReviewRouting`, `Severity`, `Category`. A finding's severity, category, and layer come from its `RuleSpec`. Project rules register as `P.<id>` through `register_project_rule` and stay Layer 1.

| Module | Layer | Responsibility |
| --- | --- | --- |
| `collector.py`, `ts_parse.py` | 1 | Walk the tree, apply `--diff`, extract auth context, slice functions |
| `deterministic.py` | 1 | D1 secrets, D2 RLS and CORS, D6a AST slop; calls the other Layer 1 detectors |
| `prose.py` | 1 | D6c prose tics in `.md`, `.mdx`, `.rst`, `.html` |
| `states.py` | 1 | D8 machines, invariants, transitions that cannot finish |
| `deslop.py` | 1 | D9 weak types, debug leftovers, larp comments, legacy copies, pointless catches, unused privates, duplicate bodies, import cycles |
| `project_rules.py` | 1 | `.vibecleaner/rules.json` pattern and import-boundary rules |
| `decision_judge.py`, `cache.py` | 2 | `gemini-decision-1` questions, chunking, content-hash cache |
| `offline_heuristics.py` | 2 | Zero-network judge for D3, D4, D5, D6b, D7a, D7b |
| `risk.py` | — | File risk and review tier 1–4, attached to every scan |
| `pipeline.py` | — | Collect, Layer 1, Layer 2, optional `--fix` drafts |
| `cli.py`, `commands.py` | — | `scan`, `states`, `deslop`, `preflight`, `rule` |
| `preflight/` | — | Read-only 42-check launch report (`engine`, `section_a`–`section_e`, `render`, `code_text`) |
| `reporter.py`, `patcher.py`, `redact.py`, `settings.py` | 3 | Terminal, Markdown, SARIF, JSON, redaction, `--fix` diffs |

Layer 1 makes no network calls. Layer 2 sends one atomic yes/no question per defect. Layer 3 prints the result. The full terminal report includes `review tier N: reason`. JSON carries the same data under `review`.

With `--diff`, Layer 1 runs on changed files and Layer 2 on functions that overlap those lines. `human_review` is the high-risk files plus every file with a critical finding, at most 25 on a full scan. Path stems are split on camelCase, and risk signals ignore comments and strings. `D8.*` is the defensive-code deslop lane. A project pattern may set `lane` to one of the eight lane names; otherwise it is `ai-slop`.

## Conventions

- Preserve behavior. Before an edit, write the equivalence: same inputs, returns, errors, side effects, and order.
- Do not swallow an exception. Catch the narrow type and log, translate, or re-raise.
- Add a test with every fix. A lookalike that should stay clean gets a test too.
- Keep functions small and single-purpose.
- A comment states a constraint the code cannot show. Do not narrate the edit in progress.
- Never commit a secret. Fixtures build a fake key by concatenation, as in `"sk_" + "live_" + "..."`.

## Adding a detector

1. Add a `RuleSpec` to `RULES` in `models.py`: id, detector, title, category, severity, layer, remediation. Layer 2 also needs `question`, `true_description`, and `false_description`.
2. Implement the check. Layer 1 hooks it from `run_deterministic`. Layer 2 rides the existing question loop.
3. Add a failing test and a clean lookalike. Run `.venv/bin/pytest -q`.
4. The eval harness scores D1, D2, D3, D4, D5, D6a, D6b, D7a, and D7b. Hits from any other detector are listed as unscored. FPR is the share of clean cases with a finding from a labeled detector; unscored detectors do not move it. Record that in the results note. Leave the frozen label sets unchanged.

## Corrections

When a review correction will recur, put it in `.vibecleaner/rules.json` with `vibecleaner rule add-pattern` or `vibecleaner rule add-boundary`. Preview with `--preview` until the rule flags the bad cases and leaves legitimate code alone, then save with `--learned-from`. `--preview` does not register the rule. A pattern may set `--lane` to one of `dedupe`, `types`, `dead-code`, `cycles`, `weak-types`, `defensive-code`, `legacy`, `ai-slop`; omit it and deslop uses `ai-slop`. A `{` or `}` in a glob is an error: list each glob separately. A non-glob `--forbid` matches the package specifier and a prefix of the resolved repo path (dotted Python names, and `@/` with or without `src/`). A broken rules file makes `scan`, `deslop`, `preflight`, and `rule list` exit 2. Add a sentence to this file only when no pattern, boundary, type constraint, or test can express the correction.
