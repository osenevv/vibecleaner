# Changelog

All notable changes to VibeCleaner (`vibecleaner`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Target-app test coverage audit & missing test suite generator (`vibecleaner tests`)**:
  - Audits Python and TypeScript/JavaScript repositories for missing module test suites, untested public symbols, missing error/rejection paths, lackluster tests (assertionless, tautological, weak JS matchers, skipped/focused, mock-heavy), and optional dynamic line coverage (`--run-coverage` via Python 3.12 `sys.monitoring` / Python 3.11 `sys.settrace` and JS/TS Istanbul `coverage/coverage-summary.json`).
  - Generates and sandbox-verifies missing `pytest` / `vitest` / `jest` test suites (`--generate`) without overwriting existing tests, plus `--prompt`, `--copy`, and tamper-guarded `--autofix` support.
- **Environment & repo diagnostics (`vibecleaner doctor`)**: Checks Python version, Git, Node, Docker daemon reachability, Layer 2 API keys, installed coding-agent CLIs, and `.vibecleaner/` config/rules validity (`--json` supported).
- **CI & GitHub Action enhancements**: Added `min-test-score` input to `action.yml`, `pip-audit` dependency check and expanded `wheel-smoke` checks (`doctor`, `tests`, `preflight`) in `.github/workflows/ci.yml`.

### Fixed & Hardened (System-Wide Post-Fix Safety & Detector Precision)
- **Cross-platform Windows & Python 3.11 compatibility**:
  - Preserved exact line endings (`newline=""`) when restoring original file contents in `cleanup.py` (`revert_rule` and `_restore_others`), fixing doubled CRLF newlines on Windows.
  - Guarded POSIX `os.getuid`/`os.getgid` in `verify/sandbox.py` and stripped surrounding quotes from `--agent` commands on Windows in `prompt_fix.py`.
- **Regression-aware post-fix test gate (`repo_health.py`, `cleanup.py`)**: `run_local_gates_detailed` + `gate_regression` now diff failure signatures (`post - baseline`) instead of treating any pre-existing failing test as a reason to skip verification. Newly introduced test failures now trigger automatic per-rule isolation and rollback even on repositories with pre-existing failures. Also skips broken `.venv` symlinks cleanly and falls back to working Python interpreters.
- **Dynamic patch-target & module-attribute verification (`repo_health.py`)**: `verify_static_tree` now verifies `monkeypatch.setattr("pkg.mod.attr", ...)`, `patch("pkg.mod.attr", ...)`, and module-attribute references (`mod.attr`) across all repo files (including tests) against touched modules.
- **HTML/CSS surface invariant verifier & custom-design preservation (`repo_health.py`, `surface_rules.py`, `cleanup.py`)**:
  - Removed blunt global `border-radius: 50%`/`999px` (`_PILL`) and `box-shadow` (`_SHADOW`) regex stripping from `cleanup.py` so circular buttons, status dots, scrollbars, and intentional elevation are never destroyed.
  - Documents that already define their own `:root` CSS custom-property design system (`>= 3` `--*` tokens) keep their intentional `font-weight`, `box-shadow`, `border-radius`, and non-purple colors; `surface.chrome` only removes objective AI slop (gradients, glassmorphism, `lorem ipsum`, empty `<p></p>`, keyboard `Tab` traps).
  - `surface_rules.py` never rewrites hex colors inside CSS custom property declarations (`--*`) or theme selectors (`:root`, `:root:not([data-theme])`, `:root[data-theme="dark"]`, `.dark`, `.light`), preserving dark-mode palettes and skipping whitespace-only churn on untouched rules.
  - `_ensure_checks` never injects a `<style data-vibecleaner="design">` block that clobbers custom properties already defined by the document.
  - `verify_surface_health` enforces CSS/tag balance, no malformed CSS declarations, zero palette collapse (distinct color tokens cannot collapse to one value), and zero token clobbering on every HTML/CSS edit.
- **Module-scoped, AST-aware passthrough wrapper inlining (`structure.py`)**: `D6a.passthrough_wrapper` now resolves imports to exact canonical modules (never rewriting same-named symbols imported from other modules), refuses to delete symbols referenced via dotted patch strings, module attributes, aliases, or star imports, and rewrites references via AST spans instead of bare regex replacement.
- **Layer-aware, domain-safe implicit coupling (`structure.py`)**: `_rank` now inspects both directory parts and module stems (`database`, `storage`, `web`, `cli`, `gui`, `desktop`, etc.), preventing storage layers from importing higher layers and preventing unrelated peer modules from being coupled over generic keys.
- **Detector precision (`production.py`, `states.py`)**:
  - `D5.unsafe_sink` skips static-literal `.innerHTML = '...'` assignments and parameterized SQL queries whose interpolated fragments are provably compile-time constants or `?` placeholder clauses.
  - `D8.retry_falls_through` requires the `try` body to exit on success (`return`/`break`), avoiding false positives on per-item `for i in range(...)` loops; `D8.unbounded_retry` skips `while True:` worker loops with an explicit pre-`try` sentinel exit (`if item is None: return`).

## [0.1.0] - 2026-11-20

### Added
- Layer 1 deterministic scanner (`D1`–`D2`, `D6a`, `D6c`, `D8`, `D9`, and project rules `P.*`) for Python, TypeScript, JavaScript, and Supabase SQL.
- Layer 2 semantic checks (`D3`, `D4`, `D5`, `D6b`, `D7a`, `D7b`) via `gemini-decision-1` with a zero-network offline heuristic fallback and content-hash caching.
- CLI subcommands: `scan`, `deslop`, `states`, `preflight`, `rule`, `init`, `start`, and `version`.
- Plain-English risk output, `--prompt`, `--copy`, `--fix` draft diffs, and `--autofix` agent loop with tamper-guard protection against test weakening.
- Terminal, Markdown, JSON, and SARIF reporters, file risk scoring (tiers 1–4), and a composite GitHub Action (`action.yml`).
- Antigravity plugin bundle (`vibecleaner init --antigravity`) with Stop and PostToolUse hooks.
