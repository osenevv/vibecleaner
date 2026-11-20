# Changelog

All notable changes to VibeCleaner (`vibeguard`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-20

### Added
- Layer 1 deterministic scanner (`D1`–`D2`, `D6a`, `D6c`, `D8`, `D9`, and project rules `P.*`) for Python, TypeScript, JavaScript, and Supabase SQL.
- Layer 2 semantic checks (`D3`, `D4`, `D5`, `D6b`, `D7a`, `D7b`) via `gemini-decision-1` with a zero-network offline heuristic fallback and content-hash caching.
- CLI subcommands: `scan`, `deslop`, `states`, `preflight`, `rule`, `init`, `start`, and `version`.
- Plain-English risk output, `--prompt`, `--copy`, `--fix` draft diffs, and `--autofix` agent loop with tamper-guard protection against test weakening.
- Terminal, Markdown, JSON, and SARIF reporters, file risk scoring (tiers 1–4), and a composite GitHub Action (`action.yml`).
- Antigravity plugin bundle (`vibecleaner init --antigravity`) with Stop and PostToolUse hooks.
