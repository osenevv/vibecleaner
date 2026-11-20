---
name: audit-code
description: >-
  Audit the current repository with VibeGuard, read VIBEGUARD_REPORT.md, and
  fix security and slop findings by severity until the scan passes. Use when
  the user asks to audit, review, or clean AI-generated code before shipping.
compatibility: >-
  Requires the vibeguard CLI on PATH. Set GEMINI_API_KEY or GOOGLE_API_KEY
  for live Layer 2; without a key, --mode auto uses the offline heuristic.
---

# Audit code with VibeGuard

Run this from the repository root.

1. Scan the change against `main`:

   ```bash
   vibeguard scan --diff main
   ```

   If `main` is not a git ref, or the directory is not a git repository, run a full scan instead:

   ```bash
   vibeguard scan .
   ```

2. Read `VIBEGUARD_REPORT.md` in the repository root. It lists each finding with severity, file, and line.
3. Fix findings by severity: critical, then high, then medium, then low. Change the code so the pattern is gone. Do not suppress a rule, skip a file, or weaken `--fail-on` to get a pass.
4. Re-run the same scan. Repeat until the process exits 0. Check with `vibeguard scan --diff main --quiet`: a clean tree prints exactly `VIBEGUARD: PASS`.
5. Use `--fix` when you want draft unified diffs for critical findings (`vibeguard scan --diff main --fix`). Read each draft, apply it only if it is a real fix, and scan again. `--fix` does not close medium or low findings; those still need a manual edit.

Live Layer 2 calls `gemini-decision-1` when `GEMINI_API_KEY` or `GOOGLE_API_KEY` is set. `--mode auto` falls back to the offline heuristic when neither key is present. Pass `--mode off` only for a fast Layer 1 check, not as the final audit.
