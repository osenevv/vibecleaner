---
name: audit-code
description: >-
  Audit the current repository with VibeCleaner, read VIBECLEANER_REPORT.md, and
  fix security and slop findings by severity until the scan passes. Use when
  the user asks to audit, review, or clean AI-generated code before shipping.
compatibility: >-
  Requires the vibecleaner CLI on PATH. Set GEMINI_API_KEY or GOOGLE_API_KEY
  for live Layer 2; without a key, --mode auto uses the offline heuristic.
---

# Audit code with VibeCleaner

Run this from the repository root.

1. Scan the change against `main`:

   ```bash
   vibecleaner scan --diff main
   ```

   If `main` is not a git ref, or the directory is not a git repository, run a full scan instead:

   ```bash
   vibecleaner scan .
   ```

   The full terminal report prints `review tier N: reason`. `--quiet` omits that line; `--json` puts the same data in `review` (`tier`, `reason`, `human_review`, `file_risk`).

2. Act on the tier before editing further:
   - Tier 1: static checks passed on low-risk files. Continue.
   - Tier 2: automated review and tests cover the change. Continue, and run the tests.
   - Tier 3: stop. Ask a person to read the files listed in `human_review` (high-risk files and any file with a critical finding) before you change them.
   - Tier 4: stop. Ask for a security review of those files. A critical finding in a high-risk file is not yours to close alone.

3. Read `VIBECLEANER_REPORT.md` in the repository root. It lists each finding with severity, file, and line.
4. Write the state-machine file and fix from it:

   ```bash
   vibecleaner states .
   ```

   Read `VIBECLEANER_STATES.md`. It is the one file of states, invariants, and transition tables. For each row under "Confirmed invalid transitions", the code can reach that transition, including through a retry or a lock that outlives the call. `while (true)` in TypeScript and JavaScript counts. Prioritize those rows by severity. Group rows that share a cause into one fix. For each group, add a regression test that reaches the bad transition, change the code so the transition ends (a retry must raise, return, or break; each `acquire` or `lock` must be released on its own receiver, in a `finally`, a `with`, or a `using` declaration), then run `vibecleaner states .` again so the file matches the code. Do not delete a confirmed row by hand.
5. Fix the other findings by severity: critical, then high, then medium, then low. Change the code so the pattern is gone. Do not suppress a rule, skip a file, or weaken `--fail-on` to get a pass. Leave auth, payment, and data-integrity semantics for the person the tier already named.
6. Re-run the same scan. Repeat until the process exits 0. Check with `vibecleaner scan --diff main --quiet`: a clean tree prints exactly `VIBECLEANER: PASS`.
7. Use `--fix` when you want draft unified diffs for critical findings (`vibecleaner scan --diff main --fix`). Read each draft, apply it only if it is a real fix, and scan again. `--fix` does not close medium or low findings; those still need a manual edit.

Related skills in this plugin:

- [deslop](../deslop/SKILL.md) groups slop into eight cleanup lanes.
- [preflight](../preflight/SKILL.md) is the 42-check launch review.
- [correct](../correct/SKILL.md) turns a human correction into a project rule.

Live Layer 2 calls `gemini-decision-1` when `GEMINI_API_KEY` or `GOOGLE_API_KEY` is set. `--mode auto` falls back to the offline heuristic when neither key is present. Pass `--mode off` only for a fast Layer 1 check, not as the final audit.
