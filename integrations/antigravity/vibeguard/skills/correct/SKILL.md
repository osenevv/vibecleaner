---
name: correct
description: >-
  Turn a human correction into a deterministic project rule. Use when the
  user corrects the agent, rejects a repeated mistake, or asks the agent to
  remember a rule. Preview the check, tune it, and save it with --learned-from.
compatibility: >-
  Requires the vibeguard CLI on PATH. Saving writes .vibeguard/rules.json in the target repo.
---

# Correct

A correction that lives only in a prompt will be copied past. Reflect, then make it a check that fails the next scan.

## Loop

1. Restate what the user corrected and the root cause: the pattern the next agent will copy.
2. Decide the check. Prefer, in order, a project pattern rule, an import boundary, a type constraint, a test, or an API change that makes the mistake a compile or lint failure. Write a sentence in the project's `AGENTS.md` only when none of those can express it.
3. Preview. Do not save yet.

   ```bash
   vibeguard rule add-pattern RULE_ID --pattern 'REGEX' --message 'MESSAGE' --preview
   vibeguard rule add-boundary RULE_ID --from 'GLOB' --forbid 'PACKAGE_OR_SPECIFIER' --message 'MESSAGE' --preview
   ```

4. Tune until the preview lists the real cases and leaves legitimate code off the list. Repeat `--include` and `--exclude` once per glob. A glob that contains `{` or `}` is rejected (exit 2): list `**/*.ts` and `**/*.tsx` separately. Pattern rules run on each line after comments and string contents are blanked. Set `"match_comments": true` in the JSON only when the correction is about a comment; the CLI does not take that flag. Pass `--lane` (or set `"lane"`) when the pattern belongs in a deslop lane other than `ai-slop`. The value is one of `dedupe`, `types`, `dead-code`, `cycles`, `weak-types`, `defensive-code`, `legacy`, `ai-slop`. A rule id is 2–49 characters, lowercase letters, digits, and hyphens, and it must start with a letter or digit. The scan reports it as `P.<id>`. `--preview` prints hits and does not save or register the rule, so `rule list` and the next scan's SARIF stay unchanged.
5. Save with `--learned-from` set to the correction, in one sentence. Drop `--preview`.
6. Fix the existing hits. Re-run `vibeguard scan`. A high rule fails a default scan (exit 1). Auth, payment, and data-integrity semantics still need a person; the rule may flag those files, and you do not change their meaning on your own.
7. `vibeguard rule list` prints each rule and how many lines it flags.

A missing rules file is an empty set. A broken file (invalid JSON, a bad id, a duplicate id, a regex that does not compile) makes `scan`, `deslop`, `preflight`, and `rule list` exit 2. Nothing from that file is applied in part.

Bare `\bany\b` is a poor pattern on Python: on this scanner it flagged `any(...)` calls. On `benchmarks/blind/positive/b12_donor_note_rawbody`, `\bas any\b` flagged 0 lines and `\bany\b` with `--include '**/*.ts'` flagged `server/routes/donorNotes.ts:16` (`as Record<string, any>`). Prefer the built-in `D9.weak_type` detector when it already names the hit.

## Example: useEffect stays in framework internals

The correction: a component used `useEffect` to load data. The check is a pattern on UI files, with framework code excluded. On a sample tree this preview flagged `components/Widget.tsx:4` and left `framework/effect.ts` alone:

```bash
vibeguard rule add-pattern useeffect-internal \
  --pattern 'useEffect\s*\(' \
  --include '**/*.ts' --include '**/*.tsx' \
  --exclude 'framework/**' \
  --message 'useEffect is restricted to framework internals' \
  --severity high --category slop \
  --learned-from 'A component used useEffect to load data.' \
  --preview
```

When the listed lines are the ones the user rejected, run the same command without `--preview`. Then move those call sites onto the allowed API and scan again.

## Example: UI components do not import the database

The correction: a component imported the database client. The check is an import boundary. A non-glob forbid matches the specifier as written (`../lib/db`, `@prisma/client`) and a prefix of the resolved repo path. `--forbid lib/db` matches `import { db } from '@/lib/db'` for `src/lib/db.ts` and for `lib/db.ts`. `--forbid lib.db` matches `from ..lib.db import connect`. On a sample tree `--forbid lib/db` flagged both the `@/` import and the relative import:

```bash
vibeguard rule add-boundary ui-no-db \
  --from 'components/**' \
  --forbid '../lib/db' --forbid 'lib/db' \
  --message 'UI components may not import the database layer' \
  --severity high \
  --learned-from 'A component imported the database client.' \
  --preview
```

Save without `--preview` once the hits are real. Point the component at a typed client method that does not import the database module, and scan again. On this VibeGuard checkout the same preview flags 0 lines, which is the right result: there is no `components/` tree.
