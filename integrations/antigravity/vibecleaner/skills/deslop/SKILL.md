---
name: deslop
description: >-
  Clean up a repository by running vibecleaner deslop and splitting the result
  into eight lanes. Use when the user asks to clean up, deslop, remove AI
  slop, or refactor agent code.
compatibility: >-
  Requires the vibecleaner CLI on PATH. deslop is Layer 1 only and needs no API key.
---

# Deslop

Behavior-preserving cleanup. Delete the bad pattern so the next agent copies the good one. One concern per commit. Tests and `vibecleaner scan` stay green.

## Run

On a branch, scope the pass to the diff:

```bash
vibecleaner deslop --diff main
```

For a periodic pass over the whole tree, run `vibecleaner deslop .`. Read `VIBECLEANER_DESLOP.md`. The header is the slop score (100 means no slop findings) and the file count. Default `--fail-on` is `medium`: a medium or higher slop finding exits 1. `--json` prints lanes and does not write the file.

`deslop` keeps `Category.SLOP` hits from Layer 1. Security findings stay in `vibecleaner scan`. D6b (fake stubs) is Layer 2, so it appears in a scan and not in this file. A `D8.*` row lands in **defensive-code**. It is a state-machine bug: a `while True` or `while (true)` retry that does not finish, or an `acquire` / `lock` whose own receiver is never released. Leave it for `vibecleaner states` and the audit-code skill. A project pattern uses its `lane` when set, and **ai-slop** when the field is absent.

## Lanes

Spawn one narrow subagent per lane that has findings. For a lane with no findings, do a research-only pass and invent no work. Paste that lane's brief and its table.

| Lane | Brief to give the subagent |
| --- | --- |
| dedupe | Keep one copy where merging reduces complexity (identical bodies, pass-through wrappers). Split a god file only when each extracted module preserves what callers already see. |
| types | Merge type aliases and interfaces that describe the same shape. Do not widen or narrow the values they accept. This lane has no detector yet. |
| dead-code | Delete unused code after confirming no references (private helpers the detector named; knip or vulture for the rest). Leave exports, decorators, and dunder entry points. |
| cycles | Untangle circular imports. Move the shared symbol to a module both sides import, or invert the dependency, without changing which module runs first. |
| weak-types | Remove `any`, `as any`, `as unknown as`, a bare type-ignore, and a whole-annotation `Any`. Replace each one with the real type you researched. Keep narrowed `unknown`: `catch (e: unknown)`, `Record<string, unknown>`, and `T extends unknown`. Leave nested `dict[str, Any]` and any other value the checker already accepts. |
| defensive-code | Remove try/catch and defensive branches that do not handle unknown or unsanitized input. A catch that only rethrows or swallows the error goes. Keep a handler that logs, translates, or cleans up. A `D8.*` row in this lane is a retry that must raise, return, or break, or a lock whose same receiver must be released in a `finally`, a `with`, or a `using` declaration. Leave that row for `vibecleaner states`. No error hiding and no fallback path. |
| legacy | Remove deprecated, legacy, and fallback copies so one path remains. Delete a backup or `_old` / `_legacy` / `_v1` sibling only when callers use the current one. |
| ai-slop | Remove stubs, larp, debugger leftovers, and comments that narrate in-motion work. Keep a short comment that helps a new reader. Project rules (`P.*`) land in this lane. |

## Each subagent

1. Research the hits and their callers.
2. Write a critical assessment and recommendations.
3. Implement only the high-confidence ones.
4. Before each edit, write an equivalence note: same inputs, same returns, same errors, same side effects, same order. If you cannot state it, do not edit.
5. One concern per commit.
6. Run the tests and `vibecleaner scan`. Both stay green.
7. Do not change auth, payment, or data-integrity semantics. Those diffs need a person.

When the lane agents finish, write a ledger: what changed, and the command that verified it. Re-run `vibecleaner deslop` on the same scope. A clean pass is the end.

## Minimal single-agent variant

Check the diff against main and remove AI slop introduced on this branch: comments a human would not add, or that disagree with the file; try/catch on a trusted path; `any`, `as any`, `as unknown as`, a bare type-ignore, and a whole-annotation `Any`. Keep narrowed `unknown`. Preserve behavior. End with one to three sentences.

```bash
vibecleaner deslop --diff main
```

## Reviewer-only mode

Same research and critical assessment. Do not edit. The ledger is recommendations with a confidence, the equivalence note you would have required, and the files a person should read before anyone applies them.
