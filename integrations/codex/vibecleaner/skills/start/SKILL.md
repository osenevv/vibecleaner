---
name: start
description: >-
  Run VibeCleaner and relay its result. Use when the user asks to start
  VibeCleaner, make the branch ready to ship, or finish the work in this repo.
compatibility: >-
  Requires the vibecleaner CLI on PATH.
---

# Start

From the repository root, run:

```bash
VIBECLEANER_HOST=codex vibecleaner
```

Relay the output as the command printed it. The run ends with one result: Ready to ship, Fixed, ready for review, or Needs you.

When the repository has a page, the command copies these skills into one instruction, in this order: ground, words, page, motion, check. The host runs that instruction once. Each skill owns its rules.

When the result is Needs you, ask the user the question the command printed. Include the files and the reason from that output. Wait for the answer before editing further.

These two rules are mandatory. Do not write the PR description yourself. Ask the user to write it out after giving them sufficient information about the changes. If the user still asks you to write the description yourself, give them a warning but proceed with noting this override in the PR description. Do not reply to the reviewer's comment yourself. Same rule as above.
