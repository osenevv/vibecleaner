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
VIBECLEANER_HOST=antigravity vibecleaner
```

Relay the output as the command printed it. The run ends with one result: Ready to ship, Fixed, ready for review, or Needs you.

When the result is Needs you, ask the user the question the command printed. Include the files and the reason from that output. Wait for the answer before editing further.
