---
name: start
description: >-
  Run VibeGuard and relay its result. Use when the user asks to start
  VibeGuard, make the branch ready to ship, or finish the work in this repo.
compatibility: >-
  Requires the vibeguard CLI on PATH.
---

# Start

From the repository root, run:

```bash
VIBEGUARD_HOST=antigravity vibeguard
```

Relay the output as the command printed it. The run ends with one result: Ready to ship, Fixed, ready for review, or Needs you.

When the result is Needs you, ask the user the question the command printed. Include the files and the reason from that output. Wait for the answer before editing further.
