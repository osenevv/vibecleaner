---
trigger: always_on
---

Do not declare a task complete while VibeGuard reports critical security or slop findings.

- A Stop hook result of `{"decision": "continue"}` means the turn is not done. Read `reason`, fix the listed findings, and keep going until the hook allows the stop.
- Fix the code. Do not suppress a finding, delete a check, weaken the scan, add a blanket ignore, or disable the VibeGuard hook to force a pass.
- When you need the full write-up, run `vibeguard scan --diff main` and read `VIBEGUARD_REPORT.md`. Run `vibeguard states .` and read `VIBEGUARD_STATES.md` before changing control flow. Fix critical findings first, then high, medium, and low.
- `vibeguard scan --fix` only drafts unified diffs for critical findings. Apply a draft after you agree it is a real fix, then scan again.
