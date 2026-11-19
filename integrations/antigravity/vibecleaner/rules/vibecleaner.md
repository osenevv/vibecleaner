---
trigger: always_on
---

Do not declare a task complete while VibeCleaner reports critical security or slop findings.

- A Stop hook result of `{"decision": "continue"}` means the turn is not done. Read `reason`, fix the listed findings, and keep going until the hook allows the stop.
- Fix the code. Do not suppress a finding, delete a check, weaken the scan, add a blanket ignore, or disable the VibeCleaner hook to force a pass.
- When you need the full write-up, run `vibecleaner scan --diff main` and read `VIBECLEANER_REPORT.md`. Run `vibecleaner states .` and read `VIBECLEANER_STATES.md` before changing control flow. Fix critical findings first, then high, medium, and low.
- `vibecleaner scan --fix` only drafts unified diffs for critical findings. Apply a draft after you agree it is a real fix, then scan again.
- When the user corrects you, follow the `correct` skill (`skills/correct/SKILL.md`). Turn the correction into a project rule with `vibecleaner rule`. A promise in chat is not the fix.
- In READMEs, docs, and UI copy, use active voice and concrete facts; cut AI buzzwords, puffery, em-dash crutches, and decorative comment banners.
- `review tier 4` means stop and ask for a security review of the listed files before any further edit. `review tier 3` means stop and ask a person to read the files in `human_review`: the high-risk files and any file with a critical finding.
