# VibeGuard state machines

`vibeguard states` writes this kind of map for the repository it scans (`VIBEGUARD_STATES.md`): states, invariants, transition tables, and only the invalid transitions the code can reach. `D8.unbounded_retry` and `D8.lock_not_released` are those confirmed rows. The audit skill then fixes them with tests and regenerates the file. This document is the map of the scanner itself, not the generated file.

This file is the map of the states the scanner actually moves through. Each machine lists its states, the invariant that must hold, and the transitions the code takes. The last section records two defects that were reachable, including under a second process, and the tests that now keep them closed.

Probabilities below are the Decisions API `noul` value: a calibrated yes-score in `0.01..0.99`. It is never `0` and never `1`.

## 1. Scan

States: `collect` → `layer1` → `select-backend` → `judge` → `save-cache` → `draft-fixes` → `report`.

Invariant: a scan either returns a `ScanResult` or raises `CollectorError` / `DecisionAPIError` before any report is written. Cache writes happen only after judging finishes. Fix drafts never run unless judging returned.

| From | Event | To | Notes |
| --- | --- | --- | --- |
| start | `collect` | `layer1` | Missing path or unknown `--diff` ref raises `CollectorError` |
| `layer1` | critical finding overlaps a unit | `judge` with that unit skipped | Lower-severity Layer 1 hits do not skip Layer 2 |
| `layer1` | no critical overlap | `judge` | Every unit is eligible |
| `select-backend` | `off`, or `auto` with no key and the caller asked for no model | `judge` disabled | No Layer 2 findings, mode `disabled` or `offline` |
| `judge` | chunk raises | `save-cache` | Successful siblings are cached; `judge.errors` is non-empty |
| `judge` | all chunks scored | `save-cache` | Complete score maps are stored; incomplete ones are not |
| `save-cache` | `--fix` and a critical finding | `draft-fixes` | One patch attempt per finding, four at a time |
| `draft-fixes` | done, or `--fix` not set | `report` | Exit code is chosen from errors, then severity |

## 2. Backend selection

States: `auto`, `live`, `offline`, `off`.

Invariant: `live` and `offline` scores never share a cache key. `live` without an API key is an error, not a silent downgrade. `auto` downgrades to `offline` when no key is set.

| Mode | Key present | Backend | `JudgeStats.mode` |
| --- | --- | --- | --- |
| `off` | either | none | `disabled` |
| `offline` | either | heuristic | `offline` |
| `auto` | yes | `gemini-decision-1` | `live` |
| `auto` | no | heuristic | `offline` |
| `live` | yes | `gemini-decision-1` | `live` |
| `live` | no | — | `DecisionAPIError`, exit 2 |

## 3. Layer 2 unit and chunk

Per unit: `pending` → `cached` or `in-flight` → `scored` or `failed` or `skipped`.

Per live request: `send` → `retry-wait` → `send` → `scored` or `failed`.

Invariant: a unit is in at most one chunk. Labels (`MOD_01` …) restart inside each chunk and are assigned before any request starts, so concurrent chunks do not relabel each other. Cache reads happen before the requests. Cache writes happen after every request has finished, on the same task that started them.

| From | Event | To |
| --- | --- | --- |
| `pending` | cache hit for this backend and this source hash | `cached` |
| `pending` | critical Layer 1 finding on a line inside the unit | `skipped` |
| `pending` | chunk accepted | `in-flight` |
| `in-flight` | HTTP 429, HTTP 5xx, or a timeout, and attempts remain | `retry-wait` then `in-flight` |
| `in-flight` | any other error, or the last attempt failed | `failed` |
| `in-flight` | every Layer 2 rule has a finite score in `0..1` | `scored`, then stored |
| `in-flight` | the response omits a rule | `failed` for the exit code; any scores that did arrive can still become findings |

Retries: at most 3 attempts, delays `0.5s`, `1s`, `2s`. The attempt holds its concurrency slot while it waits. That slows a 429 storm and does not change the stored scores. A 400, including an invalid key, is not retried.

Up to 4 chunks run at once. They share the backend object and only read it. The offline heuristic's callee catalog is filled before the chunks start.

A failed chunk does not roll back siblings. The next scan cache-hits the siblings and sends the failed units again. Exit 2 still fires whenever `judge.errors` is non-empty, so a partial success is not a pass.

## 4. Cache entry

States: `absent`, `valid`, `rejected`.

Invariant: a `valid` entry has a backend name, one finite score in `0..1` for every Layer 2 rule, and optionally `module_risk` in `0..2`. Offline and live entries use different keys (`question text + heuristic version + source hash`, or `question text + source hash`). A reader never treats an offline entry as a live one.

| From | Event | To |
| --- | --- | --- |
| `absent` | `put` of a complete score map | `valid` in memory, dirty |
| `valid` | `save` | on disk, via a temp file and `os.replace` |
| `valid` on disk | process starts and the file parses | `valid` in memory, including `module_risk` |
| on disk | score missing, non-numeric, or outside `0..1` | `rejected`, dropped, file rewritten on the next save |
| `valid` in two processes | both `save` | union of keys; a key written by the saver wins over the same key already on disk |

The lock is `.vibeguard_cache.json.lock`, held only around the merge and the replace. The walker ignores that file and the cache file.

## 5. Process exit

States: `0` pass, `1` findings at or above `--fail-on`, `2` error.

Invariant: the cutoff is inside `0.01..0.99`. Checked in the CLI before a scan starts, and again in `judge` so a library caller cannot skip it. `--fail-on` defaults to `high`. Quiet mode prints `VIBEGUARD: PASS` only when there are no findings and no judge errors.

| Condition | Exit |
| --- | --- |
| bad argv, cutoff outside `0.01..0.99`, missing root, unknown ref, live mode with no key | 2, before or instead of a pass line |
| `judge.errors` non-empty, including a failed chunk or an incomplete score map | 2, after the report |
| a finding at or above `--fail-on` | 1 |
| otherwise | 0 |

## 6. Antigravity hook

States: `stop` and `post-tool`.

Invariant: the hook process itself exits 0 and prints a JSON object, except when the workspace directory does not exist (exit 2, body `{}`). The scanner's exit code is interpreted, not forwarded.

| Scanner exit | `stop` | `post-tool` |
| --- | --- | --- |
| 0 | `{}` (also when the body is only `VIBEGUARD: PASS`) | `{}` |
| 1 | `{"decision":"continue","reason":...}` | `{}`, findings on stderr |
| 2 or higher | `{}`, error on stderr | `{}`, error on stderr |

`stop` uses `--fail-on ${VIBEGUARD_FAIL_ON:-critical}`. `post-tool` adds `--mode off` and cannot block. Both pass `--no-cache`. A missing `vibeguard` binary prints install instructions and allows the stop. This fail-open path is deliberate: an install or API failure must not trap the agent.

## 7. Fix drafts

States per critical finding: `eligible` → `drafting` → `kept` or `rejected` or `failed`.

Invariant: only `critical` findings are eligible. Layer 2 also needs `noul >= 0.85`. Without an API key and without an injected client, no draft is attempted. The stored diff is redacted. A draft that is not a unified diff (`---`, `+++`, `@@`) is dropped. Four drafts run at a time. A failure is logged and does not change the scan exit code; the finding itself still does.

## Confirmed defects

These were reachable from the code as it ran. Both are fixed. The tests named here fail on the old transitions.

### Issue 1 — cache entries did not survive a second process

1. `module_risk` was dropped while reading the file. A live severity of `0.4` came back as "absent", and the next scan filled it with the offline band (`2.0` whenever any rule was at least `0.85`). Evidence: `test_cache_keeps_module_risk_across_reload` writes `0.4`, reloads, and requires `0.4` rather than `2.0`.
2. A score outside `0..1`, or a map missing a rule, stayed in the file forever. `get` ignored it and the next `save` wrote it back. Evidence: `test_cache_rejects_scores_outside_unit_interval` saves after a load and asserts the bad key is gone.
3. Two scans that loaded the same file and then both saved: the second replace deleted the first scan's new keys. That is the same transition as two `vibeguard scan` processes. Evidence: `test_cache_save_merges_entries_from_a_stale_snapshot` loads twice, puts a different unit in each, saves both, and requires both keys.

The fix is one cache change: validate on load, keep `module_risk` when it is inside `0..2`, and merge disk keys under an exclusive lock before replace.

### Issue 2 — a cutoff of 0 or 1 could not fail Layer 2

`noul` is compared with `< threshold`, and every stored score is inside `0.01..0.99` (live values are clamped; the offline heuristic tops out at `0.93`). `--threshold 1` therefore reported no Layer 2 finding and exited 0. `--threshold 0` reported every scored rule. The CLI used to accept both because it allowed `0..1`. Evidence: `test_threshold_outside_noul_range_is_rejected` expects exit 2 for `0` and `1`, and `judge(..., threshold=1)` raises `DecisionAPIError`.

## Checked, not defects

- A retry that then succeeds stores one score map and does not double-count tokens.
- A 400 is not retried. An invalid key ends in exit 2 with `VIBEGUARD: ERROR`.
- Incomplete scores are not cached. The scan still exits 2.
- Chunk workers do not write the cache. Writes happen after `gather`.
- Hook exit 2 is fail-open by the contract in section 6, not by a missed error.
- Deleting the only lines of an auth check still selects the enclosing function (`count == 0` records that line).
