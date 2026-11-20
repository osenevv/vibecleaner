# Plan: make `vibeguard start` fix code

## What a run does today

`vibeguard scan` is the auditor. It walks Python, TypeScript, JavaScript, and SQL, runs the deterministic rules, asks six yes/no questions per sliced function, and writes a report. `deslop`, `preflight`, `states`, `rule`, and `init` do what the README says. `vibeguard --autofix` hands a prompt to an external agent and scans again. It does not check that the agent left the tests alone.

`vibeguard start` is a checker, not a fixer. In `vibeguard/run/loop.py` it does four things:

1. If the git tree has uncommitted files outside `.vibeguard/`, it stops and asks you to commit or stash. It does not touch those files.
2. It runs the offline static scan.
3. If that scan is clean, it runs the project's own test, lint, or type command. Detection covers Python, JavaScript, Go, Cargo, Make, Maven, Gradle, .NET, Ruby, PHP, and Mix. A `test`, `lint`, `typecheck`, or `build` string in `.vibeguard/config.json` wins.
4. It writes `VIBEGUARD_RUN.md` and returns ready, or a question.

It never returns fixed. A failing check becomes the question "fix the evidence below" even when a model is configured. Bare `vibeguard` still means `scan`.

Docker, when it is up, runs Python and Node. Other languages run only with `--sandbox host`.

## What is built and not called

`start` does not call these modules. They stay unused until the steps below wire them in.

- `repair/workspace.py` creates worktrees, applies a diff, and commits.
- `verify/tamper.py` compares tests, config, and public signatures with a snapshot taken before a patch.
- `probes/` writes property tests, scores mutants, and diffs old behavior against new. Python and TypeScript use a grammar. Other languages get comparison, boolean, and integer edits on the changed lines.
- `jury/panel.py` and `jury/scan_nodes.py` ask specialist questions and split the static findings into security, validation, and maintainability.
- `runtime/detect.py` knows how to boot FastAPI, Flask, Express, and Next. `runtime/check.py` does not boot them. A detected server is reported as not run.

## What the user does

One command, no flags: `vibeguard`. It includes uncommitted files, picks who edits, picks how to run the tests, fixes, re-runs the checks, and commits on a new branch. The user does not stash, name a test command, choose a model, or run it again.

Choices it makes on its own, in this order:

- Who edits: the editor it was launched from, otherwise `claude`, `codex`, or `agy` on `PATH`, otherwise a local model that is already running, otherwise an API key already in the environment.
- Who judges: the same route, not `gemini-decision-1` by default. See "Which model judges".
- Where code runs: Docker if the daemon answers, otherwise this machine.
- Which checks: `.vibeguard/config.json` if the keys are set, otherwise the ecosystem files (`go.mod`, `package.json`, `Makefile`, `Cargo.toml`, and the rest). Each check has a few equivalent spellings (`python -m pytest` or `pytest`, `go test ./...` or `go test .`, `make test` or `make check`, `bundle exec rspec` or `rspec`). The first spelling that actually starts is the one that counts. A missing binary is not a failure while another spelling remains. It does not ask which command to run.
- What to type: `vibeguard`, `vibeguard start`, `vibeguard fix`, and `vibeguard run` are the same command.

The only stop that asks for something is: no editor and no model exist anywhere. The line names the one thing that would unlock a fix. Every other failure is retried inside the run.

Auth, payment, and data-integrity edits are still committed when the checks pass. The last line names those files. It does not wait for an answer.

Progress is a few plain lines. The end is either "ready" or "fixed on `vibeguard/fix-<id>`". A model opinion without a failing command stays in `VIBEGUARD_RUN.md` and does not stop the run.

## Which model judges

The six yes/no questions stay. The model that answers them is a decision model: it returns a probability and writes no text. Chat models (Claude, GPT, Grok, Groq, Mistral, and the rest) can still write patches. They do not judge.

Two wire formats cover the hosted decision APIs. Jev's System One shape is `state` plus `noul` questions. Google and OpenAI use their own decisions endpoints. The same six questions are sent either way. The cache key is the model id, so a Jev score is never reused as a Gemini score.

| Routed key | Decision API | Model | Yes/no field |
| --- | --- | --- | --- |
| `TYPESAFE_API_KEY` or `JEV_API_KEY` | TypeSafe System One | `jev-latest` | `noul` |
| `GEMINI_API_KEY` or `GOOGLE_API_KEY` | Gemini Decisions | `gemini-decision-1` | `noul` |
| `OPENAI_API_KEY` | OpenAI Decisions, `POST /v1/decisions` | `gpt-6-luna` | `predicate` (the probability field) |
| `CLOUDFLARE_API_TOKEN` plus `CLOUDFLARE_ACCOUNT_ID` | Workers AI | `clef`, or `CLEF_MODEL` | Jev's `noul` body |
| `PERPLEXITY_API_KEY` | Perplexity Decisions | `pplx-decider-latest` | `noul` |
| `LIQUID_API_KEY` | Liquid `api.liquid.ai/decisions/v1/systemone` | `d1` | Jev's `noul` body |
| `AZURE_OPENAI_API_KEY` on Foundry | Microsoft-Decision-1, `/providers/microsoft/v1/systemone` | `microsoft-decision-1` | Jev's `noul` body |
| `LAYA_BASE_URL` | A Laya server you run | the checkpoint that server serves | Jev's `noul` body |

`VIBEGUARD_JUDGE` names one of `jev`, `gemini`, `openai`, `clef`, `decider`, `d1`, `microsoft`, `laya` when more than one key is set. When it is unset, the order in the table wins: the first key that is set is the judge. No decision key keeps the offline heuristic. `mode live` no longer requires a Gemini key.

### 0. Route the judge

Before step 1, `decision_judge.select_backend` reads that table. One System One client serves Jev, Clef, Liquid, Microsoft-Decision-1, and Laya, because they take the same request. Gemini keeps its decisions client. OpenAI Decisions is a third client: the question type is `predicate` and the score is `probability`. The threshold stays 0.75 unless a sweep for that model says otherwise. OpenAI does not claim its probabilities are calibrated, so its route records that and still uses the same cutoff until the gold set says to move it.

Check: with only `TYPESAFE_API_KEY`, only `OPENAI_API_KEY`, or only `PERPLEXITY_API_KEY`, a live scan does not call Gemini. With no decision key, the offline eval numbers stay put.

## Steps

Each step keeps `pytest`, the three offline evals, `vibeguard scan . --mode offline --no-cache --quiet`, and `vibeguard deslop .` green. Bare `vibeguard` stays `scan` until step 6.

### 1. One proven patch

Change `run/loop.py` so a failing gate, and a team that can edit, produces one candidate.

- Snapshot the tree with `verify.snapshot` before the edit.
- Ask the host agent, or one patcher model, for a unified diff against the evidence and the spec.
- Apply it in a worktree from `repair/workspace.py`.
- Re-run the gate that failed and `check_tamper`. A weakened test, a new skip, or a surprise signature change drops the candidate.
- When both pass, commit on `vibeguard/fix-<id>` and return fixed, with the commit and the evidence.
- When they fail, keep the user's branch as it was and try the next candidate in step 3. Do not stop to ask the user to fix it by hand.

Check: a temp repo whose pytest fails, and a host double that edits the source and not the test, exits fixed and the hidden assertion passes. A double that deletes the test is rejected and the branch is unchanged.

### 2. Call the checks that already exist

After step 1, `start` runs this order and stops on the first hard failure: static scan, project gates, tamper guard, probes, runtime. Security and maintainability notes from `jury/scan_nodes.py` are sections in `VIBEGUARD_RUN.md`. They do not block unless they already blocked the static scan.

`runtime_check` boots the command from `detect_app` on the host sandbox, sends one malformed request, and records the status code. A library still passes with the existing note. A server that dies on boot is a revise with that command as the evidence.

Check: the step 1 repo still fixes. A one-file WSGI app that returns 500 for bad JSON becomes a revise. A README-only repo stays ready.

### 3. Several candidates and a stop

Generate four diffs from distinct root-cause lines. Each runs in its own worktree through the gate and the tamper guard. Rank the survivors in pairs, swapping A and B. Commit the winner.

Stop without another model call when the set of findings and the diff hash repeat, or when two candidates for the same cause both fail. The result names the repeated cause and the branch is unchanged. It does not ask a follow-up question.

Check: two honest diffs and one that deletes a test. The deleting diff is dropped, one honest diff is committed, and a scripted oscillation stops on the second repeat.

### 4. Judges that can veto

Wire `jury/panel.py` into the run after the gates pass and before the commit. The yes/no gate and the specialists both use the routed judge from "Which model judges". A specialist finding blocks only when its probe fails on the current tree. An unreproduced finding is a note. When a second provider exists, the judge is not the one that wrote the diff.

Check: a probe that fails blocks the commit. A probe that passes stays in the report and the commit proceeds.

### 5. Languages and sandbox images

The property writer emits a test the detected command can run, not only a pytest or vitest file. Token mutants stay the fallback when there is no grammar.

The Docker image is the repo Dockerfile or devcontainer when one exists, then a stock image for Go, Rust, and a JVM, then the host. The progress line names which one ran.

Check: `benchmarks/repair/r11_make_only` is detected as `make test`. `r12_go_refund` is detected as `go test ./...` and runs under the Go image when Docker is up, using `/tmp/vg-go/go/bin/go` only as a host fallback.

### 6. Make bare `vibeguard` mean start

Switch the no-argument command from `scan` to `start` in the same change as the README, `AGENTS.md`, the Claude Code and Codex Start skills, and the tests that assert the old default. `vibeguard scan` keeps its flags and exit codes.

The offline self-scan must print `VIBEGUARD: PASS`. Today it fails on `agents/hosts.py`, `prompt_fix.py`, and `run/gitcmd.py`, which pass argument lists to `subprocess` and do not invoke a shell. Teach the D5 heuristic that an argument vector is not a shell injection, and add those three files as clean lookalikes in the tests.

## Done when

`vibeguard` with no arguments, in a dirty tree, with an editor or a model already available, fixes a failing test, commits that fix on a new branch, and leaves the previous branch as it was. A patch that deletes the test is not the commit. The user types nothing else.
