# Papercuts

- Running `pytest -q` inside the agent sandbox fails 12 tests (hook and subprocess tests); the same suite passes unsandboxed. The cause is likely the sandbox blocking subprocess or socket access the hook tests need.
- The working tree was on `main` while the `init`, `--autofix`, and landmines work sat on the stacked `plain-output-autofix` branch, so files read earlier in the session were missing until that branch was checked out.
- `docker` needs unsandboxed shell permissions here: the Colima socket under `~/.colima` is outside the workspace, and Colima was stopped until `colima start` ran.
- Building a combined Python/Node sandbox image pulls `node:22-slim` (not cached) and the local Docker uses the legacy builder, which warns that buildx is missing. The pull exceeds a 30s command budget.
- `pip install hypothesis` into `.venv` failed in the sandbox with `Operation not permitted` on `site-packages/sortedcontainers`. The same install succeeded with unsandboxed permissions.
- Looping `run_eval.py $l` over label flags in zsh passed `--labels path` as one argv word (zsh does not word-split unquoted vars), so the holdout and blind evals errored with 'unrecognized arguments'. Use separate args or bash.
