# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in VibeCleaner (`vibecleaner`), please **do not** open a public GitHub issue.

Instead, report it privately via GitHub Security Advisories at:
https://github.com/osenevv/vibecleaner/security/advisories/new

Include:
- A description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof of concept.
- The version of `vibecleaner` and Python you are running.

We aim to acknowledge reports within 48 hours and provide a fix or mitigation plan promptly.

## Data Handling & Privacy

- `--mode offline` and `--mode off` never make network requests.
- `--mode live` (or `--mode auto` with an API key set) sends redacted function slices and the global auth-context summary to the configured Decisions API. Detected secrets are masked before leaving your machine.
- `--fix` sends flagged function bodies to the configured Gemini fix model (`VIBECLEANER_FIX_MODEL`).
- Never commit real API keys into `.vibecleaner/` or test fixtures.
