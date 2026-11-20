---
name: preflight
description: >-
  International 42-check launch review. Use when the user asks for a launch
  preflight, a launch review, or whether an app is ready to ship. Run
  vibeguard preflight, finish the manual checks in a test environment, and
  answer in the 42-row format. Fix nothing until the owner confirms.
compatibility: >-
  Requires the vibeguard CLI on PATH. The command is read-only and needs no API key.
---

# Launch preflight

`vibeguard preflight` answers what it can from the scanned tree. You finish the rest in a test environment and report. You do not fix anything until the owner confirms.

## Run

```bash
vibeguard preflight .
```

Read `VIBEGUARD_PREFLIGHT.md`. The command is read-only and lives in the `vibeguard/preflight/` package. It exits 1 when the report has blockers: a Problem in section B or C, or check 25 or 30. Exit 2 means the command crashed or the rules file is broken; that is not a clean launch. `--json` prints the report and does not write the file. Paths in `.vibeguardignore` are invisible to the walked tree. Check 30 still sees test files and CI workflows on disk. Check 39 weighs images under `public/` and `static/`; no image files means Not applicable.

An OK on #21 is an idempotency key or an upsert in the order-creating file, or a unique constraint or `ON CONFLICT` on the orders table. An OK on #26 is pagination in the list-query file, or an index on the table that query reads. A hit in an unrelated file does not make either check OK. Comments and string contents are blanked before those checks.

The opening paragraph is an inference from routes, page names, and the README. Rewrite it after you have seen the product.

## Rules

Follow these for every manual check:

- Create, change, and delete data only in a test environment. If there is none, run a local copy with a test database, or ask the owner and mark the row Not checked.
- Checks that need production or a vendor dashboard: do not perform them. Mark them Not checked, say what the owner should verify and what success looks like, and continue.
- Payments only in test mode. Do not switch a provider between test and live.
- Do not send mass email. Do not run a load test.
- Do not read real user data. Do not print secret values. Do not ask for passwords or keys.
- Legal, tax, and accessibility items are what to confirm with a lawyer or accountant for the target markets. Name the regime, not a single country's statute: GDPR and UK GDPR, CCPA/CPRA, VAT/GST or sales tax, WCAG 2.2 AA and the European Accessibility Act, PCI DSS by using a hosted checkout and not storing card data. Note a third-party service that is blocked or slow in a target region.
- At the end, stop everything you started and list what you created.

## The 42 checks

Use the report row as the starting status. After a real test, replace it. For Not checked and Not applicable, give the reason. For a code problem, give file and line. For a dashboard check, say where to go and what counts as success.

A. Through the user's eyes. 1 first screen (offer, price, where to start). 2 main flow on a desktop width and on a phone, both sides when there are two. 3 loading, empty, and form error, with typed input preserved. 4 refresh, Back, reopen, and a second submit. 5 contrast at least 4.5:1 (WCAG 2.2 AA), labels, keyboard, and the design system when there is one.

B. Security. 6 sign-up, sign-in, sign-out, recovery, including a missing email, an expired code, and too many attempts. 7 server-side sign-out, cookie flags, CSRF. 8 two test accounts, including direct API and database requests; admin actions authorized on the server. 9 a quote and a script tag in fields and the URL. 10 leaked keys in frontend, bundles, and git history; `.gitignore`; rotated keys. 11 known-vulnerable dependencies. 12 slow password hash (bcrypt, argon2, or scrypt), encryption at rest, secrets absent from logs and links. 13 limits on sign-in, codes, email, uploads, and AI calls. 14 upload size, type, and no access to someone else's file by link. 15 an AI chat that refuses to reveal the system prompt or another user's data. 16 production settings: no localhost in emails and links, debug off, no test accounts or default passwords, database and admin panel not exposed, generic error page that is logged. 17 HTTPS only, rate limit that a spoofed `X-Forwarded-For` does not bypass, request size, HSTS and CSP, CORS limited to your domains, `.env` and `.git` not served.

C. Money. 18 test payment, decline, cancellation, and refund; amounts match; a payment for a cancelled order. 19 receipts and invoices for the target markets (VAT/GST or sales tax): line items to the provider, a receipt on payment and on refund; what to confirm with an accountant. 20 tampered price, quantity, and discount recomputed on the server. 21 two simultaneous submits and a retry after a dropped connection produce one order. 22 invalid webhook signature rejected; a replay does not credit twice. 23 subscription, trial, and promo access before and after expiry and cancellation; a trial or discount cannot be taken twice. 24 what to verify in the provider dashboard (live keys, signing secret, webhook URL, receipts and tax) and a guard against test mode in production. Do not switch modes.

D. Data and failures. 25 two accounts buy the last item or book the same slot; exactly one succeeds. 26 1001 test records; the last is reachable by pagination and search; indexes exist. 27 two time zones; timestamps stored in UTC. 28 backup schedule, failure alert, and a restore of a test backup into a fresh database. 29 rollback after a bad deploy; the release you roll back to still tolerates the new schema. 30 automated tests for the main flow, passing, and run before every deploy. 31 delete a test account; what is removed, what is kept, and for how long, matched to the privacy policy (GDPR/CCPA erasure).

E. Launch. 32 terms, privacy policy, and cookie list match sign-in, payments, analytics, and third parties; seller identity, contact, shipping, and returns; what to confirm with a lawyer. 33 customer-facing text in the languages the target markets require; what to confirm with a lawyer. 34 where personal data is stored, cross-border transfers (such as SCCs), consent recorded where required, a processing record and DPAs; what to confirm with a lawyer. 35 third-party sign-in available in the target markets, plus a fallback method. 36 third-party hosts the browser calls that may be blocked or slow in a target region. 37 SPF, DKIM, and DMARC; mail that reaches the inbox. 38 404 page, titles, Open Graph, and that the site is not hidden from search engines. 39 home page on a slow connection; image weight; when the main button appears. 40 plan limits of hosting, database, email, and AI; what the user sees when they are exceeded; where the owner sees spend. 41 an alert when the site is up but sign-in or ordering fails; a report that arrives from a signed-out user. 42 who owns the domain, hosting, payment account, and email; when billing renews; two-factor authentication on.

## Answer

Start with one paragraph: who the service is for, what a person does in it, and what result they get.

Then a 42-row table. Columns: #, status (`OK`, `Warning`, `Problem`, `Not checked`, `Not applicable`), what was found, evidence (a file and line, or a test you actually ran), consequence for the user. One or two sentences per cell.

Finish with three short lists: what blocks launch, what can wait, and the first three actions.

Stop every process you started and list every record, account, and file you created. Do not fix anything until the owner confirms.
