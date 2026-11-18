"""Check results, status labels, and how blockers and first actions are chosen."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum

__all__ = ["_blockers", "_can_wait", "_evidence", "_first_actions", "_make"]


class Status(str, Enum):
    OK = "ok"
    WARNING = "warning"
    PROBLEM = "problem"
    NOT_CHECKED = "not checked"
    NOT_APPLICABLE = "not applicable"


@dataclass
class CheckResult:
    id: int
    section: str
    title: str
    status: Status
    found: str
    evidence: str
    consequence: str
    verify: str
    locations: list[str] = field(default_factory=list)


@dataclass
class PreflightReport:
    summary: str
    stack: list[str]
    checks: list[CheckResult]
    blockers: list[int]
    can_wait: list[int]
    first_actions: list[str]


_STATUS_LABEL = {
    Status.OK: "OK",
    Status.WARNING: "Warning",
    Status.PROBLEM: "Problem",
    Status.NOT_CHECKED: "Not checked",
    Status.NOT_APPLICABLE: "Not applicable",
}
_META: dict[int, tuple[str, str]] = {
    1: ("A", "First screen"),
    2: ("A", "Main flow on desktop and phone"),
    3: ("A", "Loading, empty, and error states"),
    4: ("A", "Refresh, Back, and double submit"),
    5: ("A", "Labels, contrast, and keyboard"),
    6: ("B", "Sign-up, sign-in, and recovery"),
    7: ("B", "Cookies, sign-out, and CSRF"),
    8: ("B", "Account isolation"),
    9: ("B", "XSS and SQL injection"),
    10: ("B", "Secrets and .gitignore"),
    11: ("B", "Dependency vulnerabilities"),
    12: ("B", "Password hashing and secret logs"),
    13: ("B", "Rate limits"),
    14: ("B", "Upload size and type"),
    15: ("B", "AI prompt and data leaks"),
    16: ("B", "Debug, localhost, and default passwords"),
    17: ("B", "Headers, CORS, and proxy trust"),
    18: ("C", "Payments, refunds, and cancellations"),
    19: ("C", "Receipts, invoices, and tax"),
    20: ("C", "Server-side price"),
    21: ("C", "Order idempotency"),
    22: ("C", "Webhook signature and replay"),
    23: ("C", "Subscriptions, trials, and promos"),
    24: ("C", "Live-mode payment guard"),
    25: ("D", "Stock and booking races"),
    26: ("D", "Pagination and indexes"),
    27: ("D", "Time zones"),
    28: ("D", "Backups and restore"),
    29: ("D", "Rollback after a bad deploy"),
    30: ("D", "Automated tests"),
    31: ("D", "Account deletion"),
    32: ("E", "Terms, privacy, and consumer info"),
    33: ("E", "Localization"),
    34: ("E", "Personal data and transfers"),
    35: ("E", "Third-party sign-in"),
    36: ("E", "Third-party browser hosts"),
    37: ("E", "Email deliverability"),
    38: ("E", "404, previews, and indexing"),
    39: ("E", "Image weight"),
    40: ("E", "Plan limits and spend"),
    41: ("E", "Outage alerts and support"),
    42: ("E", "Ownership, renewals, and 2FA"),
}
_IMPACT: tuple[int, ...] = (
    10, 8, 12, 9, 22, 20, 21, 24, 7, 16, 25, 13, 14, 15, 17,
    30, 31, 32, 6, 18, 28, 4, 42, 34, 37, 1, 2, 11, 19, 23,
    27, 38, 41, 5, 3, 29, 26, 40, 36, 35, 33, 39,
)
_ACTIONS: dict[int, str] = {
    1: "Open the signed-out home page and change the first screen until a new visitor can say what the service does, what it costs, and which control starts the task.",
    2: "Walk the main flow to the result on a desktop width and on a phone, including both sides if there is a buyer and a seller.",
    3: "Trigger a slow load, an empty result, and an invalid form, and keep going only when each state says what to do and typed input is still there.",
    4: "Refresh, press Back, close the tab, and submit the form twice; the result should remain and the second submit must not create a second record.",
    5: "Label every field, give images alt text, and complete the form with the keyboard only; check text contrast against WCAG 2.2 AA (4.5:1).",
    6: "Create an account, sign in, sign out, and recover access, including a missing email, an expired code, and too many attempts.",
    7: "Set session cookies to HttpOnly, Secure, and SameSite, revoke the session on the server at sign-out, and reject cross-site form posts that lack a CSRF token.",
    8: "With two test accounts, call the API (and the database, if the browser can reach it) and confirm each account reads and changes only its own rows and files.",
    9: "Remove raw HTML sinks and SQL built with f-strings or concatenation so a quote or script in a field is stored as text and cannot change the query.",
    10: "Remove committed secrets, add `.env*` to .gitignore (keep `.env.example`), rotate every key that was exposed, then run `gitleaks detect` and `trufflehog git file://.`.",
    11: "Run `npm audit --omit=dev` and `pip-audit` (whichever ecosystems this repo uses) and update or explicitly accept each reported vulnerability.",
    12: "Store passwords only with bcrypt, argon2, or scrypt, and stop logging passwords, tokens, and secrets.",
    13: "Add a rate limit on sign-in, code sending, and AI calls so one caller cannot exhaust the quota or lock someone else out.",
    14: "Limit upload size and content type, and reject a request that uses another account's file id.",
    15: "In a test chat, ask the model for its system prompt and for another user's data; keep user text in the user role and refuse both.",
    16: "Turn debug off, remove default passwords and localhost links from production paths, and show a generic error page that is logged server-side.",
    17: "Serve HTTPS only, set HSTS and CSP, restrict CORS to your own origins, and do not trust a client-supplied X-Forwarded-For.",
    18: "In the provider's test mode, pay, decline, cancel, and refund, and match the amount and status in the cart, order, receipt, and provider.",
    19: "Send line items (name, quantity, price, tax rate) to the payment or tax provider and confirm with an accountant which VAT, GST, or sales-tax invoices your markets require.",
    20: "Recompute price, quantity, and discount on the server from your catalogue and reject a tampered total.",
    21: "Send the same order twice, including after a dropped connection, and require one idempotency key so the database keeps a single order.",
    22: "Reject a webhook with a bad signature, and store the event id so a genuine replay does not credit the payment twice.",
    23: "Check a subscription, trial, and promo code before expiry, after expiry, and after cancellation, and block a second free trial.",
    24: "In the payment dashboard confirm live keys, the webhook signing secret, the production webhook URL, and receipt settings, and block test-mode keys in production. Do not switch modes.",
    25: "From two accounts at once, buy the last item or book the same slot and keep the change only if exactly one succeeds.",
    26: "Insert 1001 rows, open the last page, and confirm an index exists for the filter and sort.",
    27: "Store timestamps in UTC and show local time to two users in different time zones.",
    28: "Read the backup schedule, confirm an alert fires when a backup fails, and restore a test backup into a fresh database.",
    29: "Rehearse a rollback and confirm the previous release still runs against the new schema without deleting user data.",
    30: "Add automated tests for the main flow and run them in CI before every deploy.",
    31: "Delete a test account and compare what is removed, what is kept, and for how long with the privacy policy (GDPR/CCPA erasure).",
    32: "Publish terms, a privacy policy, a cookie list, the seller's legal identity and contact details, and shipping and returns terms (including the EU 14-day withdrawal right where it applies).",
    33: "Confirm with a lawyer which customer-facing text must be in the local language for your target markets.",
    34: "Confirm with a lawyer where personal data is stored, which vendors receive it, and which cross-border safeguards (such as SCCs) and consent records you need.",
    35: "Confirm each OAuth provider is allowed in your target markets and that another sign-in method works where it is not.",
    36: "Load the app with third-party hosts blocked and list every font, captcha, payment, and analytics host the browser calls.",
    37: "Check SPF, DKIM, and DMARC with `dig TXT your-domain` and `dig TXT _dmarc.your-domain`, then send a message and confirm it is not in spam.",
    38: "Open a missing URL, check the page title and Open Graph preview, and remove any production noindex or `Disallow: /` you did not intend.",
    39: "On a slow connection, confirm the main button appears quickly and that images under public/ or static/ are each under 500KB or lazy-loaded.",
    40: "Write down the plan limit and the overage behavior for hosting, the database, email, and AI, and where the owner sees spend.",
    41: "Add an alert that fires when sign-in or ordering fails while the home page is up, and a support path a signed-out visitor can use.",
    42: "List who owns the domain, hosting, payment account, and email, when each bill renews, and confirm two-factor authentication is on.",
}
_AGENT_RULES = (
    "Create, change, and delete data only in a test environment. If there is none, run a local copy "
    "with a test database or ask the owner. Do not perform checks that need production or a vendor "
    "dashboard; leave them Not checked, say what the owner should verify and what success looks like, "
    "and continue. Take payments only in test mode. Do not send mass email or run load tests. Do not "
    "read real user data, print secret values, or ask for passwords or keys. Phrase legal items as what "
    "to confirm with a lawyer or accountant for the target markets (GDPR/UK GDPR, CCPA/CPRA, EU consumer "
    "rules, VAT/GST/sales tax, WCAG 2.2 / European Accessibility Act, PCI DSS by using a hosted checkout "
    "and never storing card data). Note where a third-party service is unavailable. At the end, stop "
    "everything you started and list what you created. Do not fix anything until the owner confirms."
)
_NO_PAY = (
    "No payment provider (Stripe, Paddle, Lemon Squeezy, PayPal, Adyen, YooKassa, or similar) "
    "appears in the scanned code, so this check does not apply."
)
_NO_PAY_EVIDENCE = "reason: no payment provider in the scanned code"


def _uniq(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _make(
    check_id: int,
    status: Status,
    found: str,
    evidence: str,
    consequence: str,
    verify: str = "",
    locations: list[str] | None = None,
) -> CheckResult:
    section, title = _META[check_id]
    if status == Status.NOT_CHECKED and not verify.strip():
        raise ValueError(f"check {check_id} is Not checked without verify instructions")
    return CheckResult(
        id=check_id,
        section=section,
        title=title,
        status=status,
        found=found,
        evidence=evidence,
        consequence=consequence,
        verify=verify,
        locations=_uniq(locations or []),
    )


def _evidence(locations: list[str], reason: str) -> str:
    if locations:
        shown = locations[:8]
        suffix = f" (+{len(locations) - 8} more)" if len(locations) > 8 else ""
        return "code: " + ", ".join(shown) + suffix
    return reason


def _blockers(checks: list[CheckResult]) -> list[int]:
    chosen: list[int] = []
    for check in checks:
        if check.status != Status.PROBLEM:
            continue
        if check.section in {"B", "C"} or check.id in {25, 30}:
            chosen.append(check.id)
    return chosen


def _can_wait(checks: list[CheckResult]) -> list[int]:
    chosen: list[int] = []
    for check in checks:
        if check.status == Status.WARNING:
            chosen.append(check.id)
        elif check.status == Status.NOT_CHECKED and check.section in {"A", "E"}:
            chosen.append(check.id)
    return chosen


def _action_text(check: CheckResult) -> str:
    base = _ACTIONS[check.id]
    if check.locations:
        where = ", ".join(check.locations[:3])
        return f"{base} Start at {where}."
    return base


def _first_actions(checks: list[CheckResult], blockers: list[int]) -> list[str]:
    by_id = {check.id: check for check in checks}
    blocker_ids = set(blockers)
    chosen: list[int] = []

    def take(predicate: Callable[[CheckResult], bool]) -> None:
        for check_id in _IMPACT:
            if len(chosen) >= 3:
                return
            if check_id in chosen:
                continue
            if predicate(by_id[check_id]):
                chosen.append(check_id)

    take(lambda check: check.id in blocker_ids)
    take(lambda check: check.status == Status.PROBLEM)
    take(lambda check: check.status == Status.NOT_CHECKED)
    take(lambda check: check.status == Status.WARNING)
    actions = [_action_text(by_id[check_id]) for check_id in chosen]
    filler = "Confirm the remaining Not checked rows with the owner and write down what success looks like."
    while len(actions) < 3:
        actions.append(filler)
    return actions[:3]
