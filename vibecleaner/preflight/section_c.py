"""Section C: payments, prices, and webhooks."""

from __future__ import annotations

import re

from vibecleaner.models import SourceFile
from vibecleaner.preflight.code_text import comments_blanked
from vibecleaner.preflight.patterns import (
    _CLIENT_PRICE,
    _D4,
    _IDEMPOTENT,
    _LIVE_KEY,
    _ORDER_CREATE,
    _REPLAY,
    _SERVER_PRICE,
    _SUBSCRIPTION,
    _TAX_LINES,
    _TEST_KEY,
    _WEBHOOK_ROUTE,
    _WEBHOOK_VERIFY,
)
from vibecleaner.preflight.results import CheckResult, Status, _evidence, _make, _uniq
from vibecleaner.preflight.signals import _na_payment, _payments
from vibecleaner.preflight.code_text import is_prose_path
from vibecleaner.preflight.view import (
    RepoView,
    _code_text,
    _is_comment,
    _is_example_env,
    _is_test_path,
)


def check_18(view: RepoView) -> CheckResult:
    if not _payments(view):
        return _na_payment(18, "There is no payment for a person to complete, decline, or refund.")
    return _make(
        18,
        Status.NOT_CHECKED,
        "A payment provider is present. A test payment, decline, cancellation, and refund were not run.",
        "not run",
        "The amount or status can disagree between the cart, the order, the receipt, and the provider.",
        "In test mode only, pay, decline, cancel, and refund. Success: amount, discount, shipping, and status match in the cart, order, receipt, and provider, and a payment for a cancelled order does not fulfill it.",
    )


def check_19(view: RepoView) -> CheckResult:
    if not _payments(view):
        return _na_payment(19, "There is no payment for which this app would send tax line items.")
    lines = view.search(_TAX_LINES, skip_tests=True, limit=5)
    if lines:
        return _make(
            19,
            Status.WARNING,
            "Line-item or tax fields are present in code. Whether the buyer receives a correct invoice for each target market was not checked.",
            _evidence(lines, "not run"),
            "A buyer can pay and not receive the invoice their market requires.",
            "Confirm with an accountant which VAT, GST, or sales-tax invoices you must send. Success: the provider gets name, quantity, price, and tax rate, and the buyer gets a receipt on payment and on refund.",
            lines,
        )
    return _make(
        19,
        Status.NOT_CHECKED,
        "A payment provider is present and no line-item or tax-rate field was found in code. Market-specific invoices were not checked.",
        "not run",
        "A buyer may not get a receipt, or tax may be missing for a market that requires it.",
        "Confirm with an accountant the VAT, GST, or sales-tax rules for your markets. Success: the provider receives name, quantity, price, and tax rate, and the buyer gets a receipt on payment and on refund.",
    )


def check_20(view: RepoView) -> CheckResult:
    if not _payments(view):
        return _na_payment(20, "There is no charge whose price a person could tamper with.")
    idor = view.locs_for(_D4)
    client: list[str] = []
    for source in view.files:
        if _is_test_path(source.path) or is_prose_path(source.path):
            continue
        if not _CLIENT_PRICE.search(_code_text(source)):
            continue
        if _SERVER_PRICE.search(source.text):
            continue
        for number, line in enumerate(source.text.splitlines(), start=1):
            if not _is_comment(line) and _CLIENT_PRICE.search(line):
                client.append(f"{source.path}:{number}")
                break
    locs = _uniq(idor + client)
    if locs:
        return _make(
            20,
            Status.PROBLEM,
            "A finding or a charge path uses a price or amount taken from the request, without a server catalogue price in the same file.",
            _evidence(locs, "not run"),
            "A person can change the price in the browser and pay less than the real total.",
            "Ignore client price, quantity, and discount and recompute the total on the server. Success: a tampered request is rejected or charged the catalogue total.",
            locs,
        )
    return _make(
        20,
        Status.NOT_CHECKED,
        "Payments are present. No D4 price-trust finding was supplied, and no obvious client amount was charged without a catalogue price. Tampering was not executed.",
        "not run",
        "A hidden field can still change the amount the provider charges.",
        "Tamper with price, quantity, and discount in the browser request. Success: the server recomputes the total from its catalogue and rejects the tampered amount.",
    )


_ORDER_TABLE = r"(?:[\w]+\.)?[\"'`]?(?:orders|order_items|checkouts)[\"'`]?"
_ORDERS_CONSTRAINT = re.compile(
    rf"(?is)(?:"
    rf"\bCREATE\s+UNIQUE\s+INDEX\b[^;]{{0,400}}\bON\s+{_ORDER_TABLE}\b|"
    rf"\b(?:CREATE|ALTER)\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?{_ORDER_TABLE}\b[^;]{{0,2500}}\bUNIQUE\b|"
    rf"\bINSERT\s+(?:OR\s+(?:IGNORE|REPLACE)\s+)?INTO\s+{_ORDER_TABLE}\b[^;]{{0,800}}\bON\s+CONFLICT\b"
    rf")"
)


def _loc_path(loc: str) -> str:
    path, sep, _line = loc.rpartition(":")
    return path if sep else loc


def _idempotency_lines(view: RepoView, paths: set[str]) -> list[str]:
    found: list[str] = []
    for path, number, line in view.iter_lines(skip_tests=True):
        if path not in paths or _is_comment(line):
            continue
        if _IDEMPOTENT.search(line):
            found.append(f"{path}:{number}")
    return found


def _orders_constraint_lines(view: RepoView) -> list[str]:
    found: list[str] = []
    for source in view.files:
        if _is_test_path(source.path) or is_prose_path(source.path):
            continue
        text = comments_blanked(source)
        for match in _ORDERS_CONSTRAINT.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            found.append(f"{source.path}:{line}")
    return _uniq(found)


def check_21(view: RepoView) -> CheckResult:
    if not _payments(view):
        return _na_payment(21, "There is no paid order to duplicate.")
    orders = view.search(_ORDER_CREATE, skip_tests=True, limit=8)
    if not orders:
        return _make(
            21,
            Status.NOT_CHECKED,
            "A payment provider is present and no order-insert or PaymentIntent creation was found in this tree.",
            "not run",
            "If orders are created in a service this scan did not see, a retry can still duplicate them.",
            "Submit one order twice at the same time and again after a dropped connection. Success: the database contains one order.",
        )
    evidence = _uniq(
        _idempotency_lines(view, {_loc_path(loc) for loc in orders}) + _orders_constraint_lines(view)
    )
    if evidence:
        locs = _uniq(orders + evidence)
        return _make(
            21,
            Status.OK,
            "Order or payment creation is present, and that file has an idempotency key or upsert, or the orders table has a unique or ON CONFLICT constraint.",
            _evidence(locs, "not run"),
            "A retry can still double-charge if the key is not the one the provider stores.",
            "Submit the same order twice, including after a dropped connection. Success: the database contains one order and the provider shows one charge.",
            locs,
        )
    return _make(
        21,
        Status.PROBLEM,
        "Order or payment creation is present, and that file has no idempotency key or upsert. No unique or ON CONFLICT constraint on the orders table was found.",
        _evidence(orders, "not run"),
        "A double click or a retried request can create two orders or two charges.",
        "Require an idempotency key on order creation and a unique constraint on the provider id. Success: two identical submits, including after a dropped connection, leave one order.",
        orders,
    )


def _webhook_files(view: RepoView) -> list[tuple[SourceFile, str]]:
    found: list[tuple[SourceFile, str]] = []
    for source in view.files:
        if _is_test_path(source.path) or is_prose_path(source.path):
            continue
        if "webhook" in source.path.lower():
            found.append((source, f"{source.path}:1"))
            continue
        for number, line in enumerate(source.text.splitlines(), start=1):
            if _is_comment(line):
                continue
            if _WEBHOOK_ROUTE.search(line):
                found.append((source, f"{source.path}:{number}"))
                break
    return found


def check_22(view: RepoView) -> CheckResult:
    if not _payments(view):
        return _na_payment(22, "There is no payment webhook to forge or replay.")
    hooks = _webhook_files(view)
    if not hooks:
        return _make(
            22,
            Status.NOT_CHECKED,
            "A payment provider is present and no webhook route was found in this tree.",
            "not run",
            "An unverified webhook, if one exists outside this tree, can mark an order paid.",
            "In the provider dashboard, open the webhook endpoint. Success: either webhooks are unused, or an invalid signature is rejected and a replayed event does not credit the payment twice.",
        )
    unverified: list[str] = []
    verified: list[str] = []
    replay_missing: list[str] = []
    for source, loc in hooks:
        code = _code_text(source)
        if _WEBHOOK_VERIFY.search(code):
            verified.append(loc)
            if not _REPLAY.search(code):
                replay_missing.append(loc)
        else:
            unverified.append(loc)
    if unverified:
        return _make(
            22,
            Status.PROBLEM,
            "A payment webhook route does not call stripe.webhooks.constructEvent, stripe.Webhook.construct_event, or another signature check.",
            _evidence(unverified, "not run"),
            "Anyone who can reach the URL can mark an order paid.",
            "Verify the signature and store the event id. Success: an invalid signature is rejected with a 4xx, and replaying a genuine event does not credit the payment twice.",
            unverified,
        )
    if replay_missing:
        return _make(
            22,
            Status.WARNING,
            "Webhook signature verification is present. No stored event id or other replay guard was found in that file.",
            _evidence(replay_missing, "not run"),
            "A retried genuine webhook can credit the same payment twice.",
            "Store the provider event id with a unique constraint before applying the payment. Success: the second delivery of the same event does not change the order again.",
            replay_missing,
        )
    return _make(
        22,
        Status.OK,
        "Webhook routes verify the signature and mention an event id, idempotency key, or conflict clause.",
        _evidence(verified, "not run"),
        "A bug in the dedup key can still apply one event twice.",
        "Send an invalid signature and replay a genuine event in test mode. Success: the first is rejected and the replay does not credit the payment twice.",
        verified,
    )


def check_23(view: RepoView) -> CheckResult:
    if not _payments(view):
        return _na_payment(23, "There is no paid plan whose trial or promo code could be reused.")
    hits = view.search(_SUBSCRIPTION, skip_tests=True, limit=5)
    if not hits:
        return _make(
            23,
            Status.NOT_APPLICABLE,
            "Payments are present, but no subscription, trial, or promo-code code was found.",
            "reason: no subscription, trial, or promo code",
            "There is no trial or discount in this tree to obtain twice.",
        )
    return _make(
        23,
        Status.NOT_CHECKED,
        "Subscription, trial, or promo-code code is present. Expiry and repeat redemption were not executed.",
        _evidence(hits, "not run"),
        "A person can keep access after cancellation or obtain a trial twice.",
        "Check access before expiry, after expiry, and after cancellation, and try the trial or code twice. Success: access ends when it should, and the second attempt is refused.",
        hits,
    )


def check_24(view: RepoView) -> CheckResult:
    if not _payments(view):
        return _na_payment(24, "There is no payment provider whose test mode could ship.")
    test_locs: list[str] = []
    live_locs: list[str] = []
    for path, number, line in view.iter_lines(skip_tests=True):
        if _is_comment(line) or _is_example_env(path) or _is_test_path(path):
            continue
        if _TEST_KEY.search(line):
            test_locs.append(f"{path}:{number}")
        if _LIVE_KEY.search(line):
            live_locs.append(f"{path}:{number}")
    if test_locs:
        both = " Both a test-mode and a live-mode prefix appear." if live_locs else ""
        return _make(
            24,
            Status.PROBLEM,
            "A test-mode key prefix (sk_test, pk_test, or rk_test) appears outside test files and env examples."
            + both
            + " The key is not printed.",
            _evidence(test_locs, "not run"),
            "Production can charge or display test-mode payments, so the buyer and the payout do not match.",
            "Remove test-mode keys from production config. In the provider dashboard confirm live keys, the webhook signing secret, the production webhook URL, and receipt or tax settings. Success: the running app rejects a test-mode key. Do not switch modes as part of this check.",
            _uniq(test_locs + live_locs),
        )
    return _make(
        24,
        Status.NOT_CHECKED,
        "No test-mode key prefix was found in non-test code. The provider dashboard was not opened.",
        "not run",
        "Live keys, the webhook secret, or the webhook URL can still be wrong when you go live.",
        "In the payment provider dashboard confirm live keys, the webhook signing secret, the production webhook URL, and receipt or tax settings, and that production refuses a test-mode key. Success: those four are set for live mode. Do not switch modes as part of this check.",
    )
