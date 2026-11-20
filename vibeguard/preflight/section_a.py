"""Section A: first screen, main flow, states, refresh, and labels."""

from __future__ import annotations

from pathlib import PurePosixPath

from vibeguard.preflight.patterns import (
    _IMG,
    _IMG_ALT,
    _INPUT,
    _INPUT_ID,
    _INPUT_LABELLED,
    _INPUT_TYPE_SKIP,
    _LABEL_FOR,
    _MARKUP_SUFFIXES,
)
from vibeguard.preflight.results import CheckResult, Status, _evidence, _make, _uniq
from vibeguard.preflight.signals import _has_pages, _has_ui, _http
from vibeguard.preflight.view import RepoView, _is_test_path


def check_01(view: RepoView) -> CheckResult:
    if not _has_ui(view) and not _has_pages(view):
        return _make(
            1,
            Status.NOT_APPLICABLE,
            "No home page or other customer-facing screen was found, so there is no first screen to read.",
            "reason: no customer-facing page in the scanned files",
            "A visitor who never sees an offer cannot start.",
        )
    return _make(
        1,
        Status.NOT_CHECKED,
        "Code can name pages and routes, but it cannot show what a new visitor understands from the first screen.",
        "not run",
        "A visitor may leave because the offer, the price, or the starting point is unclear.",
        "Open the home page signed out, on a desktop width and on a phone. Success: within a few seconds you can say what the service does, what it costs (or that it is free), and which control starts the main task.",
    )


def check_02(view: RepoView) -> CheckResult:
    if not _has_ui(view) and not _http(view):
        return _make(
            2,
            Status.NOT_APPLICABLE,
            "No pages or HTTP routes were found, so there is no main flow to walk.",
            "reason: no pages or HTTP routes",
            "There is no visitor flow to break.",
        )
    sides = ""
    blob = view.blob().lower()
    if any(token in blob for token in ("seller", "buyer", "merchant", "customer")):
        sides = " The names in code suggest more than one side; walk each side."
    return _make(
        2,
        Status.NOT_CHECKED,
        "Routes and pages were not executed on a desktop width or on a phone." + sides,
        "not run",
        "A control can sit off-screen or a step can be impossible on a phone, so the person never reaches the result.",
        "Walk the main flow to the result on a desktop width and on a phone. Success: menus, forms, and buttons are usable, there is no horizontal scroll, and both sides work when the product has two.",
    )


def check_03(view: RepoView) -> CheckResult:
    if not _has_ui(view):
        return _make(
            3,
            Status.NOT_APPLICABLE,
            "No customer-facing UI files were found, so loading, empty, and form-error screens do not apply.",
            "reason: no customer-facing UI",
            "There is no screen on which a person waits, sees nothing, or fixes a form.",
        )
    loading: list[str] = []
    errors: list[str] = []
    for source in view.files:
        parts = PurePosixPath(source.path).parts
        if "app" not in parts:
            continue
        name = PurePosixPath(source.path).name
        if name in {"loading.tsx", "loading.jsx"}:
            loading.append(f"{source.path}:1")
        if name in {"error.tsx", "error.jsx"}:
            errors.append(f"{source.path}:1")
    if loading and errors:
        locs = loading + errors
        return _make(
            3,
            Status.WARNING,
            "Next.js loading and error files are present, so those two states exist in the app router. Empty results and whether typed input survives an error were not run.",
            _evidence(locs, "not run"),
            "A person can still face a blank screen or lose what they typed when a form fails.",
            "Submit a slow request, an empty search, and an invalid form. Success: each state says what to do next, and the invalid form still shows what the person typed.",
            locs,
        )
    if _has_pages(view):
        missing = []
        if not loading:
            missing.append("loading.tsx")
        if not errors:
            missing.append("error.tsx")
        return _make(
            3,
            Status.WARNING,
            "No " + " or ".join(missing) + " was found under an app/ route. Inline spinners may still exist; they were not executed.",
            "reason: no app router loading.tsx or error.tsx for the missing state",
            "A slow or failed request can look frozen, with no next step.",
            "Use the main form on a slow network, with no results, and with a validation error. Success: each state names a next step and keeps the typed input.",
        )
    return _make(
        3,
        Status.NOT_CHECKED,
        "UI files exist, but no Next.js loading.tsx or error.tsx convention was found to judge loading and error states.",
        "not run",
        "A person may not know whether the app is working, empty, or failed.",
        "Use the main form while data loads, when the result is empty, and when validation fails. Success: each state says what to do, and typed input is still there.",
    )


def check_04(view: RepoView) -> CheckResult:
    if not _has_ui(view) and not _http(view):
        return _make(
            4,
            Status.NOT_APPLICABLE,
            "No pages or forms were found, so refresh, Back, and double submit do not apply.",
            "reason: no pages or forms",
            "There is no browser history or form to submit twice.",
        )
    return _make(
        4,
        Status.NOT_CHECKED,
        "Refresh, Back, and a second submit were not executed.",
        "not run",
        "A person can lose a finished result or create two orders by submitting twice.",
        "Refresh the page, press Back, close the tab and reopen it, and submit the main form twice. Success: the result is still there, and the database contains one record.",
    )


def check_05(view: RepoView) -> CheckResult:
    img_locs: list[str] = []
    input_locs: list[str] = []
    markup = False
    for source in view.files:
        suffix = PurePosixPath(source.path).suffix.lower()
        if suffix not in _MARKUP_SUFFIXES or _is_test_path(source.path):
            continue
        if "/api/" in f"/{source.path}":
            continue
        markup = True
        text = source.text
        label_ids = set(_LABEL_FOR.findall(text))
        for match in _IMG.finditer(text):
            if _IMG_ALT.search(match.group(1)) is None:
                img_locs.append(f"{source.path}:{text.count(chr(10), 0, match.start()) + 1}")
        for match in _INPUT.finditer(text):
            attrs = match.group(1)
            if _INPUT_TYPE_SKIP.search(attrs):
                continue
            if _INPUT_LABELLED.search(attrs):
                continue
            id_match = _INPUT_ID.search(attrs)
            if id_match and id_match.group(1) in label_ids:
                continue
            input_locs.append(f"{source.path}:{text.count(chr(10), 0, match.start()) + 1}")
    if not markup:
        return _make(
            5,
            Status.NOT_APPLICABLE,
            "No HTML, JSX, or Vue markup was found, so labels, alt text, and contrast do not apply to this tree.",
            "reason: no customer-facing markup",
            "There is no form or image in the scanned UI for a person to misread.",
        )
    locs = _uniq(img_locs + input_locs)
    if locs:
        return _make(
            5,
            Status.WARNING,
            f"Markup has {len(img_locs)} img tag(s) without alt and {len(input_locs)} input(s) without a label, aria-label, or aria-labelledby. Contrast and keyboard use were not measured.",
            _evidence(locs, "not run"),
            "A person using a screen reader or the keyboard can be unable to complete the form (WCAG 2.2).",
            "Give each image an alt and each field a label. Then complete the form with the keyboard only and check text contrast at 4.5:1. Success: every field name is announced and the form submits without a pointer.",
            locs[:12],
        )
    return _make(
        5,
        Status.NOT_CHECKED,
        "Scanned markup has no img without alt and no input missing a label or aria-label. Contrast and keyboard use were not measured.",
        "not run",
        "Low contrast or a keyboard trap can still block the form.",
        "Compare screens with the design system if there is one, check contrast at 4.5:1 (WCAG 2.2 AA), and complete the main form with the keyboard only. Success: every field is reachable and named, and contrast meets 4.5:1.",
    )
