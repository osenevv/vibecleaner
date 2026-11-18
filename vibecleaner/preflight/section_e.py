"""Section E: legal pages, localization, delivery, and ownership."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

from vibecleaner.preflight.patterns import (
    _ACCOUNTS,
    _ALLOW_ROOT,
    _AUTH_PRESENT,
    _CONTACT,
    _DISALLOW_ALL,
    _EMAIL_SDK,
    _HEALTH,
    _HOSTS,
    _I18N,
    _IMAGE_EXT,
    _IMAGE_LIMIT,
    _LEGAL_ROUTE,
    _LEGAL_STEMS,
    _MONITOR,
    _NOINDEX,
    _NOT_FOUND,
    _OAUTH,
    _OG,
    _PAYMENT,
    _UI_COMPONENT_SUFFIXES,
)
from vibecleaner.preflight.results import CheckResult, Status, _evidence, _make, _uniq
from vibecleaner.preflight.signals import (
    _accounts,
    _has_pages,
    _has_ui,
    _payments,
    _personal_data,
    _service,
    _vendors,
)
from vibecleaner.preflight.view import RepoView, _is_comment, _is_prose_path, _is_test_path


def _legal_pages(view: RepoView) -> list[str]:
    hits: list[str] = []
    for source in view.files:
        path = source.path
        if "/api/" in f"/{path}" or _is_test_path(path):
            continue
        stem = PurePosixPath(path).stem.lower()
        if any(token in stem for token in _LEGAL_STEMS) or stem in {"cookies", "returns"}:
            hits.append(f"{path}:1")
        if PurePosixPath(path).suffix.lower() in _UI_COMPONENT_SUFFIXES or stem.startswith("page"):
            for number, line in enumerate(source.text.splitlines(), start=1):
                if _LEGAL_ROUTE.search(line):
                    hits.append(f"{path}:{number}")
                    break
    return _uniq(hits)


def check_32(view: RepoView) -> CheckResult:
    pages = _legal_pages(view)
    if pages:
        return _make(
            32,
            Status.WARNING,
            "Legal-looking pages or routes are present. Whether the text matches sign-in, payments, analytics, and returns was not read.",
            _evidence(pages, "not run"),
            "A buyer can rely on terms that do not match what the service actually does.",
            "Read terms, privacy, cookies, the seller's legal identity and contact details, and shipping and returns. Success: they match real sign-in, payments, and analytics, and they include the EU 14-day withdrawal right where it applies. Confirm the wording with a lawyer for your markets.",
            pages,
        )
    if _personal_data(view) or _payments(view):
        where = (
            view.search_usage(_ACCOUNTS, skip_tests=True, limit=2)
            or view.search_usage(_PAYMENT, skip_tests=True, limit=2)
            or view.search_usage(_AUTH_PRESENT, skip_tests=True, limit=2)
        )
        return _make(
            32,
            Status.PROBLEM,
            "The service takes payments or holds account data, and no privacy, terms, cookie, imprint, or returns page was found.",
            _evidence(where, "reason: no privacy, terms, or returns page"),
            "A person cannot see who the seller is, how their data is used, or how to return a purchase.",
            "Publish terms, a privacy policy, a cookie list, the seller's legal identity and contact details, and shipping and returns (including the EU 14-day withdrawal right where it applies). Success: a lawyer for your target markets agrees the pages match the product.",
            where,
        )
    return _make(
        32,
        Status.NOT_APPLICABLE,
        "No payments and no personal-account data were found, and there is no customer legal page to compare.",
        "reason: no payments or personal data",
        "There is no customer contract in this tree to misstate.",
    )


def check_33(view: RepoView) -> CheckResult:
    if not _has_ui(view) and not _payments(view) and not _accounts(view):
        return _make(
            33,
            Status.NOT_APPLICABLE,
            "No customer-facing UI, accounts, or payments were found, so there is no consumer text to translate.",
            "reason: no customer-facing text",
            "There is no consumer notice in this tree that a market could require in a local language.",
        )
    i18n = view.search(_I18N, limit=3)
    found = "No localization library was found." if not i18n else "A localization library is referenced."
    return _make(
        33,
        Status.NOT_CHECKED,
        found + " Whether customer-facing text is in the language your markets require was not judged.",
        "not run" if not i18n else _evidence(i18n, "not run"),
        "A buyer may not receive consumer information in the language their market requires.",
        "List the markets you will sell to and confirm with a lawyer which consumer text must be in the local language (for example Quebec or France). Success: the lawyer agrees the live text meets that requirement.",
        i18n,
    )


def check_34(view: RepoView) -> CheckResult:
    if not _personal_data(view):
        return _make(
            34,
            Status.NOT_APPLICABLE,
            "No accounts, auth, or payments were found, so this tree does not show personal data leaving the region.",
            "reason: no personal data handling",
            "There is no personal data in this tree to transfer.",
        )
    vendors = [item for item in _vendors(view) if item not in {"Pydantic", "Zod", "FastAPI", "Express", "Postgres"}]
    listed = ", ".join(vendors) if vendors else "none named in code"
    return _make(
        34,
        Status.NOT_CHECKED,
        f"Personal data handling is present. Where it is stored and which vendors receive it were not verified. Vendors named in code: {listed}.",
        "not run",
        "Data can leave the region, or consent can be missing, without the safeguards a market requires.",
        "Confirm with a lawyer for your target markets: where data is stored, whether analytics or AI providers move it across borders (SCCs or an equivalent), whether consent is collected separately and recorded, and whether you have a processing record and DPAs. Success: the lawyer signs off on that list for GDPR/UK GDPR, CCPA/CPRA, and similar rules. Vendors to cross-check: "
        + listed
        + ".",
    )


def check_35(view: RepoView) -> CheckResult:
    hits = view.search(_OAUTH, skip_tests=True, limit=5)
    if not hits:
        return _make(
            35,
            Status.NOT_APPLICABLE,
            "No Google, Apple, GitHub, or other OAuth sign-in provider was found.",
            "reason: no third-party sign-in",
            "There is no third-party sign-in button that a market could block.",
        )
    return _make(
        35,
        Status.NOT_CHECKED,
        "Third-party sign-in is present. Availability in each target market, and a fallback method, were not checked.",
        _evidence(hits, "not run"),
        "A person in a market where that provider is blocked cannot create an account.",
        "For each provider, confirm it is permitted in your target markets and try the fallback (email or another provider) with that button hidden. Success: a person can still create an account where the provider does not work.",
        hits,
    )


def check_36(view: RepoView) -> CheckResult:
    if not _has_ui(view):
        return _make(
            36,
            Status.NOT_APPLICABLE,
            "No frontend markup was found, so this tree does not show third-party hosts the browser would call.",
            "reason: no frontend",
            "There is no browser page here whose third-party hosts can stall.",
        )
    hosts: list[str] = []
    locs: list[str] = []
    for pattern, label in _HOSTS:
        hit = view.first(pattern, skip_tests=True)
        if hit and PurePosixPath(hit.split(":", 1)[0]).suffix.lower() in _UI_COMPONENT_SUFFIXES | {".css", ".scss", ".js", ".ts"}:
            hosts.append(label)
            locs.append(hit)
    if hosts:
        return _make(
            36,
            Status.NOT_CHECKED,
            "Frontend code references third-party hosts: " + ", ".join(hosts) + ". Whether they load in each target region was not tested.",
            _evidence(locs, "not run"),
            "A blocked or slow host can delay the main button or break sign-in, payment, or captcha.",
            "Load the home page with those hosts blocked, and from a network in each target region. Success: the page still works or says clearly what failed. Hosts to try: "
            + ", ".join(hosts)
            + ".",
            locs,
        )
    return _make(
        36,
        Status.NOT_CHECKED,
        "No fonts.googleapis, recaptcha, hcaptcha, js.stripe.com, analytics, or common CDN host was found in frontend source. The built bundle was not loaded in a browser.",
        "not run",
        "A host added at build time can still stall the page in some regions.",
        "Open the browser network panel on the home page. Success: every third-party host is listed, and the page still works or degrades clearly where a host is blocked.",
    )


def check_37(view: RepoView) -> CheckResult:
    hits = view.search_usage(_EMAIL_SDK, skip_tests=True, limit=5)
    if not hits:
        return _make(
            37,
            Status.NOT_APPLICABLE,
            "No Resend, SendGrid, Postmark, Nodemailer, or SES client was found.",
            "reason: no email sending",
            "There is no product email whose spam placement this scan can judge.",
        )
    return _make(
        37,
        Status.NOT_CHECKED,
        "An email provider is present. SPF, DKIM, and DMARC were not queried.",
        _evidence(hits, "not run"),
        "Sign-up and receipt mail can land in spam or be spoofed.",
        "Run `dig TXT your-domain` for SPF and `dig TXT _dmarc.your-domain` for DMARC, and read the provider's DKIM selector. Success: SPF and DKIM pass, DMARC is at least `p=none` with a report address, and a test message arrives in the inbox.",
        hits,
    )


def check_38(view: RepoView) -> CheckResult:
    if not _has_ui(view) and not _has_pages(view):
        return _make(
            38,
            Status.NOT_APPLICABLE,
            "No website pages were found, so a 404 page, Open Graph tags, and robots rules do not apply.",
            "reason: no website",
            "There is no public page for a search engine to hide or preview.",
        )
    noindex: list[str] = []
    for source in view.files:
        if _is_test_path(source.path):
            continue
        name = PurePosixPath(source.path).name.lower()
        if _is_prose_path(source.path) and name != "robots.txt":
            continue
        if name == "robots.txt" and _DISALLOW_ALL.search(source.text) and not _ALLOW_ROOT.search(source.text):
            noindex.append(f"{source.path}:1")
        for number, line in enumerate(source.text.splitlines(), start=1):
            if _is_comment(line):
                continue
            if _NOINDEX.search(line):
                noindex.append(f"{source.path}:{number}")
    if noindex:
        return _make(
            38,
            Status.PROBLEM,
            "Production config marks the site noindex or robots.txt disallows the whole site.",
            _evidence(_uniq(noindex), "not run"),
            "Search engines will not list the site, so new visitors cannot find it.",
            "Remove the production noindex and the blanket Disallow if you want to be listed. Success: a public URL returns 200, the robots response allows it, and a shared link shows the intended title and image.",
            _uniq(noindex),
        )
    missing_page = [
        f"{source.path}:1"
        for source in view.files
        if PurePosixPath(source.path).name in {"not-found.tsx", "not-found.jsx", "404.tsx", "404.jsx", "404.js", "404.html"}
    ]
    handler = view.search(_NOT_FOUND, skip_tests=True, limit=2)
    og = view.search(_OG, skip_tests=True, limit=3)
    found_404 = missing_page or handler
    if found_404 and og:
        locs = _uniq(found_404 + og)
        return _make(
            38,
            Status.OK,
            "A 404 page or handler and a title or Open Graph tag are present, and no production noindex was found.",
            _evidence(locs, "not run"),
            "The preview text can still be the wrong sentence when a link is shared.",
            "Open a missing URL and paste the home page into a link preview. Success: the 404 is helpful, the title is the product name, and the preview image is intentional.",
            locs,
        )
    return _make(
        38,
        Status.WARNING,
        "No production noindex was found. "
        + ("A 404 page is present. " if found_404 else "No not-found.tsx, pages/404, or 404 handler was found. ")
        + ("A title or Open Graph tag is present." if og else "No Open Graph or metadata title was found."),
        _evidence(_uniq(found_404 + og), "reason: 404 or social preview tags are missing"),
        "A missing URL can show a blank host error, and a shared link can show the wrong title.",
        "Add a 404 page and Open Graph title and image if they are missing. Success: an unknown URL explains how to continue, and a pasted link shows the intended title and image.",
        _uniq(found_404 + og),
    )


def _static_images(view: RepoView) -> tuple[str, list[tuple[str, int]]]:
    """Return a scan state and every image under public/ or static/."""
    root = view.root_dir()
    if root is None:
        return "missing-root", []
    scanned = False
    images: list[tuple[str, int]] = []
    for folder in ("public", "static"):
        base = root / folder
        try:
            if not base.is_dir():
                continue
        except OSError:
            continue
        scanned = True
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [name for name in dirnames if name not in {".git", "node_modules"}]
            for name in filenames:
                path = Path(dirpath) / name
                if path.suffix.lower() not in _IMAGE_EXT:
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                images.append((path.relative_to(root).as_posix(), size))
    if not scanned:
        return "no-dir", []
    if not images:
        return "no-images", []
    images.sort(key=lambda item: item[1], reverse=True)
    return "scanned", images


def check_39(view: RepoView) -> CheckResult:
    state, images = _static_images(view)
    if state == "missing-root":
        return _make(
            39,
            Status.NOT_CHECKED,
            "The project directory was not on disk, so image file sizes were not measured.",
            "not run",
            "A multi-megabyte image can delay the main button on a slow connection.",
            "Open the home page on a slow connection and list files under public/ and static/. Success: the main button appears quickly and each image is under 500KB or lazy-loaded.",
        )
    if state == "no-dir":
        return _make(
            39,
            Status.NOT_APPLICABLE,
            "No public/ or static/ directory was found, so there is no shipped image directory to weigh.",
            "reason: no public or static directory",
            "There is no static image directory in this tree to delay the first screen.",
        )
    if state == "no-images":
        return _make(
            39,
            Status.NOT_APPLICABLE,
            "public/ or static/ has no image files, so there is no shipped image to weigh.",
            "reason: no image files",
            "There is no image file in this tree to delay the first screen.",
        )
    large = [item for item in images if item[1] > _IMAGE_LIMIT]
    if large:
        shown = ", ".join(f"{path} ({size // 1024}KB)" for path, size in large[:8])
        locs = [f"{path}:1" for path, _size in large[:8]]
        return _make(
            39,
            Status.WARNING,
            f"{len(large)} image(s) under public/ or static/ are over 500KB: {shown}.",
            _evidence(locs, "reason: image file size over 500KB"),
            "On a slow connection the main button can stay invisible while images download.",
            "Compress or lazy-load those files and reload the home page on a slow connection. Success: the main button is visible before the large images finish.",
            locs,
        )
    locs = [f"{path}:1" for path, _size in images[:8]]
    return _make(
        39,
        Status.OK,
        "No image under public/ or static/ is over 500KB.",
        _evidence(locs, "not run"),
        "A large image loaded from a remote URL can still delay the first screen.",
        "Open the home page on a slow connection. Success: the main button appears without waiting on a large image.",
        locs,
    )


def check_40(view: RepoView) -> CheckResult:
    vendors = _vendors(view)
    listed = ", ".join(vendors) if vendors else "none detected"
    return _make(
        40,
        Status.NOT_CHECKED,
        f"Plan limits and spend alerts were not opened. Vendors detected in code: {listed}.",
        "not run",
        "The product can stop, or the bill can jump, when a plan limit is crossed, with nobody watching.",
        "For hosting, the database, email, and AI, write down the plan limit, what the user sees when it is exceeded, and where the owner reads spend. Success: each of those three is written down for every vendor you will use. Vendors detected: "
        + listed
        + ".",
    )


def check_41(view: RepoView) -> CheckResult:
    health = view.search(_HEALTH, skip_tests=True, limit=3)
    monitor = view.search_usage(_MONITOR, skip_tests=True, limit=3)
    contact = view.search(_CONTACT, skip_tests=True, limit=3)
    if not _service(view) and not health and not monitor and not contact:
        return _make(
            41,
            Status.NOT_APPLICABLE,
            "No service entrypoint, health check, monitor, or support route was found.",
            "reason: no service to monitor",
            "There is no running service in this tree whose outage a person would report.",
        )
    locs = _uniq(health + monitor + contact)
    has_monitor = bool(health or monitor)
    if has_monitor and contact:
        return _make(
            41,
            Status.OK,
            "Monitoring or a health endpoint is present, and a contact or support route is present. Alerts and delivery were not tested.",
            _evidence(locs, "not run"),
            "An alert rule can still be missing, so sign-in fails while the home page looks fine.",
            "Cause sign-in or ordering to fail while the home page stays up, and submit the support form signed out. Success: the owner is notified and the report arrives.",
            locs,
        )
    if has_monitor or contact:
        found_bits = []
        if health:
            found_bits.append("a health endpoint")
        if monitor:
            found_bits.append("a monitoring SDK")
        if contact:
            found_bits.append("a contact route")
        return _make(
            41,
            Status.WARNING,
            "Found " + " and ".join(found_bits) + ". Both an outage signal and a signed-out support path are not both present.",
            _evidence(locs, "reason: monitoring or a support route is missing"),
            "The owner can miss an outage, or a visitor cannot report it without signing in.",
            "Add the missing piece. Success: an alert fires when sign-in or ordering fails while the home page is up, and a signed-out visitor can send a report that arrives.",
            locs,
        )
    return _make(
        41,
        Status.WARNING,
        "No Sentry, Datadog, logtail, OpenTelemetry, /health endpoint, or contact route was found.",
        "reason: no monitoring SDK, health endpoint, or support route",
        "The site can look up while sign-in or ordering is down, and a visitor cannot report it.",
        "Add an error monitor or health check with an alert, and a support route that works signed out. Success: the owner is notified of that failure and the visitor's report arrives.",
    )


def check_42(view: RepoView) -> CheckResult:
    del view
    return _make(
        42,
        Status.NOT_CHECKED,
        "Domain, hosting, payment-account, and email ownership, renewal dates, and two-factor authentication were not checked. This cannot be read from application code.",
        "not run",
        "A lapsed domain, card, or inbox can take the service offline, and a stolen password can take the account.",
        "List who owns the domain, hosting, payment account, and sending email, when each bill renews, and that two-factor authentication is on. Success: the owner can name each account, the renewal date, and the second factor without asking a vendor to recover access.",
    )
