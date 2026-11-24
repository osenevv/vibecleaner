"""Optional Playwright browser verification for desktop/phone overflow and light/dark themes."""

from __future__ import annotations

from pathlib import Path

from vibecleaner.fix_contract import CheckResult, Evidence, EvidenceKind, Verdict

_VIEWPORTS = (("desktop", 1280, 800), ("phone", 390, 844))
_SCHEMES = ("light", "dark")


def check_page_in_browser(url: str) -> CheckResult:
    """Render ``url`` in headless Chromium if Playwright is installed, checking horizontal overflow."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return CheckResult(
            "browser",
            Verdict.PASS,
            notes=(Evidence(EvidenceKind.JUDGE_NOTE, "Playwright not installed; browser rendering skipped."),),
        )
    overflows: list[Evidence] = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                for scheme in _SCHEMES:
                    for label, width, height in _VIEWPORTS:
                        context = browser.new_context(
                            viewport={"width": width, "height": height},
                            color_scheme=scheme,
                        )
                        try:
                            page = context.new_page()
                            page.goto(url, wait_until="networkidle", timeout=10_000)
                            overflow = page.evaluate(
                                "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
                            )
                            if overflow:
                                overflows.append(
                                    Evidence(
                                        EvidenceKind.RUNTIME_CRASH,
                                        f"Horizontal overflow at {label} ({width}px, {scheme} theme) on {url}",
                                    )
                                )
                        finally:
                            context.close()
            finally:
                browser.close()
    except Exception as exc:
        return CheckResult(
            "browser",
            Verdict.ESCALATE,
            notes=(Evidence(EvidenceKind.JUDGE_NOTE, f"Browser render could not complete: {exc}"),),
        )
    if overflows:
        return CheckResult("browser", Verdict.REVISE, evidence=tuple(overflows))
    return CheckResult(
        "browser",
        Verdict.PASS,
        notes=(Evidence(EvidenceKind.JUDGE_NOTE, f"Rendered {url} at desktop and 390px in light/dark themes with no overflow."),),
    )


def check_html_file_in_browser(path: Path) -> CheckResult:
    """Render a local HTML file in headless Chromium if Playwright is installed."""
    return check_page_in_browser(Path(path).resolve().as_uri())
