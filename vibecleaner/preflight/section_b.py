"""Section B: accounts, cookies, secrets, and request safety."""

from __future__ import annotations

from pathlib import PurePosixPath

from vibecleaner.preflight.code_text import is_blankable, is_markup_path, request_sql_lines
from vibecleaner.preflight.patterns import (
    _AI_CALL,
    _AUTH_ENDPOINT,
    _AUTH_PRESENT,
    _COOKIE_HTTPONLY_OFF,
    _COOKIE_PROVIDER,
    _COOKIE_SAMESITE_NONE,
    _COOKIE_SECURE_OFF,
    _COOKIE_SECURE_WORD,
    _COOKIE_SET,
    _CSRF,
    _D1,
    _D2_CORS,
    _D2_RLS,
    _D3,
    _D4,
    _D5,
    _DEBUG_TRUE,
    _DEFAULT_SECRET,
    _DENY_LINE,
    _FORM_POST,
    _HOSTED_AUTH,
    _LOCALHOST,
    _LOCKFILES,
    _LOGGED_SECRET,
    _LOG_CALL,
    _MARKUP_SUFFIXES,
    _NPM_MANIFESTS,
    _PLAIN_PASSWORD,
    _PY_MANIFESTS,
    _RATE_LIB,
    _SAMESITE,
    _SECURITY_HEADER_CONFIG,
    _SECURITY_HEADERS,
    _STRONG_HASH,
    _TEMPLATE_SAFE,
    _TRUST_PROXY,
    _UPLOAD,
    _UPLOAD_SIZE,
    _UPLOAD_TYPE,
    _WEAK_HASH,
    _WEB_FRAMEWORK,
    _XSS_DYNAMIC,
    _XSS_STATIC_ARG,
)
from vibecleaner.preflight.results import CheckResult, Status, _evidence, _make, _uniq
from vibecleaner.preflight.signals import _accounts, _auth, _database, detect_stack
from vibecleaner.preflight.view import (
    RepoView,
    _is_comment,
    _is_env_file,
    _is_prose_path,
    _is_scannable_source,
    _is_test_path,
    _strip_strings,
)


def check_06(view: RepoView) -> CheckResult:
    hits = view.search(_AUTH_PRESENT, skip_tests=True, limit=5)
    if not hits and not _auth(view):
        return _make(
            6,
            Status.NOT_APPLICABLE,
            "No sign-in route, session check, or auth provider was found.",
            "reason: no authentication code",
            "There is no account flow for a person to get stuck in.",
        )
    return _make(
        6,
        Status.NOT_CHECKED,
        "Authentication code is present. Sign-up, sign-in, sign-out, and recovery were not executed, including a missing email, an expired code, and too many attempts.",
        _evidence(hits, "not run"),
        "A person can be locked out or left unsure whether the account exists.",
        "Create an account, sign in, sign out, and recover access. Success: each step finishes or names the next action; a missing email, an expired code, and too many attempts each show a clear message and do not leave a half-created session.",
        hits,
    )


def _cookie_windows(view: RepoView) -> list[str]:
    bad: list[str] = []
    for source in view.files:
        if _is_test_path(source.path) or not _is_scannable_source(source):
            continue
        lines = view.comments_only_blanked(source).splitlines()
        for index, line in enumerate(lines):
            if _is_comment(line) or not _COOKIE_SET.search(line):
                continue
            window = "\n".join(lines[index : index + 16]).lower()
            if _COOKIE_HTTPONLY_OFF.search(window):
                bad.append(f"{source.path}:{index + 1}")
                continue
            if _COOKIE_SECURE_OFF.search(window):
                bad.append(f"{source.path}:{index + 1}")
                continue
            if _COOKIE_SAMESITE_NONE.search(window):
                bad.append(f"{source.path}:{index + 1}")
                continue
            has_http = "httponly" in window
            has_secure = _COOKIE_SECURE_WORD.search(window) is not None
            has_same = "samesite" in window
            if not (has_http and has_secure and has_same):
                bad.append(f"{source.path}:{index + 1}")
    return _uniq(bad)


def _form_posts(view: RepoView) -> list[str]:
    return view.search(_FORM_POST, skip_tests=True, suffixes=_MARKUP_SUFFIXES, limit=8)


def check_07(view: RepoView) -> CheckResult:
    bad_cookies = _cookie_windows(view)
    forms = _form_posts(view)
    provider = view.search_usage(_COOKIE_PROVIDER, skip_tests=True, limit=3)
    csrf = view.search(_CSRF, skip_tests=True, limit=1)
    samesite = view.search(_SAMESITE, skip_tests=True, limit=1)
    cookie_sets = view.search_usage(_COOKIE_SET, skip_tests=True, limit=8)
    cookie_session = bool(bad_cookies or provider or cookie_sets)
    if bad_cookies:
        return _make(
            7,
            Status.PROBLEM,
            "A cookie is set without HttpOnly, Secure, and SameSite all enabled. Sign-out on the server was not executed.",
            _evidence(bad_cookies, "not run"),
            "A script or an insecure request can steal the session, and another site may be able to submit actions.",
            "Set HttpOnly, Secure, and SameSite on every session cookie, revoke the session on the server at sign-out, and require a CSRF token on cookie-authenticated form posts. Success: the browser shows those three flags and a forged cross-site POST is rejected.",
            bad_cookies,
        )
    if cookie_session and forms and not csrf and not samesite:
        return _make(
            7,
            Status.PROBLEM,
            "Cookie-backed sessions and POST forms were found, with no CSRF token and no SameSite attribute.",
            _evidence(forms, "not run"),
            "Another site can submit the form while the person is signed in.",
            "Add a CSRF token or SameSite=Lax/Strict on the session cookie. Success: a cross-site POST without the token is rejected, and sign-out revokes the server session.",
            forms,
        )
    if cookie_sets:
        return _make(
            7,
            Status.WARNING,
            "Cookie setters include HttpOnly, Secure, and SameSite. Server-side sign-out was not executed.",
            _evidence(cookie_sets, "not run"),
            "The browser can drop the cookie while the server still accepts the old session.",
            "Sign out and call the API with the old cookie. Success: the server rejects it, and a cross-site POST without a CSRF token fails.",
            cookie_sets,
        )
    if provider:
        return _make(
            7,
            Status.WARNING,
            "Session cookies appear to be set by a known auth provider. Flags, server-side sign-out, and CSRF were not executed.",
            _evidence(provider, "not run"),
            "A provider default can omit Secure or leave a revoked browser cookie accepted by the server.",
            "In the provider settings, confirm HttpOnly, Secure, and SameSite, sign out, and retry the old session. Success: the old cookie is rejected and a cross-site form post fails.",
            provider,
        )
    if _auth(view):
        return _make(
            7,
            Status.NOT_CHECKED,
            "Auth code is present and no set_cookie, cookies().set, or res.cookie call was found. If the app uses only bearer tokens, CSRF does not apply to those calls; server-side sign-out was not executed.",
            "not run",
            "A person can look signed out in the browser while the server still accepts the session.",
            "Sign out, then call the API with the old cookie or token. Success: the server rejects it. If any cookie is set inside a library, it is HttpOnly, Secure, and SameSite, and cookie-authenticated POST forms use a CSRF token or SameSite.",
        )
    return _make(
        7,
        Status.NOT_APPLICABLE,
        "No session cookies and no authentication code were found.",
        "reason: no cookies and no auth",
        "There is no session cookie for another site to reuse.",
    )


def check_08(view: RepoView) -> CheckResult:
    locs = view.locs_for(_D3 | _D4 | _D2_RLS)
    if locs:
        rules = sorted({item.rule_id for item in view.findings if item.rule_id in (_D3 | _D4 | _D2_RLS)})
        return _make(
            8,
            Status.PROBLEM,
            "Existing findings mark missing authentication, client-trusted identity or price, or Supabase RLS gaps ("
            + ", ".join(rules)
            + ").",
            _evidence(locs, "not run"),
            "One account can read or change another account's data, or skip an admin check.",
            "Fix the cited lines, then repeat with two test accounts, including direct API calls. Success: each account sees and changes only its own rows and files, and a normal account cannot call an admin operation.",
            locs,
        )
    if _database(view) or _auth(view) or _accounts(view):
        return _make(
            8,
            Status.NOT_CHECKED,
            "Data access or accounts are present. Two-account authorization was not executed, and no D3, D4, or Supabase RLS finding was supplied.",
            "not run",
            "One person may be able to read or change another person's rows or files.",
            "Use two test accounts, including direct API requests and direct database requests if the browser can reach the database. Success: each account sees and changes only its own data and files, and admin operations are refused for a normal account.",
        )
    return _make(
        8,
        Status.NOT_APPLICABLE,
        "No user data access or accounts were found.",
        "reason: no accounts or database access",
        "There is no per-account data to mix up.",
    )


def _xss_hits(view: RepoView) -> tuple[list[str], list[str]]:
    problems: list[str] = []
    warnings: list[str] = []
    for source in view.files:
        if _is_test_path(source.path) or _is_prose_path(source.path):
            continue
        if not is_blankable(source) and not is_markup_path(source.path):
            continue
        lines = view.code_only(source).splitlines()
        suffix = PurePosixPath(source.path).suffix.lower()
        for index, line in enumerate(lines):
            if _is_comment(line):
                continue
            window = "\n".join(lines[index : index + 4])
            for pattern, _name in _XSS_DYNAMIC:
                if not pattern.search(line):
                    continue
                static = _XSS_STATIC_ARG.search(window) is not None
                loc = f"{source.path}:{index + 1}"
                if static:
                    warnings.append(loc)
                else:
                    problems.append(loc)
            if suffix in {".html", ".htm", ".vue", ".jinja", ".j2"} and _TEMPLATE_SAFE.search(line):
                problems.append(f"{source.path}:{index + 1}")
        for line in request_sql_lines(source):
            problems.append(f"{source.path}:{line}")
    return _uniq(problems), _uniq(warnings)


def check_09(view: RepoView) -> CheckResult:
    problems, warnings = _xss_hits(view)
    if problems:
        return _make(
            9,
            Status.PROBLEM,
            "An HTML sink or SQL built from request data was found. A quote or script in a field may run or change the query.",
            _evidence(problems, "not run"),
            "A visitor can run a script in another person's browser, or change the query.",
            "Enter a quote and <script>alert(1)</script> into fields and the URL. Success: the script does not run and the request does not change the query.",
            problems,
        )
    if warnings:
        return _make(
            9,
            Status.WARNING,
            "An HTML sink is present with a static string. Confirm no user-controlled value is passed to it later.",
            _evidence(warnings, "not run"),
            "If a later change passes user text into that sink, the script runs in the browser.",
            "Search the sink's argument and enter <script>alert(1)</script> in the matching field. Success: the page shows the text and does not run it.",
            warnings,
        )
    return _make(
        9,
        Status.NOT_CHECKED,
        "No dangerouslySetInnerHTML, innerHTML, v-html, mark_safe, Markup, document.write, or request-built SQL was found. Fields were not exercised.",
        "not run",
        "A sink that this scan did not name can still run a script or break a query.",
        "Enter a quote and <script>alert(1)</script> into every field and the URL. Success: the script does not run and the request does not break.",
    )


def _gitignore_env_line(view: RepoView) -> str | None:
    for source in view.files:
        if PurePosixPath(source.path).name != ".gitignore":
            continue
        for number, line in enumerate(source.text.splitlines(), start=1):
            raw = line.strip()
            if not raw or raw.startswith("#") or raw.startswith("!"):
                continue
            if raw in {".env", ".env*", "**/.env", "**/.env*"}:
                return f"{source.path}:{number}"
    root = view.root_dir()
    if root is None:
        return None
    path = root / ".gitignore"
    try:
        if not path.is_file():
            return None
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    for number, line in enumerate(text.splitlines(), start=1):
        raw = line.strip()
        if raw in {".env", ".env*", "**/.env", "**/.env*"}:
            return f".gitignore:{number}"
    return None


def check_10(view: RepoView) -> CheckResult:
    secret_locs = view.locs_for(_D1)
    env_locs = [f"{source.path}:1" for source in view.files if _is_env_file(source.path)]
    covered = _gitignore_env_line(view)
    if secret_locs or (env_locs and covered is None):
        locs = _uniq(secret_locs + env_locs)
        detail = "A committed secret finding or a .env file without a .gitignore rule was found."
        if env_locs and covered is None:
            detail = "A .env file is in the tree and .gitignore does not ignore .env."
        if secret_locs:
            detail = "Secret findings are present" + (" and a .env file is in the tree." if env_locs else ".")
        return _make(
            10,
            Status.PROBLEM,
            detail + " Values are not printed. Git history and built bundles were not scanned.",
            _evidence(locs, "not run"),
            "Anyone with the repo or the bundle can use the key until it is rotated.",
            "Remove the file from the tree, add `.env*` to .gitignore (keep `.env.example`), rotate every key, then run `gitleaks detect` and `trufflehog git file://.` and scan the built bundle. Success: both commands are clean and the old keys no longer work.",
            locs,
        )
    if covered and not secret_locs and not env_locs:
        return _make(
            10,
            Status.OK,
            ".gitignore ignores .env and the scan found no D1 secret finding and no committed .env file. Git history and built bundles were not scanned.",
            _evidence([covered], "not run"),
            "A key that is only in old commits or in a built bundle can still be used.",
            "Run `gitleaks detect` and `trufflehog git file://.` and scan the built `.next` or `dist` output. Success: both finish with nothing to rotate, or every reported key has been rotated.",
            [covered],
        )
    return _make(
        10,
        Status.WARNING,
        "No D1 secret finding and no committed .env file were found, and .gitignore has no `.env` or `.env*` rule. History and bundles were not scanned.",
        "reason: .gitignore does not cover .env",
        "The next .env that someone adds can be committed with every key in it.",
        "Add `.env*` to .gitignore, keep `.env.example`, and run `gitleaks detect` and `trufflehog git file://.`. Success: a new .env is ignored and both scans are clean or every leaked key is rotated.",
    )


def check_11(view: RepoView) -> CheckResult:
    locks = view.named(_LOCKFILES)
    npm = view.named(_NPM_MANIFESTS)
    pip = view.named(_PY_MANIFESTS)
    if not npm and not pip:
        return _make(
            11,
            Status.NOT_APPLICABLE,
            "No package.json, pyproject.toml, requirements.txt, or Pipfile was found, so there is no dependency manifest to audit.",
            "reason: no dependency manifest",
            "There is no declared dependency set for a known vulnerability to hide in.",
        )
    commands: list[str] = []
    if npm:
        commands.append("`npm audit --omit=dev`")
    if pip:
        commands.append("`pip-audit`")
    command_text = " and ".join(commands)
    if locks:
        return _make(
            11,
            Status.NOT_CHECKED,
            "A lockfile is present (" + ", ".join(locks) + "). Known vulnerabilities were not queried, because that needs a network audit.",
            _evidence(locks, "not run"),
            "A locked dependency can still have a known vulnerability.",
            f"Run {command_text} from the repo root. Success: the report has no unfixed advisory at or above the severity you are willing to ship, or each one has a written reason.",
            locks,
        )
    return _make(
        11,
        Status.WARNING,
        "A dependency manifest is present and no lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, uv.lock, or similar) was found.",
        "reason: no lockfile next to the manifest",
        "Two installs can resolve different versions, including a known-vulnerable one.",
        f"Commit a lockfile and run {command_text}. Success: the install is reproducible and the audit has no unfixed advisory you have not accepted.",
    )


def _secret_log_locs(view: RepoView) -> list[str]:
    found: list[str] = []
    for path, number, line in view.iter_lines(skip_tests=True):
        if _is_comment(line) or not _LOG_CALL.search(line):
            continue
        if _LOGGED_SECRET.search(_strip_strings(line)):
            found.append(f"{path}:{number}")
    return _uniq(found)


def check_12(view: RepoView) -> CheckResult:
    weak = view.search_usage(_WEAK_HASH, skip_tests=True, limit=8)
    plain = view.search(_PLAIN_PASSWORD, skip_tests=True, limit=5)
    logged = _secret_log_locs(view)
    strong = view.search_usage(_STRONG_HASH, skip_tests=True, limit=5)
    problems = _uniq(weak + plain + logged)
    if problems:
        bits: list[str] = []
        if weak:
            bits.append("a password is hashed with md5, sha1, or sha256")
        if plain:
            bits.append("a password column looks like plaintext")
        if logged:
            bits.append("a password, token, or secret variable is passed to a log or print")
        return _make(
            12,
            Status.PROBLEM,
            "Password handling is unsafe: " + "; ".join(bits) + ". Values are not printed.",
            _evidence(problems, "not run"),
            "A leaked database or log lets someone reuse the password or the token.",
            "Hash passwords only with bcrypt, argon2, or scrypt, and remove secret values from logs. Success: stored passwords use a `$2b$` or `$argon2` prefix and a log line from a failed login contains no password or token.",
            problems,
        )
    if strong:
        return _make(
            12,
            Status.OK,
            "Password hashing uses bcrypt, argon2, scrypt, or passlib, and no weak hash or secret logging was found. Encryption of personal data at rest was not verified.",
            _evidence(strong, "not run"),
            "A database backup can still be readable if the disk itself is not encrypted.",
            "Confirm with your host that the database and backups are encrypted at rest. Success: the provider names encryption at rest, and logs from a login attempt contain no password or token.",
            strong,
        )
    if _HOSTED_AUTH.search(view.usage_blob(skip_tests=True)):
        return _make(
            12,
            Status.NOT_CHECKED,
            "Sign-in is delegated to a hosted provider. This tree does not show the password hash, encryption at rest, or provider logs.",
            "not run",
            "The provider could store a fast hash, or the app could still log a token.",
            "Read the provider's security note and your logs. Success: passwords use bcrypt, argon2, or scrypt, personal data is encrypted at rest and in backups, and logs contain no passwords, codes, or tokens.",
        )
    return _make(
        12,
        Status.NOT_APPLICABLE,
        "No password storage, password column, or logging of password, token, or secret variables was found.",
        "reason: no password handling in scanned code",
        "There is no password in this tree to store or log.",
    )


def check_13(view: RepoView) -> CheckResult:
    limiter = view.search_usage(_RATE_LIB, skip_tests=True, limit=5)
    endpoints = _uniq(
        view.search(_AUTH_ENDPOINT, skip_tests=True, limit=8)
        + view.search_usage(_AI_CALL, skip_tests=True, limit=8)
    )
    if limiter:
        return _make(
            13,
            Status.WARNING,
            "A rate-limit library is present. Coverage of sign-in, code sending, uploads, and AI calls was not executed.",
            _evidence(limiter, "not run"),
            "An unlimited route can still exhaust a shared quota or lock another person out.",
            "Confirm the limiter wraps sign-in, code and email sending, uploads, and AI calls, and that one account cannot lock another. Success: the next attempt after the limit is refused, and a second account still works.",
            limiter,
        )
    if endpoints:
        return _make(
            13,
            Status.PROBLEM,
            "Sign-in or AI calls are present and no rate-limit library (slowapi, fastapi-limiter, express-rate-limit, rate-limiter-flexible, @upstash/ratelimit, or similar) was found.",
            _evidence(endpoints, "not run"),
            "One caller can exhaust the AI or email budget, or hammer sign-in.",
            "Add a limit on those routes. Success: attempts past the limit are refused, a second account is not locked out, and the limit cannot be bypassed by spoofing X-Forwarded-For.",
            endpoints,
        )
    return _make(
        13,
        Status.NOT_APPLICABLE,
        "No sign-in, verification-code, or AI call was found to rate-limit.",
        "reason: no sign-in or AI endpoint",
        "There is no sign-in or AI route here for one caller to exhaust.",
    )


def check_14(view: RepoView) -> CheckResult:
    uploads = view.search_usage(_UPLOAD, skip_tests=True, limit=8)
    if not uploads:
        return _make(
            14,
            Status.NOT_APPLICABLE,
            "No UploadFile, multer, formidable, or formData file upload was found.",
            "reason: no file upload",
            "There is no upload another person could overwrite or oversize.",
        )
    size = view.search(_UPLOAD_SIZE, skip_tests=True, limit=3)
    kind = view.search(_UPLOAD_TYPE, skip_tests=True, limit=3)
    if size and kind:
        locs = _uniq(uploads + size + kind)
        return _make(
            14,
            Status.WARNING,
            "Upload handling includes a size limit and a type or MIME check. Access to another account's file by link was not tested.",
            _evidence(locs, "not run"),
            "A shared or guessable file URL can still expose someone else's file.",
            "Upload an oversized file and a disallowed type with two accounts. Success: both bad uploads are refused, and one account cannot open the other's file by changing the link.",
            locs,
        )
    missing = []
    if not size:
        missing.append("a size limit")
    if not kind:
        missing.append("a type or MIME allow-list")
    return _make(
        14,
        Status.PROBLEM,
        "File upload code is present and is missing " + " and ".join(missing) + ".",
        _evidence(uploads, "not run"),
        "A person can upload a huge or unexpected file, or open a file that is not theirs.",
        "Add a max size and an allow-list of types, and authorize every download. Success: an oversized or wrong-type file is refused, and another account's link returns a refusal.",
        uploads,
    )


def check_15(view: RepoView) -> CheckResult:
    calls = view.search_usage(_AI_CALL, skip_tests=True, limit=8)
    if not calls:
        return _make(
            15,
            Status.NOT_APPLICABLE,
            "No OpenAI, Anthropic, LangGraph, or other AI SDK call was found.",
            "reason: no AI call",
            "There is no model prompt another person could try to extract.",
        )
    leaks = view.locs_for(_D5)
    if leaks:
        return _make(
            15,
            Status.PROBLEM,
            "A prompt-injection finding (D5.prompt_injection) says untrusted text reaches instructions or an unvalidated tool.",
            _evidence(leaks, "not run"),
            "A person can pull the system prompt or another user's data through the model.",
            "Keep user text in the user role and validate tool arguments. Success: a test chat that asks for the system prompt and for another user's data is refused.",
            leaks,
        )
    return _make(
        15,
        Status.NOT_CHECKED,
        "An AI SDK call is present. No D5 finding was supplied. A jailbreak attempt was not run.",
        _evidence(calls, "not run"),
        "The model may reveal its instructions or another user's data.",
        "In a test chat, ask for the system prompt and for another user's records. Success: the model refuses, user text stays in the user role, and no other account's data is returned.",
        calls,
    )


def check_16(view: RepoView) -> CheckResult:
    debug = view.search_usage(_DEBUG_TRUE, skip_tests=True, limit=8)
    defaults: list[str] = []
    for path, number, line in view.iter_lines(skip_tests=True):
        if _is_comment(line) or _DENY_LINE.search(line):
            continue
        if _DEFAULT_SECRET.search(line):
            defaults.append(f"{path}:{number}")
    localhost = view.search(_LOCALHOST, skip_tests=True, skip_config=True, limit=8)
    problems = _uniq(debug + defaults)
    if problems:
        bits = []
        if debug:
            bits.append("debug is set on")
        if defaults:
            bits.append("a default password such as password123 or admin/admin is present")
        extra = ""
        if localhost:
            extra = " Localhost URLs also appear outside config and tests."
        return _make(
            16,
            Status.PROBLEM,
            "Production settings look unsafe: " + " and ".join(bits) + "." + extra + " Secret values are not printed.",
            _evidence(problems + localhost, "not run"),
            "A visitor can hit a debug page, sign in with a known password, or follow a localhost link that does not resolve.",
            "Turn debug off, delete default accounts and passwords, and replace localhost links used in emails or redirects. Success: an internal error shows a generic page, the error is logged, and those passwords do not work.",
            _uniq(problems + localhost),
        )
    if localhost:
        return _make(
            16,
            Status.WARNING,
            "Localhost or 127.0.0.1 URLs appear outside tests and config files. Debug flags and default passwords were not found.",
            _evidence(localhost, "not run"),
            "A person can receive an email or redirect that points at the developer's machine.",
            "Replace those URLs with the public origin before launch. Success: no customer-facing link contains localhost or 127.0.0.1, and a forced error shows a generic page that is logged.",
            localhost,
        )
    return _make(
        16,
        Status.NOT_CHECKED,
        "No DEBUG = True, debug=True, default password, or localhost URL was found outside tests and config. The production process and its error page were not run.",
        "not run",
        "The deployed process can still run with debug on, or show a stack trace to a visitor.",
        "Open a page that raises and inspect the production environment. Success: debug is off, the visitor sees a generic error, the error is logged, and no test account or default password works.",
    )


def check_17(view: RepoView) -> CheckResult:
    cors = view.locs_for(_D2_CORS)
    proxy = view.search(_TRUST_PROXY, skip_tests=True, limit=5)
    headers = _uniq(
        view.search_usage(_SECURITY_HEADERS, skip_tests=True, limit=5)
        + view.search(_SECURITY_HEADER_CONFIG, skip_tests=True, limit=5)
    )[:5]
    web = (
        bool(_WEB_FRAMEWORK.search(view.usage_blob()))
        or "Next.js" in detect_stack(view)
        or "FastAPI" in detect_stack(view)
        or "Express" in detect_stack(view)
    )
    if cors:
        extra = " X-Forwarded-For is trusted from any client." if proxy else ""
        return _make(
            17,
            Status.PROBLEM,
            "Wildcard CORS is combined with credentials." + extra,
            _evidence(_uniq(cors + proxy), "not run"),
            "Another website can make credentialed requests, and a spoofed X-Forwarded-For can bypass a limit if proxy trust is open.",
            "List explicit origins and stop trusting every proxy address. Success: a foreign origin does not receive Access-Control-Allow-Credentials, and spoofing X-Forwarded-For does not raise the rate limit.",
            _uniq(cors + proxy),
        )
    if not web and not proxy and not headers:
        return _make(
            17,
            Status.NOT_APPLICABLE,
            "No web framework, security-header middleware, or proxy-trust setting was found.",
            "reason: no web server configuration",
            "There is no app server here whose headers or CORS this scan can judge.",
        )
    if proxy or not headers:
        locs = proxy or []
        if proxy and headers:
            return _make(
                17,
                Status.WARNING,
                "Security headers are present, and the app trusts a proxy wildcard (`trust proxy` or ProxyHeadersMiddleware with `*`).",
                _evidence(proxy, "not run"),
                "A client can spoof X-Forwarded-For and skip a rate limit or log the wrong address.",
                "Trust only your real proxy. Success: a forged X-Forwarded-For does not change the client address you limit or log, HSTS and CSP are on the response, and .env and .git are not served.",
                proxy,
            )
        if proxy:
            found = "The app trusts every proxy address (`trust proxy` true or ProxyHeadersMiddleware with `*`)."
            if not headers:
                found += " No helmet, HSTS, or CSP middleware was found."
        else:
            found = "A web framework is present and no helmet, HSTS, or Content-Security-Policy middleware was found."
        return _make(
            17,
            Status.WARNING,
            found,
            _evidence(locs, "reason: no HSTS/CSP middleware and no CORS finding"),
            "A browser may accept a downgrade or an injected script, or a client may spoof its address.",
            "Turn on HTTPS-only, HSTS, and CSP, and confirm CORS lists only your origins. Success: responses include those headers, a foreign origin is refused, spoofing X-Forwarded-For does not raise limits, and .env and .git are not served.",
            locs,
        )
    return _make(
        17,
        Status.OK,
        "Security-header middleware or HSTS/CSP configuration is present, and no wildcard CORS-with-credentials finding was supplied.",
        _evidence(headers, "not run"),
        "HTTPS, request size, and whether .env is served still depend on the host.",
        "Fetch a production response. Success: it is HTTPS, includes HSTS and CSP, CORS lists only your origins, and .env and .git return a refusal.",
        headers,
    )
