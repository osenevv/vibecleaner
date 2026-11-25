"""Path sets and compiled patterns shared by the launch checks."""

from __future__ import annotations

import re


_ENV_EXAMPLES = frozenset({".env.example", ".env.sample", ".env.template"})
_LOCKFILES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "composer.lock",
        "Gemfile.lock",
        "packages.lock.json",
    }
)
_NPM_MANIFESTS = frozenset({"package.json"})
_PY_MANIFESTS = frozenset({"pyproject.toml", "requirements.txt", "Pipfile", "setup.py", "setup.cfg"})
_DOTNET_MANIFEST_SUFFIXES = frozenset({".csproj", ".fsproj", ".vbproj"})
_IMAGE_EXT = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".svg"})
_IMAGE_LIMIT = 500 * 1024
_MARKUP_SUFFIXES = frozenset({".tsx", ".jsx", ".html", ".htm", ".vue"})
_UI_COMPONENT_SUFFIXES = frozenset({".tsx", ".jsx", ".vue", ".html", ".htm"})
_D1 = frozenset({"D1.env_file_committed", "D1.next_public_secret", "D1.hardcoded_secret"})
_D2_RLS = frozenset({"D2.supabase_missing_rls", "D2.supabase_missing_policy"})
_D2_CORS = frozenset({"D2.cors_wildcard_credentials"})
_D3 = frozenset({"D3.missing_auth"})
_D4 = frozenset({"D4.idor_or_price_trust"})
_D5 = frozenset({"D5.prompt_injection"})
_D7A = frozenset({"D7a.n_plus_one_loop"})
_PAYMENT = re.compile(
    r"(?i)(?:\bstripe\b|@stripe/|\bSTRIPE_|loadStripe|api\.stripe\.com|\bnew\s+Stripe\b|"
    r"\bpaddle\b|\blemonsqueezy\b|\blemon[-_]squeezy\b|\bpaypal\b|\bbraintree\b|\badyen\b|"
    r"\byookassa\b|\byoo[-_]kassa\b|\bmollie\b|\brazorpay\b)"
)
_AUTH_PRESENT = re.compile(
    r"(?i)(?:\bget_current_user\b|\bcurrent_user\b|\blogin_required\b|\bsupabase\.auth\b|"
    r"\bauth\.users\b|\bNextAuth\b|\bclerkMiddleware\b|@clerk/|\bnext-auth\b|"
    r"\bcreateServerClient\b|\bpassport\b|\blucia\b|\bauth0\b|\bverifySession\b|"
    r"\bcookies\.get\s*\(|\bgetServerSession\b|"
    r"['\"][^'\"]*(?:/login|/signin|/sign-in|/signup|/sign-up|/register)[^'\"]*['\"])"
)
_AUTH_ENDPOINT = re.compile(
    r"(?i)(?:['\"][^'\"]*(?:/login\b|/signin\b|/sign-in\b|/signup\b|/sign-up\b|/register\b|"
    r"/forgot\b|/reset-password\b|/magic-link\b|/otp\b|/verify-email\b)[^'\"]*['\"]|"
    r"\bdef\s+(?:login|signin|sign_in|signup|sign_up|register|forgot_password|reset_password|send_code|verify_otp)\b|"
    r"\bsignIn\s*\()"
)
_AI_CALL = re.compile(
    r"(?:OpenAI\s*\(|Anthropic\s*\(|\bChatOpenAI\b|\blanggraph\b|chat\.completions|"
    r"messages\.create|\bgenerateText\s*\(|from\s+['\"]openai['\"]|from\s+['\"]@anthropic-ai['\"]|"
    r"from\s+['\"]anthropic['\"])"
)
_HTTP = re.compile(
    r"(?i)(?:@(?:\w+\.)?(?:get|post|put|patch|delete|api_route)\s*\(|"
    r"\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(|"
    r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|"
    r"\bFastAPI\s*\(|\bAPIRouter\s*\(|\bexpress\s*\(|"
    r"\.Map(?:Get|Post|Put|Patch|Delete)\s*\(|"
    r"\[Http(?:Get|Post|Put|Patch|Delete)\b|"
    r"\bWebApplication\.CreateBuilder\s*\()"
)
_DB = re.compile(
    r"(?i)(?:\bpsycopg\b|\basyncpg\b|\bsqlalchemy\b|\bprisma\b|\bsupabase\b|\bSUPABASE_|"
    r"\bmongodb\b|\bmongoose\b|CREATE\s+TABLE|\bpostgres\b|\bmysql\b|\bsqlite\b|"
    r"from\s+['\"]pg['\"]|\bDATABASE_URL\b|"
    r"\bDbContext\b|\bUseSqlite\b|\bUseNpgsql\b|\bUseSqlServer\b|\bSqliteConnection\b)"
)
_ACCOUNTS = re.compile(
    r"(?i)(?:\bget_current_user\b|\bsupabase\.auth\b|\bauth\.users\b|\bNextAuth\b|"
    r"\bclerkMiddleware\b|@clerk/|\bnext-auth\b|\bverifySession\b|\bgetSession\b|"
    r"\bFROM\s+sessions\b|\.cookies\.get\s*\(|"
    r"CREATE\s+TABLE\s+(?:[\w.]+\.)?users\b|"
    r"\b(?:sign_up|signup|register_user|create_user|createUser)\b|"
    r"['\"][^'\"]*(?:/signup|/sign-up|/register)[^'\"]*['\"])"
)
_DELETE_ACCOUNT = re.compile(
    r"(?i)(?:\b(?:delete_account|delete_user|deleteUser|deleteAccount)\b|"
    r"auth\.admin\.delete_user|auth\.admin\.deleteUser|"
    r"['\"][^'\"]*(?:/account/delete|/settings/delete|/users/me)[^'\"]*['\"]|"
    r"@(?:\w+\.)?delete\s*\(\s*['\"][^'\"]*account)"
)
_RATE_LIB = re.compile(
    r"(?i)(?:\bslowapi\b|\bfastapi[-_]limiter\b|\bfastapi_limiter\b|express-rate-limit|"
    r"rate-limiter-flexible|@upstash/ratelimit|\bRatelimit\b|\bRateLimiter\b|"
    r"flask[-_]limiter|django[-_]ratelimit)"
)
_UPLOAD = re.compile(
    r"(?i)(?:\bUploadFile\b|\bmulter\b|\bformidable\b|\bbusboy\b|\bFileInterceptor\b|"
    r"\.formData\s*\(|request\.files\b)"
)
_UPLOAD_SIZE = re.compile(
    r"(?i)(?:max_(?:file_)?size|fileSize|file_size|MAX_UPLOAD|maxBytes|limits\s*[:=]|"
    r"\b\d+\s*\*\s*1024\b|content-length|max_length\s*=)"
)
_UPLOAD_TYPE = re.compile(
    r"(?i)(?:content_type|mimetype|mime_type|allowed_(?:types|ext|mime)|image/(?:png|jpeg|jpg|webp|gif))"
)
_COOKIE_SET = re.compile(
    r"(?i)(?:\.set_cookie\s*\(|cookies\(\)\.set\s*\(|\bres\.cookie\s*\(|response\.cookie\s*\()"
)
_COOKIE_PROVIDER = re.compile(
    r"(?i)(?:clerkMiddleware|@clerk/|next-auth|NextAuth|createServerClient|@supabase/ssr|\blucia\b)"
)
_XSS_DYNAMIC = (
    (re.compile(r"dangerouslySetInnerHTML"), "dangerouslySetInnerHTML"),
    (re.compile(r"\.innerHTML\s*="), "innerHTML"),
    (re.compile(r"\bv-html\s*="), "v-html"),
    (re.compile(r"document\.write\s*\("), "document.write"),
    (re.compile(r"\bmark_safe\s*\("), "mark_safe"),
    (re.compile(r"\bMarkup\s*\("), "Markup"),
)
_SQL_EXEC_F = re.compile(r"(?i)\b(?:execute|executemany|\.query|\.raw)\s*\(\s*f['\"]")
_SQL_KEYWORD = re.compile(r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b")
_SQL_REQUEST = re.compile(
    r"(?i)\{[^}]*(?:request|req\b|body|params|query|form|payload|args|user_input|search)[^}]*\}"
)
_SQL_CONCAT = re.compile(
    r"(?i)\b(?:execute|executemany|\.query|\.raw)\s*\([^)\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^)\n]*\+\s*"
    r"(?:request|req\b|body|params|query|form|payload|user_input)"
)
_DEBUG_TRUE = re.compile(r"(?i)(?<![A-Za-z0-9_!=<>])DEBUG\s*=\s*True\b|(?<![A-Za-z0-9_!=<>])\bdebug\s*=\s*True\b")
_DEFAULT_SECRET = re.compile(
    r"(?i)(?:['\"]password123['\"]|['\"]admin['\"]\s*/\s*['\"]admin['\"]|"
    r"\bpassword\s*=\s*['\"](?:admin|password)['\"])"
)
_LOCALHOST = re.compile(r"https?://(?:localhost|127\.0\.0\.1)(?::\d+)?")
_TRUST_PROXY = re.compile(
    r"(?i)(?:app\.set\(\s*['\"]trust proxy['\"]\s*,\s*(?:true|1)\s*\)|"
    r"ProxyHeadersMiddleware\([^)]*['\"]\*['\"]|trusted_hosts\s*=\s*['\"]\*['\"])"
)
_SECURITY_HEADERS = re.compile(
    r"(?i)(?:\bhelmet\s*\(|Strict-Transport-Security|Content-Security-Policy|"
    r"\bSecurityHeadersMiddleware\b|\bsecure_headers\b|\bSecWeb\b)"
)
_SECURITY_HEADER_CONFIG = re.compile(
    r"(?i)(?:['\"](?:Strict-Transport-Security|Content-Security-Policy)['\"]\s*(?:[:,\]=)])|"
    r"\b(?:add_header|Header\s+(?:always\s+)?set)\s+['\"]?(?:Strict-Transport-Security|Content-Security-Policy)\b|"
    r"^\s*(?:Strict-Transport-Security|Content-Security-Policy)\s*[:=])"
)
_WEB_FRAMEWORK = re.compile(r"(?i)(?:\bFastAPI\s*\(|\bexpress\s*\(|next/server|NextResponse|from\s+['\"]express['\"])")
_ORDER_CREATE = re.compile(
    r"(?i)(?:\bINSERT\s+INTO\s+(?:[\w.]+\.)?(?:orders|order_items|checkouts)\b|"
    r"checkout\.sessions\.create|paymentIntents\.create|/v1/payment_intents|"
    r"\bcreate_order\b|\bplace_order\b)"
)
_IDEMPOTENT = re.compile(
    r"(?i)(?:Idempotency-Key|idempotency_key|idempotencyKey|\bupsert\s*\(|\.upsert\s*\(|"
    r"\bON\s+CONFLICT\b|INSERT\s+OR\s+IGNORE)"
)
_WEBHOOK_ROUTE = re.compile(
    r"(?i)(?:@(?:\w+\.)?(?:post|put|api_route)\(\s*['\"][^'\"]*webhook|"
    r"\.(?:post|put|all)\(\s*['\"][^'\"]*webhook|"
    r"\bdef\s+\w*webhook\w*\s*\(|\bfunction\s+\w*webhook\w*\s*\()"
)
_WEBHOOK_VERIFY = re.compile(
    r"(?i)(?:webhooks\.constructEvent|Webhook\.construct_event|\.construct_event\s*\(|"
    r"\bconstructEvent\s*\(|\bverify_signature\b|\bverifySignature\b)"
)
_REPLAY = re.compile(
    r"(?i)(?:\bevent_id\b|\bevent\.id\b|\bprocessed_events\b|\balready_processed\b|"
    r"Idempotency-Key|idempotency_key|\bON\s+CONFLICT\b)"
)
_TEST_KEY = re.compile(r"\b(?:sk|pk|rk)_test_[0-9A-Za-z]")
_LIVE_KEY = re.compile(r"\b(?:sk|pk|rk)_live_[0-9A-Za-z]")
_TAX_LINES = re.compile(r"(?i)(?:\bline_items\b|\bautomatic_tax\b|\btax_rate\b|\btax_rates\b|\bvat_rate\b)")
_SUBSCRIPTION = re.compile(r"(?i)(?:\bsubscription\b|\bsubscriptions\b|\btrial\b|\bpromo(?:tion)?_code\b|\bcoupon\b)")
_INVENTORY = re.compile(
    r"(?i)(?:\bstock\b|\bon_hand\b|\bquantity_on_hand\b|\bavailable_quantity\b|"
    r"\bseats_remaining\b|\btimeslot\b|\btime_slot\b|"
    r"\bbooking\b|\bbookings\b|\breservation\b|\breservations\b|"
    r"\binventory\b[^.\n]{0,80}\b(?:remaining|available|decrement)\b)"
)
_STOCK_SAFE = re.compile(
    r"(?i)(?:FOR\s+UPDATE|WHERE\s+stock\s*>\s*0|WHERE\s+quantity\s*>\s*0|"
    r"\bUNIQUE\s*\([^)]*(?:slot|booking|reservation|starts_at))"
)
_LIMIT = re.compile(r"(?i)\bLIMIT\b|\.limit\s*\(|\boffset\b")
_CREATE_INDEX = re.compile(r"(?i)\bCREATE\s+(?:UNIQUE\s+)?INDEX\b")
_SCHEDULING = re.compile(
    r"(?i)(?:\bbooking\b|\bbookings\b|\bappointment\b|\bappointments\b|\breservation\b|"
    r"\breservations\b|\btimeslot\b|\btime_slot\b|\bcalendar\b|\btimezone\b|\btime_zone\b)"
)
_NAIVE_PY = re.compile(r"\bdatetime\.(?:now|utcnow|today)\(\s*\)")
_NAIVE_JS = re.compile(r"\bnew\s+Date\(\s*(?:['\"`]|[A-Za-z_])")
_NAIVE_SQL = re.compile(r"(?i)\btimestamp\b(?!\s+with\s+time\s+zone)")
_DOWN_MIGRATION = re.compile(
    r"(?im)(?:^\s*def\s+downgrade\b|^\s*def\s+down\b|\bmigrate:down\b|--\s*\+goose\s+Down\b)"
)
_CI_TEST = re.compile(r"(?i)\b(?:pytest|npm test|pnpm test|yarn test|vitest|jest|cargo test|dotnet test)\b")
_LEGAL_STEMS = ("privacy", "terms", "cookie-policy", "cookies-policy", "imprint", "impressum", "legal-notice")
_LEGAL_ROUTE = re.compile(
    r"(?i)['\"]/(privacy|terms|cookie-policy|cookies|imprint|impressum|legal|returns|refund-policy)(?:/|['\"])"
)
_OAUTH = re.compile(
    r"(?i)(?:GoogleProvider|GithubProvider|GitHubProvider|AppleProvider|"
    r"signIn\(\s*['\"](?:google|github|apple|facebook|discord)['\"]|"
    r"accounts\.google\.com|github\.com/login/oauth|appleid\.apple\.com)"
)
_EMAIL_SDK = re.compile(
    r"(?i)(?:from\s+['\"]resend['\"]|@sendgrid/|sendgrid|postmark|nodemailer|"
    r"@aws-sdk/client-ses|SendEmailCommand|\bmailgun\b|\bemails\.send\s*\()"
)
_HOST_URL = re.compile(r"""(?i)(?:https?:)?//[^\s'"`<>)]+""")
_HOSTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"fonts\.googleapis\.com"), "fonts.googleapis.com"),
    (re.compile(r"fonts\.gstatic\.com"), "fonts.gstatic.com"),
    (re.compile(r"google\.com/recaptcha|gstatic\.com/recaptcha"), "recaptcha"),
    (re.compile(r"hcaptcha\.com"), "hcaptcha"),
    (re.compile(r"js\.stripe\.com"), "js.stripe.com"),
    (re.compile(r"googletagmanager\.com"), "googletagmanager.com"),
    (re.compile(r"google-analytics\.com"), "google-analytics.com"),
    (re.compile(r"plausible\.io"), "plausible.io"),
    (re.compile(r"posthog\.com"), "posthog.com"),
    (re.compile(r"cdn\.jsdelivr\.net"), "cdn.jsdelivr.net"),
    (re.compile(r"\bunpkg\.com\b"), "unpkg.com"),
    (re.compile(r"cdnjs\.cloudflare\.com"), "cdnjs.cloudflare.com"),
    (re.compile(r"\bsegment\.(?:com|io)\b"), "segment"),
    (re.compile(r"\bmixpanel\.com\b"), "mixpanel.com"),
)
_NOINDEX = re.compile(
    r"(?i)(?:robots\s*:\s*\{[^}{]{0,200}index\s*:\s*false|noindex\s*:\s*true|"
    r"content\s*=\s*['\"][^'\"]*noindex)"
)
_DISALLOW_ALL = re.compile(r"(?m)^[ \t]*Disallow:[ \t]*/[ \t]*$")
_ALLOW_ROOT = re.compile(r"(?m)^[ \t]*Allow:[ \t]*/[ \t]*$")
_OG = re.compile(r"(?i)(?:\bopenGraph\b|og:title|og:description|export\s+const\s+metadata\b|<title\b)")
_NOT_FOUND = re.compile(
    r"(?i)(?:exception_handler\(\s*404\s*\)|status_code\s*=\s*404|notFound\s*\()"
)
_HEALTH = re.compile(r"""(?i)['\"]/(?:health|healthz|readyz|livez)['\"]""")
_CONTACT = re.compile(r"""(?i)(?:['\"]/(?:contact|support|help)['\"]|mailto:)""")
_MONITOR = re.compile(
    r"(?i)(?:@sentry/|sentry_sdk|Sentry\.init|\bdatadog\b|\blogtail\b|\bopentelemetry\b|\bddtrace\b)"
)
_ROUTE_PATH = re.compile(
    r"""(?i)(?:@(?:\w+\.)?(?:get|post|put|patch|delete|api_route)\(\s*['\"]([^'\"]+)['\"]|"""
    r"""(?:app|router)\.(?:get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"])"""
)
_FASTAPI_TITLE = re.compile(r"""FastAPI\(\s*title\s*=\s*['\"]([^'\"]+)['\"]""")
_WEAK_HASH = re.compile(
    r"(?i)(?:(?:hashlib\s*\.\s*)?(?:md5|sha1|sha256|sha512)\s*\([^)\n]{0,120}\bpassword\b|"
    r"\bpassword\b[^.\n]{0,40}(?:hashlib\s*\.\s*)?(?:md5|sha1|sha256|sha512)\s*\()"
)
_STRONG_HASH = re.compile(
    r"(?i)(?:\bbcrypt\b|\bargon2\b|\bscrypt\b|\bpasslib\b|\bpwdlib\b|\bhashpw\s*\(|\bPasswordHasher\b|\bCryptContext\b)"
)
_PLAIN_PASSWORD = re.compile(
    r"(?i)(?:\bpassword\s+(?:TEXT|VARCHAR|STRING)\b|\bpassword\s*=\s*Column\s*\()"
)
_LOG_CALL = re.compile(
    r"(?i)(?:\b(?:logger|logging|log|console)\s*\.\s*(?:debug|info|warn|warning|error|exception|critical|log)\s*\(|"
    r"\bprint\s*\()"
)
_LOGGED_SECRET = re.compile(
    r"(?i)(?<![.\w])(?:passwords?|passwd|raw_password|plain_password|access_token|refresh_token|"
    r"id_token|api_key|secret_key|client_secret|webhook_secret|session_token|auth_token|token|secret)(?!\w)"
)
_HOSTED_AUTH = re.compile(
    r"(?i)(?:\bsupabase\.auth\b|\bauth\.users\b|\bNextAuth\b|\bclerkMiddleware\b|@clerk/|\bnext-auth\b)"
)
_CLIENT_PRICE = re.compile(
    r"(?i)(?:\bbody\s*\.\s*(?:amount|amount_cents|amountCents|price|price_cents|priceCents|total)\b|"
    r"\breq\.body\s*\.\s*(?:amount|amountCents|price|priceCents)\b)"
)
_SERVER_PRICE = re.compile(r"(?i)(?:\bprice_cents\b|\bunit_amount\b|\bcatalogue\b|\bcatalog_price\b)")
_FORM_POST = re.compile(r"(?i)<form\b[^>]*\bmethod\s*=\s*['\"]post['\"]")
_CSRF = re.compile(r"(?i)\bcsrf\b")
_SAMESITE = re.compile(r"(?i)\bsamesite\b")
_STRING_LIT = re.compile(r"(\"[^\"\n]*\"|'[^'\n]*'|`[^`\n]*`)")
_IMG = re.compile(r"<img\b([^>]*)>", re.IGNORECASE)
_INPUT = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
_LABEL_FOR = re.compile(r"<label\b[^>]*\bfor\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
_DENY_LINE = re.compile(r"(?i)\b(?:reject|invalid|denylist|disallow|do not use|don't use)\b")
_IMG_ALT = re.compile(r"\balt\s*=", re.IGNORECASE)
_INPUT_TYPE_SKIP = re.compile(
    r"\btype\s*=\s*['\"](?:hidden|submit|button|image)['\"]", re.IGNORECASE
)
_INPUT_LABELLED = re.compile(r"\b(?:aria-label|aria-labelledby)\s*=", re.IGNORECASE)
_INPUT_ID = re.compile(r"\bid\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
_COOKIE_HTTPONLY_OFF = re.compile(r"httponly\s*[:=]\s*false")
_COOKIE_SECURE_OFF = re.compile(r"\bsecure\s*[:=]\s*false")
_COOKIE_SAMESITE_NONE = re.compile(r"samesite\s*[:=]\s*['\"]?none")
_COOKIE_SECURE_WORD = re.compile(r"\bsecure\b")
_XSS_STATIC_ARG = re.compile(
    r"(?:__html\s*:\s*|mark_safe\s*\(|Markup\s*\(|innerHTML\s*=\s*|document\.write\s*\()\s*['\"`]"
)
_TEMPLATE_SAFE = re.compile(r"\|\s*safe\b")
_I18N = re.compile(r"(?i)(?:next-intl|react-i18next|\bi18n\b|gettext|vue-i18n)")
_STACK_SIGNALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Next.js", re.compile(r"next/server|next/navigation|next/font|NextRequest|next\.config")),
    ("FastAPI", re.compile(r"\bFastAPI\b|\bfrom fastapi\b|\bimport fastapi\b")),
    ("Express", re.compile(r"from ['\"]express['\"]|require\(['\"]express['\"]\)|\bexpress\s*\(")),
    ("C# / .NET", re.compile(r"\.csproj\b|\.sln\b|\bMicrosoft\.AspNetCore\b|\bnamespace\s+[A-Z][\w.]*\s*[;{]|\busing\s+System\b")),
    ("Supabase", re.compile(r"supabase|SUPABASE_", re.IGNORECASE)),
    ("Stripe", re.compile(r"\bstripe\b|@stripe/|STRIPE_|loadStripe|api\.stripe\.com", re.IGNORECASE)),
    ("Prisma", re.compile(r"@prisma/client|\bprisma\b", re.IGNORECASE)),
    ("OpenAI", re.compile(r"\bopenai\b|OPENAI_|from ['\"]openai['\"]", re.IGNORECASE)),
    ("Anthropic", re.compile(r"\banthropic\b|ANTHROPIC_|@anthropic", re.IGNORECASE)),
    ("LangGraph", re.compile(r"\blanggraph\b", re.IGNORECASE)),
    ("Clerk", re.compile(r"@clerk/|clerkMiddleware")),
    ("NextAuth", re.compile(r"next-auth|NextAuth")),
    ("Supabase Auth", re.compile(r"supabase\.auth|@supabase/ssr|@supabase/auth-helpers|auth\.users", re.IGNORECASE)),
    ("Sentry", re.compile(r"@sentry/|sentry_sdk|Sentry\.init", re.IGNORECASE)),
    ("Pydantic", re.compile(r"\bpydantic\b|from pydantic\b")),
    ("Zod", re.compile(r"from ['\"]zod['\"]")),
    ("Postgres", re.compile(r"\bpsycopg\b|\basyncpg\b|from ['\"]pg['\"]")),
    ("Resend", re.compile(r"from ['\"]resend['\"]|\bResend\s*\(")),
    ("SendGrid", re.compile(r"@sendgrid/|\bSendGrid\b", re.IGNORECASE)),
    ("Postmark", re.compile(r"\bpostmark\b", re.IGNORECASE)),
    ("Nodemailer", re.compile(r"\bnodemailer\b", re.IGNORECASE)),
    ("Datadog", re.compile(r"\bdatadog\b|\bddtrace\b", re.IGNORECASE)),
    ("OpenTelemetry", re.compile(r"\bopentelemetry\b", re.IGNORECASE)),
)
