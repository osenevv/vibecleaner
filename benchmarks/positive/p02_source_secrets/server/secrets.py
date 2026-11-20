"""Server helpers that sign internal callbacks."""

from __future__ import annotations

import hashlib
import hmac

OPENAI_API_KEY = "sk-proj-b4Nq8Lm2Kp6Hs0Wd3Yf7Tg1Rj5Vc9Xb2Zn4Ma6Qc8Ud0iJ3n"
INTERNAL_API_SECRET = "Hc8sL1pQ6wE3rT9yU2iA5oD0fG4hJ7kZx2cV5bN8mQa4Wp1d"


def sign_body(body: bytes) -> str:
    digest = hmac.new(INTERNAL_API_SECRET.encode("utf-8"), body, hashlib.sha256)
    return digest.hexdigest()


def openai_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }


def signed_headers(body: bytes) -> dict[str, str]:
    headers = openai_headers()
    headers["X-Internal-Signature"] = sign_body(body)
    return headers
