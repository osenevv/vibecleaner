#!/usr/bin/env bash
# Builds a small vibe-coded app in a temp dir and walks through a VibeCleaner audit.
set -euo pipefail

VIBECLEANER="$(command -v "${VIBECLEANER:-vibecleaner}")" || {
  echo "vibecleaner not found; pip install -e . or set VIBECLEANER=/path/to/vibecleaner" >&2
  exit 2
}
PAUSE="${DEMO_PAUSE:-2}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

say() { printf '\n\033[1;36m$ %s\033[0m\n' "$*"; sleep "$PAUSE"; }

cd "$WORK"
git init -q -b main
git config user.email demo@vibecleaner.dev
git config user.name demo
git config commit.gpgsign false
mkdir -p app/api/checkout supabase/migrations api

cat > supabase/migrations/20260101_init.sql <<'SQL'
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  total_cents int not null
);
SQL

cat > app/api/checkout/route.ts <<'TS'
import { NextResponse } from "next/server";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const { userId, priceCents } = await req.json();
  const intent = await stripe.paymentIntents.create({ amount: priceCents, currency: "usd", metadata: { userId } });
  return NextResponse.json({ clientSecret: intent.client_secret });
}
TS

cat > api/main.py <<'PY'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import openai

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)


@app.post("/summarize")
def summarize(payload: dict):
    try:
        reply = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": "You are " + payload["persona"]}],
        )
        return {"summary": reply.choices[0].message.content}
    except Exception:
        pass
PY
git add -A && git commit -qm "vibe-coded MVP"

say "vibecleaner scan . --no-report"
"$VIBECLEANER" scan . --no-report || true
sleep "$PAUSE"

git checkout -qb feature
cat > api/health.py <<'PY'
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
PY
git add -A && git commit -qm "add health check"

say "vibecleaner scan . --diff main --quiet      # what an agent hook sees on a clean change"
"$VIBECLEANER" scan . --diff main --quiet
sleep "$PAUSE"
