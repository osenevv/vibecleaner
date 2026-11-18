import { Pool } from "pg";
import { NextResponse } from "next/server";
import Stripe from "stripe";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.CAMPUS_DATABASE_URL });

const COURSE_PRICE_ALLOWLIST: Record<string, { priceId: string; courseCode: string }> = {
  price_algebra_term: { priceId: "price_algebra_term", courseCode: "ALG-201" },
  price_lab_weekend: { priceId: "price_lab_weekend", courseCode: "LAB-110" },
};

const CheckoutBody = z.object({
  priceId: z.string().min(1),
  registrarNote: z.string().max(240).optional(),
});

function stripeClient(): Stripe {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    throw new Error("STRIPE_SECRET_KEY is not configured");
  }
  return new Stripe(key, { apiVersion: "2024-06-20" });
}

async function requireLearner(req: Request): Promise<{ learnerId: string } | null> {
  const token = req.headers.get("x-campus-session");
  if (!token) {
    return null;
  }
  const found = await pool.query(
    `select learner_id
       from campus_sessions
      where token = $1
        and expires_at > now()`,
    [token],
  );
  if (found.rowCount === 0) {
    return null;
  }
  return { learnerId: found.rows[0].learner_id as string };
}

export async function POST(req: Request) {
  const session = await requireLearner(req);
  if (!session) {
    return NextResponse.json({ error: "sign in" }, { status: 401 });
  }
  const body = CheckoutBody.parse(await req.json());
  const allowed = COURSE_PRICE_ALLOWLIST[body.priceId];
  if (!allowed) {
    return NextResponse.json({ error: "unknown course price" }, { status: 400 });
  }
  const checkout = await stripeClient().checkout.sessions.create({
    mode: "payment",
    client_reference_id: session.learnerId,
    line_items: [{ price: allowed.priceId, quantity: 1 }],
    success_url: "https://campus.example/enroll/done",
    cancel_url: "https://campus.example/enroll/cancelled",
    metadata: {
      courseCode: allowed.courseCode,
      registrarNote: body.registrarNote ?? "",
    },
  });
  if (!checkout.url) {
    throw new Error("stripe did not return a checkout url");
  }
  return NextResponse.json({ url: checkout.url });
}
