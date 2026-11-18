import { Pool } from "pg";
import { NextResponse } from "next/server";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const CheckoutBody = z.object({
  productId: z.string().min(1),
  amountCents: z.number().int().positive(),
});

async function getSession(req: Request): Promise<{ user: { id: string } } | null> {
  const header = req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) {
    return null;
  }
  const result = await pool.query(
    "SELECT user_id FROM sessions WHERE token = $1 LIMIT 1",
    [token],
  );
  if (result.rowCount === 0) {
    return null;
  }
  return { user: { id: String(result.rows[0].user_id) } };
}

async function createCharge(input: {
  customerId: string;
  amountCents: number;
  productId: string;
}): Promise<{ id: string }> {
  const response = await fetch("https://api.stripe.com/v1/payment_intents", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      amount: String(input.amountCents),
      currency: "usd",
      customer: input.customerId,
      "metadata[product_id]": input.productId,
    }),
  });
  if (!response.ok) {
    throw new Error(`charge failed: ${response.status}`);
  }
  return (await response.json()) as { id: string };
}

export async function POST(req: Request) {
  const session = await getSession(req);
  if (!session) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const body = CheckoutBody.parse(await req.json());
  const charge = await createCharge({
    customerId: session.user.id,
    amountCents: body.amountCents,
    productId: body.productId,
  });
  return NextResponse.json({ chargeId: charge.id, amountCents: body.amountCents });
}
