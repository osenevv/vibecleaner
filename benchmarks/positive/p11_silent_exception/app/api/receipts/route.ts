import { Pool } from "pg";
import { NextResponse } from "next/server";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const ReceiptBody = z.object({
  orderId: z.string().min(1),
});

async function getSession(req: Request): Promise<{ user: { id: string; email: string } } | null> {
  const header = req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) {
    return null;
  }
  const result = await pool.query(
    "SELECT user_id, email FROM sessions WHERE token = $1 LIMIT 1",
    [token],
  );
  if (result.rowCount === 0) {
    return null;
  }
  return {
    user: {
      id: String(result.rows[0].user_id),
      email: String(result.rows[0].email),
    },
  };
}

async function sendReceiptEmail(to: string, receiptId: string): Promise<void> {
  const response = await fetch("https://email.internal.northwind.dev/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ to, receiptId, template: "receipt" }),
  });
  if (!response.ok) {
    throw new Error(`email failed: ${response.status}`);
  }
}

export async function POST(req: Request) {
  const session = await getSession(req);
  if (!session) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const body = ReceiptBody.parse(await req.json());
  const inserted = await pool.query(
    "INSERT INTO receipts (user_id, order_id) VALUES ($1, $2) RETURNING id",
    [session.user.id, body.orderId],
  );
  try {
    await sendReceiptEmail(session.user.email, String(inserted.rows[0].id));
  } catch {}
  return NextResponse.json({ id: inserted.rows[0].id });
}
