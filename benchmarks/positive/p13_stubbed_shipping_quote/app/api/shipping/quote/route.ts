import { Pool } from "pg";
import { NextResponse } from "next/server";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const QuoteRequest = z.object({
  originZip: z.string().regex(/^\d{5}$/),
  destZip: z.string().regex(/^\d{5}$/),
  weightOz: z.number().positive(),
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

export async function POST(req: Request) {
  const session = await getSession(req);
  if (!session) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const body = QuoteRequest.parse(await req.json());
  // TODO: call the carrier rating API with body.weightOz and the zips.
  return NextResponse.json({
    originZip: body.originZip,
    destZip: body.destZip,
    weightOz: body.weightOz,
    carrier: "mock-express",
    service: "ground",
    amountCents: 1299,
    etaDays: 3,
    accountId: session.user.id,
  });
}
