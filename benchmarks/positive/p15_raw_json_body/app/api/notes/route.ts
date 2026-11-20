import { Pool } from "pg";
import { NextResponse } from "next/server";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

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
  const body = await req.json();
  const title = String(body.title ?? "").trim();
  if (!title) {
    return NextResponse.json({ error: "title is required" }, { status: 400 });
  }
  const inserted = await pool.query(
    "INSERT INTO notes (owner_id, title, body) VALUES ($1, $2, $3) RETURNING id",
    [session.user.id, title, String(body.body ?? "")],
  );
  return NextResponse.json({ id: inserted.rows[0].id }, { status: 201 });
}
