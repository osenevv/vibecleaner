import { Pool } from "pg";
import { NextResponse } from "next/server";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const TaskBody = z.object({
  title: z.string().min(1).max(160),
  dueOn: z.string().date(),
});

async function getSession(req: Request): Promise<{ user: { id: string } } | null> {
  const header = req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) {
    return null;
  }
  const found = await pool.query(
    "SELECT user_id FROM sessions WHERE token = $1 LIMIT 1",
    [token],
  );
  if (found.rowCount === 0) {
    return null;
  }
  return { user: { id: String(found.rows[0].user_id) } };
}

export async function POST(req: Request) {
  const session = await getSession(req);
  if (!session) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const payload = await req.json();
  const body = TaskBody.parse(payload);
  const inserted = await pool.query(
    "INSERT INTO tasks (owner_id, title, due_on) VALUES ($1, $2, $3) RETURNING id",
    [session.user.id, body.title, body.dueOn],
  );
  return NextResponse.json({ id: inserted.rows[0].id, title: body.title }, { status: 201 });
}
