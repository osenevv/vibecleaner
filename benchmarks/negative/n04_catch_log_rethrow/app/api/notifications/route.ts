import { Pool } from "pg";
import { NextResponse } from "next/server";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const NoteBody = z.object({
  kind: z.enum(["mention", "assignment", "reminder"]),
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
  const body = NoteBody.parse(await req.json());
  try {
    const inserted = await pool.query(
      "INSERT INTO notifications (user_id, kind) VALUES ($1, $2) RETURNING id",
      [session.user.id, body.kind],
    );
    return NextResponse.json({ id: inserted.rows[0].id }, { status: 201 });
  } catch (e) {
    console.error(e);
    throw e;
  }
}
