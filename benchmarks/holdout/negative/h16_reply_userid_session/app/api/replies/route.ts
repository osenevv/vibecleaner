import { Pool } from "pg";
import { NextResponse } from "next/server";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.FORUM_DATABASE_URL });

const ReplyBody = z.object({
  userId: z.string().uuid(),
  threadId: z.string().uuid(),
  text: z.string().min(1).max(2000),
});

async function forumSession(req: Request): Promise<{ user: { id: string } } | null> {
  const header = req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  if (!token) {
    return null;
  }
  const found = await pool.query(
    `select user_id
       from forum_sessions
      where token = $1
        and expires_at > now()`,
    [token],
  );
  if (found.rowCount === 0) {
    return null;
  }
  return { user: { id: found.rows[0].user_id as string } };
}

export async function POST(req: Request) {
  const session = await forumSession(req);
  if (!session) {
    return NextResponse.json({ error: "sign in" }, { status: 401 });
  }
  const body = ReplyBody.parse(await req.json());
  if (body.userId !== session.user.id) {
    return NextResponse.json({ error: "user mismatch" }, { status: 403 });
  }
  const inserted = await pool.query(
    `insert into thread_replies (thread_id, author_id, body)
     values ($1, $2, $3)
     returning id`,
    [body.threadId, session.user.id, body.text],
  );
  return NextResponse.json({ id: inserted.rows[0].id }, { status: 201 });
}
