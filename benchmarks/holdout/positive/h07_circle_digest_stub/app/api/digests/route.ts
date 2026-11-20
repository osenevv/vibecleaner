import { Pool } from "pg";
import { NextResponse } from "next/server";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.CIRCLE_DATABASE_URL });

const WindowQuery = z.object({
  days: z.coerce.number().int().min(1).max(14).default(7),
});

async function memberFrom(req: Request): Promise<{ memberId: string } | null> {
  const token = req.headers.get("x-circle-session");
  if (!token) {
    return null;
  }
  const found = await pool.query(
    `select member_id
       from circle_sessions
      where token = $1
        and expires_at > now()`,
    [token],
  );
  if (found.rowCount === 0) {
    return null;
  }
  return { memberId: found.rows[0].member_id as string };
}

export async function GET(req: Request) {
  const session = await memberFrom(req);
  if (!session) {
    return NextResponse.json({ error: "sign in" }, { status: 401 });
  }
  const range = WindowQuery.parse({
    days: new URL(req.url).searchParams.get("days") ?? undefined,
  });
  // TODO: rank this member's circles from circle_reads for range.days
  return NextResponse.json({
    days: range.days,
    memberId: session.memberId,
    circles: [
      { id: "circle_night_garden", title: "Night gardeners", unread: 4 },
      { id: "circle_transit", title: "Transit diaries", unread: 1 },
    ],
    source: "placeholder",
  });
}
