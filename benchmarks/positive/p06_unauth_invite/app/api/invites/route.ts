import { Pool } from "pg";
import { NextResponse } from "next/server";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const InviteBody = z.object({
  email: z.string().email(),
  teamName: z.string().min(1).max(80),
});

export async function POST(req: Request) {
  const body = InviteBody.parse(await req.json());
  const token = crypto.randomUUID();
  const result = await pool.query(
    `INSERT INTO invites (email, team_name, token)
     VALUES ($1, $2, $3)
     RETURNING id`,
    [body.email, body.teamName, token],
  );
  return NextResponse.json({ id: result.rows[0].id }, { status: 201 });
}
