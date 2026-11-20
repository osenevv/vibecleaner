import { Pool } from "pg";
import { NextResponse } from "next/server";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.CRM_DATABASE_URL });

const GrantBody = z.object({
  org_id: z.string().uuid(),
  role: z.enum(["rep", "manager", "admin"]),
  is_admin: z.boolean(),
});

async function readCrmSession(req: Request): Promise<{ userId: string } | null> {
  const token = req.headers.get("x-crm-session");
  if (!token) {
    return null;
  }
  const found = await pool.query(
    `select user_id
       from crm_sessions
      where token = $1
        and expires_at > now()`,
    [token],
  );
  if (found.rowCount === 0) {
    return null;
  }
  return { userId: found.rows[0].user_id as string };
}

export async function POST(req: Request) {
  const session = await readCrmSession(req);
  if (!session) {
    return NextResponse.json({ error: "sign in" }, { status: 401 });
  }
  const grant = GrantBody.parse(await req.json());
  if (grant.is_admin === false && grant.role === "admin") {
    return NextResponse.json({ error: "admin role needs the admin flag" }, { status: 403 });
  }
  const inserted = await pool.query(
    `insert into pipeline_grants (org_id, actor_id, role, approved)
     values ($1, $2, $3, $4)
     returning id`,
    [grant.org_id, session.userId, grant.role, grant.is_admin],
  );
  return NextResponse.json({ id: inserted.rows[0].id }, { status: 201 });
}
