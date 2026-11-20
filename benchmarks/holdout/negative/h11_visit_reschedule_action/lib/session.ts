import { cookies } from "next/headers";
import { Pool } from "pg";

export const pool = new Pool({ connectionString: process.env.CLINIC_DATABASE_URL });

export type VisitSession = { user: { id: string } };

export async function auth(): Promise<VisitSession | null> {
  const jar = await cookies();
  const token = jar.get("visit_session")?.value;
  if (!token) {
    return null;
  }
  const found = await pool.query(
    `select patient_id
       from visit_sessions
      where token = $1
        and expires_at > now()`,
    [token],
  );
  if (found.rowCount === 0) {
    return null;
  }
  return { user: { id: found.rows[0].patient_id as string } };
}
