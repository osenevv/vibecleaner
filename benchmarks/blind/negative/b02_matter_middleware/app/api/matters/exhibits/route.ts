import { Pool } from "pg";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const Exhibit = z.object({
  matterId: z.string().uuid(),
  label: z.string().min(1).max(120),
  batesStart: z.string().min(1).max(32),
});

export async function POST(request: Request) {
  const body = Exhibit.parse(await request.json());
  await pool.query(
    `insert into exhibits (matter_id, label, bates_start)
     values ($1, $2, $3)`,
    [body.matterId, body.label, body.batesStart],
  );
  return Response.json({ stored: true }, { status: 201 });
}
