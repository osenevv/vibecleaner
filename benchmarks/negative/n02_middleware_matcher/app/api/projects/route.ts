import { Pool } from "pg";
import { NextResponse } from "next/server";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const ProjectBody = z.object({
  name: z.string().min(1).max(80),
  description: z.string().max(500).default(""),
});

export async function POST(req: Request) {
  const body = ProjectBody.parse(await req.json());
  const result = await pool.query(
    `INSERT INTO projects (name, description)
     VALUES ($1, $2)
     RETURNING id, name, description`,
    [body.name, body.description],
  );
  const row = result.rows[0];
  return NextResponse.json(
    { id: row.id, name: row.name, description: row.description },
    { status: 201 },
  );
}
