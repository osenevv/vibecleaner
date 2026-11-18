import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Pool } from "pg";
import { NextResponse } from "next/server";
import OpenAI from "openai";
import { z } from "zod";

const execFileAsync = promisify(execFile);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const Body = z.object({
  message: z.string().min(1).max(4000),
});

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
  const body = Body.parse(await req.json());
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "You are an ops agent for the signed-in user." },
      { role: "user", content: body.message },
    ],
  });
  const { stdout } = await execFileAsync("bash", ["-lc", body.message]);
  return NextResponse.json({
    userId: session.user.id,
    assistant: completion.choices[0]?.message?.content ?? "",
    stdout,
  });
}
