import express, { Request, Response } from "express";
import { Pool } from "pg";

const pool = new Pool({ connectionString: process.env.CIRCLE_DATABASE_URL });
const app = express();
app.use(express.json());

app.post("/circles/:circleId/flags", async (req: Request, res: Response) => {
  const token = req.header("x-circle-session");
  if (!token) {
    res.status(401).json({ error: "sign in" });
    return;
  }
  const found = await pool.query(
    `select member_id
       from circle_sessions
      where token = $1
        and expires_at > now()`,
    [token],
  );
  if (found.rowCount === 0) {
    res.status(401).json({ error: "sign in" });
    return;
  }
  const reason = req.body.reason;
  const detail = req.body.detail;
  const inserted = await pool.query(
    `insert into circle_flags (circle_id, member_id, reason, detail)
     values ($1, $2, $3, $4)
     returning id`,
    [req.params.circleId, found.rows[0].member_id, reason, detail],
  );
  res.status(201).json({ id: inserted.rows[0].id });
});

export default app;
