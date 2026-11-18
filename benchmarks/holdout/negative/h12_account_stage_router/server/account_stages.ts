import { NextFunction, Request, Response, Router } from "express";
import { Pool } from "pg";
import { z } from "zod";

const pool = new Pool({ connectionString: process.env.CRM_DATABASE_URL });

const StageBody = z.object({
  stage: z.enum(["new", "working", "won", "lost"]),
});

async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const token = req.header("x-crm-session");
    if (!token) {
      res.status(401).json({ error: "sign in" });
      return;
    }
    const found = await pool.query(
      `select user_id
         from crm_sessions
        where token = $1
          and expires_at > now()`,
      [token],
    );
    if (found.rowCount === 0) {
      res.status(401).json({ error: "sign in" });
      return;
    }
    res.locals.userId = found.rows[0].user_id as string;
    next();
  } catch (err) {
    next(err);
  }
}

const router = Router();
router.use(requireAuth);

router.post("/accounts/:accountId/stage", async (req: Request, res: Response) => {
  const body = StageBody.parse(req.body);
  const userId = res.locals.userId as string;
  const updated = await pool.query(
    `update crm_accounts
        set stage = $1
      where id = $2
        and owner_id = $3
      returning id, stage`,
    [body.stage, req.params.accountId, userId],
  );
  if (updated.rowCount === 0) {
    res.status(404).json({ error: "account not found" });
    return;
  }
  res.json({ id: updated.rows[0].id, stage: updated.rows[0].stage });
});

export default router;
