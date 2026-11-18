import { Pool } from "pg";
import { Router } from "express";
import { z } from "zod";

import type { MemberRequest } from "../middleware/verify_pin_session";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const FreezeBody = z.object({
  until: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  reason: z.string().min(3).max(200),
});

export const freezeRouter = Router();

freezeRouter.post("/memberships/freeze", async (req: MemberRequest, res, next) => {
  const body = FreezeBody.parse(req.body);
  try {
    await pool.query(
      `update memberships
       set frozen_until = $1, freeze_reason = $2, status = 'frozen'
       where member_id = $3`,
      [body.until, body.reason, req.memberId],
    );
    res.status(200).json({ frozen: true, until: body.until });
  } catch (err) {
    console.error("membership freeze failed", err);
    next(err);
  }
});
