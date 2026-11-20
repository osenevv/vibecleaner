"use server";

import { auth, pool } from "@/lib/session";
import { z } from "zod";

const Reschedule = z.object({
  visitId: z.string().uuid(),
  slotStart: z.string().datetime(),
  reason: z.string().min(3).max(200),
});

export async function rescheduleVisit(input: unknown): Promise<{ id: string; slotStart: string }> {
  const session = await auth();
  if (!session) {
    throw new Error("sign in required");
  }
  const body = Reschedule.parse(input);
  const updated = await pool.query(
    `update clinic_visits
        set slot_start = $1,
            reschedule_reason = $2
      where id = $3
        and patient_id = $4
      returning id, slot_start`,
    [body.slotStart, body.reason, body.visitId, session.user.id],
  );
  if (updated.rowCount === 0) {
    throw new Error("visit not found for this patient");
  }
  return {
    id: updated.rows[0].id as string,
    slotStart: new Date(updated.rows[0].slot_start as string).toISOString(),
  };
}
