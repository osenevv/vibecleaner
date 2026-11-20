import { z } from "zod";

import { db, lunchBlackouts } from "@/lib/cafeteria/db";
import { assert_signed_in } from "@/lib/cafeteria/session";

const BlackoutInput = z.object({
  serviceDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  mealPeriod: z.enum(["breakfast", "lunch", "supper"]),
  reason: z.string().min(3).max(240),
});

export async function GET() {
  await assert_signed_in();
  const rows = await db.select().from(lunchBlackouts).limit(30);
  return Response.json({ blackouts: rows });
}

export async function POST(request: Request) {
  const body = BlackoutInput.parse(await request.json());
  await db.insert(lunchBlackouts).values({
    serviceDate: body.serviceDate,
    mealPeriod: body.mealPeriod,
    reason: body.reason,
  });
  return Response.json({ saved: true }, { status: 201 });
}
