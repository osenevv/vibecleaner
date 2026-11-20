import { createClient } from "@supabase/supabase-js";
import { Router } from "express";

import { gatekeeper, type DonorRequest } from "../middleware/gatekeeper";

const supabase = createClient(
  process.env.SUPABASE_URL ?? "",
  process.env.SUPABASE_ANON_KEY ?? "",
);

export const donorNotes = Router();

donorNotes.use(gatekeeper);

donorNotes.post("/donations/notes", async (req: DonorRequest, res) => {
  const body = req.body as Record<string, any>;
  const { error } = await supabase.from("donor_notes").insert({
    donor_id: req.donorId,
    note: body.note,
    campaign: body.campaign,
    dedication: body.dedication ?? null,
  });
  if (error) {
    res.status(502).json({ error: "note was not saved" });
    return;
  }
  res.status(201).json({ saved: true });
});
