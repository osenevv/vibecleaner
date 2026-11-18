import { drizzle } from "drizzle-orm/node-postgres";
import { and, eq } from "drizzle-orm";
import { pgTable, text, uuid } from "drizzle-orm/pg-core";
import { Hono } from "hono";
import { Pool } from "pg";
import { z } from "zod";

import { gatekeeper } from "../middleware/gatekeeper";

const listings = pgTable("listings", {
  id: uuid("id").primaryKey(),
  brokerageId: uuid("brokerage_id").notNull(),
  headline: text("headline").notNull(),
  showingNote: text("showing_note"),
});

const db = drizzle(new Pool({ connectionString: process.env.LISTINGS_DATABASE_URL }));

const ListingPatch = z.object({
  headline: z.string().min(3).max(140),
  showingNote: z.string().max(500).optional(),
});

const OrgScope = z.object({
  org_id: z.string().uuid(),
});

export const listingRoutes = new Hono();

listingRoutes.patch("/listings/:listingId", gatekeeper, async (c) => {
  const scope = OrgScope.parse({ org_id: c.req.query("org_id") });
  const body = ListingPatch.parse(await c.req.json());
  await db
    .update(listings)
    .set({
      headline: body.headline,
      showingNote: body.showingNote ?? null,
    })
    .where(and(eq(listings.id, c.req.param("listingId")), eq(listings.brokerageId, scope.org_id)));
  return c.json({ updated: true });
});
