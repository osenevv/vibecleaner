import { drizzle } from "drizzle-orm/node-postgres";
import { eq, inArray } from "drizzle-orm";
import { integer, pgTable, text, uuid } from "drizzle-orm/pg-core";
import { Hono } from "hono";
import { Pool } from "pg";
import { z } from "zod";

const episodes = pgTable("episodes", {
  id: uuid("id").primaryKey(),
  showId: uuid("show_id").notNull(),
  title: text("title").notNull(),
});

const plays = pgTable("plays", {
  episodeId: uuid("episode_id").notNull(),
  dayCount: integer("day_count").notNull(),
});

const rollups = pgTable("show_rollups", {
  showId: uuid("show_id").notNull(),
  hostId: uuid("host_id").notNull(),
  playCount: integer("play_count").notNull(),
});

const db = drizzle(new Pool({ connectionString: process.env.DATABASE_URL }));

const Query = z.object({
  showId: z.string().uuid(),
  page: z.coerce.number().int().min(0).max(10_000),
});

const PAGE_SIZE = 25;

export const rollupRoutes = new Hono();

rollupRoutes.post("/shows/:showId/rollups", async (c) => {
  const query = Query.parse({
    showId: c.req.param("showId"),
    page: c.req.query("page") ?? "0",
  });
  const hostId = c.get("hostId") as string;
  const rows = await db
    .select()
    .from(episodes)
    .where(eq(episodes.showId, query.showId))
    .limit(PAGE_SIZE)
    .offset(query.page * PAGE_SIZE);
  const ids = rows.map((row) => row.id);
  const playRows = ids.length
    ? await db.select().from(plays).where(inArray(plays.episodeId, ids))
    : [];
  const playCount = playRows.reduce((sum, row) => sum + row.dayCount, 0);
  await db.insert(rollups).values({ showId: query.showId, hostId, playCount });
  return c.json({ episodes: rows.length, playCount });
});
