import { drizzle } from "drizzle-orm/node-postgres";
import { date, pgTable, text, uuid } from "drizzle-orm/pg-core";
import { Pool } from "pg";

export const lunchBlackouts = pgTable("lunch_blackouts", {
  id: uuid("id").primaryKey().defaultRandom(),
  serviceDate: date("service_date").notNull(),
  mealPeriod: text("meal_period").notNull(),
  reason: text("reason").notNull(),
});

const pool = new Pool({
  connectionString: process.env.CAFETERIA_DATABASE_URL,
});

export const db = drizzle(pool);
