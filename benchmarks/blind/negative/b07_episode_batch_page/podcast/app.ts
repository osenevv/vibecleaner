import { Hono } from "hono";

import { withMember } from "./middleware/withMember";
import { rollupRoutes } from "./routes/rollups";

export function buildPodcastApp() {
  const app = new Hono();
  app.use("/shows/*", withMember);
  app.route("/", rollupRoutes);
  return app;
}

const app = buildPodcastApp();

export default app;
