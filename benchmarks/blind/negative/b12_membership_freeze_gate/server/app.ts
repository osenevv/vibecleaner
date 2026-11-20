import express from "express";

import { verify_pin_session } from "./middleware/verify_pin_session";
import { freezeRouter } from "./routes/freeze";

export function buildClubApp() {
  const app = express();
  app.use(express.json());
  app.use("/memberships", verify_pin_session);
  app.use(freezeRouter);
  return app;
}

const app = buildClubApp();

export default app;
