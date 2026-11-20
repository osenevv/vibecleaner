import express from "express";

import { donorNotes } from "./routes/donorNotes";

export function buildDonorApp() {
  const app = express();
  app.use(express.json());
  app.use(donorNotes);
  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT ?? "4000");
  buildDonorApp().listen(port, () => {
    console.info(`kiln donor notes listening on ${port}`);
  });
}
