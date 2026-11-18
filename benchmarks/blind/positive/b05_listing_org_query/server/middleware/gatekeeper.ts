import type { Context, Next } from "hono";

/** Rejects a brokerage desk request that has no broker session cookie. */

export async function gatekeeper(c: Context, next: Next): Promise<Response | void> {
  const header = c.req.header("cookie") ?? "";
  const parts = header.split(";").map((part) => part.trim());
  const raw = parts.find((part) => part.startsWith("broker_session="));
  const token = raw?.slice("broker_session=".length) ?? "";
  const brokerId = token.split(".")[0];
  if (!brokerId) {
    return c.json({ error: "broker sign-in required" }, 401);
  }
  c.set("brokerId", brokerId);
  await next();
}
