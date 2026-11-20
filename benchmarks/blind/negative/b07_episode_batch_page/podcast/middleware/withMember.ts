import type { Context, Next } from "hono";

/** Rejects a show-host request that has no host session cookie. */

export async function withMember(c: Context, next: Next): Promise<Response | void> {
  const header = c.req.header("cookie") ?? "";
  const parts = header.split(";").map((part) => part.trim());
  const raw = parts.find((part) => part.startsWith("host_session="));
  const token = raw?.slice("host_session=".length) ?? "";
  const hostId = token.split(".")[0];
  if (!hostId) {
    return c.json({ error: "host sign-in required" }, 401);
  }
  c.set("hostId", hostId);
  await next();
}
