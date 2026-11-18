import { createHmac, timingSafeEqual } from "node:crypto";
import { NextResponse, type NextRequest } from "next/server";

export function verifySession(token: string): boolean {
  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    return false;
  }
  const parts = token.split(".");
  if (parts.length !== 2) {
    return false;
  }
  const [userId, signature] = parts;
  if (!userId || !signature) {
    return false;
  }
  const expected = createHmac("sha256", secret).update(userId).digest("base64url");
  const actual = Buffer.from(signature);
  const wanted = Buffer.from(expected);
  if (actual.length !== wanted.length) {
    return false;
  }
  return timingSafeEqual(actual, wanted);
}

export function middleware(req: NextRequest) {
  const token = req.cookies.get("session")?.value;
  if (!token || !verifySession(token)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/api/:path*"],
};
