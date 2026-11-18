import { NextResponse, type NextRequest } from "next/server";

function sessionToken(request: NextRequest): string | null {
  const token = request.cookies.get("counsel_session")?.value ?? "";
  if (!token.includes(".")) {
    return null;
  }
  return token;
}

export function assert_signed_in(request: NextRequest): NextResponse | null {
  const token = sessionToken(request);
  if (!token) {
    return NextResponse.json({ error: "counsel sign-in required" }, { status: 401 });
  }
  return null;
}

export function middleware(request: NextRequest) {
  const rejected = assert_signed_in(request);
  if (rejected) {
    return rejected;
  }
  const response = NextResponse.next();
  response.headers.set("x-counsel-desk", "harbor-pine");
  return response;
}

export const config = {
  matcher: ["/api/matters/:path*"],
};
