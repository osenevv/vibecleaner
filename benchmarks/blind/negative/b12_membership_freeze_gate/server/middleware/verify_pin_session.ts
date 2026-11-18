import type { NextFunction, Request, Response } from "express";

export interface MemberRequest extends Request {
  memberId?: string;
}

export function verify_pin_session(req: MemberRequest, res: Response, next: NextFunction): void {
  const header = req.header("cookie") ?? "";
  const parts = header.split(";").map((part) => part.trim());
  const raw = parts.find((part) => part.startsWith("club_pin_session="));
  const token = raw?.slice("club_pin_session=".length) ?? "";
  const memberId = token.split(".")[0];
  if (!memberId) {
    res.status(401).json({ error: "club pin session required" });
    return;
  }
  req.memberId = memberId;
  next();
}
