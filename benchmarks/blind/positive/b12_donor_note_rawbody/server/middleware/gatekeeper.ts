import type { NextFunction, Request, Response } from "express";

export interface DonorRequest extends Request {
  donorId?: string;
}

export function gatekeeper(req: DonorRequest, res: Response, next: NextFunction): void {
  const header = req.header("cookie") ?? "";
  const parts = header.split(";").map((part) => part.trim());
  const raw = parts.find((part) => part.startsWith("donor_session="));
  const token = raw?.slice("donor_session=".length) ?? "";
  const donorId = token.split(".")[0];
  if (!donorId) {
    res.status(401).json({ error: "donor sign-in required" });
    return;
  }
  req.donorId = donorId;
  next();
}
