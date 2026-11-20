import { cookies } from "next/headers";

export interface Traveler {
  memberId: string;
}

export async function withMember(): Promise<Traveler> {
  const jar = await cookies();
  const token = jar.get("traveler_session")?.value;
  if (!token) {
    throw new Error("traveler sign-in required");
  }
  const memberId = token.split(".")[0];
  if (!memberId) {
    throw new Error("traveler session rejected");
  }
  return { memberId };
}
