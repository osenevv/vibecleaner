import { cookies } from "next/headers";

export interface CafeteriaStaff {
  staffId: string;
}

export async function assert_signed_in(): Promise<CafeteriaStaff> {
  const jar = await cookies();
  const token = jar.get("cafeteria_staff")?.value;
  if (!token) {
    throw new Error("cafeteria staff sign-in required");
  }
  const staffId = token.split(".")[0];
  if (!staffId) {
    throw new Error("cafeteria staff session rejected");
  }
  return { staffId };
}
