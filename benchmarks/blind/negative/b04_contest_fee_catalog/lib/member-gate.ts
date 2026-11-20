import { cookies } from "next/headers";

export interface Manager {
  managerId: string;
}

export async function withMember(): Promise<Manager> {
  const jar = await cookies();
  const token = jar.get("manager_session")?.value;
  if (!token) {
    throw new Error("manager sign-in required");
  }
  const managerId = token.split(".")[0];
  if (!managerId) {
    throw new Error("manager session rejected");
  }
  return { managerId };
}
