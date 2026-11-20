import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as { contestPrisma?: PrismaClient };

export const prisma =
  globalForPrisma.contestPrisma ??
  new PrismaClient({
    log: ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.contestPrisma = prisma;
}

export async function disconnectContestPrisma(): Promise<void> {
  await prisma.$disconnect();
}
