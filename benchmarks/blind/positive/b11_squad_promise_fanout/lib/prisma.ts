import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as { slatePrisma?: PrismaClient };

export const prisma =
  globalForPrisma.slatePrisma ??
  new PrismaClient({
    log: ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.slatePrisma = prisma;
}

export async function disconnectSlatePrisma(): Promise<void> {
  await prisma.$disconnect();
}
