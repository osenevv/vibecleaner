import { prisma } from "@/lib/prisma";
import { withMember } from "@/lib/member-gate";

export async function GET() {
  await withMember();
  const managers = await prisma.manager.findMany();
  const squads = await Promise.all(
    managers.map((manager) =>
      prisma.squadSlot.findMany({
        where: { managerId: manager.id },
      }),
    ),
  );
  return Response.json({
    managerCount: managers.length,
    squads: squads.flat(),
  });
}
