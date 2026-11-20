"use server";

import { z } from "zod";

import { withMember } from "@/lib/member-gate";
import { prisma } from "@/lib/prisma";

const Entry = z.object({
  contestId: z.string().uuid(),
  amount: z.number().int().positive().optional(),
});

export async function enterContest(input: unknown) {
  const member = await withMember();
  const body = Entry.parse(input);
  const contest = await prisma.contest.findFirst({
    where: { id: body.contestId, status: "open" },
  });
  if (!contest) {
    throw new Error("contest is not open");
  }
  const quoted = body.amount;
  const feeCents = contest.entryFeeCents;
  if (quoted !== undefined && quoted !== feeCents) {
    console.info("ignoring client amount; contest fee is authoritative", {
      quoted,
      feeCents,
    });
  }
  await prisma.walletDebit.create({
    data: {
      contestId: contest.id,
      managerId: member.managerId,
      amountCents: feeCents,
    },
  });
  return { contestId: contest.id, feeCents };
}
