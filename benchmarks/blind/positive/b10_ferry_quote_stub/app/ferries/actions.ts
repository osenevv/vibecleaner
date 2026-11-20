"use server";

import { z } from "zod";

import { withMember } from "@/lib/member-gate";

const QuoteRequest = z.object({
  origin: z.string().regex(/^[A-Z]{3}$/),
  dest: z.string().regex(/^[A-Z]{3}$/),
  departOn: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  cabin: z.enum(["economy", "cabin"]),
});

export async function quoteFerry(input: unknown) {
  const traveler = await withMember();
  const body = QuoteRequest.parse(input);
  // TODO: call the consolidator fare API before the spring schedule opens.
  return {
    memberId: traveler.memberId,
    origin: body.origin,
    dest: body.dest,
    departOn: body.departOn,
    carrier: "Harbor Air",
    fareCents: 42800,
    cabin: "economy",
    bagIncluded: true,
    quoteRef: "HA-18443",
  };
}
