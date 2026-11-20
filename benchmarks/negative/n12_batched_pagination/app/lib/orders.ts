import { createClient } from "@supabase/supabase-js";

const PAGE = 50;
const MAX_HEADS = 25;

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL ?? "",
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "",
);

export type OrderHead = { id: string; total_cents: number; status: string };

export async function pageOrders(userId: string, page: number): Promise<OrderHead[]> {
  const from = Math.max(page, 0) * PAGE;
  const to = from + PAGE - 1;
  const { data, error } = await supabase
    .from("orders")
    .select("id,total_cents,status")
    .eq("user_id", userId)
    .order("id", { ascending: false })
    .range(from, to);
  if (error) {
    throw error;
  }
  return (data ?? []) as OrderHead[];
}

async function fetchHead(userId: string, orderId: string): Promise<OrderHead | null> {
  const { data, error } = await supabase
    .from("orders")
    .select("id,total_cents,status")
    .eq("user_id", userId)
    .eq("id", orderId)
    .limit(1)
    .maybeSingle();
  if (error) {
    throw error;
  }
  return data as OrderHead | null;
}

export async function loadHeads(userId: string, orderIds: string[]): Promise<OrderHead[]> {
  const bounded = orderIds.slice(0, MAX_HEADS);
  const rows = await Promise.all(bounded.map((id) => fetchHead(userId, id)));
  return rows.filter((row): row is OrderHead => row !== null);
}
