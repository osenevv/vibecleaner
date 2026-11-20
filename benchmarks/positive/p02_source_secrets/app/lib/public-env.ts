import { createClient } from "@supabase/supabase-js";

export const NEXT_PUBLIC_SUPABASE_URL = "https://abcd1234efgh5678.supabase.co";

export const NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2QxMjM0ZWZnaDU2NzgiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.zT4kP8mN2vC6xL1aS5dF9gH3jK7qW0eR4tY8uI6oPbc";

export const NEXT_PUBLIC_OPENAI_API_KEY =
  "sk-proj-v9Lm3Qa7Ws2Ed8Rf4Tg6Yh1Uj5Ik0Ol2Pz8Xc4Vb7Nn3mQ6s";

export const browserAdmin = createClient(
  NEXT_PUBLIC_SUPABASE_URL,
  NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } },
);

export function adminHeaders(): { apikey: string; Authorization: string } {
  return {
    apikey: NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY}`,
  };
}

export function openaiBrowserHeaders(): { Authorization: string } {
  return { Authorization: `Bearer ${NEXT_PUBLIC_OPENAI_API_KEY}` };
}
