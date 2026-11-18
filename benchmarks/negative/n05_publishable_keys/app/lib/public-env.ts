import { createClient } from "@supabase/supabase-js";
import { loadStripe } from "@stripe/stripe-js";

export const NEXT_PUBLIC_SUPABASE_URL = "https://zzzz9999yyyy8888.supabase.co";

export const NEXT_PUBLIC_SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inp6eno5OTk5eXl5eTg4ODgiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.pL6kM9nB2vC5xZ8aS1dF4gH7jK0qW3eR6tY9uI2oPQa";

export const NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY =
  "pk_test_51Hq7kL2mN8pQ4rS6tU0vW2xY4zA6bC8dE0fG";

export const browserClient = createClient(
  NEXT_PUBLIC_SUPABASE_URL,
  NEXT_PUBLIC_SUPABASE_ANON_KEY,
);

export function stripePromise() {
  return loadStripe(NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);
}
