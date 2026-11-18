CREATE TABLE public.orders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id),
  status text NOT NULL DEFAULT 'pending',
  total_cents integer NOT NULL,
  currency text NOT NULL DEFAULT 'usd',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.invoices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id),
  order_id uuid REFERENCES public.orders (id),
  status text NOT NULL DEFAULT 'draft',
  subtotal_cents integer NOT NULL,
  tax_cents integer NOT NULL DEFAULT 0,
  total_cents integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES auth.users (id),
  display_name text NOT NULL,
  city text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE INDEX orders_user_id_idx ON public.orders (user_id);
CREATE INDEX invoices_user_id_idx ON public.invoices (user_id);
CREATE INDEX profiles_user_id_idx ON public.profiles (user_id);
