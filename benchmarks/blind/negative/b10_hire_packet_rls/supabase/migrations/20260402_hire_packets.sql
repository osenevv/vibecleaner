-- Northwind hire packets. Each table enables row level security and has policies.

CREATE TABLE public.hire_packets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  person_id uuid NOT NULL REFERENCES auth.users (id),
  role_title text NOT NULL,
  office_code text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.hire_packets ENABLE ROW LEVEL SECURITY;

CREATE POLICY hire_packets_select ON public.hire_packets
  FOR SELECT TO authenticated
  USING (person_id = auth.uid());

CREATE POLICY hire_packets_insert ON public.hire_packets
  FOR INSERT TO authenticated
  WITH CHECK (person_id = auth.uid());

CREATE POLICY hire_packets_update ON public.hire_packets
  FOR UPDATE TO authenticated
  USING (person_id = auth.uid())
  WITH CHECK (person_id = auth.uid());

CREATE TABLE public.policy_acks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  person_id uuid NOT NULL REFERENCES auth.users (id),
  packet_id uuid NOT NULL REFERENCES public.hire_packets (id) ON DELETE CASCADE,
  policy_code text NOT NULL,
  acked_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.policy_acks ENABLE ROW LEVEL SECURITY;

CREATE POLICY policy_acks_select ON public.policy_acks
  FOR SELECT TO authenticated
  USING (person_id = auth.uid());

CREATE POLICY policy_acks_insert ON public.policy_acks
  FOR INSERT TO authenticated
  WITH CHECK (person_id = auth.uid());

CREATE POLICY policy_acks_delete ON public.policy_acks
  FOR DELETE TO authenticated
  USING (person_id = auth.uid());
