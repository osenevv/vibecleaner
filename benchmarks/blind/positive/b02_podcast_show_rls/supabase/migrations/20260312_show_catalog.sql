-- Harbor Lane Podcasts catalog.
-- shows is member-scoped. episodes and ad_reads were added in the same change.

CREATE TABLE public.shows (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES auth.users (id),
  title text NOT NULL,
  slug text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.shows ENABLE ROW LEVEL SECURITY;

CREATE POLICY shows_select ON public.shows
  FOR SELECT TO authenticated
  USING (owner_id = auth.uid());

CREATE POLICY shows_insert ON public.shows
  FOR INSERT TO authenticated
  WITH CHECK (owner_id = auth.uid());

CREATE POLICY shows_update ON public.shows
  FOR UPDATE TO authenticated
  USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

CREATE POLICY shows_delete ON public.shows
  FOR DELETE TO authenticated
  USING (owner_id = auth.uid());

CREATE TABLE public.episodes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  show_id uuid NOT NULL REFERENCES public.shows (id) ON DELETE CASCADE,
  title text NOT NULL,
  audio_path text NOT NULL,
  published_at timestamptz
);

CREATE TABLE public.ad_reads (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  episode_id uuid NOT NULL REFERENCES public.episodes (id) ON DELETE CASCADE,
  sponsor_name text NOT NULL,
  script text NOT NULL
);

ALTER TABLE public.ad_reads ENABLE ROW LEVEL SECURITY;
