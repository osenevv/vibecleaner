ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.project_members ENABLE ROW LEVEL SECURITY;

CREATE POLICY projects_select ON public.projects
  FOR SELECT
  USING (auth.uid() = owner_id);

CREATE POLICY projects_insert ON public.projects
  FOR INSERT
  WITH CHECK (auth.uid() = owner_id);

CREATE POLICY projects_update ON public.projects
  FOR UPDATE
  USING (auth.uid() = owner_id)
  WITH CHECK (auth.uid() = owner_id);

CREATE POLICY projects_delete ON public.projects
  FOR DELETE
  USING (auth.uid() = owner_id);

CREATE POLICY project_members_select ON public.project_members
  FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY project_members_insert ON public.project_members
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY project_members_update ON public.project_members
  FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY project_members_delete ON public.project_members
  FOR DELETE
  USING (auth.uid() = user_id);
