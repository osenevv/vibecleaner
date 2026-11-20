CREATE TABLE "study_circles" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "mentor_id" uuid NOT NULL,
    "topic" text NOT NULL,
    "seats" integer NOT NULL DEFAULT 8,
    "created_at" timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT "study_circles_topic_len" CHECK (char_length("topic") BETWEEN 3 AND 120)
);

CREATE TABLE "reading_goals" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "circle_id" uuid NOT NULL REFERENCES "study_circles" ("id"),
    "mentor_id" uuid NOT NULL,
    "pages" integer NOT NULL,
    "created_at" timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT "reading_goals_pages" CHECK ("pages" > 0)
);

ALTER TABLE "study_circles" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "reading_goals" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "mentor reads circle"
    ON "study_circles"
    FOR SELECT
    USING ("mentor_id" = auth.uid());

CREATE POLICY "mentor inserts circle"
    ON "study_circles"
    FOR INSERT
    WITH CHECK ("mentor_id" = auth.uid());

CREATE POLICY "mentor updates circle"
    ON "study_circles"
    FOR UPDATE
    USING ("mentor_id" = auth.uid())
    WITH CHECK ("mentor_id" = auth.uid());

CREATE POLICY "mentor deletes circle"
    ON "study_circles"
    FOR DELETE
    USING ("mentor_id" = auth.uid());

CREATE POLICY "mentor reads goal"
    ON "reading_goals"
    FOR SELECT
    USING ("mentor_id" = auth.uid());

CREATE POLICY "mentor inserts goal"
    ON "reading_goals"
    FOR INSERT
    WITH CHECK ("mentor_id" = auth.uid());

CREATE POLICY "mentor updates goal"
    ON "reading_goals"
    FOR UPDATE
    USING ("mentor_id" = auth.uid())
    WITH CHECK ("mentor_id" = auth.uid());

CREATE POLICY "mentor deletes goal"
    ON "reading_goals"
    FOR DELETE
    USING ("mentor_id" = auth.uid());
