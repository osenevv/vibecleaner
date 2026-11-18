CREATE TABLE circle_boards (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    neighborhood text NOT NULL,
    title text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT circle_boards_title_len CHECK (char_length(title) BETWEEN 3 AND 80)
);

CREATE TABLE board_posts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    board_id uuid NOT NULL REFERENCES circle_boards (id),
    author_label text NOT NULL,
    body text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE post_bookmarks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id uuid NOT NULL REFERENCES board_posts (id),
    reader_label text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (post_id, reader_label)
);

CREATE INDEX board_posts_board_idx ON board_posts (board_id, created_at DESC);
CREATE INDEX post_bookmarks_reader_idx ON post_bookmarks (reader_label);
