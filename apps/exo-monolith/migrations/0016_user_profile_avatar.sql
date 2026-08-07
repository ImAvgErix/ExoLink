CREATE TABLE user_avatars (
  user_id bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  content_type varchar(32) NOT NULL,
  content bytea NOT NULL,
  content_sha256 varchar(64) NOT NULL,
  width integer NOT NULL CHECK (width BETWEEN 32 AND 1024),
  height integer NOT NULL CHECK (height BETWEEN 32 AND 1024),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT user_avatar_content_type
    CHECK (content_type IN ('image/png', 'image/jpeg', 'image/webp')),
  CONSTRAINT user_avatar_size
    CHECK (octet_length(content) BETWEEN 1 AND 524288)
);
