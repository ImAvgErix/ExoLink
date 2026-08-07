CREATE TABLE relationships (
  user_id INTEGER PRIMARY KEY,
  kind INTEGER NOT NULL CHECK (kind BETWEEN 0 AND 3),
  since TEXT NOT NULL
);

CREATE TABLE direct_channels (
  channel_id INTEGER PRIMARY KEY,
  recipient_ids BLOB NOT NULL,
  last_message_id INTEGER,
  encrypted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX direct_channels_activity_idx
  ON direct_channels (last_message_id DESC, created_at DESC);
