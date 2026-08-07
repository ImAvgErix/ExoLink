CREATE TABLE IF NOT EXISTS message_franking_openings (
  message_id INTEGER PRIMARY KEY,
  sealed_opening BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
