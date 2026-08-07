CREATE TABLE private_history_outbox (
  message_id INTEGER PRIMARY KEY,
  queued_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);

