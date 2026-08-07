ALTER TABLE outbox
  ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0;

ALTER TABLE private_history_outbox
  ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0;

CREATE INDEX outbox_retry_idx
  ON outbox (next_attempt_at, created_at);

CREATE INDEX private_history_outbox_retry_idx
  ON private_history_outbox (next_attempt_at, attempts, queued_at);
