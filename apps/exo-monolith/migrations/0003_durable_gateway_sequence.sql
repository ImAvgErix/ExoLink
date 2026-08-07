ALTER TABLE messages
  ADD COLUMN sequence bigint NOT NULL DEFAULT 0;

CREATE INDEX messages_sequence_idx ON messages (sequence);
