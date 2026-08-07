-- Repair the nullable custom-emoji shape in the original reaction primary key
-- and give every Unicode or custom emoji one stable key.
ALTER TABLE reactions
  DROP CONSTRAINT reactions_pkey;

ALTER TABLE reactions
  ALTER COLUMN emoji_id DROP NOT NULL,
  ALTER COLUMN emoji_name DROP NOT NULL;

ALTER TABLE reactions
  ADD COLUMN emoji_key varchar(64);

UPDATE reactions
SET emoji_key = COALESCE(emoji_name, emoji_id::text)
WHERE emoji_key IS NULL;

ALTER TABLE reactions
  ALTER COLUMN emoji_key SET NOT NULL;

ALTER TABLE reactions
  ADD CONSTRAINT reactions_pkey
  PRIMARY KEY (message_id, channel_id, user_id, emoji_key);

CREATE INDEX reactions_message_idx
  ON reactions (message_id, channel_id, emoji_key);

CREATE INDEX messages_reference_idx
  ON messages (reference_id, reference_channel_id)
  WHERE reference_id IS NOT NULL;
