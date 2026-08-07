ALTER TABLE mls_messages
  DROP CONSTRAINT mls_messages_target_valid,
  ADD CONSTRAINT mls_messages_target_valid
    CHECK (
      (kind = 0 AND target_device IS NOT NULL)
      OR
      kind = 1
      OR
      (kind = 2 AND target_device IS NULL)
    );

CREATE INDEX mls_messages_target_epoch_idx
  ON mls_messages (target_device, channel_id, epoch, seq)
  WHERE target_device IS NOT NULL AND consumed_at IS NULL;
