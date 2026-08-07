ALTER TABLE guilds
  ADD COLUMN owner_deletion_pending_at timestamptz;

CREATE INDEX guilds_owner_deletion_pending_idx
  ON guilds (owner_id, owner_deletion_pending_at)
  WHERE owner_deletion_pending_at IS NOT NULL AND deleted_at IS NULL;

