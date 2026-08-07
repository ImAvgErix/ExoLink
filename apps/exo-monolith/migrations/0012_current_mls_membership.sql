-- Explicit current MLS membership. Historical delivery targets cannot represent
-- removals, so future authorization and rekey fan-out use this ledger.

CREATE TABLE channel_mls_members (
  channel_id bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES device_identities(device_id) ON DELETE CASCADE,
  joined_epoch bigint NOT NULL,
  removed_epoch bigint,
  PRIMARY KEY (channel_id, device_id),
  CONSTRAINT channel_mls_members_epoch_valid
    CHECK (
      joined_epoch >= 0
      AND (removed_epoch IS NULL OR removed_epoch > joined_epoch)
    )
);

CREATE INDEX channel_mls_members_active_device_idx
  ON channel_mls_members (device_id, channel_id)
  WHERE removed_epoch IS NULL;

INSERT INTO channel_mls_members (channel_id, device_id, joined_epoch)
SELECT members.channel_id, members.device_id, MIN(members.epoch)
FROM (
  SELECT channel_id, sender_device AS device_id, epoch
  FROM mls_messages
  WHERE channel_id IS NOT NULL
  UNION ALL
  SELECT channel_id, target_device AS device_id, epoch
  FROM mls_messages
  WHERE channel_id IS NOT NULL AND target_device IS NOT NULL
) AS members
GROUP BY members.channel_id, members.device_id
ON CONFLICT (channel_id, device_id) DO NOTHING;
