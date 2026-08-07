CREATE TABLE guild_invites (
  code_hash bytea PRIMARY KEY,
  guild_id bigint NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  creator_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  uses integer NOT NULL DEFAULT 0,
  max_uses integer,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT guild_invites_uses_nonnegative CHECK (uses >= 0),
  CONSTRAINT guild_invites_max_uses_positive CHECK (max_uses IS NULL OR max_uses > 0),
  CONSTRAINT guild_invites_uses_within_limit
    CHECK (max_uses IS NULL OR uses <= max_uses)
);

CREATE INDEX guild_invites_guild_active_idx
  ON guild_invites (guild_id, created_at DESC)
  WHERE revoked_at IS NULL;

CREATE INDEX guild_invites_expiry_idx
  ON guild_invites (expires_at)
  WHERE revoked_at IS NULL AND expires_at IS NOT NULL;
