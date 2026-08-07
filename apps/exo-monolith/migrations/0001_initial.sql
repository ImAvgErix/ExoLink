-- Exocord's permanent ID epoch is 2026-01-01T00:00:00Z.
CREATE OR REPLACE FUNCTION snowflake_to_timestamp(id BIGINT)
RETURNS TIMESTAMPTZ AS $$
  SELECT to_timestamp(((id >> 22) + 1767225600000) / 1000.0);
$$ LANGUAGE SQL IMMUTABLE;

CREATE TABLE users (
  id bigint PRIMARY KEY CHECK (id >= 0),
  username varchar(32) NOT NULL,
  username_key varchar(32) NOT NULL UNIQUE,
  discriminator smallint,
  display_name varchar(32),
  avatar_hash varchar(64),
  banner_hash varchar(64),
  bio varchar(190),
  accent_color integer,
  flags bigint NOT NULL DEFAULT 0,
  public_flags bigint NOT NULL DEFAULT 0,
  email varchar(320),
  email_key varchar(320) UNIQUE,
  email_verified boolean NOT NULL DEFAULT false,
  password_hash text,
  password_changed_at timestamptz,
  mfa_enabled boolean NOT NULL DEFAULT false,
  totp_secret_enc bytea,
  backup_codes bytea,
  locale varchar(16) NOT NULL DEFAULT 'en-US',
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz,
  deleted_at timestamptz,
  trust_level smallint NOT NULL DEFAULT 0,
  phone_hash bytea
);

CREATE INDEX users_email_active_idx
  ON users (email_key) WHERE deleted_at IS NULL;
CREATE INDEX users_deleted_idx
  ON users (deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TABLE user_credentials (
  id bigint PRIMARY KEY CHECK (id >= 0),
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id bytea NOT NULL UNIQUE,
  public_key bytea NOT NULL,
  sign_count bigint NOT NULL DEFAULT 0,
  transports text[],
  aaguid uuid,
  backup_eligible boolean NOT NULL DEFAULT false,
  backup_state boolean NOT NULL DEFAULT false,
  name varchar(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE INDEX credentials_user_idx ON user_credentials (user_id);

CREATE TABLE sessions (
  id uuid PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id uuid NOT NULL,
  refresh_hash bytea NOT NULL,
  client_name varchar(64),
  os varchar(32),
  last_ip inet,
  ip_recorded_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE INDEX sessions_user_active_idx
  ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_refresh_idx ON sessions (refresh_hash);

CREATE TABLE guilds (
  id bigint PRIMARY KEY CHECK (id >= 0),
  name varchar(100) NOT NULL,
  icon_hash varchar(64),
  banner_hash varchar(64),
  description varchar(300),
  owner_id bigint NOT NULL REFERENCES users(id),
  accent integer NOT NULL DEFAULT 9133311,
  verification_level smallint NOT NULL DEFAULT 0,
  default_notifications smallint NOT NULL DEFAULT 0,
  explicit_content_filter smallint NOT NULL DEFAULT 1,
  mfa_required boolean NOT NULL DEFAULT false,
  system_channel_id bigint,
  rules_channel_id bigint,
  afk_channel_id bigint,
  afk_timeout integer NOT NULL DEFAULT 300,
  member_count integer NOT NULL DEFAULT 0,
  max_members integer NOT NULL DEFAULT 25000,
  features text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT guild_name_length CHECK (char_length(name) BETWEEN 2 AND 100)
);

CREATE TABLE channels (
  id bigint PRIMARY KEY CHECK (id >= 0),
  guild_id bigint REFERENCES guilds(id) ON DELETE CASCADE,
  parent_id bigint REFERENCES channels(id) ON DELETE SET NULL,
  type smallint NOT NULL,
  name varchar(100),
  topic varchar(1024),
  position integer NOT NULL DEFAULT 0,
  nsfw boolean NOT NULL DEFAULT false,
  rate_limit_per_user integer NOT NULL DEFAULT 0,
  bitrate integer,
  user_limit smallint,
  last_message_id bigint,
  e2ee boolean NOT NULL DEFAULT false,
  mls_group_id bytea,
  mls_epoch bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE INDEX channels_guild_active_idx
  ON channels (guild_id, position) WHERE deleted_at IS NULL;

ALTER TABLE guilds
  ADD CONSTRAINT guilds_system_channel_fk
    FOREIGN KEY (system_channel_id) REFERENCES channels(id) ON DELETE SET NULL,
  ADD CONSTRAINT guilds_rules_channel_fk
    FOREIGN KEY (rules_channel_id) REFERENCES channels(id) ON DELETE SET NULL,
  ADD CONSTRAINT guilds_afk_channel_fk
    FOREIGN KEY (afk_channel_id) REFERENCES channels(id) ON DELETE SET NULL;

CREATE TABLE roles (
  id bigint PRIMARY KEY CHECK (id >= 0),
  guild_id bigint NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  name varchar(100) NOT NULL,
  color integer NOT NULL DEFAULT 0,
  hoist boolean NOT NULL DEFAULT false,
  mentionable boolean NOT NULL DEFAULT false,
  position integer NOT NULL DEFAULT 0,
  permissions bigint NOT NULL DEFAULT 0,
  icon_hash varchar(64),
  managed boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX roles_guild_idx ON roles (guild_id, position DESC);

CREATE TABLE guild_members (
  guild_id bigint NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nick varchar(32),
  avatar_hash varchar(64),
  joined_at timestamptz NOT NULL DEFAULT now(),
  premium_since timestamptz,
  deaf boolean NOT NULL DEFAULT false,
  mute boolean NOT NULL DEFAULT false,
  pending boolean NOT NULL DEFAULT false,
  timeout_until timestamptz,
  PRIMARY KEY (guild_id, user_id)
);

CREATE INDEX guild_members_user_idx ON guild_members (user_id);

CREATE TABLE member_roles (
  guild_id bigint NOT NULL,
  user_id bigint NOT NULL,
  role_id bigint NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (guild_id, user_id, role_id),
  FOREIGN KEY (guild_id, user_id)
    REFERENCES guild_members(guild_id, user_id) ON DELETE CASCADE
);

CREATE INDEX member_roles_role_idx ON member_roles (role_id);

CREATE TABLE channel_overwrites (
  channel_id bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  target_id bigint NOT NULL,
  target_type smallint NOT NULL CHECK (target_type IN (0, 1)),
  allow_bits bigint NOT NULL DEFAULT 0,
  deny_bits bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (channel_id, target_id, target_type)
);

CREATE TABLE messages (
  id bigint NOT NULL CHECK (id >= 0),
  channel_id bigint NOT NULL,
  guild_id bigint,
  author_id bigint NOT NULL,
  type smallint NOT NULL DEFAULT 0,
  content varchar(4000),
  ciphertext bytea,
  flags integer NOT NULL DEFAULT 0,
  edited_at timestamptz,
  deleted_at timestamptz,
  reference_id bigint,
  reference_channel_id bigint,
  webhook_id bigint,
  nonce varchar(64),
  mention_everyone boolean NOT NULL DEFAULT false,
  mentions bigint[] NOT NULL DEFAULT '{}',
  mention_roles bigint[] NOT NULL DEFAULT '{}',
  attachments jsonb NOT NULL DEFAULT '[]',
  embeds jsonb NOT NULL DEFAULT '[]',
  frank_tag bytea,
  frank_commit bytea,
  PRIMARY KEY (id, channel_id)
) PARTITION BY RANGE (id);

-- The scheduler creates monthly partitions before traffic arrives. The default
-- prevents data loss if partition rotation ever fails.
CREATE TABLE messages_default PARTITION OF messages DEFAULT;

CREATE INDEX messages_channel_id_idx ON messages (channel_id, id DESC);
CREATE INDEX messages_author_idx ON messages (author_id, id DESC);

-- PostgreSQL requires every unique index on a partitioned table to include its
-- partition key. Keep idempotency keys in a small, unpartitioned coordination
-- table instead so a nonce remains unique across every message partition.
CREATE TABLE message_nonces (
  channel_id bigint NOT NULL,
  author_id bigint NOT NULL,
  nonce varchar(64) NOT NULL,
  message_id bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, author_id, nonce)
);

CREATE UNIQUE INDEX message_nonces_message_idx
  ON message_nonces (message_id, channel_id);

CREATE TABLE reactions (
  message_id bigint NOT NULL,
  channel_id bigint NOT NULL,
  user_id bigint NOT NULL,
  emoji_id bigint,
  emoji_name varchar(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id, emoji_id, emoji_name)
);

CREATE TABLE read_state (
  user_id bigint NOT NULL,
  channel_id bigint NOT NULL,
  last_message_id bigint NOT NULL DEFAULT 0,
  mention_count integer NOT NULL DEFAULT 0,
  last_ack_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, channel_id)
);

CREATE TABLE device_identities (
  device_id uuid PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  signature_key bytea NOT NULL,
  name varchar(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE TABLE mls_key_packages (
  id bigint PRIMARY KEY CHECK (id >= 0),
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id uuid NOT NULL,
  key_package bytea NOT NULL,
  cipher_suite smallint NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX mls_packages_available_idx
  ON mls_key_packages (user_id, device_id) WHERE consumed_at IS NULL;

CREATE TABLE mls_messages (
  group_id bytea NOT NULL,
  epoch bigint NOT NULL,
  seq bigint NOT NULL,
  kind smallint NOT NULL,
  sender_device uuid,
  payload bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, epoch, seq)
);

CREATE TABLE audit_log (
  id bigint PRIMARY KEY CHECK (id >= 0),
  guild_id bigint NOT NULL,
  actor_id bigint,
  target_id bigint,
  action_type smallint NOT NULL,
  changes jsonb NOT NULL DEFAULT '[]',
  reason varchar(512),
  mfa_verified boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_guild_idx ON audit_log (guild_id, id DESC);

CREATE TABLE bans (
  guild_id bigint NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  user_id bigint NOT NULL,
  actor_id bigint,
  reason varchar(512),
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE reports (
  id bigint PRIMARY KEY CHECK (id >= 0),
  reporter_id bigint NOT NULL,
  target_type smallint NOT NULL,
  target_id bigint NOT NULL,
  guild_id bigint,
  category smallint NOT NULL,
  detail varchar(2000),
  frank_payload bytea,
  frank_tag bytea,
  status smallint NOT NULL DEFAULT 0,
  handled_by bigint,
  handled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX reports_open_idx
  ON reports (status, created_at) WHERE status = 0;
