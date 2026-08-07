-- Directed relationship rows deliberately do not reveal that another user has
-- blocked the current account. States: 0 incoming, 1 outgoing, 2 friend,
-- 3 blocked by user_id.
CREATE TABLE user_relationships (
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  state smallint NOT NULL CHECK (state IN (0, 1, 2, 3)),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, target_id),
  CHECK (user_id <> target_id)
);

CREATE INDEX user_relationships_target_idx
  ON user_relationships (target_id, state, updated_at DESC);

-- One canonical row prevents duplicate 1:1 conversations even when both
-- friends press "Message" at the same time.
CREATE TABLE dm_pairs (
  user_low_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_high_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  channel_id bigint NOT NULL UNIQUE REFERENCES channels(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_low_id, user_high_id),
  CHECK (user_low_id < user_high_id)
);

CREATE TABLE channel_recipients (
  channel_id bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, user_id)
);

CREATE INDEX channel_recipients_user_idx
  ON channel_recipients (user_id, channel_id);

CREATE INDEX channels_dm_activity_idx
  ON channels (last_message_id DESC NULLS LAST, created_at DESC)
  WHERE guild_id IS NULL AND type = 1 AND deleted_at IS NULL;

-- Existing deployments used an opaque username_key. Normalize it to the
-- visible exact handle while deterministically disambiguating duplicates.
WITH ranked AS (
  SELECT id,
         row_number() OVER (
           PARTITION BY lower(username)
           ORDER BY id
         ) AS duplicate_number
  FROM users
)
UPDATE users
SET username = left(users.username, 24) || '-' || right(users.id::text, 6)
FROM ranked
WHERE users.id = ranked.id AND ranked.duplicate_number > 1;

UPDATE users SET username_key = lower(username);

CREATE UNIQUE INDEX users_visible_handle_active_idx
  ON users (lower(username))
  WHERE deleted_at IS NULL;
