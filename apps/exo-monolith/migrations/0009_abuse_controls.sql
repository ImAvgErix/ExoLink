CREATE TABLE automod_rules (
  id bigint PRIMARY KEY CHECK (id >= 0),
  guild_id bigint NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  name varchar(64) NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  trigger jsonb NOT NULL,
  action smallint NOT NULL CHECK (action BETWEEN 0 AND 4),
  duration_seconds integer,
  explanation varchar(256) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (action IN (2, 4) AND duration_seconds BETWEEN 60 AND 2419200)
    OR
    (action IN (0, 1, 3) AND duration_seconds IS NULL)
  )
);

CREATE INDEX automod_rules_guild_idx
  ON automod_rules (guild_id, enabled, id);
