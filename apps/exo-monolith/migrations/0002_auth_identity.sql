ALTER TABLE users
  ADD COLUMN token_version integer NOT NULL DEFAULT 0;

CREATE TABLE email_challenges (
  id uuid PRIMARY KEY,
  email_key varchar(320) NOT NULL,
  code_hash bytea NOT NULL,
  attempts smallint NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT email_challenge_attempts CHECK (attempts BETWEEN 0 AND 5)
);

CREATE INDEX email_challenges_active_idx
  ON email_challenges (email_key, expires_at)
  WHERE consumed_at IS NULL;

CREATE TABLE external_identities (
  provider varchar(24) NOT NULL,
  subject varchar(255) NOT NULL,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  verified_email varchar(320),
  refresh_token_enc bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, subject)
);

CREATE INDEX external_identities_user_idx
  ON external_identities (user_id);

CREATE TABLE session_refresh_tokens (
  token_hash bytea PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX session_refresh_tokens_session_idx
  ON session_refresh_tokens (session_id);

CREATE TABLE apple_login_flows (
  state_hash bytea PRIMARY KEY,
  nonce varchar(128) NOT NULL,
  device_id uuid NOT NULL,
  encrypted_result bytea,
  error varchar(160),
  expires_at timestamptz NOT NULL,
  completed_at timestamptz,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX apple_login_flows_expiry_idx
  ON apple_login_flows (expires_at)
  WHERE consumed_at IS NULL;
