CREATE TABLE attachment_uploads (
  id bigint PRIMARY KEY CHECK (id >= 0),
  channel_id bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  owner_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_id bigint,
  filename varchar(255) NOT NULL,
  declared_content_type varchar(127) NOT NULL,
  verified_content_type varchar(127),
  file_size bigint NOT NULL CHECK (file_size > 0 AND file_size <= 26214400),
  claimed_sha256 bytea NOT NULL CHECK (octet_length(claimed_sha256) = 32),
  verified_sha256 bytea CHECK (
    verified_sha256 IS NULL OR octet_length(verified_sha256) = 32
  ),
  object_key text NOT NULL,
  public_url text NOT NULL,
  width integer CHECK (width IS NULL OR width > 0),
  height integer CHECK (height IS NULL OR height > 0),
  animated boolean NOT NULL DEFAULT false,
  state smallint NOT NULL DEFAULT 0 CHECK (state IN (0, 1, 2)),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  validated_at timestamptz
);

CREATE INDEX attachment_uploads_owner_created_idx
  ON attachment_uploads (owner_id, created_at DESC);

CREATE INDEX attachment_uploads_orphan_expiry_idx
  ON attachment_uploads (expires_at)
  WHERE message_id IS NULL;

CREATE INDEX attachment_uploads_message_idx
  ON attachment_uploads (message_id, channel_id)
  WHERE message_id IS NOT NULL;

-- The fallback search path is intentionally PostgreSQL-native. Deployments can
-- mirror the same six fields into Meilisearch without changing the API.
CREATE INDEX messages_plaintext_search_idx
  ON messages USING gin (to_tsvector('simple', COALESCE(content, '')))
  WHERE ciphertext IS NULL AND deleted_at IS NULL;
