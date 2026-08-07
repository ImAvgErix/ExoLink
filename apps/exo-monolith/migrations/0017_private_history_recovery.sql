-- Client-encrypted presentation archives let a newly installed device restore
-- old MLS message plaintext without giving the service decryption keys.

CREATE TABLE private_message_archives (
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_id bigint NOT NULL,
  channel_id bigint NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 24),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 131072),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, message_id),
  FOREIGN KEY (message_id, channel_id)
    REFERENCES messages(id, channel_id) ON DELETE CASCADE
);

CREATE INDEX private_message_archives_user_message_idx
  ON private_message_archives (user_id, message_id);
