-- Device-bound MLS delivery and encrypted-message integrity.

ALTER TABLE device_identities
  ADD CONSTRAINT device_identities_device_user_unique
    UNIQUE (device_id, user_id),
  ADD CONSTRAINT device_identities_signature_key_length
    CHECK (octet_length(signature_key) = 32);

ALTER TABLE mls_key_packages
  ADD COLUMN key_package_ref bytea,
  ADD COLUMN claimed_by_device uuid,
  ADD COLUMN claimed_for_channel bigint REFERENCES channels(id) ON DELETE CASCADE,
  ADD CONSTRAINT mls_key_packages_device_user_fk
    FOREIGN KEY (device_id, user_id)
    REFERENCES device_identities(device_id, user_id)
    ON DELETE CASCADE,
  ADD CONSTRAINT mls_key_packages_suite_one
    CHECK (cipher_suite = 1),
  ADD CONSTRAINT mls_key_packages_reference_length
    CHECK (key_package_ref IS NULL OR octet_length(key_package_ref) = 32);

CREATE UNIQUE INDEX mls_key_packages_reference_unique_idx
  ON mls_key_packages (key_package_ref)
  WHERE key_package_ref IS NOT NULL;

CREATE INDEX mls_key_packages_claim_idx
  ON mls_key_packages (claimed_for_channel, claimed_by_device, consumed_at);

ALTER TABLE mls_messages
  ADD COLUMN channel_id bigint REFERENCES channels(id) ON DELETE CASCADE,
  ADD COLUMN target_device uuid REFERENCES device_identities(device_id) ON DELETE CASCADE,
  ADD COLUMN consumed_at timestamptz,
  ADD CONSTRAINT mls_messages_kind_valid CHECK (kind IN (0, 1, 2)),
  ADD CONSTRAINT mls_messages_target_valid
    CHECK (
      (kind = 0 AND target_device IS NOT NULL)
      OR
      (kind IN (1, 2) AND target_device IS NULL)
    );

CREATE INDEX mls_messages_device_inbox_idx
  ON mls_messages (target_device, created_at, seq)
  WHERE target_device IS NOT NULL AND consumed_at IS NULL;

CREATE INDEX mls_messages_channel_order_idx
  ON mls_messages (channel_id, epoch, seq);

CREATE UNIQUE INDEX channels_mls_group_unique_idx
  ON channels (mls_group_id)
  WHERE mls_group_id IS NOT NULL;

ALTER TABLE messages
  ADD COLUMN sender_device_id uuid REFERENCES device_identities(device_id),
  ADD CONSTRAINT messages_content_or_ciphertext
    CHECK ((content IS NULL) <> (ciphertext IS NULL)) NOT VALID,
  ADD CONSTRAINT messages_encryption_metadata
    CHECK (
      (ciphertext IS NULL AND frank_commit IS NULL AND frank_tag IS NULL
        AND sender_device_id IS NULL)
      OR
      (ciphertext IS NOT NULL
        AND octet_length(frank_commit) = 32
        AND octet_length(frank_tag) = 32
        AND sender_device_id IS NOT NULL)
    ) NOT VALID;
