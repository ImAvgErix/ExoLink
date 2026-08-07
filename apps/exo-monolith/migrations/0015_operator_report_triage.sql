ALTER TABLE reports
  RENAME COLUMN frank_payload TO evidence_payload;

-- Earlier alpha builds serialized the complete franking submission. Retain
-- only reviewable evidence and remove the opening secret during upgrade.
UPDATE reports AS report
SET evidence_payload = convert_to(
  jsonb_build_object(
    'content', COALESCE(legacy.payload ->> 'content', ''),
    'encrypted', true,
    'verified', true,
    'attachments', '[]'::jsonb,
    'attachmentSha256',
      COALESCE(legacy.payload -> 'attachmentSha256', '[]'::jsonb)
  )::text,
  'UTF8'
)
FROM (
  SELECT id, convert_from(evidence_payload, 'UTF8')::jsonb AS payload
  FROM reports
  WHERE evidence_payload IS NOT NULL
) AS legacy
WHERE report.id = legacy.id;

ALTER TABLE reports
  ADD COLUMN handled_by_operator varchar(100),
  ADD COLUMN resolution_note varchar(1000);

ALTER TABLE reports
  ADD CONSTRAINT reports_status_valid
  CHECK (status IN (0, 1, 2));

CREATE INDEX reports_recent_idx
  ON reports (created_at DESC, id DESC);
