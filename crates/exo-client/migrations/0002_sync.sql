CREATE TABLE guilds (
  id INTEGER PRIMARY KEY,
  owner_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  accent INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  origin INTEGER NOT NULL DEFAULT 1
);

ALTER TABLE users ADD COLUMN origin INTEGER NOT NULL DEFAULT 1;
ALTER TABLE channels ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE channels ADD COLUMN created_at TEXT;
ALTER TABLE channels ADD COLUMN origin INTEGER NOT NULL DEFAULT 1;
ALTER TABLE messages ADD COLUMN client_key TEXT;
ALTER TABLE messages ADD COLUMN created_at TEXT;
ALTER TABLE messages ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN origin INTEGER NOT NULL DEFAULT 1;

CREATE UNIQUE INDEX messages_nonce_idx
  ON messages (nonce)
  WHERE nonce IS NOT NULL;

CREATE TABLE app_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TRIGGER messages_fts_insert
AFTER INSERT ON messages
WHEN NEW.deleted = 0 AND NEW.content IS NOT NULL
BEGIN
  INSERT INTO messages_fts(rowid, content) VALUES (NEW.id, NEW.content);
END;

CREATE TRIGGER messages_fts_delete
AFTER DELETE ON messages
WHEN OLD.deleted = 0 AND OLD.content IS NOT NULL
BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, content)
  VALUES ('delete', OLD.id, OLD.content);
END;

CREATE TRIGGER messages_fts_update
AFTER UPDATE OF content, deleted ON messages
BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, content)
  SELECT 'delete', OLD.id, OLD.content
  WHERE OLD.deleted = 0 AND OLD.content IS NOT NULL;
  INSERT INTO messages_fts(rowid, content)
  SELECT NEW.id, NEW.content
  WHERE NEW.deleted = 0 AND NEW.content IS NOT NULL;
END;
