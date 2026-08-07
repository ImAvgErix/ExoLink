PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE messages (
  id INTEGER PRIMARY KEY,
  channel_id INTEGER NOT NULL,
  author_id INTEGER NOT NULL,
  content TEXT,
  flags INTEGER NOT NULL DEFAULT 0,
  edited_at INTEGER,
  deleted INTEGER NOT NULL DEFAULT 0,
  attachments BLOB,
  reactions BLOB,
  local_state INTEGER NOT NULL DEFAULT 0,
  nonce TEXT
);

CREATE INDEX messages_channel_idx ON messages (channel_id, id DESC);

CREATE TABLE ranges (
  channel_id INTEGER NOT NULL,
  start_id INTEGER NOT NULL,
  end_id INTEGER NOT NULL,
  PRIMARY KEY (channel_id, start_id),
  CHECK (start_id <= end_id)
);

CREATE VIRTUAL TABLE messages_fts USING fts5(
  content,
  content = 'messages',
  content_rowid = 'id',
  tokenize = 'unicode61'
);

CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT,
  display_name TEXT,
  avatar_hash TEXT,
  updated_at INTEGER
);

CREATE TABLE channels (
  id INTEGER PRIMARY KEY,
  guild_id INTEGER,
  name TEXT,
  type INTEGER,
  position INTEGER,
  last_message_id INTEGER,
  e2ee INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE read_state (
  channel_id INTEGER PRIMARY KEY,
  last_read_id INTEGER,
  mention_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE mls_state (
  group_id BLOB PRIMARY KEY,
  state BLOB NOT NULL,
  epoch INTEGER NOT NULL
);

CREATE TABLE outbox (
  nonce TEXT PRIMARY KEY,
  channel_id INTEGER NOT NULL,
  payload BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
