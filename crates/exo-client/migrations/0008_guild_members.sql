CREATE TABLE guild_member_users (
  guild_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  PRIMARY KEY (guild_id, user_id)
);

CREATE INDEX guild_member_users_user_idx
  ON guild_member_users (user_id, guild_id);
