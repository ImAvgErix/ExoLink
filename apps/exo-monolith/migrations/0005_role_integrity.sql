ALTER TABLE roles
  ADD CONSTRAINT roles_id_guild_unique UNIQUE (id, guild_id);

ALTER TABLE member_roles
  ADD CONSTRAINT member_roles_role_guild_fk
  FOREIGN KEY (role_id, guild_id)
  REFERENCES roles(id, guild_id)
  ON DELETE CASCADE;

CREATE INDEX member_roles_member_idx
  ON member_roles (guild_id, user_id, role_id);
