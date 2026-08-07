CREATE OR REPLACE FUNCTION validate_channel_overwrite_target()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  channel_guild_id bigint;
BEGIN
  SELECT guild_id INTO channel_guild_id
  FROM channels
  WHERE id = NEW.channel_id AND deleted_at IS NULL;

  IF channel_guild_id IS NULL THEN
    RAISE EXCEPTION 'channel overwrite references an unavailable channel';
  END IF;

  IF NEW.target_type = 0 THEN
    IF NOT EXISTS (
      SELECT 1 FROM roles
      WHERE id = NEW.target_id AND guild_id = channel_guild_id
    ) THEN
      RAISE EXCEPTION 'channel overwrite role belongs to another server';
    END IF;
  ELSIF NEW.target_type = 1 THEN
    IF NOT EXISTS (
      SELECT 1 FROM guild_members
      WHERE guild_id = channel_guild_id AND user_id = NEW.target_id
    ) THEN
      RAISE EXCEPTION 'channel overwrite member belongs to another server';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER channel_overwrites_validate_target
BEFORE INSERT OR UPDATE ON channel_overwrites
FOR EACH ROW
EXECUTE FUNCTION validate_channel_overwrite_target();

CREATE OR REPLACE FUNCTION cleanup_role_channel_overwrites()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  DELETE FROM channel_overwrites
  WHERE target_type = 0 AND target_id = OLD.id
    AND channel_id IN (
      SELECT id FROM channels WHERE guild_id = OLD.guild_id
    );
  RETURN OLD;
END;
$$;

CREATE TRIGGER roles_cleanup_channel_overwrites
AFTER DELETE ON roles
FOR EACH ROW
EXECUTE FUNCTION cleanup_role_channel_overwrites();

CREATE OR REPLACE FUNCTION cleanup_member_channel_overwrites()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  DELETE FROM channel_overwrites
  WHERE target_type = 1 AND target_id = OLD.user_id
    AND channel_id IN (
      SELECT id FROM channels WHERE guild_id = OLD.guild_id
    );
  RETURN OLD;
END;
$$;

CREATE TRIGGER members_cleanup_channel_overwrites
AFTER DELETE ON guild_members
FOR EACH ROW
EXECUTE FUNCTION cleanup_member_channel_overwrites();
