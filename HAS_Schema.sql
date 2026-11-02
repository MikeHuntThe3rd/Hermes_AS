CREATE TYPE privilege_t AS ENUM ('Consumer', 'Proprietor');

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  prv privilege_t NOT NULL,
  home_ds UUID NOT NULL,
  nickname TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  changes BIGINT NOT NULL,
  pfp TEXT
);

CREATE TABLE devices (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  cert_der BYTEA NOT NULL,
  sig_pubkey BYTEA NOT NULL,
  cert_serial BYTEA NOT NULL,
  cert_not_after BIGINT NOT NULL,
  key_id TEXT NOT NULL,
  is_revoked BOOL NOT NULL,
  CONSTRIANT uuid_version CHECK (uuid_extract_version(id) = 7)
);

CREATE TABLE dss (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    ep TEXT NOT NULL
);

CREATE TABLE deletions (
  seq        bigserial PRIMARY KEY,         -- cursor order for GET /deletions
  user_id    uuid   NOT NULL UNIQUE,        -- no FK: the users row is gone
  deleted_at bigint NOT NULL,
  key_id     text   NOT NULL,
  signature  bytea  NOT NULL
);

CREATE OR REPLACE FUNCTION change_increment() RETURNS trigger AS $$
BEGIN
    UPDATE users
    SET changes = changes + 1
    WHERE id = NEW.id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_increment_user_changes
AFTER UPDATE ON users
FOR EACH ROW
WHEN (OLD.changes IS NOT DISTINCT FROM NEW.changes
      AND OLD.* IS DISTINCT FROM NEW.*)
EXECUTE FUNCTION change_increment();
