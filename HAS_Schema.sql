CREATE TYPE privilege_t AS ENUM ('Consumer', 'Proprietor');

CREATE TABLE "users" (
  "id" uuid PRIMARY KEY DEFAULT uuidv7(),
  "prv" privilege_t NOT NULL,
  "home_ds" uuid NOT NULL,
  "nickname" text NOT NULL,
  "username" text NOT NULL UNIQUE,
  "password" text NOT NULL,
  "pfp" text
);

CREATE TABLE "devices" (
  "id" uuid PRIMARY KEY,
  "user_id" uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  "name" text NOT NULL,
  "cert_der" BYTEA NOT NULL,
  "cert_serial" BYTEA NOT NULL,
  "cert_not_after" BIGINT NOT NULL,
  "key_id" TEXT NOT NULL
);

CREATE TABLE "deletions" (
  "user_id" uuid PRIMARY KEY,
);