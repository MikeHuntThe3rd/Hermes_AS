CREATE TYPE privilege_t AS ENUM ('Consumer', 'Proprietor');

CREATE TABLE "users" (
  "id" uuid PRIMARY KEY DEFAULT uuidv7(),
  "nickname" text NOT NULL,
  "prv" privilege_t NOT NULL,
  "username" text NOT NULL UNIQUE,
  "password" text NOT NULL,
  "pfp" text
);

CREATE TABLE "devices" (
  "id" uuid PRIMARY KEY DEFAULT uuidv7(),
  "user_id" uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  "name" text NOT NULL
);

CREATE TABLE "deletions" (
  "user_id" uuid PRIMARY KEY,
);