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
  "user_id" uuid NOT NULL DEFAULT uuidv7(),
  "device" uuid NOT NULL DEFAULT uuidv7(),
  PRIMARY KEY (user_id, device)
);

CREATE TABLE "deletions" (
  "user_id" uuid PRIMARY KEY,
);