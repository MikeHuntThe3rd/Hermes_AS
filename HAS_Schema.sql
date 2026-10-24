CREATE TYPE privilege_t AS ENUM ('Consumer', 'Proprietor');

CREATE TABLE "users" (
  "id" uuid PRIMARY KEY DEFAULT uuidv7(),
  "nickname" text NOT NULL,
  "prv" privilege_t NOT NULL,
  "username" text NOT NULL UNIQUE,
  "password" text NOT NULL,
  "pfp" uuid
);

CREATE TABLE "devices" (
  "id" uuid PRIMARY KEY DEFAULT uuidv7(),
  "nickname" text NOT NULL,
  "prv" privilege_t NOT NULL,
  "username" text NOT NULL UNIQUE,
  "password" text NOT NULL,
  "pfp" uuid
);

CREATE TABLE "deletions" (
  "id" uuid PRIMARY KEY DEFAULT uuidv7(),
  "nickname" text NOT NULL,
  "prv" privilege_t NOT NULL,
  "username" text NOT NULL UNIQUE,
  "password" text NOT NULL,
  "pfp" uuid
);