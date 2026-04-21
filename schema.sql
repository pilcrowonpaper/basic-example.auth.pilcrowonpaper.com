CREATE TABLE user (
    id TEXT NOT NULL PRIMARY KEY,
    email_address TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE session (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE signup (
    id TEXT NOT NULL PRIMARY KEY,
    secret_hash BLOB NOT NULL,
    email_address TEXT NOT NULL,
    email_address_verification_code TEXT NOT NULL,
    email_address_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE email_address_update (
    id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    user_identity_verified INTEGER NOT NULL DEFAULT 0,
    new_email_address TEXT,
    new_email_address_verification_code TEXT,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE password_update (
    id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    user_identity_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE account_deletion (
    id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    user_identity_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE password_reset (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    email_address TEXT NOT NULL,
    code_hash BLOB NOT NULL,
    code_salt BLOB NOT NULL,
    first_factor_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;