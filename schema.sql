CREATE TABLE user (
    id TEXT NOT NULL PRIMARY KEY,
    email_address TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE auth_session (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX auth_session_user_index ON auth_session(user_id);

CREATE TABLE signup_session (
    id TEXT NOT NULL PRIMARY KEY,
    secret_hash BLOB NOT NULL,
    email_address TEXT NOT NULL,
    email_address_verification_code TEXT NOT NULL,
    email_address_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE email_address_update_session (
    id TEXT NOT NULL PRIMARY KEY,
    auth_session_id TEXT NOT NULL REFERENCES auth_session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    user_identity_verified INTEGER NOT NULL DEFAULT 0,
    new_email_address TEXT,
    new_email_address_verification_code TEXT,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX email_address_update_session_auth_session_id_index ON email_address_update_session(auth_session_id);

CREATE TABLE password_update_session (
    id TEXT NOT NULL PRIMARY KEY,
    auth_session_id TEXT NOT NULL REFERENCES auth_session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    user_identity_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX password_update_session_auth_session_id_index ON password_update_session(auth_session_id);

CREATE TABLE account_deletion_session (
    id TEXT NOT NULL PRIMARY KEY,
    auth_session_id TEXT NOT NULL REFERENCES auth_session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    user_identity_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX account_deletion_session_auth_session_id_index ON account_deletion_session(auth_session_id);

CREATE TABLE password_reset_session (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    email_code TEXT NOT NULL,
    user_identity_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX password_reset_session_user_id_index ON password_reset_session(user_id);
