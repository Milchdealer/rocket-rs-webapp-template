-- Your SQL goes here
CREATE TABLE session_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    uid INTEGER NOT NULL,
    session_token TEXT NOT NULL,
    issued TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_until TEXT NOT NULL,
    FOREIGN KEY(uid) REFERENCES users(id)
);