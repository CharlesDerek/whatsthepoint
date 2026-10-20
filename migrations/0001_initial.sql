CREATE TABLE admins (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL CHECK(action IN ('allow','block')),
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    preset TEXT UNIQUE,
    updated_at INTEGER,
    error TEXT,
    count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE list_domains (
    list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    PRIMARY KEY (list_id, domain)
);
CREATE TABLE queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    client TEXT NOT NULL,
    domain TEXT NOT NULL,
    qtype TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    elapsed_ms INTEGER NOT NULL,
    cached INTEGER NOT NULL,
    rcode TEXT NOT NULL
);
CREATE INDEX queries_time ON queries(at);
CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    detail TEXT NOT NULL
);
INSERT INTO rules(domain, action, note, created_at)
VALUES ('blocked.test', 'block', 'A safe domain for testing your filter.', unixepoch());
