CREATE TABLE browser_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL,
    document TEXT NOT NULL
);
CREATE TABLE browser_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    group_name TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    account_id TEXT NOT NULL DEFAULT '',
    require_native INTEGER NOT NULL DEFAULT 0,
    token_hash TEXT NOT NULL UNIQUE,
    revoked INTEGER NOT NULL DEFAULT 0,
    last_seen INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE browser_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    profile_id INTEGER NOT NULL REFERENCES browser_profiles(id),
    url TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    categories TEXT NOT NULL
);
CREATE INDEX browser_events_time ON browser_events(at);
