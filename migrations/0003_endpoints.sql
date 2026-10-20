CREATE TABLE endpoint_signing_key (id INTEGER PRIMARY KEY CHECK(id=1), secret TEXT NOT NULL);
CREATE TABLE endpoints (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    control TEXT NOT NULL,
    revision INTEGER NOT NULL,
    network TEXT NOT NULL,
    quarantined INTEGER NOT NULL DEFAULT 0,
    last_seen INTEGER,
    reported_revision INTEGER NOT NULL DEFAULT 0,
    reported_state TEXT NOT NULL DEFAULT 'not connected',
    detail TEXT NOT NULL DEFAULT ''
);
