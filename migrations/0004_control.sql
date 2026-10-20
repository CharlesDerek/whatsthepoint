CREATE TABLE control_identity (id INTEGER PRIMARY KEY CHECK(id=1), server_id TEXT NOT NULL UNIQUE);
CREATE TABLE pairing_tickets (
 id TEXT PRIMARY KEY, secret TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL,
 owner TEXT NOT NULL, endpoint_id TEXT, expires_at INTEGER NOT NULL, used_at INTEGER
);
CREATE TABLE principals (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, owner TEXT NOT NULL,
 endpoint_id TEXT, master_hash TEXT NOT NULL, node_hash TEXT NOT NULL, node TEXT NOT NULL,
 secret TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0, last_seen INTEGER
);
CREATE INDEX principals_endpoint ON principals(endpoint_id);
CREATE TABLE control_nonces (
 principal_id TEXT NOT NULL REFERENCES principals(id), nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
 PRIMARY KEY(principal_id, nonce)
);
CREATE INDEX control_nonces_expiry ON control_nonces(expires_at);
ALTER TABLE endpoints ADD COLUMN remote_uninstall_enabled INTEGER NOT NULL DEFAULT 0;
CREATE TABLE endpoint_commands (
 id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
 principal_id TEXT NOT NULL REFERENCES principals(id), node_hash TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind='uninstall'), created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'queued', detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX endpoint_commands_pending ON endpoint_commands(endpoint_id,state);
