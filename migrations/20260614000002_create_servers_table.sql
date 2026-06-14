-- migrations/20260614000002_create_servers_table.sql

CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    local_ip TEXT NOT NULL,
    pihole_path TEXT NOT NULL,
    npm_email TEXT NOT NULL,
    npm_password TEXT NOT NULL,
    active INTEGER DEFAULT 0
);
