-- migrations/20260614000001_extend_structures.sql

-- Criação da tabela de cache de containers
CREATE TABLE IF NOT EXISTS containers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    status TEXT NOT NULL,
    created TEXT NOT NULL,
    ports TEXT NOT NULL,
    cpu REAL NOT NULL,
    memory TEXT NOT NULL,
    labels TEXT NOT NULL
);

-- Criação da tabela de cache de npm_hosts
CREATE TABLE IF NOT EXISTS npm_hosts (
    id TEXT PRIMARY KEY,
    domain_names TEXT NOT NULL,
    forward_scheme TEXT NOT NULL,
    forward_host TEXT NOT NULL,
    forward_port INTEGER NOT NULL,
    ssl_active INTEGER NOT NULL,
    ssl_provider TEXT NOT NULL,
    status TEXT NOT NULL
);

-- Criação da tabela de cache de dns_entries
CREATE TABLE IF NOT EXISTS dns_entries (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL,
    source TEXT NOT NULL
);

-- Criação da tabela de controle de pipelines
CREATE TABLE IF NOT EXISTS pipelines (
    id TEXT PRIMARY KEY,
    service_name TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    description TEXT,
    category TEXT NOT NULL,
    register_npm INTEGER NOT NULL,
    register_pihole INTEGER NOT NULL,
    create_docker INTEGER NOT NULL,
    status TEXT NOT NULL,
    current_step TEXT NOT NULL,
    logs TEXT NOT NULL
);
