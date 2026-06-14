-- migrations/20260614000000_initial_setup.sql

-- Criação da tabela de Metadados dos Serviços
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain TEXT NOT NULL UNIQUE,
    target_ip TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    description TEXT,
    icon_url TEXT,
    category TEXT NOT NULL
);

-- Criação da tabela de Controle de Primeiro Acesso e Configurações de Integração
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Criação da tabela de Autenticação do Painel Administrativo
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);

-- Injeção do usuário Admin inicial de fallback (Senha padrão: admin)
INSERT OR IGNORE INTO users (username, password_hash) 
VALUES ('admin', '$2b$12$6kuxb.wR00C0X6wWf7yYIuV9Rz47V8hV.e5pOmwE6l6Cq9fE6vK1q');
