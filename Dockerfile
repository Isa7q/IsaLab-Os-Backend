# Stage 1: Build
FROM rust:1.96-slim AS builder

WORKDIR /app

# Instalar dependências de build necessárias para SSL e compilação
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiar arquivos de manifesto e código fonte
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src

# Compilar em modo release
RUN cargo build --release

# Stage 2: Runtime
FROM debian:trixie-slim AS runtime

WORKDIR /app

# Instalar ca-certificates e openssl para chamadas HTTPS da API
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copiar a CLI do Docker para permitir gerenciamento de containers a partir do socket
COPY --from=docker:latest /usr/local/bin/docker /usr/local/bin/docker

# Copiar o executável do builder
COPY --from=builder /app/target/release/homelab-governance-api /app/homelab-governance-api
COPY migrations /app/migrations

# Definir porta padrão de produção e banco de dados
ENV PORT=3001
ENV DATABASE_URL=sqlite:///app/data/homelab.db

EXPOSE 3001

CMD ["/app/homelab-governance-api"]
