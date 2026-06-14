# 🖥️ IsaLab Homelab OS - Backend API REST em Rust

Este repositório contém o código-fonte completo do backend nativo do **IsaLab Homelab OS**. A API foi desenvolvida em **Rust** utilizando o ecossistema assíncrono do **Tokio** e o framework web **Axum**, fornecendo governança de rede, automação de DNS, gerenciamento de proxies reversos e metadados de serviços locais para Homelabs.

---

## 🛠️ Arquitetura e Estrutura do Projeto

O projeto segue uma separação limpa de arquivos e modularização profissional baseada em responsabilidade única (SRP):

* 📁 **`migrations/`**: Contém os scripts SQL de migração automática do banco de dados SQLite executados pelo `sqlx`.
* 📄 **`src/main.rs`**: Inicialização do servidor Axum, carregamento das variáveis de ambiente, pooling do banco de dados SQLite e inicialização automática do banco (migrações e seeding padrão).
* 📄 **`src/handlers.rs`**: Controladores assíncronos das rotas da API REST (autenticação, onboarding, CRUD de serviços, simulação do estado do Docker e orquestração assíncrona de pipelines).
* 📄 **`src/pihole.rs`**: Manipulação física e assíncrona do arquivo de configuração `pihole.toml` (Pi-hole v6) e reinicialização do DNS.
* 📄 **`src/npm.rs`**: Módulo de integração com o Nginx Proxy Manager (Auto-Login para geração de JWT temporário e cadastro de Proxy Hosts).
* 📄 **`src/casaos.rs`**: Módulo de descoberta e raspagem de ícones oficiais consumindo a API nativa do CasaOS.

---

## 🚀 Como Executar o Projeto Localmente

### 1. Pré-requisitos
Certifique-se de ter instalado em sua máquina:
* **Rust & Cargo** (Mínimo v1.75+)
* **SQLite3** (Não obrigatório, pois o driver `sqlx-sqlite` compila e cria o banco automaticamente)

### 2. Configurando Variáveis de Ambiente
A API aceita configurações via variáveis de ambiente. Você pode exportá-las diretamente no terminal ou criar um arquivo `.env` na raiz do backend:

```bash
# Porta em que o servidor Axum irá rodar (padrão: 3001)
PORT=3000

# URL de conexão com o banco SQLite (padrão: sqlite://homelab.db)
DATABASE_URL=sqlite://homelab.db

# Segredo de assinatura dos tokens JWT administrativos
JWT_SECRET=sua_chave_secreta_jwt_aqui
```

### 3. Rodando a Aplicação
Execute os seguintes comandos no terminal:

```bash
# Certifique-se de carregar o ambiente do Cargo se acabou de instalar o Rust
source "$HOME/.cargo/env"

# Compilar e iniciar a API em modo de Desenvolvimento
cargo run

# Compilar e iniciar a API em modo de Produção (Performance Máxima)
cargo run --release
```

---

## 💾 Banco de Dados & Seeding Automático

Ao iniciar o servidor pela primeira vez:
1. O arquivo SQLite definido no `DATABASE_URL` (padrão: `homelab.db` na raiz) será gerado automaticamente.
2. Todas as migrações da pasta `/migrations` serão aplicadas pelo `sqlx` (tabelas de `services`, `system_config`, `users`).
3. As colunas extras exigidas pelo frontend (como `pinned`, `docker_container_id`, `name`, etc.) serão anexadas.
4. **Seeding Padrão:** Caso o banco esteja zerado, o backend injetará automaticamente a base de dados mockada (Komga, Gitea, Jellyfin, NPM, etc.) para que você possa testar o frontend completo imediatamente sem precisar cadastrar dados manualmente.

---

## 🔗 Guia de Integração e APIs
Para detalhes técnicos sobre os payloads enviados e recebidos por cada endpoint do backend, consulte o **[GUIA_BACKEND.md](GUIA_BACKEND.md)** ou a versão rica visual em **[GUIA_BACKEND.html](GUIA_BACKEND.html)**.
